import fs from '#fs'
import path from '#path'

import b4a from 'b4a'
import hypercoreCrypto from 'hypercore-crypto'
import Hyperswarm from 'hyperswarm'
import ProtomuxRPC from 'protomux-rpc'
import sodium from 'sodium-universal'

import { PROTOCOL, PROTOCOL_VERSION } from './contract.mjs'
import { fsyncDirectorySync, writeAllSync } from './fs-safety.mjs'
import { fromBase64Url, toBase64Url, topicSecret } from './identity.mjs'

const RPC_PROTOCOL = `${PROTOCOL}/peer/${PROTOCOL_VERSION}`
const MAX_RPC_REQUEST = 1024 * 1024
const MAX_SYNC_RESPONSE = 512 * 1024
const MAX_SYNC_PAGES = 2000
const SYNC_PAGE_LIMIT = 50
const RPC_TIMEOUT_MS = 10_000

export class PeerTopic {
  constructor ({
    topic,
    journal,
    noiseSeed,
    onError = () => {},
    swarmFactory = (options) => new Hyperswarm(options),
    checkpointFactory = (filename) => new CheckpointStore(filename)
  }) {
    this.topic = topic
    this.journal = journal
    this.onError = onError
    this.secret = topicSecret(topic)
    this.discoveryTopic = derive('discovery', this.secret)
    this.rpcId = derive('rpc', this.secret)
    this.noiseKeyPair = hypercoreCrypto.keyPair(noiseSeed)
    this.swarm = swarmFactory({ keyPair: this.noiseKeyPair })
    this.discovery = null
    this.rpcs = new Set()
    this.checkpoints = checkpointFactory(path.join(journal.directory, 'peer-checkpoints.jsonl'))
    this.joined = false
    this.closePromise = null
  }

  async open () {
    if (this.joined) return
    if (this.closePromise) throw new Error('peer topic cannot be reopened after shutdown')
    try {
      this.checkpoints.open()
      this.swarm.on('connection', (connection, info) => this.#onConnection(connection, info))
      this.swarm.on('connection-error', (error) => this.onError(error))
      this.discovery = this.swarm.join(this.discoveryTopic, { client: true, server: true })
      await this.discovery.flushed()
      this.joined = true
    } catch (error) {
      try { await this.close() } catch (closeError) {
        throw new AggregateError([error, closeError], 'peer topic open and rollback both failed')
      }
      throw error
    }
  }

  async close () {
    if (this.closePromise) return this.closePromise
    this.closePromise = this.#close()
    return this.closePromise
  }

  async #close () {
    this.joined = false
    const errors = []
    for (const rpc of this.rpcs) {
      try { rpc.destroy() } catch (error) { errors.push(error) }
    }
    this.rpcs.clear()
    if (this.discovery) {
      try { await this.discovery.destroy() } catch (error) { errors.push(error) }
      this.discovery = null
    }
    try { await this.swarm.destroy() } catch (error) { errors.push(error) }
    try { this.checkpoints.close() } catch (error) { errors.push(error) }
    if (this.noiseKeyPair.secretKey) this.noiseKeyPair.secretKey.fill(0)
    this.secret.fill(0)
    if (errors.length > 0) throw new AggregateError(errors, 'peer topic shutdown failed')
  }

  broadcast (message, excluded = null) {
    const encoded = encodeRpc({ message })
    for (const rpc of this.rpcs) {
      if (rpc === excluded || rpc.closed) continue
      rpc.request('push', encoded, { timeout: RPC_TIMEOUT_MS }).catch((error) => this.onError(error))
    }
  }

  #onConnection (connection, info) {
    const peerId = toBase64Url(info.publicKey)
    const localAuth = connectionAuth(this.secret, this.noiseKeyPair.publicKey, info.publicKey)
    const expectedRemoteAuth = connectionAuth(this.secret, info.publicKey, this.noiseKeyPair.publicKey)
    let authenticated = false
    let remoteAuthCleared = false
    const clearRemoteAuth = () => {
      if (remoteAuthCleared) return
      expectedRemoteAuth.fill(0)
      remoteAuthCleared = true
    }
    const rpc = new ProtomuxRPC(connection, {
      protocol: RPC_PROTOCOL,
      id: this.rpcId,
      handshake: encodeRpc({
        protocol: PROTOCOL,
        protocol_version: PROTOCOL_VERSION,
        auth: toBase64Url(localAuth)
      })
    })
    localAuth.fill(0)
    this.rpcs.add(rpc)
    rpc.on('open', (handshake) => {
      try {
        const value = decodeRpc(handshake, 4096)
        const auth = fromBase64Url(value.auth || '')
        if (value.protocol !== PROTOCOL || value.protocol_version !== PROTOCOL_VERSION || auth.byteLength !== expectedRemoteAuth.byteLength || !sodium.sodium_memcmp(auth, expectedRemoteAuth)) throw new Error('peer failed topic capability authentication')
        authenticated = true
      } catch (error) {
        try { rpc.destroy(error) } catch (destroyError) { this.onError(destroyError) }
      } finally {
        clearRemoteAuth()
      }
    })
    rpc.respond('head', () => {
      requireAuthenticated(authenticated)
      return encodeRpc({ latest: this.journal.records.length })
    })
    rpc.respond('history', (request) => {
      requireAuthenticated(authenticated)
      return this.#history(request)
    })
    rpc.respond('push', async (request) => {
      requireAuthenticated(authenticated)
      return this.#push(request, rpc)
    })
    rpc.on('close', () => {
      clearRemoteAuth()
      this.rpcs.delete(rpc)
    })
    rpc.on('destroy', () => {
      clearRemoteAuth()
      this.rpcs.delete(rpc)
    })
    rpc.fullyOpened()
      .then(() => {
        requireAuthenticated(authenticated)
        return this.#sync(rpc, peerId)
      })
      .catch((error) => {
        this.onError(error)
        try { rpc.destroy(error) } catch (destroyError) { this.onError(destroyError) }
      })
  }

  #history (request) {
    const value = decodeRpc(request, 16 * 1024)
    if (!Number.isSafeInteger(value.after) || value.after < 0) throw new Error('invalid history cursor')
    if (!Number.isSafeInteger(value.limit) || value.limit < 1 || value.limit > SYNC_PAGE_LIMIT) throw new Error('invalid history limit')
    return encodeRpc(this.journal.peerPageAfter(value.after, value.limit, MAX_SYNC_RESPONSE))
  }

  async #push (request, source) {
    const value = decodeRpc(request, MAX_RPC_REQUEST)
    const { record, inserted } = this.journal.append(value.message)
    if (inserted) this.broadcast(record.message, source)
    return encodeRpc({ accepted: true, inserted })
  }

  async #sync (rpc, peerId) {
    const head = decodeRpc(await rpc.request('head', b4a.alloc(0), { timeout: RPC_TIMEOUT_MS }), 1024)
    if (!Number.isSafeInteger(head.latest) || head.latest < 0 || head.latest > 100_000) throw new Error('invalid peer journal head')
    let after = this.checkpoints.get(peerId)
    if (after > head.latest) {
      after = 0
      this.checkpoints.set(peerId, 0)
    }

    for (let pageNumber = 0; after < head.latest && pageNumber < MAX_SYNC_PAGES; pageNumber++) {
      const response = await rpc.request(
        'history',
        encodeRpc({ after, limit: SYNC_PAGE_LIMIT }),
        { timeout: RPC_TIMEOUT_MS }
      )
      const page = decodeRpc(response, MAX_SYNC_RESPONSE + 16 * 1024)
      if (!Array.isArray(page.entries) || !Number.isSafeInteger(page.latest) || page.latest < after || page.latest > 100_000) throw new Error('invalid peer history page')
      if (page.entries.length === 0 && after < page.latest) throw new Error('peer history page did not advance')
      for (const entry of page.entries) {
        if (!Number.isSafeInteger(entry.sequence) || entry.sequence !== after + 1) throw new Error('non-contiguous peer history page')
        const { record, inserted } = this.journal.append(entry.message)
        if (inserted) this.broadcast(record.message, rpc)
        after = entry.sequence
      }
      this.checkpoints.set(peerId, after)
      if (after >= page.latest) break
    }
    if (after < head.latest) throw new Error('peer history exceeds the bounded sync budget')
  }
}

export class CheckpointStore {
  constructor (filename, { writeSync = (...args) => fs.writeSync(...args) } = {}) {
    this.filename = filename
    this.values = new Map()
    this.handle = null
    this.writeSync = writeSync
  }

  open () {
    const existed = fileExists(this.filename)
    let bytes
    try { bytes = fs.readFileSync(this.filename) } catch (error) {
      if (error.code !== 'ENOENT') throw error
      bytes = b4a.alloc(0)
    }
    if (bytes.byteLength > 16 * 1024 * 1024) throw new Error('peer checkpoint journal exceeds its safety limit')
    if (bytes.byteLength > 0 && bytes[bytes.byteLength - 1] !== 0x0a) {
      const lastNewline = bytes.lastIndexOf(0x0a)
      const handle = fs.openSync(this.filename, 'r+')
      try {
        fs.ftruncateSync(handle, lastNewline < 0 ? 0 : lastNewline + 1)
        fs.fsyncSync(handle)
      } finally {
        fs.closeSync(handle)
      }
      bytes = lastNewline < 0 ? bytes.subarray(0, 0) : bytes.subarray(0, lastNewline + 1)
    }
    for (const line of bytes.toString('utf8').split('\n')) {
      if (!line) continue
      const value = JSON.parse(line)
      if (value.version !== 1 || !/^[A-Za-z0-9_-]{43}$/.test(value.peer_id) || !Number.isSafeInteger(value.sequence) || value.sequence < 0 || value.sequence > 100_000) throw new Error('invalid peer checkpoint record')
      this.values.set(value.peer_id, value.sequence)
    }
    this.handle = fs.openSync(this.filename, 'a', 0o600)
    if (!existed) {
      fs.fsyncSync(this.handle)
      fsyncDirectorySync(path.dirname(this.filename))
    }
  }

  close () {
    if (this.handle === null) return
    fs.fsyncSync(this.handle)
    fs.closeSync(this.handle)
    this.handle = null
  }

  get (peerId) {
    return this.values.get(peerId) || 0
  }

  set (peerId, sequence) {
    if (this.values.get(peerId) === sequence) return
    if (this.handle === null) throw new Error('checkpoint store is not open')
    if (this.values.size >= 1024 && !this.values.has(peerId)) throw new Error('peer checkpoint count exceeds its safety limit')
    const line = `${JSON.stringify({ version: 1, peer_id: peerId, sequence })}\n`
    if (fileSize(this.filename) + b4a.byteLength(line) > 16 * 1024 * 1024) throw new Error('peer checkpoint journal exceeds its safety limit')
    try {
      writeAllSync(this.handle, line, this.writeSync)
      fs.fsyncSync(this.handle)
    } catch (error) {
      const handle = this.handle
      this.handle = null
      try { fs.closeSync(handle) } catch (closeError) {
        throw new AggregateError([error, closeError], 'checkpoint write and emergency close both failed')
      }
      throw error
    }
    this.values.set(peerId, sequence)
  }
}

function derive (purpose, secret) {
  return hypercoreCrypto.hash([
    b4a.from(`${PROTOCOL}/${PROTOCOL_VERSION}/${purpose}\0`),
    secret
  ])
}

function connectionAuth (secret, senderPublicKey, receiverPublicKey) {
  return hypercoreCrypto.hash([
    b4a.from(`${PROTOCOL}/${PROTOCOL_VERSION}/connection-auth\0`),
    secret,
    senderPublicKey,
    receiverPublicKey
  ])
}

function requireAuthenticated (authenticated) {
  if (!authenticated) throw new Error('peer is not authenticated for this topic')
}

function encodeRpc (value) {
  return b4a.from(JSON.stringify(value))
}

function decodeRpc (bytes, limit) {
  if (!bytes || bytes.byteLength > limit) throw new Error('peer RPC body exceeds its safety limit')
  const value = JSON.parse(b4a.toString(bytes))
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('peer RPC body must be an object')
  return value
}

function fileSize (filename) {
  try { return fs.statSync(filename).size } catch (error) {
    if (error.code === 'ENOENT') return 0
    throw error
  }
}

function fileExists (filename) {
  try {
    fs.statSync(filename)
    return true
  } catch (error) {
    if (error.code === 'ENOENT') return false
    throw error
  }
}
