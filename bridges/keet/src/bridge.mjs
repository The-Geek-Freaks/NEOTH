import fs from '#fs'
import path from '#path'

import b4a from 'b4a'
import hypercoreCrypto from 'hypercore-crypto'

import { ContractError } from './contract.mjs'
import { createIdentity, createSignedMessage, toBase64Url, verifySignedMessage } from './identity.mjs'
import { TopicJournal } from './journal.mjs'
import { PeerTopic } from './peer-topic.mjs'

export class KeetBridgeService {
  constructor ({
    storage,
    config,
    onError = (error) => console.error('[peer]', error.message),
    onFatal = () => {},
    createIdentityFn = createIdentity,
    journalFactory = (directory, validateMessage) => new TopicJournal(directory, validateMessage),
    peerFactory = (options) => new PeerTopic(options)
  }) {
    this.storage = storage
    this.config = config
    this.onError = onError
    this.onFatal = onFatal
    this.createIdentityFn = createIdentityFn
    this.journalFactory = journalFactory
    this.peerFactory = peerFactory
    this.identityState = null
    this.topics = new Map()
    this.ready = false
    this.fatalError = null
    this.closePromise = null
  }

  async open () {
    if (this.ready) return
    if (this.closePromise) throw new Error('bridge service cannot be reopened after shutdown')
    fs.mkdirSync(path.join(this.storage, 'topics'), { recursive: true, mode: 0o700 })
    try {
      this.identityState = await this.createIdentityFn(this.config.mnemonic)
      for (const topic of this.config.topics) {
        const topicDirectory = path.join(this.storage, 'topics', storageName(topic))
        const journal = this.journalFactory(topicDirectory, (message) => verifySignedMessage(message, topic))
        try {
          journal.open()
        } catch (error) {
          try { journal.close() } catch (closeError) {
            throw new AggregateError([error, closeError], `topic journal open rollback failed for ${topic}`)
          }
          throw error
        }
        journal.on('fatal', (error) => {
          this.#handleFatal(error)
        })
        const noiseSeed = hypercoreCrypto.hash([
          b4a.from('neoth-keet-bridge/noise-seed/v1\0'),
          b4a.from(this.config.mnemonic),
          b4a.from(topic)
        ])
        let peer
        try {
          peer = this.peerFactory({ topic, journal, noiseSeed, onError: this.onError })
        } catch (error) {
          try { journal.close() } catch (closeError) {
            throw new AggregateError([error, closeError], `topic peer construction rollback failed for ${topic}`)
          }
          throw error
        } finally {
          noiseSeed.fill(0)
        }
        // Register before opening so any failed DHT join is included in the
        // service-wide rollback path.
        this.topics.set(topic, { journal, peer })
        await peer.open()
      }
      if (this.fatalError) throw this.fatalError
      this.ready = true
    } catch (error) {
      try { await this.close() } catch (closeError) {
        throw new AggregateError([error, closeError], 'bridge open and rollback both failed')
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
    this.ready = false
    const active = [...this.topics.values()]
    this.topics.clear()
    const errors = []
    for (const { peer, journal } of active.reverse()) {
      try { await peer.close() } catch (error) { errors.push(error) }
      try { journal.close() } catch (error) { errors.push(error) }
    }
    if (this.identityState) {
      try { this.identityState.close() } catch (error) { errors.push(error) }
    }
    this.identityState = null
    if (errors.length > 0) throw new AggregateError(errors, 'bridge shutdown failed')
  }

  get selfId () {
    return this.identityState?.selfId || null
  }

  topicState (topic) {
    const active = this.#topic(topic)
    return {
      joined: active.peer.joined,
      latest_cursor: active.journal.latestCursor,
      self_id: this.identityState.selfId
    }
  }

  async poll (topic, sequence, waitMs, limit) {
    const active = this.#topic(topic)
    active.journal.assertCanReadAfter(sequence)
    await active.journal.waitForAfter(sequence, waitMs)
    return active.journal.apiPageAfter(sequence, limit)
  }

  #handleFatal (error) {
    if (this.fatalError) return
    this.fatalError = error
    this.ready = false
    void this.close().catch((closeError) => this.onError(closeError))
    try { this.onFatal(error) } catch (callbackError) { this.onError(callbackError) }
  }

  post (topic, request) {
    const active = this.#topic(topic)
    const fingerprint = requestFingerprint(request)
    const existing = active.journal.lookupIdempotency(request.idempotency_key, fingerprint)
    if (existing) return { message_id: existing }
    const message = createSignedMessage({
      identityState: this.identityState,
      topic,
      text: request.text,
      replyTo: request.reply_to,
      displayName: this.config.display_name
    })
    const { record } = active.journal.append(message, {
      idempotencyKey: request.idempotency_key,
      fingerprint
    })
    active.peer.broadcast(record.message)
    return { message_id: record.message.message_id }
  }

  #topic (topic) {
    if (!this.ready) throw new ContractError(409, 'bridge_not_ready', 'bridge is not ready')
    const active = this.topics.get(topic)
    if (!active) throw new ContractError(404, 'unknown_topic', 'topic is not provisioned in this bridge')
    if (!active.peer.joined) throw new ContractError(409, 'topic_not_joined', 'topic transport is not joined')
    return active
  }
}

function requestFingerprint (request) {
  return toBase64Url(hypercoreCrypto.hash([
    b4a.from('neoth-keet-bridge/idempotency/v1\0'),
    b4a.from(JSON.stringify([request.text, request.reply_to || null]))
  ]))
}

function storageName (topic) {
  return toBase64Url(hypercoreCrypto.hash([
    b4a.from('neoth-keet-bridge/storage/v1\0'),
    b4a.from(topic)
  ]))
}
