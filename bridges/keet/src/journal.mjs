import { EventEmitter } from '#events'
import fs from '#fs'
import path from '#path'

import b4a from 'b4a'

import { ContractError, cursorFor } from './contract.mjs'
import { fsyncDirectorySync, writeAllSync } from './fs-safety.mjs'

const JOURNAL_VERSION = 1
const MAX_JOURNAL_BYTES = 256 * 1024 * 1024
const MAX_RECORDS = 100_000

export class TopicJournal extends EventEmitter {
  constructor (directory, validateMessage, { writeSync = (...args) => fs.writeSync(...args) } = {}) {
    super()
    this.directory = directory
    this.filename = path.join(directory, 'messages.jsonl')
    this.validateMessage = validateMessage
    this.records = []
    this.byMessageId = new Map()
    this.byIdempotencyKey = new Map()
    this.handle = null
    this.writeSync = writeSync
  }

  open () {
    const directoryExisted = fileExists(this.directory)
    const journalExisted = fileExists(this.filename)
    fs.mkdirSync(this.directory, { recursive: true, mode: 0o700 })
    if (!directoryExisted) fsyncDirectorySync(path.dirname(this.directory))
    this.#recoverAndLoad()
    this.handle = fs.openSync(this.filename, 'a', 0o600)
    try {
      try { fs.chmodSync(this.filename, 0o600) } catch (error) {
        if (error.code !== 'ENOSYS' && error.code !== 'EPERM') throw error
      }
      if (!journalExisted) {
        fs.fsyncSync(this.handle)
        fsyncDirectorySync(this.directory)
      }
    } catch (error) {
      try { this.close() } catch (closeError) {
        throw new AggregateError([error, closeError], 'journal open and rollback both failed')
      }
      throw error
    }
  }

  close () {
    if (this.handle === null) return
    fs.fsyncSync(this.handle)
    fs.closeSync(this.handle)
    this.handle = null
  }

  get latestCursor () {
    return cursorFor(this.records.length)
  }

  lookupIdempotency (key, fingerprint) {
    const existing = this.byIdempotencyKey.get(key)
    if (!existing) return null
    if (existing.fingerprint !== fingerprint) {
      throw new ContractError(409, 'idempotency_conflict', 'idempotency key was already used with another message')
    }
    return existing.messageId
  }

  append (message, { idempotencyKey = null, fingerprint = null } = {}) {
    if (this.handle === null) throw new Error('journal is not open')
    const normalized = this.validateMessage(message)
    const existing = this.byMessageId.get(normalized.message_id)
    if (existing) {
      if (JSON.stringify(existing.message) !== JSON.stringify(normalized)) throw new Error('message id collision with different payload')
      return { record: existing, inserted: false }
    }
    if (this.records.length >= MAX_RECORDS) throw new Error('topic journal reached its safety record limit')
    if ((idempotencyKey === null) !== (fingerprint === null)) throw new Error('incomplete idempotency metadata')
    if (idempotencyKey !== null && this.byIdempotencyKey.has(idempotencyKey)) throw new Error('idempotency key was not checked before append')

    const record = {
      version: JOURNAL_VERSION,
      sequence: this.records.length + 1,
      message: normalized,
      idempotency_key: idempotencyKey,
      request_fingerprint: fingerprint
    }
    const line = `${JSON.stringify(record)}\n`
    const currentSize = fileSize(this.filename)
    if (currentSize + utf8Length(line) > MAX_JOURNAL_BYTES) throw new Error('topic journal reached its safety size limit')
    try {
      writeAllSync(this.handle, line, this.writeSync)
      fs.fsyncSync(this.handle)
    } catch (error) {
      const handle = this.handle
      this.handle = null
      try { fs.closeSync(handle) } catch (closeError) {
        error = new AggregateError([error, closeError], 'journal write and emergency close both failed')
      }
      this.emit('fatal', error)
      throw error
    }
    this.#index(record)
    this.emit('append', record.sequence)
    return { record, inserted: true }
  }

  async waitForAfter (sequence, waitMs) {
    if (sequence < this.records.length || waitMs === 0) return
    await new Promise((resolve) => {
      let timer = null
      const onAppend = () => {
        if (timer !== null) clearTimeout(timer)
        this.off('append', onAppend)
        resolve()
      }
      timer = setTimeout(() => {
        this.off('append', onAppend)
        resolve()
      }, waitMs)
      this.on('append', onAppend)
      if (sequence < this.records.length) onAppend()
    })
  }

  assertCanReadAfter (sequence) {
    this.#assertSequence(sequence)
  }

  apiPageAfter (sequence, limit) {
    this.#assertSequence(sequence)
    const selected = this.records.slice(sequence, sequence + limit)
    const messages = selected.map((record) => ({
      cursor: cursorFor(record.sequence),
      message_id: record.message.message_id,
      sender_id: record.message.sender_id,
      sender_display: record.message.sender_display,
      text: record.message.text,
      sent_at_ms: record.message.sent_at_ms,
      reply_to: record.message.reply_to
    }))
    return {
      messages,
      next_cursor: selected.length > 0 ? cursorFor(selected.at(-1).sequence) : cursorFor(sequence)
    }
  }

  peerPageAfter (sequence, limit, byteLimit) {
    this.#assertSequence(sequence)
    const entries = []
    let bytes = 0
    for (const record of this.records.slice(sequence, sequence + limit)) {
      const entry = { sequence: record.sequence, message: record.message }
      const encoded = JSON.stringify(entry)
      if (entries.length > 0 && bytes + utf8Length(encoded) > byteLimit) break
      if (utf8Length(encoded) > byteLimit) throw new Error('single peer message exceeds sync page safety limit')
      entries.push(entry)
      bytes += utf8Length(encoded)
    }
    return { entries, latest: this.records.length }
  }

  #assertSequence (sequence) {
    if (!Number.isSafeInteger(sequence) || sequence < 0) throw new ContractError(400, 'invalid_cursor', 'invalid cursor sequence')
    if (sequence > this.records.length) throw new ContractError(409, 'cursor_ahead', 'cursor is ahead of this topic journal')
  }

  #recoverAndLoad () {
    let bytes
    try {
      const stats = fs.statSync(this.filename)
      if (stats.size > MAX_JOURNAL_BYTES) throw new Error('topic journal exceeds its safety size limit')
      bytes = fs.readFileSync(this.filename)
    } catch (error) {
      if (error.code === 'ENOENT') return
      throw error
    }
    if (bytes.byteLength === 0) return
    const lastNewline = bytes.lastIndexOf(0x0a)
    if (lastNewline !== bytes.byteLength - 1) {
      const handle = fs.openSync(this.filename, 'r+')
      try {
        fs.ftruncateSync(handle, lastNewline < 0 ? 0 : lastNewline + 1)
        fs.fsyncSync(handle)
      } finally {
        fs.closeSync(handle)
      }
      bytes = lastNewline < 0 ? bytes.subarray(0, 0) : bytes.subarray(0, lastNewline + 1)
    }
    const text = bytes.toString('utf8')
    for (const line of text.split('\n')) {
      if (!line) continue
      const record = validateRecord(JSON.parse(line), this.validateMessage, this.records.length + 1)
      this.#index(record)
      if (this.records.length > MAX_RECORDS) throw new Error('topic journal exceeds its safety record limit')
    }
  }

  #index (record) {
    if (this.byMessageId.has(record.message.message_id)) throw new Error('duplicate message id in durable journal')
    if (record.idempotency_key !== null && this.byIdempotencyKey.has(record.idempotency_key)) throw new Error('duplicate idempotency key in durable journal')
    this.records.push(record)
    this.byMessageId.set(record.message.message_id, record)
    if (record.idempotency_key !== null) {
      this.byIdempotencyKey.set(record.idempotency_key, {
        messageId: record.message.message_id,
        fingerprint: record.request_fingerprint
      })
    }
  }
}

function validateRecord (value, validateMessage, expectedSequence) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid journal record')
  const keys = Object.keys(value).sort().join(',')
  if (keys !== 'idempotency_key,message,request_fingerprint,sequence,version') throw new Error('unknown journal record field')
  if (value.version !== JOURNAL_VERSION || value.sequence !== expectedSequence) throw new Error('non-contiguous journal record')
  if ((value.idempotency_key === null) !== (value.request_fingerprint === null)) throw new Error('invalid journal idempotency metadata')
  if (value.idempotency_key !== null) {
    if (typeof value.idempotency_key !== 'string' || value.idempotency_key.length === 0 || value.idempotency_key.length > 128) throw new Error('invalid journal idempotency key')
    if (typeof value.request_fingerprint !== 'string' || !/^[A-Za-z0-9_-]{43}$/.test(value.request_fingerprint)) throw new Error('invalid request fingerprint')
  }
  return { ...value, message: validateMessage(value.message) }
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

function utf8Length (value) {
  return b4a.byteLength(value)
}
