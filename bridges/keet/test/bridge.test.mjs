import assert from 'node:assert/strict'
import { EventEmitter } from 'node:events'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { KeetBridgeService } from '../src/bridge.mjs'

const topic = `nk1_${'A'.repeat(43)}`

class JournalStub extends EventEmitter {
  constructor (directory, closeError = null) {
    super()
    this.directory = directory
    this.closeError = closeError
    this.closed = 0
  }

  open () {}

  close () {
    this.closed++
    if (this.closeError) throw this.closeError
  }
}

test('service rolls back the current topic when peer open fails', async (context) => {
  const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'neoth-keet-bridge-'))
  context.after(() => fs.rmSync(storage, { recursive: true, force: true }))
  const journal = new JournalStub(storage)
  let peerCloses = 0
  let identityCloses = 0
  const service = new KeetBridgeService({
    storage,
    config: { mnemonic: 'test mnemonic', topics: [topic] },
    createIdentityFn: async () => ({ selfId: 'self', close: () => { identityCloses++ } }),
    journalFactory: () => journal,
    peerFactory: () => ({
      joined: false,
      async open () { throw new Error('DHT join failed') },
      async close () { peerCloses++ }
    })
  })
  await assert.rejects(service.open(), /DHT join failed/)
  assert.equal(peerCloses, 1)
  assert.equal(journal.closed, 1)
  assert.equal(identityCloses, 1)
  assert.equal(service.ready, false)
  assert.equal(service.topics.size, 0)
})

test('service shutdown attempts every layer and aggregates cleanup failures', async (context) => {
  const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'neoth-keet-bridge-'))
  context.after(() => fs.rmSync(storage, { recursive: true, force: true }))
  const journal = new JournalStub(storage, new Error('journal close failed'))
  let peerCloses = 0
  let identityCloses = 0
  const service = new KeetBridgeService({
    storage,
    config: { mnemonic: 'test mnemonic', topics: [topic] },
    createIdentityFn: async () => ({
      selfId: 'self',
      close () {
        identityCloses++
        throw new Error('identity close failed')
      }
    }),
    journalFactory: () => journal,
    peerFactory: () => ({
      joined: true,
      async open () {},
      async close () {
        peerCloses++
        throw new Error('peer close failed')
      }
    })
  })
  await service.open()
  await assert.rejects(service.close(), (error) => error instanceof AggregateError && error.errors.length === 3)
  assert.equal(peerCloses, 1)
  assert.equal(journal.closed, 1)
  assert.equal(identityCloses, 1)
  assert.equal(service.ready, false)
})

test('fatal journal failure closes peer runtime and notifies the process boundary', async (context) => {
  const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'neoth-keet-bridge-'))
  context.after(() => fs.rmSync(storage, { recursive: true, force: true }))
  const journal = new JournalStub(storage)
  let peerCloses = 0
  const fatal = new Error('journal fsync failed')
  const seen = []
  const service = new KeetBridgeService({
    storage,
    config: { mnemonic: 'test mnemonic', topics: [topic] },
    onFatal: (error) => seen.push(error),
    createIdentityFn: async () => ({ selfId: 'self', close () {} }),
    journalFactory: () => journal,
    peerFactory: () => ({
      joined: true,
      async open () {},
      async close () { peerCloses++ }
    })
  })
  await service.open()
  journal.emit('fatal', fatal)
  await service.close()
  assert.equal(peerCloses, 1)
  assert.equal(service.ready, false)
  assert.deepEqual(seen, [fatal])
})
