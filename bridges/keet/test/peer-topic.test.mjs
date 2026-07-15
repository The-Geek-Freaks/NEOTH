import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { CheckpointStore, PeerTopic } from '../src/peer-topic.mjs'

const topic = `nk1_${'A'.repeat(43)}`

function journal (directory) {
  return { directory, records: [] }
}

test('peer topic does not report joined before discovery flush and rolls back a failed join', async (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'neoth-keet-peer-'))
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  let rejectFlush
  let discoveryDestroys = 0
  let swarmDestroys = 0
  let checkpointCloses = 0
  const peer = new PeerTopic({
    topic,
    journal: journal(directory),
    noiseSeed: new Uint8Array(32),
    swarmFactory: () => ({
      on () {},
      join: () => ({
        flushed: () => new Promise((resolve, reject) => { rejectFlush = reject }),
        async destroy () { discoveryDestroys++ }
      }),
      async destroy () { swarmDestroys++ }
    }),
    checkpointFactory: () => ({ open () {}, close () { checkpointCloses++ } })
  })
  const opening = peer.open()
  await Promise.resolve()
  assert.equal(peer.joined, false)
  rejectFlush(new Error('discovery flush failed'))
  await assert.rejects(opening, /discovery flush failed/)
  assert.equal(peer.joined, false)
  assert.equal(discoveryDestroys, 1)
  assert.equal(swarmDestroys, 1)
  assert.equal(checkpointCloses, 1)
})

test('peer topic shutdown aggregates discovery, swarm, and checkpoint failures', async (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'neoth-keet-peer-'))
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const peer = new PeerTopic({
    topic,
    journal: journal(directory),
    noiseSeed: new Uint8Array(32),
    swarmFactory: () => ({
      on () {},
      join: () => ({
        async flushed () {},
        async destroy () { throw new Error('discovery destroy failed') }
      }),
      async destroy () { throw new Error('swarm destroy failed') }
    }),
    checkpointFactory: () => ({
      open () {},
      close () { throw new Error('checkpoint close failed') }
    })
  })
  await peer.open()
  assert.equal(peer.joined, true)
  await assert.rejects(peer.close(), (error) => error instanceof AggregateError && error.errors.length === 3)
  assert.equal(peer.joined, false)
})

test('checkpoint store poisons its handle after a partial write', (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'neoth-keet-checkpoint-'))
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const filename = path.join(directory, 'checkpoints.jsonl')
  let writes = 0
  const store = new CheckpointStore(filename, {
    writeSync (handle, bytes, offset, length, position) {
      writes++
      if (writes > 1) return 0
      return fs.writeSync(handle, bytes, offset, Math.min(8, length), position)
    }
  })
  store.open()
  assert.throws(() => store.set('A'.repeat(43), 1), /forward progress/)
  assert.throws(() => store.set('A'.repeat(43), 2), /not open/)

  const recovered = new CheckpointStore(filename)
  recovered.open()
  assert.equal(recovered.get('A'.repeat(43)), 0)
  recovered.close()
})
