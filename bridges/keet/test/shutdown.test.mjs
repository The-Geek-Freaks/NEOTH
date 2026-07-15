import assert from 'node:assert/strict'
import test from 'node:test'

import { createShutdownHandler } from '../src/shutdown.mjs'

test('shutdown is idempotent across two signals', async () => {
  let releaseServer
  let serverCloses = 0
  let serviceCloses = 0
  let lockCloses = 0
  const exits = []
  const server = {
    close () {
      serverCloses++
      return new Promise((resolve) => { releaseServer = resolve })
    }
  }
  const service = { async close () { serviceCloses++ } }
  const shutdown = createShutdownHandler({
    server,
    service,
    storageLock: { async close () { lockCloses++ } },
    onError: assert.fail,
    exit: (code) => exits.push(code)
  })
  const first = shutdown()
  const second = shutdown()
  assert.equal(first, second)
  releaseServer()
  await first
  await Promise.resolve()
  assert.equal(serverCloses, 1)
  assert.equal(serviceCloses, 1)
  assert.equal(lockCloses, 1)
  assert.deepEqual(exits, [0])
})

test('fatal shutdown closes the runtime and exits non-zero', async () => {
  const fatal = new Error('journal durability failed')
  const seen = []
  const exits = []
  const closed = []
  const shutdown = createShutdownHandler({
    server: { async close () { closed.push('server') } },
    service: { async close () { closed.push('service') } },
    storageLock: { async close () { closed.push('lock') } },
    onError: (error) => seen.push(error),
    exit: (code) => exits.push(code)
  })
  await shutdown(fatal)
  await Promise.resolve()
  assert.deepEqual(closed, ['server', 'service', 'lock'])
  assert.deepEqual(seen, [fatal])
  assert.deepEqual(exits, [1])
})

test('shutdown closes both layers and reports aggregate failure once', async () => {
  const seen = []
  const exits = []
  const shutdown = createShutdownHandler({
    server: { async close () { throw new Error('http close failed') } },
    service: { async close () { throw new Error('peer close failed') } },
    onError: (error) => seen.push(error),
    exit: (code) => exits.push(code)
  })
  await assert.rejects(shutdown(), AggregateError)
  await Promise.resolve()
  assert.equal(seen.length, 1)
  assert.equal(seen[0].errors.length, 2)
  assert.deepEqual(exits, [1])
})
