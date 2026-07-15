import assert from 'node:assert/strict'
import test from 'node:test'

import { fsyncDirectorySync, writeAllSync } from '../src/fs-safety.mjs'

test('writeAllSync completes short writes without duplicating bytes', () => {
  const stored = []
  let calls = 0
  writeAllSync(7, 'abcdef', (handle, bytes, offset, length, position) => {
    assert.equal(handle, 7)
    assert.equal(position, null)
    calls++
    const written = Math.min(2, length)
    stored.push(...bytes.subarray(offset, offset + written))
    return written
  })
  assert.equal(calls, 3)
  assert.equal(new TextDecoder().decode(new Uint8Array(stored)), 'abcdef')
})

test('writeAllSync fails closed when a write makes no progress', () => {
  assert.throws(() => writeAllSync(7, 'x', () => 0), /forward progress/)
  assert.throws(() => writeAllSync(7, 'x', () => 2), /forward progress/)
})

test('fsyncDirectorySync reports supported and unsupported directory durability', () => {
  const calls = []
  assert.equal(fsyncDirectorySync('/storage', {
    openSync: (target, flags) => { calls.push(['open', target, flags]); return 9 },
    fsyncSync: (handle) => calls.push(['fsync', handle]),
    closeSync: (handle) => calls.push(['close', handle])
  }), true)
  assert.deepEqual(calls, [['open', '/storage', 'r'], ['fsync', 9], ['close', 9]])

  assert.equal(fsyncDirectorySync('/storage', {
    openSync: () => { const error = new Error('unsupported'); error.code = 'EPERM'; throw error }
  }), false)

  let closed = false
  assert.equal(fsyncDirectorySync('/storage', {
    openSync: () => 10,
    fsyncSync: () => { const error = new Error('unsupported'); error.code = 'EINVAL'; throw error },
    closeSync: () => { closed = true }
  }), false)
  assert.equal(closed, true)
})
