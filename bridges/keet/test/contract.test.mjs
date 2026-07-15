import assert from 'node:assert/strict'
import test from 'node:test'

import {
  CAPABILITIES,
  ContractError,
  assertBearerToken,
  assertTopicId,
  cursorFor,
  healthPayload,
  parsePollQuery,
  sequenceFromCursor,
  validatePostMessage
} from '../src/contract.mjs'

const topic = `nk1_${'a'.repeat(42)}A`

test('health advertises full duplex only while ready', () => {
  assert.deepEqual(healthPayload(true), {
    protocol: 'neoth-keet-bridge',
    protocol_version: 1,
    bridge_version: '1.0.0',
    ready: true,
    capabilities: ['send_text', 'receive_text']
  })
  assert.deepEqual(healthPayload(false).capabilities, [])
  assert.deepEqual(CAPABILITIES, ['send_text', 'receive_text'])
})

test('token topic and cursor validators pin the v1 boundary', () => {
  assert.equal(assertBearerToken('a'.repeat(32)), 'a'.repeat(32))
  assert.equal(assertTopicId(topic), topic)
  assert.equal(cursorFor(42), 'c:42')
  assert.equal(sequenceFromCursor('c:42'), 42)
  assert.throws(() => assertBearerToken('short'), ContractError)
  assert.throws(() => assertTopicId('keet-room-name'), ContractError)
  assert.throws(() => assertTopicId(`nk1_${'a'.repeat(43)}`), ContractError)
  assert.throws(() => sequenceFromCursor('42'), ContractError)
})

test('poll query requires the bounded Rust client shape', () => {
  const query = parsePollQuery(new URLSearchParams('after=c%3A9&wait_ms=25000&limit=50'))
  assert.deepEqual(query, { after: 'c:9', sequence: 9, waitMs: 25_000, limit: 50 })
  assert.throws(() => parsePollQuery(new URLSearchParams('after=c%3A9&wait_ms=25001&limit=50')), ContractError)
  assert.throws(() => parsePollQuery(new URLSearchParams('after=c%3A9&wait_ms=1&limit=51')), ContractError)
  assert.throws(() => parsePollQuery(new URLSearchParams('after=c%3A9&wait_ms=1&limit=1&extra=1')), ContractError)
  assert.throws(() => parsePollQuery(new URLSearchParams('after=c%3A9&after=c%3A10&wait_ms=1&limit=1')), ContractError)
})

test('post body accepts current UUID idempotency and rejects schema drift', () => {
  assert.deepEqual(validatePostMessage({
    text: 'hello',
    idempotency_key: '9d94b9e9-4d7d-4fe7-9169-3f4fc2c6ef56'
  }), {
    text: 'hello',
    idempotency_key: '9d94b9e9-4d7d-4fe7-9169-3f4fc2c6ef56',
    reply_to: null
  })
  assert.throws(() => validatePostMessage({ text: 'hello', idempotency_key: 'key', extra: true }), ContractError)
  assert.throws(() => validatePostMessage({ text: '', idempotency_key: 'key' }), ContractError)
  assert.throws(() => validatePostMessage({ text: '   ', idempotency_key: 'key' }), ContractError)
})
