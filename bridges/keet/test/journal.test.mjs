import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { ContractError } from '../src/contract.mjs'
import { TopicJournal } from '../src/journal.mjs'

const fingerprint = 'f'.repeat(43)

function message (id, text = 'hello') {
  return {
    message_id: id,
    sender_id: 'alice',
    sender_display: 'Alice',
    text,
    sent_at_ms: 1_700_000_000_000,
    reply_to: null
  }
}

test('journal persists dedup idempotency and exact API cursors', (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'neoth-keet-journal-'))
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const journal = new TopicJournal(directory, (value) => value)
  journal.open()
  assert.throws(() => journal.assertCanReadAfter(1), ContractError)
  journal.append(message('m1'), { idempotencyKey: 'request-1', fingerprint })
  journal.append(message('m2'))
  assert.equal(journal.lookupIdempotency('request-1', fingerprint), 'm1')
  assert.throws(() => journal.lookupIdempotency('request-1', 'x'.repeat(43)), ContractError)
  assert.deepEqual(journal.apiPageAfter(0, 1), {
    messages: [{
      cursor: 'c:1',
      message_id: 'm1',
      sender_id: 'alice',
      sender_display: 'Alice',
      text: 'hello',
      sent_at_ms: 1_700_000_000_000,
      reply_to: null
    }],
    next_cursor: 'c:1'
  })
  assert.deepEqual(journal.apiPageAfter(2, 50), { messages: [], next_cursor: 'c:2' })
  journal.close()

  const reopened = new TopicJournal(directory, (value) => value)
  reopened.open()
  assert.equal(reopened.latestCursor, 'c:2')
  assert.equal(reopened.append(message('m2')).inserted, false)
  reopened.close()
})

test('journal removes only a torn tail and rejects complete corruption', (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'neoth-keet-journal-'))
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const journal = new TopicJournal(directory, (value) => value)
  journal.open()
  journal.append(message('m1'))
  journal.close()

  const filename = path.join(directory, 'messages.jsonl')
  fs.appendFileSync(filename, '{"partial":')
  const recovered = new TopicJournal(directory, (value) => value)
  recovered.open()
  assert.equal(recovered.latestCursor, 'c:1')
  recovered.close()

  fs.appendFileSync(filename, '{"complete":"corruption"}\n')
  const corrupt = new TopicJournal(directory, (value) => value)
  assert.throws(() => corrupt.open())
})

test('journal poisons its handle after a short-write failure and recovers the torn tail', (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'neoth-keet-journal-'))
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  let writes = 0
  const journal = new TopicJournal(directory, (value) => value, {
    writeSync (handle, bytes, offset, length, position) {
      writes++
      if (writes > 1) return 0
      return fs.writeSync(handle, bytes, offset, Math.min(8, length), position)
    }
  })
  journal.open()
  assert.throws(() => journal.append(message('m1')), /forward progress/)
  assert.throws(() => journal.append(message('m2')), /journal is not open/)

  const recovered = new TopicJournal(directory, (value) => value)
  recovered.open()
  assert.equal(recovered.latestCursor, 'c:0')
  recovered.close()
})
