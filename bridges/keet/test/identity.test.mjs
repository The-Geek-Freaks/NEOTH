import assert from 'node:assert/strict'
import test from 'node:test'

import {
  createIdentity,
  createSignedMessage,
  generateMnemonic,
  randomTopicId,
  topicSecret,
  verifySignedMessage
} from '../src/identity.mjs'

test('Keet identity signs a portable exact sender id', async () => {
  const identity = await createIdentity(generateMnemonic())
  const topic = randomTopicId()
  assert.equal(topicSecret(topic).byteLength, 32)
  const message = createSignedMessage({
    identityState: identity,
    topic,
    text: 'hello',
    replyTo: null,
    displayName: 'Alice',
    now: () => 1_700_000_000_000
  })
  const verified = verifySignedMessage(message, topic)
  assert.equal(verified.sender_id, identity.selfId)
  assert.equal(verified.text, 'hello')
  assert.throws(() => verifySignedMessage({ ...message, text: 'tampered' }, topic))
  identity.close()
})
