import b4a from 'b4a'
import hypercoreCrypto from 'hypercore-crypto'
import Identity from 'keet-identity-key'

import { MAX_TEXT_BYTES, PROTOCOL, PROTOCOL_VERSION, assertTopicId, utf8Length } from './contract.mjs'

const MAX_PROOF_BYTES = 16 * 1024
const MESSAGE_KEYS = new Set([
  'protocol',
  'protocol_version',
  'topic',
  'message_id',
  'sender_id',
  'sender_display',
  'text',
  'sent_at_ms',
  'reply_to',
  'proof'
])

export function randomToken () {
  return toBase64Url(hypercoreCrypto.randomBytes(32))
}

export function generateMnemonic () {
  return Identity.generateMnemonic()
}

export function randomTopicId () {
  return `nk1_${toBase64Url(hypercoreCrypto.randomBytes(32))}`
}

export function topicSecret (topic) {
  assertTopicId(topic)
  const encoded = topic.slice(4)
  const secret = fromBase64Url(encoded)
  if (secret.byteLength !== 32 || toBase64Url(secret) !== encoded) throw new Error('non-canonical topic secret')
  return secret
}

export async function createIdentity (mnemonic) {
  const identity = await Identity.from({ mnemonic })
  const deviceKeyPair = hypercoreCrypto.keyPair()
  const deviceProof = await identity.bootstrap(deviceKeyPair.publicKey)
  const selfId = toBase64Url(identity.identityPublicKey)
  return {
    selfId,
    identity,
    deviceKeyPair,
    deviceProof,
    close () {
      identity.clear()
      if (deviceKeyPair.secretKey) deviceKeyPair.secretKey.fill(0)
    }
  }
}

export function createSignedMessage ({ identityState, topic, text, replyTo, displayName, now = Date.now }) {
  assertTopicId(topic)
  if (typeof text !== 'string' || text.trim().length === 0 || utf8Length(text) > MAX_TEXT_BYTES) throw new Error('invalid message text')
  const envelope = {
    protocol: PROTOCOL,
    protocol_version: PROTOCOL_VERSION,
    topic,
    message_id: `m1_${toBase64Url(hypercoreCrypto.randomBytes(16))}`,
    sender_id: identityState.selfId,
    sender_display: displayName || null,
    text,
    sent_at_ms: now(),
    reply_to: replyTo || null
  }
  const payload = canonicalMessage(envelope)
  const proof = Identity.attestData(payload, identityState.deviceKeyPair, identityState.deviceProof)
  return { ...envelope, proof: toBase64Url(proof) }
}

export function verifySignedMessage (value, expectedTopic) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('message must be an object')
  for (const key of Object.keys(value)) {
    if (!MESSAGE_KEYS.has(key)) throw new Error(`unsupported message field: ${key}`)
  }
  if (value.protocol !== PROTOCOL || value.protocol_version !== PROTOCOL_VERSION) throw new Error('wrong peer protocol')
  if (value.topic !== expectedTopic) throw new Error('message belongs to another topic')
  if (!/^m1_[A-Za-z0-9_-]{22}$/.test(value.message_id)) throw new Error('invalid message id')
  if (!/^[A-Za-z0-9_-]{43}$/.test(value.sender_id)) throw new Error('invalid sender id')
  if (value.sender_display !== null && value.sender_display !== undefined) {
    if (typeof value.sender_display !== 'string' || value.sender_display.trim().length === 0 || utf8Length(value.sender_display) > 512 || hasControl(value.sender_display)) throw new Error('invalid sender display')
  }
  if (typeof value.text !== 'string' || value.text.trim().length === 0 || utf8Length(value.text) > MAX_TEXT_BYTES) throw new Error('invalid message text')
  if (!Number.isSafeInteger(value.sent_at_ms) || value.sent_at_ms < 0) throw new Error('invalid message timestamp')
  if (value.reply_to !== null && value.reply_to !== undefined) {
    if (typeof value.reply_to !== 'string' || value.reply_to.length === 0 || utf8Length(value.reply_to) > 1024 || hasControl(value.reply_to)) throw new Error('invalid reply id')
  }
  if (typeof value.proof !== 'string' || value.proof.length === 0 || value.proof.length > Math.ceil(MAX_PROOF_BYTES * 4 / 3)) throw new Error('invalid identity proof')
  const proof = fromBase64Url(value.proof)
  if (proof.byteLength > MAX_PROOF_BYTES || toBase64Url(proof) !== value.proof) throw new Error('non-canonical identity proof')
  const expectedIdentity = fromBase64Url(value.sender_id)
  if (expectedIdentity.byteLength !== 32 || toBase64Url(expectedIdentity) !== value.sender_id) throw new Error('non-canonical sender id')

  const verified = Identity.verify(proof, canonicalMessage(value))
  if (!verified || !verified.identityPublicKey || !b4a.equals(verified.identityPublicKey, expectedIdentity)) {
    throw new Error('Keet identity proof does not match sender id')
  }
  return {
    protocol: PROTOCOL,
    protocol_version: PROTOCOL_VERSION,
    topic: value.topic,
    message_id: value.message_id,
    sender_id: value.sender_id,
    sender_display: value.sender_display || null,
    text: value.text,
    sent_at_ms: value.sent_at_ms,
    reply_to: value.reply_to || null,
    proof: value.proof
  }
}

export function canonicalMessage (value) {
  return b4a.from(JSON.stringify([
    PROTOCOL,
    PROTOCOL_VERSION,
    value.topic,
    value.message_id,
    value.sender_id,
    value.sender_display || null,
    value.text,
    value.sent_at_ms,
    value.reply_to || null
  ]))
}

export function toBase64Url (bytes) {
  return b4a.toString(bytes, 'base64url')
}

export function fromBase64Url (value) {
  return b4a.from(value, 'base64url')
}

function hasControl (value) {
  for (const character of value) {
    const code = character.codePointAt(0)
    if (code <= 0x1f || code === 0x7f) return true
  }
  return false
}
