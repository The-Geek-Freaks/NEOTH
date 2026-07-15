import b4a from 'b4a'

export const PROTOCOL = 'neoth-keet-bridge'
export const PROTOCOL_VERSION = 1
export const BRIDGE_VERSION = '1.0.0'
export const CAPABILITIES = Object.freeze(['send_text', 'receive_text'])

export const MAX_CONTROL_BODY = 64 * 1024
export const MAX_POLL_BODY = 1024 * 1024
export const MAX_TEXT_BYTES = 64 * 1024
export const MAX_POLL_LIMIT = 50
export const MAX_POLL_WAIT_MS = 25_000
export const TOPIC_PREFIX = 'nk1_'

const TOKEN_RE = /^[A-Za-z0-9._~-]{32,4096}$/
const TOPIC_RE = /^nk1_[A-Za-z0-9_-]{43}$/
const IDEMPOTENCY_RE = /^[A-Za-z0-9._~-]{1,128}$/
const CURSOR_RE = /^c:(0|[1-9][0-9]{0,15})$/

export class ContractError extends Error {
  constructor (status, code, message) {
    super(message)
    this.name = 'ContractError'
    this.status = status
    this.code = code
  }
}

export function assertBearerToken (token) {
  if (typeof token !== 'string' || !TOKEN_RE.test(token)) {
    throw new ContractError(400, 'invalid_token', 'bearer token must be 32..4096 URL-safe ASCII characters')
  }
  return token
}

export function assertTopicId (topic) {
  if (typeof topic !== 'string' || !TOPIC_RE.test(topic) || !isCanonical32ByteBase64Url(topic.slice(TOPIC_PREFIX.length))) {
    throw new ContractError(400, 'invalid_topic', `topic must be ${TOPIC_PREFIX} followed by a 32-byte base64url secret`)
  }
  return topic
}

function isCanonical32ByteBase64Url (value) {
  let decoded
  try { decoded = b4a.from(value, 'base64url') } catch { return false }
  return decoded.byteLength === 32 && b4a.toString(decoded, 'base64url') === value
}

export function cursorFor (sequence) {
  if (!Number.isSafeInteger(sequence) || sequence < 0) {
    throw new TypeError('cursor sequence must be a non-negative safe integer')
  }
  return `c:${sequence}`
}

export function sequenceFromCursor (cursor) {
  if (typeof cursor !== 'string' || !CURSOR_RE.test(cursor)) {
    throw new ContractError(400, 'invalid_cursor', 'after must be an opaque cursor returned by this bridge')
  }
  const sequence = Number(cursor.slice(2))
  if (!Number.isSafeInteger(sequence)) {
    throw new ContractError(400, 'invalid_cursor', 'cursor is outside the supported range')
  }
  return sequence
}

export function parsePollQuery (searchParams) {
  const known = new Set(['after', 'wait_ms', 'limit'])
  const seen = new Set()
  for (const [key] of searchParams) {
    if (!known.has(key)) throw new ContractError(400, 'invalid_query', `unsupported query parameter: ${key}`)
    if (seen.has(key)) throw new ContractError(400, 'invalid_query', `duplicate query parameter: ${key}`)
    seen.add(key)
  }

  const after = searchParams.get('after')
  const sequence = sequenceFromCursor(after)
  const waitRaw = searchParams.get('wait_ms')
  const limitRaw = searchParams.get('limit')
  if (waitRaw === null || !/^(0|[1-9][0-9]{0,5})$/.test(waitRaw)) {
    throw new ContractError(400, 'invalid_wait', 'wait_ms must be an integer from 0 through 25000')
  }
  if (limitRaw === null || !/^[1-9][0-9]?$/.test(limitRaw)) {
    throw new ContractError(400, 'invalid_limit', 'limit must be an integer from 1 through 50')
  }
  const waitMs = Number(waitRaw)
  const limit = Number(limitRaw)
  if (waitMs > MAX_POLL_WAIT_MS || limit > MAX_POLL_LIMIT) {
    throw new ContractError(400, 'query_limit', 'poll query exceeds the v1 wait or page limit')
  }
  return { after, sequence, waitMs, limit }
}

export function validatePostMessage (value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) {
    throw new ContractError(400, 'invalid_json', 'request body must be a JSON object')
  }
  const allowed = new Set(['text', 'reply_to', 'idempotency_key'])
  for (const key of Object.keys(value)) {
    if (!allowed.has(key)) throw new ContractError(400, 'unknown_field', `unsupported request field: ${key}`)
  }
  if (typeof value.text !== 'string' || value.text.trim().length === 0 || utf8Length(value.text) > MAX_TEXT_BYTES) {
    throw new ContractError(400, 'invalid_text', 'text must contain 1..65536 UTF-8 bytes')
  }
  if (!IDEMPOTENCY_RE.test(value.idempotency_key || '')) {
    throw new ContractError(400, 'invalid_idempotency_key', 'idempotency_key must be 1..128 URL-safe ASCII characters')
  }
  if (value.reply_to !== undefined && value.reply_to !== null) {
    if (typeof value.reply_to !== 'string' || value.reply_to.length === 0 || utf8Length(value.reply_to) > 1024 || hasControl(value.reply_to)) {
      throw new ContractError(400, 'invalid_reply_to', 'reply_to must be a non-empty opaque message id')
    }
  }
  return {
    text: value.text,
    idempotency_key: value.idempotency_key,
    reply_to: value.reply_to ?? null
  }
}

export function healthPayload (ready) {
  return {
    protocol: PROTOCOL,
    protocol_version: PROTOCOL_VERSION,
    bridge_version: BRIDGE_VERSION,
    ready: ready === true,
    capabilities: ready === true ? [...CAPABILITIES] : []
  }
}

export function utf8Length (value) {
  return b4a.byteLength(value)
}

function hasControl (value) {
  for (const char of value) {
    const code = char.codePointAt(0)
    if (code <= 0x1f || code === 0x7f) return true
  }
  return false
}
