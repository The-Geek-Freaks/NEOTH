import http from '#http'
import { URL } from '#url'

import b4a from 'b4a'
import sodium from 'sodium-universal'

import {
  ContractError,
  MAX_CONTROL_BODY,
  assertBearerToken,
  assertTopicId,
  healthPayload,
  parsePollQuery,
  validatePostMessage
} from './contract.mjs'

const REQUEST_BODY_LIMIT = MAX_CONTROL_BODY + 4096

export class BridgeHttpServer {
  constructor ({ service, token, host = '127.0.0.1', port = 9130, onError = (error) => console.error('[http]', error.message) }) {
    assertBearerToken(token)
    if (host !== '127.0.0.1' && host !== '::1') throw new Error('bridge HTTP host must be numeric loopback')
    if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('bridge HTTP port must be 1..65535')
    this.service = service
    this.token = token
    this.host = host
    this.port = port
    this.onError = onError
    this.server = null
  }

  async open () {
    if (this.server) return
    const server = http.createServer((request, response) => {
      this.#handle(request, response).catch((error) => this.#respondError(response, error))
    })
    if ('headersTimeout' in server) server.headersTimeout = 5000
    if ('requestTimeout' in server) server.requestTimeout = 35_000
    if ('keepAliveTimeout' in server) server.keepAliveTimeout = 5000
    await new Promise((resolve, reject) => {
      const onError = (error) => {
        server.off('listening', onListening)
        reject(error)
      }
      const onListening = () => {
        server.off('error', onError)
        resolve()
      }
      server.once('error', onError)
      server.once('listening', onListening)
      server.listen(this.port, this.host)
    })
    this.server = server
  }

  async close () {
    if (!this.server) return
    const server = this.server
    this.server = null
    await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
  }

  async #handle (request, response) {
    this.#authenticate(request)
    let url
    const authority = this.host === '::1' ? '[::1]' : this.host
    try { url = new URL(request.url, `http://${authority}:${this.port}`) } catch {
      throw new ContractError(400, 'invalid_url', 'request URL is invalid')
    }

    if (request.method === 'GET' && url.pathname === '/v1/health') {
      assertNoQuery(url)
      return sendJson(response, 200, healthPayload(this.service.ready))
    }

    const route = /^\/v1\/topics\/([^/]+)(\/messages)?$/.exec(url.pathname)
    if (!route) throw new ContractError(404, 'not_found', 'endpoint not found')
    let topic
    try { topic = decodeURIComponent(route[1]) } catch {
      throw new ContractError(400, 'invalid_topic_encoding', 'topic path segment has invalid percent encoding')
    }
    assertTopicId(topic)

    if (!route[2] && request.method === 'GET') {
      assertNoQuery(url)
      return sendJson(response, 200, this.service.topicState(topic))
    }
    if (route[2] && request.method === 'GET') {
      const query = parsePollQuery(url.searchParams)
      const page = await this.service.poll(topic, query.sequence, query.waitMs, query.limit)
      return sendJson(response, 200, page)
    }
    if (route[2] && request.method === 'POST') {
      assertNoQuery(url)
      const body = validatePostMessage(await readJson(request))
      return sendJson(response, 200, this.service.post(topic, body))
    }
    throw new ContractError(405, 'method_not_allowed', 'method is not allowed for this endpoint')
  }

  #authenticate (request) {
    const header = request.headers.authorization
    if (typeof header !== 'string' || !header.startsWith('Bearer ')) throw new ContractError(401, 'unauthorized', 'bearer authentication required')
    const candidate = header.slice(7)
    const expectedBytes = b4a.from(this.token)
    const candidateBytes = b4a.from(candidate)
    if (candidateBytes.byteLength !== expectedBytes.byteLength || !sodium.sodium_memcmp(candidateBytes, expectedBytes)) {
      throw new ContractError(401, 'unauthorized', 'bearer authentication failed')
    }
  }

  #respondError (response, error) {
    if (response.headersSent || response.destroyed) return
    if (error instanceof ContractError) return sendJson(response, error.status, { error: { code: error.code, message: error.message } })
    this.onError(error)
    return sendJson(response, 500, { error: { code: 'internal_error', message: 'bridge operation failed' } })
  }
}

async function readJson (request) {
  const contentType = request.headers['content-type'] || ''
  if (!/^application\/json(?:\s*;|$)/i.test(contentType)) throw new ContractError(415, 'content_type', 'Content-Type must be application/json')
  const declared = request.headers['content-length']
  if (declared !== undefined) {
    if (!/^(0|[1-9][0-9]*)$/.test(declared) || Number(declared) > REQUEST_BODY_LIMIT) throw new ContractError(413, 'body_too_large', 'request body exceeds its safety limit')
  }
  const chunks = []
  let length = 0
  let overflow = false
  await new Promise((resolve, reject) => {
    request.on('data', (chunk) => {
      length += chunk.byteLength
      if (length > REQUEST_BODY_LIMIT) {
        overflow = true
        return
      }
      chunks.push(chunk)
    })
    request.on('end', resolve)
    request.on('error', reject)
  })
  if (overflow) throw new ContractError(413, 'body_too_large', 'request body exceeds its safety limit')
  let parsed
  try { parsed = JSON.parse(b4a.toString(b4a.concat(chunks, length))) } catch {
    throw new ContractError(400, 'invalid_json', 'request body is not valid JSON')
  }
  return parsed
}

function assertNoQuery (url) {
  if (url.search !== '') throw new ContractError(400, 'invalid_query', 'this endpoint accepts no query parameters')
}

function sendJson (response, status, value) {
  const body = JSON.stringify(value)
  response.statusCode = status
  response.setHeader('Content-Type', 'application/json; charset=utf-8')
  response.setHeader('Content-Length', b4a.byteLength(body))
  response.setHeader('Cache-Control', 'no-store')
  response.setHeader('X-Content-Type-Options', 'nosniff')
  response.end(body)
}
