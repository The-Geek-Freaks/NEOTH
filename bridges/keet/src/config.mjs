import fs from '#fs'
import path from '#path'

import b4a from 'b4a'

import { assertBearerToken, assertTopicId } from './contract.mjs'
import { fsyncDirectorySync, writeAllSync } from './fs-safety.mjs'
import { securePrivatePath, securePrivatePaths } from './windows-acl.mjs'

const SNAPSHOT_RE = /^config-([1-9][0-9]*)\.json$/

export function defaultBridgeStorage (environment, homeDirectory) {
  const neothHome = environment.NEOTH_HOME
  return typeof neothHome === 'string' && neothHome.length > 0
    ? path.join(neothHome, 'keet-bridge')
    : path.join(homeDirectory, '.neoth', 'keet-bridge')
}

export function ensurePrivateDirectory (directory) {
  preparePrivateDirectory(directory)
  securePrivatePath(path.resolve(directory), { directory: true })
}

export function loadConfig (directory) {
  preparePrivateDirectory(directory)
  const snapshots = fs.readdirSync(directory)
    .map((name) => {
      const match = SNAPSHOT_RE.exec(name)
      return match ? { name, generation: Number(match[1]) } : null
    })
    .filter(Boolean)
    .sort((left, right) => right.generation - left.generation)
  securePrivatePaths([
    { target: path.resolve(directory), directory: true },
    ...snapshots.map((snapshot) => ({ target: path.resolve(directory, snapshot.name), directory: false }))
  ])

  for (const snapshot of snapshots) {
    const filename = path.join(directory, snapshot.name)
    const bytes = fs.readFileSync(filename)
    if (bytes.byteLength === 0 || bytes[bytes.byteLength - 1] !== 0x0a) {
      // A torn newest snapshot is ignored; the previous fsync'd generation
      // remains authoritative on every supported platform.
      continue
    }
    if (bytes.byteLength > 1024 * 1024) throw new Error(`bridge config snapshot is oversized: ${snapshot.name}`)
    const config = validateConfig(JSON.parse(bytes.toString('utf8')))
    if (config.generation !== snapshot.generation) throw new Error(`bridge config generation mismatch: ${snapshot.name}`)
    return config
  }
  return null
}

function preparePrivateDirectory (directory) {
  const resolved = path.resolve(directory)
  const existed = pathExists(resolved)
  fs.mkdirSync(directory, { recursive: true, mode: 0o700 })
  try { fs.chmodSync(directory, 0o700) } catch (error) {
    if (error.code !== 'ENOSYS' && error.code !== 'EPERM') throw error
  }
  if (!existed) fsyncDirectorySync(path.dirname(resolved))
}

export function saveConfig (directory, input) {
  ensurePrivateDirectory(directory)
  const highest = fs.readdirSync(directory).reduce((current, name) => {
    const match = SNAPSHOT_RE.exec(name)
    return match ? Math.max(current, Number(match[1])) : current
  }, 0)
  const config = validateConfig({ ...input, generation: highest + 1 })
  const filename = path.join(directory, `config-${config.generation}.json`)
  const handle = fs.openSync(filename, 'wx', 0o600)
  try {
    writeAllSync(handle, `${JSON.stringify(config)}\n`)
    fs.fsyncSync(handle)
  } finally {
    fs.closeSync(handle)
  }
  try { fs.chmodSync(filename, 0o600) } catch (error) {
    if (error.code !== 'ENOSYS' && error.code !== 'EPERM') throw error
  }
  securePrivatePath(path.resolve(filename), { directory: false })
  fsyncDirectorySync(path.resolve(directory))
  return config
}

export function validateConfig (value) {
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid bridge config')
  if (value.version !== 1 || !Number.isSafeInteger(value.generation) || value.generation < 1) throw new Error('unsupported bridge config')
  assertBearerToken(value.bearer_token)
  if (typeof value.mnemonic !== 'string' || value.mnemonic.trim().split(/\s+/).length !== 24) throw new Error('invalid Keet identity mnemonic')
  if (typeof value.display_name !== 'string' || value.display_name.trim() !== value.display_name || value.display_name.length === 0 || utf8Length(value.display_name) > 256 || hasControl(value.display_name)) throw new Error('invalid display name')
  if (!Array.isArray(value.topics) || value.topics.length > 128) throw new Error('invalid topic list')
  const topics = [...new Set(value.topics.map(assertTopicId))].sort()
  return {
    version: 1,
    generation: value.generation,
    bearer_token: value.bearer_token,
    mnemonic: value.mnemonic,
    display_name: value.display_name,
    topics
  }
}

function utf8Length (value) {
  return b4a.byteLength(value)
}

function hasControl (value) {
  for (const character of value) {
    const code = character.codePointAt(0)
    if (code <= 0x1f || code === 0x7f) return true
  }
  return false
}

function pathExists (target) {
  try {
    fs.statSync(target)
    return true
  } catch (error) {
    if (error.code === 'ENOENT') return false
    throw error
  }
}

export function addTopic (directory, topic) {
  assertTopicId(topic)
  const current = loadConfig(directory)
  if (!current) throw new Error('bridge is not set up; run setup first')
  if (current.topics.includes(topic)) return current
  return saveConfig(directory, { ...current, topics: [...current.topics, topic] })
}

export function removeTopic (directory, topic) {
  assertTopicId(topic)
  const current = loadConfig(directory)
  if (!current) throw new Error('bridge is not set up; run setup first')
  if (!current.topics.includes(topic)) return current
  return saveConfig(directory, { ...current, topics: current.topics.filter((candidate) => candidate !== topic) })
}
