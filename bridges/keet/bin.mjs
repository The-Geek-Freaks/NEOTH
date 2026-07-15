#!/usr/bin/env node

import os from '#os'
import path from '#path'
import process from '#process'

import b4a from 'b4a'

import { KeetBridgeService } from './src/bridge.mjs'
import { addTopic, loadConfig, removeTopic, saveConfig } from './src/config.mjs'
import { BridgeHttpServer } from './src/server.mjs'
import { createIdentity, generateMnemonic, randomToken, randomTopicId } from './src/identity.mjs'
import { closeRuntime, createShutdownHandler } from './src/shutdown.mjs'
import { StorageLock, verifyStorageIdle } from './src/storage-lock.mjs'

const VERSION = '1.0.0'
const argv = globalThis.Bare
  ? Bare.argv.slice(import.meta.url.startsWith('bare:') ? 1 : 2)
  : process.argv.slice(2)

try {
  await main(argv)
} catch (error) {
  console.error(`neoth-keet-bridge: ${error.message}`)
  exit(1)
}

async function main (args) {
  const parsed = parseArgs(args)
  if (parsed.help) return printHelp()
  if (parsed.version) return console.log(VERSION)

  if (parsed.command === 'setup') return setup(parsed)
  if (parsed.command === 'identity') return identity(parsed)
  if (parsed.command === 'topic') return topicCommand(parsed)
  if (parsed.command === 'repair-lock') return repairLock(parsed)
  if (parsed.command === 'serve') return serve(parsed)
  throw new Error(`unknown command: ${parsed.command}`)
}

async function repairLock (options) {
  const permit = await verifyStorageIdle(options.storage, { host: options.host, port: options.port })
  const repaired = StorageLock.repair(options.storage, permit)
  console.log(repaired ? 'removed verified-idle storage lock' : 'storage lock is already clear')
}

async function setup (options) {
  let config = loadConfig(options.storage)
  if (!config) {
    config = saveConfig(options.storage, {
      version: 1,
      bearer_token: randomToken(),
      mnemonic: generateMnemonic(),
      display_name: options.displayName,
      topics: [randomTopicId()]
    })
  }
  const state = await createIdentity(config.mnemonic)
  const output = {
    bridge_url: `http://${formatHost(options.host)}:${options.port}`,
    bearer_token: config.bearer_token,
    topic: config.topics[0] || null,
    self_id: state.selfId,
    storage: options.storage
  }
  state.close()
  console.log(JSON.stringify(output))
}

async function identity (options) {
  const config = requireConfig(options.storage)
  const state = await createIdentity(config.mnemonic)
  console.log(state.selfId)
  state.close()
}

function topicCommand (options) {
  if (options.topicAction === 'create') {
    const created = randomTopicId()
    addTopic(options.storage, created)
    console.log(created)
    return
  }
  if (options.topicAction === 'join') {
    addTopic(options.storage, options.topicValue)
    console.log(options.topicValue)
    return
  }
  if (options.topicAction === 'leave') {
    removeTopic(options.storage, options.topicValue)
    console.log(options.topicValue)
    return
  }
  if (options.topicAction === 'list') {
    const config = requireConfig(options.storage)
    for (const configured of config.topics) console.log(configured)
    return
  }
  throw new Error('topic command must be create, join, leave, or list')
}

async function serve (options) {
  const config = requireConfig(options.storage)
  const onError = (error) => console.error(`[bridge] ${error.message}`)
  let pendingFatal = null
  let shutdown = null
  const service = new KeetBridgeService({
    storage: options.storage,
    config,
    onError,
    onFatal: (error) => {
      pendingFatal = pendingFatal || error
      if (shutdown) shutdown(error)
    }
  })
  const server = new BridgeHttpServer({
    service,
    token: config.bearer_token,
    host: options.host,
    port: options.port,
    onError
  })
  const storageLock = StorageLock.acquire(options.storage)
  try {
    await service.open()
    await server.open()
  } catch (error) {
    try { await closeRuntime(server, service, storageLock) } catch (closeError) {
      throw new AggregateError([error, closeError], 'bridge startup and rollback both failed')
    }
    throw error
  }

  shutdown = createShutdownHandler({
    server,
    service,
    storageLock,
    onError: (error) => console.error(`neoth-keet-bridge: shutdown failed: ${error.message}`),
    exit
  })
  process.once('SIGINT', () => shutdown())
  process.once('SIGTERM', () => shutdown())
  if (pendingFatal) return shutdown(pendingFatal)
  console.log(`neoth-keet-bridge ${VERSION} ready on http://${formatHost(options.host)}:${options.port}`)
  console.log(`identity ${service.selfId}; ${config.topics.length} provisioned topic(s)`)
}

function parseArgs (args) {
  const result = {
    command: 'serve',
    storage: path.join(os.homedir(), '.neoth', 'keet-bridge'),
    host: '127.0.0.1',
    port: 9130,
    displayName: 'NEOTH',
    topicAction: null,
    topicValue: null,
    help: false,
    version: false
  }
  const positional = []
  for (let index = 0; index < args.length; index++) {
    const argument = args[index]
    if (argument === '--help' || argument === '-h') result.help = true
    else if (argument === '--version' || argument === '-V') result.version = true
    else if (argument === '--storage') result.storage = requireValue(args, ++index, argument)
    else if (argument === '--host') result.host = requireValue(args, ++index, argument)
    else if (argument === '--port') result.port = parsePort(requireValue(args, ++index, argument))
    else if (argument === '--display-name') result.displayName = requireValue(args, ++index, argument)
    else if (argument.startsWith('-')) throw new Error(`unknown option: ${argument}`)
    else positional.push(argument)
  }
  if (positional.length > 0) result.command = positional.shift()
  if (result.command === 'topic') {
    result.topicAction = positional.shift() || null
    result.topicValue = positional.shift() || null
  }
  if (positional.length > 0) throw new Error(`unexpected argument: ${positional[0]}`)
  if (result.host !== '127.0.0.1' && result.host !== '::1') throw new Error('--host must be 127.0.0.1 or ::1')
  if (result.displayName.trim() !== result.displayName || result.displayName.length === 0 || b4a.byteLength(result.displayName) > 256) throw new Error('--display-name must contain 1..256 UTF-8 bytes without edge whitespace')
  return result
}

function requireConfig (storage) {
  const config = loadConfig(storage)
  if (!config) throw new Error(`bridge is not set up at ${storage}; run neoth-keet-bridge setup first`)
  return config
}

function requireValue (args, index, option) {
  if (index >= args.length || args[index].startsWith('-')) throw new Error(`${option} requires a value`)
  return args[index]
}

function parsePort (value) {
  if (!/^[1-9][0-9]{0,4}$/.test(value)) throw new Error('--port must be 1..65535')
  const port = Number(value)
  if (port > 65535) throw new Error('--port must be 1..65535')
  return port
}

function formatHost (host) {
  return host === '::1' ? '[::1]' : host
}

function exit (code) {
  if (globalThis.Bare) Bare.exit(code)
  else process.exit(code)
}

function printHelp () {
  console.log(`neoth-keet-bridge ${VERSION}

Usage:
  neoth-keet-bridge setup [--storage DIR] [--display-name NAME]
  neoth-keet-bridge serve [--storage DIR] [--host 127.0.0.1|::1] [--port 9130]
  neoth-keet-bridge identity [--storage DIR]
  neoth-keet-bridge topic create [--storage DIR]
  neoth-keet-bridge topic join TOPIC [--storage DIR]
  neoth-keet-bridge topic leave TOPIC [--storage DIR]
  neoth-keet-bridge topic list [--storage DIR]
  neoth-keet-bridge repair-lock [--storage DIR] [--host 127.0.0.1|::1] [--port 9130]

setup prints one sensitive JSON record for wiring NEOTH. Protect it like a password.
Topic IDs are capability secrets: share them only with peers intended for that topic.`)
}
