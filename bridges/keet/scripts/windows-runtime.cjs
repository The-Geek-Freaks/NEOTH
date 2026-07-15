'use strict'

const crypto = require('crypto')
const fs = require('fs')
const path = require('path')

const { type: { EXECUTABLE } } = require('bare-build/constants')

const root = path.resolve(__dirname, '..')
// bare-build 1.0.2 sends piped Windows CLI output to NUL. Patch only its
// pinned console-window branch; a changed upstream binary fails closed.
const runtimes = {
  'win32-arm64': {
    module: 'bare-build-win32-arm64',
    sha256: 'ba4968aaa9918a23c12d7a865718277248a24ee99f3fd096af253d5d61bf98a5',
    offset: 0x1826c,
    before: Buffer.from('e00200b5', 'hex'),
    after: Buffer.from('17000014', 'hex')
  },
  'win32-x64': {
    module: 'bare-build-win32-x64',
    sha256: '0fa62fb9e7691c4d57e9764d6331b13483642ba63a745be8821309424e299882',
    offset: 0x1b2d9,
    before: Buffer.from('7557', 'hex'),
    after: Buffer.from('eb57', 'hex')
  }
}

const prebuilds = {}
for (const host of Object.keys(runtimes)) {
  prebuilds[host] = () => ({
    type: EXECUTABLE,
    path: prepare(host)
  })
}

function prepare (host) {
  const runtime = runtimes[host]
  if (!runtime) throw new Error(`unsupported patched Windows runtime: ${host}`)

  const source = require(runtime.module)
  const binary = fs.readFileSync(source)
  const digest = crypto.createHash('sha256').update(binary).digest('hex')
  if (digest !== runtime.sha256) {
    throw new Error(`${runtime.module} changed: expected ${runtime.sha256}, got ${digest}`)
  }
  if (!binary.subarray(runtime.offset, runtime.offset + runtime.before.length).equals(runtime.before)) {
    throw new Error(`${runtime.module} console patch site does not match the pinned runtime`)
  }

  runtime.after.copy(binary, runtime.offset)
  const target = path.join(root, 'out', '.runtime', host, 'bare.exe')
  fs.mkdirSync(path.dirname(target), { recursive: true })
  fs.writeFileSync(target, binary)
  return target
}

module.exports = { prebuilds, prepare }
