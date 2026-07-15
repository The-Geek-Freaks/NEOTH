'use strict'

const os = require('os')
const path = require('path')
const { spawnSync } = require('child_process')

const root = path.resolve(__dirname, '..')
const host = `${os.platform()}-${os.arch()}`
const supported = new Set([
  'darwin-arm64',
  'darwin-x64',
  'linux-arm64',
  'linux-x64',
  'win32-arm64',
  'win32-x64'
])
if (!supported.has(host)) {
  console.error(`Unsupported platform/arch: ${host}`)
  process.exit(1)
}
const packageFile = require.resolve('bare-build/package', { paths: [root] })
const command = path.join(path.dirname(packageFile), 'bin.js')
const args = [
  command,
  '--name',
  'neoth-keet-bridge',
  '--standalone',
  '--host',
  host,
  '--out',
  path.join(root, 'out', host)
]
if (os.platform() === 'win32') args.push('--runtime', './scripts/windows-runtime.cjs')
args.push(path.join(root, 'bin.mjs'))

const result = spawnSync(process.execPath, args, { cwd: root, stdio: 'inherit' })
if (result.error) {
  console.error(result.error.message)
  process.exit(1)
}
if (result.status !== 0) process.exit(result.status || 1)
