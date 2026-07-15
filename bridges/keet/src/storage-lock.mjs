import fs from '#fs'
import http from '#http'
import path from '#path'
import process from '#process'
import subprocess from '#subprocess'

import b4a from 'b4a'
import hypercoreCrypto from 'hypercore-crypto'

import { fsyncDirectorySync, writeAllSync } from './fs-safety.mjs'

const LOCK_NAME = 'serve.lock'
const RECOVERY_NAME = '.serve-lock-recovery'
const RECOVERY_OWNER = 'owner.json'
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/
const RECOVERY_ATTEMPTS = 32
const REPAIR_PERMIT = Symbol('storage-repair-permit')
const WINDOWS_START_SCRIPT = `$ErrorActionPreference = 'Stop'
$target = [int]$env:NEOTH_LOCK_PID
$value = [System.Diagnostics.Process]::GetProcessById($target).StartTime.ToUniversalTime().Ticks
[Console]::Out.Write($value.ToString())`

export class StorageLockError extends Error {
  constructor (code, message) {
    super(message)
    this.name = 'StorageLockError'
    this.code = code
  }
}

export class StorageLock {
  static acquire (storage) {
    const directory = path.resolve(storage)
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 })
    const owner = newOwnerRecord()
    const recovery = RecoveryMutex.acquire(directory, owner)
    const lockPath = path.join(directory, LOCK_NAME)
    let claimed = false
    let failure = null
    try {
      if (pathExists(lockPath)) {
        let current
        try { current = readClaim(lockPath) } catch (error) {
          throw new StorageLockError('unsafe_storage_lock', `storage has an invalid lock at ${lockPath}; run repair-lock only after its process/listener checks pass (${error.message})`)
        }
        const state = ownerState(current)
        if (state === 'live') throw new StorageLockError('storage_lock_held', `storage is already owned by live neoth-keet-bridge pid ${current.pid}`)
        if (state === 'ambiguous') throw new StorageLockError('unsafe_storage_lock', `storage lock owner pid ${current.pid} could not be identified safely`)
        fs.unlinkSync(lockPath)
        fsyncDirectorySync(directory)
      }
      claimFile(directory, lockPath, owner)
      claimed = true
    } catch (error) {
      failure = error
    }
    try { recovery.close() } catch (error) {
      failure = failure ? new AggregateError([failure, error], 'storage claim and recovery-mutex release both failed') : error
    }
    if (failure) {
      if (claimed) {
        try { removeOwnedClaim(lockPath, owner); fsyncDirectorySync(directory) } catch (error) {
          throw new AggregateError([failure, error], 'storage lock acquisition rollback failed')
        }
      }
      throw failure
    }
    return new StorageLock(directory, lockPath, owner)
  }

  static repair (storage, permit) {
    const directory = path.resolve(storage)
    if (!permit || permit[REPAIR_PERMIT] !== directory) throw new StorageLockError('repair_not_verified', 'repair-lock requires a fresh no-listener/no-process verification')
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 })
    const owner = newOwnerRecord()
    const recovery = RecoveryMutex.acquire(directory, owner)
    const lockPath = path.join(directory, LOCK_NAME)
    let repaired = false
    let failure = null
    try {
      if (pathExists(lockPath)) {
        let current = null
        try { current = readClaim(lockPath) } catch {}
        if (current) {
          const state = ownerState(current)
          if (state === 'live') throw new StorageLockError('storage_lock_held', `refusing to repair a lock owned by live pid ${current.pid}`)
          if (state === 'ambiguous') throw new StorageLockError('unsafe_storage_lock', `refusing to repair an ambiguous lock owner pid ${current.pid}`)
        }
        fs.unlinkSync(lockPath)
        fsyncDirectorySync(directory)
        repaired = true
      }
    } catch (error) {
      failure = error
    } finally {
      try { recovery.close() } catch (error) {
        failure = failure ? new AggregateError([failure, error], 'storage repair and recovery-mutex release both failed') : error
      }
    }
    if (failure) throw failure
    return repaired
  }

  constructor (directory, lockPath, owner) {
    this.directory = directory
    this.lockPath = lockPath
    this.owner = owner
    this.closed = false
  }

  close () {
    if (this.closed) return
    removeOwnedClaim(this.lockPath, this.owner)
    this.closed = true
    fsyncDirectorySync(this.directory)
  }
}

export async function verifyStorageIdle (storage, { host = '127.0.0.1', port = 9130 } = {}) {
  const directory = path.resolve(storage)
  if (host !== '127.0.0.1' && host !== '::1') throw new Error('storage repair host must be numeric loopback')
  if (!Number.isSafeInteger(port) || port < 1 || port > 65535) throw new Error('storage repair port must be 1..65535')
  await assertNoListener(host, port)
  if (knownBridgeProcess(directory)) {
    throw new StorageLockError('repair_process_active', 'another neoth-keet-bridge/Bare serve process is still visible; refusing lock repair')
  }
  return Object.freeze({ [REPAIR_PERMIT]: directory })
}

class RecoveryMutex {
  static acquire (directory, owner) {
    const mutexPath = path.join(directory, RECOVERY_NAME)
    for (let attempt = 0; attempt < RECOVERY_ATTEMPTS; attempt++) {
      const temporaryPath = path.join(directory, `.serve-lock-recovery-${owner.pid}-${randomToken()}.tmp`)
      createClaimDirectory(temporaryPath, owner)
      try {
        fs.renameSync(temporaryPath, mutexPath)
        fsyncDirectorySync(directory)
        return new RecoveryMutex(directory, mutexPath, owner)
      } catch (error) {
        try { removeClaimDirectory(temporaryPath, owner.token) } catch (cleanupError) {
          throw new AggregateError([error, cleanupError], 'recovery-mutex contender cleanup failed')
        }
        if (!pathExists(mutexPath)) {
          if (renameCollision(error)) continue
          throw error
        }
      }

      let current
      try { current = readClaim(path.join(mutexPath, RECOVERY_OWNER)) } catch (error) {
        throw new StorageLockError('unsafe_recovery_lock', `storage recovery mutex is invalid; refusing unsafe recovery (${error.message})`)
      }
      const state = ownerState(current)
      if (state === 'live') throw new StorageLockError('storage_recovery_held', `storage recovery is already in progress in live pid ${current.pid}`)
      if (state === 'ambiguous') throw new StorageLockError('unsafe_recovery_lock', `storage recovery owner pid ${current.pid} is ambiguous`)

      const quarantine = path.join(directory, `.serve-lock-recovery-stale-${current.token}`)
      if (pathExists(quarantine)) {
        removeClaimDirectory(quarantine, current.token)
        fsyncDirectorySync(directory)
        continue
      }
      try {
        fs.renameSync(mutexPath, quarantine)
      } catch (error) {
        if (renameCollision(error) || !pathExists(mutexPath)) continue
        throw error
      }
      removeClaimDirectory(quarantine, current.token)
      fsyncDirectorySync(directory)
    }
    throw new StorageLockError('storage_recovery_contended', 'storage recovery remained contended after the bounded retry budget')
  }

  constructor (directory, mutexPath, owner) {
    this.directory = directory
    this.mutexPath = mutexPath
    this.owner = owner
    this.closed = false
  }

  close () {
    if (this.closed) return
    removeClaimDirectory(this.mutexPath, this.owner.token)
    this.closed = true
    fsyncDirectorySync(this.directory)
  }
}

function newOwnerRecord () {
  const observed = observeProcess(process.pid)
  if (observed.state !== 'live') throw new StorageLockError('process_identity_unavailable', 'could not prove the current process start identity for storage locking')
  return {
    version: 1,
    pid: process.pid,
    process_start_id: observed.id,
    started_at_ms: Date.now(),
    token: randomToken()
  }
}

function ownerState (record) {
  const observed = observeProcess(record.pid)
  if (observed.state === 'dead') return 'stale'
  if (observed.state !== 'live') return 'ambiguous'
  return observed.id === record.process_start_id ? 'live' : 'stale'
}

function observeProcess (pid) {
  try {
    process.kill(pid, 0)
  } catch (error) {
    if (error.code === 'ESRCH') return { state: 'dead' }
    if (error.code !== 'EPERM') return { state: 'ambiguous' }
  }

  const platform = globalThis.Bare?.platform || process.platform
  let raw
  try {
    if (platform === 'linux') raw = linuxProcessStart(pid)
    else if (platform === 'win32') raw = windowsProcessStart(pid)
    else if (platform === 'darwin') raw = darwinProcessStart(pid)
    else return { state: 'ambiguous' }
  } catch (error) {
    try { process.kill(pid, 0) } catch (checkError) {
      if (checkError.code === 'ESRCH') return { state: 'dead' }
    }
    return { state: 'ambiguous' }
  }
  return { state: 'live', id: identityHash(platform, raw) }
}

function linuxProcessStart (pid) {
  const boot = b4a.toString(fs.readFileSync('/proc/sys/kernel/random/boot_id')).trim()
  const stat = b4a.toString(fs.readFileSync(`/proc/${pid}/stat`))
  const end = stat.lastIndexOf(')')
  if (!/^[0-9a-f-]{36}$/i.test(boot) || end < 2) throw new Error('invalid Linux process identity')
  const fields = stat.slice(end + 2).trim().split(/\s+/)
  const startTicks = fields[19]
  if (!/^[0-9]+$/.test(startTicks || '')) throw new Error('invalid Linux process start ticks')
  return `${boot}:${startTicks}`
}

function windowsProcessStart (pid) {
  const result = subprocess.spawnSync('powershell.exe', [
    '-NoLogo',
    '-NoProfile',
    '-NonInteractive',
    '-Command',
    WINDOWS_START_SCRIPT
  ], {
    env: { ...process.env, NEOTH_LOCK_PID: String(pid) },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
    maxBuffer: 16 * 1024
  })
  if (result.error || result.status !== 0) throw result.error || new Error('Windows process identity query failed')
  const value = b4a.toString(result.stdout).trim()
  if (!/^[0-9]+$/.test(value)) throw new Error('invalid Windows process start ticks')
  return value
}

function darwinProcessStart (pid) {
  const result = subprocess.spawnSync('ps', ['-o', 'lstart=', '-p', String(pid)], {
    env: { ...process.env, LC_ALL: 'C' },
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 16 * 1024
  })
  if (result.error || result.status !== 0) throw result.error || new Error('macOS process identity query failed')
  const value = b4a.toString(result.stdout).trim().replace(/\s+/g, ' ')
  if (value.length < 16 || value.length > 128) throw new Error('invalid macOS process start value')
  return value
}

async function assertNoListener (host, port) {
  await new Promise((resolve, reject) => {
    let settled = false
    const finish = (error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      if (error) reject(error)
      else resolve()
    }
    const request = http.request({ host, port, path: '/v1/health', method: 'GET' }, (response) => {
      if (typeof response.resume === 'function') response.resume()
      finish(new StorageLockError('repair_listener_active', `a listener is active on ${host}:${port}; refusing lock repair`))
    })
    request.on('error', (error) => {
      if (['ECONNREFUSED', 'EHOSTUNREACH', 'ENETUNREACH'].includes(error.code)) finish(null)
      else finish(new StorageLockError('repair_listener_ambiguous', `could not prove ${host}:${port} is idle (${error.message})`))
    })
    const timer = setTimeout(() => {
      try { request.destroy() } catch {}
      finish(new StorageLockError('repair_listener_active', `listener probe on ${host}:${port} did not refuse the connection`))
    }, 1000)
    request.end()
  })
}

function knownBridgeProcess (storage) {
  const platform = globalThis.Bare?.platform || process.platform
  if (platform === 'linux') return knownLinuxBridgeProcess(storage)
  if (platform === 'win32') return knownWindowsBridgeProcess()
  if (platform === 'darwin') return knownDarwinBridgeProcess(storage)
  throw new StorageLockError('repair_process_ambiguous', `process verification is unsupported on ${platform}`)
}

function knownLinuxBridgeProcess (storage) {
  for (const name of fs.readdirSync('/proc')) {
    if (!/^[1-9][0-9]*$/.test(name) || Number(name) === process.pid) continue
    let command
    let executable
    try {
      command = b4a.toString(fs.readFileSync(`/proc/${name}/cmdline`)).replace(/\0/g, ' ')
      executable = b4a.toString(fs.readFileSync(`/proc/${name}/comm`)).trim()
    } catch (error) {
      if (error.code === 'ENOENT') continue
      throw new StorageLockError('repair_process_ambiguous', `could not inspect process ${name}`)
    }
    if (bridgeProcessMatch(executable, command, storage)) return true
  }
  return false
}

function knownWindowsBridgeProcess () {
  const script = `$ErrorActionPreference = 'Stop'
$self = [int]$env:NEOTH_LOCK_PID
$matches = @([System.Diagnostics.Process]::GetProcesses() | Where-Object {
  $_.Id -ne $self -and ($_.ProcessName -eq 'neoth-keet-bridge' -or $_.ProcessName -eq 'bare')
})
[Console]::Out.Write($matches.Count.ToString())`
  const result = subprocess.spawnSync('powershell.exe', ['-NoLogo', '-NoProfile', '-NonInteractive', '-Command', script], {
    env: { ...process.env, NEOTH_LOCK_PID: String(process.pid) },
    stdio: ['ignore', 'pipe', 'pipe'],
    windowsHide: true,
    maxBuffer: 16 * 1024
  })
  if (result.error || result.status !== 0) throw new StorageLockError('repair_process_ambiguous', 'could not enumerate Windows bridge processes')
  const count = b4a.toString(result.stdout).trim()
  if (!/^[0-9]+$/.test(count)) throw new StorageLockError('repair_process_ambiguous', 'Windows bridge process check returned invalid output')
  return Number(count) > 0
}

function knownDarwinBridgeProcess (storage) {
  const result = subprocess.spawnSync('ps', ['-axo', 'pid=,comm=,args='], {
    env: { ...process.env, LC_ALL: 'C' },
    stdio: ['ignore', 'pipe', 'pipe'],
    maxBuffer: 4 * 1024 * 1024
  })
  if (result.error || result.status !== 0) throw new StorageLockError('repair_process_ambiguous', 'could not enumerate macOS bridge processes')
  for (const line of b4a.toString(result.stdout).split('\n')) {
    const match = /^\s*([0-9]+)\s+(\S+)\s+(.*)$/.exec(line)
    if (!match || Number(match[1]) === process.pid) continue
    if (bridgeProcessMatch(path.basename(match[2]), match[3], storage)) return true
  }
  return false
}

function bridgeProcessMatch (executable, command, storage) {
  const normalized = executable.toLowerCase().replace(/\.exe$/, '')
  if (normalized === 'neoth-keet-bridge' || normalized === 'bare') return true
  if (/\bbin\.mjs\b/.test(command) && /\bserve\b/.test(command)) return true
  return command.includes(storage) && command.includes('neoth-keet-bridge')
}

function identityHash (platform, value) {
  return b4a.toString(hypercoreCrypto.hash([
    b4a.from('neoth-keet-bridge/process-start/v1\0'),
    b4a.from(platform),
    b4a.from('\0'),
    b4a.from(value)
  ]), 'base64url')
}

function randomToken () {
  return b4a.toString(hypercoreCrypto.randomBytes(32), 'base64url')
}

function claimFile (directory, lockPath, owner) {
  const temporaryPath = path.join(directory, `.serve-lock-${owner.pid}-${owner.token}.tmp`)
  writeCompleteClaim(temporaryPath, owner)
  let linked = false
  let failure = null
  try {
    fs.linkSync(temporaryPath, lockPath)
    linked = true
  } catch (error) {
    failure = error
  }
  try { fs.unlinkSync(temporaryPath) } catch (error) {
    failure = failure ? new AggregateError([failure, error], 'storage lock claim cleanup failed') : error
  }
  if (failure) {
    if (linked) {
      try { fs.unlinkSync(lockPath) } catch (rollbackError) {
        throw new AggregateError([failure, rollbackError], 'storage lock claim rollback failed')
      }
    }
    throw failure
  }
  fsyncDirectorySync(directory)
}

function createClaimDirectory (directory, owner) {
  fs.mkdirSync(directory, { mode: 0o700 })
  try {
    writeCompleteClaim(path.join(directory, RECOVERY_OWNER), owner)
    fsyncDirectorySync(directory)
  } catch (error) {
    try { removeClaimDirectory(directory, owner.token) } catch (cleanupError) {
      throw new AggregateError([error, cleanupError], 'recovery claim directory cleanup failed')
    }
    throw error
  }
}

function removeClaimDirectory (directory, expectedToken) {
  const ownerPath = path.join(directory, RECOVERY_OWNER)
  const current = readClaim(ownerPath)
  if (current.token !== expectedToken) throw new StorageLockError('storage_recovery_changed', 'recovery mutex ownership changed; refusing to remove it')
  fs.unlinkSync(ownerPath)
  fs.rmdirSync(directory)
}

function writeCompleteClaim (filename, record) {
  const handle = fs.openSync(filename, 'wx', 0o600)
  let failure = null
  try {
    writeAllSync(handle, `${JSON.stringify(record)}\n`)
    fs.fsyncSync(handle)
  } catch (error) {
    failure = error
  }
  try { fs.closeSync(handle) } catch (error) {
    failure = failure ? new AggregateError([failure, error], 'storage claim write and close both failed') : error
  }
  if (failure) {
    try { fs.unlinkSync(filename) } catch (cleanupError) {
      throw new AggregateError([failure, cleanupError], 'storage claim cleanup failed')
    }
    throw failure
  }
}

function removeOwnedClaim (filename, expected) {
  const current = readClaim(filename)
  if (current.token !== expected.token || current.pid !== expected.pid || current.process_start_id !== expected.process_start_id) {
    throw new StorageLockError('storage_lock_changed', 'storage lock ownership changed; refusing to remove it')
  }
  fs.unlinkSync(filename)
}

function readClaim (filename) {
  const bytes = fs.readFileSync(filename)
  if (bytes.byteLength === 0 || bytes.byteLength > 4096 || bytes[bytes.byteLength - 1] !== 0x0a) throw new Error('incomplete storage claim')
  const value = JSON.parse(b4a.toString(bytes))
  if (value === null || typeof value !== 'object' || Array.isArray(value)) throw new Error('invalid storage claim')
  if (Object.keys(value).sort().join(',') !== 'pid,process_start_id,started_at_ms,token,version') throw new Error('unknown storage claim field')
  if (value.version !== 1 || !Number.isSafeInteger(value.pid) || value.pid < 1) throw new Error('invalid storage claim owner')
  if (!Number.isSafeInteger(value.started_at_ms) || value.started_at_ms < 0) throw new Error('invalid storage claim timestamp')
  if (!canonicalToken(value.token) || !canonicalToken(value.process_start_id)) throw new Error('invalid storage claim identity')
  return value
}

function canonicalToken (value) {
  if (typeof value !== 'string' || !TOKEN_RE.test(value)) return false
  const decoded = b4a.from(value, 'base64url')
  return decoded.byteLength === 32 && b4a.toString(decoded, 'base64url') === value
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

function renameCollision (error) {
  return ['EACCES', 'EEXIST', 'ENOENT', 'ENOTEMPTY', 'EPERM'].includes(error?.code)
}
