import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { StorageLock, StorageLockError, verifyStorageIdle } from '../src/storage-lock.mjs'

test('storage lock admits one writer and releases only its own claim', (context) => {
  const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'neoth-keet-lock-'))
  context.after(() => fs.rmSync(storage, { recursive: true, force: true }))
  const first = StorageLock.acquire(storage)
  assert.equal(fs.existsSync(path.join(storage, 'serve.lock')), true)
  assert.throws(() => StorageLock.acquire(storage), (error) => {
    return error instanceof StorageLockError && error.code === 'storage_lock_held'
  })
  first.close()
  assert.equal(fs.existsSync(path.join(storage, 'serve.lock')), false)

  const second = StorageLock.acquire(storage)
  second.close()
  assert.deepEqual(fs.readdirSync(storage), [])
})

test('a provably dead owner is recovered while malformed claims need verified repair', async (context) => {
  const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'neoth-keet-lock-'))
  context.after(() => fs.rmSync(storage, { recursive: true, force: true }))
  const filename = path.join(storage, 'serve.lock')
  fs.writeFileSync(filename, `${JSON.stringify({
    version: 1,
    pid: 999999,
    process_start_id: 'A'.repeat(43),
    started_at_ms: 1,
    token: 'A'.repeat(43)
  })}\n`)
  const recovered = StorageLock.acquire(storage)
  const live = JSON.parse(fs.readFileSync(filename, 'utf8'))
  assert.equal(live.pid, process.pid)
  recovered.close()

  fs.writeFileSync(filename, '{"partial":')
  assert.throws(() => StorageLock.acquire(storage), (error) => {
    return error instanceof StorageLockError && error.code === 'unsafe_storage_lock'
  })
  assert.equal(fs.readFileSync(filename, 'utf8'), '{"partial":')
  assert.throws(() => StorageLock.repair(storage), (error) => {
    return error instanceof StorageLockError && error.code === 'repair_not_verified'
  })
  const port = await unusedPort()
  const permit = await verifyStorageIdle(storage, { port })
  assert.equal(StorageLock.repair(storage, permit), true)
  assert.equal(fs.existsSync(filename), false)
})

test('repair verification refuses an active listener', async (context) => {
  const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'neoth-keet-lock-listener-'))
  context.after(() => fs.rmSync(storage, { recursive: true, force: true }))
  const http = await import('node:http')
  const server = http.createServer((request, response) => response.end('active'))
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  context.after(() => server.close())
  const port = server.address().port
  await assert.rejects(verifyStorageIdle(storage, { port }), (error) => {
    return error instanceof StorageLockError && error.code === 'repair_listener_active'
  })
})

async function unusedPort () {
  const net = await import('node:net')
  const server = net.createServer()
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve))
  const port = server.address().port
  await new Promise((resolve, reject) => server.close((error) => error ? reject(error) : resolve()))
  return port
}

test('concurrent contenders recover one stale claim without deleting the winner', async (context) => {
  const storage = fs.mkdtempSync(path.join(os.tmpdir(), 'neoth-keet-lock-race-'))
  context.after(() => fs.rmSync(storage, { recursive: true, force: true }))
  fs.writeFileSync(path.join(storage, 'serve.lock'), `${JSON.stringify({
    version: 1,
    pid: 999999,
    process_start_id: 'A'.repeat(43),
    started_at_ms: 1,
    token: 'A'.repeat(43)
  })}\n`)
  const moduleUrl = new URL('../src/storage-lock.mjs', import.meta.url).href
  const program = `import { StorageLock } from ${JSON.stringify(moduleUrl)};
const storage = process.argv[1];
try {
  const lock = StorageLock.acquire(storage);
  console.log('ACQUIRED');
  setTimeout(() => { lock.close(); process.exit(0) }, 3000);
} catch (error) {
  console.log('BLOCKED:' + (error.code || error.name));
  process.exit(2);
}`
  const { spawn } = await import('node:child_process')
  const run = () => new Promise((resolve) => {
    const child = spawn(process.execPath, ['--input-type=module', '-e', program, storage], { stdio: ['ignore', 'pipe', 'pipe'] })
    let stdout = ''
    let stderr = ''
    child.stdout.on('data', (chunk) => { stdout += chunk })
    child.stderr.on('data', (chunk) => { stderr += chunk })
    child.on('exit', (code) => resolve({ code, stdout, stderr }))
  })
  const results = await Promise.all([run(), run()])
  assert.equal(results.filter((result) => result.stdout.includes('ACQUIRED')).length, 1, JSON.stringify(results))
  assert.equal(results.filter((result) => result.stdout.includes('BLOCKED:')).length, 1, JSON.stringify(results))
  assert.equal(fs.existsSync(path.join(storage, 'serve.lock')), false)
})
