import assert from 'node:assert/strict'
import fs from 'node:fs'
import test from 'node:test'

import runtime from '../scripts/windows-runtime.cjs'

test('patched Windows standalone runtimes preserve redirected standard streams', () => {
  for (const [host, offset, patched] of [
    ['win32-arm64', 0x1826c, '17000014'],
    ['win32-x64', 0x1b2d9, 'eb57']
  ]) {
    const executable = runtime.prepare(host)
    const binary = fs.readFileSync(executable)
    assert.equal(binary.subarray(offset, offset + patched.length / 2).toString('hex'), patched)
    assert.equal(runtime.prebuilds[host]().path, executable)
  }
})
