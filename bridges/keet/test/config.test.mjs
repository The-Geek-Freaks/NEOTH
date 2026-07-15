import assert from 'node:assert/strict'
import fs from 'node:fs'
import os from 'node:os'
import path from 'node:path'
import test from 'node:test'

import { addTopic, loadConfig, saveConfig } from '../src/config.mjs'

function fixture () {
  return {
    version: 1,
    bearer_token: 'b'.repeat(32),
    mnemonic: Array.from({ length: 24 }, (_, index) => `word${index}`).join(' '),
    display_name: 'NEOTH',
    topics: [`nk1_${'a'.repeat(42)}A`]
  }
}

test('config snapshots are append-only and recover from a torn newest generation', (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'neoth-keet-config-'))
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  const first = saveConfig(directory, fixture())
  assert.equal(first.generation, 1)
  fs.writeFileSync(path.join(directory, 'config-2.json'), '{"torn":')
  assert.deepEqual(loadConfig(directory), first)

  const secondTopic = `nk1_${'c'.repeat(42)}E`
  const next = addTopic(directory, secondTopic)
  assert.equal(next.generation, 3)
  assert.deepEqual(next.topics, [fixture().topics[0], secondTopic])
  assert.deepEqual(loadConfig(directory), next)
})

test('invalid secret material fails closed', (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'neoth-keet-config-'))
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  assert.throws(() => saveConfig(directory, { ...fixture(), bearer_token: 'short' }))
  assert.throws(() => saveConfig(directory, { ...fixture(), display_name: '' }))
  assert.throws(() => saveConfig(directory, { ...fixture(), display_name: 'NEOTH\nBridge' }))
  assert.equal(loadConfig(directory), null)
})

test('complete config corruption never rolls back to older credentials', (context) => {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'neoth-keet-config-'))
  context.after(() => fs.rmSync(directory, { recursive: true, force: true }))
  saveConfig(directory, fixture())
  fs.writeFileSync(path.join(directory, 'config-2.json'), '{"complete":"corruption"}\n')
  assert.throws(() => loadConfig(directory))
})
