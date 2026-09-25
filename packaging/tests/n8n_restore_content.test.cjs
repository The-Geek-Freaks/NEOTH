'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const path = require('node:path');
const vm = require('node:vm');
const crypto = require('node:crypto');

const source = fs.readFileSync(path.join(__dirname,
  '../../SRC/neothd/src/integrations/n8n/managed_restore_verify.js'), 'utf8');

function exercise(options = {}) {
  const counts = options.counts || [2, 1];
  const exports = [];
  const deleted = [];
  const files = new Map();
  let reads = 0;
  let output = '';
  const processStub = {
    exitCode: 0,
    umask(mask) { assert.equal(mask, 0o077); },
    stdout: { write(text) { output += text; } },
  };
  class DatabaseSync {
    constructor(filename, settings) {
      assert.equal(filename, '/home/node/.n8n/database.sqlite');
      assert.deepEqual({ ...settings }, { readOnly: true });
      this.pass = reads++;
    }
    exec(statement) { assert.ok(['BEGIN', 'COMMIT'].includes(statement)); }
    close() {}
    prepare(statement) {
      if (statement === 'PRAGMA quick_check(1)') {
        return { get: () => ({ quick_check: options.corrupt ? 'corrupt fixture' : 'ok' }) };
      }
      const offset = statement.includes('workflow_entity') ? 0 : 1;
      const value = counts[offset] + (options.drift && this.pass > 0 && offset === 0 ? 1 : 0);
      return { get: () => ({ count: value,
        exportable: value - (options.missingVersion && offset === 0 ? 1 : 0) }) };
    }
  }
  const fakeFs = {
    lstatSync(filename) {
      return { isFile: () => true, isSymbolicLink: () => false,
        size: filename.endsWith('database.sqlite') ? 4096 : Buffer.byteLength(files.get(filename) || '') };
    },
    mkdtempSync(prefix) { assert.equal(prefix, '/tmp/neoth-restore-'); return prefix + 'fixture'; },
    chmodSync(_filename, mode) { assert.equal(mode, 0o700); },
    readFileSync(filename) { return files.get(filename); },
    unlinkSync(filename) { deleted.push(filename); files.delete(filename); },
    rmdirSync(filename) {
      assert.equal(files.size, 0);
      if (options.cleanupFailure) throw new Error('private cleanup failure');
      deleted.push(filename);
    },
    rmSync(filename) { deleted.push(filename); files.clear(); },
  };
  function spawnSync(program, args, settings) {
    assert.equal(program, 'n8n');
    assert.equal(settings.stdio, 'ignore');
    assert.equal(settings.timeout, 15000);
    assert.equal(settings.killSignal, 'SIGKILL');
    exports.push([...args]);
    const credentials = args[0] === 'export:credentials';
    assert.ok(args.includes('--all'));
    assert.equal(args.includes('--decrypted'), credentials);
    const filename = args.find((value) => value.startsWith('--output=')).slice('--output='.length);
    assert.ok(filename.startsWith('/tmp/neoth-restore-fixture/'));
    const size = (credentials ? counts[1] : counts[0]) + (options.truncated ? -1 : 0);
    const values = Array.from({ length: size }, (_, index) => credentials
      ? { id: `credential-${index}`, data: options.encrypted ? 'ciphertext' : { key: 'PRIVATE_SENTINEL' } }
      : { id: `workflow-${index}`, nodes: [] });
    files.set(filename, JSON.stringify(values));
    if (options.exportFailure && credentials) return { status: 1, signal: null };
    if (options.timeout && credentials) return { status: null, signal: 'SIGKILL', error: new Error('timeout') };
    return { status: 0, signal: null };
  }
  const modules = {
    'node:fs': fakeFs, 'node:path': path, 'node:sqlite': { DatabaseSync },
    'node:child_process': { spawnSync }, 'node:crypto': crypto,
  };
  vm.runInNewContext(source, {
    require(name) { assert.ok(Object.hasOwn(modules, name)); return modules[name]; },
    process: processStub,
  });
  assert.ok(!output.includes('PRIVATE_SENTINEL'));
  return { output, exitCode: processStub.exitCode, exports, files, deleted };
}

test('nonempty restore requires actual decrypted export and removes plaintext before proof', () => {
  const result = exercise();
  assert.equal(result.exitCode, 0);
  const proof = JSON.parse(result.output);
  assert.equal(proof.workflow_count, 2);
  assert.equal(proof.credential_count, 1);
  assert.equal(proof.credential_decryption_proven, true);
  assert.equal(result.exports.length, 2);
  assert.equal(result.files.size, 0);
  assert.equal(result.deleted.length, 3);
  const { evidence_sha256, ...counts } = proof;
  assert.equal(evidence_sha256, crypto.createHash('sha256')
    .update('neoth-n8n-restore-content-v1\0').update(JSON.stringify(counts)).digest('hex'));
});

test('empty restored database succeeds without claiming a credential decryption', () => {
  const result = exercise({ counts: [0, 0] });
  assert.equal(result.exitCode, 0);
  assert.equal(result.exports.length, 0);
  assert.equal(JSON.parse(result.output).credential_decryption_proven, false);
});

test('unusable data and unsuccessful exports cannot publish a proof', () => {
  for (const options of [
    { corrupt: true }, { exportFailure: true }, { timeout: true },
    { encrypted: true }, { truncated: true }, { drift: true }, { cleanupFailure: true },
    { missingVersion: true },
  ]) {
    const result = exercise(options);
    assert.equal(result.exitCode, 1, JSON.stringify(options));
    assert.equal(result.output, '', JSON.stringify(options));
    assert.equal(result.files.size, 0, JSON.stringify(options));
  }
});
