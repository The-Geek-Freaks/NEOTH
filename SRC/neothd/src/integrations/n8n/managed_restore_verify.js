// Runs only inside the exact, networkless restore candidate. No caller input.
'use strict';

const fs = require('node:fs');
const path = require('node:path');
const { DatabaseSync } = require('node:sqlite');
const { spawnSync } = require('node:child_process');
const { createHash } = require('node:crypto');

const DATABASE = '/home/node/.n8n/database.sqlite';
const MAX_EXPORT_BYTES = 32 * 1024 * 1024;
const MAX_COUNT = 0xffffffff;
let directory;

function snapshot() {
  const stat = fs.lstatSync(DATABASE);
  if (!stat.isFile() || stat.isSymbolicLink()) throw new Error('database');
  const db = new DatabaseSync(DATABASE, { readOnly: true });
  try {
    db.exec('BEGIN');
    if (db.prepare('PRAGMA quick_check(1)').get().quick_check !== 'ok') {
      throw new Error('integrity');
    }
    const workflowRow = db.prepare(
      "SELECT COUNT(*) AS count, COUNT(CASE WHEN typeof(versionId) = 'text' AND length(versionId) > 0 THEN 1 END) AS exportable FROM workflow_entity"
    ).get();
    // n8n's default export omits rows without a selected version. A successful
    // candidate must validate every restored workflow, never silently omit one.
    if (workflowRow.count !== workflowRow.exportable) throw new Error('workflow-version');
    const workflows = workflowRow.count;
    const credentials = db.prepare('SELECT COUNT(*) AS count FROM credentials_entity').get().count;
    if (![workflows, credentials].every((n) => Number.isSafeInteger(n) && n >= 0 && n <= MAX_COUNT)) {
      throw new Error('count');
    }
    db.exec('COMMIT');
    return { workflow_count: workflows, credential_count: credentials };
  } finally {
    db.close();
  }
}

function verifyExport(command, filename, expectedCount, decrypted) {
  if (expectedCount === 0) return;
  const output = path.join(directory, filename);
  const args = [command, '--all', `--output=${output}`];
  if (decrypted) args.push('--decrypted');
  const child = spawnSync('n8n', args, {
    stdio: 'ignore',
    timeout: 15000,
    killSignal: 'SIGKILL',
  });
  if (child.error || child.signal || child.status !== 0) throw new Error('export');
  const stat = fs.lstatSync(output);
  if (!stat.isFile() || stat.isSymbolicLink() || stat.size === 0 || stat.size > MAX_EXPORT_BYTES) {
    throw new Error('export-file');
  }
  const values = JSON.parse(fs.readFileSync(output, 'utf8'));
  if (!Array.isArray(values) || values.length !== expectedCount) throw new Error('export-count');
  const ids = new Set();
  for (const value of values) {
    if (!value || typeof value !== 'object' || Array.isArray(value) ||
        typeof value.id !== 'string' || value.id.length === 0 || ids.has(value.id)) {
      throw new Error('export-record');
    }
    ids.add(value.id);
    if (decrypted && (!value.data || typeof value.data !== 'object' || Array.isArray(value.data))) {
      throw new Error('decrypt');
    }
    if (!decrypted && !Array.isArray(value.nodes)) throw new Error('workflow');
  }
  // Plaintext never survives beyond this private tmpfs validation step.
  fs.unlinkSync(output);
}

try {
  process.umask(0o077);
  const before = snapshot();
  directory = fs.mkdtempSync('/tmp/neoth-restore-');
  fs.chmodSync(directory, 0o700);
  verifyExport('export:workflow', 'workflows.json', before.workflow_count, false);
  verifyExport('export:credentials', 'credentials.json', before.credential_count, true);
  const after = snapshot();
  if (JSON.stringify(before) !== JSON.stringify(after)) throw new Error('drift');
  fs.rmdirSync(directory);
  directory = undefined;
  const receipt = {
    workflow_count: before.workflow_count,
    credential_count: before.credential_count,
    credential_decryption_proven: before.credential_count > 0,
  };
  // This digest binds only the content-free proof, never credential values.
  const evidence = createHash('sha256')
    .update('neoth-n8n-restore-content-v1\0')
    .update(JSON.stringify(receipt))
    .digest('hex');
  process.stdout.write(JSON.stringify({ ...receipt, evidence_sha256: evidence }) + '\n');
} catch {
  // No error message, stack, export payload, or key crosses the container boundary.
  process.exitCode = 1;
} finally {
  if (directory) {
    try {
      fs.rmSync(directory, { recursive: true, force: true });
    } catch {
      process.exitCode = 1;
    }
  }
}
