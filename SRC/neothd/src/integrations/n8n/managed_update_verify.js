'use strict';
// Never print export data. This runs only within an exact, networkless Update
// candidate whose /tmp is a noexec/nosuid/nodev tmpfs.
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

const LIMIT = 64 * 1024 * 1024;
const COUNT_LIMIT = 10000;
let directory;
function fail() { process.exitCode = 23; }
function canonical(value) {
  if (value === null || typeof value === 'boolean' || typeof value === 'string') return JSON.stringify(value);
  if (typeof value === 'number') { if (!Number.isFinite(value)) throw Error(); return JSON.stringify(value); }
  if (Array.isArray(value)) return `[${value.map(canonical).join(',')}]`;
  if (!value || typeof value !== 'object') throw Error();
  const keys = Object.keys(value).sort();
  return `{${keys.map(key => `${JSON.stringify(key)}:${canonical(value[key])}`).join(',')}}`;
}
function object(value) { if (!value || Array.isArray(value) || typeof value !== 'object') throw Error(); return value; }
function withoutTopLevelTimestamps(record) {
  object(record);
  const copy = { ...record };
  // Only entity timestamps are known migration-volatile. Nested timestamps,
  // version identities, counters, relations, scopes, and all other exported
  // values remain in the canonical input.
  delete copy.createdAt; delete copy.updatedAt;
  return copy;
}
function workflowRecord(value) {
  const record = withoutTopLevelTimestamps(value);
  if (typeof record.id !== 'string' || !record.id || typeof record.name !== 'string'
      || typeof record.active !== 'boolean' || !Array.isArray(record.nodes)
      || !object(record.connections) || !Array.isArray(record.nodeGroups)) throw Error();
  return record;
}
function credentialRecord(value) {
  const record = withoutTopLevelTimestamps(value);
  if (typeof record.id !== 'string' || !record.id || typeof record.name !== 'string'
      || typeof record.type !== 'string' || !object(record.data)) throw Error();
  return record;
}
function readExport(file) {
  const stat = fs.lstatSync(file); if (!stat.isFile() || stat.isSymbolicLink() || stat.size < 2 || stat.size > LIMIT) throw Error();
  const value = JSON.parse(fs.readFileSync(file, 'utf8')); if (!Array.isArray(value) || value.length > COUNT_LIMIT) throw Error();
  return value;
}
function exportTo(command, output, decrypted) {
  const args = [command, '--all']; if (decrypted) args.push('--decrypted'); args.push(`--output=${output}`);
  const result = spawnSync('n8n', args, { stdio: 'ignore', timeout: 30000, killSignal: 'SIGKILL' });
  if (result.error || result.signal || result.status !== 0) throw Error();
}
function distinct(records) {
  const seen = new Set(); for (const record of records) { if (typeof record.id !== 'string' || !record.id || seen.has(record.id)) throw Error(); seen.add(record.id); }
}
try {
  process.umask(0o077);
  directory = fs.mkdtempSync('/tmp/neoth-update-content-'); fs.chmodSync(directory, 0o700);
  const workflowsFile = path.join(directory, 'workflows.json');
  const credentialsFile = path.join(directory, 'credentials.json');
  exportTo('export:workflow', workflowsFile, false); exportTo('export:credentials', credentialsFile, true);
  const workflows = readExport(workflowsFile).map(workflowRecord);
  const credentials = readExport(credentialsFile).map(credentialRecord);
  distinct(workflows); distinct(credentials);
  const byId = (left, right) => left.id < right.id ? -1 : left.id > right.id ? 1 : 0;
  workflows.sort(byId); credentials.sort(byId);
  const privateCanonical = canonical({ workflows, credentials });
  const content_sha256 = crypto.createHash('sha256').update('neoth-n8n-update-content-v1\0').update(privateCanonical).digest('hex');
  fs.rmSync(directory, { recursive: true, force: true }); directory = undefined;
  process.stdout.write(JSON.stringify({ workflow_count: workflows.length, credential_count: credentials.length, content_sha256 }));
} catch (_) { fail(); }
finally { if (directory) try { fs.rmSync(directory, { recursive: true, force: true }); } catch (_) { fail(); } }
