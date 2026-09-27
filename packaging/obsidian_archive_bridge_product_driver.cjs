"use strict";
// Minimal headless adapter for the checked-in Obsidian bundle.  It supplies
// only the Plugin/Vault calls used by main.js; queueing, descriptor HMACs and
// IPC remain the production bundle's code.  It is not an Obsidian UI test.
const fs = require("fs");
const path = require("path");

function argument(name) {
  const index = process.argv.indexOf(name);
  if (index < 0 || index + 1 >= process.argv.length) throw new Error("missing_argument");
  return process.argv[index + 1];
}
const pluginPath = path.resolve(argument("--plugin"));
const vaultRoot = path.resolve(argument("--vault"));
const mode = argument("--mode");
const output = path.resolve(argument("--output"));
const pairingPath = process.argv.includes("--pairing") ? path.resolve(argument("--pairing")) : undefined;
const replayPath = process.argv.includes("--replay") ? path.resolve(argument("--replay")) : undefined;
const dataPath = path.join(path.dirname(pluginPath), "data.json");

class TFile {
  constructor(relative) { this.path = relative.replaceAll(path.sep, "/"); this.extension = path.extname(relative).slice(1); }
}
class Plugin {
  constructor(app) { this.app = app; }
  async loadData() { try { return JSON.parse(fs.readFileSync(dataPath, "utf8")); } catch { return undefined; } }
  async saveData(value) { fs.writeFileSync(dataPath, JSON.stringify(value)); }
  addStatusBarItem() { return { setText() {}, remove() {} }; }
  addCommand() {}
  registerEvent() {}
}
class Modal { constructor(app) { this.app = app; this.contentEl = { empty() {} }; this.titleEl = { setText() {} }; } open() {} close() {} }
class Notice { constructor() {} }
class Setting { setName() { return this; } setDesc() { return this; } addTextArea() { return this; } addButton() { return this; } }

function filesUnder(root, relative = "") {
  const result = [];
  for (const entry of fs.readdirSync(path.join(root, relative), { withFileTypes: true })) {
    const child = path.join(relative, entry.name);
    if (entry.isDirectory()) result.push(...filesUnder(root, child));
    else if (entry.isFile() && child.endsWith(".md")) result.push(new TFile(child));
  }
  return result;
}
const vault = {
  on() { return {}; },
  getMarkdownFiles() { return mode === "replay" ? [] : filesUnder(vaultRoot); },
  async read(file) { return fs.readFileSync(path.join(vaultRoot, file.path), "utf8"); },
};
const app = { vault };
const stub = path.join(path.dirname(pluginPath), "node_modules", "obsidian", "index.js");
fs.mkdirSync(path.dirname(stub), { recursive: true });
fs.writeFileSync(stub, "module.exports = " + JSON.stringify({}) + ";");
require.cache[stub] = { id: stub, filename: stub, loaded: true, exports: { Plugin, TFile, Modal, Notice, Setting } };

async function settle(ms) { await new Promise((resolve) => setTimeout(resolve, ms)); }
async function waitForIdle(plugin) {
  const deadline = Date.now() + 5000;
  for (;;) {
    await plugin.settingsWrites.catch(() => {});
    if (!plugin.scanRunning && !plugin.syncing) {
      // Let work scheduled by syncPending's finally block enter before
      // declaring quiescence; this is a scheduling checkpoint, not a delay.
      await Promise.resolve();
      if (!plugin.scanRunning && !plugin.syncing) return;
    }
    if (Date.now() >= deadline) throw new Error("plugin_did_not_quiesce");
    await settle(20);
  }
}
function opaqueDescriptor(value) {
  if (!value || typeof value !== "object" || typeof value.event_id !== "string" || typeof value.generation !== "number" || typeof value.source_id !== "string" || typeof value.source_revision !== "string") throw new Error("invalid_replay_descriptor");
  return { event_id: value.event_id, generation: value.generation, source_id: value.source_id, source_revision: value.source_revision };
}
async function main() {
  const Bundle = require(pluginPath).default;
  const exchanges = [];
  const syncDescriptors = [];
  // onload intentionally starts a best-effort sync. Wrap the production method
  // before onload so that initial asynchronous attempt is observed too.
  const originalExchange = Bundle.prototype.exchange;
  Bundle.prototype.exchange = async function (...args) {
    if (args[1]?.op === "sync") syncDescriptors.push(opaqueDescriptor(args[1]));
    const response = await originalExchange.apply(this, args);
    exchanges.push(response.status);
    return response;
  };
  const plugin = new Bundle(app);
  await plugin.onload();
  if (mode === "offline-pair") {
    if (!pairingPath) throw new Error("pairing_required");
    await plugin.applyPairing(JSON.parse(fs.readFileSync(pairingPath, "utf8")));
  } else if (mode === "sync") {
    await plugin.syncPending(true);
  } else if (mode === "replay") {
    if (!replayPath) throw new Error("replay_required");
    const descriptor = opaqueDescriptor(JSON.parse(fs.readFileSync(replayPath, "utf8")));
    await plugin.changeSettings(() => { plugin.settings.pending.push(descriptor); });
    await plugin.syncPending(true);
  } else {
    throw new Error("unsupported_mode");
  }
  await waitForIdle(plugin);
  const settings = JSON.parse(fs.readFileSync(dataPath, "utf8"));
  fs.writeFileSync(output, JSON.stringify({ mode, pending: settings.pending?.length ?? -1, exchanges, sync_descriptors: syncDescriptors }));
  plugin.onunload();
}
main().catch((error) => { process.stderr.write(String(error && error.stack || error)); process.exitCode = 1; });
