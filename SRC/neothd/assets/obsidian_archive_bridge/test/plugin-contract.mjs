import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import Module from "node:module";

const requireBundle = Module.createRequire(import.meta.url);
const root = path.resolve(import.meta.dirname, "..");
const manifest = JSON.parse(fs.readFileSync(path.join(root, "manifest.json"), "utf8"));
const source = fs.readFileSync(path.join(root, "src", "main.ts"), "utf8");

test("manifest declares the desktop-only paired bridge", () => {
  assert.equal(manifest.id, "neoth-archive-bridge");
  assert.equal(manifest.version, "0.2.0");
  assert.equal(manifest.minAppVersion, "1.5.0");
  assert.equal(manifest.isDesktopOnly, true);
});

test("source stores only bounded opaque descriptors and uses the local pipe", () => {
  assert.match(source, /const QUEUE_LIMIT = 128/);
  assert.match(source, /event_id: string/);
  assert.match(source, /source_id: string/);
  assert.match(source, /source_revision: string/);
  assert.match(source, /net\.createConnection\(\{ path: endpoint \}\)/);
  assert.match(source, /JSON\.stringify\(request\)\}\\n/);
  assert.match(source, /op: "status"/);
  assert.match(source, /op: "sync"/);
  assert.match(source, /pairingSecret/);
  assert.equal(source.includes("fetch("), false);
  assert.equal(source.includes("requestUrl"), false);
  assert.equal(source.includes("XMLHttpRequest"), false);
  assert.equal(source.includes("WebSocket"), false);
  assert.equal(source.includes("vault.modify"), false);
  assert.equal(source.includes("vault.create"), false);
});

test("source scopes descriptors to opted-in NEOTH session markdown", () => {
  assert.match(source, /const SESSION_ROOT = "NEOTH-sessions\/"/);
  assert.match(source, /const BRIDGE_SOURCE = "neoth-archive-bridge"/);
  assert.match(source, /file\.extension === "md"/);
  assert.match(source, /isBridgeNote\(content\)/);
  assert.match(source, /source:\\\\s\*/);
});

test("pairing state merges unknown settings and stops on revocation responses", () => {
  assert.match(source, /const \{ enabled, pairingSecret, pairingGeneration, endpoint, pending, \.\.\.unknown \} = value/);
  assert.match(source, /\.\.\.this\.passthroughSettings/);
  assert.match(source, /pending\.filter\(\(entry\) => entry\.generation === payload\.pairingGeneration\)/);
  assert.match(source, /response\.generation === expectedGeneration/);
  assert.match(source, /response\.status === "accepted" \|\| response\.status === "already_current" \|\| response\.status === "stale_revision"/);
  assert.match(source, /this\.pairingBlocked = true/);
  assert.match(source, /unpaired.*revoked.*generation_mismatch.*vault_mismatch/s);
});

test("source serializes snapshots and protects a newer descriptor or pairing from an old response", () => {
  assert.match(source, /private settingsWrites: Promise<void> = Promise\.resolve\(\)/);
  assert.match(source, /private pairingEpoch = 0/);
  assert.match(source, /const epoch = this\.pairingEpoch/);
  assert.match(source, /!this\.isCurrentPairing\(pairing, epoch\)/);
  assert.match(source, /samePendingEvent\(candidate, entry\)/);
  assert.match(source, /this\.settings\.pending\.splice\(acknowledgedIndex, 1\)/);
  assert.equal(source.includes("this.settings.pending.shift()"), false);
});

test("source retains a finite cursor for queue overflow and waits for an explicit retry after pipe failure", () => {
  assert.match(source, /private existingCursor = 0/);
  assert.match(source, /private rescanNeeded = false/);
  assert.match(source, /this\.existingCursor = index/);
  assert.match(source, /private scanRunning = false/);
  assert.match(source, /void this\.requestExistingScan\(\)/);
  assert.match(source, /daemon unavailable; queued locally/);
});

test("built bundle starts unpaired without opening a local pipe and unload cleans status", async () => {
  const bundle = path.join(root, "main.js");
  assert.equal(fs.existsSync(bundle), true, "hosted build must create main.js");
  const originalLoad = Module._load;
  const notices = [];
  let pipeConnections = 0;
  class FakePlugin {
    constructor(app) {
      this.app = app;
      this.commands = [];
    }
    addCommand(command) { this.commands.push(command); }
    addStatusBarItem() {
      return {
        setText: (text) => { this.statusText = text; },
        remove: () => { this.statusRemoved = true; },
      };
    }
    registerEvent() {}
    async loadData() { return { unrelated: "preserved" }; }
    async saveData(value) { this.saved = value; }
  }
  class FakeNotice { constructor(message) { notices.push(message); } }
  class FakeModal {}
  class FakeSetting {}
  Module._load = (request, parent, isMain) => {
    if (request === "obsidian") return { Plugin: FakePlugin, Notice: FakeNotice, Modal: FakeModal, Setting: FakeSetting, TFile: class {} };
    if (request === "net") return { createConnection: () => { pipeConnections += 1; throw new Error("unpaired bridge must not open a pipe"); } };
    return originalLoad(request, parent, isMain);
  };
  try {
    delete requireBundle.cache[requireBundle.resolve(bundle)];
    const loaded = requireBundle(bundle);
    const PluginClass = loaded.default.default ?? loaded.default;
    const instance = new PluginClass({ vault: { getMarkdownFiles: () => [], on: () => ({}) } });
    await instance.onload();
    assert.equal(instance.statusText, "NEOTH Archive Bridge: not paired (sync disabled)");
    assert.equal(instance.commands.length, 3);
    assert.equal(notices.length, 0);
    assert.equal(pipeConnections, 0);
    instance.onunload();
    assert.equal(instance.statusRemoved, true);
  } finally {
    Module._load = originalLoad;
  }
});

async function loadBundledBridge({ files = [], read, reply }) {
  const bundle = path.join(root, "main.js");
  const originalLoad = Module._load;
  const requests = [];
  const saves = [];
  class FakeTFile {
    constructor(path) {
      this.path = path;
      this.extension = path.split(".").pop();
    }
  }
  class FakePlugin {
    constructor(app) { this.app = app; }
    addCommand() {}
    addStatusBarItem() { return { setText: (text) => { this.statusText = text; }, remove() {} }; }
    registerEvent() {}
    async loadData() { return { keep: "unknown" }; }
    async saveData(value) { saves.push(structuredClone(value)); }
  }
  class FakeNotice { constructor() {} }
  class FakeModal {}
  class FakeSetting {}
  Module._load = (request, parent, isMain) => {
    if (request === "obsidian") return { Plugin: FakePlugin, Notice: FakeNotice, Modal: FakeModal, Setting: FakeSetting, TFile: FakeTFile };
    if (request === "net") return {
      createConnection: () => {
        const listeners = new Map();
        const socket = {
          once(event, listener) { listeners.set(event, listener); return socket; },
          on(event, listener) { listeners.set(event, listener); return socket; },
          write(raw) {
            const request = JSON.parse(raw);
            requests.push(request);
            reply(request, (response) => listeners.get("data")?.(Buffer.from(`${JSON.stringify(response)}\n`)), () => listeners.get("error")?.(new Error("offline")));
          },
          end() {},
          destroy() {},
        };
        queueMicrotask(() => listeners.get("connect")?.());
        return socket;
      },
    };
    return originalLoad(request, parent, isMain);
  };
  try {
    delete requireBundle.cache[requireBundle.resolve(bundle)];
    const loaded = requireBundle(bundle);
    const PluginClass = loaded.default.default ?? loaded.default;
    const instance = new PluginClass({ vault: { getMarkdownFiles: () => files, on: () => ({}), read } });
    await instance.onload();
    return { instance, FakeTFile, requests, saves, restore: () => { instance.onunload(); Module._load = originalLoad; } };
  } catch (error) {
    Module._load = originalLoad;
    throw error;
  }
}

const paired = (generation) => ({ protocol: 1, endpoint: "\\\\.\\pipe\\neoth-test", pairingSecret: "0123456789abcdef", pairingGeneration: generation });
const note = (revision) => `---\nsource: neoth-archive-bridge\n---\n${revision}`;

async function settle(check, attempts = 80) {
  for (let index = 0; index < attempts; ++index) {
    if (check()) return;
    await new Promise((resolve) => setImmediate(resolve));
  }
  assert.fail("bridge did not reach the expected state");
}

test("built bundle keeps a replacement when an older ACK arrives", async () => {
  let delayed;
  let content = note("first");
  const filePath = "NEOTH-sessions/race.md";
  const bridge = await loadBundledBridge({
    read: async () => content,
    reply: (request, respond) => {
      if (request.op === "status") respond({ status: "ok", generation: request.generation });
      else if (!delayed) delayed = respond;
    },
  });
  try {
    await bridge.instance.applyPairing(paired(1));
    const file = new bridge.FakeTFile(filePath);
    await bridge.instance.queueFile(file);
    await settle(() => delayed);
    const old = bridge.instance.settings.pending[0];
    content = note("replacement");
    await bridge.instance.queueFile(file);
    delayed({ status: "accepted", generation: 1 });
    await settle(() => bridge.instance.settings.pending.length === 1);
    assert.notEqual(bridge.instance.settings.pending[0].event_id, old.event_id);

    assert.equal(bridge.saves.at(-1).keep, "unknown");
  } finally {
    bridge.restore();
  }
});

test("built bundle ignores a revoked response from before re-pairing", async () => {
  let delayed;
  const bridge = await loadBundledBridge({
    read: async () => note("old-pair"),
    reply: (request, respond) => {
      if (request.op === "status") respond({ status: "ok", generation: request.generation });
      else if (request.generation === 2) respond({ status: "accepted", generation: 2 });
      else delayed = respond;
    },
  });
  try {
    await bridge.instance.applyPairing(paired(1));
    await bridge.instance.queueFile(new bridge.FakeTFile("NEOTH-sessions/old-pair.md"));
    await settle(() => delayed);
    await bridge.instance.applyPairing(paired(2));
    await bridge.instance.queueFile(new bridge.FakeTFile("NEOTH-sessions/new-pair.md"));
    delayed({ status: "revoked", generation: 1 });
    await settle(() => bridge.requests.some((request) => request.op === "sync" && request.generation === 2));
    await settle(() => bridge.instance.settings.pending.length === 0);
    assert.equal(bridge.instance.settings.pairingGeneration, 2);
    assert.equal(bridge.instance.pairingBlocked, false);
  } finally {
    bridge.restore();
  }
});

test("built bundle retains offline entries without a busy loop, times out a stalled pipe, and rejects wrong-generation ACKs", async () => {
  let mode = "offline";
  const bridge = await loadBundledBridge({
    read: async () => note("durable"),
    reply: (request, respond, fail) => {
      if (mode === "offline") fail();
      else if (mode === "stalled") {}
      else if (request.op === "status") respond({ status: "ok", generation: request.generation });
      else respond({ status: "accepted", generation: mode === "accepted" ? request.generation : request.generation + 1 });
    },
  });
  try {
    await bridge.instance.applyPairing(paired(3));
    await bridge.instance.queueFile(new bridge.FakeTFile("NEOTH-sessions/offline.md"));
    await bridge.instance.queueFile(new bridge.FakeTFile("NEOTH-sessions/offline-two.md"));
    await bridge.instance.queueFile(new bridge.FakeTFile("NEOTH-sessions/offline-three.md"));
    await settle(() => bridge.instance.settings.pending.length === 3);
    const offlineRequests = bridge.requests.length;
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(bridge.requests.length, offlineRequests);
    mode = "stalled";
    await bridge.instance.syncPending();
    assert.equal(bridge.instance.settings.pending.length, 3);
    assert.equal(bridge.instance.syncing, false);
    mode = "accepted";
    await bridge.instance.syncPending();
    assert.equal(bridge.instance.settings.pending.length, 0);
    await bridge.instance.queueFile(new bridge.FakeTFile("NEOTH-sessions/wrong-generation.md"));
    mode = "wrong-generation";
    await bridge.instance.syncPending();
    await settle(() => bridge.instance.pairingBlocked);
    assert.equal(bridge.instance.settings.pending.length, 1);
  } finally {
    bridge.restore();
  }
});

test("built bundle unload cancels a stalled exchange without starting another pipe", async () => {
  let delayed;
  const bridge = await loadBundledBridge({
    read: async () => note("unload"),
    reply: (request, respond) => {
      if (request.op === "status") respond({ status: "ok", generation: request.generation });
      else delayed = respond;
    },
  });
  try {
    await bridge.instance.applyPairing(paired(5));
    await bridge.instance.queueFile(new bridge.FakeTFile("NEOTH-sessions/unload.md"));
    await settle(() => delayed);
    const requestsBeforeUnload = bridge.requests.length;
    bridge.instance.onunload();
    delayed({ status: "accepted", generation: 5 });
    await new Promise((resolve) => setImmediate(resolve));
    await new Promise((resolve) => setImmediate(resolve));
    assert.equal(bridge.requests.length, requestsBeforeUnload);
  } finally {
    bridge.restore();
  }
});

test("built bundle scans 129 notes in finite batches of at most 128 descriptors", async () => {
  const paths = Array.from({ length: 129 }, (_, index) => `NEOTH-sessions/${index}.md`);
  const bridge = await loadBundledBridge({
    files: paths.map((path) => ({ path, extension: "md" })),
    read: async (file) => note(file.path),
    reply: (request, respond) => respond(request.op === "status"
      ? { status: "ok", generation: request.generation }
      : { status: "accepted", generation: request.generation }),
  });
  try {
    await bridge.instance.applyPairing(paired(4));
    await settle(() => bridge.requests.filter((request) => request.op === "sync").length === 129);
    assert.equal(Math.max(...bridge.saves.map((saved) => saved.pending.length)), 128);
    assert.equal(bridge.instance.settings.pending.length, 0);
  } finally {
    bridge.restore();
  }
});
