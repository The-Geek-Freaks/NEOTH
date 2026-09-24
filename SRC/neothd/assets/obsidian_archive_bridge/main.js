"use strict";
var __defProp = Object.defineProperty;
var __getOwnPropDesc = Object.getOwnPropertyDescriptor;
var __getOwnPropNames = Object.getOwnPropertyNames;
var __hasOwnProp = Object.prototype.hasOwnProperty;
var __export = (target, all) => {
  for (var name in all)
    __defProp(target, name, { get: all[name], enumerable: true });
};
var __copyProps = (to, from, except, desc) => {
  if (from && typeof from === "object" || typeof from === "function") {
    for (let key of __getOwnPropNames(from))
      if (!__hasOwnProp.call(to, key) && key !== except)
        __defProp(to, key, { get: () => from[key], enumerable: !(desc = __getOwnPropDesc(from, key)) || desc.enumerable });
  }
  return to;
};
var __toCommonJS = (mod) => __copyProps(__defProp({}, "__esModule", { value: true }), mod);

// src/main.ts
var main_exports = {};
__export(main_exports, {
  default: () => NeothArchiveBridge
});
module.exports = __toCommonJS(main_exports);
var import_obsidian = require("obsidian");
var PLUGIN_ID = "neoth-archive-bridge";
var PLUGIN_VERSION = "0.2.0";
var PROTOCOL_VERSION = 1;
var QUEUE_LIMIT = 128;
var IPC_TIMEOUT_MS = 1e3;
var MAX_IPC_RESPONSE_BYTES = 8 * 1024;
var SESSION_ROOT = "NEOTH-sessions/";
var BRIDGE_SOURCE = "neoth-archive-bridge";
var net = require("net");
var crypto = require("crypto");
var NeothArchiveBridge = class extends import_obsidian.Plugin {
  constructor() {
    super(...arguments);
    this.settings = { enabled: false, pending: [] };
    this.passthroughSettings = {};
    this.settingsWrites = Promise.resolve();
    this.activeIpc = /* @__PURE__ */ new Set();
    this.unloaded = false;
    this.syncing = false;
    this.syncRequested = false;
    this.pairingBlocked = false;
    this.pairingEpoch = 0;
    this.existingCursor = 0;
    this.rescanNeeded = false;
    this.scanRunning = false;
    this.scanRequested = false;
  }
  async onload() {
    const stored = await this.loadData();
    this.settings = normalizeSettings(stored);
    this.passthroughSettings = unknownSettings(stored);
    this.statusItem = this.addStatusBarItem();
    this.updateStatus();
    this.addCommand({
      id: "pair-with-neoth-owner",
      name: "Pair with local NEOTH owner",
      callback: () => new PairingModal(this.app, (payload) => void this.applyPairing(payload)).open()
    });
    this.addCommand({
      id: "sync-local-archive-notes",
      name: "Sync local NEOTH archive notes",
      callback: () => void this.syncPending(true)
    });
    this.addCommand({
      id: "inspect-local-archive-notes",
      name: "Inspect local NEOTH session notes",
      callback: () => this.inspectLocalArchiveNotes()
    });
    this.registerEvent(this.app.vault.on("modify", (file) => {
      if (file instanceof import_obsidian.TFile) void this.queueFile(file);
    }));
    this.registerEvent(this.app.vault.on("rename", (file) => {
      if (file instanceof import_obsidian.TFile) void this.queueFile(file);
    }));
    void this.requestExistingScan();
    void this.syncPending();
  }
  onunload() {
    this.unloaded = true;
    ++this.pairingEpoch;
    this.syncRequested = false;
    for (const cancel of this.activeIpc) cancel();
    this.activeIpc.clear();
    this.statusItem?.remove();
    this.statusItem = void 0;
  }
  async applyPairing(payload) {
    ++this.pairingEpoch;
    await this.changeSettings(() => {
      this.settings = {
        ...this.settings,
        enabled: true,
        pairingSecret: payload.pairingSecret,
        pairingGeneration: payload.pairingGeneration,
        endpoint: payload.endpoint,
        pending: this.settings.pending.filter((entry) => entry.generation === payload.pairingGeneration)
      };
      this.pairingBlocked = false;
      this.existingCursor = 0;
      this.rescanNeeded = false;
    });
    new import_obsidian.Notice("NEOTH Archive Bridge paired locally. Queued note descriptors will sync when the daemon is available.");
    await this.requestExistingScan();
    await this.syncPending(true);
  }
  async requestExistingScan() {
    this.scanRequested = true;
    if (this.scanRunning) return;
    this.scanRunning = true;
    try {
      while (this.scanRequested) {
        this.scanRequested = false;
        await this.queueExistingEligibleNotes();
        if (this.rescanNeeded) return;
      }
    } finally {
      this.scanRunning = false;
      if (this.settings.pending.length > 0 && this.isPairingReady()) void this.syncPending();
    }
  }
  async queueExistingEligibleNotes() {
    if (!this.isPairingReady()) return;
    const files = this.app.vault.getMarkdownFiles();
    for (let index = this.existingCursor; index < files.length; ++index) {
      const result = await this.queueFile(files[index]);
      if (result === "full") {
        this.existingCursor = index;
        this.rescanNeeded = true;
        return;
      }
      if (this.settings.pending.length >= QUEUE_LIMIT && index + 1 < files.length) {
        this.existingCursor = index + 1;
        this.rescanNeeded = true;
        return;
      }
    }
    this.existingCursor = 0;
    this.rescanNeeded = false;
  }
  async queueFile(file) {
    if (!this.isPairingReady() || !isNeothSessionNote(file)) return "skipped";
    const pairing = this.requirePairing();
    const epoch = this.pairingEpoch;
    const content = await this.app.vault.read(file);
    if (!isBridgeNote(content) || !this.isCurrentPairing(pairing, epoch)) return "skipped";
    const pending = descriptorFor(file, content, pairing.pairingSecret, pairing.pairingGeneration);
    const result = await this.changeSettings(() => {
      if (!this.isCurrentPairing(pairing, epoch)) return "skipped";
      const existingIndex = this.settings.pending.findIndex((entry) => entry.source_id === pending.source_id);
      if (existingIndex >= 0) {
        this.settings.pending[existingIndex] = pending;
        return "queued";
      }
      if (this.settings.pending.length >= QUEUE_LIMIT) return "full";
      this.settings.pending.push(pending);
      return "queued";
    });
    if (result === "full") {
      this.updateStatus("queue full; sync required");
      new import_obsidian.Notice("NEOTH Archive Bridge queue is full. Sync with the local daemon before more notes are queued.");
      this.rescanNeeded = true;
      void this.requestExistingScan();
    } else if (result === "queued" && !this.scanRunning) {
      void this.syncPending();
    }
    return result;
  }
  async syncPending(requestAfterCurrent = false) {
    if (this.syncing) {
      this.syncRequested || (this.syncRequested = requestAfterCurrent);
      return;
    }
    if (!this.isPairingReady()) return;
    this.syncing = true;
    const epoch = this.pairingEpoch;
    let syncedEntry = false;
    let reachedDaemon = false;
    let pairingForCatch;
    try {
      const pairing = this.requirePairing();
      pairingForCatch = pairing;
      const status = await this.exchange(pairing.endpoint, {
        op: "status",
        protocol: PROTOCOL_VERSION,
        pairingSecret: pairing.pairingSecret,
        generation: pairing.pairingGeneration
      });
      if (!this.isCurrentPairing(pairing, epoch) || !this.acceptsStatus(status, pairing.pairingGeneration, epoch)) return;
      reachedDaemon = true;
      while (this.settings.pending.length > 0 && !this.pairingBlocked) {
        if (!this.isCurrentPairing(pairing, epoch)) return;
        const entry = this.settings.pending[0];
        const response = await this.exchange(pairing.endpoint, {
          op: "sync",
          protocol: PROTOCOL_VERSION,
          pairingSecret: pairing.pairingSecret,
          ...entry
        });
        if (!this.isCurrentPairing(pairing, epoch)) return;
        if (isAcknowledgement(response, pairing.pairingGeneration)) {
          await this.changeSettings(() => {
            if (!this.isCurrentPairing(pairing, epoch)) return;
            const acknowledgedIndex = this.settings.pending.findIndex((candidate) => samePendingEvent(candidate, entry));
            if (acknowledgedIndex >= 0) this.settings.pending.splice(acknowledgedIndex, 1);
          });
          syncedEntry = true;
          continue;
        }
        this.blockPairing(response, epoch);
      }
    } catch {
      if (pairingForCatch && this.isCurrentPairing(pairingForCatch, epoch)) this.updateStatus("daemon unavailable; queued locally");
    } finally {
      this.syncing = false;
      const requested = this.syncRequested;
      this.syncRequested = false;
      if (reachedDaemon && this.rescanNeeded && this.isPairingReady()) void this.requestExistingScan();
      else if ((requested || syncedEntry) && this.settings.pending.length > 0 && this.isPairingReady()) void this.syncPending();
    }
  }
  exchange(endpoint, request) {
    if (this.unloaded) return Promise.reject(new Error("plugin unloaded"));
    return privateIpcExchange(
      endpoint,
      request,
      (cancel) => this.activeIpc.add(cancel),
      (cancel) => this.activeIpc.delete(cancel)
    );
  }
  acceptsStatus(response, expectedGeneration, epoch) {
    if (response.status === "ok" && response.generation === expectedGeneration) return true;
    this.blockPairing(response, epoch);
    return false;
  }
  blockPairing(response, epoch) {
    if (epoch !== this.pairingEpoch) return;
    this.pairingBlocked = true;
    this.updateStatus(response.status.replaceAll("_", " "));
    new import_obsidian.Notice(`NEOTH Archive Bridge sync stopped: ${response.status.replaceAll("_", " ")}. Re-pair from NEOTH if needed.`);
  }
  isPairingReady() {
    return !this.unloaded && this.settings.enabled && !this.pairingBlocked && typeof this.settings.pairingSecret === "string" && typeof this.settings.pairingGeneration === "number" && typeof this.settings.endpoint === "string";
  }
  requirePairing() {
    if (!this.isPairingReady()) throw new Error("pairing is not ready");
    return {
      pairingSecret: this.settings.pairingSecret,
      pairingGeneration: this.settings.pairingGeneration,
      endpoint: this.settings.endpoint
    };
  }
  isCurrentPairing(pairing, epoch) {
    return !this.unloaded && epoch === this.pairingEpoch && !this.pairingBlocked && this.settings.pairingSecret === pairing.pairingSecret && this.settings.pairingGeneration === pairing.pairingGeneration && this.settings.endpoint === pairing.endpoint;
  }
  async changeSettings(change) {
    let result;
    const write = this.settingsWrites.then(async () => {
      result = change();
      await this.persistSettings();
      this.updateStatus();
    });
    this.settingsWrites = write.catch(() => void 0);
    await write;
    return result;
  }
  async persistSettings() {
    await this.saveData({
      ...this.passthroughSettings,
      enabled: this.settings.enabled,
      pairingSecret: this.settings.pairingSecret,
      pairingGeneration: this.settings.pairingGeneration,
      endpoint: this.settings.endpoint,
      pending: this.settings.pending.map((entry) => ({ ...entry }))
    });
  }
  updateStatus(detail) {
    if (!this.statusItem) return;
    if (!this.settings.enabled) {
      this.statusItem.setText("NEOTH Archive Bridge: not paired (sync disabled)");
    } else if (detail) {
      this.statusItem.setText(`NEOTH Archive Bridge: ${detail}`);
    } else {
      this.statusItem.setText(`NEOTH Archive Bridge: paired; ${this.settings.pending.length} queued`);
    }
  }
  inspectLocalArchiveNotes() {
    const sessionNotes = this.app.vault.getMarkdownFiles().filter((file) => isNeothSessionNote(file));
    new import_obsidian.Notice(`${PLUGIN_ID} ${PLUGIN_VERSION}: ${sessionNotes.length} local NEOTH session note(s); ${this.settings.pending.length} opaque descriptor(s) queued.`);
  }
};
var PairingModal = class extends import_obsidian.Modal {
  constructor(app, accept) {
    super(app);
    this.accept = accept;
    this.payload = "";
  }
  onOpen() {
    this.titleEl.setText("Pair NEOTH Archive Bridge");
    new import_obsidian.Setting(this.contentEl).setName("One-time pairing payload").setDesc("Paste the payload printed by neoth obsidian bridge pair. It is stored only in this plugin's private settings.").addTextArea((text) => text.setPlaceholder("{\u2026}").onChange((value) => {
      this.payload = value;
    }));
    new import_obsidian.Setting(this.contentEl).addButton((button) => button.setButtonText("Pair").setCta().onClick(() => {
      const parsed = parsePairingPayload(this.payload);
      if (!parsed) {
        new import_obsidian.Notice("Invalid NEOTH pairing payload.");
        return;
      }
      this.accept(parsed);
      this.close();
    }));
  }
  onClose() {
    this.contentEl.empty();
  }
};
function normalizeSettings(value) {
  if (!isRecord(value)) return { enabled: false, pending: [] };
  return {
    enabled: value.enabled === true,
    pairingSecret: typeof value.pairingSecret === "string" ? value.pairingSecret : void 0,
    pairingGeneration: isNonNegativeInteger(value.pairingGeneration) ? value.pairingGeneration : void 0,
    endpoint: isEndpoint(value.endpoint) ? value.endpoint : void 0,
    pending: Array.isArray(value.pending) ? value.pending.filter(isPendingEvent).slice(-QUEUE_LIMIT) : []
  };
}
function unknownSettings(value) {
  if (!isRecord(value)) return {};
  const { enabled, pairingSecret, pairingGeneration, endpoint, pending, ...unknown } = value;
  return unknown;
}
function isAcknowledgement(response, expectedGeneration) {
  return response.generation === expectedGeneration && (response.status === "accepted" || response.status === "already_current" || response.status === "stale_revision");
}
function samePendingEvent(left, right) {
  return left.event_id === right.event_id && left.generation === right.generation && left.source_id === right.source_id && left.source_revision === right.source_revision;
}
function parsePairingPayload(value) {
  try {
    const parsed = JSON.parse(value);
    if (!isRecord(parsed) || parsed.protocol !== PROTOCOL_VERSION || !isEndpoint(parsed.endpoint) || typeof parsed.pairingSecret !== "string" || parsed.pairingSecret.length < 16 || !isNonNegativeInteger(parsed.pairingGeneration)) return void 0;
    return {
      protocol: PROTOCOL_VERSION,
      endpoint: parsed.endpoint,
      pairingSecret: parsed.pairingSecret,
      pairingGeneration: parsed.pairingGeneration
    };
  } catch {
    return void 0;
  }
}
function descriptorFor(file, content, pairingSecret, generation) {
  const sourceId = `obsidian:source:hmac-sha256:${hmac(pairingSecret, `neoth/obsidian-archive-bridge/source/v1\0${normalizePath(file.path)}`)}`;
  const revision = `hmac-sha256:${hmac(pairingSecret, `neoth/obsidian-archive-bridge/revision/v1\0${sourceId}\0${content}`)}`;
  return { event_id: newEventId(), generation, source_id: sourceId, source_revision: revision };
}
function privateIpcExchange(endpoint, request, onAbort, onSettled) {
  return new Promise((resolve, reject) => {
    let settled = false;
    let wire = "";
    let receivedBytes = 0;
    const decoder = new TextDecoder();
    const socket = net.createConnection({ path: endpoint });
    let timeout;
    const cancel = () => fail(new Error("private IPC cancelled"));
    const finish = () => {
      if (timeout !== void 0) clearTimeout(timeout);
      onSettled?.(cancel);
    };
    const fail = (error) => {
      if (!settled) {
        settled = true;
        finish();
        socket.destroy();
        reject(error instanceof Error ? error : new Error("private IPC failed"));
      }
    };
    onAbort?.(cancel);
    timeout = setTimeout(() => fail(new Error("private IPC timed out")), IPC_TIMEOUT_MS);
    socket.once("error", fail);
    socket.once("connect", () => socket.write(`${JSON.stringify(request)}
`));
    socket.on("data", (chunk) => {
      if (settled) return;
      receivedBytes += chunk.byteLength;
      if (receivedBytes > MAX_IPC_RESPONSE_BYTES) {
        fail(new Error("private IPC response exceeds the limit"));
        return;
      }
      wire += decoder.decode(chunk, { stream: true });
      const newline = wire.indexOf("\n");
      if (newline < 0) return;
      try {
        const response = parseBridgeResponse(wire.slice(0, newline));
        if (!response) throw new Error("invalid bridge response");
        settled = true;
        finish();
        socket.end();
        resolve(response);
      } catch (error) {
        fail(error);
      }
    });
    socket.once("close", () => {
      if (!settled) fail(new Error("private IPC closed before a response"));
    });
  });
}
function parseBridgeResponse(value) {
  try {
    const parsed = JSON.parse(value);
    if (!isRecord(parsed) || typeof parsed.status !== "string") return void 0;
    const statuses = ["ok", "accepted", "already_current", "stale_revision", "unpaired", "revoked", "generation_mismatch", "vault_mismatch", "event_reuse_conflict", "error"];
    if (!statuses.includes(parsed.status)) return void 0;
    return {
      status: parsed.status,
      generation: isNonNegativeInteger(parsed.generation) ? parsed.generation : void 0,
      receipt: typeof parsed.receipt === "string" ? parsed.receipt : void 0,
      message: typeof parsed.message === "string" ? parsed.message : void 0
    };
  } catch {
    return void 0;
  }
}
function isNeothSessionNote(file) {
  return file.path.startsWith(SESSION_ROOT) && file.extension === "md";
}
function isBridgeNote(content) {
  const frontmatter = content.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/)?.[1];
  return frontmatter !== void 0 && new RegExp(`^source:\\s*["']?${BRIDGE_SOURCE}["']?\\s*$`, "m").test(frontmatter);
}
function normalizePath(path) {
  return path.replaceAll("\\", "/").normalize("NFC");
}
function hmac(key, value) {
  return crypto.createHmac("sha256", key).update(value, "utf8").digest("hex");
}
function newEventId() {
  return crypto.randomUUID?.() ?? `event-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}
function isRecord(value) {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}
function isNonNegativeInteger(value) {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}
function isEndpoint(value) {
  return typeof value === "string" && value.length > 0 && value.length <= 512 && !value.includes("\0");
}
function isPendingEvent(value) {
  return isRecord(value) && typeof value.event_id === "string" && value.event_id.length > 0 && value.event_id.length <= 128 && isNonNegativeInteger(value.generation) && typeof value.source_id === "string" && value.source_id.startsWith("obsidian:source:hmac-sha256:") && typeof value.source_revision === "string" && value.source_revision.startsWith("hmac-sha256:");
}
