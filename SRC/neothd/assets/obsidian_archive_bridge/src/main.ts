import { App, Modal, Notice, Plugin, Setting, TFile } from "obsidian";

declare const require: (name: string) => unknown;

const PLUGIN_ID = "neoth-archive-bridge";
const PLUGIN_VERSION = "0.2.0";
const PROTOCOL_VERSION = 1;
const QUEUE_LIMIT = 128;
const IPC_TIMEOUT_MS = 1_000;
const MAX_IPC_RESPONSE_BYTES = 8 * 1024;
const SESSION_ROOT = "NEOTH-sessions/";
const BRIDGE_SOURCE = "neoth-archive-bridge";

type PendingEvent = {
  event_id: string;
  generation: number;
  source_id: string;
  source_revision: string;
};

type BridgeSettings = {
  enabled: boolean;
  pairingSecret?: string;
  pairingGeneration?: number;
  endpoint?: string;
  pending: PendingEvent[];
};

type PairingPayload = {
  protocol: 1;
  endpoint: string;
  pairingSecret: string;
  pairingGeneration: number;
};

type BridgeStatusRequest = {
  op: "status";
  protocol: 1;
  pairingSecret: string;
  generation: number;
};

type BridgeSyncRequest = PendingEvent & {
  op: "sync";
  protocol: 1;
  pairingSecret: string;
};

type BridgeResponse = {
  status: "ok" | "accepted" | "already_current" | "stale_revision" | "unpaired" | "revoked" | "generation_mismatch" | "vault_mismatch" | "event_reuse_conflict" | "error";
  generation?: number;
  receipt?: string;
  message?: string;
};

type SocketLike = {
  once(event: "connect" | "error" | "close", listener: (...args: unknown[]) => void): SocketLike;
  on(event: "data", listener: (chunk: Uint8Array) => void): SocketLike;
  write(data: string): void;
  end(): void;
  destroy(): void;
};

type NetModule = {
  createConnection(options: { path: string }): SocketLike;
};

type CryptoModule = {
  createHmac(algorithm: string, key: string): { update(value: string, encoding?: string): { digest(encoding: "hex"): string } };
  randomUUID?: () => string;
};

const net = require("net") as NetModule;
const crypto = require("crypto") as CryptoModule;

/**
 * Desktop-only NEOTH Archive Bridge client. The daemon remains the only
 * authority that pairs a vault or imports its contents. This client keeps
 * only opaque, bounded change descriptors and sends them over the per-pair
 * same-user pipe supplied by the one-time CLI pairing payload.
 */
export default class NeothArchiveBridge extends Plugin {
  private statusItem?: { setText(text: string): void; remove(): void };
  private settings: BridgeSettings = { enabled: false, pending: [] };
  private passthroughSettings: Record<string, unknown> = {};
  private settingsWrites: Promise<void> = Promise.resolve();
  private activeIpc = new Set<() => void>();
  private unloaded = false;
  private syncing = false;
  private syncRequested = false;
  private pairingBlocked = false;
  private pairingEpoch = 0;
  private existingCursor = 0;
  private rescanNeeded = false;
  private scanRunning = false;
  private scanRequested = false;

  async onload(): Promise<void> {
    const stored = await this.loadData();
    this.settings = normalizeSettings(stored);
    this.passthroughSettings = unknownSettings(stored);
    this.statusItem = this.addStatusBarItem();
    this.updateStatus();

    this.addCommand({
      id: "pair-with-neoth-owner",
      name: "Pair with local NEOTH owner",
      callback: () => new PairingModal(this.app, (payload) => void this.applyPairing(payload)).open(),
    });
    this.addCommand({
      id: "sync-local-archive-notes",
      name: "Sync local NEOTH archive notes",
      callback: () => void this.syncPending(true),
    });
    this.addCommand({
      id: "inspect-local-archive-notes",
      name: "Inspect local NEOTH session notes",
      callback: () => this.inspectLocalArchiveNotes(),
    });

    this.registerEvent(this.app.vault.on("modify", (file) => void this.queueFile(file)));
    this.registerEvent(this.app.vault.on("rename", (file) => {
      if (file instanceof TFile) void this.queueFile(file);
    }));
    void this.requestExistingScan();
    void this.syncPending();
  }

  onunload(): void {
    this.unloaded = true;
    ++this.pairingEpoch;
    this.syncRequested = false;
    for (const cancel of this.activeIpc) cancel();
    this.activeIpc.clear();
    this.statusItem?.remove();
    this.statusItem = undefined;
  }

  private async applyPairing(payload: PairingPayload): Promise<void> {
    ++this.pairingEpoch;
    await this.changeSettings(() => {
      this.settings = {
        ...this.settings,
        enabled: true,
        pairingSecret: payload.pairingSecret,
        pairingGeneration: payload.pairingGeneration,
        endpoint: payload.endpoint,
        pending: this.settings.pending.filter((entry) => entry.generation === payload.pairingGeneration),
      };
      this.pairingBlocked = false;
      this.existingCursor = 0;
      this.rescanNeeded = false;
    });
    new Notice("NEOTH Archive Bridge paired locally. Queued note descriptors will sync when the daemon is available.");
    await this.requestExistingScan();
    await this.syncPending(true);
  }

  private async requestExistingScan(): Promise<void> {
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
    }
  }

  private async queueExistingEligibleNotes(): Promise<void> {
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

  private async queueFile(file: TFile): Promise<"queued" | "skipped" | "full"> {
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
      new Notice("NEOTH Archive Bridge queue is full. Sync with the local daemon before more notes are queued.");
      this.rescanNeeded = true;
      void this.requestExistingScan();
    } else if (result === "queued") {
      void this.syncPending();
    }
    return result;
  }

  private async syncPending(requestAfterCurrent = false): Promise<void> {
    if (this.syncing) {
      this.syncRequested ||= requestAfterCurrent;
      return;
    }
    if (!this.isPairingReady()) return;
    this.syncing = true;
    const epoch = this.pairingEpoch;
    let syncedEntry = false;
    let reachedDaemon = false;
    let pairing: Required<Pick<BridgeSettings, "pairingSecret" | "pairingGeneration" | "endpoint">> | undefined;
    try {
      pairing = this.requirePairing();
      const status = await this.exchange(pairing.endpoint, {
        op: "status",
        protocol: PROTOCOL_VERSION,
        pairingSecret: pairing.pairingSecret,
        generation: pairing.pairingGeneration,
      } satisfies BridgeStatusRequest);
      if (!this.isCurrentPairing(pairing, epoch) || !this.acceptsStatus(status, pairing.pairingGeneration, epoch)) return;
      reachedDaemon = true;

      while (this.settings.pending.length > 0 && !this.pairingBlocked) {
        if (!this.isCurrentPairing(pairing, epoch)) return;
        const entry = this.settings.pending[0];
        const response = await this.exchange(pairing.endpoint, {
          op: "sync",
          protocol: PROTOCOL_VERSION,
          pairingSecret: pairing.pairingSecret,
          ...entry,
        } satisfies BridgeSyncRequest);
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
      // Daemon absence and a broken pipe leave descriptors durable for retry.
      if (pairing && this.isCurrentPairing(pairing, epoch)) this.updateStatus("daemon unavailable; queued locally");
    } finally {
      this.syncing = false;
      const requested = this.syncRequested;
      this.syncRequested = false;
      if (reachedDaemon && this.rescanNeeded && this.isPairingReady()) void this.requestExistingScan();
      else if ((requested || syncedEntry) && this.settings.pending.length > 0 && this.isPairingReady()) void this.syncPending();
    }
  }

  private exchange(endpoint: string, request: BridgeStatusRequest | BridgeSyncRequest): Promise<BridgeResponse> {
    if (this.unloaded) return Promise.reject(new Error("plugin unloaded"));
    return privateIpcExchange(
      endpoint,
      request,
      (cancel) => this.activeIpc.add(cancel),
      (cancel) => this.activeIpc.delete(cancel),
    );
  }

  private acceptsStatus(response: BridgeResponse, expectedGeneration: number, epoch: number): boolean {
    if (response.status === "ok" && response.generation === expectedGeneration) return true;
    this.blockPairing(response, epoch);
    return false;
  }

  private blockPairing(response: BridgeResponse, epoch: number): void {
    if (epoch !== this.pairingEpoch) return;
    this.pairingBlocked = true;
    this.updateStatus(response.status.replaceAll("_", " "));
    new Notice(`NEOTH Archive Bridge sync stopped: ${response.status.replaceAll("_", " ")}. Re-pair from NEOTH if needed.`);
  }

  private isPairingReady(): boolean {
    return !this.unloaded
      && this.settings.enabled
      && !this.pairingBlocked
      && typeof this.settings.pairingSecret === "string"
      && typeof this.settings.pairingGeneration === "number"
      && typeof this.settings.endpoint === "string";
  }

  private requirePairing(): Required<Pick<BridgeSettings, "pairingSecret" | "pairingGeneration" | "endpoint">> {
    if (!this.isPairingReady()) throw new Error("pairing is not ready");
    return {
      pairingSecret: this.settings.pairingSecret!,
      pairingGeneration: this.settings.pairingGeneration!,
      endpoint: this.settings.endpoint!,
    };
  }

  private isCurrentPairing(pairing: Required<Pick<BridgeSettings, "pairingSecret" | "pairingGeneration" | "endpoint">>, epoch: number): boolean {
    return !this.unloaded
      && epoch === this.pairingEpoch
      && !this.pairingBlocked
      && this.settings.pairingSecret === pairing.pairingSecret
      && this.settings.pairingGeneration === pairing.pairingGeneration
      && this.settings.endpoint === pairing.endpoint;
  }

  private async changeSettings<T>(change: () => T): Promise<T> {
    let result!: T;
    const write = this.settingsWrites.then(async () => {
      result = change();
      await this.persistSettings();
      this.updateStatus();
    });
    this.settingsWrites = write.catch(() => undefined);
    await write;
    return result;
  }

  private async persistSettings(): Promise<void> {
    await this.saveData({
      ...this.passthroughSettings,
      enabled: this.settings.enabled,
      pairingSecret: this.settings.pairingSecret,
      pairingGeneration: this.settings.pairingGeneration,
      endpoint: this.settings.endpoint,
      pending: this.settings.pending.map((entry) => ({ ...entry })),
    });
  }

  private updateStatus(detail?: string): void {
    if (!this.statusItem) return;
    if (!this.settings.enabled) {
      this.statusItem.setText("NEOTH Archive Bridge: not paired (sync disabled)");
    } else if (detail) {
      this.statusItem.setText(`NEOTH Archive Bridge: ${detail}`);
    } else {
      this.statusItem.setText(`NEOTH Archive Bridge: paired; ${this.settings.pending.length} queued`);
    }
  }

  private inspectLocalArchiveNotes(): void {
    const sessionNotes = this.app.vault.getMarkdownFiles().filter((file) => isNeothSessionNote(file));
    new Notice(`${PLUGIN_ID} ${PLUGIN_VERSION}: ${sessionNotes.length} local NEOTH session note(s); ${this.settings.pending.length} opaque descriptor(s) queued.`);
  }
}

class PairingModal extends Modal {
  private payload = "";

  constructor(app: App, private readonly accept: (payload: PairingPayload) => void) {
    super(app);
  }

  onOpen(): void {
    this.titleEl.setText("Pair NEOTH Archive Bridge");
    new Setting(this.contentEl)
      .setName("One-time pairing payload")
      .setDesc("Paste the payload printed by neoth obsidian bridge pair. It is stored only in this plugin's private settings.")
      .addTextArea((text) => text.setPlaceholder("{…}").onChange((value) => { this.payload = value; }));
    new Setting(this.contentEl).addButton((button) => button.setButtonText("Pair").setCta().onClick(() => {
      const parsed = parsePairingPayload(this.payload);
      if (!parsed) {
        new Notice("Invalid NEOTH pairing payload.");
        return;
      }
      this.accept(parsed);
      this.close();
    }));
  }

  onClose(): void {
    this.contentEl.empty();
  }
}

function normalizeSettings(value: unknown): BridgeSettings {
  if (!isRecord(value)) return { enabled: false, pending: [] };
  return {
    enabled: value.enabled === true,
    pairingSecret: typeof value.pairingSecret === "string" ? value.pairingSecret : undefined,
    pairingGeneration: isNonNegativeInteger(value.pairingGeneration) ? value.pairingGeneration : undefined,
    endpoint: isEndpoint(value.endpoint) ? value.endpoint : undefined,
    pending: Array.isArray(value.pending) ? value.pending.filter(isPendingEvent).slice(-QUEUE_LIMIT) : [],
  };
}

function unknownSettings(value: unknown): Record<string, unknown> {
  if (!isRecord(value)) return {};
  const { enabled, pairingSecret, pairingGeneration, endpoint, pending, ...unknown } = value;
  return unknown;
}

function isAcknowledgement(response: BridgeResponse, expectedGeneration: number): boolean {
  return response.generation === expectedGeneration
    && (response.status === "accepted" || response.status === "already_current" || response.status === "stale_revision");
}

function samePendingEvent(left: PendingEvent, right: PendingEvent): boolean {
  return left.event_id === right.event_id
    && left.generation === right.generation
    && left.source_id === right.source_id
    && left.source_revision === right.source_revision;
}

function parsePairingPayload(value: string): PairingPayload | undefined {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!isRecord(parsed)
      || parsed.protocol !== PROTOCOL_VERSION
      || !isEndpoint(parsed.endpoint)
      || typeof parsed.pairingSecret !== "string" || parsed.pairingSecret.length < 16
      || !isNonNegativeInteger(parsed.pairingGeneration)) return undefined;
    return {
      protocol: PROTOCOL_VERSION,
      endpoint: parsed.endpoint,
      pairingSecret: parsed.pairingSecret,
      pairingGeneration: parsed.pairingGeneration,
    };
  } catch {
    return undefined;
  }
}

function descriptorFor(file: TFile, content: string, pairingSecret: string, generation: number): PendingEvent {
  const sourceId = `obsidian:source:hmac-sha256:${hmac(pairingSecret, `neoth/obsidian-archive-bridge/source/v1\0${normalizePath(file.path)}`)}`;
  const revision = `hmac-sha256:${hmac(pairingSecret, `neoth/obsidian-archive-bridge/revision/v1\0${sourceId}\0${content}`)}`;
  return { event_id: newEventId(), generation, source_id: sourceId, source_revision: revision };
}

function privateIpcExchange(
  endpoint: string,
  request: BridgeStatusRequest | BridgeSyncRequest,
  onAbort?: (cancel: () => void) => void,
  onSettled?: (cancel: () => void) => void,
): Promise<BridgeResponse> {
  return new Promise((resolve, reject) => {
    let settled = false;
    let wire = "";
    let receivedBytes = 0;
    const decoder = new TextDecoder();
    const socket = net.createConnection({ path: endpoint });
    let timeout: ReturnType<typeof setTimeout> | undefined;
    const cancel = () => fail(new Error("private IPC cancelled"));
    const finish = () => {
      if (timeout !== undefined) clearTimeout(timeout);
      onSettled?.(cancel);
    };
    const fail = (error: unknown) => {
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
    socket.once("connect", () => socket.write(`${JSON.stringify(request)}\n`));
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

function parseBridgeResponse(value: string): BridgeResponse | undefined {
  try {
    const parsed: unknown = JSON.parse(value);
    if (!isRecord(parsed) || typeof parsed.status !== "string") return undefined;
    const statuses: BridgeResponse["status"][] = ["ok", "accepted", "already_current", "stale_revision", "unpaired", "revoked", "generation_mismatch", "vault_mismatch", "event_reuse_conflict", "error"];
    if (!statuses.includes(parsed.status as BridgeResponse["status"])) return undefined;
    return {
      status: parsed.status as BridgeResponse["status"],
      generation: isNonNegativeInteger(parsed.generation) ? parsed.generation : undefined,
      receipt: typeof parsed.receipt === "string" ? parsed.receipt : undefined,
      message: typeof parsed.message === "string" ? parsed.message : undefined,
    };
  } catch {
    return undefined;
  }
}

function isNeothSessionNote(file: TFile): boolean {
  return file.path.startsWith(SESSION_ROOT) && file.extension === "md";
}

function isBridgeNote(content: string): boolean {
  const frontmatter = content.match(/^---\r?\n([\s\S]*?)\r?\n---(?:\r?\n|$)/)?.[1];
  return frontmatter !== undefined && new RegExp(`^source:\\s*["']?${BRIDGE_SOURCE}["']?\\s*$`, "m").test(frontmatter);
}

function normalizePath(path: string): string {
  return path.replaceAll("\\", "/").normalize("NFC");
}

function hmac(key: string, value: string): string {
  return crypto.createHmac("sha256", key).update(value, "utf8").digest("hex");
}

function newEventId(): string {
  return crypto.randomUUID?.() ?? `event-${Date.now()}-${Math.random().toString(16).slice(2)}`;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function isNonNegativeInteger(value: unknown): value is number {
  return typeof value === "number" && Number.isSafeInteger(value) && value >= 0;
}

function isEndpoint(value: unknown): value is string {
  return typeof value === "string" && value.length > 0 && value.length <= 512 && !value.includes("\0");
}

function isPendingEvent(value: unknown): value is PendingEvent {
  return isRecord(value)
    && typeof value.event_id === "string" && value.event_id.length > 0 && value.event_id.length <= 128
    && isNonNegativeInteger(value.generation)
    && typeof value.source_id === "string" && value.source_id.startsWith("obsidian:source:hmac-sha256:")
    && typeof value.source_revision === "string" && value.source_revision.startsWith("hmac-sha256:");
}
