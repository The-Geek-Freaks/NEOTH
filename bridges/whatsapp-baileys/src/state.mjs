import { chmod, mkdir, open, readFile, rename, rm, stat } from "node:fs/promises";
import path from "node:path";

const DEFAULT_MAX_EVENTS = 5_000;
const DEFAULT_MAX_BYTES = 128 * 1024 * 1024;
const DEFAULT_MAX_SEEN = 20_000;
const DEFAULT_MAX_OUTBOUND = 5_000;
const DEFAULT_OUTBOUND_TTL_MS = 24 * 60 * 60 * 1_000;

export async function ensurePrivateDirectory(directory) {
  await mkdir(directory, { recursive: true, mode: 0o700 });
  const metadata = await stat(directory);
  if (!metadata.isDirectory()) throw new Error(`${directory} is not a directory`);
  if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
    throw new Error(`${directory} is not owned by the service user`);
  }
  // Never swallow this: auth and message journals contain account secrets.
  await chmod(directory, 0o700);
}

async function syncDirectory(directory) {
  // POSIX directory fsync makes the rename durable. Node cannot open a Windows
  // directory handle for fsync; the temp file itself is still flushed there.
  if (process.platform === "win32") return;
  const handle = await open(directory, "r");
  try {
    await handle.sync();
  } finally {
    await handle.close();
  }
}

export async function atomicWrite(file, body) {
  const directory = path.dirname(file);
  await ensurePrivateDirectory(directory);
  const temporary = `${file}.${process.pid}.${Date.now()}.tmp`;
  let renamed = false;
  try {
    const handle = await open(temporary, "wx", 0o600);
    try {
      await handle.writeFile(body);
      await handle.sync();
    } finally {
      await handle.close();
    }
    await rename(temporary, file);
    renamed = true;
    await syncDirectory(directory);
  } finally {
    if (!renamed) await rm(temporary, { force: true }).catch(() => {});
  }
}

async function readJson(file, fallback) {
  try {
    return JSON.parse(await readFile(file, "utf8"));
  } catch (error) {
    if (error?.code === "ENOENT") return fallback;
    throw error;
  }
}

function positiveInteger(value, fallback) {
  const parsed = Number(value);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export class CursorError extends Error {
  constructor(code, message, details = {}) {
    super(message);
    this.name = "CursorError";
    this.code = code;
    this.details = details;
  }
}

export class EventJournal {
  static async open(directory, options = {}) {
    await ensurePrivateDirectory(directory);
    const journal = new EventJournal(directory, options);
    await journal.#load();
    return journal;
  }

  constructor(directory, options) {
    this.directory = directory;
    this.journalPath = path.join(directory, "events.jsonl");
    this.seenPath = path.join(directory, "seen.json");
    this.maxEvents = positiveInteger(options.maxEvents, DEFAULT_MAX_EVENTS);
    this.maxBytes = positiveInteger(options.maxBytes, DEFAULT_MAX_BYTES);
    this.maxSeen = positiveInteger(options.maxSeen, DEFAULT_MAX_SEEN);
    this.events = [];
    this.seen = new Map();
    this.nextSequence = 1;
    this.waiters = new Set();
    this.appendTail = Promise.resolve();
  }

  async #load() {
    let body = "";
    let repairedTrailingPartial = false;
    try {
      body = await readFile(this.journalPath, "utf8");
    } catch (error) {
      if (error?.code !== "ENOENT") throw error;
    }
    const lines = body.split("\n");
    let previousSequence = null;
    for (let index = 0; index < lines.length; index += 1) {
      const line = lines[index];
      if (!line.trim()) continue;
      try {
        const record = JSON.parse(line);
        if (!Number.isSafeInteger(record.seq) || record.seq < 1 || !record.event) {
          throw new Error("invalid journal record shape");
        }
        if (previousSequence !== null && record.seq !== previousSequence + 1) {
          throw new Error(`non-contiguous journal sequence after ${previousSequence}`);
        }
        this.events.push({ ...record, bytes: Buffer.byteLength(`${line}\n`) });
        this.nextSequence = Math.max(this.nextSequence, record.seq + 1);
        previousSequence = record.seq;
        if (index === lines.length - 1 && !body.endsWith("\n")) {
          repairedTrailingPartial = true;
        }
      } catch (error) {
        const isTrailingPartial = index === lines.length - 1 && !body.endsWith("\n");
        if (!isTrailingPartial) {
          throw new Error(`corrupt WhatsApp event journal at line ${index + 1}: ${error.message}`);
        }
        repairedTrailingPartial = true;
      }
    }

    // A crash may leave one partial final record. Ignoring it without
    // truncating would turn it into a corrupt interior record on next append.
    if (repairedTrailingPartial) {
      const repaired = this.events
        .map(({ seq, event }) => `${JSON.stringify({ seq, event })}\n`)
        .join("");
      await atomicWrite(this.journalPath, repaired);
    }

    const persistedSeen = await readJson(this.seenPath, []);
    if (!Array.isArray(persistedSeen)) throw new Error("seen.json must be an array");
    for (const id of persistedSeen) {
      if (typeof id === "string" && id) this.seen.set(id, true);
    }
    for (const record of this.events) {
      const id = record.event?.id;
      if (typeof id === "string" && id) this.seen.set(id, true);
    }
    this.#trimSeen();
    await this.#pruneIfNeeded();
  }

  latestCursor() {
    return String(this.nextSequence - 1);
  }

  // The status path may only act for an inbound turn still retained by this
  // durable journal. It does not accept a caller-supplied recipient alone.
  hasInboundAdmission(inboundId, chatId) {
    return this.events.some(({ event }) => event?.id === inboundId && event?.chat_id === chatId);
  }

  // Status creation is additionally bound to the account that received the
  // inbound turn.  Do not infer it while reading old records: an entry from
  // before this binding existed is intentionally ineligible for status sends.
  hasStatusAdmission(accountId, inboundId, chatId) {
    return this.events.some(({ event }) => (
      event?.id === inboundId
      && event?.chat_id === chatId
      && event?.account_id === accountId
      && (event.status_closed === undefined || event.status_closed === false)
    ));
  }

  // Closing the existing retained inbound needs no separately evictable
  // tombstone. Serialize with appends so an ingest cannot overwrite closure.
  async closeStatusAdmission(accountId, inboundId, chatId) {
    const close = async () => {
      const record = this.events.find(({ event }) => (
        event?.id === inboundId && event?.chat_id === chatId && event?.account_id === accountId
      ));
      if (!record) throw statusError("status_inbound_not_retained", 409, "final reply has no retained inbound binding");
      if (record.event.status_closed === true) return;
      record.event = { ...record.event, status_closed: true };
      record.bytes = Buffer.byteLength(`${JSON.stringify({ seq: record.seq, event: record.event })}\n`);
      const body = this.events.map(({ seq, event }) => `${JSON.stringify({ seq, event })}\n`).join("");
      // On ambiguous persistence failure keep memory closed; caller halts.
      await atomicWrite(this.journalPath, body);
      await this.#pruneIfNeeded();
    };
    const result = this.appendTail.then(close, close);
    this.appendTail = result.catch(() => {});
    return await result;
  }

  async append(event) {
    const append = () => this.#append(event);
    const result = this.appendTail.then(append, append);
    // Keep the serialization tail usable after a rejected append while still
    // returning the original rejection to its caller.
    this.appendTail = result.catch(() => {});
    return await result;
  }

  async #append(event) {
    if (!event || typeof event.id !== "string" || !event.id.trim()) {
      throw new Error("event.id is required");
    }
    if (this.seen.has(event.id)) return false;

    const record = { seq: this.nextSequence, event };
    const line = `${JSON.stringify(record)}\n`;
    const handle = await open(this.journalPath, "a", 0o600);
    try {
      await handle.write(line);
      await handle.sync();
    } finally {
      await handle.close();
    }

    this.nextSequence += 1;
    this.events.push({ ...record, bytes: Buffer.byteLength(line) });
    this.seen.set(event.id, true);
    this.#trimSeen();
    await atomicWrite(this.seenPath, `${JSON.stringify([...this.seen.keys()])}\n`);
    await this.#pruneIfNeeded();
    for (const notify of this.waiters) notify();
    this.waiters.clear();
    return true;
  }

  #trimSeen() {
    while (this.seen.size > this.maxSeen) {
      this.seen.delete(this.seen.keys().next().value);
    }
  }

  async #pruneIfNeeded() {
    let totalBytes = this.events.reduce((sum, event) => sum + event.bytes, 0);
    let changed = false;
    while (this.events.length > this.maxEvents || totalBytes > this.maxBytes) {
      const removed = this.events.shift();
      if (!removed) break;
      totalBytes -= removed.bytes;
      changed = true;
    }
    if (!changed) return;
    const body = this.events
      .map(({ seq, event }) => `${JSON.stringify({ seq, event })}\n`)
      .join("");
    await atomicWrite(this.journalPath, body);
  }

  readAfter(rawCursor, rawLimit = 50) {
    const cursor = Number(rawCursor ?? 0);
    const limit = Math.min(100, positiveInteger(rawLimit, 50));
    if (!Number.isSafeInteger(cursor) || cursor < 0) {
      throw new CursorError("invalid_cursor", "cursor must be a non-negative integer");
    }
    const latest = this.nextSequence - 1;
    if (cursor > latest) {
      throw new CursorError("future_cursor", "cursor is ahead of the bridge journal", {
        latest_cursor: String(latest),
      });
    }
    const earliest = this.events[0]?.seq ?? this.nextSequence;
    if (cursor < earliest - 1) {
      throw new CursorError("cursor_expired", "cursor predates retained bridge events", {
        earliest_cursor: String(earliest - 1),
        latest_cursor: String(latest),
      });
    }
    const selected = this.events.filter((record) => record.seq > cursor).slice(0, limit);
    return {
      cursor: String(selected.at(-1)?.seq ?? cursor),
      messages: selected.map((record) => record.event),
    };
  }

  async waitForEvents(timeoutMs) {
    await new Promise((resolve) => {
      const timer = setTimeout(() => {
        this.waiters.delete(done);
        resolve();
      }, timeoutMs);
      const done = () => {
        clearTimeout(timer);
        resolve();
      };
      this.waiters.add(done);
    });
  }
}

export class OutboundDedupStore {
  static async open(directory, options = {}) {
    await ensurePrivateDirectory(directory);
    const store = new OutboundDedupStore(directory, options);
    await store.#load();
    return store;
  }

  constructor(directory, options) {
    this.file = path.join(directory, "outbound-dedup.json");
    this.maxEntries = positiveInteger(options.maxEntries, DEFAULT_MAX_OUTBOUND);
    this.ttlMs = positiveInteger(options.ttlMs, DEFAULT_OUTBOUND_TTL_MS);
    this.entries = new Map();
  }

  async #load() {
    const rows = await readJson(this.file, []);
    if (!Array.isArray(rows)) throw new Error("outbound-dedup.json must be an array");
    for (const row of rows) {
      if (typeof row?.key !== "string" || !row.key) continue;
      const createdAt = Number(row.createdAt);
      const fingerprint = typeof row.fingerprint === "string" && row.fingerprint
        ? row.fingerprint
        : null;
      if (!Number.isFinite(createdAt)) {
        throw new Error(`outbound-dedup.json has invalid createdAt for key ${row.key}`);
      }
      if (row.state === "pending") {
        this.entries.set(row.key, { state: "pending", messageId: null, fingerprint, createdAt });
      } else if (typeof row?.messageId === "string" && row.messageId) {
        // Rows written before the pending-state hardening had no `state`.
        this.entries.set(row.key, { state: "sent", messageId: row.messageId, fingerprint, createdAt });
      }
    }
    this.#prune(Date.now());
  }

  get(key, now = Date.now()) {
    const entry = this.lookup(key, now);
    return entry?.state === "sent" ? entry.messageId : null;
  }

  lookup(key, now = Date.now()) {
    this.#prune(now);
    const entry = this.entries.get(key);
    return entry ? { ...entry } : null;
  }

  async reserve(key, now = Date.now(), fingerprint = null) {
    const existing = this.lookup(key, now);
    if (existing) return existing;
    const entry = { state: "pending", messageId: null, fingerprint, createdAt: now };
    this.entries.set(key, entry);
    this.#prune(now);
    await this.#persist();
    return { ...entry };
  }

  async complete(key, messageId, now = Date.now()) {
    const fingerprint = this.entries.get(key)?.fingerprint ?? null;
    this.entries.delete(key);
    this.entries.set(key, { state: "sent", messageId, fingerprint, createdAt: now });
    this.#prune(now);
    await this.#persist();
  }

  async put(key, messageId, now = Date.now()) {
    await this.complete(key, messageId, now);
  }

  async resolvePending(key, resolution, messageId = null, now = Date.now()) {
    const existing = this.lookup(key, now);
    if (!existing) throw new Error(`no outbound record exists for idempotency key ${key}`);
    if (existing.state !== "pending") {
      throw new Error(`idempotency key ${key} is already resolved as sent`);
    }
    if (resolution === "sent") {
      if (typeof messageId !== "string" || !messageId.trim()) {
        throw new Error("a WhatsApp message id is required for a sent resolution");
      }
      await this.complete(key, messageId.trim(), now);
      return;
    }
    if (resolution === "not-sent") {
      this.entries.delete(key);
      await this.#persist();
      return;
    }
    throw new Error("resolution must be `sent` or `not-sent`");
  }

  async #persist() {
    const rows = [...this.entries].map(([entryKey, value]) => ({ key: entryKey, ...value }));
    await atomicWrite(this.file, `${JSON.stringify(rows)}\n`);
  }

  #prune(now) {
    for (const [key, value] of this.entries) {
      // Unknown outcomes are safety tombstones. Deleting one automatically can
      // turn a delayed retry into a duplicate WhatsApp message, so only an
      // explicit offline operator reconciliation may resolve/remove pending.
      if (value.state === "sent" && now - value.createdAt >= this.ttlMs) {
        this.entries.delete(key);
      }
    }
    const sentKeys = [...this.entries]
      .filter(([, value]) => value.state === "sent")
      .map(([key]) => key);
    while (sentKeys.length > this.maxEntries) {
      this.entries.delete(sentKeys.shift());
    }
  }
}

// Status operations deliberately use a store separate from normal outbound
// sends. A sent outbound-dedup record may age out; a status message key must
// remain bound to its admitted inbound turn for every later edit. Pending
// records never expire and block that tuple until an explicit reconciliation.
export class StatusOperationStore {
  static async open(directory, options = {}) {
    await ensurePrivateDirectory(directory);
    const store = new StatusOperationStore(directory, options);
    await store.#load();
    return store;
  }

  constructor(directory, options) {
    this.file = path.join(directory, "status-operations.json");
    this.maxStatuses = positiveInteger(options.maxStatuses, DEFAULT_MAX_OUTBOUND);
    this.maxCommittedOperations = positiveInteger(options.maxCommittedOperations, 64);
    this.entries = new Map();
  }

  async #load() {
    const rows = await readJson(this.file, []);
    if (!Array.isArray(rows)) throw new Error("status-operations.json must be an array");
    for (const row of rows) {
      const tuple = row?.tuple;
      if (!validStatusTuple(tuple) || !Array.isArray(row.operations)) {
        throw new Error("status-operations.json has an invalid status binding");
      }
      const key = statusTupleKey(tuple);
      if (key !== row.key || this.entries.has(key)) {
        throw new Error("status-operations.json has duplicate or mismatched status binding");
      }
      const revision = Number(row.revision);
      if (!Number.isSafeInteger(revision) || revision < -1) {
        throw new Error("status-operations.json has an invalid revision");
      }
      const operations = row.operations.map((operation) => validStatusOperation(operation));
      const entry = {
        tuple: { ...tuple },
        revision,
        messageKey: row.messageKey ? validStatusMessageKey(row.messageKey) : null,
        operations,
        updatedAt: Number.isFinite(Number(row.updatedAt)) ? Number(row.updatedAt) : 0,
      };
      if ((entry.revision >= 0) !== Boolean(entry.messageKey)) {
        throw new Error("status-operations.json has an incomplete committed binding");
      }
      this.entries.set(key, entry);
    }
  }

  lookup(tuple) {
    const entry = this.entries.get(statusTupleKey(tuple));
    return entry ? cloneStatusEntry(entry) : null;
  }

  // A resolved tuple may be discarded only once its corresponding inbound is
  // no longer retained/admittable. Time/LRU order is unsafe: an old turn can
  // receive a new edit while a newer retained turn would otherwise be evicted
  // and allowed to create a duplicate visible status.
  async pruneResolvedWithoutAdmission(isRetained) {
    if (typeof isRetained !== "function") throw new Error("status admission predicate is required");
    for (const [key, entry] of this.entries) {
      if (entry.operations.some((item) => item.state === "pending")) continue;
      if (!isRetained(entry.tuple)) this.entries.delete(key);
    }
    await this.#persist();
  }

  hasCapacityForNewTuple(tuple) {
    return this.entries.has(statusTupleKey(tuple)) || this.entries.size < this.maxStatuses;
  }

  async reserve(tuple, operation, now = Date.now()) {
    const key = statusTupleKey(tuple);
    let entry = this.entries.get(key);
    if (entry) {
      // A later uncertain edit means this entire visible status is
      // indeterminate. Even a previously committed key must not make the
      // caller infer a usable status state until offline reconciliation.
      if (entry.operations.some((item) => item.state === "pending")) {
        throw statusError("outbound_outcome_unknown", 409, "an earlier status operation is unresolved for this turn");
      }
      const existing = entry.operations.find((item) => item.idempotencyKey === operation.idempotencyKey);
      if (existing) {
        if (!sameStatusOperation(existing, operation)) throw statusError("idempotency_payload_mismatch", 409, "status idempotency key is bound to a different operation");
        return { entry: cloneStatusEntry(entry), deduplicated: true };
      }
      if (operation.kind === "create") {
        throw statusError("status_already_created", 409, "a status message is already bound to this turn");
      }
      if (entry.revision < 0 || !entry.messageKey) throw statusError("status_binding_invalid", 409, "status binding is incomplete");
      if (operation.revision !== entry.revision + 1) {
        throw statusError("status_revision_conflict", 409, "status revision must strictly advance by one");
      }
    } else {
      if (operation.kind !== "create" || operation.revision !== 0) {
        throw statusError("status_not_created", 409, "status edits require a committed create for this turn");
      }
      entry = { tuple: { ...tuple }, revision: -1, messageKey: null, operations: [], updatedAt: now };
      this.entries.set(key, entry);
    }
    entry.operations.push({ ...operation, state: "pending", createdAt: now });
    entry.updatedAt = now;
    await this.#persist();
    return { entry: cloneStatusEntry(entry), deduplicated: false };
  }

  async complete(tuple, idempotencyKey, messageKey = null, now = Date.now()) {
    const entry = this.entries.get(statusTupleKey(tuple));
    const operation = entry?.operations.find((item) => item.idempotencyKey === idempotencyKey);
    if (!entry || !operation || operation.state !== "pending") {
      throw new Error("cannot complete an unknown or resolved status operation");
    }
    if (operation.kind === "create") {
      entry.messageKey = validStatusMessageKey(messageKey);
    } else if (!entry.messageKey) {
      throw new Error("cannot complete an edit without a stored status message key");
    }
    operation.state = "committed";
    entry.revision = operation.revision;
    entry.updatedAt = now;
    this.#trimOperations(entry);
    await this.#persist();
    return cloneStatusEntry(entry);
  }

  async resolvePending(idempotencyKey, resolution, messageKey = null, now = Date.now()) {
    for (const [key, entry] of this.entries) {
      const operation = entry.operations.find((item) => item.idempotencyKey === idempotencyKey);
      if (!operation) continue;
      if (operation.state !== "pending") throw new Error("status operation is already resolved");
      if (resolution === "sent") return await this.complete(entry.tuple, idempotencyKey, messageKey, now);
      if (resolution !== "not-sent") throw new Error("resolution must be `sent` or `not-sent`");
      entry.operations = entry.operations.filter((item) => item !== operation);
      entry.updatedAt = now;
      if (entry.revision < 0 && entry.operations.length === 0) this.entries.delete(key);
      await this.#persist();
      return;
    }
    throw new Error(`no status operation exists for idempotency key ${idempotencyKey}`);
  }

  async #persist() {
    const rows = [...this.entries].map(([key, value]) => ({ key, ...cloneStatusEntry(value) }));
    await atomicWrite(this.file, `${JSON.stringify(rows)}\n`);
  }

  #trimOperations(entry) {
    const committed = entry.operations.filter((item) => item.state === "committed");
    if (committed.length <= this.maxCommittedOperations) return;
    const retain = new Set(committed.slice(-this.maxCommittedOperations));
    entry.operations = entry.operations.filter((item) => item.state === "pending" || retain.has(item));
  }

}

function statusTupleKey(tuple) {
  return JSON.stringify([tuple.accountId, tuple.chatId, tuple.inboundId]);
}

function validStatusTuple(value) {
  return value && ["accountId", "chatId", "inboundId"].every((field) => typeof value[field] === "string" && value[field].length > 0 && value[field].length <= 512);
}

function validStatusMessageKey(value) {
  if (!value || typeof value.id !== "string" || !value.id || typeof value.remoteJid !== "string" || !value.remoteJid || value.fromMe !== true) {
    throw new Error("status message key must include id, remoteJid, and fromMe=true");
  }
  return {
    id: value.id,
    remoteJid: value.remoteJid,
    fromMe: true,
    ...(typeof value.participant === "string" && value.participant ? { participant: value.participant } : {}),
  };
}

function validStatusOperation(value) {
  if (!value || !["create", "edit"].includes(value.kind) || typeof value.idempotencyKey !== "string" || !value.idempotencyKey || typeof value.fingerprint !== "string" || !value.fingerprint || !Number.isSafeInteger(value.revision) || value.revision < 0 || !["pending", "committed"].includes(value.state)) {
    throw new Error("status-operations.json has an invalid operation");
  }
  return { kind: value.kind, idempotencyKey: value.idempotencyKey, fingerprint: value.fingerprint, revision: value.revision, state: value.state, createdAt: Number(value.createdAt) || 0 };
}

function sameStatusOperation(left, right) {
  return left.kind === right.kind && left.revision === right.revision && left.fingerprint === right.fingerprint;
}

function cloneStatusEntry(entry) {
  return {
    tuple: { ...entry.tuple },
    revision: entry.revision,
    messageKey: entry.messageKey ? { ...entry.messageKey } : null,
    operations: entry.operations.map((item) => ({ ...item })),
    updatedAt: entry.updatedAt,
  };
}

function statusError(code, statusCode, message) {
  const error = new Error(message);
  error.code = code;
  error.statusCode = statusCode;
  return error;
}
