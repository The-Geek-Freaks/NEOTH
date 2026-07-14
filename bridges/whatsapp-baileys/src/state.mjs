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
