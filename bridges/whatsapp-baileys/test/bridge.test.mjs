import assert from "node:assert/strict";
import { chmod, mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { execFile } from "node:child_process";
import { promisify } from "node:util";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { createBridgeServer } from "../src/api.mjs";
import { BaileysRuntime } from "../src/runtime.mjs";
import { openDurableAuthState } from "../src/auth-state.mjs";
import { CursorError, EventJournal, OutboundDedupStore, StatusOperationStore } from "../src/state.mjs";
import { statusEditEnabledFromEnv } from "../src/status_config.mjs";

async function temporaryDirectory() {
  return await mkdtemp(path.join(os.tmpdir(), "neoth-wa-bridge-"));
}

const execFileAsync = promisify(execFile);

test("event journal persists cursor and deduplicates across restart", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  let journal = await EventJournal.open(directory);
  assert.equal(await journal.append({ id: "chat:m1", text: "one" }), true);
  assert.equal(await journal.append({ id: "chat:m1", text: "duplicate" }), false);
  assert.deepEqual(journal.readAfter("0").messages.map((event) => event.text), ["one"]);
  journal = await EventJournal.open(directory);
  assert.equal(journal.latestCursor(), "1");
  assert.equal(await journal.append({ id: "chat:m1", text: "duplicate after restart" }), false);
  assert.equal(await journal.append({ id: "chat:m2", text: "two" }), true);
  assert.equal(journal.readAfter("1").messages[0].id, "chat:m2");
});

test("journal rejects expired cursor instead of silently losing events", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const journal = await EventJournal.open(directory, { maxEvents: 2, maxBytes: 1_000_000 });
  await journal.append({ id: "1", text: "one" });
  await journal.append({ id: "2", text: "two" });
  await journal.append({ id: "3", text: "three" });
  assert.throws(() => journal.readAfter("0"), (error) => error instanceof CursorError && error.code === "cursor_expired");
  const body = await readFile(path.join(directory, "events.jsonl"), "utf8");
  assert.equal(body.trim().split("\n").length, 2);
});

test("journal repairs one crash-truncated final record before next append", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const first = JSON.stringify({ seq: 1, event: { id: "one", text: "one" } });
  await writeFile(path.join(directory, "events.jsonl"), `${first}\n{\"seq\":2`, { mode: 0o600 });
  let journal = await EventJournal.open(directory);
  assert.equal(journal.latestCursor(), "1");
  assert.equal(await journal.append({ id: "two", text: "two" }), true);
  journal = await EventJournal.open(directory);
  assert.deepEqual(journal.readAfter("0").messages.map((event) => event.id), ["one", "two"]);
});

test("outbound idempotency survives restart", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  let store = await OutboundDedupStore.open(directory);
  const now = Date.now();
  await store.put("reply:m1", "sent-1", now);
  store = await OutboundDedupStore.open(directory, { ttlMs: 10_000 });
  assert.equal(store.get("reply:m1", now + 1_000), "sent-1");
  assert.equal(store.get("reply:m1", now + 20_000), null);
});

test("pending outbound intent survives restart and remains fail-closed", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  let store = await OutboundDedupStore.open(directory);
  const now = Date.now();
  await store.reserve("reply:unknown", now);
  store = await OutboundDedupStore.open(directory, { ttlMs: 10_000 });
  assert.equal(store.lookup("reply:unknown", now + 1_000)?.state, "pending");
  assert.equal(store.get("reply:unknown", now + 1_000), null);
});

test("pending outbound tombstones ignore TTL and sent-entry caps until reconciliation", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const now = Date.now();
  const store = await OutboundDedupStore.open(directory, { ttlMs: 10, maxEntries: 1 });
  await store.reserve("pending-1", now);
  await store.reserve("pending-2", now + 1);
  await store.put("sent-1", "message-1", now + 2);
  await store.put("sent-2", "message-2", now + 3);
  assert.equal(store.lookup("pending-1", now + 1_000_000)?.state, "pending");
  assert.equal(store.lookup("pending-2", now + 1_000_000)?.state, "pending");
  await store.resolvePending("pending-1", "not-sent", null, now + 1_000_001);
  assert.equal(store.lookup("pending-1", now + 1_000_002), null);
  await store.resolvePending("pending-2", "sent", "operator-confirmed-id", now + 1_000_003);
  assert.equal(store.get("pending-2", now + 1_000_004), "operator-confirmed-id");
});

test("repo-owned auth state atomically persists credentials and signal keys", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const authDirectory = path.join(directory, "auth");
  let auth = await openDurableAuthState(authDirectory);
  auth.state.creds.registered = true;
  await auth.saveCreds();
  await Promise.all([
    auth.state.keys.set({ session: { alice: Buffer.from("alice") } }),
    auth.state.keys.set({ session: { bob: Buffer.from("bob") } }),
  ]);
  await auth.close();
  auth = await openDurableAuthState(authDirectory);
  assert.equal(auth.state.creds.registered, true);
  const keys = await auth.state.keys.get("session", ["alice", "bob"]);
  assert.equal(Buffer.from(keys.alice).toString(), "alice");
  assert.equal(Buffer.from(keys.bob).toString(), "bob");
  await auth.close();
});

test("corrupt auth state fails closed and releases its process lock", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const authDirectory = path.join(directory, "auth");
  await mkdir(authDirectory, { mode: 0o700 });
  const file = path.join(authDirectory, "auth-state.json");
  await writeFile(file, "not-json", { mode: 0o600 });
  await assert.rejects(openDurableAuthState(authDirectory), /cannot load durable/u);
  await rm(file);
  const recovered = await openDurableAuthState(authDirectory);
  await recovered.close();
});

test("systemd env preflight requires an owner-only regular file", {
  skip: process.platform === "win32",
}, async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const file = path.join(directory, "bridge.env");
  await writeFile(file, `NEOTH_WA_BRIDGE_TOKEN=${"a".repeat(64)}\n`, { mode: 0o600 });
  await chmod(file, 0o600);
  const script = path.resolve("src/check-env.mjs");
  await execFileAsync(process.execPath, [script, file]);
  await chmod(file, 0o644);
  await assert.rejects(execFileAsync(process.execPath, [script, file]));
});

test("inbound journal failure fail-stops and later events cannot overtake", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  let appends = 0;
  let ended = false;
  const runtime = new BaileysRuntime({
    stateDirectory: directory,
    journal: {
      append: async () => {
        appends += 1;
        throw new Error("simulated fsync failure");
      },
    },
    outboundStore: await OutboundDedupStore.open(directory),
  });
  runtime.connected = true;
  runtime.socket = { end: () => { ended = true; } };
  const message = (id) => ({
    key: { remoteJid: "491701234567@s.whatsapp.net", id, fromMe: false },
    message: { conversation: `message ${id}` },
    messageTimestamp: 1,
  });
  await runtime.handleInboundBatch([message("one"), message("two")], runtime.socket);
  assert.equal(appends, 1, "the second event in the failed batch must not overtake");
  assert.equal(runtime.health().status, "fatal");
  assert.equal(runtime.health().error_code, "inbound_journal_persistence_failed");
  assert.equal(ended, true);
  await runtime.handleInboundBatch([message("three")], runtime.socket);
  assert.equal(appends, 1, "events after fail-stop must not enter the journal");
});

test("inbound journal persists the immutable linked account at arrival", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const journal = await EventJournal.open(directory);
  const runtime = new BaileysRuntime({
    stateDirectory: directory,
    journal,
    outboundStore: await OutboundDedupStore.open(directory),
  });
  const socketA = { user: { id: "491701234567@s.whatsapp.net" } };
  const socketB = { user: { id: "491709999999@s.whatsapp.net" } };
  runtime.socket = socketA;
  runtime.accountId = "+491701234567";
  const ingest = runtime.handleInboundBatch([{
    key: { remoteJid: "491701000000@s.whatsapp.net", id: "arrival-1", fromMe: false },
    message: { conversation: "arrival bound" },
    messageTimestamp: 1,
  }], socketA);
  runtime.socket = socketB;
  runtime.accountId = "+491709999999";
  await ingest;
  assert.equal(journal.readAfter("0").messages[0].account_id, "+491701234567");
  await runtime.handleInboundBatch([{
    key: { remoteJid: "491701000000@s.whatsapp.net", id: "arrival-unknown", fromMe: false },
    message: { conversation: "unknown account remains ineligible" },
    messageTimestamp: 1,
  }], {});
  assert.equal(journal.readAfter("1").messages[0].account_id, undefined);
});

test("concurrent duplicate sends cross the WhatsApp boundary once", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const outboundStore = await OutboundDedupStore.open(directory);
  const runtime = new BaileysRuntime({
    stateDirectory: directory,
    journal: await EventJournal.open(directory),
    outboundStore,
  });
  let sends = 0;
  runtime.connected = true;
  runtime.socket = {
    sendMessage: async () => {
      sends += 1;
      await new Promise((resolve) => setTimeout(resolve, 10));
      return { key: { id: "out-one" } };
    },
  };
  const request = { to: "+491701234567", text: "hello", idempotency_key: "same" };
  const [first, second] = await Promise.all([runtime.send(request), runtime.send(request)]);
  assert.equal(sends, 1);
  assert.equal(first.message_id, "out-one");
  assert.equal(second.message_id, "out-one");
  assert.equal(second.deduplicated, true);
});

test("one idempotency key cannot silently deduplicate a different payload", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const outboundStore = await OutboundDedupStore.open(directory);
  const runtime = new BaileysRuntime({
    stateDirectory: directory,
    journal: await EventJournal.open(directory),
    outboundStore,
  });
  let sends = 0;
  runtime.connected = true;
  runtime.socket = {
    sendMessage: async () => {
      sends += 1;
      return { key: { id: `out-${sends}` } };
    },
  };
  await runtime.send({ to: "+491701234567", text: "one", idempotency_key: "fixed" });
  await assert.rejects(
    runtime.send({ to: "+491701234567", text: "two", idempotency_key: "fixed" }),
    (error) => error?.code === "idempotency_payload_mismatch",
  );
  assert.equal(sends, 1);
});

test("outbound validation rejects non-canonical media before reserving or sending", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const outboundStore = await OutboundDedupStore.open(directory);
  const runtime = new BaileysRuntime({
    stateDirectory: directory,
    journal: await EventJournal.open(directory),
    outboundStore,
  });
  let sends = 0;
  runtime.connected = true;
  runtime.socket = { sendMessage: async () => { sends += 1; return { key: { id: "bad" } }; } };
  await assert.rejects(
    runtime.send({
      to: "+491701234567",
      idempotency_key: "bad-media",
      media: { kind: "image", mime: "image/png\r\nX: y", data_b64: "%%%" },
    }),
  );
  assert.equal(sends, 0);
  assert.equal(outboundStore.lookup("bad-media"), null, "invalid payload must not reserve a key");
});

test("HTTP API requires bearer and exposes cursor plus send", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const journal = await EventJournal.open(directory);
  await journal.append({ id: "chat:m1", text: "hello" });
  const sent = [];
  const statuses = [];
  const runtime = {
    health: () => ({ status: "ok", connected: true, linked: true, account_id: "+49123", status_edit_v1: true }),
    send: async (body) => { sent.push(body); return { message_id: "out-1", deduplicated: false }; },
    status: async (body) => { statuses.push(body); return { message_id: "status-1", deduplicated: false }; },
  };
  const token = "x".repeat(32);
  const server = await createBridgeServer({ token, journal, runtime, port: 0 });
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address.port}`;
  assert.equal((await fetch(`${base}/v1/health`)).status, 401);
  assert.equal((await fetch(`${base}/v1/status`, { method: "POST" })).status, 401);
  const headers = { authorization: `Bearer ${token}` };
  const health = await (await fetch(`${base}/v1/health`, { headers })).json();
  assert.equal(health.latest_cursor, "1");
  assert.equal(health.capabilities.media, true);
  assert.equal(health.capabilities.status_edit_v1, true);
  const batch = await (await fetch(`${base}/v1/messages?cursor=0&timeout_ms=0`, { headers })).json();
  assert.equal(batch.cursor, "1");
  assert.equal(batch.messages[0].id, "chat:m1");
  const sendResponse = await fetch(`${base}/v1/messages`, {
    method: "POST",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify({ to: "+49123", text: "reply", idempotency_key: "reply:m1" }),
  });
  assert.equal(sendResponse.status, 200);
  assert.equal((await sendResponse.json()).message_id, "out-1");
  assert.equal(sent[0].idempotency_key, "reply:m1");
  const statusResponse = await fetch(`${base}/v1/status`, {
    method: "POST",
    headers: { ...headers, "content-type": "application/json" },
    body: JSON.stringify({ op: "create", account_id: "+49123", chat_id: "chat", inbound_id: "chat:m1", idempotency_key: "neoth-wa-status-create-1", revision: 0, activity: { phase: "start" } }),
  });
  assert.equal(statusResponse.status, 200);
  assert.equal((await statusResponse.json()).message_id, "status-1");
  assert.equal(statuses[0].inbound_id, "chat:m1");
});

test("HTTP API reports cursor expiry as 409", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const journal = await EventJournal.open(directory, { maxEvents: 1 });
  await journal.append({ id: "1", text: "one" });
  await journal.append({ id: "2", text: "two" });
  const token = "y".repeat(32);
  const server = await createBridgeServer({
    token,
    journal,
    runtime: { health: () => ({ status: "ok" }), send: async () => ({ message_id: "x" }) },
    port: 0,
  });
  t.after(() => server.close());
  const response = await fetch(`http://127.0.0.1:${server.address.port}/v1/messages?cursor=0&timeout_ms=0`, {
    headers: { authorization: `Bearer ${token}` },
  });
  assert.equal(response.status, 409);
  assert.equal((await response.json()).error, "cursor_expired");
});

async function statusFixture(directory, storeOptions = {}) {
  const journal = await EventJournal.open(directory);
  await journal.append({ id: "120@g.us:in-1", chat_id: "120@g.us", account_id: "+491701234567", text: "admitted" });
  const runtime = new BaileysRuntime({
    stateDirectory: directory,
    journal,
    outboundStore: await OutboundDedupStore.open(directory),
    statusStore: await StatusOperationStore.open(directory, storeOptions),
  });
  runtime.connected = true;
  runtime.accountId = "+491701234567";
  return runtime;
}

function statusRequest(overrides = {}) {
  return {
    op: "create",
    account_id: "+491701234567",
    chat_id: "120@g.us",
    inbound_id: "120@g.us:in-1",
    idempotency_key: "neoth-wa-status-create-1",
    revision: 0,
    activity: { phase: "tool_start", label: "Read file", step: 1, total: 2 },
    ...overrides,
  };
}

test("status create and edit retain the full admitted Baileys message key", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtime = await statusFixture(directory);
  const calls = [];
  runtime.socket = {
    sendMessage: async (chat, content) => {
      calls.push({ chat, content });
      return { key: { id: calls.length === 1 ? "status-1" : "edit-1", remoteJid: chat, fromMe: true } };
    },
  };
  assert.equal((await runtime.status(statusRequest())).message_id, "status-1");
  assert.equal((await runtime.status(statusRequest({
    op: "edit", revision: 1, idempotency_key: "neoth-wa-status-edit-1",
    activity: { phase: "tool_finish", label: "Read file", step: 2, total: 2 },
  }))).message_id, "status-1");
  assert.deepEqual(calls[1], {
    chat: "120@g.us",
    content: { text: "Completed: Read file (2/2)", edit: { id: "status-1", remoteJid: "120@g.us", fromMe: true } },
  });
});

test("status transport rejects unadmitted tuples, rotated accounts, raw details, and wa-reply keys", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtime = await statusFixture(directory);
  let calls = 0;
  runtime.socket = { sendMessage: async () => { calls += 1; return { key: { id: "unused", remoteJid: "120@g.us", fromMe: true } }; } };
  await assert.rejects(runtime.status(statusRequest({ inbound_id: "missing" })), (error) => error?.code === "status_inbound_not_retained");
  await assert.rejects(runtime.status(statusRequest({ account_id: "+499999999999" })), (error) => error?.code === "status_account_mismatch");
  await assert.rejects(runtime.status(statusRequest({ activity: { phase: "tool_start", label: "Read file", detail: "secret args" } })), (error) => error?.code === "invalid_status_activity");
  await assert.rejects(runtime.status(statusRequest({ idempotency_key: "neoth-wa-reply-in-1" })), (error) => error?.code === "invalid_status_operation");
  assert.equal(calls, 0);
});

test("status transport rejects an inbound retained before QR account rotation", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const journal = await EventJournal.open(directory);
  await journal.append({ id: "120@g.us:old-account", chat_id: "120@g.us", account_id: "+491701000000", text: "old account inbound" });
  const runtime = new BaileysRuntime({
    stateDirectory: directory,
    journal,
    outboundStore: await OutboundDedupStore.open(directory),
    statusStore: await StatusOperationStore.open(directory),
  });
  runtime.connected = true;
  runtime.accountId = "+491701234567";
  let sends = 0;
  runtime.socket = { sendMessage: async () => { sends += 1; return { key: { id: "must-not-send" } }; } };
  await assert.rejects(
    runtime.status(statusRequest({ inbound_id: "120@g.us:old-account" })),
    (error) => error?.code === "status_inbound_not_retained",
  );
  assert.equal(sends, 0);
});

test("persisted legacy inbound without an arrival account remains status-ineligible after restart", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  let journal = await EventJournal.open(directory);
  await journal.append({ id: "120@g.us:legacy", chat_id: "120@g.us", text: "legacy v1 delivery" });
  journal = await EventJournal.open(directory);
  const runtime = new BaileysRuntime({
    stateDirectory: directory,
    journal,
    outboundStore: await OutboundDedupStore.open(directory),
    statusStore: await StatusOperationStore.open(directory),
  });
  runtime.connected = true;
  runtime.accountId = "+491701234567";
  let sends = 0;
  runtime.socket = { sendMessage: async () => { sends += 1; return { key: { id: "must-not-send" } }; } };
  await assert.rejects(
    runtime.status(statusRequest({ inbound_id: "120@g.us:legacy" })),
    (error) => error?.code === "status_inbound_not_retained",
  );
  assert.equal(sends, 0);
  assert.equal(journal.readAfter("0").messages[0].text, "legacy v1 delivery");
});

test("status rotation after durable reservation leaves a pending tombstone and sends nothing", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtime = await statusFixture(directory);
  let sends = 0;
  const socketA = { sendMessage: async () => { sends += 1; throw new Error("must not write A"); } };
  const socketB = { sendMessage: async () => { sends += 1; throw new Error("must not write B"); } };
  runtime.socket = socketA;
  const reserve = runtime.statusStore.reserve.bind(runtime.statusStore);
  runtime.statusStore.reserve = async (...args) => {
    const prepared = await reserve(...args);
    runtime.socket = socketB;
    runtime.accountId = "+491709999999";
    return prepared;
  };
  await assert.rejects(runtime.status(statusRequest()), (error) => error?.code === "status_connection_changed");
  const tuple = { accountId: "+491701234567", chatId: "120@g.us", inboundId: "120@g.us:in-1" };
  assert.equal((await StatusOperationStore.open(directory)).lookup(tuple).operations[0].state, "pending");
  assert.equal(sends, 0);
});

test("pending status operations block every later status operation until explicit reconciliation", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtime = await statusFixture(directory);
  let sends = 0;
  runtime.socket = { sendMessage: async () => { sends += 1; throw new Error("network dropped after send boundary"); } };
  await assert.rejects(runtime.status(statusRequest()));
  runtime.socket = { sendMessage: async () => { sends += 1; return { key: { id: "must-not-send", remoteJid: "120@g.us", fromMe: true } }; } };
  await assert.rejects(runtime.status(statusRequest({ idempotency_key: "neoth-wa-status-create-2" })), (error) => error?.code === "outbound_outcome_unknown");
  await assert.rejects(runtime.status(statusRequest({ op: "edit", revision: 1, idempotency_key: "neoth-wa-status-edit-1" })), (error) => error?.code === "outbound_outcome_unknown");
  assert.equal(sends, 1);
  const store = await StatusOperationStore.open(directory);
  assert.equal(store.lookup({ accountId: "+491701234567", chatId: "120@g.us", inboundId: "120@g.us:in-1" }).operations[0].state, "pending");
});

test("committed status operation is idempotent only with the exact binding and payload", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtime = await statusFixture(directory);
  let sends = 0;
  runtime.socket = { sendMessage: async (chat) => { sends += 1; return { key: { id: "status-1", remoteJid: chat, fromMe: true } }; } };
  const first = await runtime.status(statusRequest());
  const second = await runtime.status(statusRequest());
  assert.equal(first.deduplicated, false);
  assert.equal(second.deduplicated, true);
  await assert.rejects(runtime.status(statusRequest({ activity: { phase: "tool_start", label: "Write file" } })), (error) => error?.code === "idempotency_payload_mismatch");
  assert.equal(sends, 1);
});

test("pending status tombstones survive restart and cannot be pruned into a later edit", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const tuple = { accountId: "+491701234567", chatId: "120@g.us", inboundId: "120@g.us:in-1" };
  const create = { kind: "create", idempotencyKey: "neoth-wa-status-create-pending", revision: 0, fingerprint: "a".repeat(64) };
  let store = await StatusOperationStore.open(directory, { maxStatuses: 1, maxCommittedOperations: 1 });
  await store.reserve(tuple, create, 1);
  store = await StatusOperationStore.open(directory, { maxStatuses: 1, maxCommittedOperations: 1 });
  assert.equal(store.lookup(tuple).operations[0].state, "pending");
  await assert.rejects(
    store.reserve(tuple, { kind: "edit", idempotencyKey: "neoth-wa-status-edit-later", revision: 1, fingerprint: "b".repeat(64) }, 2),
    (error) => error?.code === "outbound_outcome_unknown",
  );
});

test("an unresolved edit blocks even a prior committed status receipt", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const tuple = { accountId: "+491701234567", chatId: "120@g.us", inboundId: "120@g.us:in-1" };
  const create = { kind: "create", idempotencyKey: "neoth-wa-status-create-committed", revision: 0, fingerprint: "a".repeat(64) };
  const store = await StatusOperationStore.open(directory);
  await store.reserve(tuple, create, 1);
  await store.complete(tuple, create.idempotencyKey, { id: "status-1", remoteJid: "120@g.us", fromMe: true }, 2);
  await store.reserve(tuple, { kind: "edit", idempotencyKey: "neoth-wa-status-edit-pending", revision: 1, fingerprint: "b".repeat(64) }, 3);
  await assert.rejects(store.reserve(tuple, create, 4), (error) => error?.code === "outbound_outcome_unknown");
});

test("status capacity fails closed while every bound inbound remains retained", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtime = await statusFixture(directory, { maxStatuses: 2 });
  await runtime.journal.append({ id: "120@g.us:in-2", chat_id: "120@g.us", account_id: "+491701234567", text: "admitted two" });
  await runtime.journal.append({ id: "120@g.us:in-3", chat_id: "120@g.us", account_id: "+491701234567", text: "admitted three" });
  let sends = 0;
  runtime.socket = { sendMessage: async (chat) => ({ key: { id: `status-${++sends}`, remoteJid: chat, fromMe: true } }) };
  await runtime.status(statusRequest());
  await runtime.status(statusRequest({ inbound_id: "120@g.us:in-2", idempotency_key: "neoth-wa-status-create-2" }));
  await runtime.status(statusRequest({ op: "edit", revision: 1, idempotency_key: "neoth-wa-status-edit-1", activity: { phase: "finalize" } }));
  await assert.rejects(
    runtime.status(statusRequest({ inbound_id: "120@g.us:in-3", idempotency_key: "neoth-wa-status-create-3" })),
    (error) => error?.code === "status_capacity_exhausted",
  );
  assert.equal(sends, 3, "retained tuple capacity cannot evict another visible status binding");
});

test("committed status create survives restart and edits with its stored full key", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  let runtime = await statusFixture(directory);
  runtime.socket = { sendMessage: async (chat) => ({ key: { id: "status-1", remoteJid: chat, fromMe: true, participant: "+491701234567" } }) };
  await runtime.status(statusRequest());
  const journal = await EventJournal.open(directory);
  runtime = new BaileysRuntime({
    stateDirectory: directory,
    journal,
    outboundStore: await OutboundDedupStore.open(directory),
    statusStore: await StatusOperationStore.open(directory),
  });
  runtime.connected = true;
  runtime.accountId = "+491701234567";
  let edit = null;
  runtime.socket = { sendMessage: async (_chat, content) => { edit = content.edit; return { key: { id: "edit-1", remoteJid: "120@g.us", fromMe: true } }; } };
  await runtime.status(statusRequest({ op: "edit", revision: 1, idempotency_key: "neoth-wa-status-edit-restart", activity: { phase: "finalize" } }));
  assert.deepEqual(edit, { id: "status-1", remoteJid: "120@g.us", fromMe: true, participant: "+491701234567" });
});

test("status reconciliation command clears only an explicitly reconciled pending operation", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const tuple = { accountId: "+491701234567", chatId: "120@g.us", inboundId: "120@g.us:in-1" };
  const key = "neoth-wa-status-create-reconcile";
  const store = await StatusOperationStore.open(directory);
  await store.reserve(tuple, { kind: "create", idempotencyKey: key, revision: 0, fingerprint: "c".repeat(64) });
  await execFileAsync(process.execPath, [path.resolve("src/reconcile.mjs"), "status", key, "not-sent"], {
    env: { ...process.env, NEOTH_WA_STATE_DIR: directory },
  });
  assert.equal((await StatusOperationStore.open(directory)).lookup(tuple), null);
});

test("status transport opt-in parser defaults off and runtime health reports the configured capability", async (t) => {
  assert.equal(statusEditEnabledFromEnv({}), false);
  assert.equal(statusEditEnabledFromEnv({ NEOTH_WA_STATUS_EDIT_V1: "true" }), false);
  assert.equal(statusEditEnabledFromEnv({ NEOTH_WA_STATUS_EDIT_V1: "1" }), true);
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const off = new BaileysRuntime({
    stateDirectory: directory,
    journal: await EventJournal.open(directory),
    outboundStore: await OutboundDedupStore.open(directory),
  });
  assert.equal(off.health().status_edit_v1, false);
  assert.equal((await statusFixture(directory)).health().status_edit_v1, true);
});

function statusFinalRequest(overrides = {}) {
  return {
    to: "120@g.us", text: "Final reply", idempotency_key: "neoth-wa-reply-c578494e4757bea8f44d9d22c8ec9a314c99b594f97880d423a66bfb6d82e007",
    status_turn: { account_id: "+491701234567", chat_id: "120@g.us", inbound_id: "120@g.us:in-1" },
    ...overrides,
  };
}

test("final reply HTTP barrier rejects a delayed status after final send and after restart", { timeout: 5000 }, async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtime = await statusFixture(directory);
  const calls = [];
  let enteredFinal;
  let releaseFinal;
  const entered = new Promise((resolve) => { enteredFinal = resolve; });
  const held = new Promise((resolve) => { releaseFinal = resolve; });
  runtime.socket = {
    sendMessage: async (chat, content) => {
      calls.push(content.text);
      if (content.text === "Final reply") { enteredFinal(); await held; }
      return { key: { id: `out-${calls.length}`, remoteJid: chat, fromMe: true } };
    },
  };
  await runtime.status(statusRequest());
  const token = "z".repeat(32);
  const server = await createBridgeServer({ token, journal: runtime.journal, runtime, port: 0 });
  t.after(() => { releaseFinal(); return server.close(); });
  const base = `http://127.0.0.1:${server.address.port}`;
  const post = (route, body) => fetch(`${base}${route}`, {
    method: "POST", headers: { authorization: `Bearer ${token}`, "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  const final = post("/v1/messages", statusFinalRequest());
  await entered;
  assert.equal(runtime.journal.hasStatusAdmission("+491701234567", "120@g.us:in-1", "120@g.us"), false);
  const delayed = post("/v1/status", statusRequest({
    op: "edit", revision: 1, idempotency_key: "neoth-wa-status-late",
    activity: { phase: "tool_finish", label: "Read file" },
  }));
  releaseFinal();
  assert.equal((await final).status, 200);
  assert.equal((await delayed).status, 409);
  assert.equal(calls.length, 2);
  assert.equal(calls[1], "Final reply");
  runtime.journal = await EventJournal.open(directory);
  await assert.rejects(runtime.status(statusRequest()), { code: "status_inbound_not_retained" });
  assert.equal(calls.length, 2);
});

test("journal closure survives concurrent append and restart without relying on status cache", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtime = await statusFixture(directory);
  await Promise.all([
    runtime.journal.closeStatusAdmission("+491701234567", "120@g.us:in-1", "120@g.us"),
    runtime.journal.append({ id: "120@g.us:in-2", chat_id: "120@g.us", account_id: "+491701234567", text: "next" }),
  ]);
  const journal = await EventJournal.open(directory);
  assert.equal(journal.latestCursor(), "2");
  assert.equal(journal.hasStatusAdmission("+491701234567", "120@g.us:in-1", "120@g.us"), false);
  assert.equal(journal.hasStatusAdmission("+491701234567", "120@g.us:in-2", "120@g.us"), true);
  await journal.closeStatusAdmission("+491701234567", "120@g.us:in-1", "120@g.us");
  assert.equal(journal.readAfter("0").messages[0].status_closed, true);
});

test("uncertain final send leaves status closed and outbound intent pending", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtime = await statusFixture(directory);
  let calls = 0;
  runtime.socket = { sendMessage: async () => { calls += 1; throw new Error("injected uncertain send"); } };
  await assert.rejects(runtime.send(statusFinalRequest()), /injected uncertain send/);
  assert.equal(runtime.outboundStore.lookup("neoth-wa-reply-c578494e4757bea8f44d9d22c8ec9a314c99b594f97880d423a66bfb6d82e007").state, "pending");
  runtime.journal = await EventJournal.open(directory);
  await assert.rejects(runtime.status(statusRequest()), { code: "status_inbound_not_retained" });
  await assert.rejects(runtime.send(statusFinalRequest()), { code: "outbound_outcome_unknown" });
  assert.equal(calls, 1);
});

test("final status binding refuses wrong account, recipient, namespace and unretained turn", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtime = await statusFixture(directory);
  let calls = 0;
  runtime.socket = { sendMessage: async () => { calls += 1; throw new Error("unexpected write"); } };
  const tuple = statusFinalRequest().status_turn;
  for (const body of [
    statusFinalRequest({ status_turn: { ...tuple, account_id: "+491700000000" } }),
    statusFinalRequest({ status_turn: { ...tuple, chat_id: "999@g.us" } }),
    statusFinalRequest({ idempotency_key: "unrelated-reply" }),
  ]) await assert.rejects(runtime.send(body), { code: "status_final_binding_mismatch" });
  await assert.rejects(runtime.send(statusFinalRequest({ idempotency_key: "neoth-wa-reply-8c39bf42dea1b2f4ebc871ad199f2e21d9928f1cd457e916f343bf56a299eb3f", status_turn: { ...tuple, inbound_id: "missing" } })), { code: "status_inbound_not_retained" });
  assert.equal(runtime.journal.hasStatusAdmission(tuple.account_id, tuple.inbound_id, tuple.chat_id), true);
  assert.equal(calls, 0);
});

test("durable final closure failure halts before any queued transport write", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtime = await statusFixture(directory);
  let calls = 0;
  runtime.socket = { sendMessage: async () => { calls += 1; throw new Error("unexpected write"); } };
  runtime.journal.closeStatusAdmission = async () => { throw new Error("injected closure persistence failure"); };
  const results = await Promise.allSettled([runtime.send(statusFinalRequest()), runtime.status(statusRequest())]);
  assert.deepEqual(results.map((result) => result.status), ["rejected", "rejected"]);
  assert.equal(runtime.fatalError.code, "status_close_persistence_failed");
  assert.equal(calls, 0);
});

test("account rotation after durable final closure cannot write through replacement socket", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtime = await statusFixture(directory);
  let calls = 0;
  runtime.socket = { sendMessage: async () => { calls += 1; throw new Error("old socket write"); } };
  const close = runtime.journal.closeStatusAdmission.bind(runtime.journal);
  runtime.journal.closeStatusAdmission = async (...args) => {
    await close(...args);
    runtime.accountId = "+491700000000";
    runtime.socket = { sendMessage: async () => { calls += 1; throw new Error("replacement socket write"); } };
  };
  await assert.rejects(runtime.send(statusFinalRequest()), { code: "status_connection_changed" });
  assert.equal(runtime.outboundStore.lookup("neoth-wa-reply-c578494e4757bea8f44d9d22c8ec9a314c99b594f97880d423a66bfb6d82e007").state, "pending");
  assert.equal(calls, 0);
});

test("status vocabulary distinguishes denied and unknown from successful tools", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtime = await statusFixture(directory);
  const texts = [];
  runtime.socket = { sendMessage: async (chat, content) => {
    texts.push(content.text);
    return { key: { id: "status-one", remoteJid: chat, fromMe: true } };
  } };
  await runtime.status(statusRequest({ activity: { phase: "tool_rejected", label: "Write file" } }));
  await runtime.status(statusRequest({ op: "edit", revision: 1, idempotency_key: "neoth-wa-status-uncertain", activity: { phase: "unknown" } }));
  assert.deepEqual(texts, ["Not allowed: Write file", "Outcome unknown"]);
});

test("bound final refuses legacy dedup rows without an authenticated payload fingerprint", async (t) => {
  const directory = await temporaryDirectory();
  t.after(() => rm(directory, { recursive: true, force: true }));
  const runtime = await statusFixture(directory);
  const request = statusFinalRequest();
  await runtime.outboundStore.reserve(request.idempotency_key);
  await runtime.outboundStore.complete(request.idempotency_key, "legacy-final");
  let calls = 0;
  runtime.socket = { sendMessage: async () => { calls += 1; throw new Error("unexpected write"); } };
  await assert.rejects(runtime.send(request), { code: "idempotency_payload_mismatch" });
  assert.equal(calls, 0);
});
