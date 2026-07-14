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
import { CursorError, EventJournal, OutboundDedupStore } from "../src/state.mjs";

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
  const runtime = {
    health: () => ({ status: "ok", connected: true, linked: true, account_id: "+49123" }),
    send: async (body) => { sent.push(body); return { message_id: "out-1", deduplicated: false }; },
  };
  const token = "x".repeat(32);
  const server = await createBridgeServer({ token, journal, runtime, port: 0 });
  t.after(() => server.close());
  const base = `http://127.0.0.1:${server.address.port}`;
  assert.equal((await fetch(`${base}/v1/health`)).status, 401);
  const headers = { authorization: `Bearer ${token}` };
  const health = await (await fetch(`${base}/v1/health`, { headers })).json();
  assert.equal(health.latest_cursor, "1");
  assert.equal(health.capabilities.media, true);
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
