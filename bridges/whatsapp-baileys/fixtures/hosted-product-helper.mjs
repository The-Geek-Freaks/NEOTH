/** Hosted-only real bridge/daemon journey. Never starts a linked Baileys session. */
import http from "node:http";
import path from "node:path";
import readline from "node:readline";
import { createBridgeServer } from "../src/api.mjs";
import { BaileysRuntime } from "../src/runtime.mjs";
import { EventJournal, OutboundDedupStore, StatusOperationStore } from "../src/state.mjs";
import { statusEditEnabledFromEnv } from "../src/status_config.mjs";

if (process.env.GITHUB_ACTIONS !== "true") throw new Error("hosted runner required");
const directory = process.argv[2];
const mode = process.argv[3];
if (!path.isAbsolute(directory ?? "") || !["success", "tool_error", "disabled", "cancel"].includes(mode)) {
  throw new Error("invalid hosted scenario");
}
const ACCOUNT = "+491700000001";
const CHAT = "491701234567@s.whatsapp.net";
const RAW_ID = "w2511-inbound";
const INBOUND = CHAT + ":" + RAW_ID;
const PROMPT = "W2511 held tool WhatsApp canary";
const FINAL = mode === "tool_error" ? "W2511 tool error handled" : "W2511 tool completed";
const TOKEN = "w2511_loopback_only_bridge_token_0000000001";
const labels = "(?:Read file|Write file|List files|Search code|Tool call)";
const publicText = new RegExp("^(?:Working|Working: " + labels + "|Completed: " + labels
  + "|Not allowed: " + labels + "|Outcome unknown|Finalizing|Done|Stopped|Limit reached|Connection stale)$");
let journal, runtime, bridge, pendingFinal;
let providerCalls = 0, promptVerified = false, resultVerified = false, injected = false;
let violations = 0, sequence = 0;
const writes = [];
const key = { id: "w2511-status-key", remoteJid: CHAT, fromMe: true };
function snapshot() {
  return { providerCalls, promptVerified, resultVerified, injected, violations, writes,
    retained: journal.events.length,
    statusAdmission: journal.hasStatusAdmission(ACCOUNT, INBOUND, CHAT) };
}
async function openBridge() {
  journal = await EventJournal.open(directory);
  const outboundStore = await OutboundDedupStore.open(directory);
  const statusStore = statusEditEnabledFromEnv() ? await StatusOperationStore.open(directory) : null;
  runtime = new BaileysRuntime({ stateDirectory: directory, journal, outboundStore, statusStore });
  runtime.accountId = ACCOUNT;
  runtime.connected = true;
  runtime.socket = {
    user: { id: ACCOUNT.slice(1) + "@s.whatsapp.net" },
    async sendMessage(chat, content) {
      const text = content.text;
      const isFinal = text === FINAL;
      const validEdit = !content.edit || (content.edit.id === key.id
        && content.edit.remoteJid === CHAT && content.edit.fromMe === true);
      if (chat !== CHAT || !validEdit || (!isFinal && !publicText.test(text))
          || Object.keys(content).some(k => !["text", "edit"].includes(k))
          || (isFinal && content.edit) || writes.some(w => w.kind === "final")) {
        violations++;
        throw new Error("unexpected socket write");
      }
      const kind = isFinal ? "final" : text.startsWith("Working: ") ? "tool_start"
        : text.startsWith("Completed: ") ? "tool_finish" : text === "Stopped" ? "tool_error" : "status";
      writes.push({ sequence: ++sequence, kind, edit: Boolean(content.edit),
        closedBeforeSend: !journal.hasStatusAdmission(ACCOUNT, INBOUND, CHAT) });
      return { key: isFinal ? { ...key, id: "w2511-final-key" } : { ...key } };
    },
    end() {},
  };
  bridge = await createBridgeServer({ token: TOKEN, journal, runtime, host: "127.0.0.1", port: 0 });
}
function respond(response, content) {
  response.writeHead(200, { "content-type": "application/json" });
  response.end(JSON.stringify({ id: "w2511", object: "chat.completion", model: "w2511-loopback",
    choices: [{ index: 0, message: { role: "assistant", content }, finish_reason: "stop" }] }));
}
const provider = http.createServer(async (request, response) => {
  try {
    if (request.method !== "POST" || request.url !== "/v1/chat/completions") throw new Error("route");
    let body = "", bytes = 0;
    for await (const chunk of request) {
      bytes += chunk.length;
      if (bytes > 256 * 1024) throw new Error("body cap");
      body += chunk.toString("utf8");
    }
    const value = JSON.parse(body);
    const messages = value.messages;
    if (!Array.isArray(messages)) throw new Error("messages");
    providerCalls++;
    if (providerCalls === 1) {
      promptVerified = messages.filter(m => m.role === "user" && typeof m.content === "string" && m.content.includes(PROMPT)).length === 1;
      if (!promptVerified) throw new Error("prompt");
      const fence = String.fromCharCode(96).repeat(3);
      respond(response, fence + 'mcp-tool-call\n{"server":"w2511-held","tool":"read","arguments":{}}\n' + fence);
    } else if (providerCalls === 2) {
      resultVerified = body.includes(mode === "tool_error" ? "W2511_FIXTURE_ERROR" : "W2511_FIXTURE_OK");
      if (!resultVerified || pendingFinal) throw new Error("tool result");
      // Keep the pipeline alive until the actual terminal tool status is observed.
      pendingFinal = response;
    } else {
      throw new Error("duplicate provider call");
    }
  } catch {
    violations++;
    response.writeHead(500, { "content-type": "application/json" });
    response.end('{"error":"hosted_contract_refused"}');
  }
});
provider.headersTimeout = 5000;
provider.requestTimeout = 120000;
await openBridge();
await new Promise(resolve => provider.listen(0, "127.0.0.1", resolve));
const reply = value => process.stdout.write(JSON.stringify(value) + "\n");
reply({ ready: true, bridge: bridge.address.port, provider: provider.address().port });
const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity });
try {
  for await (const line of input) {
    if (line.length > 4096) throw new Error("control cap");
    const { op } = JSON.parse(line);
    if (op === "inject") {
      if (injected) throw new Error("duplicate inbound injection");
      injected = true;
      await runtime.handleInboundBatch([{ key: { remoteJid: CHAT, id: RAW_ID, fromMe: false },
        message: { conversation: PROMPT }, messageTimestamp: Math.floor(Date.now() / 1000) }]);
      reply(snapshot());
    } else if (op === "snapshot") {
      reply(snapshot());
    } else if (op === "finish") {
      if (!pendingFinal || pendingFinal.destroyed) throw new Error("final response absent");
      respond(pendingFinal, FINAL);
      pendingFinal = null;
      reply({ finished: true });
    } else if (op === "late" || op === "restart_late") {
      if (op === "restart_late") {
        await runtime.stop();
        await bridge.close();
        await openBridge();
      }
      const before = writes.length;
      const response = await fetch("http://127.0.0.1:" + bridge.address.port + "/v1/status", {
        method: "POST", headers: { authorization: "Bearer " + TOKEN, "content-type": "application/json" },
        body: JSON.stringify({ op: "create", account_id: ACCOUNT, chat_id: CHAT, inbound_id: INBOUND,
          idempotency_key: "neoth-wa-status-w2511-late", revision: 0,
          activity: { phase: "tool_start", label: "Read file" } }),
        signal: AbortSignal.timeout(5000),
      });
      const body = await response.json();
      reply({ status: response.status, refused: body.error === "status_inbound_not_retained",
        writesUnchanged: before === writes.length, ...snapshot() });
    } else if (op === "stop") {
      break;
    } else {
      throw new Error("unknown control");
    }
  }
} finally {
  pendingFinal?.destroy();
  await runtime.stop();
  await bridge.close();
  provider.closeAllConnections();
  await new Promise(resolve => provider.close(resolve));
  input.close();
}
