import os from "node:os";
import path from "node:path";
import { createBridgeServer } from "./api.mjs";
import { BaileysRuntime } from "./runtime.mjs";
import { EventJournal, OutboundDedupStore, StatusOperationStore } from "./state.mjs";
import { statusEditEnabledFromEnv } from "./status_config.mjs";

const stateDirectory = path.resolve(
  process.env.NEOTH_WA_STATE_DIR || path.join(os.homedir(), ".neoth", "whatsapp-baileys-bridge"),
);
const token = process.env.NEOTH_WA_BRIDGE_TOKEN;
const host = process.env.NEOTH_WA_BIND || "127.0.0.1";
const port = Number(process.env.NEOTH_WA_PORT || 9120);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("NEOTH_WA_PORT must be 1..65535");

const journal = await EventJournal.open(stateDirectory);
const outboundStore = await OutboundDedupStore.open(stateDirectory);
// This store is opened only by the sidecar. It gives status edits their own
// durable tuple/message-key binding and leaves v1 text/media send semantics
// unchanged.
// Transport support is inert until the operator explicitly enables it. The
// Rust adapter must still see health capability and opt in for the admitted
// account/turn; this flag alone never emits a WhatsApp status message.
const statusEditEnabled = statusEditEnabledFromEnv();
const statusStore = statusEditEnabled ? await StatusOperationStore.open(stateDirectory) : null;
const runtime = new BaileysRuntime({
  stateDirectory,
  journal,
  outboundStore,
  statusStore,
});
runtime.start();
const server = await createBridgeServer({ token, journal, runtime, host, port });
console.log(`NEOTH WhatsApp Baileys bridge listening on http://${host}:${server.address.port}`);

let stopping = false;
async function stop(signal) {
  if (stopping) return;
  stopping = true;
  console.log(`Stopping bridge (${signal})...`);
  await server.close();
  await runtime.stop();
}
process.once("SIGINT", () => void stop("SIGINT"));
process.once("SIGTERM", () => void stop("SIGTERM"));
