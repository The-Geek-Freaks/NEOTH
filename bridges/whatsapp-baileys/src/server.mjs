import os from "node:os";
import path from "node:path";
import { createBridgeServer } from "./api.mjs";
import { BaileysRuntime } from "./runtime.mjs";
import { EventJournal, OutboundDedupStore } from "./state.mjs";

const stateDirectory = path.resolve(
  process.env.NEOTH_WA_STATE_DIR || path.join(os.homedir(), ".neoth", "whatsapp-baileys-bridge"),
);
const token = process.env.NEOTH_WA_BRIDGE_TOKEN;
const host = process.env.NEOTH_WA_BIND || "127.0.0.1";
const port = Number(process.env.NEOTH_WA_PORT || 9120);
if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error("NEOTH_WA_PORT must be 1..65535");

const journal = await EventJournal.open(stateDirectory);
const outboundStore = await OutboundDedupStore.open(stateDirectory);
const runtime = new BaileysRuntime({ stateDirectory, journal, outboundStore });
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
