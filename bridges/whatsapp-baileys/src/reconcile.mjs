import os from "node:os";
import path from "node:path";
import { OutboundDedupStore } from "./state.mjs";

const [key, resolution, messageId] = process.argv.slice(2);
if (!key || !resolution) {
  throw new Error("usage: pnpm reconcile -- <idempotency-key> <sent|not-sent> [message-id]");
}
const stateDirectory = path.resolve(
  process.env.NEOTH_WA_STATE_DIR || path.join(os.homedir(), ".neoth", "whatsapp-baileys-bridge"),
);
const store = await OutboundDedupStore.open(stateDirectory);
await store.resolvePending(key, resolution, messageId);
console.log(`Resolved outbound idempotency key as ${resolution}.`);
