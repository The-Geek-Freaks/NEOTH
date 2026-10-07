import os from "node:os";
import path from "node:path";
import { OutboundDedupStore, StatusOperationStore } from "./state.mjs";

const args = process.argv.slice(2);
const isStatus = args[0] === "status";
const [key, resolution, outcome] = isStatus ? args.slice(1) : args;
if (!key || !["sent", "not-sent"].includes(resolution)) {
  throw new Error("usage: pnpm reconcile -- <idempotency-key> <sent|not-sent> [message-id]; or: pnpm reconcile -- status <idempotency-key> <sent|not-sent> [full-message-key-json]");
}
const stateDirectory = path.resolve(
  process.env.NEOTH_WA_STATE_DIR || path.join(os.homedir(), ".neoth", "whatsapp-baileys-bridge"),
);
if (isStatus) {
  let messageKey = null;
  if (outcome !== undefined) {
    try { messageKey = JSON.parse(outcome); } catch { throw new Error("status sent reconciliation requires full message-key JSON"); }
  }
  const store = await StatusOperationStore.open(stateDirectory);
  await store.resolvePending(key, resolution, messageKey);
  console.log(`Resolved status operation as ${resolution}.`);
} else {
  const store = await OutboundDedupStore.open(stateDirectory);
  await store.resolvePending(key, resolution, outcome);
  console.log(`Resolved outbound idempotency key as ${resolution}.`);
}
