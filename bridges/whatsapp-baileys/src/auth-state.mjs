import { open, readFile, rm } from "node:fs/promises";
import path from "node:path";
import { BufferJSON, initAuthCreds, proto } from "baileys";
import { atomicWrite, ensurePrivateDirectory } from "./state.mjs";

const AUTH_STATE_VERSION = 1;

function normalizeKeyData(raw) {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new Error("auth-state.json keys must be an object");
  }
  const keys = Object.create(null);
  for (const [category, rows] of Object.entries(raw)) {
    if (!rows || typeof rows !== "object" || Array.isArray(rows)) {
      throw new Error(`auth-state.json key category ${category} must be an object`);
    }
    keys[category] = Object.assign(Object.create(null), rows);
  }
  return keys;
}

async function acquireProcessLock(directory) {
  const file = path.join(directory, "auth-state.lock");
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const handle = await open(file, "wx", 0o600);
      await handle.writeFile(`${process.pid}\n`);
      await handle.sync();
      return {
        async close() {
          await handle.close();
          const owner = (await readFile(file, "utf8").catch(() => "")).trim();
          if (owner === String(process.pid)) await rm(file, { force: true });
        },
      };
    } catch (error) {
      if (error?.code !== "EEXIST" || attempt > 0) throw error;
      const owner = Number((await readFile(file, "utf8")).trim());
      if (!Number.isSafeInteger(owner) || owner < 1) {
        throw new Error("auth-state.lock is malformed; inspect it before removing it");
      }
      try {
        process.kill(owner, 0);
        throw new Error(`another Baileys bridge process is active (pid ${owner})`);
      } catch (probeError) {
        if (probeError?.code !== "ESRCH") throw probeError;
      }
      await rm(file, { force: true });
    }
  }
  throw new Error("could not acquire auth-state lock");
}

export async function openDurableAuthState(directory) {
  await ensurePrivateDirectory(directory);
  const lock = await acquireProcessLock(directory);
  const file = path.join(directory, "auth-state.json");
  let snapshot;
  let created = false;
  try {
    const body = await readFile(file, "utf8");
    snapshot = JSON.parse(body, BufferJSON.reviver);
  } catch (error) {
    if (error?.code !== "ENOENT") {
      await lock.close();
      throw new Error(`cannot load durable Baileys auth state: ${error.message}`, { cause: error });
    }
    snapshot = { version: AUTH_STATE_VERSION, creds: initAuthCreds(), keys: Object.create(null) };
    created = true;
  }

  let keyData;
  try {
    if (snapshot?.version !== AUTH_STATE_VERSION
        || !snapshot.creds || typeof snapshot.creds !== "object") {
      throw new Error(`unsupported or malformed durable Baileys auth state in ${file}`);
    }
    keyData = normalizeKeyData(snapshot.keys ?? {});
  } catch (error) {
    await lock.close();
    throw error;
  }
  const state = {
    creds: snapshot.creds,
    keys: null,
  };
  let writeTail = Promise.resolve();
  const persist = () => {
    const body = `${JSON.stringify(
      { version: AUTH_STATE_VERSION, creds: state.creds, keys: keyData },
      BufferJSON.replacer,
    )}\n`;
    const write = () => atomicWrite(file, body);
    const result = writeTail.then(write, write);
    writeTail = result.catch(() => {});
    return result;
  };

  state.keys = {
    async get(type, ids) {
      const result = {};
      const category = keyData[type] ?? Object.create(null);
      for (const id of ids) {
        let value = category[id];
        if (type === "app-state-sync-key" && value) {
          value = proto.Message.AppStateSyncKeyData.fromObject(value);
        }
        result[id] = value;
      }
      return result;
    },
    async set(data) {
      for (const [category, rows] of Object.entries(data ?? {})) {
        if (!keyData[category]) keyData[category] = Object.create(null);
        for (const [id, value] of Object.entries(rows ?? {})) {
          if (value == null) delete keyData[category][id];
          else keyData[category][id] = value;
        }
        if (Object.keys(keyData[category]).length === 0) delete keyData[category];
      }
      await persist();
    },
  };

  if (created) {
    try {
      await persist();
    } catch (error) {
      await lock.close();
      throw error;
    }
  }
  return {
    state,
    saveCreds: persist,
    async close() {
      try {
        await writeTail;
      } finally {
        await lock.close();
      }
    },
  };
}
