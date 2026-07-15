import path from "node:path";
import { createHash } from "node:crypto";
import {
  DisconnectReason,
  downloadMediaMessage,
  fetchLatestBaileysVersion,
  makeWASocket,
  normalizeMessageContent,
} from "baileys";
import qrcode from "qrcode-terminal";
import { openDurableAuthState } from "./auth-state.mjs";

const MAX_MEDIA_BYTES = 10 * 1024 * 1024;
const MAX_TEXT_BYTES = 64 * 1024;
const MAX_BACKOFF_MS = 30_000;

const logger = {
  level: "silent",
  child() { return this; },
  trace() {}, debug() {}, info() {}, warn() {}, error() {}, fatal() {},
};

function sleep(milliseconds) {
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function statusCode(error) {
  return error?.output?.statusCode ?? error?.data?.statusCode ?? error?.statusCode ?? null;
}

function normalizePhoneJid(jid) {
  if (typeof jid !== "string") return "";
  const [local, domain] = jid.split("@");
  if (domain === "s.whatsapp.net" && /^\d+(?::\d+)?$/.test(local)) {
    return `+${local.split(":")[0]}`;
  }
  return jid;
}

function outboundJid(recipient) {
  if (typeof recipient !== "string" || !recipient.trim()) throw Object.assign(new Error("recipient is required"), { statusCode: 400 });
  const value = recipient.trim();
  if (/^\+\d{7,15}$/.test(value)) return `${value.slice(1)}@s.whatsapp.net`;
  if (/^[^\s@]+@(s\.whatsapp\.net|g\.us|lid)$/.test(value)) return value;
  throw Object.assign(new Error("recipient must be E.164 or a WhatsApp JID"), { statusCode: 400 });
}

function boundedText(value, { required = false } = {}) {
  const text = typeof value === "string" ? value.trim() : "";
  if (required && !text) {
    throw Object.assign(new Error("text is required when media is absent"), { statusCode: 400 });
  }
  if (Buffer.byteLength(text) > MAX_TEXT_BYTES) {
    throw Object.assign(new Error("text/caption exceeds 64 KiB"), { statusCode: 413 });
  }
  return text || undefined;
}

function decodeBase64(value) {
  if (typeof value !== "string" || !value) {
    throw Object.assign(new Error("media.data_b64 is required"), { statusCode: 400 });
  }
  if (value.length > Math.ceil(MAX_MEDIA_BYTES / 3) * 4 + 4
      || !/^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/.test(value)) {
    throw Object.assign(new Error("media.data_b64 must be canonical base64 within the 10 MiB limit"), { statusCode: 400 });
  }
  const data = Buffer.from(value, "base64");
  if (!data.length || data.length > MAX_MEDIA_BYTES) {
    throw Object.assign(new Error("media must decode to 1 byte..10 MiB"), { statusCode: 400 });
  }
  return data;
}

function mediaMime(value) {
  const mime = typeof value === "string" ? value.trim() : "";
  if (!mime || mime.length > 255 || /[\r\n\0]/.test(mime)) {
    throw Object.assign(new Error("media.mime must be 1..255 characters without controls"), { statusCode: 400 });
  }
  return mime;
}

function payloadFingerprint(recipient, fields) {
  const hash = createHash("sha256");
  for (const value of [recipient, fields.kind, fields.text, fields.mime, fields.filename]) {
    const encoded = Buffer.from(value ?? "", "utf8");
    const length = Buffer.allocUnsafe(8);
    length.writeBigUInt64LE(BigInt(encoded.length));
    hash.update(length).update(encoded);
  }
  if (fields.data) hash.update(fields.data);
  return hash.digest("hex");
}

function timestampMs(value) {
  if (typeof value === "number") return Math.max(0, Math.trunc(value * 1000));
  if (typeof value === "bigint") return Number(value * 1000n);
  if (value && typeof value.toNumber === "function") return Math.max(0, Math.trunc(value.toNumber() * 1000));
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.max(0, Math.trunc(parsed * 1000)) : Date.now();
}

function messageText(message) {
  return message?.conversation
    ?? message?.extendedTextMessage?.text
    ?? message?.imageMessage?.caption
    ?? message?.videoMessage?.caption
    ?? message?.documentMessage?.caption
    ?? message?.buttonsResponseMessage?.selectedDisplayText
    ?? message?.listResponseMessage?.title
    ?? message?.templateButtonReplyMessage?.selectedDisplayText
    ?? null;
}

function mediaDescriptor(message) {
  const candidates = [
    ["image", message?.imageMessage, "image/jpeg"],
    ["video", message?.videoMessage, "video/mp4"],
    ["audio", message?.audioMessage, "audio/ogg; codecs=opus"],
    ["document", message?.documentMessage, "application/octet-stream"],
    ["sticker", message?.stickerMessage, "image/webp"],
  ];
  for (const [kind, value, fallbackMime] of candidates) {
    if (value) return { kind, value, mime: value.mimetype || fallbackMime, filename: value.fileName || null };
  }
  return null;
}

function replyTo(message) {
  const parts = [
    message?.extendedTextMessage,
    message?.imageMessage,
    message?.videoMessage,
    message?.audioMessage,
    message?.documentMessage,
    message?.stickerMessage,
  ];
  return parts.find((part) => part?.contextInfo?.stanzaId)?.contextInfo?.stanzaId ?? null;
}

export class BaileysRuntime {
  constructor({ stateDirectory, journal, outboundStore }) {
    this.authDirectory = path.join(stateDirectory, "auth");
    this.journal = journal;
    this.outboundStore = outboundStore;
    this.socket = null;
    this.connected = false;
    this.accountId = null;
    this.stopping = false;
    this.loop = null;
    this.closeCurrent = null;
    this.saveChain = Promise.resolve();
    this.ingestChain = Promise.resolve();
    this.sendChain = Promise.resolve();
    this.authState = null;
    this.fatalError = null;
  }

  start() {
    if (!this.loop) this.loop = this.#connectLoop();
  }

  async stop() {
    this.stopping = true;
    this.closeCurrent?.({ stopped: true });
    try { this.socket?.end?.(new Error("NEOTH Baileys bridge shutdown")); } catch {}
    await this.loop;
    await this.ingestChain;
    try { await this.sendChain; } catch {}
    await this.saveChain;
    await this.authState?.close();
  }

  health() {
    return {
      status: "ok",
      ...(this.fatalError ? { status: "fatal", error_code: this.fatalError.code } : {}),
      connected: this.connected,
      linked: Boolean(this.accountId),
      account_id: this.accountId,
    };
  }

  async #connectLoop() {
    try {
      this.authState = await openDurableAuthState(this.authDirectory);
      const setKeys = this.authState.state.keys.set.bind(this.authState.state.keys);
      this.authState.state.keys.set = async (data) => {
        try {
          await setKeys(data);
        } catch (error) {
          this.#failStop("auth_key_persistence_failed", error);
          throw error;
        }
      };
    } catch (error) {
      this.#failStop("auth_state_load_failed", error);
      return;
    }
    let backoffMs = 2_000;
    while (!this.stopping) {
      try {
        const result = await this.#connectOnce();
        if (result?.loggedOut) {
          console.error("WhatsApp session logged out; remove the auth directory and restart to pair again.");
          return;
        }
        if (result?.fatal) return;
        backoffMs = result?.opened ? 2_000 : Math.min(MAX_BACKOFF_MS, Math.floor(backoffMs * 1.8));
      } catch (error) {
        console.error(`Baileys connection failed: ${String(error)}`);
        backoffMs = Math.min(MAX_BACKOFF_MS, Math.floor(backoffMs * 1.8));
      }
      if (!this.stopping) await sleep(backoffMs + Math.floor(Math.random() * Math.max(1, backoffMs / 4)));
    }
  }

  async #connectOnce() {
    const { state, saveCreds } = this.authState;
    let version;
    try { ({ version } = await fetchLatestBaileysVersion()); } catch (error) {
      console.warn(`Could not fetch latest WhatsApp Web version; using Baileys default: ${String(error)}`);
    }
    const socket = makeWASocket({
      auth: state,
      ...(version ? { version } : {}),
      logger,
      browser: ["NEOTH", "Baileys Bridge", "1.0.0"],
      printQRInTerminal: false,
      syncFullHistory: false,
      markOnlineOnConnect: false,
      keepAliveIntervalMs: 30_000,
      connectTimeoutMs: 60_000,
      defaultQueryTimeoutMs: 60_000,
    });
    this.socket = socket;
    let opened = false;

    socket.ev.on("creds.update", () => {
      this.saveChain = this.saveChain
        .then(saveCreds, saveCreds)
        .catch((error) => this.#failStop("auth_credentials_persistence_failed", error));
    });
    socket.ev.on("messages.upsert", ({ messages, type }) => {
      if (type !== "notify" && type !== "append") return;
      this.handleInboundBatch(messages, socket);
    });
    if (socket.ws && typeof socket.ws.on === "function") {
      socket.ws.on("error", (error) => console.error(`Baileys websocket error: ${String(error)}`));
    }

    return await new Promise((resolve) => {
      let resolved = false;
      const finish = (value) => {
        if (resolved) return;
        resolved = true;
        this.connected = false;
        if (this.socket === socket) this.socket = null;
        this.closeCurrent = null;
        resolve({ opened, ...value });
      };
      this.closeCurrent = finish;
      socket.ev.on("connection.update", ({ connection, lastDisconnect, qr }) => {
        if (qr) {
          console.log("Scan this QR in WhatsApp > Linked devices:");
          qrcode.generate(qr, { small: true });
        }
        if (connection === "open") {
          opened = true;
          this.connected = true;
          this.accountId = normalizePhoneJid(socket.user?.id ?? state.creds?.me?.id ?? "") || null;
          console.log(`WhatsApp connected${this.accountId ? ` as ${this.accountId}` : ""}.`);
        }
        if (connection === "close") {
          const code = statusCode(lastDisconnect?.error);
          if (code === DisconnectReason.loggedOut) this.accountId = null;
          finish({ loggedOut: code === DisconnectReason.loggedOut });
        }
      });
    });
  }

  async #ingest(rawMessage, socket) {
    const remoteJid = rawMessage?.key?.remoteJid;
    const rawId = rawMessage?.key?.id;
    if (!remoteJid || !rawId || rawMessage?.key?.fromMe || remoteJid === "status@broadcast") return;
    const message = normalizeMessageContent(rawMessage.message);
    if (!message) return;
    const descriptor = mediaDescriptor(message);
    let media = null;
    let text = messageText(message)?.trim() || null;
    if (descriptor) {
      try {
        const data = await downloadMediaMessage(rawMessage, "buffer", {}, {
          logger,
          reuploadRequest: socket.updateMediaMessage,
        });
        if (data.length > MAX_MEDIA_BYTES) {
          text = text || `[${descriptor.kind} attachment omitted: exceeds 10 MiB]`;
        } else {
          media = {
            kind: descriptor.kind,
            mime: descriptor.mime,
            filename: descriptor.filename,
            data_b64: data.toString("base64"),
          };
        }
      } catch (error) {
        console.error(`WhatsApp media download failed for ${rawId}: ${String(error)}`);
        text = text || `[${descriptor.kind} attachment could not be downloaded]`;
      }
    }
    if (!text && !media) return;
    const isGroup = remoteJid.endsWith("@g.us");
    const senderJid = isGroup ? rawMessage.key.participant : remoteJid;
    if (!senderJid) return;
    await this.journal.append({
      id: `${remoteJid}:${rawId}`,
      chat_id: remoteJid,
      sender_id: normalizePhoneJid(senderJid),
      sender_display: rawMessage.pushName || null,
      timestamp_ms: timestampMs(rawMessage.messageTimestamp),
      text,
      reply_to: replyTo(message),
      is_group: isGroup,
      media,
    });
  }

  handleInboundBatch(messages, socket = this.socket) {
    if (this.fatalError) return this.ingestChain;
    const ingest = async () => {
      if (this.fatalError) return;
      for (const message of messages ?? []) {
        if (this.fatalError) return;
        await this.#ingest(message, socket);
      }
    };
    // Baileys may emit another batch while journal fsync is pending. Serialize
    // batches so cursor sequences and the persistent dedup set cannot race.
    // A persistence failure is terminal: continuing could let later events
    // overtake and permanently hide the failed inbound.
    this.ingestChain = this.ingestChain
      .then(ingest, ingest)
      .catch((error) => this.#failStop("inbound_journal_persistence_failed", error));
    return this.ingestChain;
  }

  #failStop(code, error) {
    if (this.fatalError) return;
    this.fatalError = { code, error: String(error) };
    this.connected = false;
    console.error(`Baileys bridge halted (${code}): ${String(error)}`);
    const socket = this.socket;
    this.closeCurrent?.({ fatal: true });
    try { socket?.end?.(new Error(`NEOTH Baileys fail-stop: ${code}`)); } catch {}
  }

  async send(request) {
    if (this.fatalError) {
      const error = new Error(`bridge is halted: ${this.fatalError.code}`);
      error.statusCode = 503;
      error.code = this.fatalError.code;
      throw error;
    }
    const send = () => this.#sendOnce(request);
    // Serialize sends so concurrent HTTP retries for one idempotency key cannot
    // both cross the lookup/reservation boundary.
    this.sendChain = this.sendChain.then(send, send);
    return await this.sendChain;
  }

  async #sendOnce(request) {
    if (!this.connected || !this.socket) throw Object.assign(new Error("WhatsApp is not connected"), { statusCode: 503 });
    const recipient = outboundJid(request?.to);
    const key = typeof request?.idempotency_key === "string" ? request.idempotency_key.trim() : "";
    if (!key || key.length > 200) throw Object.assign(new Error("idempotency_key is required (max 200 characters)"), { statusCode: 400 });
    let content;
    let fingerprint;
    if (request.media) {
      const media = request.media;
      const data = decodeBase64(media.data_b64);
      const mime = mediaMime(media.mime);
      const caption = boundedText(request.text);
      const filename = typeof media.filename === "string" ? media.filename.trim() : "";
      if (filename.length > 255 || /[\r\n\0]/.test(filename)) {
        throw Object.assign(new Error("media.filename exceeds 255 characters or contains controls"), { statusCode: 400 });
      }
      switch (media.kind) {
        case "image": content = { image: data, mimetype: mime, caption }; break;
        case "video": content = { video: data, mimetype: mime, caption }; break;
        case "audio": content = { audio: data, mimetype: mime, ptt: Boolean(media.ptt) }; break;
        case "sticker": content = { sticker: data }; break;
        case "document": content = { document: data, mimetype: mime, fileName: filename || "attachment", caption }; break;
        default: throw Object.assign(new Error("media.kind must be image, video, audio, document, or sticker"), { statusCode: 400 });
      }
      fingerprint = payloadFingerprint(recipient, {
        kind: media.kind,
        text: caption,
        mime,
        filename,
        data,
      });
    } else {
      const text = boundedText(request?.text, { required: true });
      content = { text };
      fingerprint = payloadFingerprint(recipient, { kind: "text", text });
    }

    const previous = this.outboundStore.lookup(key);
    if (previous?.fingerprint && previous.fingerprint !== fingerprint) {
      const error = new Error("idempotency key was already reserved for a different payload");
      error.statusCode = 409;
      error.code = "idempotency_payload_mismatch";
      throw error;
    }
    if (previous?.state === "sent") {
      return { message_id: previous.messageId, deduplicated: true };
    }
    if (previous?.state === "pending") {
      const error = new Error(
        "this idempotency key has an unknown prior send outcome; refusing to resend",
      );
      error.statusCode = 409;
      error.code = "outbound_outcome_unknown";
      throw error;
    }

    // Persist intent before crossing the network boundary. A crash after this
    // point leaves `pending`, so a retry fails closed instead of double-sending.
    await this.outboundStore.reserve(key, Date.now(), fingerprint);
    const sent = await this.socket.sendMessage(recipient, content);
    const messageId = sent?.key?.id;
    if (!messageId) throw Object.assign(new Error("Baileys did not return an outbound message id"), { statusCode: 502 });
    await this.outboundStore.complete(key, messageId);
    return { message_id: messageId, deduplicated: false };
  }
}
