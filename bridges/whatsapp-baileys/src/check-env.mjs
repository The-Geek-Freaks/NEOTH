import { lstat, readFile } from "node:fs/promises";

const file = process.argv[2];
if (!file) throw new Error("usage: node src/check-env.mjs <environment-file>");
const metadata = await lstat(file);
if (!metadata.isFile() || metadata.isSymbolicLink()) {
  throw new Error("Baileys environment path must be a regular, non-symlink file");
}
if (typeof process.getuid === "function" && metadata.uid !== process.getuid()) {
  throw new Error("Baileys environment file must be owned by the service user");
}
if ((metadata.mode & 0o777) !== 0o600) {
  throw new Error("Baileys environment file must be mode 0600 (no group/other access)");
}
if (metadata.size > 4_096) throw new Error("Baileys environment file is unexpectedly large");
const body = await readFile(file, "utf8");
const tokens = body
  .split(/\r?\n/u)
  .map((line) => line.trim())
  .filter((line) => line && !line.startsWith("#"))
  .filter((line) => line.startsWith("NEOTH_WA_BRIDGE_TOKEN="))
  .map((line) => line.slice("NEOTH_WA_BRIDGE_TOKEN=".length));
if (tokens.length !== 1 || !/^[A-Za-z0-9._~-]{32,}$/u.test(tokens[0])) {
  throw new Error("environment file needs exactly one unquoted 32+ character NEOTH_WA_BRIDGE_TOKEN");
}
console.log("Baileys environment file permissions and token shape are valid.");
