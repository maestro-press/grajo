/**
 * The BOT storage key — the one storage credential a contained bot's MCP child may hold.
 *
 * Why this file exists. A bot's storage-using MCP child (crow-storage, and the reviewed bundles
 * that declare `needs: ["shared-storage"]`) used to be hydrated with this instance's
 * `storage.shared.*` settings, opened host-side by the bot engine. Those are the INSTANCE-WIDE
 * credential (on a MinIO install, a root-level key), and a sibling process in the sandbox can
 * read the child's `/proc/<pid>/environ`. So the credential a bot gets must be a SEPARATE,
 * operator-provisioned, path-scoped key — and it must not live in `crow.db`, which is
 * bot-writable: a sealed value there is not bound to the setting name, so a bot that could write
 * the row could point its own child at any credential it liked.
 *
 * It lives at `<CROW_HOME>/secrets/bot-storage.json`, in the directory a bot sandbox is never
 * bound, written 0600 by `scripts/ops/minio-bot-storage.sh` (which also creates the MinIO policy
 * that limits the key to `projects/*`, `bots/*`, `studio/*` and `sunvox-studio/*` of
 * `<prefix>-files`). Same safety conventions as `<CROW_HOME>/secrets/local-model-endpoints.json`
 * (servers/gateway/models/local-model-servers.js, scripts/cli/local-model-pin.js): the DIRECTORY
 * must be a real (not symlinked) directory this user owns at mode 0700, and the file must be a
 * REGULAR file this user owns with no group/other bits, reached without a symlink, and small —
 * a credential another principal could read or swap proves nothing.
 *
 * Why the checks are done HERE and not with servers/shared/secret-values.js's `anchorSecretsDir`:
 * that helper REPAIRS a dir it finds at the wrong mode (it chmods it to 0700) and creates one that
 * is missing, where this reader must REFUSE — a bot storage key is never reason enough to change
 * the instance's home, and "someone already loosened it" is exactly what must not pass silently.
 * So the read is the explicit form: lstat the directory, open the file with O_NOFOLLOW, fstat the
 * fd that was opened, read from that fd. One lookup of the directory, one of the file, and no
 * window in which the path can be swapped between the check and the read.
 *
 * HOST-SIDE ONLY, and deliberately dependency-free: this module imports no identity, no seal
 * helper and no storage client, so nothing it pulls in could open a sealed value. The bot engine
 * (scripts/pi-bots/mcp_writer.mjs) is its one caller, and only the OPENED values travel on.
 *
 * THERE IS NO FALLBACK, by design: no file means no bot storage (the child gets the marker `0`),
 * never the shared settings and never this instance's `S3_*`/`MINIO_*` environment.
 */

import { closeSync, constants as fsConstants, fstatSync, lstatSync, openSync, readSync } from "node:fs";
import { dirname, join } from "node:path";

/** The file's name inside `<CROW_HOME>/secrets`. */
export const BOT_STORAGE_KEY_FILE = "bot-storage.json";
/** A key file is a few hundred bytes; anything this large is not one. */
export const BOT_STORAGE_KEY_MAX_BYTES = 64 * 1024;
/** The reason `readBotStorageKey` reports when there is simply no file (a normal state). */
export const BOT_STORAGE_KEY_MISSING = "missing";

/** The env names a hydrated bot block carries — the SAME six the shared hydration used, so
 *  nothing downstream changes shape (servers/storage/s3-client.js envStorageConfig). */
export const BOT_STORAGE_ENV_NAMES = Object.freeze([
  "S3_ENDPOINT", "S3_USE_SSL", "S3_REGION", "S3_BUCKET_PREFIX", "S3_ACCESS_KEY", "S3_SECRET_KEY",
]);
/** The marker every bot block carries: `1` = the opened bot key is in this env, `0` = no storage. */
export const BOT_STORAGE_FROM_HOST_ENV = "CROW_STORAGE_FROM_HOST";

/** `<CROW_HOME>/secrets/bot-storage.json`. */
export function botStorageKeyPath(crowHome) {
  return join(String(crowHome), "secrets", BOT_STORAGE_KEY_FILE);
}

const BUCKET_PREFIX_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,62}$/;

/**
 * `/v1`-style endpoint text → `host:port` (the shape S3_ENDPOINT has always carried). The scheme
 * is dropped because `use_ssl` states it; a path is dropped because only the authority is used.
 */
function normalizeEndpoint(raw) {
  let s = String(raw).trim();
  s = s.replace(/^[A-Za-z][A-Za-z0-9+.-]*:\/\//, "");
  s = s.split("/")[0].split("?")[0].split("#")[0];
  return s;
}

/** True for a file this user alone can read (no group/other bits), of the owner-only rule above. */
function ownerOnly(st) {
  if (typeof st.isFile !== "function" || !st.isFile()) return false;
  if (st.isSymbolicLink && st.isSymbolicLink()) return false;
  if (typeof process.getuid === "function" && Number(st.uid) !== process.getuid()) return false;
  return (Number(st.mode) & 0o077) === 0;
}

/**
 * This instance's secrets directory, or WHY it will not be used: it must be a REAL directory (a
 * symlink is refused, so the file it holds cannot be moved elsewhere without notice), this user's,
 * and mode 0700 exactly. Never created, never repaired here.
 * @returns {{dir: string, reason: null} | {dir: null, reason: string}}
 */
function trustedSecretsDir(home) {
  const dir = dirname(botStorageKeyPath(home));
  let st;
  try {
    st = lstatSync(dir); // lstat, never stat: a symlinked secrets dir is refused, not followed
  } catch (err) {
    if (err && err.code === "ENOENT") return { dir: null, reason: BOT_STORAGE_KEY_MISSING };
    return { dir: null, reason: `its secrets directory cannot be examined (${(err && err.code) || "read error"})` };
  }
  if (st.isSymbolicLink && st.isSymbolicLink()) return { dir: null, reason: "its secrets directory is a symbolic link" };
  if (typeof st.isDirectory !== "function" || !st.isDirectory()) return { dir: null, reason: "its secrets directory is not a directory" };
  if (typeof process.getuid === "function" && Number(st.uid) !== process.getuid()) {
    return { dir: null, reason: "its secrets directory is not owned by this user" };
  }
  const mode = Number(st.mode) & 0o777;
  if (mode !== 0o700) {
    return { dir: null, reason: `its secrets directory is not owner-only (mode ${mode.toString(8)})` };
  }
  return { dir, reason: null };
}

/**
 * Read the key file through ONE opened descriptor: O_NOFOLLOW refuses a symlink at the path, and
 * every check below is made on that descriptor — the file judged is the file read, even if the
 * path is replaced a moment later.
 * @returns {{raw: string, reason: null} | {raw: null, reason: string}}
 */
function readKeyFile(path) {
  let fd;
  try {
    try {
      fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW);
    } catch (err) {
      if (err && err.code === "ENOENT") return { raw: null, reason: BOT_STORAGE_KEY_MISSING };
      if (err && err.code === "ELOOP") return { raw: null, reason: "it is a symbolic link" };
      return { raw: null, reason: `it cannot be opened (${(err && err.code) || "read error"})` };
    }
    let st;
    try {
      st = fstatSync(fd);
    } catch (err) {
      return { raw: null, reason: `it cannot be examined (${(err && err.code) || "read error"})` };
    }
    if (!st.isFile()) return { raw: null, reason: "it is not a regular file" };
    if (typeof process.getuid === "function" && Number(st.uid) !== process.getuid()) {
      return { raw: null, reason: "it is not owned by this user" };
    }
    if (!ownerOnly(st)) {
      return { raw: null, reason: `it is readable by other users (mode ${(Number(st.mode) & 0o777).toString(8)})` };
    }
    if (Number(st.size) > BOT_STORAGE_KEY_MAX_BYTES) return { raw: null, reason: `it is too large (${Number(st.size)} bytes)` };
    if (Number(st.size) === 0) return { raw: null, reason: "it is empty" };
    const buf = Buffer.alloc(Number(st.size));
    let off = 0;
    while (off < buf.length) {
      const n = readSync(fd, buf, off, buf.length - off, off);
      if (n <= 0) break;
      off += n;
    }
    if (off === 0) return { raw: null, reason: "it is empty" };
    return { raw: buf.subarray(0, off).toString("utf8"), reason: null };
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* already closed */ }
    }
  }
}

/**
 * This instance's bot storage key, or WHY there is none.
 *
 * @param {{crowHome?: string|(() => string)}} [opts] the instance's home (default: none — the
 *   caller states it, so a wrong home is never guessed at)
 * @returns {{config: null, reason: string} | {config: {endpoint: string, useSSL: boolean,
 *   region: string, bucketPrefix: string, accessKey: string, secretKey: string}, reason: null}}
 *   `reason` is `BOT_STORAGE_KEY_MISSING` for "no file" (a normal state) and a short, value-free
 *   sentence for every refusal (an operator fault, reported to the operator).
 */
export function readBotStorageKey({ crowHome } = {}) {
  const home = typeof crowHome === "function" ? crowHome() : crowHome;
  if (typeof home !== "string" || home === "") return { config: null, reason: "no Crow home was resolved" };

  // The directory first: a secrets dir this user does not alone own and cannot alone write (mode
  // 0700 exactly) makes the file inside it untrustworthy however it looks itself.
  const dir = trustedSecretsDir(home);
  if (!dir.dir) return { config: null, reason: dir.reason };
  const path = botStorageKeyPath(home);

  const file = readKeyFile(path);
  if (file.raw === null) return { config: null, reason: file.reason };
  const raw = file.raw;
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { config: null, reason: "it is not valid JSON" };
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { config: null, reason: "it is not a JSON object" };
  }

  const text = (value) => (typeof value === "string" ? value.trim() : "");
  const endpoint = normalizeEndpoint(text(parsed.endpoint));
  if (!endpoint) return { config: null, reason: "it has no endpoint" };
  const accessKey = text(parsed.access_key);
  if (!accessKey) return { config: null, reason: "it has no access_key" };
  const secretKey = text(parsed.secret_key);
  if (!secretKey) return { config: null, reason: "it has no secret_key" };
  if (parsed.use_ssl !== undefined && typeof parsed.use_ssl !== "boolean") {
    return { config: null, reason: "its use_ssl is not a boolean" };
  }
  const region = parsed.region === undefined ? "us-east-1" : text(parsed.region);
  if (!region) return { config: null, reason: "its region is empty" };
  const bucketPrefix = parsed.bucket_prefix === undefined ? "crow" : text(parsed.bucket_prefix);
  if (!BUCKET_PREFIX_RE.test(bucketPrefix)) return { config: null, reason: "its bucket_prefix is not a bucket name" };

  return {
    config: { endpoint, useSSL: parsed.use_ssl === true, region, bucketPrefix, accessKey, secretKey },
    reason: null,
  };
}

/**
 * The env a hydrated bot block carries: exactly the six S3_* names plus the marker. Nothing else —
 * no MINIO_*, no CROW_* home, no seed, no seal key.
 * @param {object} config readBotStorageKey's config
 * @returns {Record<string, string>}
 */
export function botStorageEnv(config) {
  return {
    S3_ENDPOINT: String(config.endpoint),
    S3_USE_SSL: config.useSSL ? "true" : "false",
    S3_REGION: config.region || "us-east-1",
    S3_BUCKET_PREFIX: config.bucketPrefix || "crow",
    S3_ACCESS_KEY: String(config.accessKey || ""),
    S3_SECRET_KEY: String(config.secretKey || ""),
    [BOT_STORAGE_FROM_HOST_ENV]: "1",
  };
}