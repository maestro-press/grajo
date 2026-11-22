/**
 * Crow Recurring Reports' custom steps: the small file bundles a report may run, the assets they read,
 * the hosts they may reach and the credential bindings for those hosts.
 *
 * A custom step is untrusted code, so nothing here runs anything: this module owns the CONTENT and the
 * OWNER APPROVALS, and the sandboxed runner is a later part. What it guarantees:
 *
 *   - A step is a small file bundle (`files_json`) plus a requirements text and the names of the assets
 *     it binds, with one row per (report, step key, revision). Its `bundle_hash` is a sha256 over the
 *     sorted (path, sha256(content)) list, the requirements text and the sorted (name, sha256) list of
 *     the bound assets, each value length-prefixed, so `{"ab": "c"}` and `{"a": "bc"}` cannot hash alike
 *     and a re-framing cannot collide with a different shape of content.
 *   - An approval is a seal over (report, `<step key>:<rev>`, bundle hash, `language`, `entry`, nonce)
 *     under the keychain seed (seal.js kind "step"), and `verifyStep` recomputes the bundle hash NOW
 *     from the stored row and the CURRENT asset rows, and reads the two columns NOW, before it looks at
 *     the seal. A direct UPDATE of a file, of the requirements, of an asset row, of the language or of
 *     the entry therefore reads as unapproved, and refusing or revoking NULLS the seal and its nonce,
 *     so an old seal can never re-approve a row.
 *   - The NEWEST revision is the one that runs. `runnableStep` answers `step_waiting` unless that newest
 *     revision is approved, sealed and its assets are the ones on disk, so an approved older revision
 *     never carries a newer proposed one into a run.
 *   - A host is an exact lower-case host name or a `*.suffix` wildcard with at least two labels after
 *     the `*.`. A credential binds one EXACT host of one report to one keychain row, and only while
 *     that host is approved: `injectRulesFor` is the array the relay is handed, and it never carries a
 *     secret, only a function that reads one.
 *   - No secret value is ever stored in a reports table, returned by a list, logged or put in an error.
 *     A credential row names a keychain row (`connection_uuid`); `credentialSecretFor` reads the value
 *     from the keychain at call time, and it re-reads the binding row on every call: a row that is
 *     gone, that names another keychain row, or that a direct UPDATE moved stops answering, so a
 *     revocation, a rotation or a replacement reaches a closure a run already holds.
 *   - An owner's approval of a credential carries the keychain reference and the rule digest the owner
 *     was shown, and the write is guarded by both, by the state and by the exact rule text that was
 *     hashed. A row that moved under the decision answers `credential_changed`, never an approval.
 *
 * The inject rules are validated here with the same rules the egress relay applies to its `inject`
 * option (scripts/pi-bots/pi_egress.mjs): that module cannot be imported from the gateway (it is a bot
 * runtime script), so the rules are duplicated on purpose and a test drives both with the same bad
 * input list. A rule without path prefixes, or with a bare `/` that names no segment, is refused: an
 * empty prefix list would put the credential everywhere on the host, which is the thing the list
 * exists to prevent.
 *
 * `deps` is the seam, and every member falls back to the real thing:
 *   - `loadSeed()`: the keychain seed bytes, or null (a missing seed refuses every approval).
 *   - `loadKeychainKey()`: `{id, seed}`, the key a credential's keychain row is sealed under.
 *   - `now()`: epoch ms for every row and audit stamp.
 *   - `crowHome()` or `crowHome`: this instance's home; assets live under `<home>/reports/<id>/assets`.
 *
 * Every refusal is an Error with a `code`: `bad_input`, `too_large`, `not_found`, `owner_only`,
 * `keychain_key_missing`, `bad_inject` (a credential whose rule the relay would refuse),
 * `host_not_approved`, and `step_changed` / `host_changed` / `credential_changed` when a row moved
 * under a decision.
 */
import { createHash, randomBytes } from "node:crypto";
import { chmodSync, mkdirSync, readFileSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { isIP } from "node:net";
import { join } from "node:path";
import { approvalSeal, newApprovalNonce, verifyApprovalSeal } from "./seal.js";
import { approvalInternals } from "./approvals.js";
import { recordAudit } from "./store.js";
import { lineDiff } from "../../shared/line-diff.js";
import { resolveCrowHome } from "../../shared/crow-home.js";
import { loadKeychainKey } from "../keychain/key.js";
import { REPORTS_BUNDLE, disconnectServiceSecrets, ensureKeychainTable, serviceSecretsFor } from "../keychain/store.js";

const fail = approvalInternals.fail;
const text = approvalInternals.text;

/* ------------------------------------------------------------------------ the words */

/** The four states a step, host or credential row may hold (this module owns them; there is no CHECK). */
export const STEP_STATES = Object.freeze(["proposed", "approved", "refused", "revoked"]);

/** The two languages a step bundle may be written in. */
export const STEP_LANGUAGES = Object.freeze(["python", "node"]);

/** A step key: what a recipe's custom block names, and the stable half of its seal's step id. */
export const STEP_KEY_RE = /^[a-z][a-z0-9_-]{0,31}$/;

/** A step's file bundle: at most this many files, at most this many bytes of content in total. */
export const STEP_MAX_FILES = 200;
export const STEP_MAX_BUNDLE_BYTES = 2 * 1024 * 1024;

/** A step's requirements text: at most this many bytes. */
export const STEP_REQUIREMENTS_MAX_BYTES = 64 * 1024;

/** One asset's name, and the bytes one report's assets may hold in total. */
export const ASSET_NAME_RE = /^[A-Za-z0-9._-]{1,100}$/;
export const ASSET_MAX_BYTES = 20 * 1024 * 1024;

/** The env key a report credential is saved under in the keychain (kind "service"). */
export const REPORT_CREDENTIAL_ENV_KEY = "REPORT_CREDENTIAL";

/** The line an owner is shown when a host is approved. The plan's exact sentence. */
export const HOST_APPROVAL_LINE = "Check that this site allows automated access. This is your responsibility.";

/** The reason `runnableStep` gives when the newest revision may not run. */
export const STEP_WAITING = "step_waiting";

/** A file path inside a step bundle: POSIX, relative, and no longer than this. */
const FILE_PATH_MAX = 200;
/** A step key's revision and the reason word a refuser writes. */
const MAX_REV = 1_000_000;

/** Methods the relay lets an inject rule cover, and what a rule covers when it names none. */
const INJECT_METHODS = Object.freeze(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]);
const INJECT_DEFAULT_METHODS = Object.freeze(["GET", "HEAD"]);
const INJECT_MAX_PREFIXES = 20;
const INJECT_MAX_PREFIX_CHARS = 200;
/** An HTTP token (RFC 9110), and the query name a credential may be carried in. */
const INJECT_TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const INJECT_QUERY_RE = /^[A-Za-z0-9_.-]{1,64}$/;
/** Header names a credential is never attached to: they frame the request itself. */
const INJECT_BAD_HEADER = new Set(["host", "content-length", "transfer-encoding", "connection"]);
/** The longest a header's format may be, and the one placeholder it must hold once. */
const INJECT_FORMAT_MAX = 200;

/** One DNS label of a host name, the same shape the relay reads. */
const HOST_LABEL_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/;
const HOST_MAX = 253;

/** A sha256 as this module writes it. */
const SHA256_RE = /^[0-9a-f]{64}$/;
/** A connection uuid: 8 to 80 of the characters a uuid and a hand-made one use. */
const UUID_RE = /^[A-Za-z0-9-]{8,80}$/;
/** The characters a report id may hold on its way into a filesystem path. */
const PATH_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
/** Control characters, C0 and C1 and the two Unicode separators. */
const CONTROL_CHARS = /[\u0000-\u001f\u007f\u0080-\u009f\u2028\u2029]/;
/** The same, except the whitespace a requirements file really holds: tab, newline and carriage return. */
const REQUIREMENTS_CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f\u0080-\u009f\u2028\u2029]/;

/* --------------------------------------------------------------------------- deps */

function defaultLoadKeychainKey() {
  try {
    return loadKeychainKey();
  } catch {
    return null;
  }
}

/**
 * `deps` with every member present. The approvals seam (the seed reader and the clock) comes from the
 * approvals module itself, so a step approval and a live approval read the same keychain seed.
 */
function resolveDeps(deps) {
  const given = deps == null ? {} : deps;
  const base = approvalInternals.resolveDeps(given);
  const loadKeychainKeyFn = typeof given.loadKeychainKey === "function"
    ? given.loadKeychainKey
    : defaultLoadKeychainKey;
  const homeFn = given.crowHome;
  const crowHome = () => {
    if (typeof homeFn === "function") {
      const value = homeFn();
      if (typeof value === "string" && value) return value;
    }
    if (typeof homeFn === "string" && homeFn) return homeFn;
    return resolveCrowHome();
  };
  return { ...base, loadKeychainKey: loadKeychainKeyFn, crowHome };
}

/* ------------------------------------------------------------------------- hashing */

function sha256Hex(value) {
  const bytes = Buffer.isBuffer(value)
    ? value
    : value instanceof Uint8Array
      ? Buffer.from(value.buffer, value.byteOffset, value.byteLength)
      : Buffer.from(String(value), "utf8");
  return createHash("sha256").update(bytes).digest("hex");
}

/** One length-prefixed value (a 4-byte big-endian length, then the UTF-8 bytes). */
function pushFramed(chunks, value) {
  const body = Buffer.from(String(value), "utf8");
  const head = Buffer.alloc(4);
  head.writeUInt32BE(body.length, 0);
  chunks.push(head, body);
}

/**
 * A bundle's hash: sha256 over the sorted (path, sha256(content)) list, the requirements text and the
 * sorted (name, sha256) list of the bound assets.
 *
 * Every value is length-prefixed and the three sections are labelled, so the framing is unambiguous:
 * a path and a piece of content cannot be re-cut into two different bundles, a file named "a" holding
 * "bc" hashes differently from a file named "ab" holding "c", and a requirements text that looks like
 * a file list stays the requirements text. Deterministic: the same content always hashes the same.
 *
 * @param {{files?: object|Map<string, string|Buffer>, requirements?: string,
 *   assetHashes?: Array<{name: string, sha256: string}>|object}} bundle
 * @returns {string} 64 lower-case hex characters
 * @throws {Error} `bad_input` for a file list, a content, a name or a hash this cannot frame
 */
export function bundleHashOf(bundle = {}) {
  const { files, requirements, assetHashes } = bundle == null ? {} : bundle;
  const fileEntries = fileEntriesOf(files);
  const assets = assetHashEntriesOf(assetHashes);
  const reqs = requirements == null ? "" : requirements;
  if (typeof reqs !== "string") throw fail("bad_input", "requirements");
  const chunks = [];
  pushFramed(chunks, "v1");
  pushFramed(chunks, "crow-reports-step-bundle");
  pushFramed(chunks, `files:${fileEntries.length}`);
  for (const [path, content] of fileEntries) {
    pushFramed(chunks, path);
    pushFramed(chunks, sha256Hex(content));
  }
  pushFramed(chunks, "requirements");
  pushFramed(chunks, reqs);
  pushFramed(chunks, `assets:${assets.length}`);
  for (const [name, hash] of assets) {
    pushFramed(chunks, name);
    pushFramed(chunks, hash);
  }
  return createHash("sha256").update(Buffer.concat(chunks)).digest("hex");
}

/** A `files` map as sorted (path, content) pairs. */
function fileEntriesOf(files) {
  let entries;
  if (files instanceof Map) entries = [...files.entries()];
  else if (files != null && typeof files === "object" && !Array.isArray(files)) entries = Object.entries(files);
  else throw fail("bad_input", "files");
  const out = [];
  for (const [path, content] of entries) {
    if (typeof path !== "string" || !path) throw fail("bad_input", "file path");
    if (typeof content !== "string" && !Buffer.isBuffer(content) && !(content instanceof Uint8Array)) {
      throw fail("bad_input", "file content");
    }
    out.push([path, content]);
  }
  out.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return out;
}

/** An `assetHashes` list as sorted (name, hash) pairs. Objects, pairs and a plain map are accepted. */
function assetHashEntriesOf(assetHashes) {
  if (assetHashes == null) return [];
  const out = [];
  const add = (name, hash) => {
    if (typeof name !== "string" || !name) throw fail("bad_input", "asset name");
    if (typeof hash !== "string" || !SHA256_RE.test(hash)) throw fail("bad_input", "asset hash");
    out.push([name, hash]);
  };
  if (Array.isArray(assetHashes)) {
    for (const entry of assetHashes) {
      if (Array.isArray(entry)) add(entry[0], entry[1]);
      else if (entry && typeof entry === "object") add(entry.name, entry.sha256);
      else throw fail("bad_input", "asset hash");
    }
  } else if (typeof assetHashes === "object") {
    for (const [name, hash] of Object.entries(assetHashes)) add(name, hash);
  } else {
    throw fail("bad_input", "asset hashes");
  }
  out.sort((a, b) => (a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0));
  return out;
}

/* ---------------------------------------------------------------------- validation */

/** A step key: `[a-z][a-z0-9_-]{0,31}`. The seal's step id is `<key>:<rev>`. */
function normalizeStepKey(value) {
  if (typeof value !== "string" || !STEP_KEY_RE.test(value)) throw fail("bad_input", "stepKey");
  return value;
}

function normalizeLanguage(value) {
  if (typeof value !== "string" || !STEP_LANGUAGES.includes(value)) throw fail("bad_input", "language");
  return value;
}

/**
 * A file path inside a bundle: relative, POSIX, no `..`, no leading `/`, no backslash, no NUL or any
 * other control character, no empty or `.` segment, no trailing slash.
 */
function normalizeRelativePath(value) {
  if (typeof value !== "string" || !value || value.length > FILE_PATH_MAX) {
    throw fail("bad_input", "file path");
  }
  if (CONTROL_CHARS.test(value)) throw fail("bad_input", "file path");
  if (value.startsWith("/")) throw fail("bad_input", "absolute file path");
  if (value.includes("\\")) throw fail("bad_input", "file path");
  if (value.endsWith("/")) throw fail("bad_input", "file path");
  for (const segment of value.split("/")) {
    if (!segment || segment === "." || segment === "..") throw fail("bad_input", "file path");
  }
  return value;
}

/** A bundle's file map: every path validated, duplicates by normalized name refused, sizes bounded. */
function normalizeFiles(files) {
  let entries;
  if (files instanceof Map) entries = [...files.entries()];
  else if (files != null && typeof files === "object" && !Array.isArray(files)) entries = Object.entries(files);
  else throw fail("bad_input", "files");
  if (entries.length === 0) throw fail("bad_input", "files");
  if (entries.length > STEP_MAX_FILES) throw fail("too_large", "files");
  const out = new Map();
  let bytes = 0;
  for (const [rawPath, content] of entries) {
    const path = normalizeRelativePath(rawPath);
    if (out.has(path)) throw fail("bad_input", "duplicate file path");
    if (typeof content !== "string") throw fail("bad_input", "file content");
    bytes += Buffer.byteLength(content, "utf8");
    if (bytes > STEP_MAX_BUNDLE_BYTES) throw fail("too_large", "files");
    out.set(path, content);
  }
  return out;
}

function normalizeRequirements(value) {
  if (value == null) return "";
  if (typeof value !== "string") throw fail("bad_input", "requirements");
  if (REQUIREMENTS_CONTROL.test(value)) throw fail("bad_input", "requirements");
  if (Buffer.byteLength(value, "utf8") > STEP_REQUIREMENTS_MAX_BYTES) throw fail("too_large", "requirements");
  return value;
}

/** An asset name: `[A-Za-z0-9._-]{1,100}`, never `.` or `..` (it also becomes a path segment). */
function normalizeAssetName(value) {
  if (typeof value !== "string" || !ASSET_NAME_RE.test(value)) throw fail("bad_input", "asset name");
  if (value === "." || value === "..") throw fail("bad_input", "asset name");
  return value;
}

/** The asset names a step binds: deduplicated, each a valid name, in the order given. */
function normalizeAssetNames(assets) {
  if (assets == null) return [];
  if (!Array.isArray(assets)) throw fail("bad_input", "assets");
  const out = [];
  for (const name of assets) {
    const clean = normalizeAssetName(name);
    if (!out.includes(clean)) out.push(clean);
  }
  return out;
}

/**
 * A host a report may reach: an exact lower-case name, or `*.suffix` with at least two labels after the
 * `*.`. Never an IP, never a bare TLD, never a trailing dot, never a port.
 */
export function normalizeHost(value) {
  if (typeof value !== "string") throw fail("bad_input", "host");
  if (CONTROL_CHARS.test(value)) throw fail("bad_input", "host");
  const raw = value;
  if (!raw || raw.length > HOST_MAX) throw fail("bad_input", "host");
  if (raw !== raw.toLowerCase()) throw fail("bad_input", "host");
  if (raw.endsWith(".")) throw fail("bad_input", "host");
  const wildcard = raw.startsWith("*.");
  const name = wildcard ? raw.slice(2) : raw;
  if (!name || name.includes("*")) throw fail("bad_input", "host");
  if (isIP(name)) throw fail("bad_input", "host");
  const labels = name.split(".");
  if (labels.length < 2) throw fail("bad_input", "host");
  for (const label of labels) {
    if (!HOST_LABEL_RE.test(label)) throw fail("bad_input", "host");
  }
  return wildcard ? `*.${name}` : name;
}

/** An exact host: a credential binds one site, never a wildcard. */
function normalizeExactHost(value) {
  const host = normalizeHost(value);
  if (host.startsWith("*.")) throw fail("bad_input", "host");
  return host;
}

/** The relay's own matching rule: an exact name, or a `*.suffix` wildcard (never the bare suffix). */
export function hostAllowed(host, list) {
  if (!Array.isArray(list)) return true;
  const h = text(host).trim().toLowerCase().replace(/\.$/, "");
  return list.some((pattern) => {
    const q = text(pattern).trim().toLowerCase().replace(/\.$/, "");
    if (q.startsWith("*.")) return h.endsWith(q.slice(1)) && h.length > q.length - 1;
    return h === q;
  });
}

/* ------------------------------------------------------------------- inject rules */

function injectError(code, message) {
  const err = new Error(`${code}: ${message}`);
  err.code = code;
  err.detail = message;
  return err;
}

/** The path prefixes a rule must name (at least one), each a path on the host. A bare
 *  `/` names no segment and is refused: it would put the credential everywhere. */
function normalizeInjectPrefixes(raw) {
  const bad = (why) => injectError("inject_bad_path_prefixes", why);
  if (!Array.isArray(raw) || raw.length === 0) throw bad("pathPrefixes must be a non-empty array of strings");
  if (raw.length > INJECT_MAX_PREFIXES) throw bad(`pathPrefixes holds at most ${INJECT_MAX_PREFIXES} entries`);
  const out = [];
  for (const prefix of raw) {
    if (typeof prefix !== "string" || prefix === "") throw bad("a path prefix must be a non-empty string");
    if (prefix.length > INJECT_MAX_PREFIX_CHARS) throw bad(`a path prefix is at most ${INJECT_MAX_PREFIX_CHARS} characters`);
    if (prefix[0] !== "/") throw bad("a path prefix starts with /");
    if (!prefix.split("/").some((segment) => segment !== "")) throw bad("a path prefix names at least one path segment");
    if (prefix.includes("..") || prefix.includes("?") || prefix.includes("#")) throw bad("a path prefix holds no .., ? or #");
    if (/[\u0000-\u001f\u007f]/.test(prefix)) throw bad("a path prefix holds no control character");
    if (!out.includes(prefix)) out.push(prefix);
  }
  return out;
}

/** The methods a rule allows: GET and HEAD unless it says, drawn from the inject set. */
function normalizeInjectMethods(raw) {
  if (raw === undefined || raw === null) return [...INJECT_DEFAULT_METHODS];
  const bad = (why) => injectError("inject_bad_methods", why);
  if (!Array.isArray(raw) || raw.length === 0) throw bad("methods must be a non-empty array");
  const out = [];
  for (const method of raw) {
    if (typeof method !== "string" || !INJECT_METHODS.includes(method)) {
      throw bad(`a method is one of ${INJECT_METHODS.join(", ")}`);
    }
    if (!out.includes(method)) out.push(method);
  }
  return out;
}

/**
 * One credential's inject rule, validated exactly as the egress relay validates its `inject` entry: one
 * exact lower-case host, exactly one of a header or a query parameter, a format holding one `{}` on a
 * header only, and a non-empty path prefix list (with optional methods). The rules are duplicated here
 * because the gateway cannot import the bot runtime's relay; a test drives both with the same bad input
 * list so the two cannot drift.
 *
 * @returns {{header?: string, query?: string, format?: string, pathPrefixes: string[], methods: string[]}}
 * @throws {Error} the relay's own codes (`inject_bad_target`, `inject_bad_header`, ...)
 */
export function normalizeInject(value) {
  if (!value || typeof value !== "object" || Array.isArray(value)) {
    throw injectError("inject_bad_entry", "an inject rule must be an object");
  }
  const hasHeader = value.header !== undefined && value.header !== null;
  const hasQuery = value.query !== undefined && value.query !== null;
  if (hasHeader === hasQuery) throw injectError("inject_bad_target", "exactly one of header or query is required");
  const out = {};
  if (hasHeader) {
    const header = String(value.header);
    const lower = header.toLowerCase();
    if (!INJECT_TOKEN_RE.test(header) || INJECT_BAD_HEADER.has(lower) || lower.startsWith("proxy-")) {
      throw injectError("inject_bad_header", "not a header a credential may be attached to");
    }
    out.header = header;
    out.format = "{}";
    if (value.format !== undefined && value.format !== null) {
      const format = String(value.format);
      if (format.length > INJECT_FORMAT_MAX || CONTROL_CHARS.test(format)) {
        throw injectError("inject_bad_format", "format is a short single line");
      }
      if (format.split("{}").length !== 2) throw injectError("inject_bad_format", "format must hold {} exactly once");
      out.format = format;
    }
  } else {
    const query = String(value.query);
    if (!INJECT_QUERY_RE.test(query)) throw injectError("inject_bad_query", "a query name is 1-64 of A-Z a-z 0-9 _ . -");
    if (value.format !== undefined && value.format !== null) {
      throw injectError("inject_bad_format", "format applies to a header, not to a query parameter");
    }
    out.query = query;
  }
  out.pathPrefixes = normalizeInjectPrefixes(value.pathPrefixes);
  out.methods = normalizeInjectMethods(value.methods);
  return out;
}

/** A stored `inject_json` as its rule, or null when it is not one (a direct UPDATE, a damaged row). */
function decodeInject(json) {
  let parsed;
  try {
    parsed = JSON.parse(text(json));
  } catch {
    return null;
  }
  try {
    return normalizeInject(parsed);
  } catch {
    return null;
  }
}

/**
 * One credential rule as the canonical text the seal digests: the five keys in one fixed order, with
 * "" in the two slots a rule cannot fill (exactly one of `header` and `query` is present, and `format`
 * belongs to a header only), the path prefixes sorted and the methods sorted. No other key is written:
 * `normalizeInject` reads only those five, so a key a direct UPDATE added to the stored JSON is not
 * part of the rule at all and cannot change what the relay attaches.
 *
 * Sorting is what makes the digest describe the BINDING and not the order it was typed in; the fixed
 * key order is what makes two spellings of one rule one digest.
 *
 * @param {object} rule an inject rule (normalised here, so a raw submitted rule works too)
 * @returns {string}
 * @throws {Error} the relay's own codes for a rule it would refuse
 */
export function canonicalInject(rule) {
  const normalized = normalizeInject(rule);
  return JSON.stringify({
    header: normalized.header === undefined ? "" : normalized.header,
    query: normalized.query === undefined ? "" : normalized.query,
    format: normalized.format === undefined ? "" : normalized.format,
    pathPrefixes: [...normalized.pathPrefixes].sort(),
    methods: [...normalized.methods].sort(),
  });
}

/**
 * The digest of a credential rule: the sha256 of `canonicalInject`, 64 lower-case hex characters. This
 * is the `injectHash` field of the credential seal, so the shape of what the relay will attach (which
 * header or query, the format, which paths, which methods) is under the owner's approval.
 *
 * @param {object} rule an inject rule
 * @returns {string}
 * @throws {Error} the relay's own codes for a rule it would refuse
 */
export function injectHashOf(rule) {
  return sha256Hex(canonicalInject(rule));
}

/* ------------------------------------------------------------------------ the envelope */

/**
 * A row's `files_json` as `{files, assets}`, or null when it is not the envelope this module writes.
 *
 * The envelope is `{"files": {<path>: <text>}, "assets": [<name>]}`, which keeps the bound asset names
 * inside the one column task 3 fixes while still putting them under the step's seal.
 */
function decodeEnvelope(row) {
  let parsed;
  try {
    parsed = JSON.parse(text(row?.files_json));
  } catch {
    return null;
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return null;
  const rawFiles = parsed.files;
  if (!rawFiles || typeof rawFiles !== "object" || Array.isArray(rawFiles)) return null;
  const files = new Map();
  for (const [path, content] of Object.entries(rawFiles)) {
    if (typeof path !== "string" || typeof content !== "string") return null;
    files.set(path, content);
  }
  const rawAssets = parsed.assets === undefined ? [] : parsed.assets;
  if (!Array.isArray(rawAssets)) return null;
  const assets = [];
  for (const name of rawAssets) {
    if (typeof name !== "string" || !name) return null;
    if (!assets.includes(name)) assets.push(name);
  }
  return { files, assets };
}

function encodeEnvelope(files, assets) {
  const out = {};
  for (const path of [...files.keys()].sort()) out[path] = files.get(path);
  return JSON.stringify({ files: out, assets: [...assets] });
}

/* ------------------------------------------------------------------------ row reading */

const STEP_COLUMNS = `report_id, step_key, rev, language, entry, files_json, requirements, bundle_hash,
  proposed_by, state, approval_nonce, approval_seal, approved_at, created_at`;

const HOST_COLUMNS = `report_id, host, state, approval_nonce, approval_seal, approved_at, created_at`;

const CREDENTIAL_COLUMNS = `report_id, host, connection_uuid, inject_json, state, approval_nonce,
  approval_seal, approved_at, created_at`;

/**
 * One step revision, or null. A revision is addressed by its own three-part key, never by position, so
 * a decision names exactly the row it was made about.
 */
export async function stepRow(db, reportId, stepKey, rev) {
  if (typeof reportId !== "string" || !reportId) throw fail("bad_input", "reportId");
  const key = normalizeStepKey(stepKey);
  const number = Number(rev);
  if (!Number.isInteger(number) || number < 1 || number > MAX_REV) throw fail("bad_input", "rev");
  const { rows } = await db.execute({
    sql: `SELECT ${STEP_COLUMNS} FROM report_custom_steps
           WHERE report_id = ? AND step_key = ? AND rev = ?`,
    args: [reportId, key, number],
  });
  return rows[0] ?? null;
}

/** The newest revision of one step, or null when the report has no row for that key. */
export async function newestStep(db, reportId, stepKey) {
  if (typeof reportId !== "string" || !reportId) throw fail("bad_input", "reportId");
  const key = normalizeStepKey(stepKey);
  const { rows } = await db.execute({
    sql: `SELECT ${STEP_COLUMNS} FROM report_custom_steps
           WHERE report_id = ? AND step_key = ? ORDER BY rev DESC LIMIT 1`,
    args: [reportId, key],
  });
  return rows[0] ?? null;
}

/** Every step key of one report at its newest revision, ordered by key. */
export async function listSteps(db, reportId) {
  if (typeof reportId !== "string" || !reportId) throw fail("bad_input", "reportId");
  const { rows } = await db.execute({
    sql: `SELECT ${STEP_COLUMNS} FROM report_custom_steps AS s
           WHERE report_id = ?
             AND rev = (SELECT MAX(rev) FROM report_custom_steps AS t
                         WHERE t.report_id = s.report_id AND t.step_key = s.step_key)
           ORDER BY step_key ASC`,
    args: [reportId],
  });
  return rows;
}

/** The previous APPROVED revision of one step (strictly before `rev`), or null. */
async function previousApprovedStep(db, reportId, stepKey, rev) {
  const { rows } = await db.execute({
    sql: `SELECT ${STEP_COLUMNS} FROM report_custom_steps
           WHERE report_id = ? AND step_key = ? AND rev < ? AND state = 'approved'
           ORDER BY rev DESC LIMIT 1`,
    args: [reportId, stepKey, Number(rev)],
  });
  return rows[0] ?? null;
}

async function stepRowsOfReport(db, reportId) {
  const { rows } = await db.execute({
    sql: `SELECT ${STEP_COLUMNS} FROM report_custom_steps WHERE report_id = ? ORDER BY step_key, rev`,
    args: [reportId],
  });
  return rows;
}

/* ----------------------------------------------------------------------------- assets */

/**
 * One report's asset rows for the named assets. A name with no row is a missing asset: the caller
 * decides whether that is a refusal (a proposal) or a failed verification (an approval).
 */
async function assetRowsFor(db, reportId, names) {
  if (!Array.isArray(names) || names.length === 0) return [];
  const { rows } = await db.execute({
    sql: `SELECT report_id, name, sha256, bytes FROM report_assets
           WHERE report_id = ? AND name IN (${names.map(() => "?").join(", ")}) ORDER BY name`,
    args: [reportId, ...names],
  });
  return rows;
}

/** The `{name, sha256}` list a bundle hash covers, or null when a named asset has no row. */
async function assetHashesFor(db, reportId, names) {
  const rows = await assetRowsFor(db, reportId, names);
  if (rows.length !== names.length) return null;
  return rows.map((row) => ({ name: row.name, sha256: text(row.sha256) }));
}

/** The bundle hash of a stored step, computed from the row's files and the CURRENT asset rows. */
async function bundleHashNow(db, reportId, row, decoded) {
  const assetHashes = await assetHashesFor(db, reportId, decoded.assets);
  if (!assetHashes) return null;
  try {
    return bundleHashOf({ files: decoded.files, requirements: text(row.requirements), assetHashes });
  } catch {
    return null;
  }
}

/** A report id as a filesystem path segment, or a refusal. */
function pathIdOf(value) {
  if (typeof value !== "string" || !PATH_ID_RE.test(value)) throw fail("bad_input", "reportId");
  if (value === "." || value === "..") throw fail("bad_input", "reportId");
  return value;
}

function reportAreaDir(d, reportId) {
  return join(d.crowHome(), "reports", pathIdOf(reportId));
}

function assetDir(d, reportId) {
  return join(reportAreaDir(d, reportId), "assets");
}

function assetPath(d, reportId, sha256) {
  return join(assetDir(d, reportId), sha256);
}

/** The bytes of one asset, written under its own hash: 0600, in a 0700 directory, atomically. */
function writeAssetFile(d, reportId, sha256, bytes) {
  const dir = assetDir(d, reportId);
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  try {
    chmodSync(dir, 0o700);
  } catch {
    // A directory this process does not own keeps its mode; the file below is still 0600.
  }
  const target = join(dir, sha256);
  const temp = join(dir, `.tmp-${process.pid}-${randomBytes(6).toString("hex")}`);
  writeFileSync(temp, bytes, { mode: 0o600 });
  try {
    chmodSync(temp, 0o600);
  } catch {
    // Best effort: writeFileSync already asked for 0600.
  }
  renameSync(temp, target);
  try {
    chmodSync(target, 0o600);
  } catch {
    // Best effort.
  }
}

function toBytes(value) {
  if (Buffer.isBuffer(value)) return value;
  if (value instanceof Uint8Array) return Buffer.from(value.buffer, value.byteOffset, value.byteLength);
  if (typeof value === "string") return Buffer.from(value, "utf8");
  throw fail("bad_input", "bytes");
}

/**
 * Remove one content-addressed asset file when no row of this report names its hash any more. The
 * bytes of a replaced or removed asset are not kept; a file that another row of the same report still
 * names is left exactly where it is. Never throws: a file that cannot be removed is a leftover, not a
 * failure of the write that made it unreferenced.
 */
async function unlinkAssetIfUnreferenced(db, d, reportId, sha256) {
  if (typeof sha256 !== "string" || !SHA256_RE.test(sha256)) return false;
  try {
    const { rows } = await db.execute({
      sql: "SELECT COUNT(*) AS n FROM report_assets WHERE report_id = ? AND sha256 = ?",
      args: [reportId, sha256],
    });
    if (Number(rows[0]?.n ?? 0) > 0) return false;
    rmSync(assetPath(d, reportId, sha256), { force: true });
    return true;
  } catch {
    return false;
  }
}

/**
 * Save one named asset for a report: the bytes under `<home>/reports/<id>/assets/<sha256>` (mode 0600)
 * and its row in `report_assets`. The name is the key, so saving the same name again replaces the
 * content and changes the hash, which breaks the seal of every step that binds it. The bytes of the
 * content it replaced are removed when no other row of the report still names that hash.
 *
 * The bytes one report's assets may hold in total are capped; the assets directory is created 0700.
 * A write that would cross the cap writes nothing at all.
 *
 * @param {object} db
 * @param {object} [deps] `crowHome`, `now`
 * @param {{reportId: string, name: string, bytes: Buffer|Uint8Array|string}} input
 * @returns {Promise<{name: string, sha256: string, bytes: number, createdAt: number}>}
 * @throws {Error} `bad_input`, `too_large`, `not_found`
 */
export async function saveAsset(db, deps, { reportId, name, bytes } = {}) {
  const d = resolveDeps(deps);
  const report = await approvalInternals.requireReport(db, reportId);
  const assetName = normalizeAssetName(name);
  const content = toBytes(bytes);
  if (content.length === 0) throw fail("bad_input", "bytes");
  if (content.length > ASSET_MAX_BYTES) throw fail("too_large", "asset");
  const { rows } = await db.execute({
    sql: "SELECT COALESCE(SUM(bytes), 0) AS total FROM report_assets WHERE report_id = ? AND name != ?",
    args: [report.id, assetName],
  });
  const other = Number(rows[0]?.total) || 0;
  if (other + content.length > ASSET_MAX_BYTES) throw fail("too_large", "assets");
  const prior = await db.execute({
    sql: "SELECT sha256 FROM report_assets WHERE report_id = ? AND name = ?",
    args: [report.id, assetName],
  });
  const previousSha = prior.rows[0] ? text(prior.rows[0].sha256) : null;
  const sha256 = sha256Hex(content);
  const at = d.now();
  writeAssetFile(d, report.id, sha256, content);
  await db.execute({
    sql: `INSERT INTO report_assets (report_id, name, sha256, bytes, created_at)
          VALUES (?, ?, ?, ?, ?)
          ON CONFLICT(report_id, name) DO UPDATE SET
            sha256 = excluded.sha256, bytes = excluded.bytes, created_at = excluded.created_at`,
    args: [report.id, assetName, sha256, content.length, at],
  });
  // The content this name no longer holds is gone from the disk unless another row still names it.
  if (previousSha && previousSha !== sha256) await unlinkAssetIfUnreferenced(db, d, report.id, previousSha);
  return { name: assetName, sha256, bytes: content.length, createdAt: at };
}

/**
 * Remove one named asset: its row, and the file behind its hash when no other row of the report names
 * that hash. The row goes first, so a failed unlink leaves a file nothing refers to rather than a row
 * whose bytes are gone.
 *
 * @param {object} db
 * @param {object} [deps]
 * @param {{reportId: string, name: string}} input
 * @returns {Promise<{name: string, removed: boolean, sha256: string|null}>}
 * @throws {Error} `bad_input`, `not_found`
 */
export async function removeAsset(db, deps, { reportId, name } = {}) {
  const d = resolveDeps(deps);
  const report = await approvalInternals.requireReport(db, reportId);
  const assetName = normalizeAssetName(name);
  const { rows } = await db.execute({
    sql: "SELECT sha256 FROM report_assets WHERE report_id = ? AND name = ?",
    args: [report.id, assetName],
  });
  if (!rows[0]) return { name: assetName, removed: false, sha256: null };
  const sha256 = text(rows[0].sha256);
  await db.execute({
    sql: "DELETE FROM report_assets WHERE report_id = ? AND name = ?",
    args: [report.id, assetName],
  });
  await unlinkAssetIfUnreferenced(db, d, report.id, sha256);
  return { name: assetName, removed: true, sha256 };
}

/**
 * Does the file behind this asset row still hash to the row's sha256? A swapped file, a deleted one, a
 * row that names a path this module would not write, or an unreadable directory is `false`.
 *
 * @param {object} [deps]
 * @param {object} row a `report_assets` row
 * @returns {Promise<boolean>}
 */
export async function verifyAssetOnDisk(deps, row) {
  try {
    if (row == null || typeof row !== "object") return false;
    const d = resolveDeps(deps);
    const reportId = pathIdOf(text(row.report_id !== undefined ? row.report_id : row.reportId));
    const sha256 = text(row.sha256);
    if (!SHA256_RE.test(sha256)) return false;
    const bytes = readFileSync(assetPath(d, reportId, sha256));
    return sha256Hex(bytes) === sha256;
  } catch {
    return false;
  }
}

/**
 * One report's assets, newest name first, each with whether its file still matches its hash. The bytes
 * are never returned.
 *
 * @param {object} db
 * @param {string} reportId
 * @param {object} [deps]
 * @returns {Promise<Array<{name: string, sha256: string, bytes: number, createdAt: number,
 *   verified: boolean}>>}
 */
export async function listAssets(db, reportId, deps) {
  if (typeof reportId !== "string" || !reportId) throw fail("bad_input", "reportId");
  const d = resolveDeps(deps);
  const { rows } = await db.execute({
    sql: "SELECT report_id, name, sha256, bytes, created_at FROM report_assets WHERE report_id = ? ORDER BY name ASC",
    args: [reportId],
  });
  const out = [];
  for (const row of rows) {
    out.push({
      name: row.name,
      sha256: text(row.sha256),
      bytes: Number(row.bytes),
      createdAt: Number(row.created_at),
      verified: await verifyAssetOnDisk(d, row),
    });
  }
  return out;
}

/* ------------------------------------------------------------------------------ steps */

/** The seal's step id for one revision: the stable half of what the owner approved. */
export function stepIdOf(stepKey, rev) {
  return `${stepKey}:${Number(rev)}`;
}

/** One file of a bundle: its path, its size and its hash, never its text. */
function fileSummary(path, content) {
  return { path, bytes: Buffer.byteLength(content, "utf8"), sha256: sha256Hex(content) };
}

/**
 * One step row as a page reads it: the state, whether its approval still verifies, its files as paths,
 * sizes and hashes, its assets, and never the seal or the nonce. `bundleHash` is the hash the owner's
 * tap has to hand back, so the views a page reads pass the hash of what would run NOW (recomputed from
 * the row and the current asset rows); without one the stored column is answered as it is.
 */
function stepView(row, verified, { withFiles = false, bundleHash = undefined } = {}) {
  if (!row) return null;
  const decoded = decodeEnvelope(row) ?? { files: new Map(), assets: [] };
  const paths = [...decoded.files.keys()].sort();
  const view = {
    reportId: row.report_id,
    stepKey: row.step_key,
    rev: Number(row.rev),
    language: row.language,
    entry: row.entry,
    requirements: text(row.requirements),
    bundleHash: bundleHash !== undefined ? bundleHash : row.bundle_hash == null ? null : text(row.bundle_hash),
    proposedBy: row.proposed_by,
    state: row.state,
    approvedAt: row.approved_at == null ? null : Number(row.approved_at),
    createdAt: Number(row.created_at),
    assets: [...decoded.assets],
    files: paths.map((path) => fileSummary(path, decoded.files.get(path))),
    verified,
  };
  if (withFiles) view.contents = paths.map((path) => ({ path, text: decoded.files.get(path) }));
  return view;
}

/**
 * Does this step row still hold the owner's approval?
 *
 * `true` only when the state is `approved`, the seal verifies over the bundle hash RECOMPUTED now from
 * the row's own files, its requirements and the CURRENT asset rows, and every asset it names still has
 * a row, and over the `language` and `entry` the row holds NOW. A direct UPDATE of a file, the
 * requirements, the asset list, an asset row, the language or the entry therefore makes an approved row
 * unapproved, and a refusal or a revocation (which nulls the seal) can never be undone by restoring the
 * state word. Never throws: a broken row, a missing seed and a malformed seal are `false`.
 *
 * `language` and `entry` are read from the row rather than from a caller's copy of it: `entry` names the
 * file that runs and `language` names the runtime it runs in, so both are part of what the owner
 * approved (seal.js's "step" field list) and neither can move under a seal.
 *
 * @param {object} db
 * @param {object} [deps]
 * @param {object|null} row a `report_custom_steps` row (or the camelCase view a caller built)
 * @returns {Promise<boolean>}
 */
export async function verifyStep(db, deps, row) {
  try {
    if (row == null || typeof row !== "object") return false;
    if (row.state !== "approved") return false;
    const reportId = text(row.report_id !== undefined ? row.report_id : row.reportId);
    const stepKey = text(row.step_key !== undefined ? row.step_key : row.stepKey);
    const rev = Number(row.rev);
    if (!reportId || !STEP_KEY_RE.test(stepKey)) return false;
    if (!Number.isInteger(rev) || rev < 1) return false;
    const seal = row.approval_seal !== undefined ? row.approval_seal : row.approvalSeal;
    const nonce = row.approval_nonce !== undefined ? row.approval_nonce : row.approvalNonce;
    if (typeof seal !== "string" || !seal) return false;
    if (typeof nonce !== "string" || !nonce) return false;
    const decoded = decodeEnvelope(row);
    if (!decoded) return false;
    const bundleHash = await bundleHashNow(db, reportId, row, decoded);
    if (!bundleHash) return false;
    const language = text(row.language);
    const entry = text(row.entry);
    if (!STEP_LANGUAGES.includes(language) || !entry) return false;
    const seed = await approvalInternals.seedOf(resolveDeps(deps));
    return verifyApprovalSeal(
      "step",
      { reportId, stepId: stepIdOf(stepKey, rev), bundleHash, language, entry, nonce },
      seal,
      seed,
    );
  } catch {
    return false;
  }
}

/**
 * Propose one revision of one step: validated, hashed and stored `proposed`, waiting for the owner.
 *
 * A proposal approves nothing. The revision is the next one for that key, and the bundle hash is
 * computed from the submitted files, the requirements text and the CURRENT asset hashes, so the row
 * records what the owner will be asked to approve.
 *
 * @param {object} db
 * @param {object} [deps]
 * @param {{reportId: string, stepKey: string, language: "python"|"node", entry: string,
 *   files: object|Map<string, string>, assets?: string[], requirements?: string,
 *   proposedBy: "owner"|"bot:<id>"}} input
 * @returns {Promise<object>} the step row as a page reads it
 * @throws {Error} `bad_input`, `too_large`, `not_found`, `keychain_key_missing`
 */
export async function proposeStep(db, deps, {
  reportId, stepKey, language, entry, files, assets, requirements, proposedBy,
} = {}) {
  const d = resolveDeps(deps);
  const report = await approvalInternals.requireReport(db, reportId);
  const key = normalizeStepKey(stepKey);
  const lang = normalizeLanguage(language);
  const normalizedFiles = normalizeFiles(files);
  const entryPath = normalizeRelativePath(entry);
  if (!normalizedFiles.has(entryPath)) throw fail("bad_input", "entry");
  const reqs = normalizeRequirements(requirements);
  const assetNames = normalizeAssetNames(assets);
  const assetHashes = await assetHashesFor(db, report.id, assetNames);
  if (!assetHashes) throw fail("bad_input", "asset");
  const by = approvalInternals.normalizeProposedBy(proposedBy);
  const filesJson = encodeEnvelope(normalizedFiles, assetNames);
  if (Buffer.byteLength(filesJson, "utf8") > STEP_MAX_BUNDLE_BYTES) throw fail("too_large", "files_json");
  const bundleHash = bundleHashOf({ files: normalizedFiles, requirements: reqs, assetHashes });
  const at = d.now();
  const newest = await newestStep(db, report.id, key);
  let rev = newest ? Number(newest.rev) + 1 : 1;
  for (let attempt = 0; attempt < 3; attempt += 1) {
    try {
      await db.execute({
        sql: `INSERT INTO report_custom_steps
                (report_id, step_key, rev, language, entry, files_json, requirements, bundle_hash,
                 proposed_by, state, created_at)
              VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, 'proposed', ?)`,
        args: [report.id, key, rev, lang, entryPath, filesJson, reqs, bundleHash, by, at],
      });
      return stepView(await stepRow(db, report.id, key, rev), false);
    } catch (err) {
      // Another propose of the same key took this revision number: answer the next one.
      if (attempt === 2) throw err;
      const again = await newestStep(db, report.id, key);
      rev = again ? Number(again.rev) + 1 : 1;
    }
  }
  throw fail("step_changed");
}

/**
 * The owner's approval of one step revision: a fresh nonce, a seal over (report, `<key>:<rev>`, the
 * bundle hash recomputed now, the row's language and entry, the nonce), the state and the approval time
 * in one guarded write, and an audit row. An already-approved revision whose seal still verifies is
 * answered as it is, so a repeated tap is not a second approval; any other state is approved with a
 * FRESH seal, which is what makes a re-approval after a refusal real work rather than a replay.
 *
 * `bundleHash` is the hash the owner's view showed (the step view hands it back). The decision is about
 * THAT bundle: a file, a requirement or an asset that moved between the view and the tap recomputes to
 * another hash and answers `step_changed`, so the owner's OK is never silently given to other content.
 * The write is also guarded by the stored hash it read, so a concurrent write changes no row.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, stepKey: string, rev: number, bundleHash: string,
 *   actor: {kind: "owner"}}} input
 * @returns {Promise<object>} the step row as a page reads it (with its file text)
 * @throws {Error} `owner_only`, `bad_input`, `not_found`, `keychain_key_missing`, `step_changed`
 */
export async function approveStep(db, deps, { reportId, stepKey, rev, bundleHash, actor } = {}) {
  approvalInternals.requireOwner(actor);
  const d = resolveDeps(deps);
  await approvalInternals.requireReport(db, reportId);
  const key = normalizeStepKey(stepKey);
  const expected = normalizeBundleHash(bundleHash);
  const row = await stepRow(db, reportId, key, rev);
  if (!row) throw fail("not_found", "step");
  const decoded = decodeEnvelope(row);
  if (!decoded) throw fail("bad_input", "files_json");
  const current = await bundleHashNow(db, row.report_id, row, decoded);
  if (!current) throw fail("bad_input", "asset");
  // What the owner saw has to be what is here NOW.
  if (current !== expected) throw fail("step_changed");
  if (row.state === "approved" && (await verifyStep(db, d, row))) {
    return stepView(row, true, { withFiles: true, bundleHash: current });
  }
  const language = text(row.language);
  const entry = text(row.entry);
  if (!STEP_LANGUAGES.includes(language) || !entry) throw fail("bad_input", "language");
  const seed = await approvalInternals.seedOf(d);
  const nonce = newApprovalNonce();
  const seal = approvalSeal(
    "step",
    { reportId: row.report_id, stepId: stepIdOf(key, row.rev), bundleHash: current, language, entry, nonce },
    seed,
  );
  const at = d.now();
  const written = await db.execute({
    sql: `UPDATE report_custom_steps
             SET state = 'approved', approval_nonce = ?, approval_seal = ?, approved_at = ?, bundle_hash = ?
           WHERE report_id = ? AND step_key = ? AND rev = ? AND state = ? AND bundle_hash IS ?`,
    args: [nonce, seal, at, current, row.report_id, key, Number(row.rev), row.state, row.bundle_hash ?? null],
  });
  if (Number(written?.rowsAffected ?? 0) !== 1) throw fail("step_changed");
  await recordAudit(db, {
    reportId: row.report_id,
    kind: "step",
    subject: stepIdOf(key, row.rev),
    actor: "owner",
    decided: "approved",
    at,
  });
  return stepView(await stepRow(db, row.report_id, key, row.rev), true, { withFiles: true, bundleHash: current });
}

/**
 * Refuse or revoke one step revision: the state in one word and BOTH the seal and its nonce set to NULL,
 * so an old seal can never re-approve the row. The write is guarded by the state this read saw.
 */
async function decideStep(db, deps, { reportId, stepKey, rev, actor, state, decided } = {}) {
  approvalInternals.requireOwner(actor);
  const d = resolveDeps(deps);
  await approvalInternals.requireReport(db, reportId);
  const key = normalizeStepKey(stepKey);
  const row = await stepRow(db, reportId, key, rev);
  if (!row) throw fail("not_found", "step");
  const at = d.now();
  const written = await db.execute({
    sql: `UPDATE report_custom_steps
             SET state = ?, approval_nonce = NULL, approval_seal = NULL, approved_at = NULL
           WHERE report_id = ? AND step_key = ? AND rev = ? AND state = ?`,
    args: [state, row.report_id, key, Number(row.rev), row.state],
  });
  if (Number(written?.rowsAffected ?? 0) !== 1) throw fail("step_changed");
  await recordAudit(db, {
    reportId: row.report_id,
    kind: "step",
    subject: stepIdOf(key, row.rev),
    actor: "owner",
    decided,
    at,
  });
  return stepView(await stepRow(db, row.report_id, key, row.rev), false, { withFiles: true });
}

/**
 * The owner's refusal of a proposed step revision.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, stepKey: string, rev: number, actor: {kind: "owner"}}} input
 * @returns {Promise<object>}
 */
export async function refuseStep(db, deps, { reportId, stepKey, rev, actor } = {}) {
  return decideStep(db, deps, { reportId, stepKey, rev, actor, state: "refused", decided: "refused" });
}

/**
 * The owner's revocation of an approved step revision.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, stepKey: string, rev: number, actor: {kind: "owner"}}} input
 * @returns {Promise<object>}
 */
export async function revokeStep(db, deps, { reportId, stepKey, rev, actor } = {}) {
  return decideStep(db, deps, { reportId, stepKey, rev, actor, state: "revoked", decided: "revoked" });
}

/**
 * The step a run would execute, or the reason it may not.
 *
 * The NEWEST revision must be approved and verified. An older approved revision never carries a newer
 * one into a run: a proposal is visible to the owner as the thing that needs a tap, and nothing runs
 * until it gets one. Every other condition (no row for the key, a broken seal, an asset swapped on
 * disk, a bad key) answers `{ok: false, reason: "step_waiting"}` rather than throwing, because one
 * unapproved step is a report that waits, not a run that crashes. The `language` and `entry` it answers
 * are the row's own columns, covered by the seal like every other part of the approval (see
 * `verifyStep`).
 *
 * @param {object} db
 * @param {object} deps
 * @param {string} reportId
 * @param {string} stepKey
 * @returns {Promise<{ok: true, step: object}|{ok: false, reason: "step_waiting"}>}
 */
export async function runnableStep(db, deps, reportId, stepKey) {
  try {
    const d = resolveDeps(deps);
    if (typeof reportId !== "string" || !reportId) return { ok: false, reason: STEP_WAITING };
    const key = normalizeStepKey(stepKey);
    const row = await newestStep(db, reportId, key);
    if (!row) return { ok: false, reason: STEP_WAITING };
    if (!(await verifyStep(db, d, row))) return { ok: false, reason: STEP_WAITING };
    const decoded = decodeEnvelope(row);
    if (!decoded) return { ok: false, reason: STEP_WAITING };
    const assets = await assetRowsFor(db, reportId, decoded.assets);
    if (assets.length !== decoded.assets.length) return { ok: false, reason: STEP_WAITING };
    for (const asset of assets) {
      if (!(await verifyAssetOnDisk(d, asset))) return { ok: false, reason: STEP_WAITING };
    }
    return {
      ok: true,
      step: {
        reportId,
        stepKey: key,
        rev: Number(row.rev),
        language: row.language,
        entry: row.entry,
        requirements: text(row.requirements),
        bundleHash: text(row.bundle_hash),
        files: Object.fromEntries([...decoded.files.entries()].sort((a, b) => (a[0] < b[0] ? -1 : 1))),
        assets: assets.map((asset) => ({
          name: asset.name,
          sha256: text(asset.sha256),
          path: assetPath(d, reportId, text(asset.sha256)),
        })),
      },
    };
  } catch {
    return { ok: false, reason: STEP_WAITING };
  }
}

/**
 * The per-file line diff of one step revision against the previous APPROVED revision.
 *
 * The comparison base is the previous approved revision, never the previous one: what an owner needs to
 * read is "what would change from what I approved". With no earlier approval every file reads as added.
 *
 * @param {object} db
 * @param {string} reportId
 * @param {string} stepKey
 * @param {number} rev
 * @returns {Promise<{reportId: string, stepKey: string, rev: number, previousRev: number|null,
 *   files: Array<{path: string, status: string, added: number, removed: number, capped: boolean,
 *   lines: Array<{op: string, text: string}>}>, added: number, removed: number}>}
 * @throws {Error} `bad_input` or `not_found`
 */
export async function stepDiff(db, reportId, stepKey, rev) {
  if (typeof reportId !== "string" || !reportId) throw fail("bad_input", "reportId");
  const key = normalizeStepKey(stepKey);
  const row = await stepRow(db, reportId, key, rev);
  if (!row) throw fail("not_found", "step");
  const current = decodeEnvelope(row);
  if (!current) throw fail("bad_input", "files_json");
  const previous = await previousApprovedStep(db, reportId, key, row.rev);
  const before = previous ? decodeEnvelope(previous) : null;
  const paths = [...new Set([...(before ? before.files.keys() : []), ...current.files.keys()])].sort();
  const files = [];
  let added = 0;
  let removed = 0;
  for (const path of paths) {
    const oldText = before && before.files.has(path) ? before.files.get(path) : "";
    const newText = current.files.has(path) ? current.files.get(path) : "";
    const status = !before || !before.files.has(path)
      ? "added"
      : !current.files.has(path)
        ? "removed"
        : oldText === newText
          ? "same"
          : "changed";
    const diff = lineDiff(oldText, newText);
    added += diff.added;
    removed += diff.removed;
    files.push({ path, status, added: diff.added, removed: diff.removed, capped: diff.capped, lines: diff.lines });
  }
  return {
    reportId,
    stepKey: key,
    rev: Number(row.rev),
    previousRev: previous ? Number(previous.rev) : null,
    files,
    added,
    removed,
  };
}

/**
 * Every step key of one report at its newest revision, each with whether its approval still verifies.
 * The file text is not in the answer; a page that shows code asks for one revision.
 *
 * @param {object} db
 * @param {string} reportId
 * @param {object} [deps]
 * @returns {Promise<object[]>}
 */
export async function listStepsForPage(db, reportId, deps) {
  const d = resolveDeps(deps);
  const rows = await listSteps(db, reportId);
  const out = [];
  for (const row of rows) {
    const decoded = decodeEnvelope(row);
    const now = decoded ? await bundleHashNow(db, reportId, row, decoded) : null;
    out.push(stepView(row, await verifyStep(db, d, row), now === null ? {} : { bundleHash: now }));
  }
  return out;
}

/** One revision as a page reads it, with its files' text, or null when there is no such revision. */
export async function stepDetail(db, reportId, stepKey, rev, deps) {
  const d = resolveDeps(deps);
  const row = await stepRow(db, reportId, stepKey, rev);
  if (!row) return null;
  const decoded = decodeEnvelope(row);
  const now = decoded ? await bundleHashNow(db, reportId, row, decoded) : null;
  return stepView(row, await verifyStep(db, d, row), {
    withFiles: true,
    ...(now === null ? {} : { bundleHash: now }),
  });
}

/* ------------------------------------------------------------------------------ hosts */

function hostView(row, verified) {
  if (!row) return null;
  return {
    reportId: row.report_id,
    host: row.host,
    state: row.state,
    approvedAt: row.approved_at == null ? null : Number(row.approved_at),
    createdAt: Number(row.created_at),
    verified,
  };
}

/** One report's host row for one host, or null. */
export async function hostRow(db, reportId, host) {
  if (typeof reportId !== "string" || !reportId) throw fail("bad_input", "reportId");
  const value = normalizeHost(host);
  const { rows } = await db.execute({
    sql: `SELECT ${HOST_COLUMNS} FROM report_hosts WHERE report_id = ? AND host = ?`,
    args: [reportId, value],
  });
  return rows[0] ?? null;
}

async function hostRowsOfReport(db, reportId) {
  const { rows } = await db.execute({
    sql: `SELECT ${HOST_COLUMNS} FROM report_hosts WHERE report_id = ? ORDER BY host ASC`,
    args: [reportId],
  });
  return rows;
}

/**
 * Does this host row still hold the owner's approval? `true` only when the state is `approved` and the
 * seal verifies over the report, the host as the row holds it NOW and the nonce, so a direct UPDATE of
 * the host name makes an approved row unapproved. Never throws.
 */
export async function verifyHost(db, deps, row) {
  try {
    if (row == null || typeof row !== "object") return false;
    if (row.state !== "approved") return false;
    const reportId = text(row.report_id !== undefined ? row.report_id : row.reportId);
    const host = text(row.host);
    if (!reportId || !host) return false;
    const seal = row.approval_seal !== undefined ? row.approval_seal : row.approvalSeal;
    const nonce = row.approval_nonce !== undefined ? row.approval_nonce : row.approvalNonce;
    if (typeof seal !== "string" || !seal) return false;
    if (typeof nonce !== "string" || !nonce) return false;
    const seed = await approvalInternals.seedOf(resolveDeps(deps));
    return verifyApprovalSeal("host", { reportId, host, nonce }, seal, seed);
  } catch {
    return false;
  }
}

/**
 * Propose one host for one report. An already approved row whose seal still verifies is answered as it
 * is, so a repeated tap is not a second approval; any other row (a proposal, a refusal, a revocation, or
 * a row whose seal no longer verifies) goes back to `proposed` with its seal and nonce NULLED, waiting
 * for a fresh approval.
 *
 * @param {object} db
 * @param {object} [deps]
 * @param {{reportId: string, host: string}} input
 * @returns {Promise<object>} the host row as a page reads it
 * @throws {Error} `bad_input`, `not_found`, `host_changed`
 */
export async function proposeHost(db, deps, { reportId, host } = {}) {
  const d = resolveDeps(deps);
  await approvalInternals.requireReport(db, reportId);
  const value = normalizeHost(host);
  const existing = await hostRow(db, reportId, value);
  const at = d.now();
  if (!existing) {
    await db.execute({
      sql: `INSERT INTO report_hosts (report_id, host, state, created_at) VALUES (?, ?, 'proposed', ?)`,
      args: [reportId, value, at],
    });
    return hostView(await hostRow(db, reportId, value), false);
  }
  if (existing.state === "approved" && (await verifyHost(db, d, existing))) {
    return hostView(existing, true);
  }
  if (existing.state === "proposed") return hostView(existing, false);
  const written = await db.execute({
    sql: `UPDATE report_hosts
             SET state = 'proposed', approval_nonce = NULL, approval_seal = NULL, approved_at = NULL
           WHERE report_id = ? AND host = ? AND state = ?`,
    args: [reportId, value, existing.state],
  });
  if (Number(written?.rowsAffected ?? 0) !== 1) throw fail("host_changed");
  return hostView(await hostRow(db, reportId, value), false);
}

/**
 * The owner's approval of one host: a fresh nonce, a seal over (report, host, nonce), the state and the
 * approval time in one guarded write, and an audit row. The answer carries the sentence the owner is
 * shown beside the tap (`HOST_APPROVAL_LINE`), returned here so the view cannot drift from the plan.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, host: string, actor: {kind: "owner"}}} input
 * @returns {Promise<{host: object, notice: string}>}
 * @throws {Error} `owner_only`, `bad_input`, `not_found`, `keychain_key_missing`, `host_changed`
 */
export async function approveHost(db, deps, { reportId, host, actor } = {}) {
  approvalInternals.requireOwner(actor);
  const d = resolveDeps(deps);
  await approvalInternals.requireReport(db, reportId);
  const value = normalizeHost(host);
  const row = await hostRow(db, reportId, value);
  if (!row) throw fail("not_found", "host");
  if (row.state === "approved" && (await verifyHost(db, d, row))) {
    return { host: hostView(row, true), notice: HOST_APPROVAL_LINE };
  }
  const seed = await approvalInternals.seedOf(d);
  const nonce = newApprovalNonce();
  const seal = approvalSeal("host", { reportId, host: value, nonce }, seed);
  const at = d.now();
  const written = await db.execute({
    sql: `UPDATE report_hosts
             SET state = 'approved', approval_nonce = ?, approval_seal = ?, approved_at = ?
           WHERE report_id = ? AND host = ? AND state = ?`,
    args: [nonce, seal, at, reportId, value, row.state],
  });
  if (Number(written?.rowsAffected ?? 0) !== 1) throw fail("host_changed");
  await recordAudit(db, {
    reportId,
    kind: "host",
    subject: value,
    actor: "owner",
    decided: "approved",
    at,
  });
  return { host: hostView(await hostRow(db, reportId, value), true), notice: HOST_APPROVAL_LINE };
}

/**
 * Revoke one host: the state in one word and both the seal and its nonce NULLED. A credential bound to
 * that host stops being usable at the same moment, because `injectRulesFor` re-checks the host approval.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, host: string, actor: {kind: "owner"}}} input
 * @returns {Promise<object>} the host row as a page reads it
 * @throws {Error} `owner_only`, `bad_input`, `not_found`, `host_changed`
 */
export async function revokeHost(db, deps, { reportId, host, actor } = {}) {
  approvalInternals.requireOwner(actor);
  const d = resolveDeps(deps);
  await approvalInternals.requireReport(db, reportId);
  const value = normalizeHost(host);
  const row = await hostRow(db, reportId, value);
  if (!row) throw fail("not_found", "host");
  const at = d.now();
  const written = await db.execute({
    sql: `UPDATE report_hosts
             SET state = 'revoked', approval_nonce = NULL, approval_seal = NULL, approved_at = NULL
           WHERE report_id = ? AND host = ? AND state = ?`,
    args: [reportId, value, row.state],
  });
  if (Number(written?.rowsAffected ?? 0) !== 1) throw fail("host_changed");
  await recordAudit(db, {
    reportId,
    kind: "host",
    subject: value,
    actor: "owner",
    decided: "revoked",
    at,
  });
  return hostView(await hostRow(db, reportId, value), false);
}

/**
 * One report's hosts, each with whether its approval still verifies. The seal and the nonce are never in
 * the answer.
 *
 * @param {object} db
 * @param {string} reportId
 * @param {object} [deps]
 * @returns {Promise<object[]>}
 */
export async function listHosts(db, reportId, deps) {
  if (typeof reportId !== "string" || !reportId) throw fail("bad_input", "reportId");
  const d = resolveDeps(deps);
  const out = [];
  for (const row of await hostRowsOfReport(db, reportId)) {
    out.push(hostView(row, await verifyHost(db, d, row)));
  }
  return out;
}

/**
 * Is this exact host covered by an approved, verified host of this report (exactly, or by a `*.suffix`
 * wildcard row)? The answer a credential proposal and the delivery target both stand on.
 *
 * @param {object} db
 * @param {object} [deps]
 * @param {string} reportId
 * @param {string} host an exact host
 * @returns {Promise<boolean>}
 */
export async function hostApproved(db, deps, reportId, host) {
  try {
    const d = resolveDeps(deps);
    const value = normalizeExactHost(host);
    for (const row of await hostRowsOfReport(db, reportId)) {
      if (row.state !== "approved") continue;
      if (!hostAllowed(value, [row.host])) continue;
      if (await verifyHost(db, d, row)) return true;
    }
    return false;
  } catch {
    return false;
  }
}

/* ------------------------------------------------------------------------ credentials */

/** A keychain reference an owner's view holds, which an approval has to still be about. */
function normalizeConnectionRef(value) {
  if (typeof value !== "string" || !UUID_RE.test(value)) throw fail("bad_input", "connectionUuid");
  return value;
}

/** The digest of the rule an owner's view showed, which an approval has to still be about. */
function normalizeInjectHash(value) {
  if (typeof value !== "string" || !SHA256_RE.test(value)) throw fail("bad_input", "injectHash");
  return value;
}

/** The bundle hash an owner's view showed, which an approval has to still be about. */
function normalizeBundleHash(value) {
  if (typeof value !== "string" || !SHA256_RE.test(value)) throw fail("bad_input", "bundleHash");
  return value;
}

/**
 * One credential row as a page reads it, with the digest of its rule (`injectHash`) because that is
 * what the owner's tap hands back with the reference, and never the seal or the nonce.
 */
function credentialView(row, verified) {
  if (!row) return null;
  const inject = decodeInject(row.inject_json);
  return {
    reportId: row.report_id,
    host: row.host,
    connectionUuid: text(row.connection_uuid),
    inject: inject
      ? {
        ...(inject.header ? { header: inject.header, format: inject.format } : { query: inject.query }),
        pathPrefixes: [...inject.pathPrefixes],
        methods: [...inject.methods],
      }
      : null,
    injectHash: inject ? injectHashOf(inject) : null,
    state: row.state,
    approvedAt: row.approved_at == null ? null : Number(row.approved_at),
    createdAt: Number(row.created_at),
    verified,
  };
}

/** One report's credential row for one host, or null. */
export async function credentialRow(db, reportId, host) {
  if (typeof reportId !== "string" || !reportId) throw fail("bad_input", "reportId");
  const value = normalizeExactHost(host);
  const { rows } = await db.execute({
    sql: `SELECT ${CREDENTIAL_COLUMNS} FROM report_credentials WHERE report_id = ? AND host = ?`,
    args: [reportId, value],
  });
  return rows[0] ?? null;
}

async function credentialRowsOfReport(db, reportId) {
  const { rows } = await db.execute({
    sql: `SELECT ${CREDENTIAL_COLUMNS} FROM report_credentials WHERE report_id = ? ORDER BY host ASC`,
    args: [reportId],
  });
  return rows;
}

/**
 * Does this credential row still hold the owner's approval? `true` only when the state is `approved`,
 * its stored rule is still one the relay would accept, and the seal verifies over (report, the
 * connection reference, the host as the row holds it NOW, the digest of the rule the row holds NOW, the
 * nonce).
 *
 * The rule's SHAPE is under the seal as `injectHash` (seal.js's "credential" field list), so a direct
 * UPDATE of `inject_json` that widens a path prefix, adds a method or moves the credential to another
 * header or query parameter is a different rule from the approved one and reads as unapproved. A row
 * whose rule no longer parses does not verify either. Never throws.
 */
export async function verifyCredential(db, deps, row) {
  try {
    if (row == null || typeof row !== "object") return false;
    if (row.state !== "approved") return false;
    const reportId = text(row.report_id !== undefined ? row.report_id : row.reportId);
    const host = text(row.host);
    const ref = text(row.connection_uuid !== undefined ? row.connection_uuid : row.connectionUuid);
    if (!reportId || !host || !ref) return false;
    const inject = decodeInject(row.inject_json);
    if (!inject) return false;
    const injectHash = injectHashOf(inject);
    const seal = row.approval_seal !== undefined ? row.approval_seal : row.approvalSeal;
    const nonce = row.approval_nonce !== undefined ? row.approval_nonce : row.approvalNonce;
    if (typeof seal !== "string" || !seal) return false;
    if (typeof nonce !== "string" || !nonce) return false;
    const seed = await approvalInternals.seedOf(resolveDeps(deps));
    return verifyApprovalSeal(
      "credential", { reportId, credentialRef: ref, host, injectHash, nonce }, seal, seed,
    );
  } catch {
    return false;
  }
}

/**
 * Propose one credential binding: one EXACT host of one report to one keychain row, with the inject rule
 * the relay will use.
 *
 * A credential needs an approved host. A well-formed host that the report has not approved (or whose
 * approval no longer verifies) is `host_not_approved`; a malformed host or a wildcard is `bad_input`. A
 * rule the relay would refuse is `bad_inject`, and a rule with no path prefixes is refused there too, so
 * a credential can never be attached to a whole host.
 *
 * A row already bound for that host goes back to `proposed` with its seal and nonce NULLED and the new
 * keychain reference, which is the same write a revocation makes: replacing a credential is never an
 * approval, and the previous reference is handed back so the caller can retire its keychain row.
 *
 * @param {object} db
 * @param {object} [deps]
 * @param {{reportId: string, host: string, connectionUuid: string, inject: object,
 *   proposedBy?: "owner"|"bot:<id>"}} input
 * @returns {Promise<object>} the credential row as a page reads it
 * @throws {Error} `bad_input`, `bad_inject`, `host_not_approved`, `not_found`, `credential_changed`
 */
export async function proposeCredential(db, deps, {
  reportId, host, connectionUuid, inject, proposedBy,
} = {}) {
  const d = resolveDeps(deps);
  const report = await approvalInternals.requireReport(db, reportId);
  const value = normalizeExactHost(host);
  const ref = normalizeConnectionRef(connectionUuid);
  let rule;
  try {
    rule = normalizeInject(inject);
  } catch (err) {
    throw fail("bad_inject", err && typeof err.code === "string" ? err.code : "inject_bad_entry");
  }
  // The actor word is validated after the rule so a bot's malformed request never reaches the host read.
  const by = proposedBy === undefined ? "owner" : approvalInternals.normalizeProposedBy(proposedBy);
  if (!(await hostApproved(db, d, report.id, value))) throw fail("host_not_approved");
  const injectJson = JSON.stringify(rule);
  const at = d.now();
  const existing = await credentialRow(db, report.id, value);
  if (!existing) {
    await db.execute({
      sql: `INSERT INTO report_credentials
              (report_id, host, connection_uuid, inject_json, state, created_at)
            VALUES (?, ?, ?, ?, 'proposed', ?)`,
      args: [report.id, value, ref, injectJson, at],
    });
    return {
      ...credentialView(await credentialRow(db, report.id, value), false),
      proposedBy: by,
      previousConnectionUuid: null,
    };
  }
  const written = await db.execute({
    sql: `UPDATE report_credentials
             SET connection_uuid = ?, inject_json = ?, state = 'proposed',
                 approval_nonce = NULL, approval_seal = NULL, approved_at = NULL
           WHERE report_id = ? AND host = ? AND state = ?`,
    args: [ref, injectJson, report.id, value, existing.state],
  });
  if (Number(written?.rowsAffected ?? 0) !== 1) throw fail("credential_changed");
  return {
    ...credentialView(await credentialRow(db, report.id, value), false),
    proposedBy: by,
    previousConnectionUuid: text(existing.connection_uuid) || null,
  };
}

/**
 * The owner's approval of one credential binding: a fresh nonce and a seal over (report, the keychain
 * reference, the host, the digest of the rule the row holds now, the nonce).
 *
 * The decision is about a row the owner SAW, so `connectionUuid` and `injectHash` are the reference and
 * the rule digest that view carried. A row whose stored reference or rule digest is another one, or a
 * row whose rule no longer parses, is never approved with this tap: the first answers
 * `credential_changed` and the second `bad_inject`. An already-approved binding whose seal still verifies
 * is answered as it is, so a repeated tap is not a second approval.
 *
 * The write is guarded by the report, the host, the reference, the state this read saw and the exact
 * `inject_json` text the digest was taken from, so a rule or a reference written between this read and
 * the write changes no row and answers `credential_changed` too.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, host: string, connectionUuid: string, injectHash: string,
 *   actor: {kind: "owner"}}} input
 * @returns {Promise<object>} the credential row as a page reads it
 * @throws {Error} `owner_only`, `bad_input`, `bad_inject`, `not_found`, `keychain_key_missing`,
 *   `credential_changed`
 */
export async function approveCredential(db, deps, {
  reportId, host, connectionUuid, injectHash, actor,
} = {}) {
  approvalInternals.requireOwner(actor);
  const d = resolveDeps(deps);
  await approvalInternals.requireReport(db, reportId);
  const value = normalizeExactHost(host);
  const expectedRef = normalizeConnectionRef(connectionUuid);
  const expectedHash = normalizeInjectHash(injectHash);
  const row = await credentialRow(db, reportId, value);
  if (!row) throw fail("not_found", "credential");
  const injectJson = text(row.inject_json);
  const inject = decodeInject(injectJson);
  if (!inject) throw fail("bad_inject", "inject_json");
  const sealedHash = injectHashOf(inject);
  // The row the owner was shown has to be the row that is there NOW: another keychain reference or
  // another rule is a decision about a binding that has moved.
  if (text(row.connection_uuid) !== expectedRef || sealedHash !== expectedHash) {
    throw fail("credential_changed");
  }
  if (row.state === "approved" && (await verifyCredential(db, d, row))) {
    return credentialView(row, true);
  }
  const seed = await approvalInternals.seedOf(d);
  const nonce = newApprovalNonce();
  const seal = approvalSeal(
    "credential",
    { reportId, credentialRef: expectedRef, host: value, injectHash: sealedHash, nonce },
    seed,
  );
  const at = d.now();
  const written = await db.execute({
    sql: `UPDATE report_credentials
             SET state = 'approved', approval_nonce = ?, approval_seal = ?, approved_at = ?
           WHERE report_id = ? AND host = ? AND connection_uuid = ? AND inject_json = ? AND state = ?`,
    args: [nonce, seal, at, reportId, value, expectedRef, injectJson, row.state],
  });
  if (Number(written?.rowsAffected ?? 0) !== 1) throw fail("credential_changed");
  await recordAudit(db, {
    reportId,
    kind: "credential",
    subject: value,
    actor: "owner",
    decided: "approved",
    at,
  });
  return credentialView(await credentialRow(db, reportId, value), true);
}

/**
 * Revoke one credential binding: the state in one word, both the seal and its nonce NULLED, and, unless
 * `skipDisconnect` is set, the keychain row it named marked as no longer served (the keychain's own
 * disconnect helper), so a revoked binding leaves nothing a reader could still open. Only a keychain row
 * that really is this bundle's `REPORT_CREDENTIAL` row is marked (`disconnectKeychainRow`), so a binding
 * a direct UPDATE pointed at another bundle's connection leaves that connection alone. A keychain
 * failure never undoes the revocation.
 *
 * `skipDisconnect` (default false) is for a caller that knows the named keychain row is not this report's
 * to touch, which is the delete path's `not_a_reports_credential` case: the binding is revoked and the
 * connection somebody else owns is left exactly as it is.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, host: string, actor: {kind: "owner"}, skipDisconnect?: boolean}} input
 * @returns {Promise<object>} the credential row as a page reads it
 * @throws {Error} `owner_only`, `bad_input`, `not_found`, `credential_changed`
 */
export async function revokeCredential(db, deps, { reportId, host, actor, skipDisconnect = false } = {}) {
  approvalInternals.requireOwner(actor);
  const d = resolveDeps(deps);
  await approvalInternals.requireReport(db, reportId);
  const value = normalizeExactHost(host);
  const row = await credentialRow(db, reportId, value);
  if (!row) throw fail("not_found", "credential");
  const at = d.now();
  const written = await db.execute({
    sql: `UPDATE report_credentials
             SET state = 'revoked', approval_nonce = NULL, approval_seal = NULL, approved_at = NULL
           WHERE report_id = ? AND host = ? AND state = ?`,
    args: [reportId, value, row.state],
  });
  if (Number(written?.rowsAffected ?? 0) !== 1) throw fail("credential_changed");
  if (skipDisconnect !== true) await disconnectKeychainRow(db, text(row.connection_uuid));
  await recordAudit(db, {
    reportId,
    kind: "credential",
    subject: value,
    actor: "owner",
    decided: "revoked",
    at,
  });
  return credentialView(await credentialRow(db, reportId, value), false);
}

/**
 * Retire a credential's keychain row from serving, never failing the caller over it.
 *
 * ONLY this bundle's own report-credential row is disconnected: the keychain row must be a `service` row
 * whose bundle id is `crow-reports` and whose env key is `REPORT_CREDENTIAL`. That check lives HERE so
 * every caller gets it (the owner's revoke route, the report delete path, and whatever comes later): a
 * row a direct UPDATE pointed at another bundle's connection is somebody else's secret, and marking it
 * disconnected would take that bundle's credential away on a reports decision. The read is metadata
 * only and never opens a value.
 */
async function disconnectKeychainRow(db, connectionUuid) {
  if (typeof connectionUuid !== "string" || !connectionUuid) return;
  let ours = false;
  try {
    await ensureKeychainTable(db);
    const { rows } = await db.execute({
      sql: `SELECT 1 AS ours FROM crow_keychain
             WHERE kind = 'service' AND connection_uuid = ? AND bundle_id = ? AND env_key = ?`,
      args: [connectionUuid, REPORTS_BUNDLE, REPORT_CREDENTIAL_ENV_KEY],
    });
    ours = rows.length > 0;
  } catch {
    // A keychain that cannot be read is not a row this revoke may mark: leave it alone.
    return;
  }
  if (!ours) return;
  try {
    await disconnectServiceSecrets(db, connectionUuid);
  } catch {
    // The binding is already revoked; a keychain that cannot be marked is still never read for it.
  }
}

/**
 * One report's credential bindings, each with whether its approval still verifies. The secret is never
 * in the answer, and neither is the seal or its nonce: a credential row names a keychain row and the
 * rule, nothing more.
 *
 * @param {object} db
 * @param {string} reportId
 * @param {object} [deps]
 * @returns {Promise<object[]>}
 */
export async function listCredentials(db, reportId, deps) {
  if (typeof reportId !== "string" || !reportId) throw fail("bad_input", "reportId");
  const d = resolveDeps(deps);
  const out = [];
  for (const row of await credentialRowsOfReport(db, reportId)) {
    out.push(credentialView(row, await verifyCredential(db, d, row)));
  }
  return out;
}

/**
 * Is this credential binding usable right now? The state, its seal, and an approved and verified host
 * of the report that covers it. Every reader here stands on this one function, so a revoked host or a
 * broken seal stops the credential even when its own row was never touched.
 */
async function credentialUsable(db, d, row) {
  try {
    if (row == null || row.state !== "approved") return false;
    if (!(await verifyCredential(db, d, row))) return false;
    const value = normalizeExactHost(text(row.host));
    for (const host of await hostRowsOfReport(db, text(row.report_id))) {
      if (host.state !== "approved") continue;
      if (!hostAllowed(value, [host.host])) continue;
      if (await verifyHost(db, d, host)) return true;
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * The secret a credential binding stands for, as the sync function the egress relay calls.
 *
 * Nothing is read here except the keychain: the value comes from
 * `serviceSecretsFor(db, key, connectionUuid, {allowedKeys: ["REPORT_CREDENTIAL"]})`, never from a
 * reports table. The returned function answers the last completed read and starts a fresh one on every
 * call, so the plaintext never lives outside this closure and a revocation or a tampered row stops it
 * within one refresh; `secret.refresh()` awaits a fresh read for a caller that wants the answer now.
 *
 * Every read re-fetches the binding row for (report, host) and requires it to still name the keychain
 * row this closure was built on, before the state, the seal and the rule digest are re-checked on that
 * fresh row. A row that is gone, a revocation, a rotation to another keychain row and a replacement
 * therefore all answer "", including on a closure a run built before the change, and a closure built
 * before a replacement never serves the new row's secret.
 * `() => ""` is returned when anything is off: no such binding, a revoked or unverifiable row, a host
 * that is no longer approved, a missing keychain key, or a row that no longer opens.
 *
 * @param {object} db
 * @param {object} [deps]
 * @param {{reportId: string, host: string}} input
 * @returns {Promise<(() => string) & {refresh: () => Promise<string>}>}
 */
export async function credentialSecretFor(db, deps, { reportId, host } = {}) {
  const d = resolveDeps(deps);
  const empty = () => "";
  empty.refresh = async () => "";
  let row = null;
  try {
    row = await credentialRow(db, reportId, host);
  } catch {
    return empty;
  }
  if (!row || !(await credentialUsable(db, d, row))) return empty;
  const connectionUuid = text(row.connection_uuid);
  const hostValue = text(row.host);

  /** The binding row as it is NOW, or null when it moved away from the one this closure was built on. */
  const liveRow = async () => {
    const fresh = await credentialRow(db, reportId, hostValue);
    if (!fresh) return null;
    if (text(fresh.connection_uuid) !== connectionUuid) return null;
    return (await credentialUsable(db, d, fresh)) ? fresh : null;
  };

  const read = async () => {
    try {
      if (!(await liveRow())) return "";
      const key = await d.loadKeychainKey();
      if (!key || typeof key.id !== "string" || !Buffer.isBuffer(key.seed)) return "";
      const found = await serviceSecretsFor(db, key, connectionUuid, {
        allowedKeys: [REPORT_CREDENTIAL_ENV_KEY],
      });
      const value = found[REPORT_CREDENTIAL_ENV_KEY];
      return typeof value === "string" ? value : "";
    } catch {
      return "";
    }
  };
  let current = await read();
  let inFlight = null;
  const secret = () => {
    if (inFlight == null) {
      inFlight = read()
        .then((value) => {
          current = value;
        })
        .catch(() => {
          current = "";
        })
        .finally(() => {
          inFlight = null;
        });
    }
    return current;
  };
  secret.refresh = async () => {
    current = await read();
    return current;
  };
  return secret;
}

/**
 * The inject rules the egress relay is handed for one report: one per APPROVED and VERIFIED credential
 * whose host is still approved and verified, in the relay's own shape
 * (`{host, header|query, format, pathPrefixes, methods, secret}`). The `secret` is a function that reads
 * the keychain at call time; no rule ever carries a value.
 *
 * A rule for a query parameter carries no `format` (the relay refuses one there), and a host a rule
 * names must also be in the relay's own egress list: this list says what the owner approved, the relay's
 * list says what the run may reach, and both must allow it.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string}} input
 * @returns {Promise<Array<object>>}
 */
export async function injectRulesFor(db, deps, { reportId } = {}) {
  if (typeof reportId !== "string" || !reportId) throw fail("bad_input", "reportId");
  const d = resolveDeps(deps);
  const rules = [];
  for (const row of await credentialRowsOfReport(db, reportId)) {
    if (!(await credentialUsable(db, d, row))) continue;
    const inject = decodeInject(row.inject_json);
    if (!inject) continue;
    const secret = await credentialSecretFor(db, d, { reportId, host: row.host });
    const rule = {
      host: text(row.host),
      pathPrefixes: [...inject.pathPrefixes],
      methods: [...inject.methods],
      secret,
    };
    if (inject.header) {
      rule.header = inject.header;
      rule.format = inject.format;
    } else {
      rule.query = inject.query;
    }
    rules.push(rule);
  }
  return rules;
}

/* ------------------------------------------------------- the credential card's label */

/** A report id as `reports/store.js` mints it. */
const SPEC_REPORT_RE = /^rpt-[0-9a-f]{16}$/;
/** The keys a credential request's label may hold, and the longest one this grammar reads. */
const SPEC_KEYS = Object.freeze(["report", "host", "header", "query", "format", "paths", "methods"]);
const SPEC_LABEL_MAX = 240;
/** The token a spec ends with, so a label that was cut short never reads as a complete binding. */
const SPEC_END = "end";
const SPEC_END_SUFFIX = `;${SPEC_END}`;

/**
 * The label a bot hands to `crow_request_secret` for one credential binding: the grammar
 * `parseCredentialSpec` reads, in the order `SPEC_KEYS` names, or null when the assembled label is not
 * one that grammar reads.
 *
 * The label is built from the caller's values and then READ BACK through `parseCredentialSpec`, so this
 * function can only ever answer a label that names exactly the binding it was given: a value holding a
 * `;` or an `=`, two targets, a missing path list, a bad host, a control character and a label past the
 * grammar's bound all answer null rather than a shorter or a different binding. No secret is involved:
 * the label names a keychain row to be filled in, never a value.
 *
 * @param {{reportId: string, host: string, header?: string|null, query?: string|null,
 *   format?: string|null, paths: string[], methods?: string[]|null}} spec
 * @returns {string|null}
 */
export function credentialSpecLabel({ reportId, host, header, query, format, paths, methods } = {}) {
  if (typeof reportId !== "string" || !reportId) return null;
  if (typeof host !== "string" || !host) return null;
  for (const value of [header, query, format]) {
    if (value === undefined || value === null) continue;
    if (typeof value !== "string" || !value) return null;
  }
  if (!Array.isArray(paths) || paths.length === 0) return null;
  for (const path of paths) {
    if (typeof path !== "string" || !path) return null;
  }
  if (methods !== undefined && methods !== null) {
    if (!Array.isArray(methods) || methods.length === 0) return null;
    for (const method of methods) {
      if (typeof method !== "string" || !method) return null;
    }
  }
  const values = new Map([
    ["report", reportId],
    ["host", host],
    ["header", header],
    ["query", query],
    ["format", format],
    ["paths", paths.join(",")],
    ["methods", Array.isArray(methods) ? methods.join(",") : null],
  ]);
  const parts = [];
  for (const key of SPEC_KEYS) {
    const value = values.get(key);
    if (value === undefined || value === null || value === "") continue;
    parts.push(`${key}=${value}`);
  }
  const label = `${parts.join(";")}${SPEC_END_SUFFIX}`;
  return parseCredentialSpec(label) === null ? null : label;
}

/**
 * A credential request's `label` as the binding it asks for, or null.
 *
 * The secret card carries no report fields, so the bot spells the binding in its own label with one
 * strict grammar:
 *
 *   report=<rpt-id>;host=<host>;header=<Name>[;format=<text with {}>];paths=<p1,p2>[;methods=GET,HEAD];end
 *   report=<rpt-id>;host=<host>;query=<name>;paths=<p1,p2>[;methods=GET,HEAD];end
 *
 * Every key appears at most once, no other key is read, `report`, `host` and `paths` are required,
 * exactly one of `header` or `query` is required, `format` belongs to a header only, and the assembled
 * rule must pass the same validation the egress relay applies to its `inject` option (so a rule with no
 * path prefixes, a framing header, a bad format or an unknown method is refused here too). The label
 * ends with the bare token `;end`, which carries no value and is the only part that holds no `=`: a
 * label whose tail was cut off therefore reads as no binding at all rather than as a shorter one.
 * Anything else, including a stray `;` inside a value, an extra key, a value that is not lower-case for
 * the host, any control character and a missing `;end`, is `null`: the request never reaches the card.
 *
 * The card's own label cap for this target (request-store.js's `REPORT_CREDENTIAL_LABEL_MAX`, the tool
 * schema's 400) is longer than this grammar's bound, so a label that cap had to cut is 400 characters
 * long and this bound refuses it outright: an over-long spec is refused when the bot asks, never
 * truncated into a different binding.
 *
 * @param {string} label the cleaned label a secret request carries
 * @returns {{reportId: string, host: string, inject: object}|null}
 */
export function parseCredentialSpec(label) {
  if (typeof label !== "string" || !label || label.length > SPEC_LABEL_MAX) return null;
  if (CONTROL_CHARS.test(label)) return null;
  if (label !== label.trim()) return null;
  if (!label.endsWith(SPEC_END_SUFFIX)) return null;
  const parts = label.slice(0, -SPEC_END_SUFFIX.length).split(";");
  if (parts.length < 4) return null;
  const seen = new Map();
  for (const part of parts) {
    const at = part.indexOf("=");
    if (at <= 0) return null;
    const key = part.slice(0, at);
    const value = part.slice(at + 1);
    if (!SPEC_KEYS.includes(key)) return null;
    if (seen.has(key)) return null;
    if (!value) return null;
    seen.set(key, value);
  }
  const reportId = seen.get("report");
  if (!reportId || !SPEC_REPORT_RE.test(reportId)) return null;
  let host;
  try {
    host = normalizeExactHost(seen.get("host") ?? "");
  } catch {
    return null;
  }
  const paths = seen.get("paths");
  if (!paths) return null;
  const hasHeader = seen.has("header");
  const hasQuery = seen.has("query");
  if (hasHeader === hasQuery) return null;
  const inject = { pathPrefixes: paths.split(",") };
  if (hasHeader) inject.header = seen.get("header");
  else inject.query = seen.get("query");
  if (seen.has("format")) inject.format = seen.get("format");
  if (seen.has("methods")) inject.methods = seen.get("methods").split(",");
  let rule;
  try {
    rule = normalizeInject(inject);
  } catch {
    return null;
  }
  return { reportId, host, inject: rule };
}