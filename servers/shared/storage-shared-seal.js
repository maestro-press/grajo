/**
 * storage-shared-seal — the ONE opener for the two identity-sealed Shared Storage settings,
 * `storage.shared.access_key` and `storage.shared.secret_key`.
 *
 * Those two values are the only identity-seed-sealed settings that SYNC (sync-allowlist
 * `storage.shared.*`), so a sibling instance opens them with its own copy of the shared seed.
 * An original `enc:v1:` blob carries no AAD, which means it opens under ANY setting name: a
 * bot with crow.db write access could copy the secret blob into `access_key` and SigV4 would
 * then send the secret, as the key id, in clear to the endpoint. Re-pointing the endpoint (or
 * flipping `use_ssl`) has the same effect without any copy at all.
 *
 * THE BOUND FORM (`enc:v2:`) closes both: the AAD names the setting key, the NORMALIZED
 * endpoint and the SSL flag, so a blob opens only for the setting and the address it was
 * sealed for. No instance id goes in it, on purpose: a paired instance must open a blob its
 * sibling sealed.
 *
 *   storageSharedAad(key, endpoint, useSSL)
 *     = JSON.stringify(["crow-storage-shared-v2", key, normalizeStorageEndpoint(endpoint), useSSL === true])
 *
 * (Same style as the keychain's `rowAad` in servers/gateway/keychain/store.js: a JSON array
 * whose first element is a version tag.)
 *
 * RELEASE 1 IS READER-FIRST. Nothing here WRITES a value — the settings form still seals v1 —
 * and this module only decides what a reader may accept:
 *
 *   enc:v2: …        opened with the AAD above. A bad endpoint, a wrong key name, a changed
 *                    endpoint/SSL flag or a wrong identity all fail the tag check, and the
 *                    refusal is classified `storage_credentials_unbound`.
 *   enc:v1: …        still accepted BEFORE the era (a mixed fleet's peer keeps writing v1 until release 2's
 *                    fleet gate passes), opened exactly as before.
 *   any other enc: … REFUSED as `unknown_envelope`. This is new and deliberate: an older
 *                    reader takes such a value as PLAINTEXT and hands the literal string
 *                    `enc:v2:…` to the storage client as a credential.
 *   anything else    plaintext, still accepted in release 1.
 *
 * An OPENED plaintext that is itself an envelope (a sealed value sealed twice, or a blob moved
 * between settings) is `nested_envelope`: no reader may hand that to the storage client as a
 * credential, and the refusal lives HERE so every reader (s3-client's async and sync paths, the
 * settings section's keep-the-stored-key path) inherits it.
 *
 * ENDPOINT EQUALITY: the AAD names the NORMALIZED endpoint (`host:port`), so a bound value opens
 * only for the address it was sealed for. The reader must therefore DIAL that same address —
 * `splitNormalizedEndpoint` is how it derives host and port from the AAD's spelling, instead of
 * parsing the raw setting a second, laxer way (a scheme strip one spelling accepted and the
 * other did not would let the AAD name one host while the client dialled another).
 *
 * A refusal is classified, never thrown: the caller owns the era rule (a v2-only era comes in
 * release 2). Every refusal logs ONE line naming the reason code and the setting key — never
 * the value, the endpoint, the plaintext or an error message.
 */
import { isCanonicalSealed, isSealed, openSecret, openSecretBound } from "../sharing/secret-box.js";

/** The two setting names this module owns. The order is incidental (the AAD names one). */
export const STORAGE_SHARED_CREDENTIAL_KEYS = Object.freeze([
  "storage.shared.access_key",
  "storage.shared.secret_key",
]);

/** The AAD's version tag: bump it (not the prefix) when the bound context changes. */
const AAD_TAG = "crow-storage-shared-v2";
const PREFIX_V1 = "enc:v1:";
const PREFIX_V2 = "enc:v2:";
/** The port the storage reader assumes when an endpoint names none (servers/storage/s3-client.js). */
const DEFAULT_PORT = 9000;

/**
 * The endpoint as the AAD names it: `host:port`.
 *
 * It must match what the storage READER actually dials, so this normalizes exactly one way —
 * strip an optional `http://`/`https://` scheme, strip ONE trailing `/`, lower-case the host,
 * and always spell the port (9000 when absent) — and REFUSES everything it cannot normalize
 * unambiguously: userinfo, a path beyond the trailing slash, a query or fragment, an empty or
 * whitespace-bearing host, a non-numeric or out-of-range port, and an IPv6 literal (refused
 * rather than guessed at, because bracket/port spellings differ).
 *
 * @param {unknown} endpoint
 * @returns {string} `host:port`
 * @throws {Error} a fixed, value-free message when the endpoint cannot be normalized
 */
export function normalizeStorageEndpoint(endpoint) {
  if (typeof endpoint !== "string") throw new Error("storage-shared-seal: endpoint must be a string");
  let s = endpoint.trim();
  if (s === "") throw new Error("storage-shared-seal: empty endpoint");
  s = s.replace(/^https?:\/\//i, "");
  if (s.includes("@")) throw new Error("storage-shared-seal: endpoint has userinfo");
  if (s.includes("?")) throw new Error("storage-shared-seal: endpoint has a query");
  if (s.includes("#")) throw new Error("storage-shared-seal: endpoint has a fragment");
  if (s.endsWith("/")) s = s.slice(0, -1);
  if (s.includes("/")) throw new Error("storage-shared-seal: endpoint has a path");
  if (s.startsWith("[")) throw new Error("storage-shared-seal: IPv6 endpoint literals are refused");
  const colon = s.lastIndexOf(":");
  let host = colon === -1 ? s : s.slice(0, colon);
  let port = colon === -1 ? DEFAULT_PORT : s.slice(colon + 1);
  if (host.includes(":")) throw new Error("storage-shared-seal: IPv6 endpoint literals are refused");
  host = host.toLowerCase();
  if (host === "" || /\s/.test(host)) throw new Error("storage-shared-seal: bad endpoint host");
  if (!/^\d+$/.test(port)) throw new Error("storage-shared-seal: bad endpoint port");
  const n = Number(port);
  if (!Number.isInteger(n) || n < 1 || n > 65535) throw new Error("storage-shared-seal: bad endpoint port");
  return `${host}:${n}`;
}

/**
 * Host and port of a NORMALIZED endpoint (`host:port`, as normalizeStorageEndpoint spells it).
 *
 * This is the reader's side of the AAD's promise: the address the AAD names is the address the
 * client dials. It re-runs the same normalization, so a caller can hand it either the stored
 * setting or an already-normalized string and get one answer.
 *
 * @param {unknown} normalized a `host:port` endpoint (any spelling normalizeStorageEndpoint accepts)
 * @returns {{host: string, port: number}}
 * @throws {Error} exactly when normalizeStorageEndpoint would
 */
export function splitNormalizedEndpoint(normalized) {
  const value = normalizeStorageEndpoint(normalized);
  const colon = value.lastIndexOf(":");
  return { host: value.slice(0, colon), port: Number(value.slice(colon + 1)) };
}

/**
 * The stored `use_ssl` value as the storage reader reads it: `"true"` or `"1"` are on, anything
 * else (including a missing row) is off. ONE parser for every reader, so the AAD, the client and
 * the settings display cannot disagree about which flag a row means.
 *
 * @param {unknown} value the raw setting value
 * @returns {boolean}
 */
export function parseStorageUseSSL(value) {
  return value === "true" || value === "1";
}

/**
 * The AAD one of these two settings is sealed under. `useSSL` is a boolean here; callers
 * convert the stored `"true"`/`"1"` string with parseStorageUseSSL.
 *
 * @param {string} settingKey one of STORAGE_SHARED_CREDENTIAL_KEYS
 * @param {string} endpoint
 * @param {boolean} useSSL
 * @returns {string}
 * @throws {Error} for a key name this module does not own, or an endpoint it cannot normalize
 */
export function storageSharedAad(settingKey, endpoint, useSSL) {
  if (!STORAGE_SHARED_CREDENTIAL_KEYS.includes(settingKey)) {
    throw new Error("storage-shared-seal: not a shared storage credential key");
  }
  return JSON.stringify([AAD_TAG, settingKey, normalizeStorageEndpoint(endpoint), useSSL === true]);
}

/**
 * Open a stored Shared Storage credential, classifying everything it may be.
 *
 * Never throws: a refusal is `{ok: false, reason}` with one of
 *   "storage_credentials_unbound" — a v2 blob that does not open for THIS key name, endpoint
 *                                   and SSL flag (a swap, a re-pointed endpoint, a wrong
 *                                   identity, or an endpoint that cannot be normalized);
 *   "unopenable"                  — a v1 blob that does not open (wrong identity, tampering);
 *   "noncanonical"                — a sealed body that is not the exact form this release
 *                                   writes (trailing whitespace, stripped padding);
 *   "unknown_envelope"            — any other `enc:` prefix, and a non-string/empty value;
 *   "nested_envelope"             — a value that OPENS to another envelope: never a credential;
 *   "storage_credentials_pre_era" — release 2: THIS instance's era is on (`era: true`), and the
 *                                   value is an `enc:v1:` blob or plaintext. Nothing here writes
 *                                   either after the conversion, so it can only be a bot's. The
 *                                   caller owns the era verdict (storage-shared-era.js); this
 *                                   function never reads it, so it stays pure.
 *
 * @param {unknown} value the stored row value
 * @param {{settingKey: string, endpoint: string, useSSL: boolean, identity: object, era?: boolean}} ctx
 * @returns {{ok: true, plaintext: string, version: "v1"|"v2"|"plain"} | {ok: false, reason: string}}
 */
export function openStorageSharedValue(value, { settingKey, endpoint, useSSL, identity, era = false } = {}) {
  const refuse = (reason) => {
    // Reason code and setting key ONLY: never the value, the endpoint, the plaintext or an
    // error message (an error can quote a decoded nonce or a base64 body).
    console.warn("[storage] shared credential refused:", reason, settingKey);
    return { ok: false, reason };
  };

  if (typeof value !== "string" || value === "") return refuse("unknown_envelope");

  if (value.startsWith(PREFIX_V2)) {
    if (!isCanonicalSealed(value)) return refuse("noncanonical");
    let plaintext;
    try {
      plaintext = openSecretBound(value, identity, storageSharedAad(settingKey, endpoint, useSSL));
    } catch {
      return refuse("storage_credentials_unbound");
    }
    if (plaintext === null) return refuse("storage_credentials_unbound");
    if (isNestedEnvelope(plaintext)) return refuse("nested_envelope");
    return { ok: true, plaintext, version: "v2" };
  }

  if (value.startsWith(PREFIX_V1)) {
    if (era === true) return refuse("storage_credentials_pre_era");
    if (!isCanonicalSealed(value)) return refuse("noncanonical");
    let plaintext;
    try {
      plaintext = openSecret(value, identity);
    } catch {
      return refuse("unopenable");
    }
    if (plaintext === null) return refuse("unopenable");
    if (isNestedEnvelope(plaintext)) return refuse("nested_envelope");
    return { ok: true, plaintext, version: "v1" };
  }

  // Any other envelope spelling is NOT plaintext: an old reader would have used the literal
  // string as a credential.
  if (value.slice(0, 4).toLowerCase() === "enc:") return refuse("unknown_envelope");

  // Plaintext: accepted before the era, refused after it.
  if (era === true) return refuse("storage_credentials_pre_era");
  return { ok: true, plaintext: value, version: "plain" };
}

/**
 * Is an OPENED plaintext itself an envelope? A sealed value sealed twice, or a blob carried from
 * one setting to another, is never a credential: it would reach the endpoint as a key id.
 * `isSealed` covers the two canonical prefixes; the case-insensitive check also catches an
 * `ENC:` spelling, which an older reader would likewise have used as a literal credential.
 */
function isNestedEnvelope(plaintext) {
  return typeof plaintext === "string"
    && (isSealed(plaintext) || plaintext.slice(0, 4).toLowerCase() === "enc:");
}