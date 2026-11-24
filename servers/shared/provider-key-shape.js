/**
 * The SHAPE of a stored provider API key — the one place that decides what a
 * `providers.api_key` cell holds (design §1.1, §2.1), for readers on both sides
 * of the seal boundary.
 *
 * Three shapes exist and nothing else:
 *
 *   none       NULL, "" or exactly "none" (the sentinel a keyless provider row
 *              has always used — memory/rerank/embeddings treat it as "no key")
 *   plain      a key the owner typed, stored as typed (the pre-seal shape)
 *   envelope   `pk1:<keyId16 hex>:<fp16 hex>:<base64url>` — the sealed form
 *
 * Anything that STARTS with `pk1:` and does not match the envelope grammar is
 * `malformed`, never `plain`: a truncated or corrupted envelope must never be
 * handed to an HTTP client as if it were the key. Malformed values are counted
 * and reported, never rewritten, and never opened.
 *
 * `fp16` is the first 16 hex of sha256 over the TRIMMED plaintext, so the same
 * key written with trailing whitespace keeps one identity. The envelope covers
 * the RAW bytes (see servers/gateway/keychain/provider-key-box.js); the
 * fingerprint is deliberately computed over the trimmed form so a reader can
 * decide "is this the same key the owner typed" without opening the seal.
 *
 * Pure by design: the only import is `node:crypto` (a builtin, safe inside a
 * bot child), for the sha256 the fingerprint needs. Nothing here reads a file,
 * the environment or the database, and nothing here ever logs a value.
 */
import { createHash, createHmac } from "node:crypto";

/** The envelope prefix, and the version it names. */
export const KEY_ENVELOPE_PREFIX = "pk1:";

/** `<prefix><keyId16>:<fp16>:<base64url>` — exactly, anchored at both ends. */
export const PROVIDER_KEY_ENVELOPE_RE = /^pk1:([0-9a-f]{16}):([0-9a-f]{16}):([A-Za-z0-9_-]+)$/;

/**
 * The shapes parseStoredKey can return. `none` is the empty sentinel, `plain` an
 * unsealed value, `envelope` a well-formed sealed value, `malformed` a value
 * that claims to be sealed and is not.
 */
export const KEY_SHAPES = Object.freeze(["none", "plain", "envelope", "malformed"]);

/**
 * Classify a stored `providers.api_key` cell WITHOUT returning the value.
 *
 * @param {unknown} stored
 * @returns {{kind: "none"} |
 *           {kind: "plain"} |
 *           {kind: "malformed"} |
 *           {kind: "envelope", keyId: string, fp: string, payload: string}}
 */
export function parseStoredKey(stored) {
  if (stored == null) return { kind: "none" };
  if (typeof stored !== "string") return { kind: "malformed" };
  if (stored === "" || stored === "none") return { kind: "none" };
  const m = PROVIDER_KEY_ENVELOPE_RE.exec(stored);
  if (m) return { kind: "envelope", keyId: m[1], fp: m[2], payload: m[3] };
  if (stored.startsWith(KEY_ENVELOPE_PREFIX)) return { kind: "malformed" };
  return { kind: "plain" };
}

/** True when a well-formed sealed envelope is stored. */
export function isProviderKeyEnvelope(stored) {
  return parseStoredKey(stored).kind === "envelope";
}

/**
 * Does this cell hold a key at all? False only for the `none` sentinel — a
 * malformed envelope still means "something is stored here", and calling it
 * "no key" would let a reader fall through to an unauthenticated request.
 */
export function hasProviderKey(stored) {
  return parseStoredKey(stored).kind !== "none";
}

/**
 * First 16 hex of sha256 over the TRIMMED plaintext — the `fp16` an envelope
 * carries, so a saved key keeps one identity across whitespace and re-saves.
 *
 * Null when there is no key to fingerprint: a non-string, or a value that
 * trims to "" or to the `none` sentinel.
 *
 * @param {unknown} plaintext
 * @returns {string|null}
 */
export function providerKeyFp(plaintext) {
  if (typeof plaintext !== "string") return null;
  const trimmed = plaintext.trim();
  if (trimmed === "" || trimmed === "none") return null;
  return createHash("sha256").update(trimmed, "utf8").digest("hex").slice(0, 16);
}

/**
 * The tag that keeps the sealed-key consent fingerprint from ever colliding with
 * the legacy one (HMAC over the plaintext key itself).
 */
export const CONSENT_FP_PREFIX = "fp1:";

/**
 * The per-box consent fingerprint for a SEALED key: `HMAC-SHA256(salt,
 * "fp1:" + fp16)` hex, first 16 (design §3.1).
 *
 * It lives HERE, in a pure module, rather than beside the seal pass in the
 * gateway's keychain, because every reader of the cloud-door consent map needs
 * it — including the bot bridge, which must never reach the keychain, the key
 * file or the crypto box. A reader holding a stored envelope can compute it
 * without the plaintext (the envelope carries `fp16`), and a reader holding the
 * opened plaintext computes the same value, which is why `checkStamp` and the
 * consent entry agree on one identity for one key.
 *
 * @param {string} salt 64 hex
 * @param {string} fp16 the first 16 hex of sha256 over the trimmed plaintext
 * @returns {string}
 */
export function sealedConsentFingerprint(salt, fp16) {
  return createHmac("sha256", Buffer.from(String(salt), "hex"))
    .update(CONSENT_FP_PREFIX + String(fp16))
    .digest("hex")
    .slice(0, 16);
}