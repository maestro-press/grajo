/**
 * secret-box — symmetric encryption for config secrets stored in dashboard_settings.
 *
 * Purpose: sync feeds are signed but not encrypted on disk (feed files live at
 * ~/.crow/data/instance-sync/<peer>/ as plaintext JSON). Replicating credentials
 * (MinIO root password, etc.) via sync-allowlist would leave plaintext on every
 * paired host. secret-box seals sensitive values before they're written so the
 * ciphertext is safe to replicate; only hosts with the same Crow identity seed
 * can decrypt.
 *
 * KDF matches servers/sharing/identity.js:49-51 (hkdf-sha256 over the master seed).
 * Cipher: AES-256-GCM via node:crypto.
 *
 * TWO WIRE FORMATS, one key:
 *
 *   "enc:v1:" + base64(nonce(12) || ciphertext || tag(16))              — no AAD
 *   "enc:v2:" + base64(nonce(12) || ciphertext || tag(16))              — AAD bound
 *
 * v1 is the original form (Shared Storage settings and scripts/ops/verify-secret-box.mjs
 * still use it). v2 is BOUND: `cipher.setAAD(aad)` under the SAME HKDF key (info
 * "crow-secret-box-v1" unchanged, so the two eras share a key), which makes a sealed value
 * open only for the one context its AAD names — the keychain uses it to bind a blob to the
 * row it belongs to, so a blob copied into another row fails its tag check instead of
 * yielding that row's plaintext (servers/gateway/keychain/store.js `rowAad`).
 *
 * The two openers are deliberately NOT interchangeable: `openSecret` (v1) THROWS on an
 * `enc:v2:` value and `openSecretBound` THROWS on an `enc:v1:` one, so no caller can
 * silently open today's blob as yesterday's (the caller owns the era rule: a v1 value is
 * accepted only before the keychain's conversion era). `isSealed` is true for both.
 *
 * THE EXACT FORM. The two prefixes above are what this release writes, and its body is
 * canonical base64 (`sealedBodyBytes`). Because the decoder ignores whitespace and padding, a
 * blob re-spelled as `"<value>\n"` or with its `=` pad stripped is a DIFFERENT string that
 * opens to the same plaintext — the reason the keychain's duplicate screen keys on the decoded
 * nonce (`sealedNonceHex`) and refuses any value that is not canonical (`isCanonicalSealed`).
 */
import { createCipheriv, createDecipheriv, randomBytes } from "node:crypto";
import { hkdf } from "@noble/hashes/hkdf";
import { sha256 } from "@noble/hashes/sha256";

const PREFIX = "enc:v1:";
const PREFIX_V2 = "enc:v2:";
const INFO = "crow-secret-box-v1";
const NONCE_LEN = 12;
const TAG_LEN = 16;

function deriveKey(identity) {
  if (!identity?.seed) {
    throw new Error("secret-box: identity.seed missing — cannot derive key");
  }
  const seed = Buffer.isBuffer(identity.seed) ? identity.seed : Buffer.from(identity.seed);
  return Buffer.from(hkdf(sha256, seed, undefined, INFO, 32));
}

export function isSealed(value) {
  return typeof value === "string" && (value.startsWith(PREFIX) || value.startsWith(PREFIX_V2));
}

/** The original, unbound form. */
export function isSealedV1(value) {
  return typeof value === "string" && value.startsWith(PREFIX);
}

/** The AAD-bound form. */
export function isSealedV2(value) {
  return typeof value === "string" && value.startsWith(PREFIX_V2);
}

/**
 * The bytes a sealed value's body decodes to, judged EXACTLY: the body must re-encode to
 * itself. Node's base64 decoder ignores whitespace and a missing `=` pad, so
 * `"enc:v1:<body>\n"`, `"enc:v1: <body>"` and a padding-stripped body all decode to the SAME
 * bytes and open to the same plaintext while being different strings. A body that does not
 * round-trip is therefore not a form this release wrote, and every caller that classifies a
 * blob refuses it (`servers/gateway/boot/keychain-aad.js` for a candidate, `keychain/store.js`
 * for a value it is about to open). Null for a body that is not canonical and for a value that
 * is not sealed at all. Never throws, never returns a plaintext.
 */
export function sealedBodyBytes(value) {
  if (!isSealed(value)) return null;
  const prefix = value.startsWith(PREFIX_V2) ? PREFIX_V2 : PREFIX;
  const body = value.slice(prefix.length);
  if (body === "") return null;
  const bytes = Buffer.from(body, "base64");
  if (bytes.length === 0) return null;
  if (bytes.toString("base64") !== body) return null;
  return bytes;
}

/** Is this a sealed value in EXACTLY the canonical base64 form this release writes? */
export function isCanonicalSealed(value) {
  return sealedBodyBytes(value) !== null;
}

/**
 * The 12-byte GCM nonce of a sealed value (hex), decoded LENIENTLY: every spelling that decodes
 * to the same bytes answers the same nonce, including whitespace added around the body, a
 * stripped `=` pad, and a copy whose ciphertext was tampered with. Random nonces mean two
 * genuine rows never carry one nonce, so two rows that DO share a nonce name a copy. Null when
 * the value is not sealed or carries fewer bytes than a nonce. Deliberately NOT gated on the
 * canonical form: it must also count re-encoded (non-canonical) copies, so a copy still marks
 * its source as a duplicate.
 */
export function sealedNonceHex(value) {
  if (!isSealed(value)) return null;
  const prefix = value.startsWith(PREFIX_V2) ? PREFIX_V2 : PREFIX;
  const bytes = Buffer.from(value.slice(prefix.length), "base64");
  if (bytes.length < NONCE_LEN) return null;
  return bytes.subarray(0, NONCE_LEN).toString("hex");
}

/**
 * The AAD as bytes. It must be a NON-EMPTY Buffer or string: an empty AAD (or a missing
 * one) would seal a value that any context can open, which is exactly what v2 exists to
 * prevent, so it is refused rather than silently treated as "no AAD".
 */
function aadBytes(aad) {
  if (Buffer.isBuffer(aad)) {
    if (aad.length === 0) throw new Error("secret-box: aad must not be empty");
    return aad;
  }
  if (typeof aad === "string") {
    if (aad === "") throw new Error("secret-box: aad must not be empty");
    return Buffer.from(aad, "utf8");
  }
  throw new Error("secret-box: aad must be a non-empty Buffer or string");
}

function sealWith(prefix, plaintext, identity, aad) {
  if (plaintext == null) return plaintext;
  const pt = typeof plaintext === "string" ? Buffer.from(plaintext, "utf8") : Buffer.from(plaintext);
  const key = deriveKey(identity);
  const nonce = randomBytes(NONCE_LEN);
  const cipher = createCipheriv("aes-256-gcm", key, nonce);
  if (aad) cipher.setAAD(aad);
  const ct = Buffer.concat([cipher.update(pt), cipher.final()]);
  const tag = cipher.getAuthTag();
  return prefix + Buffer.concat([nonce, ct, tag]).toString("base64");
}

function openWith(prefix, value, identity, aad) {
  const blob = Buffer.from(value.slice(prefix.length), "base64");
  if (blob.length < NONCE_LEN + TAG_LEN) {
    throw new Error("secret-box: ciphertext too short");
  }
  const nonce = blob.subarray(0, NONCE_LEN);
  const tag = blob.subarray(blob.length - TAG_LEN);
  const ct = blob.subarray(NONCE_LEN, blob.length - TAG_LEN);
  const key = deriveKey(identity);
  const decipher = createDecipheriv("aes-256-gcm", key, nonce);
  if (aad) decipher.setAAD(aad);
  decipher.setAuthTag(tag);
  const pt = Buffer.concat([decipher.update(ct), decipher.final()]);
  return pt.toString("utf8");
}

/**
 * Seal a value in the ORIGINAL (unbound) v1 form. Byte-compatible with every v1 blob
 * already on disk; Shared Storage settings and the operator's verify tool still use it.
 */
export function sealSecret(plaintext, identity) {
  return sealWith(PREFIX, plaintext, identity, null);
}

/**
 * Seal a value BOUND to `aad`: opening it needs the same AAD (an `enc:v2:` blob). The
 * AAD is REQUIRED — an empty one throws before anything is derived, because a v2 blob
 * with no AAD would be a v1 blob wearing a v2 prefix.
 */
export function sealSecretBound(plaintext, identity, aad) {
  const bytes = aadBytes(aad);
  return sealWith(PREFIX_V2, plaintext, identity, bytes);
}

/**
 * Opens an ORIGINAL v1 sealed value. Returns plaintext string, or null if value is not
 * sealed at all (callers can distinguish "no-op, already plain" from an error). Throws on
 * tag mismatch — a tampered or wrong-identity blob should fail loudly — and throws on an
 * `enc:v2:` value, which only `openSecretBound` may open (never a silent null).
 */
export function openSecret(value, identity) {
  if (isSealedV2(value)) {
    throw new Error("secret-box: an enc:v2 value must be opened with openSecretBound");
  }
  if (!isSealedV1(value)) return null;
  return openWith(PREFIX, value, identity, null);
}

/**
 * Opens an AAD-BOUND v2 sealed value with the same AAD it was sealed under. Returns null
 * for a value that is not sealed at all; THROWS on an `enc:v1:` value (the caller's era
 * rule owns that form), on a wrong/empty AAD and on any tag failure — a blob copied into
 * another row (another AAD) never yields a plaintext.
 */
export function openSecretBound(value, identity, aad) {
  const bytes = aadBytes(aad);
  if (isSealedV1(value)) {
    throw new Error("secret-box: an enc:v1 value is not bound and has no AAD to open it with");
  }
  if (!isSealedV2(value)) return null;
  return openWith(PREFIX_V2, value, identity, bytes);
}