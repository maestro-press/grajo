/**
 * The provider-key box (design §2.2): how ONE provider API key is sealed into a
 * `providers.api_key` cell, and how it is opened again.
 *
 * Envelope (design §2.1, parsed by servers/shared/provider-key-shape.js):
 *
 *   pk1:<keyId16 hex>:<fp16 hex>:<base64url(nonce(12) || ciphertext || tag(16))>
 *
 * Key: HKDF-SHA256(keychain seed, salt = empty, info = "crow-provider-key-v1", 32).
 * It is the keychain's OWN key (keychain/key.js), never the instance identity
 * seed, so a copied crow.db — or an exported identity.json — cannot open a
 * provider key. A restored crow.db without its key file fails CLOSED: the
 * envelope names the key id it was sealed under, so `open` returns null without
 * even deriving a key, and never a wrong plaintext.
 *
 * AAD binds what the envelope claims to what the caller asked for:
 *   JSON(["crow-provider-key-v1", purpose, slotId, keyId, fp16])
 * — so a ciphertext moved to another provider row, another key id or another
 * purpose does not open. The seal covers the RAW bytes of the value (trailing
 * whitespace included); `fp16` is the fingerprint of the TRIMMED value, which
 * is the identity a reader compares when deciding "same key, no re-save".
 *
 * Nothing in this module logs, returns in an error, or exports a key value, an
 * envelope or a key id. Every failure is `null` from `open` (a refusal to read
 * is never an exception on a request path) and a fixed, value-free Error from
 * `seal`.
 */
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import {
  parseStoredKey,
  providerKeyFp,
} from "../../shared/provider-key-shape.js";
import { installProviderKeyring, PROVIDER_KEY_SEAL_UNAVAILABLE } from "../../shared/provider-keyring.js";
import { keychainKeyState, loadKeychainKey } from "./key.js";

/** The HKDF info string; also the first element of every AAD. */
export const PROVIDER_KEY_HKDF_INFO = "crow-provider-key-v1";
/** The only purpose implemented here. Another purpose has no prefix and no AAD. */
export const PROVIDER_KEY_PURPOSE = "provider";
const PURPOSE_PREFIX = Object.freeze({ provider: "pk1" });
const NONCE_LEN = 12;
const TAG_LEN = 16;

function refuse(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

/** The one implemented purpose, or a refusal naming no key material. */
function purposePrefix(purpose) {
  const prefix = PURPOSE_PREFIX[purpose];
  if (!prefix) throw refuse("PROVIDER_KEY_PURPOSE_UNSUPPORTED", "provider-key-box: only the provider purpose is implemented");
  return prefix;
}

/** A usable keychain key: `{ id: 16 hex, seed: 32 bytes }`. */
function usableKey(key) {
  if (!key || typeof key.id !== "string" || !/^[0-9a-f]{16}$/.test(key.id)) return null;
  const seed = Buffer.isBuffer(key.seed) ? key.seed : null;
  return seed && seed.length === 32 ? { id: key.id, seed } : null;
}

/** HKDF-SHA256(seed, salt empty, info, 32). */
function deriveSealKey(key) {
  return Buffer.from(hkdfSync("sha256", key.seed, Buffer.alloc(0), PROVIDER_KEY_HKDF_INFO, 32));
}

/** The associated data: everything the envelope claims, bound to the request. */
function associatedData(prefix, slotId, keyId, fp) {
  return Buffer.from(JSON.stringify([PROVIDER_KEY_HKDF_INFO, prefix, String(slotId), keyId, fp]), "utf8");
}

/**
 * Seal one provider key.
 *
 * @param {{purpose?: string, slotId: string, plaintext: string, key: {id:string, seed:Buffer}}} args
 * @returns {string} the envelope
 */
export function seal({ purpose = PROVIDER_KEY_PURPOSE, slotId, plaintext, key } = {}) {
  const prefix = purposePrefix(purpose);
  const k = usableKey(key);
  if (!k) throw refuse("PROVIDER_KEY_NO_KEY", "provider-key-box: a keychain key is required to seal a provider key");
  if (typeof slotId !== "string" || slotId === "") throw new TypeError("provider-key-box: a slot id is required");
  if (typeof plaintext !== "string" || plaintext === "") throw refuse("PROVIDER_KEY_EMPTY", "provider-key-box: nothing to seal");
  const fp = providerKeyFp(plaintext);
  if (!fp) throw refuse("PROVIDER_KEY_EMPTY", "provider-key-box: nothing to seal");

  const sealKey = deriveSealKey(k);
  const nonce = randomBytes(NONCE_LEN);
  const cipher = createCipheriv("aes-256-gcm", sealKey, nonce);
  cipher.setAAD(associatedData(prefix, slotId, k.id, fp));
  const body = Buffer.concat([cipher.update(Buffer.from(plaintext, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  const payload = Buffer.concat([nonce, body, tag]).toString("base64url");
  return `${prefix}:${k.id}:${fp}:${payload}`;
}

/**
 * Open a stored provider key. Null for anything that is not a well-formed
 * envelope for THIS key — a plain value, the `none` sentinel, a malformed
 * envelope, an envelope under another key id (no decryption is attempted), a
 * failed/tampered decrypt, a row moved onto another slot, and a value whose
 * plaintext does not match the fingerprint the envelope carries.
 *
 * @param {{purpose?: string, slotId: string, stored: unknown, key: {id:string, seed:Buffer}}} args
 * @returns {string|null}
 */
export function open({ purpose = PROVIDER_KEY_PURPOSE, slotId, stored, key } = {}) {
  const prefix = purposePrefix(purpose);
  if (typeof slotId !== "string" || slotId === "") return null;
  const parsed = parseStoredKey(stored);
  if (parsed.kind !== "envelope" || !stored.startsWith(prefix + ":")) return null;
  // The key id FIRST, before the seed is even read: a crow.db restored onto a
  // machine with another key file must not derive, let alone decrypt, and never
  // yields a wrong plaintext.
  if (!key || typeof key.id !== "string" || parsed.keyId !== key.id) return null;
  const k = usableKey(key);
  if (!k) return null;

  let plaintext;
  try {
    const blob = Buffer.from(parsed.payload, "base64url");
    if (blob.length < NONCE_LEN + TAG_LEN) return null;
    const nonce = blob.subarray(0, NONCE_LEN);
    const tag = blob.subarray(blob.length - TAG_LEN);
    const body = blob.subarray(NONCE_LEN, blob.length - TAG_LEN);
    const decipher = createDecipheriv("aes-256-gcm", deriveSealKey(k), nonce);
    decipher.setAAD(associatedData(prefix, slotId, parsed.keyId, parsed.fp));
    decipher.setAuthTag(tag);
    plaintext = Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
  } catch {
    return null;
  }
  // The fingerprint the envelope carries must describe what came out, or the
  // value is not this row's key.
  if (providerKeyFp(plaintext) !== parsed.fp) return null;
  return plaintext;
}

/** sha256 over a string's bytes (never exported, never logged). */

/**
 * Install this box into the shared provider-keyring seam, bound to the
 * keychain key of `crowHome`. The gateway calls it at boot; nothing else does.
 *
 * A missing or invalid key file installs a REFUSING keyring (reads null, seals
 * throw PROVIDER_KEY_SEAL_UNAVAILABLE) instead of leaving the slot empty, so a
 * process that asked for the keyring and did not get a key can never fall back
 * to writing a provider key in the clear.
 *
 * It also stops refusing by itself once a key appears (review round 1, H2): a
 * fresh install has no keychain key yet, and the key is minted later by the §3.2
 * rule (boot, store.ensureWriteKey, another route). Rather than require every
 * mint site to re-install the keyring — one of them would be forgotten — a seal
 * and an open re-check the key FILE when the install found none, and pick the
 * key up on the first call after it exists. While it is still missing the answer
 * is the same refusal as before, so nothing is ever written in the clear.
 *
 * @param {{crowHome?: string}} [args]
 * @returns {boolean} true when a usable key was installed
 */
export function installGatewayProviderKeyring({ crowHome } = {}) {
  const options = crowHome ? { crowHome } : undefined;
  let key = null;
  try {
    key = loadKeychainKey(options);
  } catch {
    key = null;
  }
  let k = usableKey(key);
  if (!k) {
    // The key may appear later; the first seal/open after that adopts it. SEAL
    // re-checks the file every time (a save must start working at once); OPEN
    // caches a negative for a second, so a request path in the refusing state
    // does not read a file per row.
    let missingCheckedAt = 0;
    const adoptForSeal = () => {
      const now = adoptKey(options);
      if (now) { k = now; missingCheckedAt = 0; }
      return now;
    };
    const adoptForOpen = () => {
      const at = Date.now();
      if (missingCheckedAt && at - missingCheckedAt < 1000) return null;
      const now = adoptKey(options);
      if (now) { k = now; missingCheckedAt = 0; } else missingCheckedAt = at;
      return now;
    };
    installProviderKeyring({
      open: (slotId, stored) => {
        const now = k || adoptForOpen();
        return now ? open({ slotId, stored, key: now }) : null;
      },
      seal: (slotId, plaintext) => {
        const now = k || adoptForSeal();
        if (!now) {
          throw refuse(PROVIDER_KEY_SEAL_UNAVAILABLE, "Crow cannot seal a saved provider key on this instance.");
        }
        return seal({ slotId, plaintext, key: now });
      },
    });
    return false;
  }
  installProviderKeyring({
    open: (slotId, stored) => open({ slotId, stored, key: k }),
    seal: (slotId, plaintext) => seal({ slotId, plaintext, key: k }),
  });
  return true;
}

/**
 * The key file's current state, read fresh: the gateway keyring's own late-bind
 * for an install that found no key. Null while it is still missing or damaged.
 * Cheap (one small file), and only on the path that would otherwise refuse.
 */
function adoptKey(options) {
  try {
    return keychainKeyState(options).key;
  } catch {
    return null;
  }
}