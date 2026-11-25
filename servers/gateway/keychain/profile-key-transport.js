/**
 * The profile-key TRANSIT box (profile-key sync design §2.1): how one profile API key
 * travels inside a signed instance-sync entry. It is never stored at rest (at rest a
 * key is an `sk1:`, see provider-key-box.js, purpose `profile`).
 *
 *   ps1:<base64url( gen(1) || nonce(12) || ciphertext || tag(16) )>
 *
 *   gen  0x01  <->  HKDF-SHA256(identity seed, salt empty, info "crow-profile-key-sync-v1", 32)
 *   AES-256-GCM over the TRIMMED UTF-8 key
 *   AAD = "crow-profile-key-sync" 0x00 gen 0x00 settingKey 0x00 profileId
 *
 * There is NO fingerprint anywhere: in the clear it would let a feed holder confirm a
 * guessed key offline, and in the AAD the GCM tag already authenticates the plaintext.
 *
 * The identity seed is a PARAMETER. This module never imports identity.js: its callers
 * are the gateway's sync hooks, which already hold the identity. It is gateway-only
 * code and sits in the bot import guard's forbidden set.
 *
 * `openTransit` never throws on bad input (null for everything that is not a
 * well-formed value for THIS seed, setting key and profile id). `sealTransit` throws
 * only fixed, value-free errors. Nothing here logs or returns a key, seed or envelope
 * inside an error.
 */
import { createCipheriv, createDecipheriv, hkdfSync, randomBytes } from "node:crypto";
import { isValidProfileId, PROFILE_ENVELOPE_MAX_LENGTH } from "../../shared/provider-key-shape.js";

export const TRANSIT_PREFIX = "ps1:";
export const TRANSIT_SETTING_KEYS = Object.freeze(["ai_profiles", "tts_profiles", "stt_profiles", "vision_profiles"]);
/** gen byte -> HKDF info. Exactly one generation exists; the byte reserves room. */
const GENERATIONS = Object.freeze({ 0x01: "crow-profile-key-sync-v1" });
const CURRENT_GEN = 0x01;
const LABEL = "crow-profile-key-sync";
const NONCE_LEN = 12;
const TAG_LEN = 16;

function usableSeed(seed) {
  return seed instanceof Uint8Array && seed.length === 32 ? seed : null;
}

function validSlot(settingKey, profileId) {
  return TRANSIT_SETTING_KEYS.includes(settingKey) && isValidProfileId(profileId);
}

function aad(gen, settingKey, profileId) {
  return Buffer.concat([
    Buffer.from(LABEL, "utf8"), Buffer.from([0]),
    Buffer.from([gen]), Buffer.from([0]),
    Buffer.from(settingKey, "utf8"), Buffer.from([0]),
    Buffer.from(profileId, "utf8"),
  ]);
}

function transitKey(seed, gen) {
  return Buffer.from(hkdfSync("sha256", Buffer.from(seed), Buffer.alloc(0), GENERATIONS[gen], 32));
}

/** True when `value` has the `ps1:` prefix (shape only, nothing is opened). */
export function isTransitEnvelope(value) {
  return typeof value === "string" && value.startsWith(TRANSIT_PREFIX);
}

/**
 * Seal one profile key for the wire.
 * @param {{seed: Uint8Array, settingKey: string, profileId: string, plaintext: string}} args
 * @returns {string} `ps1:...`
 */
export function sealTransit({ seed, settingKey, profileId, plaintext } = {}) {
  const s = usableSeed(seed);
  if (!s) throw new Error("profile-key-transport: an identity seed is required");
  if (!validSlot(settingKey, profileId)) throw new Error("profile-key-transport: unknown setting key or profile id");
  const trimmed = typeof plaintext === "string" ? plaintext.trim() : "";
  if (trimmed === "") throw new Error("profile-key-transport: nothing to seal");
  const nonce = randomBytes(NONCE_LEN);
  const cipher = createCipheriv("aes-256-gcm", transitKey(s, CURRENT_GEN), nonce);
  cipher.setAAD(aad(CURRENT_GEN, settingKey, profileId));
  const body = Buffer.concat([cipher.update(Buffer.from(trimmed, "utf8")), cipher.final()]);
  const tag = cipher.getAuthTag();
  return TRANSIT_PREFIX + Buffer.concat([Buffer.from([CURRENT_GEN]), nonce, body, tag]).toString("base64url");
}

/**
 * Open a `ps1:` value. Null for anything that is not a well-formed value for this
 * seed, setting key and profile id: not a string, another prefix (`sk1:`, `enc:v1:`),
 * bad or non-canonical base64, truncated, an unknown generation, a tag failure.
 * Never throws.
 * @param {{seed: Uint8Array, settingKey: string, profileId: string, stored: unknown}} args
 * @returns {string|null}
 */
export function openTransit({ seed, settingKey, profileId, stored } = {}) {
  try {
    const s = usableSeed(seed);
    if (!s || !validSlot(settingKey, profileId) || !isTransitEnvelope(stored)) return null;
    if (stored.length > PROFILE_ENVELOPE_MAX_LENGTH) return null; // bounded BEFORE any decoding
    const b64 = stored.slice(TRANSIT_PREFIX.length);
    if (!/^[A-Za-z0-9_-]+$/.test(b64)) return null;
    const blob = Buffer.from(b64, "base64url");
    if (blob.toString("base64url") !== b64) return null;
    if (blob.length < 1 + NONCE_LEN + 1 + TAG_LEN) return null;
    const gen = blob[0];
    if (!Object.hasOwn(GENERATIONS, gen)) return null;
    const nonce = blob.subarray(1, 1 + NONCE_LEN);
    const tag = blob.subarray(blob.length - TAG_LEN);
    const body = blob.subarray(1 + NONCE_LEN, blob.length - TAG_LEN);
    const decipher = createDecipheriv("aes-256-gcm", transitKey(s, gen), nonce);
    decipher.setAAD(aad(gen, settingKey, profileId));
    decipher.setAuthTag(tag);
    const plain = Buffer.concat([decipher.update(body), decipher.final()]).toString("utf8");
    return plain === "" ? null : plain;
  } catch {
    return null;
  }
}
