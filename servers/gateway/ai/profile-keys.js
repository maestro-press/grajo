/**
 * The profile-key helper (profile-key sync design §2.2, §2.3): the ONE module outside
 * the transit box that handles a profile's API key. A "profile" is an entry of the
 * `ai_profiles` / `tts_profiles` / `stt_profiles` / `vision_profiles` blobs.
 *
 * Fields on a profile object:
 *   apiKey         legacy plaintext. Always "" once sealed; a NON-EMPTY value always
 *                  wins over apiKeySealed (it is the newer write from an older writer).
 *   apiKeySealed   `sk1:...` at rest, `ps1:...` or the literal "keep" in a sync entry
 *                  only, absent when there is no key.
 *
 * The functions are PURE over a parsed profile object plus a keyring:
 *
 *   keyring = { open(slotId, stored) -> plaintext|null, seal(slotId, plaintext) -> sk1 }
 *             (provider-key-box.js `makeProfileKeyring(key)` builds one; slot id is
 *             `<kind>/<profileId>`). NO keyring means "this is not the gateway": every
 *             read is null and every transit output is "keep". The helper installs and
 *             mints nothing and imports no identity, so a process that was never handed
 *             a keyring (a stdio server, a bundle, a bot) can never open a key.
 *   seed   = the identity seed, passed in by the sync hook that holds it (transit only).
 *
 * Nothing here logs. Errors are fixed, value-free sentences with a code.
 *
 * Inert in this PR: nothing in production calls this module yet.
 */
import { sealTransit, openTransit, isTransitEnvelope, TRANSIT_SETTING_KEYS } from "../keychain/profile-key-transport.js";
import { PROFILE_KINDS } from "../keychain/provider-key-box.js";
import { isProfileKeyEnvelope, isValidProfileId } from "../../shared/provider-key-shape.js";

export const PROFILE_KEY_SEAL_UNAVAILABLE = "PROFILE_KEY_SEAL_UNAVAILABLE";
export const KEEP = "keep";
/**
 * The explicit "this profile has no key" marker a capable sender puts in `apiKeySealed`.
 * A removal is ONLY ever taken from this marker, inside a signed entry from a peer that
 * advertised the capability on this connection — never inferred from a blank field, so a
 * peer that is old, downgraded or wrongly flagged as capable cannot wipe a key by sending
 * a profile without one (orchestrator ruling, 2026-11-25).
 */
export const CLEAR = "clear";

const KIND_OF_SETTING = Object.freeze({
  ai_profiles: "ai", tts_profiles: "tts", stt_profiles: "stt", vision_profiles: "vision",
});

function refuse(code, message) {
  const err = new Error(message);
  err.code = code;
  return err;
}

function isObj(v) { return v != null && typeof v === "object" && !Array.isArray(v); }
/**
 * The key text of a value: trimmed, and "" for anything that is not a key. The exact
 * trimmed `none` is the sentinel a keyless row has always used (providerKeyFp and
 * parseStoredKey in provider-key-shape.js compare it case-sensitively, so `None` IS a
 * key); it is NEVER sealed and never counts as a failure. A keyless profile stores
 * `apiKey: ""` with no `apiKeySealed`, the form an empty key has today; the readers that
 * want a placeholder (`apiKey || "none"`) keep working unchanged.
 */
function trimmed(v) {
  if (typeof v !== "string") return "";
  const t = v.trim();
  return t === "none" ? "" : t;
}
function slotOf(kind, profile) {
  const id = isObj(profile) ? profile.id : undefined;
  if (!PROFILE_KINDS.includes(kind) || !isValidProfileId(id)) return null;
  return `${kind}/${id}`;
}
function usableKeyring(keyring) {
  return keyring && typeof keyring.open === "function" && typeof keyring.seal === "function" ? keyring : null;
}
function kindFor(settingKey, kind) {
  return kind || KIND_OF_SETTING[settingKey] || null;
}
/** A copy of the profile with both key fields removed. */
function bare(profile) {
  const out = { ...profile };
  delete out.apiKey;
  delete out.apiKeySealed;
  return out;
}
/** A copy with the key fields set from `sealed` (an sk1, or null for none). */
function withSealed(profile, sealed) {
  const out = bare(profile);
  if (typeof sealed === "string" && sealed !== "") { out.apiKeySealed = sealed; out.apiKey = ""; }
  else if (Object.hasOwn(profile, "apiKey")) out.apiKey = "";
  return out;
}

/**
 * The plaintext key of a profile, or null. A non-empty plaintext `apiKey` wins; else the
 * `sk1:` is opened with the keyring. No keyring, no slot, or anything that does not open:
 * null. Never throws.
 *
 * @param {object} profile
 * @param {{kind: string, keyring?: object|null}} opts
 * @returns {string|null}
 */
export function readProfileKey(profile, { kind, keyring } = {}) {
  try {
    const kr = usableKeyring(keyring);
    const slot = slotOf(kind, profile);
    if (!kr || !slot) return null;
    const plain = trimmed(profile.apiKey);
    if (plain !== "") return plain;
    if (!isProfileKeyEnvelope(profile.apiKeySealed)) return null;
    const opened = kr.open(slot, profile.apiKeySealed);
    return typeof opened === "string" && opened !== "" ? opened : null;
  } catch {
    return null;
  }
}

/**
 * The profile in storage form: a key is `apiKeySealed: sk1:...` with `apiKey: ""`
 * (a non-empty plaintext wins and replaces the sealed value). A profile with no key is
 * returned unchanged; an already-sealed one is returned as is (idempotent). An
 * `apiKeySealed` that is not an `sk1:` shape (`ps1:`, "keep", junk) is dropped: a
 * storage-form profile never carries one. Throws PROFILE_KEY_SEAL_UNAVAILABLE rather than
 * leave a plaintext key unsealed.
 *
 * @param {object} profile
 * @param {{kind: string, keyring?: object|null}} opts
 * @returns {object}
 */
export function sealProfileForStorage(profile, { kind, keyring } = {}) {
  if (!isObj(profile)) return profile;
  const plain = trimmed(profile.apiKey);
  if (plain !== "") {
    const kr = usableKeyring(keyring);
    const slot = slotOf(kind, profile);
    if (!kr || !slot) throw refuse(PROFILE_KEY_SEAL_UNAVAILABLE, "Crow cannot seal a saved profile key on this instance.");
    let sealed;
    try { sealed = kr.seal(slot, plain); } catch { sealed = null; }
    if (typeof sealed !== "string" || !isProfileKeyEnvelope(sealed)) {
      throw refuse(PROFILE_KEY_SEAL_UNAVAILABLE, "Crow cannot seal a saved profile key on this instance.");
    }
    return withSealed(profile, sealed);
  }
  if (isProfileKeyEnvelope(profile.apiKeySealed)) {
    return profile.apiKey === "" ? { ...profile } : withSealed(profile, profile.apiKeySealed);
  }
  // No key. A stray non-sk1 `apiKeySealed` ("keep", a ps1) must not reach storage, and
  // an `apiKey` that is not a key ("none", whitespace, a non-string) is stored as "".
  if (Object.hasOwn(profile, "apiKeySealed") || (Object.hasOwn(profile, "apiKey") && profile.apiKey !== "")) {
    return withSealed(profile, null);
  }
  return { ...profile };
}

/**
 * The blank-field rule of the settings forms (design §2.3). Edit + blank keeps the stored
 * `apiKeySealed` (the profile is returned as it is); create + blank means no key; a
 * non-blank submission is sealed. Returns a new profile object.
 *
 * @param {object} existing the profile being edited, or the new profile's base fields
 * @param {unknown} submittedKey
 * @param {{mode: "create"|"edit", kind: string, keyring?: object|null}} opts
 */
export function applySubmittedKey(existing, submittedKey, { mode, kind, keyring } = {}) {
  if (mode !== "create" && mode !== "edit") {
    throw refuse("PROFILE_KEY_MODE_INVALID", "applySubmittedKey: mode must be create or edit");
  }
  const base = isObj(existing) ? existing : {};
  // An explicit `none` is "no key" (the sentinel), in both modes: never sealed.
  if (typeof submittedKey === "string" && submittedKey.trim() === "none") return withSealed(base, null);
  const typed = trimmed(submittedKey);
  if (typed === "") {
    return mode === "edit" ? sealProfileForStorage(base, { kind, keyring }) : bare(base);
  }
  return sealProfileForStorage({ ...base, apiKey: typed }, { kind, keyring });
}

/** Both key fields removed (the switch to `auto` / pointer mode). */
export function stripProfileKeys(profile) {
  return isObj(profile) ? bare(profile) : profile;
}

/**
 * One profile for a sync entry (outbound). `apiKeySealed` is `ps1:...` when there is a
 * key this gateway can open, or the literal "keep" when it cannot (no keyring, an `sk1:`
 * that does not open, a profile without an id): `refused` is then true. A profile with no
 * key has no `apiKeySealed`. `apiKey` is always "". Never a plaintext, never an `sk1:`.
 * Never throws.
 *
 * @param {object} profile
 * @param {{settingKey: string, kind?: string, keyring?: object|null, seed?: Uint8Array}} opts
 * @returns {{profile: object, refused: boolean}}
 */
export function toTransit(profile, { settingKey, kind, keyring, seed } = {}) {
  if (!isObj(profile)) return { profile, refused: false };
  const hasKey = trimmed(profile.apiKey) !== ""
    || (typeof profile.apiKeySealed === "string" && profile.apiKeySealed !== "");
  const out = bare(profile);
  out.apiKey = "";
  if (!hasKey) { out.apiKeySealed = CLEAR; return { profile: out, refused: false }; }
  try {
    const k = kindFor(settingKey, kind);
    const plain = TRANSIT_SETTING_KEYS.includes(settingKey)
      ? readProfileKey(profile, { kind: k, keyring })
      : null;
    if (plain !== null) {
      out.apiKeySealed = sealTransit({ seed, settingKey, profileId: profile.id, plaintext: plain });
      return { profile: out, refused: false };
    }
  } catch { /* fall through to keep */ }
  out.apiKeySealed = KEEP;
  return { profile: out, refused: true };
}

/**
 * The profile to store for one incoming sync profile (inbound, design §2.2 table).
 * Returns `{ profile, outcome }`; `outcome` is "applied" (a key was opened/sealed),
 * "kept" (the local key stays), "cleared" (the sender removed the key), "none" or
 * "failed" (a key could not be taken; the local one stays; one alert upstream).
 *
 *  - a `ps1:` that opens              -> `sk1:` under THIS keyring
 *  - a `ps1:` that fails / unknown gen -> keep local, failed
 *  - "keep"                           -> keep local
 *  - "clear", capable sender          -> no key (cleared): the ONLY way a key is removed
 *  - "clear", NOT capable sender      -> keep local
 *  - blank (no marker), any sender    -> keep local (a blank never clears)
 *  - a non-empty plaintext `apiKey`   -> sealed `sk1:` (and it wins over any sealed field)
 *  - an incoming `sk1:`               -> treated as a failed `ps1:`
 * Never throws; the stored profile never holds a `ps1:`.
 */
export function fromTransitWithOutcome(incoming, localProfile, { settingKey, kind, keyring, seed, senderCapable } = {}) {
  if (!isObj(incoming)) return { profile: incoming, outcome: "none" };
  const k = kindFor(settingKey, kind);
  const kr = usableKeyring(keyring);
  const local = isObj(localProfile) && isValidProfileId(incoming.id) && localProfile.id === incoming.id ? localProfile : null;

  /** The local key in storage form, or null (never throws). */
  const keepLocal = () => {
    if (!local) return { sealed: null, plain: null };
    if (isProfileKeyEnvelope(local.apiKeySealed) && trimmed(local.apiKey) === "") {
      return { sealed: local.apiKeySealed, plain: null };
    }
    const plain = trimmed(local.apiKey);
    if (plain !== "") {
      try {
        const sealed = sealProfileForStorage(local, { kind: k, keyring: kr }).apiKeySealed;
        if (isProfileKeyEnvelope(sealed)) return { sealed, plain: null };
      } catch { /* cannot seal here */ }
      return { sealed: null, plain };
    }
    if (isProfileKeyEnvelope(local.apiKeySealed)) return { sealed: local.apiKeySealed, plain: null };
    return { sealed: null, plain: null };
  };
  const finish = (sealed, outcome, plain = null) => {
    const out = withSealed(incoming, sealed);
    if (plain) out.apiKey = plain; // only a local key that could not be sealed here, as it was
    return { profile: out, outcome };
  };
  const kept = (outcome) => { const l = keepLocal(); return finish(l.sealed, outcome, l.plain); };

  // Junk is never "blank": a non-string `apiKey`, or an `apiKeySealed` that is neither
  // absent nor a string, keeps the local key and reports a failure.
  if (incoming.apiKey !== undefined && typeof incoming.apiKey !== "string") return kept("failed");
  const sealedIn = incoming.apiKeySealed;
  if (sealedIn !== undefined && typeof sealedIn !== "string") return kept("failed");
  const plainIn = trimmed(incoming.apiKey);

  if (plainIn !== "") {
    const slot = slotOf(k, incoming);
    try {
      const s = kr && slot ? kr.seal(slot, plainIn) : null;
      if (typeof s === "string" && isProfileKeyEnvelope(s)) return finish(s, "applied");
    } catch { /* fall through */ }
    return kept("failed");
  }
  if (sealedIn === KEEP) return kept("kept");
  if (sealedIn === CLEAR) return senderCapable === true ? finish(null, "cleared") : kept("kept");
  if (typeof sealedIn === "string") {
    if (sealedIn !== "" && isTransitEnvelope(sealedIn)) {
      const slot = slotOf(k, incoming);
      const plain = TRANSIT_SETTING_KEYS.includes(settingKey)
        ? openTransit({ seed, settingKey, profileId: incoming.id, stored: sealedIn })
        : null;
      // A ps1 that opens to the `none` sentinel is "no key": never sealed, not a failure.
      if (plain !== null && trimmed(plain) === "") return finish(null, "cleared");
      if (plain !== null && kr && slot) {
        try {
          const s = kr.seal(slot, plain);
          if (typeof s === "string" && isProfileKeyEnvelope(s)) return finish(s, "applied");
        } catch { /* fall through */ }
      }
    }
    return kept("failed"); // "", fails to open, unknown generation, an incoming sk1:, junk
  }
  // Blank: `apiKeySealed` absent AND `apiKey` absent, "", or the `none` sentinel.
  // A blank never clears, from any sender: removal needs the explicit CLEAR marker.
  return kept("kept");
}

/** `fromTransitWithOutcome(...).profile`: the profile to store. */
export function fromTransit(incoming, localProfile, opts = {}) {
  return fromTransitWithOutcome(incoming, localProfile, opts).profile;
}
