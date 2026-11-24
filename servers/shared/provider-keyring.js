/**
 * The provider-keyring seam (design §1.1).
 *
 * A shared module (or a bot process) that has to OPEN or SEAL a stored provider
 * API key must not import the gateway's keychain, the key file or the crypto
 * box: those belong to the gateway process, and a bot-reachable file importing
 * them is exactly what tests/bot-seed-import-guard.test.js refuses. So the
 * gateway INSTALLS an implementation into this module at boot, and everybody
 * else calls through it.
 *
 * The seam is deliberately tiny and dependency-free (no imports at all):
 *
 *   keyringOpen(slotId, stored)  → the plaintext, or null
 *   keyringSeal(slotId, plain)   → the envelope, or a thrown refusal
 *
 * Before an implementation is installed (a CLI, a test, a process that has not
 * booted the gateway) every read is null and every seal REFUSES with
 * `PROVIDER_KEY_SEAL_UNAVAILABLE` — a writer must never silently store a
 * provider key in the clear because the keyring was not wired. The refusal is
 * the safe direction: nothing is written.
 *
 * Nothing here logs, returns or throws a key VALUE: `keyringOpen` answers null
 * on every failure, and the seal refusal carries a fixed sentence plus a code.
 */
export const PROVIDER_KEY_SEAL_UNAVAILABLE = "PROVIDER_KEY_SEAL_UNAVAILABLE";

/**
 * A provider row HOLDS a key this process cannot read (a malformed cell, or an
 * envelope that does not open here): a reader must refuse the request rather
 * than send it unauthenticated. The model door answers it with a 503.
 */
export const PROVIDER_KEY_UNREADABLE = "PROVIDER_KEY_UNREADABLE";

/**
 * A sender in a process with NO keyring (the memory server) met a sealed key. It
 * is not a fault of the value — this process simply cannot open it — so it has
 * its own code, distinct from PROVIDER_KEY_UNREADABLE, and the sender stops
 * before making a request.
 */
export const PROVIDER_KEY_NOT_IN_PROCESS = "PROVIDER_KEY_NOT_IN_PROCESS";

/** The one installation slot. Null members mean "nothing installed". */
const slot = { open: null, seal: null, sameKey: null };

/**
 * Install the gateway's implementation. `open` and `seal` are the ones a real
 * caller installs: `open(slotId, stored) -> plaintext|null` and
 * `seal(slotId, plain) -> envelope`. `sameKey(stored, plain) -> boolean` ("is this
 * stored cell already this key?") is optional and the gateway does NOT install it
 * (review round 1, L1): that question is answered by opening the cell, in
 * servers/shared/providers-db.js `sameKeyCell`, which every writer already goes
 * through — a second, fingerprint-only answer here was the bug.
 *
 * @param {{open?: ((slotId:string, stored:string)=>string|null)|null,
 *          seal?: ((slotId:string, plain:string)=>string)|null,
 *          sameKey?: ((stored:string, plain:string)=>boolean)|null}} impl
 */
export function installProviderKeyring(impl = {}) {
  slot.open = typeof impl.open === "function" ? impl.open : null;
  slot.seal = typeof impl.seal === "function" ? impl.seal : null;
  slot.sameKey = typeof impl.sameKey === "function" ? impl.sameKey : null;
}

/** Forget the installed implementation (the test seam, and a shutdown). */
export function clearProviderKeyring() {
  slot.open = null;
  slot.seal = null;
  slot.sameKey = null;
}

/** True when a seal/open implementation is installed in this process. */
export function providerKeyringInstalled() {
  return typeof slot.open === "function" || typeof slot.seal === "function";
}

/**
 * Is `stored` already the key `plain`? Answered by the installed keyring (it
 * needs the key's identity, not just the plaintext). False when no keyring is
 * installed: a caller must treat that as "changed", never as "same".
 * Never throws.
 *
 * @param {unknown} stored
 * @param {unknown} plain
 * @returns {boolean}
 */
export function keyringSameKey(stored, plain) {
  if (typeof slot.sameKey !== "function") return false;
  try { return slot.sameKey(stored, plain) === true; } catch { return false; }
}

/**
 * Open a stored provider key for `slotId` (the provider row id). Null when there
 * is nothing to open, when no keyring is installed, when the value is not an
 * envelope for THIS key, or when opening fails for any reason. Never throws.
 *
 * @param {string} slotId
 * @param {unknown} stored
 * @returns {string|null}
 */
export function keyringOpen(slotId, stored) {
  if (typeof stored !== "string" || stored === "") return null;
  if (typeof slot.open !== "function") return null;
  let opened;
  try {
    opened = slot.open(slotId, stored);
  } catch {
    return null;
  }
  return typeof opened === "string" ? opened : null;
}

/**
 * Seal one provider key for `slotId`. A value with nothing to seal (null, a
 * non-string, "" or the "none" sentinel) is returned unchanged — the caller
 * decides what a keyless row stores, and sealing is never applied to it.
 *
 * Throws an Error whose `code` is PROVIDER_KEY_SEAL_UNAVAILABLE when no sealer
 * is installed: a writer must refuse rather than store the value in the clear.
 *
 * @param {string} slotId
 * @param {unknown} plain
 * @returns {string|null|undefined}
 */
export function keyringSeal(slotId, plain) {
  if (typeof plain !== "string" || plain === "" || plain === "none") return plain;
  if (typeof slot.seal !== "function") {
    const err = new Error("Crow cannot seal a saved provider key on this instance.");
    err.code = PROVIDER_KEY_SEAL_UNAVAILABLE;
    throw err;
  }
  return slot.seal(slotId, plain);
}