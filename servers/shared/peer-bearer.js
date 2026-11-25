/**
 * The paired-instance bearer seam (§8 PR 4 of the keyed-token-hashes design).
 *
 * `crow_instances.auth_token_hash` is now an `h1.` MAC under
 * `<CROW_HOME>/secrets/token-hmac.key` (`servers/shared/token-mac.js`), so the code that MINTS
 * it and the code that VERIFIES it hold a key. `servers/gateway/instance-registry.js` is
 * BOT-REACHABLE — `scripts/pi-bots/{bridge,runtime-gate,bot-classifier}.mjs`, the sync-emit
 * path and several shared modules import its `getOrCreateLocalInstanceId` — so it must never
 * import the key module, not even lazily (`tests/bot-seed-import-guard.test.js` follows literal
 * dynamic specifiers too, and it refuses a computed one outright).
 *
 * So the implementation is INSTALLED, exactly like the provider keyring
 * (`servers/shared/provider-keyring.js`): `servers/gateway/peer-inbound-token.js` installs
 * itself into this slot when it is loaded, and the gateway does that at boot, before it
 * listens. This module has no imports at all, so a bot-reachable chain that reaches it gets
 * nothing but a slot.
 *
 *   peerBearerFind(db, bearer, opts)   → the trusted `crow_instances` row, or null
 *   peerBearerMint(db, bearer)         → the `h1.` verifier to STORE for that bearer
 *
 * NOTHING INSTALLED MEANS REFUSE. A process that never loaded the implementation (a bot child,
 * a CLI that has not opted in, a half-booted gateway) answers `null` to every lookup and throws
 * `PEER_BEARER_MINT_UNAVAILABLE` to every mint, which is the fail-closed direction: a bare
 * sha256 is never accepted and nothing is written. `validateInstanceToken` in that process
 * therefore refuses every peer instead of falling back to `sha256(token)`, which is the exact
 * forgery this PR closes.
 *
 * Errors are NOT swallowed by `peerBearerFind`: `validateInstanceToken`'s "retry on a fresh
 * client" path (the 2026-06-14 corruption incident) depends on a database error propagating, so
 * a transient WAL desync still surfaces as a DB error rather than as "bad token".
 */

/** A mint was attempted in a process that never installed the implementation. */
export const PEER_BEARER_MINT_UNAVAILABLE = "PEER_BEARER_MINT_UNAVAILABLE";

/** The one installation slot. Null members mean "nothing installed". */
const slot = { find: null, mint: null };

/** Set once, so an ignored second install says so once rather than on every import. */
let secondInstallWarned = false;

/**
 * Install the host-side implementation (servers/gateway/peer-inbound-token.js does this at
 * module evaluation). Either member may be omitted; an omitted one leaves its slot empty, which
 * the callers below treat as refuse.
 *
 * FIRST INSTALL WINS, deliberately. The slot is what every validator in this process reads, so a
 * later install could swap the verifier out from under them — the one thing this seam must never
 * allow, since the alternative to the installed implementation is a bare-sha256 fallback. A
 * second install (a module loaded twice by two URLs, a bundle's own copy, a test harness) is
 * therefore IGNORED and says so in one console line; nothing already installed changes. A
 * process that needs a different implementation must exit and restart.
 *
 * @param {{ find?: ((db: object, bearer: string, opts?: object) => Promise<object|null>)|null,
 *           mint?: ((db: object, bearer: string) => Promise<string>)|null }} impl
 * @returns {boolean} true when this call installed; false when a first install already won
 */
export function installPeerBearer(impl = {}) {
  if (slot.find || slot.mint) {
    if (!secondInstallWarned) {
      secondInstallWarned = true;
      console.warn("[peer-bearer] an implementation is already installed in this process; the later install was ignored");
    }
    return false;
  }
  slot.find = typeof impl.find === "function" ? impl.find : null;
  slot.mint = typeof impl.mint === "function" ? impl.mint : null;
  return Boolean(slot.find || slot.mint);
}

/**
 * Forget the installed implementation: TEST SEAM ONLY (there is no production caller, and a
 * running gateway must never lose its verifier — see `installPeerBearer`'s first-install-wins
 * rule). Named for it so nothing in `servers/` reaches for it: uninstalling in a live process
 * turns every peer lookup into a refusal.
 */
export function clearPeerBearerForTest() {
  slot.find = null;
  slot.mint = null;
  secondInstallWarned = false;
}

/** True when a lookup implementation is installed in this process. */
export function peerBearerInstalled() {
  return typeof slot.find === "function";
}

/**
 * Find the trusted peer row whose verifier matches `bearer`, or null.
 *
 * Null when nothing is installed (see the header: refuse, never fall back), and null for an
 * empty presented bearer. A database error is RETHROWN — the caller's retry-on-fresh-client
 * logic is what turns that into a loud, recoverable refusal.
 *
 * @param {object} db crow.db client
 * @param {string} bearer the raw bearer a peer presented
 * @param {{ channel?: string }} [opts] passed through to the implementation (a label for the
 *        legacy alarm's audit row; never a secret)
 * @returns {Promise<object|null>}
 */
export async function peerBearerFind(db, bearer, opts = {}) {
  if (typeof slot.find !== "function") return null;
  if (typeof bearer !== "string" || bearer === "") return null;
  const row = await slot.find(db, bearer, opts);
  return row && typeof row === "object" ? row : null;
}

/**
 * The verifier to store for a freshly minted bearer.
 *
 * Throws `PEER_BEARER_MINT_UNAVAILABLE` when no implementation is installed: a writer must
 * never store `sha256(bearer)` because the key was not wired.
 *
 * @param {object} db crow.db client
 * @param {string} bearer the raw bearer this instance hands (or is handed)
 * @returns {Promise<string>} the `h1.` value
 */
export async function peerBearerMint(db, bearer) {
  if (typeof slot.mint !== "function") {
    const err = new Error(
      "This process cannot mint a paired-instance bearer verifier: the keyed-hash implementation "
      + "is not installed here (only the gateway and the pairing tools install it). Nothing was written.",
    );
    err.code = PEER_BEARER_MINT_UNAVAILABLE;
    throw err;
  }
  if (typeof bearer !== "string" || bearer === "") {
    throw new TypeError("peerBearerMint needs the raw bearer");
  }
  return slot.mint(db, bearer);
}