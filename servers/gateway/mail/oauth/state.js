/**
 * The OAuth flow store: the short-lived record that ties a provider's redirect back to the person (and
 * the Crow session) that started the flow.
 *
 * `begin()` mints an unguessable state token and keeps everything the token request will need — the
 * PKCE verifier, the client id and secret, the exact redirect URI, the tenant and the account being
 * added — under it, in memory only. `take()` spends the token: the redirect handler calls it once, and
 * a second use is null. That is the whole point of `state`: a replayed callback must not be able to
 * redeem a second code in someone else's browser, so `take()` deletes the entry on ANY lookup that
 * finds it, including one whose session does not match, and answers null without saying why.
 *
 * Two things keep the store from growing without limit: a per-session cap (a person abandoning flows
 * evicts their own oldest) and a total cap (abandoned flows across sessions evict the globally oldest).
 * An entry older than `ttlMs` is expired: the provider's redirect is worthless after that, and `take()`
 * deletes it rather than returning it. `begin()` and `take()` also SWEEP: every expired entry is dropped
 * before anything else happens, so abandoned flows — and the PKCE verifier and client secret they hold —
 * do not sit in memory until a cap or a restart happens to clear them.
 *
 * The token and the session id are compared with `crypto.timingSafeEqual` over equal-length buffers,
 * and the entry is found by WALKING the store — never by `Map.get(stateToken)` — so the time a lookup
 * takes does not depend on which entry matched, nor on how many bytes of a guess were right. A wrong
 * length is simply not equal (that is the one thing a lookup does reveal, and it reveals nothing about
 * an entry: every entry has the same token length).
 *
 * Nothing here touches the network, the database or the disk.
 */
import { randomBytes, timingSafeEqual } from "node:crypto";
import { MailError } from "../errors.js";

/** 32 random bytes base64url-encodes to 43 characters of `[A-Za-z0-9-._~]` — plenty for a state token. */
const TOKEN_BYTES = 32;

/** Ten minutes: long enough to sign in at the provider, short enough that an abandoned flow is noise. */
const DEFAULT_TTL_MS = 600_000;

const base64url = (bytes) => bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

function requireString(value, detail) {
  if (typeof value !== "string" || value.length === 0) throw new MailError("BAD_INPUT", detail);
  return value;
}

function positiveInt(value, fallback) {
  return Number.isInteger(value) && value > 0 ? value : fallback;
}

/** Equal-length, constant-time comparison of two strings. A different length is not equal (and reveals nothing). */
function sameString(a, b) {
  if (typeof a !== "string" || typeof b !== "string") return false;
  const left = Buffer.from(a, "utf8");
  const right = Buffer.from(b, "utf8");
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

/**
 * Build a flow store.
 *
 * @param {object} [options]
 * @param {() => number} [options.now] the clock, injectable so a test can age an entry past its TTL
 * @param {number} [options.ttlMs] how long a flow may take (default 10 minutes)
 * @param {number} [options.perSessionCap] flows one session may have open (oldest of that session evicted)
 * @param {number} [options.totalCap] flows the whole store may hold (globally oldest evicted)
 * @returns {{begin: Function, take: Function, size: () => number}}
 */
export function createFlowStore({ now = Date.now, ttlMs = DEFAULT_TTL_MS, perSessionCap = 20, totalCap = 200 } = {}) {
  /** state token -> flow record. Iteration order is insertion order, so the first key is the oldest. */
  const entries = new Map();
  const sessionCap = positiveInt(perSessionCap, 20);
  const globalCap = positiveInt(totalCap, 200);
  const ttl = Number.isFinite(ttlMs) && ttlMs > 0 ? ttlMs : DEFAULT_TTL_MS;

  /** A token nothing else in the store holds (collisions are impossible in practice; this is a belt). */
  function newToken() {
    for (;;) {
      const token = base64url(randomBytes(TOKEN_BYTES));
      if (!entries.has(token)) return token;
    }
  }

  /** Walk the whole store, comparing every key in constant time — never `entries.has(guess)`. */
  function locate(stateToken) {
    const wanted = Buffer.from(stateToken, "utf8");
    let match = null;
    for (const key of entries.keys()) {
      const stored = Buffer.from(key, "utf8");
      if (stored.length === wanted.length && timingSafeEqual(stored, wanted)) match = key;
    }
    return match;
  }

  /** Evict this session's oldest flows until it is inside its cap. */
  function trimSession(sessionId) {
    let held = 0;
    for (const record of entries.values()) if (sameString(record.sessionId, sessionId)) held += 1;
    while (held > sessionCap) {
      let removed = false;
      for (const [token, record] of entries) {
        if (!sameString(record.sessionId, sessionId)) continue;
        drop(token, record);
        held -= 1;
        removed = true;
        break;
      }
      // Unreachable while `held` counts the same set, but never spin if it ever drifts.
      if (!removed) return;
    }
  }

  /** Evict the globally oldest flows until the store is inside its total cap. */
  function trimTotal() {
    while (entries.size > globalCap) {
      const oldest = entries.keys().next();
      if (oldest.done) return;
      drop(oldest.value, entries.get(oldest.value));
    }
  }

  /**
   * Forget one entry and the secrets it holds. The verifier and the client secret are only ever needed
   * by the token request of a live flow, so a record that is leaving the store is scrubbed as it goes:
   * a leaked reference cannot keep a secret alive after the flow is gone.
   */
  function drop(token, record) {
    entries.delete(token);
    if (record != null && typeof record === "object") {
      record.verifier = null;
      record.clientSecret = null;
    }
  }

  /** Whether a record is past its TTL. */
  function expired(record) {
    return now() > record.createdAt + ttl;
  }

  /**
   * Drop every expired flow (and with it the PKCE verifier and the client secret it holds). Called by
   * `begin()` and `take()`: an abandoned flow must not sit in memory until a cap happens to evict it,
   * and a store of mostly-expired entries must not answer a lookup from stale state.
   */
  function sweep() {
    for (const [token, record] of entries) {
      if (expired(record)) drop(token, record);
    }
  }

  /**
   * Start a flow: keep everything the token request will need under a fresh state token.
   *
   * @param {object} flow
   * @param {string} flow.sessionId the Crow session that began it; another session cannot spend it
   * @param {string} flow.provider "google" or "microsoft" (whatever the caller handles — not checked here)
   * @param {object|null} [flow.accountDraft] the account being added, carried to the callback
   * @param {string} flow.verifier the PKCE verifier (`newVerifier()`), kept server-side only
   * @param {string|null} [flow.clientId]
   * @param {string|null} [flow.clientSecret] a secret is kept in memory for this flow only and never logged
   * @param {string|null} [flow.redirectUri] the exact URI the callback will be checked against
   * @param {string|null} [flow.tenant] a Microsoft tenant, when the caller collected one
   * @returns {string} the state token for the authorization URL
   */
  function begin({ sessionId, provider, accountDraft = null, verifier, clientId = null, clientSecret = null, redirectUri = null, tenant = null } = {}) {
    requireString(sessionId, "session");
    requireString(verifier, "verifier");
    // Abandoned flows (and their verifier and client secret) go before another entry joins the store.
    sweep();
    const token = newToken();
    entries.set(token, {
      sessionId,
      provider,
      accountDraft,
      verifier,
      clientId,
      clientSecret,
      redirectUri,
      tenant,
      createdAt: now(),
    });
    trimSession(sessionId);
    trimTotal();
    return token;
  }

  /**
   * Spend a state token: at most once, for the session that began it, before its TTL runs out.
   *
   * The entry is deleted whenever the token is FOUND — even when the session does not match — so a
   * stolen token cannot be tried twice. An unknown token, a mismatched session, an expired flow and a
   * value that is not a string all answer null, and the caller gets nothing that says which happened.
   *
   * @param {string} stateToken the `state` the provider echoed back
   * @param {string} sessionId the Crow session handling the callback
   * @returns {object|null} the flow record, or null
   */
  function take(stateToken, sessionId) {
    if (typeof stateToken !== "string" || stateToken.length === 0) return null;
    if (typeof sessionId !== "string" || sessionId.length === 0) return null;
    // A lookup also sweeps: expired flows are dropped (with their secrets) rather than kept until a cap.
    sweep();
    const token = locate(stateToken);
    if (token === null) return null;
    const record = entries.get(token);
    if (!record) return null;
    if (!sameString(sessionId, record.sessionId)) {
      drop(token, record);
      return null;
    }
    if (expired(record)) {
      drop(token, record);
      return null;
    }
    entries.delete(token);
    return record;
  }

  /** How many flows are open right now (the caps are enforced in `begin`). */
  function size() {
    return entries.size;
  }

  return { begin, take, size };
}