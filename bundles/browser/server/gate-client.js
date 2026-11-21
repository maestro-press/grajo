/**
 * The MCP's side of the browser relay gate — two small things, no Playwright.
 *
 * The relay in front of Chromium (`cdp-relay.mjs --attach`) fails every request from a
 * page whose guard-bearing MCP has gone or has not hooked it yet. "Guard-bearing" is a
 * declaration the relay VERIFIES against what it sees on the wire, so a client declares it
 * in two steps:
 *
 *   1. intent — `connectOverCDP` carries `X-Crow-Guard-Client: 1` (`GATE_INTENT_HEADER` /
 *      `GATE_INTENT_VALUE`). While that is pending, the relay holds the client's new
 *      targets instead of resuming them, so nothing they run escapes the guard.
 *   2. readiness — once `installPrivateAddressGuard` has resolved on a context (routes,
 *      WebSocket routes, init script), one relay-handled command
 *      `Crow.guardReady {v: 1, exceptionsHash}` (`sendGuardReady`).
 *
 * `exceptionsHash` identifies the owner's exception list in one line of the relay's log;
 * it is not a secret and nothing is decided by it. `readGateStatus` reads the relay's own
 * `Crow-Guard` field for `crow_browser_status`: a diagnosis line, never a control.
 *
 * This module deliberately imports nothing but `node:crypto`. It is imported by
 * `server.js`, it ships in the bundle's own `server/` tree (an installed copy resolves
 * nothing outside its directory), and it must be loadable without Playwright and without
 * a browser — which is why the two shapes below are plain functions over their arguments.
 */
import { createHash } from "node:crypto";

/** The header a guard-bearing client declares its intent with, and its value. */
export const GATE_INTENT_HEADER = "X-Crow-Guard-Client";
export const GATE_INTENT_VALUE = "1";

/** The `/json/version` field the relay publishes while its gate is up, and its value. */
const GATE_STATUS_FIELD = "Crow-Guard";
const GATE_STATUS_VALUE = "gate/1";

/** The handshake's version, sent as `Crow.guardReady {v, exceptionsHash}`. */
const GATE_READY_VERSION = 1;

/** A status read never holds a tool call: the relay answers at once or not at all. */
const STATUS_TIMEOUT_MS = 2000;

/** How many hex characters of the digest the relay's log line carries. */
const HASH_CHARS = 16;

/** One log line, through the caller's logger when it gave one, and never a throw. */
function say(log, line) {
  if (typeof log !== "function") return;
  try {
    log(line);
  } catch {
    /* a log line is never worth failing a tool turn over */
  }
}

/**
 * The exception list as the relay logs it: 16 hex characters of sha256 over the list.
 *
 * The list is sorted and stringified first, so it is an identity for the SET of entries:
 * the order the owner wrote them in does not change it, a shorter list is a different
 * list, and two entries never collide with their concatenation (`["1","2"]` against
 * `["12"]`). A missing list is the empty one. Anything that is not an array hashes as
 * `[]`: this is a label for a log line, not a parser for the exception setting.
 *
 * @param {string[]|undefined|null} exceptions
 * @returns {string} 16 lowercase hex characters
 */
export function exceptionsHash(exceptions) {
  const list = Array.isArray(exceptions) ? exceptions : [];
  const canonical = JSON.stringify([...list].map(String).sort());
  return createHash("sha256").update(canonical, "utf8").digest("hex").slice(0, HASH_CHARS);
}

/**
 * Tell the relay that this client's guard is installed: one `Crow.guardReady` command.
 *
 * Called once per connection and context, AFTER `installPrivateAddressGuard` resolved —
 * the relay verifies the declaration against the guard's own commands on the wire
 * (`Fetch.enable` plus the marker-bearing init script), so declaring early would be
 * declaring something untrue. The command is relay-handled and never reaches Chromium.
 *
 * It opens one browser-level CDP session, sends the one command, and detaches; the session
 * is detached on every path, including a failure (a session leaked per connect is a
 * session leaked per turn), and nothing here throws:
 *
 *   - `{ ok: true }`                                   the relay took the declaration;
 *   - `{ ok: false, unsupported: true }`               the relay answered an error, which is
 *                                                      what a relay older than the gate does
 *                                                      (no `Crow.*` commands exist there).
 *                                                      The caller carries on exactly as
 *                                                      before; one short line goes through
 *                                                      the optional `log`;
 *   - `{ ok: false }`                                  no session to send on, or the send
 *                                                      failed some other way.
 *
 * @param {{newBrowserCDPSession: () => Promise<any>}} browser - a Playwright Browser
 * @param {{exceptions?: string[]|undefined|null, log?: (line: string) => void}} [options]
 * @returns {Promise<{ok: boolean, unsupported?: boolean}>}
 */
export async function sendGuardReady(browser, options = {}) {
  const { exceptions, log } = options || {};
  let session;
  try {
    session = await browser.newBrowserCDPSession();
  } catch {
    // No browser-level session: the handshake could not even be attempted. The tools are
    // about to find out why on their own; a tool turn does not fail for this.
    return { ok: false };
  }
  try {
    await session.send("Crow.guardReady", {
      v: GATE_READY_VERSION,
      exceptionsHash: exceptionsHash(exceptions),
    });
    return { ok: true };
  } catch {
    // An older relay's "method not found", or a relay that is going away. Either way this
    // is a known state, not a fault: the caller continues as it did before the gate.
    say(log, "[browser] the relay did not accept Crow.guardReady (a relay older than the gate): carrying on");
    return { ok: false, unsupported: true };
  } finally {
    try {
      await session.detach();
    } catch {
      /* the session may already be gone with the connection */
    }
  }
}

/**
 * Read the relay's own gate line from `/json/version`: `"yes"` or `"no"`.
 *
 * `Crow-Guard: gate/1` appears only while the relay's gate is up, so this answers the
 * operator's question "is the gate in the running container" — it is a diagnosis for
 * `crow_browser_status`, never a control (nothing is enabled or disabled by it, and the
 * gate has no off switch to be reached from here).
 *
 * Every failure is `"no"`, never a throw: a non-2xx answer, a body that is not JSON, a
 * body with no `Crow-Guard` string (a relay older than the gate advertises nothing, and
 * only the string `gate/1` counts), and a relay that does not answer at all.
 *
 * @param {string} cdpUrl - the CDP endpoint, with or without a trailing slash
 * @param {Record<string, string>} [headers] - the CDP bearer headers for this instance
 * @param {typeof fetch} [fetchImpl] - the fetch implementation to use (defaults to the global one)
 * @returns {Promise<"yes"|"no">}
 */
export async function readGateStatus(cdpUrl, headers = {}, fetchImpl = globalThis.fetch) {
  const base = String(cdpUrl ?? "").replace(/\/+$/, "");
  try {
    const response = await fetchImpl(`${base}/json/version`, {
      method: "GET",
      headers: headers || {},
      redirect: "error",
      signal: AbortSignal.timeout(STATUS_TIMEOUT_MS),
    });
    if (!response) return "no";
    const status = Number(response.status);
    if (!(status >= 200 && status < 300)) return "no";
    const body = await response.json();
    if (!body || typeof body !== "object") return "no";
    return body[GATE_STATUS_FIELD] === GATE_STATUS_VALUE ? "yes" : "no";
  } catch {
    return "no";
  }
}