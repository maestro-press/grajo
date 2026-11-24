/**
 * The terminal's nudge to the running gateway, after `crow mail add` has stored an account.
 *
 * The CLI writes crow.db itself, and the sync supervisor loads its accounts once, at boot — so
 * without this the new account would not sync until the next restart. The gateway exposes one
 * loopback-only route for exactly this (`POST /mail/local/sync-now`), authenticated by the path-scoped
 * token at `MAIL_HOOK_TOKEN.path()`. This helper is best effort in every direction:
 *
 *   - a token file that is missing, empty or unreadable means the gateway has not minted one (it
 *     mints one per boot), and no request is made;
 *   - the request goes to `127.0.0.1` and nowhere else, with a short timeout;
 *   - a refused, unreachable or timed-out gateway, and even a fetch that never settles, resolve
 *     without throwing. A caller's exit code never depends on the gateway being up.
 *
 * The caller (scripts/cli/mail-add.js) keeps its existing closing line on both paths: nothing here
 * prints anything, and no token is ever logged.
 */
import { readFileSync } from "node:fs";

/** The 127.0.0.1-only host: the hook is a same-box route, so a name would be a wider target. */
export const MAIL_SYNC_HOOK_HOST = "127.0.0.1";

/** The route this helper posts to (servers/gateway/routes/mail-sync-hook.js). */
export const MAIL_SYNC_HOOK_PATH = "/mail/local/sync-now";

/** A short budget: the CLI's job is done either way, so this waits for nothing. */
export const MAIL_SYNC_HOOK_TIMEOUT_MS = 3000;

/**
 * Ask the gateway on `port` to start syncing `accountId` now.
 *
 * @param {object} options
 * @param {string} options.accountId the account the add just stored
 * @param {string} options.tokenPath the raw MAIL_HOOK_TOKEN file (read-only)
 * @param {number|string} options.port this gateway's port (models/door.js `gatewayPort()`)
 * @param {Function} [options.fetchImpl] the transport (TEST seam; `globalThis.fetch` by default)
 * @param {Function} [options.readFile] the token reader (TEST seam; `readFileSync` by default)
 * @param {number} [options.timeoutMs] the whole call's budget
 * @returns {Promise<{notified: boolean}>} never rejects; `notified` is true only on a completed reply
 */
export async function notifyMailSyncHook({
  accountId,
  tokenPath,
  port,
  fetchImpl = (...args) => globalThis.fetch(...args),
  readFile = readFileSync,
  timeoutMs = MAIL_SYNC_HOOK_TIMEOUT_MS,
} = {}) {
  if (typeof accountId !== "string" || accountId === "") return { notified: false };
  if (typeof tokenPath !== "string" || tokenPath === "") return { notified: false };
  const parsedPort = Number.parseInt(String(port ?? ""), 10);
  if (!Number.isFinite(parsedPort) || parsedPort <= 0) return { notified: false };

  let token;
  try {
    token = String(readFile(tokenPath, "utf8")).trim();
  } catch {
    // No token file: the gateway has not booted since this feature shipped, or it is not running.
    return { notified: false };
  }
  if (!token) return { notified: false };

  const url = `http://${MAIL_SYNC_HOOK_HOST}:${parsedPort}${MAIL_SYNC_HOOK_PATH}`;
  const controller = new AbortController();
  let timer = null;
  try {
    const outcome = await Promise.race([
      Promise.resolve()
        .then(() => fetchImpl(url, {
          method: "POST",
          headers: { "content-type": "application/json", authorization: `Bearer ${token}` },
          body: JSON.stringify({ accountId }),
          signal: controller.signal,
        }))
        .then((res) => (res && res.ok === false ? "failed" : "notified"), () => "failed"),
      new Promise((resolve) => {
        timer = setTimeout(() => {
          // Abort so a real fetch does not keep the socket (and the process) alive after the race.
          try { controller.abort(); } catch { /* already settled */ }
          resolve("timeout");
        }, timeoutMs);
      }),
    ]);
    return { notified: outcome === "notified" };
  } catch {
    return { notified: false };
  } finally {
    if (timer !== null) clearTimeout(timer);
  }
}

export default notifyMailSyncHook;