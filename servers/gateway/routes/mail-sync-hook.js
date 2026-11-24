/**
 * Crow Mail's local sync hook: `POST /mail/local/sync-now`.
 *
 * `scripts/cli/mail-add.js` connects an account by writing crow.db itself, so the running gateway's
 * sync supervisor — which loads its accounts once, at `start()` — would not touch the new account
 * until the next boot. The dashboard's own connect calls `supervisor.syncNow(id)`; this is the same
 * nudge for the terminal, and it is the only reason this route exists.
 *
 * It is not a dashboard route and it is not an MCP mount. The auth is its own path-scoped token
 * (server-side `MAIL_HOOK_TOKEN`), minted at boot, rotated every boot, and validated by nothing else.
 * Admission, in this order, each refusal fail-closed (a throw in a step is that step's refusal):
 *
 *   a. a genuine same-box caller: `isLocalPeer` true, not a relayed socket, no instance/cross-host
 *      auth, no Funnel header -> 404 `{error:"not_found"}`;
 *   b. `Authorization: Bearer <token>` valid for MAIL_HOOK_TOKEN only -> 401 `{error:"bad_token"}`.
 *      The full local token, the board token and every other family token are refused here, exactly
 *      as this token is refused by every other validator;
 *   c. a JSON body `{accountId}` that matches MAIL_ACCOUNT_ID_RE and names an account in the state
 *      the supervisor syncs (`active`) -> 400 `{error:"bad_request"}`, or 404
 *      `{error:"unknown_account"}` for a malformed/unknown/disabled id;
 *   d. a live mail runtime -> 503 `{error:"mail_off"}`;
 *   e. `supervisor.syncNow(accountId)`, started but NOT awaited, and 202 `{ok:true}`.
 *
 * The answer never carries account data, and the token is never echoed or logged. Refusals are logged
 * once an hour per code (`noteRefusedOnce`) and a rejected sync is logged by account id only.
 */
import { Router, json as jsonParserOf } from "express";
import { isRelayedSocket } from "../../shared/bot-doors.js";
import { isLocalPeer } from "../../shared/peer-class.js";
import { withoutWriteContext } from "../../shared/history/write-context.js";
import { MAIL_HOOK_TOKEN } from "../local-token.js";
import { getAccount } from "../mail/store/accounts.js";
import { noteRefusedOnce } from "../loopback-gate.js";
import { MAIL_ACCOUNT_ID_RE, getMailSupervisor } from "./mail-api.js";

/** The one path this router serves. Funnel-blocked (it is not in PUBLIC_FUNNEL_PREFIXES). */
export const MAIL_SYNC_HOOK_PATH = "/mail/local/sync-now";

/** The refusal log tag: one tag for every answer this hook refuses. */
const REFUSAL_TAG = "mail-sync-hook";

/** A sync request is an id and nothing else; this is not a document endpoint. */
const BODY_LIMIT = "8kb";

const first = (v) => {
  const x = Array.isArray(v) ? v[0] : v;
  if (x == null) return undefined;
  return String(x).trim();
};

/** The bearer's token, or null. The scheme is case-insensitive, exactly as the loopback gate reads it. */
function bearerToken(headers = {}) {
  const m = /^bearer\s+(\S+)\s*$/i.exec(String(first(headers?.authorization) ?? ""));
  return m?.[1] ?? null;
}

/** The body's account id, or null for anything that is not one the store could have minted. */
function readAccountId(body) {
  if (body == null || typeof body !== "object" || Array.isArray(body)) return null;
  const id = body.accountId;
  return typeof id === "string" && MAIL_ACCOUNT_ID_RE.test(id) ? id : null;
}

/**
 * The router. Mountable on a bare express app: `createDbClient` opens this route's client (closed in
 * `finally`), `getSupervisor` reads the mail runtime (routes/mail-api.js by default) and `log` takes
 * the one line a rejected sync writes.
 *
 * @param {{createDbClient: () => object, getSupervisor?: () => object|null, log?: object}} options
 * @returns {import("express").Router}
 */
export function mailSyncHookRouter({ createDbClient, getSupervisor = getMailSupervisor, log = console } = {}) {
  if (typeof createDbClient !== "function") throw new TypeError("mailSyncHookRouter: createDbClient is required");
  const router = Router();
  const jsonParser = jsonParserOf({ limit: BODY_LIMIT });

  const refuse = (res, status, code) => {
    noteRefusedOnce(REFUSAL_TAG, code);
    if (res.headersSent) return undefined;
    return res.status(status).json({ error: code });
  };

  async function handle(req, res) {
    // a. Only this host's own processes, unproxied and not through Funnel. A relayed socket is never
    //    the operator (the local token's own relay rule, local-token.js): an egress relay binds a
    //    loopback address, so `isLocalPeer` alone would admit a contained bot. A throw here is the
    //    same refusal: a caller that is not provably local learns nothing about the route.
    let local = false;
    try {
      local = isLocalPeer(req.socket?.remoteAddress, req.headers) === true
        && !isRelayedSocket(req.socket)
        && !req.instanceAuth
        && !req.crossHostAuth
        && !req.headers?.["tailscale-funnel-request"];
    } catch {
      local = false;
    }
    if (!local) return refuse(res, 404, "not_found");

    let db = null;
    try {
      // b. MAIL_HOOK_TOKEN's hash only. A database that cannot be opened cannot validate anything,
      //    so it is the same refusal as a wrong token.
      try { db = createDbClient(); } catch { db = null; }
      if (db == null) return refuse(res, 401, "bad_token");
      const token = bearerToken(req.headers);
      let valid = false;
      if (token) {
        try { valid = (await MAIL_HOOK_TOKEN.validate(db, token)) === true; } catch { valid = false; }
      }
      if (!valid) return refuse(res, 401, "bad_token");

      // c. The id, then the row. Only an account the supervisor would itself sync (`active`) is
      //    accepted; a read failure is refused, never read as an unknown account that still syncs.
      const accountId = readAccountId(req.body);
      if (!accountId) return refuse(res, 400, "bad_request");
      let account = null;
      try { account = await getAccount(db, accountId); } catch { account = null; }
      if (!account || account.status !== "active") return refuse(res, 404, "unknown_account");

      // d. The mail runtime. Without it there is no worker to start.
      let supervisor = null;
      try { supervisor = getSupervisor(); } catch { supervisor = null; }
      if (!supervisor || typeof supervisor.syncNow !== "function") return refuse(res, 503, "mail_off");

      // e. Fire and forget, with no write context: the sync outlives this request, exactly as the
      //    dashboard's startBackgroundSync opens it. A rejection is logged by account id only.
      withoutWriteContext(() => {
        Promise.resolve()
          .then(() => supervisor.syncNow(accountId))
          .catch(() => {
            try { log.warn(`[${REFUSAL_TAG}] sync rejected for ${accountId}`); } catch { /* a log line is never a response */ }
          });
      });
      return res.status(202).json({ ok: true });
    } finally {
      try { db?.close?.(); } catch { /* already closed is the only close failure here */ }
    }
  }

  router.post(MAIL_SYNC_HOOK_PATH, jsonParser, (req, res) => {
    handle(req, res).catch(() => {
      // A throw that escaped every step is still a refusal, never a 500 carrying text.
      refuse(res, 404, "not_found");
    });
  });

  return router;
}

export default mailSyncHookRouter;