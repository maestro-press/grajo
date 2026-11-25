/**
 * F4a Layer 3 — owner-side cross-instance bot edit/run endpoints.
 *
 * Mounted under /dashboard/bot-federation/* behind federationVerifyMiddleware
 * (HMAC). Every handler re-checks botPeerManageable(db, botId) — the gate is
 * authoritative; the HMAC middleware only proves the caller is a known peer.
 * Secrets never cross the wire (redactDefForPeer); only allowlisted non-secret
 * fields are writable (applyPeerPatch). Under /dashboard → Funnel-blocked;
 * never add to PUBLIC_FUNNEL_PREFIXES.
 */
import { Router } from "express";
import { botPeerManageable } from "../bot-management-exposure.js";
import { redactDefForPeer, applyPeerPatch } from "../bot-federation.js";
import { regenerateBotMcp as defaultRegen } from "../dashboard/panels/bot-mcp-regen.js";
import { auditCrossHostCall } from "../../shared/cross-host-auth.js";
import { getOrCreateLocalInstanceId } from "../instance-registry.js";
import { writeBotDef, setBotEnabled } from "../../shared/bot-def-store.js";

/** Factory so tests can inject db + regen. */
export function makeBotFederationHandlers({ db, regenerateBotMcp = defaultRegen, auditFn = auditCrossHostCall }) {
  async function loadDef(botId) {
    const row = (await db.execute({
      sql: "SELECT definition, enabled, project_id FROM pi_bot_defs WHERE bot_id=?",
      args: [botId],
    })).rows[0];
    if (!row) return null;
    let def = {};
    try { def = JSON.parse(row.definition || "{}"); } catch { def = {}; }
    // `definition`, `enabled` and `project_id` are returned as READ: they are the compare-and-swap
    // the write path takes (a peer edit refuses rather than clobbers a newer save).
    return {
      def,
      definition: row.definition ?? null,
      enabled: row.enabled,
      project_id: row.project_id ?? null,
    };
  }

  async function audit(req, action, botId, httpStatus, error) {
    let localId = null;
    try { localId = getOrCreateLocalInstanceId(); } catch { /* best-effort */ }
    const source = req.headers?.["x-crow-source"] || null;
    try {
      await auditFn(db, {
        sourceInstanceId: source,
        targetInstanceId: localId,
        direction: "inbound",
        action,
        bundleId: botId,
        actor: source ? `instance:${source}` : null,
        httpStatus,
        error: error || null,
      });
    } catch { /* audit must never break the path */ }
  }

  return {
    async getDef(req, res) {
      const botId = req.params.botId;
      if (!(await botPeerManageable(db, botId))) {
        await audit(req, "federation.bot.def", botId, 403, "not_manageable");
        return res.status(403).json({ error: "not_manageable" });
      }
      const row = await loadDef(botId);
      if (!row) {
        await audit(req, "federation.bot.def", botId, 404, "bot_not_found");
        return res.status(404).json({ error: "bot_not_found" });
      }
      await audit(req, "federation.bot.def", botId, 200, null);
      return res.type("application/json").send(JSON.stringify({ bot_id: botId, definition: redactDefForPeer(row.def) }));
    },

    async patch(req, res) {
      const botId = req.params.botId;
      if (!(await botPeerManageable(db, botId))) {
        await audit(req, "federation.bot.patch", botId, 403, "not_manageable");
        return res.status(403).json({ error: "not_manageable" });
      }
      const row = await loadDef(botId);
      if (!row) {
        await audit(req, "federation.bot.patch", botId, 404, "bot_not_found");
        return res.status(404).json({ error: "bot_not_found" });
      }
      const patch = (req.body && req.body.patch) || {};
      let merged;
      try { merged = applyPeerPatch(row.def, patch); }
      catch (e) {
        await audit(req, "federation.bot.patch", botId, 400, "field_not_patchable");
        return res.status(400).json({ error: "field_not_patchable", detail: String(e.message || e) });
      }
      const toolsChanged = Object.keys(patch).some((k) => k.startsWith("tools.") || k === "skills");
      // The ONE write path (servers/shared/bot-def-store.js): the row's keyed MAC covers the
      // definition and the project_id column, so a peer edit is signed exactly like an owner's.
      // A write that lands 0 rows — a stale compare-and-swap because the bot was saved meanwhile (by
      // the owner, another peer, or a bot-definition write) — OR that is refused because the row does
      // not verify (`BOT_DEF_UNVERIFIED`: it was changed outside Crow) is the route's EXISTING conflict
      // answer, never a silent success: the peer's patch did not apply.
      let written;
      try {
        written = await writeBotDef(db, {
          bot_id: botId,
          definition: merged,
          expectDefinition: row.definition ?? null,
          expectEnabled: row.enabled,
          expectProjectId: row.project_id ?? null,
        });
      } catch (err) {
        if (err && err.code === "BOT_DEF_UNVERIFIED") {
          await audit(req, "federation.bot.patch", botId, 409, "unverified");
          return res.status(409).json({ error: "stale", detail: "the bot changed meanwhile; fetch it again and re-apply the patch" });
        }
        throw err;
      }
      if (Number(written && written.rowsAffected) === 0) {
        await audit(req, "federation.bot.patch", botId, 409, "stale");
        return res.status(409).json({ error: "stale", detail: "the bot changed meanwhile; fetch it again and re-apply the patch" });
      }
      let mcp = null;
      if (toolsChanged) {
        try { mcp = await regenerateBotMcp(db, botId); }
        catch (e) {
          console.warn("[bot-federation] mcp regen failed for", botId, ":", e.message);
          mcp = { error: String(e.message || e) };
        }
      }
      await audit(req, "federation.bot.patch", botId, 200, null);
      return res.json({ ok: true, regenerated: toolsChanged, mcp: mcp && !mcp.error ? { path: mcp.path, servers: mcp.servers } : mcp });
    },

    async setEnabled(req, res) {
      const botId = req.params.botId;
      if (!(await botPeerManageable(db, botId))) {
        await audit(req, "federation.bot.enabled", botId, 403, "not_manageable");
        return res.status(403).json({ error: "not_manageable" });
      }
      const row = await loadDef(botId);
      if (!row) {
        await audit(req, "federation.bot.enabled", botId, 404, "bot_not_found");
        return res.status(404).json({ error: "bot_not_found" });
      }
      const enabled = req.body && Number(req.body.enabled) ? 1 : 0;
      // `enabled` is inside the definition's MAC (servers/shared/bot-def-store.js `setBotEnabled`),
      // and a partial write states the row it read (round D, item F1): a peer toggle over a row that
      // moved or does not verify is refused, never signed blind.
      let written;
      try {
        written = await setBotEnabled(db, botId, enabled, {
          expectDefinition: row.definition ?? null,
          expectEnabled: row.enabled,
          expectProjectId: row.project_id ?? null,
        });
      } catch (err) {
        if (err && err.code === "BOT_DEF_UNVERIFIED") {
          await audit(req, "federation.bot.enabled", botId, 409, "unverified");
          return res.status(409).json({ error: "stale", detail: "the bot changed meanwhile; fetch it again and retry" });
        }
        throw err;
      }
      if (Number(written && written.rowsAffected) === 0) {
        await audit(req, "federation.bot.enabled", botId, 409, "stale");
        return res.status(409).json({ error: "stale", detail: "the bot changed meanwhile; fetch it again and retry" });
      }
      await audit(req, "federation.bot.enabled", botId, 200, null);
      return res.json({ ok: true, enabled });
    },
  };
}

/** Build an Express router for the three routes (relative to the /dashboard mount). */
export function botFederationRouter({ createDbClient, verifyMiddleware }) {
  const router = Router();
  const wrap = (name) => async (req, res) => {
    const db = createDbClient();
    try { await makeBotFederationHandlers({ db })[name](req, res); }
    catch (err) { if (!res.headersSent) res.status(500).json({ error: "bot_federation_failed" }); }
    finally { db.close(); }
  };
  router.get("/bot-federation/def/:botId", verifyMiddleware, wrap("getDef"));
  router.post("/bot-federation/patch/:botId", verifyMiddleware, wrap("patch"));
  router.post("/bot-federation/enabled/:botId", verifyMiddleware, wrap("setEnabled"));
  return router;
}
