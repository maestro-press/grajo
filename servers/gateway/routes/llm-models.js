// servers/gateway/routes/llm-models.js
/**
 * Lifecycle API for programs (spec §5.2): pi-lab and the board start, stop
 * and inspect local models through the owning gateway. Bearer auth: the full
 * local MCP token OR the path-scoped models token (<CROW_HOME>/models-token),
 * and never on a socket the egress relay opened — both hashes live in
 * bot-writable crow.db, and a relayed bot's model door is /llm/v1, /llm/p and
 * /llm/c (servers/shared/bot-doors.js isRelayedSocket).
 * Mounted beside /llm/v1 with no dashboard auth; Funnel-rejected globally.
 *
 * The lifecycle itself lives in models/lifecycle-core.js, shared with the
 * dashboard-session door in routes/models.js (/api/models/providers/*); both
 * default to the one process-wide job store (sharedJobStore). This file only
 * owns the transport: paths, bearer auth, Funnel refusal and the
 * `{ error: { code, message } }` envelope.
 */
import express from "express";
import { createDbClient } from "../../db.js";
import { validateLocalToken, validateModelsToken } from "../local-token.js";
import { isRelayedSocket } from "../../shared/bot-doors.js";
import { createLifecycleCore } from "../models/lifecycle-core.js";
import { defaultLifecycleDeps } from "../models/lifecycle-deps.js";
import { requesterTag } from "../requester-tag.js";

export default function llmModelsRouter(opts = {}) {
  let _db = null;
  const db = () => (_db ||= createDbClient());
  const { authFn, loadProvidersFn, ...rest } = opts;
  const deps = {
    ...defaultLifecycleDeps(),
    ...(loadProvidersFn ? { providersFn: () => (loadProvidersFn() || {}).providers || {} } : {}),
    ...rest,
  };
  const auth = authFn || (async (token) => (await validateLocalToken(db(), token)) || (await validateModelsToken(db(), token)));
  const core = createLifecycleCore(deps);
  const router = express.Router();
  router.use("/llm/models", (req, res, next) => {
    if (req.headers["tailscale-funnel-request"]) return res.status(403).json({ error: { code: "FUNNEL_REFUSED", message: "/llm is never reachable through Funnel" } });
    next();
  });
  router.use("/llm/models", express.json({ limit: "1mb" }));

  router.use("/llm/models", async (req, res, next) => {
    const h = req.headers.authorization || "";
    const token = h.startsWith("Bearer ") ? h.slice(7) : null;
    // Starting, stopping and inspecting this box's models is lifecycle (owner)
    // authority, and both tokens that open it here have their verifier in
    // bot-writable crow.db (`mcp_local_token_hash`, `mcp_models_token_hash`): a
    // contained bot has crow.db bound read-write, so it could write one of them
    // and then present its own value. A socket the egress relay opened therefore
    // never authenticates on this rail at all — exactly the rule
    // localTokenAuthMiddleware applies to the full local token
    // (servers/gateway/local-token.js). The bots' own model door is /llm/v1 and
    // /llm/p (its source rule, no bearer) plus /llm/c (its own token); none of
    // them is here.
    const relayed = isRelayedSocket(req.socket);
    try {
      if (token && !relayed && (await auth(token))) return next();
    } catch (err) {
      console.warn(`[llm-models] auth check failed: ${err.message}`);
    }
    res.status(401).json({ error: { code: "UNAUTHENTICATED", message: "bearer token required (local MCP token or CROW_HOME/models-token)" } });
  });

  // 2xx bodies pass through; refusals and failures wrap as { error: {...} }.
  const send = (res, { status, body }) => res.status(status).json(status >= 400 ? { error: body } : body);

  router.get("/llm/models", (req, res) => res.json({ models: core.listing() }));
  router.post("/llm/models/:provider/start", (req, res) => send(res, core.start(req.params.provider, requesterTag(req))));
  router.get("/llm/models/jobs/:id", (req, res) => send(res, core.job(req.params.id)));
  router.post("/llm/models/:provider/stop", async (req, res) => send(res, await core.stop(req.params.provider, requesterTag(req))));

  return router;
}
