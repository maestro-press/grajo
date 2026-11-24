/**
 * Provider registry loader + health matrix.
 *
 * Loads `models.json` from the same search paths as server.js and exposes:
 *   - loadProviders()             — returns the parsed providers map
 *   - probeProvider(name, cfg)    — liveness probe (GET /v1/models with timeout)
 *   - healthMatrix()              — probes all providers in parallel, returns a matrix
 *
 * Also exports an Express handler `providersHealthHandler` for mounting at
 * /api/providers/health. The handler is meant to sit behind dashboard auth.
 */

import { readFileSync, existsSync, statSync } from "fs";
import { createDbClient } from "../db.js";
import { repoModelsJsonSearchPaths } from "./models-json-paths.js";
import { guardedFetch } from "../gateway/ai/adapter-guard.js";

// -----------------------------------------------------------------------
// Cache layer — providers are read many times per orchestration; cache DB
// rows in-process and invalidate every 30s OR when upsertProvider is called.
// -----------------------------------------------------------------------

let _cache = null;
let _cacheLoadedAt = 0;
const CACHE_TTL_MS = 30_000;

/**
 * Force cache invalidation (called by upsertProvider / disableProvider).
 */
export function invalidateProvidersCache() {
  _cache = null;
  _cacheLoadedAt = 0;
}

/**
 * Load providers. Tries the DB first (Phase 5-full canonical source), then
 * falls back to models.json. Returns the same shape the orchestrator has
 * always expected: { providers, _source }.
 *
 * Sync mode: the orchestrator + providers-health.js + lifecycle.js all call
 * this in hot paths that can't easily be async. We maintain a cached snapshot
 * that's refreshed by an async warmer and return the cached copy here.
 */
export function loadProviders() {
  // Best-effort cache refresh if stale
  if (_cache && Date.now() - _cacheLoadedAt < CACHE_TTL_MS) return _cache;
  // Fire async refresh; return stale or fall back to models.json meanwhile
  refreshCache().catch(() => {});
  return _cache || loadFromModelsJson();
}

async function refreshCache() {
  try {
    const { loadProvidersFromDb } = await import("./providers-db.js");
    const db = createDbClient();
    const fromDb = await loadProvidersFromDb(db);
    if (fromDb && Object.keys(fromDb.providers).length > 0) {
      _cache = fromDb;
      _cacheLoadedAt = Date.now();
      return;
    }
  } catch {}
  _cache = loadFromModelsJson();
  _cacheLoadedAt = Date.now();
}

/**
 * Invalidate the cache AND await a real refresh before returning (Item G,
 * PR G-F, defect 2). `invalidateProvidersCache()` above only clears the
 * cache and leaves the next `loadProviders()` call to fire an un-awaited
 * background `refreshCache()` — fine for the common "somebody else will
 * call `loadProviders()` again eventually and see the update" case, but
 * wrong for a caller that's about to hand the row it just wrote to
 * something that needs to see it RIGHT NOW: a fresh native-model
 * registration followed immediately by the start route's
 * `maybeAcquireLocalProvider` -> `loadProviders()` lookup was invisible
 * for up to one DB round-trip, which `loadProviders()`'s synchronous
 * contract can never await — the lookup fell through to the stale/
 * models.json-fallback cache and 409'd `NOT_NATIVE` for a model that was
 * already durably registered.
 *
 * `loadProviders()` itself stays synchronous on purpose (see its doc —
 * many hot-path callers, e.g. the orchestrator, can't be made async), so
 * this is a separate, deliberately async sibling for the handful of
 * callers (today: `manager.js`'s `registerModel`) that CAN await —
 * they pass this as their `invalidateCacheFn` instead of the plain sync
 * `invalidateProvidersCache`.
 */
export async function invalidateAndRefreshProvidersCache() {
  invalidateProvidersCache();
  await refreshCache();
  return _cache;
}

function loadFromModelsJson() {
  for (const p of repoModelsJsonSearchPaths()) {
    try {
      const raw = readFileSync(p, "utf-8");
      const cfg = JSON.parse(raw);
      // Strip JSON-schema meta keys
      const providers = {};
      for (const [k, v] of Object.entries(cfg.providers || {})) {
        if (k.startsWith("$")) continue;
        const gpuPolicy = (v.mutexGroup || v.alwaysResident || v.defaultMember)
          ? { mutexGroup: v.mutexGroup ?? null, alwaysResident: !!v.alwaysResident, defaultMember: !!v.defaultMember }
          : null;
        providers[k] = {
          baseUrl: v.baseUrl,
          apiKey: v.apiKey,
          host: v.host,
          bundleId: v.bundleId,
          description: v.$description || v.description,
          models: v.models || [],
          gpuPolicy,
        };
      }
      return { providers, _source: p };
    } catch {
      // try next
    }
  }
  return { providers: {}, _source: null };
}

/**
 * Probe a single provider's /v1/models endpoint.
 * Returns { ok, status, latencyMs, models?, error? }.
 *
 * The row it reads (`base_url`, `api_key`) is bot-writable — a contained bot has
 * crow.db bound read-write — and this probe attaches the row's key, so it goes
 * through the same guard as every other request-time read of that row
 * (`gateway/ai/adapter-guard.js`, `kind: "probe"`): an own-host provider may be
 * probed at `/v1/models` only and never receives the key, a forbidden address
 * (link-local / cloud metadata) is refused, and a rebindable DNS name is
 * resolved once and pinned. A refused probe is just `{ ok: false, error }` — the
 * matrix keeps working, that provider reads as unreachable. `guard` is the
 * adapters' test seam.
 */
export async function probeProvider(name, cfg, { timeoutMs = 3000, guard } = {}) {
  const started = Date.now();
  const out = { name, baseUrl: cfg.baseUrl, host: cfg.host || "local" };

  if (!cfg.baseUrl) {
    return { ...out, ok: false, error: "no baseUrl" };
  }

  // Construct /v1/models URL from the provider's baseUrl
  // baseUrl is expected to be ".../v1" — append "/models"
  const url = cfg.baseUrl.replace(/\/+$/, "") + "/models";

  try {
    const headers = {};
    if (cfg.apiKey && cfg.apiKey !== "none") {
      headers.Authorization = `Bearer ${cfg.apiKey}`;
    }
    const res = await guardedFetch(url, {
      method: "GET",
      headers,
      signal: AbortSignal.timeout(timeoutMs),
      timeoutMs,
      guard: { ...guard, kind: "probe" },
    });
    const latencyMs = Date.now() - started;
    if (!res.ok) {
      return { ...out, ok: false, status: res.status, latencyMs, error: `http ${res.status}` };
    }
    let models = [];
    try {
      const body = await res.json();
      if (Array.isArray(body?.data)) {
        models = body.data.map((m) => m.id).filter(Boolean);
      }
    } catch {
      // Non-JSON response is still "ok" for liveness
    }
    return { ...out, ok: true, status: res.status, latencyMs, models };
  } catch (err) {
    const latencyMs = Date.now() - started;
    return {
      ...out,
      ok: false,
      latencyMs,
      error: err.name === "TimeoutError" ? "timeout" : String(err.message || err),
    };
  }
}

/**
 * Probe all providers in parallel.
 * @returns {Promise<{providers: Record<string, object>, summary: {total, ok, failed}, source: string|null}>}
 */
export async function healthMatrix({ timeoutMs = 3000 } = {}) {
  const cfg = loadProviders();
  const providers = cfg.providers || {};
  const names = Object.keys(providers);
  const results = await Promise.all(
    names.map((name) => probeProvider(name, providers[name], { timeoutMs }))
  );
  const map = {};
  let ok = 0;
  for (const r of results) {
    map[r.name] = r;
    if (r.ok) ok += 1;
  }
  return {
    source: cfg._source,
    summary: { total: names.length, ok, failed: names.length - ok },
    providers: map,
  };
}

/**
 * Express handler for GET /api/providers/health.
 * Honors ?timeout=<ms> query param (capped at 10000).
 */
export async function providersHealthHandler(req, res) {
  const q = Number(req.query?.timeout);
  const timeoutMs = Number.isFinite(q) ? Math.min(Math.max(q, 500), 10000) : 3000;
  try {
    const matrix = await healthMatrix({ timeoutMs });
    res.json(matrix);
  } catch (err) {
    res.status(500).json({ error: String(err.message || err) });
  }
}
