/**
 * The two boot CATCH-UPS, run as one PIPELINE PER ADD-ON.
 *
 * Once per gateway boot, after the add-ons have settled, two passes give an existing install
 * what the install path would have:
 *   1. bundle-first-admin-catchup.js — the app's admin login, from the bundle's setup script;
 *   2. bundle-api-token.js — the API token that app mints for Crow.
 * A token's script signs in with the admin the first pass just made, so within ONE add-on the
 * order is fixed: first-admin, then token.
 *
 * Across add-ons nothing depends on anything, and that is what this module exists for. The
 * first-admin pass' after-step recreates the app's container through the guarded recreate,
 * which WAITS when that add-on already has a start (or recreate) in flight — up to ten minutes.
 * Walking the whole installed list in one chain (as boot used to) meant one busy add-on held up
 * every other add-on's first-admin catch-up and then ALL token catch-ups: up to N × 10 min.
 * Here each add-on gets its own pipeline, the pipelines run concurrently under a small cap, and
 * a wait in one holds only that add-on.
 *
 * Never throws and never rejects: every step is caught on its own, so a failure in one add-on —
 * or in one add-on's first-admin step — never costs another pipeline or that add-on's token
 * step. Fire-and-forget from boot: nothing on the listen/request path awaits this.
 *
 * Log lines are the ones the passes always wrote (`[first-admin] catch-up: <id> <result>`,
 * `[api-token] catch-up: <id> <result>`, and the `… catch-up skipped: <reason>` warnings); ids
 * and result words only, never anything a pass handled.
 */

/** How many add-on pipelines may be in flight at once (a big install must not open dozens of DB handles). */
export const BOOT_CATCHUP_CONCURRENCY = 4;

/**
 * The ids in installed.json — the same list the two passes themselves walk (bundle-core's
 * readInstalled over the configured home). An unreadable list is no ids, never a failure.
 */
async function installedIds() {
  try {
    const [config, core] = await Promise.all([
      import("./bundles-config.js"),
      import("./bundle-core.js"),
    ]);
    const installed = core.readInstalled(core.installedPath(config.CROW_HOME));
    return (Array.isArray(installed) ? installed : [])
      .map((entry) => (entry && typeof entry.id === "string" ? entry.id : ""))
      .filter(Boolean);
  } catch {
    return [];
  }
}

/** The real first-admin step: the module's own wiring, one run for one add-on. */
async function firstAdminStep({ onlyId }) {
  const { runFirstAdminCatchUp, firstAdminCatchUpDeps } = await import("./bundle-first-admin-catchup.js");
  return runFirstAdminCatchUp({ deps: await firstAdminCatchUpDeps(), onlyId });
}

/** The real token step: the module's own wiring, one run for one add-on. */
async function apiTokenStep({ onlyId }) {
  const { runApiTokenCatchUp, apiTokenCatchUpDeps } = await import("./bundle-api-token.js");
  return runApiTokenCatchUp({ deps: await apiTokenCatchUpDeps(), onlyId });
}

/** `id result, id result` — the summary line both passes write, from one summary. */
function ranLine(summary) {
  const ran = summary && Array.isArray(summary.ran) ? summary.ran : [];
  if (!ran.length) return "";
  return ran.map((r) => `${r.id} ${r.result}`).join(", ");
}

/**
 * One add-on: its first-admin catch-up, then its token catch-up. Each step is caught on its
 * own, so a first-admin failure still leaves the token step its chance (it has its own gates)
 * and neither can reject into the pool.
 *
 * @param {string} id installed bundle id
 * @param {object} o
 * @param {(o: {onlyId: string}) => Promise<object>} o.firstAdmin
 * @param {(o: {onlyId: string}) => Promise<object>} o.apiToken
 * @param {{firstAdmin: Array, apiToken: Array}} o.summary collects the ran entries
 * @param {(m: string) => void} o.log
 * @param {(m: string) => void} o.warn
 */
async function pipelineFor(id, { firstAdmin, apiToken, summary, log, warn }) {
  try {
    const result = await firstAdmin({ onlyId: id });
    const line = ranLine(result);
    if (line) log(`[first-admin] catch-up: ${line}`);
    for (const r of (result && Array.isArray(result.ran) ? result.ran : [])) summary.firstAdmin.push(r);
  } catch (err) {
    warn(`[first-admin] catch-up skipped: ${err?.message || err}`);
  }
  try {
    const result = await apiToken({ onlyId: id });
    const line = ranLine(result);
    if (line) log(`[api-token] catch-up: ${line}`);
    for (const r of (result && Array.isArray(result.ran) ? result.ran : [])) summary.apiToken.push(r);
  } catch (err) {
    warn(`[api-token] catch-up skipped: ${err?.message || err}`);
  }
}

/**
 * Run the boot catch-ups: the settle gate first, then one first-admin→token pipeline per
 * installed add-on, at most `concurrency` at a time. Never throws.
 *
 * @param {object} [o]
 * @param {() => Promise<void>} [o.settled] the same gate the walls pass uses: the add-ons
 *                          have settled (bounded). A gate that fails skips the pass.
 * @param {() => Promise<string[]>|string[]} [o.listIds] the installed ids; defaults to
 *                          installed.json — the same list the passes themselves walk
 * @param {(o: {onlyId: string}) => Promise<object>} [o.firstAdmin] one add-on's first-admin pass
 * @param {(o: {onlyId: string}) => Promise<object>} [o.apiToken] one add-on's token pass
 * @param {number} [o.concurrency] pipelines in flight at once (default BOOT_CATCHUP_CONCURRENCY)
 * @param {(m: string) => void} [o.log] console.log by default
 * @param {(m: string) => void} [o.warn] console.warn by default
 * @returns {Promise<{firstAdmin: Array<{id: string, result: string}>, apiToken: Array<{id: string, result: string}>}>}
 */
export async function runBootCatchUps({
  settled = async () => {},
  listIds = installedIds,
  firstAdmin = firstAdminStep,
  apiToken = apiTokenStep,
  concurrency = BOOT_CATCHUP_CONCURRENCY,
  log = (m) => console.log(m),
  warn = (m) => console.warn(m),
} = {}) {
  const summary = { firstAdmin: [], apiToken: [] };
  try {
    await settled();
  } catch (err) {
    // Nothing is caught up on a boot whose add-ons never settled; next boot asks again. Both
    // passes were gated on this same answer, so it is reported once, in the first pass' words.
    try { warn(`[first-admin] catch-up skipped: ${err?.message || err}`); } catch { /* console gone */ }
    return summary;
  }

  let ids = [];
  try {
    const listed = await listIds();
    ids = [...new Set((Array.isArray(listed) ? listed : [])
      .map((id) => (typeof id === "string" ? id : ""))
      .filter(Boolean))];
  } catch (err) {
    try { warn(`[first-admin] catch-up skipped: ${err?.message || err}`); } catch { /* console gone */ }
    return summary;
  }

  // A small worker pool: each free worker takes the next add-on, so the cap bounds the
  // pipelines (and their DB handles) without serialising a large install.
  const queue = ids.slice();
  const take = () => (queue.length > 0 ? queue.shift() : null);
  const cap = Math.max(1, Math.min(Number.isInteger(concurrency) && concurrency > 0 ? concurrency : BOOT_CATCHUP_CONCURRENCY, queue.length || 1));
  const worker = async () => {
    for (let id = take(); id !== null; id = take()) {
      try {
        await pipelineFor(id, { firstAdmin, apiToken, summary, log, warn });
      } catch {
        // pipelineFor catches both steps itself; this is only belt and braces, so one add-on
        // can never take a worker (or the pool) down with it.
      }
    }
  };
  await Promise.all(Array.from({ length: cap }, worker));
  return summary;
}