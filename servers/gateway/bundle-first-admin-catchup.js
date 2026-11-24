/**
 * The boot CATCH-UP for first-admin setup (the operator's ruling: an app's admin setup
 * happens automatically, with no click, also for apps installed before it existed).
 *
 * The install path runs a `crow`/`via: "setup"` bundle's script once, right after
 * `compose up` succeeded (routes/bundles.js, runFirstAdminSetup). Two kinds of install never
 * got that run:
 *   - apps installed BEFORE the version that shipped the automatic setup, and
 *   - apps whose containers were not up yet at install time (the run answered "not-running").
 * Both used to wait for the operator to press "Set it up for me" on the Extensions card.
 * Once per gateway boot, after the add-ons have settled, this pass walks installed.json and
 * gives each of them exactly the run the card's button would start.
 *
 * Every gate is a silent skip, never a failure:
 *   - the installed entry is not satellite-hosted (its tools, and its setup, are another
 *     box's business) — the same rule the card uses, plus the add-on's own transport;
 *   - the REVIEWED manifest (getManifest, never the installed copy) declares a setup script
 *     Crow may run (firstAdminSetupPlan, not refused), and is not an invite-only app (whose
 *     card is decided by its own admin API, never by a script);
 *   - the keychain does NOT already hold this bundle's admin login — neither under the
 *     manifest's admin key (firstAdminSavedKey, the same check the card uses to decide there
 *     is nothing left to ask) nor under the setup plan's own `secretEnv`, which can be a
 *     different entry name (the two stay in step with the run's own "already saved" answer);
 *   - `first_admin_auto:<id>` has no result for THIS install (installedAt), except
 *     "not-running" (exit 4: the app was not up), which is retried on the next boot only.
 *     "ok", "kept" and "failed" are never re-run automatically: a failed run stays on the
 *     card's button, where the operator can read why;
 *   - the app is running (composeServiceRunning, the same question the install path asks
 *     before it runs the script);
 *   - the per-bundle lock is free (tryBeginFirstAdminSetup, the set the install path and the
 *     card share): a run already in flight is skipped silently, because it will record its
 *     own result.
 *
 * The run is the card route's own code path: runFirstAdminSetup with the same arguments and
 * the reviewed manifest/script, under the lock this pass took (holdsLock). When the manifest
 * also declares `firstAdmin.setup.after`, that step runs exactly as the route runs it
 * (applyFirstAdminAfter with the guarded recreate, which needs no request); a failure rings
 * the same one bell the route rings, because the card itself is already hidden by the login
 * the run just saved. A follow-up step that a caller cannot perform (no recreate seam) is
 * left to the card instead of being half-applied. That recreate WAITS for a start of the same
 * add-on in flight, so it can outlive the install it started for: when the owner uninstalled
 * and reinstalled the add-on meanwhile, this pass drops the run (no bell, nothing named) — the
 * new install runs its own setup — with one line on the console. The same check runs BEFORE the
 * after-step writes its env into the bundle's .env, so that write never lands in a newer install.
 *
 * A run that wrote the bundle's mcp-addons.json entry (mcpEnvUpdated) reconnects that add-on
 * the way the API-token catch-up does after it saves a token, so its MCP child picks the new
 * login up WITHOUT a gateway restart. Nothing here ever restarts the gateway: a restart at
 * boot would kill whatever install job is running.
 *
 * A run that really CREATED the login ("ok", and not the run's own `alreadySaved` answer, which
 * changed nothing) also tells the owner, once per install (reportChanged → the "Crow set the
 * admin password" bell): a catch-up can replace a password an app or a device has used for
 * months, and nothing else would say so. That bell carries no password and no log line.
 *
 * NEVER throws, and never logs or returns a password: the only values that leave are bundle
 * ids and the run's own result word.
 */
import { join } from "node:path";
import { installStampOf } from "./bundle-api-token.js";
import { applyFirstAdminAfter, firstAdminAfterPlan } from "./bundle-first-admin-after.js";
import { firstAdminAutoKey, reportFirstAdminNotice, reportFirstAdminPasswordChanged } from "./bundle-first-admin.js";
import {
  endFirstAdminSetup,
  firstAdminSetupPlan,
  runFirstAdminSetup,
  tryBeginFirstAdminSetup,
} from "./bundle-first-admin-setup.js";
import { firstAdminSavedKey } from "./dashboard/shared/first-admin.js";

/** One `dashboard_settings` marker value, parsed — null when it is missing or unreadable. */
function parseMarker(raw) {
  if (typeof raw !== "string" || raw.trim() === "") return null;
  try {
    const v = JSON.parse(raw);
    return v && typeof v === "object" && !Array.isArray(v) ? v : null;
  } catch {
    return null;
  }
}

/** The one line this pass may write about a bundle it deliberately did not finish. */
const afterStepSkippedLine = (id) =>
  `[first-admin] ${id}: the follow-up step needs a container restart this run cannot do; the Extensions card can do it`;

/** The one line for a run whose install was replaced under it (before or after the wait). */
const reinstallLine = (id) =>
  `[first-admin] catch-up: ${id} was reinstalled or removed while it waited; the new install runs its own setup`;

/**
 * Whether this run's install is STILL the installed one: the entry exists and carries the same
 * install stamp (`installStampOf`). A throw answers false — nothing here may be attributed to
 * an install it cannot read.
 */
async function stillSameInstall(id, installAt, seam) {
  try {
    const installed = await (await seam("listInstalled"))();
    const entry = (Array.isArray(installed) ? installed : []).find((i) => i && i.id === id);
    return !!entry && installStampOf(entry) === installAt;
  } catch {
    return false;
  }
}

/**
 * The catch-up's real seams. Built lazily and memoised by the caller: a test that injects
 * every seam never loads the database, the routes module or the config module.
 *
 * Exported so the gateway's boot wiring (boot/post-listen.js) hands runFirstAdminCatchUp
 * these and not a second copy of them.
 */
export async function firstAdminCatchUpDeps() {
  const [{ readFileSync }, config, core] = await Promise.all([
    import("node:fs"),
    import("./bundles-config.js"),
    import("./bundle-core.js"),
  ]);
  // One settings client for the whole pass, opened on first use and closed by the caller.
  let handle = null;
  const db = async () => {
    if (!handle) {
      const { createDbClient } = await import("../db.js");
      handle = createDbClient();
    }
    return handle;
  };
  const mcpEntry = (id) => {
    try {
      const all = JSON.parse(readFileSync(config.MCP_ADDONS_PATH, "utf8"));
      const entry = all && typeof all === "object" ? all[id] : null;
      return entry && typeof entry === "object" ? entry : null;
    } catch {
      return null;
    }
  };
  return {
    appBundles: () => config.APP_BUNDLES,
    bundlesDir: () => config.BUNDLES_DIR,
    crowHome: () => config.CROW_HOME,
    setupDeps: () => ({}),
    listInstalled: () => core.readInstalled(core.installedPath(config.CROW_HOME)),
    getManifest: (id) => config.getManifest(id),
    readSetting: async (key) => {
      try {
        const client = await db();
        const { rows } = await client.execute({ sql: "SELECT value FROM dashboard_settings WHERE key = ?", args: [key] });
        const value = rows?.[0]?.value;
        return value === undefined || value === null ? null : String(value);
      } catch {
        return null;
      }
    },
    mcpTransport: (id) => {
      const entry = mcpEntry(id);
      return entry && typeof entry.transport === "string" ? entry.transport : "stdio";
    },
    // Metadata only: an active extension entry for this bundle + key, whatever key sealed it.
    // The same row firstAdminSavedBundleIds reads for the card.
    hasAdminSaved: async (id, envKey) => {
      try {
        const client = await db();
        const { rows } = await client.execute({
          sql: "SELECT 1 FROM crow_keychain WHERE kind = 'extension' AND status = 'active' AND bundle_id = ? AND env_key = ? LIMIT 1",
          args: [id, envKey],
        });
        return (rows || []).length > 0;
      } catch {
        // A home that never held a secret has no table: that is no row, not a failure.
        return false;
      }
    },
    // A failed `ps` answers true (bundle-core): the script's own exit 4 is the real answer
    // then, and a missing run is the worse error than one that finds the app down.
    appRunning: async (id) => core.composeServiceRunning(join(config.BUNDLES_DIR, id), { crowHome: config.CROW_HOME }),
    tryBegin: (id) => tryBeginFirstAdminSetup(id),
    end: (id) => endFirstAdminSetup(id),
    runSetup: (o) => runFirstAdminSetup(o),
    applyAfter: (o) => applyFirstAdminAfter(o),
    // The same guarded recreate the card route's after-step uses: it needs no request (it is
    // the path the shared-storage re-apply also uses), so it is safe from the boot pass.
    // WAIT, not refuse: this pass runs once per boot and has NO retry, so a recreate skipped
    // because a start of the same add-on was in flight would leave the app's sign-ups open
    // until the next boot. It queues behind that run instead (bounded: a timeout comes back
    // as ok:false, which rings the existing after-failure bell). The wait holds only THIS
    // add-on: boot runs one catch-up pipeline per add-on (bundle-boot-catchups.js), so a
    // busy add-on's queue never delays another add-on's catch-up.
    // opts is the caller's per-run binding (catchUpOne passes `{ installStamp }`: the install
    // this run started for). The wait policy is ours and always applied.
    recreate: async (id, opts = {}) => {
      const { recreateBundleGuarded } = await import("./routes/bundles.js");
      return recreateBundleGuarded(id, { ...opts, onBusy: "wait" });
    },
    reconnect: async (id) => {
      const proxy = await import("./proxy.js");
      return proxy.reconnectAddonServer(id);
    },
    reportAfterFailure: (o) => reportFirstAdminNotice(o),
    reportChanged: (o) => reportFirstAdminPasswordChanged(o),
    warn: (m) => console.warn(m),
    close: async () => {
      try { handle?.close?.(); } catch { /* already closed */ }
      handle = null;
    },
  };
}

/**
 * One bundle's catch-up. Returns the run's result word, or null when a gate skipped it.
 * Throws only into runFirstAdminCatchUp's per-bundle catch; the lock is always released.
 */
async function catchUpOne(id, entry, seam) {
  // Hosted elsewhere: its own box's admin setup, not this one's (the card's own rule), and the
  // add-on's transport says the same thing from the MCP side.
  if (String((entry && entry.mode) || "").toLowerCase() === "satellite") return null;

  const manifest = await (await seam("getManifest"))(id);
  if (!manifest || typeof manifest !== "object") return null;
  // An invite-only app's card — and its setup — is decided by its own admin API: a setup
  // script is not how that app's admin comes to exist.
  const fa = manifest.firstAdmin && typeof manifest.firstAdmin === "object" ? manifest.firstAdmin : null;
  if (fa && fa.invite) return null;
  const plan = firstAdminSetupPlan(manifest);
  if (!plan || plan.refused) return null;

  const transport = String((await (await seam("mcpTransport"))(id)) ?? "").toLowerCase();
  if (transport === "satellite") return null;

  // A login the keychain already holds is the card's own "nothing left to ask" signal: the
  // operator may have saved a working one by hand, or an earlier run already made it.
  const savedKey = firstAdminSavedKey(manifest);
  if (savedKey && (await (await seam("hasAdminSaved"))(id, savedKey))) return null;
  // The run itself skips when the keychain holds the plan's `secretEnv`, which can differ
  // from the manifest's admin key: checking it here too (rather than only trusting the run's
  // answer) keeps the pass from taking the lock and recreating a container every boot.
  if (plan.secretEnv && plan.secretEnv !== savedKey && (await (await seam("hasAdminSaved"))(id, plan.secretEnv))) return null;

  const installAt = installStampOf(entry);
  const prior = parseMarker(await (await seam("readSetting"))(firstAdminAutoKey(id)));
  const recorded = prior && typeof prior.result === "string" && (prior.install ?? null) === (installAt ?? null)
    ? prior.result
    : null;
  // One run per install, except "the app was not up" — that one is retried next boot only.
  if (recorded && recorded !== "not-running") return null;

  // The app has to be up: a script that talks to a stopped app can only fail. The next boot
  // asks again (nothing is recorded for this answer).
  let running = false;
  try { running = !!(await (await seam("appRunning"))(id)); } catch { running = false; }
  if (!running) return null;

  // The same lock the install path and the card take. A run already in flight is skipped
  // silently: it records its own result.
  const begin = await seam("tryBegin");
  const end = await seam("end");
  if (!begin(id)) return null;

  const destDir = join((await seam("bundlesDir"))(), id);
  let run;
  try {
    run = await (await seam("runSetup"))({
      bundleId: id,
      manifest,
      // Crow's OWN copy of the bundle decides what runs (the installed folder can be mounted
      // into the bundle's container); it is only the working directory.
      scriptDir: join((await seam("appBundles"))(), id),
      destDir,
      installId: installAt,
      crowHome: (await seam("crowHome"))() || null,
      // This pass already took the lock above: the run must not take it a second time (it is a
      // Set, so a second take would answer "busy" and nothing would ever run).
      holdsLock: true,
      deps: (await seam("setupDeps"))() || {},
    });
  } finally {
    try { await end(id); } catch { /* the lock is a Set: a failed release changes nothing else */ }
  }

  const result = run && typeof run.result === "string" ? run.result : "failed";
  // "busy" means another run started between the check and ours: it owns the answer, and
  // nothing was recorded by either of us.
  if (result === "busy") return null;

  // The login was already in the keychain: the run changed NOTHING (no script, no marker), so
  // there is nothing to reconnect, no follow-up step to apply — a container recreate on every
  // boot is exactly what this answer exists to prevent — and no password change to announce.
  if (run && run.alreadySaved) return "ok";

  // The login also went into the bundle's mcp-addons.json entry, which an MCP child reads
  // only when it is spawned: reconnect that add-on ONCE here (what the API-token catch-up
  // does after saving a token) instead of asking for a gateway restart.
  if (run && run.mcpEnvUpdated) {
    try { await (await seam("reconnect"))(id); } catch { /* the login is saved either way */ }
  }

  // The manifest's follow-up step ("Crow creates, then closes"), exactly as the card route
  // runs it: only once the app really holds Crow's password, and never at the cost of the
  // account. Its own failure rings the same one bell the route rings — the card is already
  // hidden by the login the run saved, so a bell is the only way the operator hears it.
  const afterPlan = result === "ok" ? firstAdminAfterPlan(manifest) : null;
  let after = null;
  if (afterPlan) {
    const recreate = await seam("recreate");
    if (afterPlan.recreate && typeof recreate !== "function") {
      try { (await seam("warn"))(afterStepSkippedLine(id)); } catch { /* console gone */ }
    } else {
      // The follow-up step WRITES the manifest's after-env into this bundle's .env, and its
      // recreate waits: checked BEFORE that write, so a reinstall meanwhile leaves the NEW
      // install's .env alone. The run belonged to an install that is gone; the new one runs
      // its own setup. (Only the after-step writes: the post-wait check below is unchanged.)
      if (!(await stillSameInstall(id, installAt, seam))) {
        try { (await seam("warn"))(reinstallLine(id)); } catch { /* console gone */ }
        return null;
      }
      try {
        after = await (await seam("applyAfter"))({
          bundleId: id,
          manifest,
          destDir,
          // Bound to THIS install: a recreate that queued behind a start must not restart an
          // install the owner made meanwhile (recreateBundleGuarded answers code "reinstalled").
          recreate: typeof recreate === "function" ? (bid) => recreate(bid, { installStamp: installAt }) : null,
        });
      } catch {
        after = null;
      }
    }
  }

  // The recreate above can WAIT minutes for a start of this add-on in flight. If the owner
  // uninstalled and reinstalled the add-on within that wait, this run belongs to an install
  // that no longer exists: the new install runs its own setup, and neither the after-failure
  // bell nor "Crow set the admin password" may name the old one. One line, then nothing.
  if (!(await stillSameInstall(id, installAt, seam))) {
    try { (await seam("warn"))(reinstallLine(id)); } catch { /* console gone */ }
    return null;
  }

  if (after && after.ok === false) {
    try {
      await (await seam("reportAfterFailure"))({
        bundleId: id,
        manifest,
        bundleName: (typeof manifest.name === "string" && manifest.name) || id,
        installId: installAt,
        autoResult: result,
        afterResult: { ok: after.ok, outcome: after.outcome },
      });
    } catch { /* a bell that cannot be written never undoes anything */ }
  }

  // A run that really created the login replaces whatever the operator (or an app, or a phone
  // still pointed at this app) has been using: say so once for this install. The bell is the
  // last thing this pass does, it carries no password and no log, and its own failure is
  // swallowed like every other reporting seam here.
  if (result === "ok") {
    try {
      await (await seam("reportChanged"))({
        bundleId: id,
        manifest,
        bundleName: (typeof manifest.name === "string" && manifest.name) || id,
        installId: installAt,
      });
    } catch { /* a bell that cannot be written never undoes anything */ }
  }
  return result;
}

/**
 * The catch-up for EXISTING installs: once per gateway boot, after the add-ons have settled,
 * give every installed bundle whose app can be given its admin by a script that admin — the
 * install path ran the step only from the version that shipped it, so an install made before
 * it (or one whose app was not up yet) never got one.
 *
 * Gates: see the module comment. NEVER throws, and never logs or returns a password.
 *
 * @param {object} [o]
 * @param {object} [o.deps] seams: listInstalled, getManifest, readSetting, mcpTransport,
 *                          hasAdminSaved, appRunning, tryBegin, end, runSetup, applyAfter,
 *                          recreate, reconnect, reportAfterFailure, reportChanged, warn,
 *                          appBundles, bundlesDir, crowHome, setupDeps, close
 * @param {string} [o.onlyId] process exactly this installed entry (the boot wiring runs one
 *                          such pass per add-on, so a wait in one add-on's step — the
 *                          recreate seam waits for a start in flight — holds only that
 *                          add-on). Every other entry is left to its own pass.
 * @returns {Promise<{checked: number, ran: Array<{id: string, result: string}>}>}
 */
export async function runFirstAdminCatchUp({ deps = {}, onlyId = null } = {}) {
  const only = typeof onlyId === "string" && onlyId ? onlyId : null;
  const injected = deps && typeof deps === "object" ? deps : {};
  let real = null;
  const seam = async (name) => {
    if (injected[name] !== undefined) return injected[name];
    if (!real) real = await firstAdminCatchUpDeps();
    return real[name];
  };
  const summary = { checked: 0, ran: [] };
  try {
    let installed = [];
    try { installed = (await (await seam("listInstalled"))()) || []; } catch { installed = []; }
    for (const entry of Array.isArray(installed) ? installed : []) {
      const id = entry && typeof entry.id === "string" ? entry.id : "";
      if (!id) continue;
      if (only && id !== only) continue;
      summary.checked += 1;
      try {
        const result = await catchUpOne(id, entry, seam);
        if (result) summary.ran.push({ id, result });
      } catch {
        // One bundle's failure never stops the others (and never escapes this function).
      }
    }
  } catch {
    /* nothing installed, no readable list: nothing to catch up */
  } finally {
    try { await (injected.close ? injected.close() : real?.close?.()); } catch { /* already closed */ }
  }
  return summary;
}