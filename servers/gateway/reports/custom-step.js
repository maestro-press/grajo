/**
 * The gateway's way into a report's custom step: every check that stands between an approved step and
 * the sandboxed runner, in the order they have to happen, and the run itself.
 *
 * A recipe's `custom` block (PR 4a) calls `runCustomStepForReport`; this module is the one place that
 * decides whether a step may run at all. It is not a block runner and it registers nothing: PR 4a wires
 * the block type to this function, and this module imports nothing under `mail/`, so no path from here
 * can reach a send.
 *
 * The order, and why:
 *   a. `runnableStep`: the NEWEST revision of that step key must be approved, sealed, and its assets
 *      the ones on disk. Anything else is `step_waiting` with the one sentence an owner reads.
 *   b. the cap: a run that is not the schedule counts ONE `extra_step_runs` for the report's day, taken
 *      with one conditional increment (`claimExtraStepRun`), and a claim that finds the cap used up is
 *      `cap_reached`. A manual run and a bot-requested preview both count; the scheduled run does not.
 *   c. the files and the hosts the approval covers are re-checked NOW: an asset swapped under it is
 *      `asset_changed`, a host whose seal no longer verifies is `host_unverified`. A step never runs
 *      with an asset or a host the owner did not approve.
 *   d. the bundle dir is written FRESH from the approved `files_json`, every path validated again here,
 *      into a 0700 tmp dir that is removed whatever happens.
 *   e. `ensureEnv`: the per-report, per-language env, built walled if it is not there yet.
 *   f. `runCustomStep`: the walled run. A `no_wall` answer notifies the owner AT MOST once per report
 *      per day (a `report_state` row keyed by the day is the dedupe), because one broken computer is one
 *      notice and not one per run.
 *
 * PR 4a: `trigger` is a caller's word today, and it decides whether a run counts against the day's
 * `extra_step_runs` cap. PR 4a MUST derive it from the server-side run row (the run it is executing for
 * the report's own row, never an argument a caller shapes); until then nothing else in this module can
 * tell a scheduled run from a manual one.
 *
 * Every error text this module returns passes through `redactSecrets` with this instance's secret
 * values, and no branch of it ever answers with a message from a child process.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir as osTmpdir } from "node:os";
import { dirname, isAbsolute, join, resolve, sep } from "node:path";

import { dayInTz, getCaps, claimExtraStepRun } from "./caps.js";
import {
  STEP_MAX_BUNDLE_BYTES,
  STEP_KEY_RE,
  injectRulesFor,
  runnableStep,
  verifyAssetOnDisk,
  verifyHost,
} from "./steps.js";
import { resolveCrowHome } from "../../shared/crow-home.js";
import { redactSecrets } from "../../shared/redact-secrets.js";
import { getSecretValues } from "../../shared/secret-values.js";
import { ensureEnv as ensureEnvFor } from "../../../scripts/report-steps/env.mjs";
import { NO_WALL_CODE, NO_WALL_TEXT, runCustomStep } from "../../../scripts/report-steps/runner.mjs";

/** The sentence an owner reads while a step's newest revision is not approved (the plan's words). */
export const stepWaitingText = (stepKey) => `Step ${stepKey} is waiting for your OK`;

/** A file path inside a bundle: relative, POSIX, no `..`, no leading `/`, no control character. */
const CONTROL_CHARS = /[\u0000-\u001f\u007f\u0080-\u009f\u2028\u2029]/;
const FILE_PATH_MAX = 200;

const fail = (code) => {
  const err = new Error(code);
  err.code = code;
  return err;
};

/** This instance's home, from the deps seam or the environment. */
function homeOf(deps) {
  if (typeof deps.crowHome === "function") {
    const value = deps.crowHome();
    if (typeof value === "string" && value) return value;
  }
  if (typeof deps.crowHome === "string" && deps.crowHome) return deps.crowHome;
  return resolveCrowHome();
}

/** The literal secret values an error text is scrubbed with. */
function secretsOf(deps) {
  if (typeof deps.getSecrets === "function") {
    try {
      const list = deps.getSecrets();
      if (Array.isArray(list)) return list;
    } catch {
      /* fall through to this instance's list */
    }
  }
  try {
    return getSecretValues();
  } catch {
    return [];
  }
}

/**
 * The day a cap is counted against: the caller's (`deps.day`), else today in the caller's zone
 * (`deps.timeZone`), else UTC. A cap counter must never throw because a stored zone stopped being valid,
 * and `dayInTz` already answers UTC for a zone it cannot read.
 */
function dayOf(deps, now) {
  if (typeof deps.day === "string" && /^\d{4}-\d{2}-\d{2}$/.test(deps.day)) return deps.day;
  return dayInTz(now, typeof deps.timeZone === "string" ? deps.timeZone : undefined);
}

/**
 * Write one bundle's files into a fresh dir, with every path validated AGAIN here: a row changed under
 * an approval, a crafted `files_json` or a path that resolves out of the dir writes nothing at all.
 *
 * @param {object|Map<string, string>} files path -> text, as `runnableStep` answers it
 * @param {string} dir
 * @returns {number} the bytes written
 * @throws {Error} `bad_input` for a path or a content this refuses, `too_large` past the bundle cap
 */
export function writeBundleDir(files, dir) {
  if (typeof dir !== "string" || !isAbsolute(dir)) throw fail("bad_input");
  let entries;
  if (files instanceof Map) entries = [...files.entries()];
  else if (files && typeof files === "object" && !Array.isArray(files)) entries = Object.entries(files);
  else throw fail("bad_input");
  if (entries.length === 0) throw fail("bad_input");
  const root = resolve(dir);
  let bytes = 0;
  for (const [path, content] of entries) {
    if (typeof path !== "string" || !path || path.length > FILE_PATH_MAX) throw fail("bad_input");
    if (CONTROL_CHARS.test(path) || path.includes("\\") || path.startsWith("/") || path.endsWith("/")) {
      throw fail("bad_input");
    }
    for (const segment of path.split("/")) {
      if (!segment || segment === "." || segment === "..") throw fail("bad_input");
    }
    if (typeof content !== "string") throw fail("bad_input");
    const target = resolve(root, path);
    if (target !== root && !target.startsWith(root.endsWith(sep) ? root : root + sep)) throw fail("bad_input");
    if (target === root) throw fail("bad_input");
    bytes += Buffer.byteLength(content, "utf8");
    if (bytes > STEP_MAX_BUNDLE_BYTES) throw fail("too_large");
    mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
    writeFileSync(target, content, { mode: 0o600 });
  }
  return bytes;
}

/**
 * The owner's one notice a day for a step that cannot run on this Crow. The `report_state` row is the
 * dedupe AND the claim: the insert is the only thing that decides, so two runs that reach it at once
 * produce one notice. No notifier means nothing is written at all.
 */
async function notifyNoWallOnce(db, deps, reportId, day, now) {
  const notify = deps.notifyOwner;
  if (typeof notify !== "function") return;
  const key = "step_no_wall:" + day;
  let claimed = false;
  try {
    const written = await db.execute({
      sql: `INSERT INTO report_state (report_id, key, value_json, updated_at)
            VALUES (?, ?, ?, ?)
            ON CONFLICT(report_id, key) DO NOTHING`,
      args: [reportId, key, JSON.stringify({ code: NO_WALL_CODE, day }), now],
    });
    claimed = Number(written?.rowsAffected ?? 0) === 1;
  } catch {
    return;
  }
  if (!claimed) return;
  try {
    await notify({ title: NO_WALL_TEXT, body: null, reportId });
  } catch {
    // A notice that cannot be written is not a run that must fail: the row already says it was sent.
  }
}

/**
 * Run one approved custom step of one report.
 *
 * @param {object} db
 * @param {object} deps the seam: `runStep` (the runner), `ensureEnv`, `notifyOwner`, `day`, `timeZone`,
 *   `now`, `crowHome`, `getSecrets`, plus everything the approvals and the runner take (`loadSeed`,
 *   `secrets`, `extraSecrets`, `nodeBin`, `prlimit`, ...). `relayOptions` and `testSeams` are NOT
 *   forwarded to the runner: they belong to a test harness that calls `runCustomStep` directly.
 * @param {{report: object, stepKey: string, input?: any, params?: any, trigger?: string}} run
 * @returns {Promise<{ok: true, output: object}|{ok: false, code: string, error: string}>}
 */
export async function runCustomStepForReport(db, deps = {}, { report, stepKey, input, params, trigger } = {}) {
  const seam = deps && typeof deps === "object" ? deps : {};
  const reportId = report && typeof report.id === "string" ? report.id : null;
  const redact = (value) => redactSecrets(String(value == null ? "" : value), secretsOf(seam));
  let bundleDir = null;
  try {
    if (!reportId) return { ok: false, code: "bad_input", error: "bad_input" };
    if (typeof stepKey !== "string" || !STEP_KEY_RE.test(stepKey)) {
      return { ok: false, code: "bad_input", error: "bad_input" };
    }
    const now = Number(typeof seam.now === "function" ? seam.now() : Date.now()) || Date.now();
    const home = homeOf(seam);
    // The approvals module reads its home and its clock the same way this module does.
    const stepDeps = { ...seam, crowHome: home };

    // (a) The newest revision must be approved and sealed, and its assets the ones on disk.
    const runnable = await runnableStep(db, stepDeps, reportId, stepKey);
    if (!runnable || runnable.ok !== true) {
      return { ok: false, code: "step_waiting", error: stepWaitingText(stepKey) };
    }
    const step = runnable.step;

    // (b) One extra step run for anything that is not the schedule.
    const day = dayOf(seam, now);
    if (trigger !== "schedule") {
      const caps = await getCaps(db);
      const claimed = await claimExtraStepRun(db, {
        reportId,
        day,
        max: caps.maxExtraStepRunsPerReportDay,
      });
      if (!claimed) return { ok: false, code: "cap_reached", error: "cap_reached" };
    }

    // (c) The assets and the hosts the approval covers, checked again now.
    const assetsDir = join(home, "reports", reportId, "assets");
    for (const asset of Array.isArray(step.assets) ? step.assets : []) {
      const verified = await verifyAssetOnDisk(stepDeps, {
        report_id: reportId,
        name: asset.name,
        sha256: asset.sha256,
      });
      if (!verified) return { ok: false, code: "asset_changed", error: "asset_changed" };
    }
    const { rows: hostRows } = await db.execute({
      sql: "SELECT report_id, host, state, approval_nonce, approval_seal FROM report_hosts WHERE report_id = ?",
      args: [reportId],
    });
    const egressAllow = [];
    for (const row of hostRows) {
      if (row.state !== "approved") continue;
      if (!(await verifyHost(db, stepDeps, row))) return { ok: false, code: "host_unverified", error: "host_unverified" };
      egressAllow.push(String(row.host));
    }
    const injectRules = await injectRulesFor(db, stepDeps, { reportId });

    // (d) The bundle dir, written fresh, removed whatever happens.
    bundleDir = mkdtempSync(join(osTmpdir(), "crow-report-step-bundle-" + process.pid + "-"));
    writeBundleDir(step.files, bundleDir);

    // (e) The env.
    const envFn = typeof seam.ensureEnv === "function" ? seam.ensureEnv : ensureEnvFor;
    const env = await envFn({
      reportId,
      language: step.language,
      requirements: step.requirements,
      crowHome: home,
      deps: seam,
    });
    if (!env || env.ok !== true) {
      const code = env && typeof env.code === "string" ? env.code : "env_failed";
      if (code === NO_WALL_CODE) {
        await notifyNoWallOnce(db, seam, reportId, day, now);
        return { ok: false, code: NO_WALL_CODE, error: NO_WALL_TEXT };
      }
      return { ok: false, code, error: code };
    }

    // (f) The run.
    const runFn = typeof seam.runStep === "function" ? seam.runStep : runCustomStep;
    // The runner's seams are a test harness's (`relayOptions` can carry a socket override,
    // `testSeams` unlocks the rest): a gateway caller never hands them on, so no caller can widen the
    // egress list or the credential rules this run owns.
    const runSeam = { ...seam };
    delete runSeam.relayOptions;
    delete runSeam.testSeams;
    const result = await runFn({
      reportId,
      stepKey,
      input,
      // The step's own stored state, when PR 4a has one to hand it; a run without one gets null and the
      // answer's `state` is what the caller writes for the next run.
      state: seam.state === undefined ? null : seam.state,
      params,
      timeoutMs: seam.timeoutMs,
      memoryMb: seam.memoryMb,
      deps: {
        ...runSeam,
        language: step.language,
        entry: step.entry,
        envDir: env.dir,
        uvCacheDir: env.cacheDir,
        bundleDir,
        assetsDir,
        assetBinds: (Array.isArray(step.assets) ? step.assets : []).map((asset) => ({
          name: asset.name,
          path: asset.path,
        })),
        egressAllow,
        injectRules,
        home,
      },
    });
    if (!result || result.ok !== true) {
      const code = result && typeof result.code === "string" ? result.code : "exit_nonzero";
      if (code === NO_WALL_CODE) {
        await notifyNoWallOnce(db, seam, reportId, day, now);
        return { ok: false, code: NO_WALL_CODE, error: NO_WALL_TEXT };
      }
      return { ok: false, code, error: redact(code) };
    }
    return { ok: true, output: result.output };
  } catch (err) {
    // Nothing a child or a filesystem says is handed on raw: the code word is the answer, redacted.
    const code = err && typeof err.code === "string" && err.code ? err.code : "exit_nonzero";
    return { ok: false, code, error: redact(code) };
  } finally {
    if (bundleDir) {
      try { rmSync(bundleDir, { recursive: true, force: true }); } catch { /* already gone */ }
    }
  }
}