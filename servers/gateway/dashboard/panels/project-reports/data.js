/**
 * The reads behind a project's Reports list and one report's page (Crow Recurring Reports, task 9b).
 *
 * READ ONLY. Nothing here writes a row, starts a run or sends anything: the page's buttons call the
 * owner API (routes/reports-api.js) and come back with a fresh page.
 *
 * WHAT THE PATH PROVES, and nothing else: the slug must be a live project of this instance, and a
 * report id must be one of THAT project's reports (`reports.project_id`). Anything else answers null
 * and the panel renders the project's missing page, so an id from another project is never readable
 * through this path.
 *
 * THE VIEWER KIND DECIDES WHAT IS READ AT ALL. `viewer: "owner"` is this machine's own password sign-in
 * (the panel's viewerOf), and it reads everything the page draws. `viewer: "member"` is a reader: the
 * reduced shape, which holds the report's name, its status, its next run and its run history (time, result
 * word, trigger label, version number) and nothing else. No pause reason, no run error text, no sender
 * account, no recipient address or count, no step or host list, no recipe settings sits in that answer,
 * because the data must not leave the server for a reader the owner did not allow to see it. A refused
 * request (a peer sign-in, a signed peer call) never reaches this module at all.
 *
 * TIMES are epoch ms in every row here. A next run is formatted in the SCHEDULE's own zone (the zone the
 * cron is read in), with the zone's name beside it, so the time the page shows is the time the report
 * actually runs at. A run's time is formatted in the same zone when the report has one, and in this
 * machine's zone otherwise.
 *
 * A RUN'S ERROR TEXT is re-redacted here, against this instance's secret values, exactly as the run view
 * does (report-run/data.js): a stored row is written redacted, and a page redacts it again because it
 * shows it.
 *
 * A VERSION is found through `report_versions` (run id + report id), never through the report's artifact:
 * a preview's version lives in the report's separate preview artifact. The artifact tables belong to the
 * Artifacts extension, which may not be installed, and retention may have pruned a version: a row that is
 * gone makes the version "expired" (readable, but no document), and a table that cannot be read at all
 * leaves its state unknown rather than calling a version expired.
 */
import { ACTIVE_PROJECT_WHERE } from "../../../../shared/shell-items.js";
import { getSecretValues } from "../../../../shared/secret-values.js";
import { redactSecrets } from "../../../../shared/redact-secrets.js";
import { isLive, listRecipients } from "../../../reports/approvals.js";
import { buildApprovalsDeps } from "../../../reports/approvals-deps.js";
import { listRuns } from "../../../reports/run.js";
import { listSends } from "../../../reports/send-log.js";
import { listHosts, listStepsForPage } from "../../../reports/steps.js";
import { getReport, listReports } from "../../../reports/store.js";
import { getAccount } from "../../../mail/store/accounts.js";

/** How many runs a report page shows. */
export const HISTORY_LIMIT = 30;

/** How many rows of the send log one page reads (the log's own list cap). */
const SENDS_LIMIT = 200;

/** How long one settings value may be on the page. */
const VALUE_MAX = 120;

/** A settings key whose NAME says it carries a secret is not rendered at all. */
const SECRET_KEY_RE = /secret|token|password|key/i;

function text(value) {
  if (value == null) return "";
  return typeof value === "string" ? value : String(value);
}

/** This instance's secret values, or none: a page must render even if the list cannot be read. */
function secretValues() {
  try {
    const values = getSecretValues();
    return Array.isArray(values) ? values : [];
  } catch {
    return [];
  }
}

/** The live project the slug names, or null. Never throws. */
export async function liveProject(db, slug) {
  if (typeof slug !== "string" || !slug) return null;
  try {
    const { rows } = await db.execute({
      sql: `SELECT id, slug, name FROM project_spaces WHERE slug = ? AND ${ACTIVE_PROJECT_WHERE}`,
      args: [slug],
    });
    const row = rows[0];
    return row
      ? { id: Number(row.id), slug: String(row.slug), name: String(row.name || row.slug) }
      : null;
  } catch {
    return null;
  }
}

/* --------------------------------------------------------------------------- times */

/**
 * One moment as the page reads it: the date and the time, and the zone's name. A zone the runtime does
 * not know falls back to this machine's zone rather than failing the page.
 *
 * @param {number|null} ms epoch ms, or null
 * @param {string} lang
 * @param {string|null} tz an IANA zone name from the report's schedule row
 * @returns {string|null}
 */
export function whenText(ms, lang, tz = null) {
  const at = Number(ms);
  if (!Number.isFinite(at)) return null;
  const locale = lang === "es" ? "es" : "en";
  const options = {
    year: "numeric", month: "short", day: "numeric",
    hour: "numeric", minute: "2-digit", timeZoneName: "short",
  };
  try {
    return new Intl.DateTimeFormat(locale, tz ? { ...options, timeZone: tz } : options).format(new Date(at));
  } catch {
    try {
      return new Intl.DateTimeFormat(locale, options).format(new Date(at));
    } catch {
      return null;
    }
  }
}

/* --------------------------------------------------------------------- the schedule */

/** One report's own `schedules` row, or null. A pointer that names no row, or another schedule's
 *  row, is no schedule of this report. Never throws. */
async function scheduleRow(db, report) {
  const id = Number(report?.schedule_id);
  if (!Number.isInteger(id) || id <= 0) return null;
  try {
    const { rows } = await db.execute({
      sql: "SELECT id, task, cron_expression, tz, enabled, next_run FROM schedules WHERE id = ?",
      args: [id],
    });
    const row = rows[0];
    if (!row) return null;
    if (text(row.task) !== `report:${report.id}`) return null;
    return row;
  } catch {
    return null;
  }
}

/**
 * The report's schedule as a page reads it: the cron and the zone, and the next run's text when the row is
 * on, the report is approved to run (`running`: live AND its seal verifies) and that window is still ahead
 * of the clock this page reads against. An off row, a report whose approval does not verify, or one whose
 * stored window has already passed, has no next run to name.
 */
function scheduleView(row, { lang, now, running = false }) {
  if (!row) return null;
  const cron = text(row.cron_expression);
  const tz = text(row.tz) || null;
  const at = Date.parse(text(row.next_run));
  const enabled = Number(row.enabled) === 1;
  const nextRunAt = Number.isFinite(at) ? at : null;
  const nextRunText = running && enabled && nextRunAt !== null && nextRunAt > now
    ? whenText(nextRunAt, lang, tz)
    : null;
  return { cron, tz, enabled, nextRunAt, nextRunText };
}

/* ----------------------------------------------------------------------- versions */

/**
 * The artifact version one run wrote, as a history row reads it. The owner reads it whole: `state` is
 * "ok" (the version row is there, so the run view can show it), "expired" (a report_versions row exists
 * but the artifact version is gone: retention pruned it, and a hold would have kept it) or "unknown" (the
 * artifact tables cannot be read at all, so nothing is claimed either way), and `href` is the run view's
 * path. A READER gets the number alone: no link, and no word about whether the document is still there.
 *
 * @param {object} db
 * @param {{slug: string}} project
 * @param {string} reportId
 * @param {string} runId
 * @param {"owner"|"member"} viewer
 * @returns {Promise<null|{n: number, state?: "ok"|"expired"|"unknown", href?: string|null}>}
 */
async function versionOf(db, project, reportId, runId, viewer = "member") {
  let mapped;
  try {
    const { rows } = await db.execute({
      sql: "SELECT artifact_id, n FROM report_versions WHERE run_id = ? AND report_id = ? LIMIT 1",
      args: [runId, reportId],
    });
    mapped = rows[0] ?? null;
  } catch {
    return null;
  }
  if (!mapped) return null;
  const n = Number(mapped.n);
  if (!Number.isInteger(n)) return null;
  if (viewer !== "owner") return { n };
  const artifactId = text(mapped.artifact_id);
  let state = "unknown";
  try {
    const { rows } = await db.execute({
      sql: "SELECT 1 FROM artifact_versions WHERE artifact_id = ? AND n = ?",
      args: [artifactId, n],
    });
    state = rows.length ? "ok" : "expired";
  } catch {
    state = "unknown";
  }
  const href = state === "ok"
    ? `/dashboard/project/${encodeURIComponent(project.slug)}/reports/${encodeURIComponent(reportId)}/runs/${encodeURIComponent(runId)}`
    : null;
  return { n, state, href };
}

/* -------------------------------------------------------------------------- runs */

/** One line of error text: redacted, whitespace collapsed, or null when there is none. */
function errorLine(run, secrets) {
  const flat = redactSecrets(text(run == null ? "" : run.errorText), secrets).replace(/\s+/g, " ").trim();
  return flat || null;
}

/** The send log grouped by run: how many of its sends went, are unknown, failed or are still waiting. */
function countsByRun(sends) {
  const byRun = new Map();
  for (const send of sends) {
    const runId = text(send.runId);
    if (!runId) continue;
    let counts = byRun.get(runId);
    if (!counts) {
      counts = { sent: 0, unknown: 0, failed: 0, pending: 0 };
      byRun.set(runId, counts);
    }
    if (send.status === "sent") counts.sent += 1;
    else if (send.status === "unknown") counts.unknown += 1;
    else if (send.status === "failed" || send.status === "refused") counts.failed += 1;
    else counts.pending += 1;
  }
  return byRun;
}

/**
 * One report's runs as its history reads them, newest first. A reader's row carries the time, the result
 * word and the trigger label (and the version's number): no error text (listRuns reads it, and this row
 * does not return it, because it names the owner's sources), no
 * send counts, no link into the run view, and not even the run's own id.
 */
async function historyOf(db, { project, report, viewer, lang, tz }) {
  const owner = viewer === "owner";
  const runs = await listRuns(db, report.id, { limit: HISTORY_LIMIT });
  const secrets = owner ? secretValues() : [];
  let counts = new Map();
  if (owner) {
    try {
      counts = countsByRun(await listSends(db, { reportId: report.id, limit: SENDS_LIMIT }));
    } catch {
      counts = new Map();
    }
  }
  const rows = [];
  for (const run of runs) {
    const version = await versionOf(db, project, report.id, run.id, viewer);
    const runTime = whenText(run.endedAt ?? run.startedAt ?? run.createdAt, lang, tz);
    if (!owner) {
      rows.push({
        trigger: text(run.trigger),
        status: text(run.status),
        late: Number(run.late) === 1,
        timeText: runTime,
        version,
      });
      continue;
    }
    rows.push({
      id: run.id,
      trigger: text(run.trigger),
      status: text(run.status),
      late: Number(run.late) === 1,
      startedAt: run.startedAt ?? null,
      endedAt: run.endedAt ?? null,
      timeText: runTime,
      errorText: errorLine(run, secrets),
      version,
      sends: counts.get(run.id) ?? null,
      // "Send to the rest" is the owner's, and only a run that finished and holds an unknown send has one.
      canSendRest: owner
        && ["ok", "empty", "failed"].includes(text(run.status))
        && (text(run.trigger) === "schedule" || (text(run.trigger) === "manual" && text(run.requestedBy) === "owner"))
        && (counts.get(run.id)?.unknown ?? 0) > 0,
    });
  }
  return rows;
}

/**
 * A usable preview for go-live: the newest run with trigger "preview", status "ok" and the report's
 * CURRENT head revision. A preview of an older revision approves nothing, so it is not one.
 */
function previewOf(runs, report) {
  const head = Number(report.recipe_rev);
  for (const run of runs) {
    if (text(run.trigger) !== "preview") continue;
    if (text(run.status) !== "ok") continue;
    if (Number(run.recipeRev) !== head) continue;
    return run.id;
  }
  return null;
}

/* ------------------------------------------------------------------------- the recipe */

/** One settings value as short text: a string as it is, anything else as its JSON, cut at VALUE_MAX. */
function shortValue(value) {
  let out;
  try {
    out = typeof value === "string" ? value : JSON.stringify(value);
  } catch {
    out = "";
  }
  const flat = text(out).replace(/\s+/g, " ").trim();
  return flat.length > VALUE_MAX ? `${flat.slice(0, VALUE_MAX)}…` : flat;
}

/**
 * A recipe read-only: every block's type, id and its settings as "key: value" pairs. A key whose NAME
 * says it carries a secret is dropped, and no value ever leaves with more than VALUE_MAX characters.
 */
export function recipeBlocks(report) {
  let recipe;
  try {
    recipe = JSON.parse(text(report.recipe_json));
  } catch {
    return [];
  }
  const blocks = recipe != null && Array.isArray(recipe.blocks) ? recipe.blocks : [];
  const out = [];
  for (const block of blocks) {
    if (block == null || typeof block !== "object") continue;
    const settings = block.settings != null && typeof block.settings === "object" && !Array.isArray(block.settings)
      ? block.settings
      : {};
    const pairs = [];
    for (const [key, value] of Object.entries(settings)) {
      if (SECRET_KEY_RE.test(key)) continue;
      pairs.push({ key, value: shortValue(value) });
    }
    out.push({ id: text(block.id), type: text(block.type), settings: pairs });
  }
  return out;
}

/* ------------------------------------------------------------------------- the list */

/**
 * Every report of one project, newest first, as the list page reads them.
 *
 * A reader's row is the reduced shape: the name, the status, the next run's text and the last result.
 * Nothing else is read for that row — no recipient list, no version, no schedule cron or zone — so an
 * address or a settings value cannot be in the answer at all.
 *
 * @param {object} db
 * @param {{project: {id: number, slug: string, name: string}, viewer?: "owner"|"member", lang?: string,
 *   now?: number}} input
 * @returns {Promise<{project: object, owner: boolean, reports: object[]}>}
 */
export async function loadReportsList(db, { project, viewer = "member", lang = "en", now = Date.now() } = {}) {
  const owner = viewer === "owner";
  const clock = Number.isFinite(now) ? Number(now) : Date.now();
  const deps = buildApprovalsDeps();
  const rows = await listReports(db, { projectId: project.id });
  const reports = [];
  for (const report of rows) {
    const live = await isLive(db, deps, report);
    const schedule = scheduleView(await scheduleRow(db, report), {
      lang, now: clock, running: text(report.status) === "live" && live,
    });
    const runs = await listRuns(db, report.id, { limit: 1 });
    const latest = runs[0] ?? null;
    if (!owner) {
      reports.push({
        id: report.id,
        title: text(report.title),
        status: text(report.status),
        live,
        pauseReason: null,
        nextRunText: schedule ? schedule.nextRunText : null,
        lastRun: latest
          ? {
            status: text(latest.status),
            late: Number(latest.late) === 1,
            endedText: whenText(latest.endedAt ?? latest.startedAt ?? latest.createdAt, lang, schedule ? schedule.tz : null),
          }
          : null,
      });
      continue;
    }
    const latestVersion = latest ? await versionOf(db, project, report.id, latest.id, viewer) : null;
    let recipientCount = null;
    try {
      const recipients = await listRecipients(db, report.id, deps);
      recipientCount = recipients.filter((row) => row.state === "approved").length;
    } catch {
      recipientCount = null;
    }
    reports.push({
      id: report.id,
      title: text(report.title),
      status: text(report.status),
      live,
      pauseReason: text(report.pause_reason) || null,
      schedule,
      nextRunText: schedule ? schedule.nextRunText : null,
      lastRun: latest
        ? {
          status: text(latest.status),
          late: Number(latest.late) === 1,
          endedAt: latest.endedAt ?? null,
          endedText: whenText(latest.endedAt ?? latest.startedAt ?? latest.createdAt, lang, schedule ? schedule.tz : null),
        }
        : null,
      latestRun: latest ? { id: latest.id, href: latestVersion && latestVersion.href ? latestVersion.href : null } : null,
      recipientCount,
    });
  }
  return { project, owner, reports };
}

/* ------------------------------------------------------------------- the report page */

/**
 * One report of one project, as its page reads it, or null when the id is not a report of this project.
 *
 * A reader's page is the reduced shape: the name, the status, the next run's text and the history rows
 * historyOf builds for a reader. The schedule's cron and zone, the delivery and comment settings, the
 * recipe, the sender, the recipient list, the steps and the hosts are not read for it, and the preview a
 * go-live would use is the owner's, so it is not looked for.
 *
 * @param {object} db
 * @param {{project: {id: number, slug: string, name: string}, reportId?: string,
 *   viewer?: "owner"|"member", lang?: string, now?: number}} input
 * @returns {Promise<null|{project: object, owner: boolean, report: object}>}
 */
export async function loadReportPage(db, { project, reportId, viewer = "member", lang = "en", now = Date.now() } = {}) {
  const owner = viewer === "owner";
  if (typeof reportId !== "string" || !reportId) return null;
  const clock = Number.isFinite(now) ? Number(now) : Date.now();
  let report;
  try {
    report = await getReport(db, reportId);
  } catch {
    return null;
  }
  if (!report) return null;
  if (Number(report.project_id) !== Number(project.id)) return null;

  const deps = buildApprovalsDeps();
  const live = await isLive(db, deps, report);
  const schedule = scheduleView(await scheduleRow(db, report), {
    lang, now: clock, running: text(report.status) === "live" && live,
  });
  const tz = schedule ? schedule.tz : null;

  if (!owner) {
    return {
      project,
      owner: false,
      report: {
        id: report.id,
        title: text(report.title),
        status: text(report.status),
        live,
        pauseReason: null,
        nextRunText: schedule ? schedule.nextRunText : null,
        runs: await historyOf(db, { project, report, viewer, lang, tz }),
      },
    };
  }

  const runs = await historyOf(db, { project, report, viewer, lang, tz });
  // A usable preview for go-live: the newest preview run of the revision the report is at now.
  const previewRunId = previewOf(await listRuns(db, report.id, { limit: HISTORY_LIMIT }), report);

  const view = {
    id: report.id,
    title: text(report.title),
    status: text(report.status),
    live,
    pauseReason: text(report.pause_reason) || null,
    nextRunText: schedule ? schedule.nextRunText : null,
    schedule: schedule ? { cron: schedule.cron, tz: schedule.tz, nextRunText: schedule.nextRunText } : null,
    deliveryMode: text(report.delivery_mode),
    commentTierDefault: text(report.comment_tier_default),
    commentVisibility: text(report.comment_visibility),
    aiCommentary: Number(report.ai_commentary) === 1,
    recipe: recipeBlocks(report),
    sender: await senderOf(db, report),
    // The sender account id the page showed, exactly as the go-live route compares it: the row's own
    // column, the empty string when it has none. The client sends it back with a go-live.
    senderAccountId: text(report.sender_account_id),
    recipients: await recipientsOf(db, report, deps),
    steps: await stepsOf(db, report, deps),
    hosts: await hostsOf(db, report, deps),
    runs,
    preview: previewRunId ? { runId: previewRunId } : null,
  };
  return { project, owner, report: view };
}

/** The account the report sends from, as an address, or null. A missing or unreadable row is null. */
async function senderOf(db, report) {
  const accountId = text(report.sender_account_id);
  if (!accountId) return null;
  try {
    const account = await getAccount(db, accountId);
    if (!account || !account.address) return null;
    return { address: text(account.address) };
  } catch {
    return null;
  }
}

/** The report's recipient list, addresses and all (owner only). */
async function recipientsOf(db, report, deps) {
  try {
    const rows = await listRecipients(db, report.id, deps);
    return rows.map((row) => ({
      id: row.id,
      address: text(row.address),
      state: text(row.state),
      tier: row.commentTier == null ? null : text(row.commentTier),
    }));
  } catch {
    return [];
  }
}

/** The report's custom steps at their newest revision, as keys, revisions and approval state. */
async function stepsOf(db, report, deps) {
  try {
    const rows = await listStepsForPage(db, report.id, deps);
    return rows.map((row) => ({ key: text(row.stepKey), rev: Number(row.rev), state: text(row.state) }));
  } catch {
    return [];
  }
}

/** The report's host list, as hosts and approval state. */
async function hostsOf(db, report, deps) {
  try {
    const rows = await listHosts(db, report.id, deps);
    return rows.map((row) => ({ host: text(row.host), state: text(row.state) }));
  } catch {
    return [];
  }
}