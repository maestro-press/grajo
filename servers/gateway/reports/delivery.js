/**
 * Delivery: the one place a report's run becomes mail.
 *
 * `run.js` calls its injected `deliver(db, {report, run, live, status, artifactVersion, result})` once per
 * scheduled or manual run, with the finished run row, the verified live set and the run's own result. This
 * module is what that seam is wired to at boot (`makeDeliver`), and it is the ONLY importer of the
 * reports-only send door (`mail/reports-door.js`): nothing on a bot's side reaches a send, because a send
 * is reached only from a run this owner approved and the door takes a `report_sends` row id, never an
 * address.
 *
 * WHAT ONE CALL DOES, in order, and why the order matters:
 *
 *   1. A PREVIEW delivers nothing. It is not an approved run, it has no live set, and no recipient ever
 *      sees it: zero counts, no notice, no row.
 *   2. The OWNER'S NOTICE about this run is written BEFORE any mail, and whatever the delivery mode and
 *      whoever the recipients are: a failed run is `essential` and `high` (the owner asked to always
 *      hear that a report they approved did not run), an empty run is `essential` and `normal`, and any
 *      other run only when the report's notify-every-run switch is on, which is NOT essential. So a
 *      storage-nearly-full failure, whose error text the run engine recorded, reaches the owner even in
 *      `crow_only` mode and even with no recipients at all, and a notification type the owner switched
 *      off cannot swallow it.
 *   3. `crow_only` stops here: no email, and the counts are zero. (`deliverPending` settles the run's
 *      `pending` rows `refused` for the same reason; see below.)
 *   4. The VERSION to pin is the run's own when it is one a recipient may be shown, else the newest
 *      version that is (`latestRecipientVersion`), and NEVER the artifact's `current_version`: a preview
 *      or an owner edit can sit at current, and a mail link is a promise about one version. The pin may
 *      be null (a failed run wrote no version).
 *   5. Each APPROVED recipient (state `approved` AND a seal that still verifies) gets at most one send
 *      row for this run. Its link comes from `links.js`: a recipient with no link kind, or with a link
 *      that is not an absolute http(s) URL, is SKIPPED with no row and no mail. A `sent`, `sending` or
 *      `unknown` row means this one is already spoken for, whatever else the log holds, so the recipient
 *      is SKIPPED and never mailed twice. Otherwise a `pending` row is REUSED: it is the row "Send to
 *      the rest" wrote, and the log often holds the `failed` or `refused` row of an attempt that did
 *      not go beside it. A recipient whose only rows are `failed` or `refused` is skipped too, because
 *      this run's next attempt is not this delivery's to write. A recipient with no row at all is
 *      written `pending` with the next attempt, exactly as `send-log.js` writes it, and the row id is
 *      read back: a lost insert race is a skip.
 *   6. The mail is built by `email/default-layout.js` (which owns the sanitiser, the honest line and the
 *      footer that cannot be removed) and handed to the door, which owns the claim, the recipient's seal
 *      check and the outcome. A throw from one recipient counts as `failed` for that recipient and never
 *      stops the others.
 *   7. A send that ended `sent` or `unknown` HOLDS the pinned version for `reports.link_days` (default
 *      180 days), through the artifacts store's `holdVersion`, so retention never deletes what a mail
 *      still points at. A hold that fails changes no count and is not thrown: the mail already went.
 *   8. If any send ended failed, unknown or refused, the owner gets ONE more essential notice with the
 *      counts, so a partly delivered run is never silent.
 *   9. A recipient skipped for want of a LINK (no link kind yet, or no dashboard base because this
 *      instance does not know an address a reader could open, so `links.js` answers null) was never
 *      attempted and owns no send row, so the owner gets ONE
 *      essential notice about it too: nothing was written anywhere else that says the mail did not go.
 *      That count is kept apart from the other skips: a recipient this run is already spoken for is not
 *      a miss and rings nothing.
 *
 * HONEST RUNS: a failed or empty run still mails every approved recipient, with the honest line and the
 * link. A failed run's email carries the honest line and NOTHING ELSE (`document: null`): a half report
 * is worse than no report, and the reader is told what happened.
 *
 * "SEND TO THE REST" ROWS ARE SENT BY `deliverPending`, NOT BY `deliver`: the owner's tap on a finished
 * report's send log writes `pending` rows for the recipients that run did not mail (`send-log.js`), and
 * `deliverPending(db, deps, {reportId, runId})` is the one function that sends exactly those rows. It
 * reads the run, the report and the version the run wrote (its stored document, its allowed links) and
 * makes NO row of its own; a recipient this run already `sent`, is `sending` or left `unknown` has its
 * `pending` row settled `refused` / `not_pending` instead. A row it cannot send at all settles too (see
 * `settlePendingRow`), so no row is left `pending` for ever by a tap. It writes no run-level notice,
 * because the run was announced when it happened, and it still writes the counts notice when a row did
 * not go. THE TRIGGER IS THE REPORTS SCHEDULER HOOK'S TICK
 * (`reports/schedule-hook.js`), which calls it for the pairs those rows name once they are past its
 * grace. A custom step's own email template is not replayed there, because the run-to-version row keeps
 * the document and the links and no template.
 *
 * NOTHING HERE THROWS OUT for a per-recipient problem, and every string this module stores or shows is
 * passed through `redactSecrets` first. The deps are the whole seam, and each falls back to the real thing
 * when absent: `sendMail` (the door), `adapterFor` (boot's mail adapter source), `approvals` (the seal
 * seed the recipient check reads), `notify` (`createNotification`), `holdVersion` (the artifacts store's
 * own), `linkFor` (`links.js`), `getRun` (`run.js`, read by `deliverPending`), `now`, `getSecrets`,
 * `localInstanceId` and `baseUrl`.
 */
import { randomBytes } from "node:crypto";
import { createNotification } from "../../shared/notifications.js";
import { redactSecrets } from "../../shared/redact-secrets.js";
import { getSecretValues } from "../../shared/secret-values.js";
import { sendReportMail } from "../mail/reports-door.js";
import { listRecipients } from "./approvals.js";
import {
  isRecipientSafeVersion, latestRecipientVersion, loadArtifactsRuntime,
} from "./artifact-bridge.js";
import { defaultLayout } from "./email/default-layout.js";
import {
  EMAILS_SKIPPED_BODY, emailsNotSentNotice, emailsSkippedNotice, runEmptyNotice, runFailedNotice,
  runReadyNotice,
} from "./email/copy.js";
import { commentTierOf, isAbsoluteHttpUrl, linkFor, reportPagePath } from "./links.js";
import { SENDABLE_RUN_STATUSES } from "./send-log.js";
import { getRun } from "./run.js";
import { getReport } from "./store.js";
import { countsText } from "./send-sweep.js";

/** What one send row's status may be, as this module counts it. */
export const DELIVERY_OUTCOMES = Object.freeze(["sent", "refused", "failed", "unknown"]);

/**
 * A row in one of these states is this run's own answer for that recipient: the mail went (`sent`), is in
 * hand (`sending`), may have gone (`unknown`), or the attempt was refused or failed. None of them makes a
 * delivery write a second attempt, and a `pending` row written beside one is still the row that goes (see
 * `claimSendRow`). The three that mean "already spoken for" are `BLOCKING_SEND_STATUSES`.
 */
export const SETTLED_SEND_STATUSES = Object.freeze(["sent", "sending", "unknown", "refused", "failed"]);

/**
 * A row in one of these states means this recipient's mail for this run is already spoken for: it went,
 * it is in hand, or nobody knows. Nothing is ever sent beside one, even when a `pending` row exists.
 */
export const BLOCKING_SEND_STATUSES = Object.freeze(["sent", "sending", "unknown"]);

/** The `dashboard_settings` key holding how long a mailed version is held, in days. */
export const LINK_DAYS_KEY = "reports.link_days";

/** How long a version is held when the setting is absent or not a usable number. */
export const DEFAULT_LINK_DAYS = 180;

/** The longest report title a notice carries (it is untrusted text). */
export const NOTICE_TITLE_MAX = 80;

/** The longest failure text a notice body carries. */
export const NOTICE_BODY_MAX = 300;

const DAY_MS = 86_400_000;

/** Control characters, `\n` and `\t` kept: whitespace is collapsed where one line is wanted. */
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g;

function text(value) {
  if (value == null) return "";
  return typeof value === "string" ? value : String(value);
}

function fail(code, detail) {
  const err = new Error(detail ? `${code}: ${detail}` : code);
  err.code = code;
  if (detail) err.detail = detail;
  return err;
}

function zeroCounts() {
  return { sent: 0, refused: 0, failed: 0, unknown: 0, skipped: 0 };
}

/** One line: control characters dropped, every run of whitespace made one space. */
function oneLine(value) {
  return text(value).replace(CONTROL, "").replace(/\s+/g, " ").trim();
}

/** At most `max` characters, never splitting a surrogate pair. */
function bound(value, max) {
  const source = text(value);
  if (source.length <= max) return source;
  let end = max;
  const code = source.charCodeAt(end - 1);
  if (code >= 0xd800 && code <= 0xdbff) end -= 1;
  return source.slice(0, end);
}

/** The report's title as a notice may carry it: one line, no control characters, bounded. */
function noticeTitleOf(report) {
  const flat = oneLine(report == null ? "" : report.title);
  return bound(flat, NOTICE_TITLE_MAX).trim() || "This report";
}

function defaultGetSecrets() {
  try {
    return getSecretValues();
  } catch {
    return [];
  }
}

function secretsOf(deps) {
  try {
    const values = deps.getSecrets();
    return Array.isArray(values) ? values : [];
  } catch {
    return [];
  }
}

/**
 * The artifacts store's own `holdVersion`, resolved lazily: the Artifacts bundle is installed at runtime,
 * so this module never imports it. A runtime that carries no `holdVersion` throws here, and `deliver`'s
 * caller swallows that: a hold is the mail's promise, but a version already sent is not unmailed by a
 * bundle too old to hold it.
 */
async function defaultHoldVersion(db, deps, args) {
  const runtime = await loadArtifactsRuntime(deps == null ? {} : deps);
  return runtime.store.holdVersion(db, args);
}

/** The deps with every member present; a member that is absent falls back to the real thing. */
function resolveDeps(db, deps) {
  const given = deps == null ? {} : deps;
  const fn = (key, fallback) => (typeof given[key] === "function" ? given[key] : fallback);
  return {
    sendMail: fn("sendMail", sendReportMail),
    adapterFor: typeof given.adapterFor === "function" ? given.adapterFor : null,
    approvals: given.approvals == null ? {} : given.approvals,
    notify: fn("notify", createNotification),
    holdVersion: fn("holdVersion", (args) => defaultHoldVersion(db, given, args)),
    linkFor: fn("linkFor", linkFor),
    getRun: fn("getRun", getRun),
    now: fn("now", Date.now),
    getSecrets: fn("getSecrets", defaultGetSecrets),
    localInstanceId: given.localInstanceId,
    baseUrl: typeof given.baseUrl === "string" ? given.baseUrl : null,
  };
}

/** How many days a mailed version is held, from the setting, else the default. Never throws. */
async function linkDaysOf(db) {
  try {
    const { rows } = await db.execute({
      sql: "SELECT value FROM dashboard_settings WHERE key = ?",
      args: [LINK_DAYS_KEY],
    });
    const raw = text(rows[0]?.value).trim();
    const value = raw ? Number(raw) : NaN;
    if (Number.isFinite(value) && value > 0) return value;
  } catch {
    // A setting that cannot be read is the default, never a failed delivery.
  }
  return DEFAULT_LINK_DAYS;
}

/**
 * The version this delivery pins and holds: the run's own when it is one a recipient may be shown,
 * otherwise the newest version that is. Never the artifact's `current_version` (see the module comment).
 * A read that fails answers null: nothing is held, and nothing is mailed differently.
 */
async function pinVersion(db, artifactId, artifactVersion) {
  if (typeof artifactId !== "string" || !artifactId) return null;
  const asked = Number(artifactVersion);
  try {
    if (Number.isInteger(asked) && asked > 0 && (await isRecipientSafeVersion(db, artifactId, asked))) {
      return asked;
    }
    return await latestRecipientVersion(db, artifactId);
  } catch {
    return null;
  }
}

/** Is the report's notify-every-run switch on? The column is 0/1, and a caller's boolean counts too. */
function notifiesEveryRun(report) {
  const raw = report == null ? 0 : report.notify_every_run;
  return raw === true || Number(raw) === 1;
}

/** The failure text a notice body carries: one line, redacted, bounded, or null when it is empty. */
function failureBody(errorText, secrets) {
  const flat = oneLine(redactSecrets(text(errorText), secrets));
  const bounded = bound(flat, NOTICE_BODY_MAX).trim();
  return bounded || null;
}

/**
 * The owner's notice for this run, as `createNotification` takes it, or null when this run says nothing
 * (a finished run on a report whose notify-every-run switch is off).
 */
function runNoticeOf(report, run, status, title, secrets) {
  if (status === "failed") {
    const errorText = run == null ? null : (run.errorText ?? run.error_text);
    return {
      title: runFailedNotice(title),
      priority: "high",
      essential: true,
      body: failureBody(errorText, secrets),
    };
  }
  if (status === "empty") {
    return { title: runEmptyNotice(title), priority: "normal", essential: true, body: null };
  }
  if (!notifiesEveryRun(report)) return null;
  return { title: runReadyNotice(title), priority: "normal", essential: false, body: null };
}

/** Write one notice; a notice that cannot be written is never a failed run. */
async function ring(db, deps, notice) {
  if (notice == null) return;
  try {
    await deps.notify(db, {
      type: "reports",
      source: "reports",
      essential: notice.essential === true,
      priority: notice.priority,
      title: notice.title,
      body: notice.body ?? null,
      action_url: notice.action_url ?? null,
      metadata: notice.metadata ?? null,
    });
  } catch {
    // The bell is the owner's convenience; the rows are the record.
  }
}

/** This run's send rows for one recipient, oldest attempt first. */
async function sendRowsFor(db, runId, recipientId) {
  const { rows } = await db.execute({
    sql: `SELECT id, status, attempt FROM report_sends
           WHERE run_id = ? AND recipient_id = ? ORDER BY attempt ASC`,
    args: [runId, recipientId],
  });
  return rows;
}

/**
 * The one `pending` send row this recipient's mail for this run goes through, or null when this run and
 * this recipient are already spoken for (or an insert race lost).
 *
 * A `sent`, `sending` or `unknown` row is the answer "never again": nothing is sent beside it, even when
 * a `pending` row was written next to it. Otherwise a `pending` row WINS and is answered as it is: it is
 * the row "Send to the rest" wrote, and the log often holds the `failed` or `refused` row of an attempt
 * that did not go beside it. A run whose only rows for this recipient are `failed` or `refused` is not
 * retried here: this delivery writes no new attempt next to a settled one.
 *
 * A new row is written exactly the way `send-log.js` writes "Send to the rest": `pending`, the next
 * attempt, the account the report sends from, one clock for both timestamps, and `INSERT OR IGNORE` so
 * the unique (run, recipient, attempt) index settles two overlapping deliveries. Only a row this call
 * wrote (and read back as still `pending`) is answered.
 */
async function claimSendRow(db, { report, run, recipient, now }) {
  const runId = text(run == null ? "" : run.id);
  const recipientId = text(recipient == null ? "" : recipient.id);
  if (!runId || !recipientId) return null;
  const existing = await sendRowsFor(db, runId, recipientId);
  let pendingId = null;
  let highest = 0;
  for (const row of existing) {
    const attempt = Number(row.attempt);
    if (Number.isFinite(attempt) && attempt > highest) highest = attempt;
    const status = text(row.status);
    if (BLOCKING_SEND_STATUSES.includes(status)) return null;
    if (status === "pending") pendingId = text(row.id);
  }
  if (pendingId) return pendingId;
  // Only `failed` and `refused` rows are left: this attempt is not ours to write.
  if (existing.length) return null;

  const id = `rsd-${randomBytes(8).toString("hex")}`;
  const accountId = text(report == null ? "" : report.sender_account_id) || null;
  const at = Number(now);
  let wrote = false;
  try {
    const inserted = await db.execute({
      sql: `INSERT OR IGNORE INTO report_sends
              (id, run_id, report_id, recipient_id, attempt, account_id, status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'pending', ?, ?)`,
      args: [id, runId, text(report.id), recipientId, highest + 1, accountId, at, at],
    });
    wrote = Number(inserted?.rowsAffected ?? 0) === 1;
  } catch {
    wrote = false;
  }
  if (!wrote) return null;
  const { rows } = await db.execute({
    sql: "SELECT id, status FROM report_sends WHERE id = ?",
    args: [id],
  });
  const stored = rows[0];
  return stored && text(stored.status) === "pending" ? text(stored.id) : null;
}

/**
 * One recipient's mail, built and handed to the door.
 *
 * A failed run's email carries the honest line and nothing else, so `document` is null there whatever the
 * caller passed: the layout's own failure line is the body.
 *
 * @returns {Promise<"sent"|"refused"|"failed"|"unknown">} the door's own outcome, or `failed` for a mail
 *   this module could not build or a door that threw
 */
async function sendOne(db, deps, {
  report, run, status, recipient, link, sendId, document, allowedLinks, override,
}) {
  let mail;
  try {
    mail = defaultLayout({
      report,
      run,
      document: status === "failed" ? null : document,
      link: link.url,
      deliveryMode: text(report.delivery_mode),
      tier: commentTierOf(report, recipient),
      allowedLinks,
      override,
    });
  } catch {
    return "failed";
  }
  try {
    const answer = await deps.sendMail(db, {
      adapterFor: deps.adapterFor,
      approvals: deps.approvals,
      getSecrets: deps.getSecrets,
      now: deps.now,
      localInstanceId: deps.localInstanceId,
    }, { sendId, subject: mail.subject, html: mail.html, text: mail.text });
    const outcome = text(answer == null ? "" : answer.status);
    return DELIVERY_OUTCOMES.includes(outcome) ? outcome : "failed";
  } catch {
    // The door settles its own row, and an adapter's text (which can quote a server reply or a username)
    // never reaches this module: only the outcome does.
    return "failed";
  }
}

/**
 * One recipient's whole delivery: the link, the row it goes through, the mail and the hold.
 *
 * This is the per-recipient part of `deliver`, and it is shared with `deliverPending` so the two cannot
 * drift apart. `sendId` is that existing `pending` row when the caller has one (`deliverPending`); with
 * none it is `claimSendRow` that decides whether this run still owes this recipient an attempt.
 *
 * @returns {Promise<"sent"|"refused"|"failed"|"unknown"|"nolink"|"skipped">} the door's own outcome,
 *   `failed` for a mail this module could not build or a door that threw, `nolink` for a recipient this
 *   instance cannot make an absolute link for (nothing was claimed), and `skipped` for a recipient the
 *   run is already spoken for
 */
async function deliverToRecipient(db, d, {
  report, run, status, recipient, document, allowedLinks, override, artifactId, pinned, now, linkDays,
  sendId = null,
}) {
  let link = null;
  try {
    link = await d.linkFor(db, {
      report, recipient, run, sendId, baseUrl: d.baseUrl, localInstanceId: d.localInstanceId,
    });
  } catch {
    link = null;
  }
  // No link kind for this recipient (tiers a and b until PR 6a), or a link a mail client could not open:
  // nothing is claimed and nothing is mailed.
  if (link == null || typeof link.url !== "string" || !isAbsoluteHttpUrl(link.url)) return "nolink";

  const rowId = sendId ?? await claimSendRow(db, { report, run, recipient, now });
  if (!rowId) return "skipped";

  const outcome = await sendOne(db, d, {
    report, run, status, recipient, link, sendId: rowId, document, allowedLinks, override,
  });

  if ((outcome === "sent" || outcome === "unknown") && pinned != null && artifactId) {
    try {
      await d.holdVersion({
        artifactId,
        n: pinned,
        holder: `report-send:${rowId}`,
        until: now + linkDays * DAY_MS,
      });
    } catch {
      // A version already sent is not unmailed by a hold that could not be written.
    }
  }
  return outcome;
}

/**
 * Deliver one run of one report.
 *
 * @param {object} db a libsql-shaped client
 * @param {object} deps the seam (see the module comment)
 * @param {{report?: object|null, run?: object|null, live?: object|null, status?: string,
 *   artifactVersion?: number|null, result?: object|null, document?: object|string|null,
 *   emailOverride?: {html?: string, text?: string}|null}} payload `result` is the run's own result
 *   (`{document, allowedLinks, email, ...}`); `document` and `emailOverride` override what it carries
 * @returns {Promise<{sent: number, refused: number, failed: number, unknown: number, skipped: number}>}
 *   never rejects for a per-recipient problem
 */
export async function deliver(db, deps, payload = {}) {
  const d = resolveDeps(db, deps);
  const given = payload != null && typeof payload === "object" ? payload : {};
  const report = given.report ?? null;
  const run = given.run ?? null;
  const live = given.live ?? null;
  const result = given.result ?? null;
  const status = text(given.status) || text(run == null ? "" : run.status);
  const counts = zeroCounts();

  // A preview is not an approved run: no notice, no row, no mail.
  if (text(run == null ? "" : run.trigger) === "preview") return counts;
  if (report == null || typeof report !== "object" || !text(report.id)) return counts;

  const secrets = secretsOf(d);
  const title = noticeTitleOf(report);
  const actionUrl = await reportPagePath(db, report);

  // The owner hears about this run before any mail leaves, and whatever the mode and the recipients are.
  const notice = runNoticeOf(report, run, status, title, secrets);
  if (notice) {
    await ring(db, d, {
      ...notice,
      action_url: actionUrl,
      metadata: { reportId: text(report.id), runId: text(run == null ? "" : run.id) || null },
    });
  }

  // `crow_only`: the report is written and sent to nobody.
  if (text(report.delivery_mode) === "crow_only") return counts;

  const artifactId = text(live == null ? "" : live.artifactId) || text(report.artifact_id);
  const pinned = await pinVersion(db, artifactId, given.artifactVersion);

  const document = given.document !== undefined
    ? given.document
    : (result == null ? null : (result.document ?? null));
  const allowedLinks = result != null && Array.isArray(result.allowedLinks) ? result.allowedLinks : [];
  const override = given.emailOverride !== undefined
    ? given.emailOverride
    : (result == null ? null : (result.email ?? null));

  const now = Number(d.now());
  const linkDays = await linkDaysOf(db);

  let recipients = [];
  try {
    recipients = await listRecipients(db, text(report.id), d.approvals);
  } catch {
    recipients = [];
  }

  // Skips kept apart: only a missing link is something the owner has to hear about.
  let linkSkips = 0;

  for (const recipient of recipients) {
    if (recipient == null || recipient.state !== "approved" || recipient.verified !== true) continue;

    const outcome = await deliverToRecipient(db, d, {
      report, run, status, recipient, document, allowedLinks, override, artifactId, pinned,
      now, linkDays,
    });
    // A recipient with no absolute link owns no row: the owner hears about it in its own notice below.
    if (outcome === "nolink") {
      counts.skipped += 1;
      linkSkips += 1;
      continue;
    }
    if (outcome === "skipped") {
      counts.skipped += 1;
      continue;
    }
    if (DELIVERY_OUTCOMES.includes(outcome)) counts[outcome] += 1;
  }

  if (counts.failed + counts.unknown + counts.refused > 0) {
    await ring(db, d, {
      title: emailsNotSentNotice(title),
      body: countsText({
        sent: counts.sent,
        unknown: counts.unknown,
        notSent: counts.failed + counts.refused,
      }),
      priority: "high",
      essential: true,
      action_url: actionUrl,
      metadata: { reportId: text(report.id), runId: text(run == null ? "" : run.id) || null },
    });
  }

  // A recipient with no link is a mail that never happened and left no send row behind: the one record of
  // it is this notice. One per run, whatever the number of recipients, and essential because nothing else
  // says it. A recipient this run is already spoken for is counted in `skipped` too, and rings nothing.
  if (linkSkips > 0) {
    await ring(db, d, {
      title: emailsSkippedNotice(title),
      body: EMAILS_SKIPPED_BODY,
      priority: "high",
      essential: true,
      action_url: actionUrl,
      metadata: { reportId: text(report.id), runId: text(run == null ? "" : run.id) || null },
    });
  }

  return counts;
}

/**
 * The version one run wrote, as a delivery may replay it: the `report_versions` row's artifact id, its
 * version number and its recorded links, plus the document that version stored.
 *
 * A read that fails answers empty values rather than throwing: the artifacts bundle owns those two
 * tables, and a box with no bundle at all still has to be able to send the rows the owner wrote.
 *
 * @returns {Promise<{artifactId: string|null, pinned: number|null, allowedLinks: string[],
 *   document: {markdown: string}|null}>}
 */
async function runVersionOf(db, reportId, runId) {
  const empty = { artifactId: null, pinned: null, allowedLinks: [], document: null };
  let mapped = null;
  try {
    const { rows } = await db.execute({
      sql: `SELECT artifact_id, n, allowed_links_json FROM report_versions
             WHERE run_id = ? AND report_id = ? AND "trigger" <> 'preview'
             ORDER BY n DESC LIMIT 1`,
      args: [runId, reportId],
    });
    mapped = rows[0] ?? null;
  } catch {
    return empty;
  }
  if (!mapped) return empty;
  const artifactId = text(mapped.artifact_id) || null;
  const asked = Number(mapped.n);
  const pinned = Number.isInteger(asked) && asked > 0 ? asked : null;
  let allowedLinks = [];
  try {
    const parsed = JSON.parse(text(mapped.allowed_links_json) || "[]");
    if (Array.isArray(parsed)) allowedLinks = parsed.filter((url) => typeof url === "string");
  } catch {
    allowedLinks = [];
  }
  let document = null;
  if (artifactId != null && pinned != null) {
    try {
      const { rows } = await db.execute({
        sql: "SELECT source_json FROM artifact_versions WHERE artifact_id = ? AND n = ?",
        args: [artifactId, pinned],
      });
      const source = rows[0] == null ? null : JSON.parse(text(rows[0].source_json) || "null");
      if (source != null && typeof source === "object" && typeof source.markdown === "string") {
        document = { markdown: source.markdown };
      }
    } catch {
      document = null;
    }
  }
  return { artifactId, pinned, allowedLinks, document };
}

/**
 * Does this run already hold a `sent`, `sending` or `unknown` row for this recipient? One of those is the
 * answer "never again", whatever else the log carries beside it.
 */
async function alreadySpokenFor(db, runId, recipientId) {
  const { rows } = await db.execute({
    sql: `SELECT 1 FROM report_sends
           WHERE run_id = ? AND recipient_id = ? AND status IN ('sent', 'sending', 'unknown')
           LIMIT 1`,
    args: [runId, recipientId],
  });
  return rows.length > 0;
}

/**
 * Settle one `pending` row that this pass cannot send, terminally: ONE guarded statement, so only a row
 * that is still `pending` moves. A row another pass claimed (`sending`), sent, or settled some other way
 * is never rewritten by this, and nothing here touches a status other than `pending`.
 *
 * The statuses and reasons are the send door's own vocabulary: `refused` with `recipient_not_approved`
 * (the words the door uses for the same refusal) or `not_pending` (the mail is already spoken for), and
 * `failed` with `no_link` (this instance cannot make a link for that recipient, so nothing was mailed).
 * All three are internal codes; a person reads the notice, never the row.
 *
 * A write that fails leaves the row exactly as it is: the next pass offers it again.
 *
 * @param {object} db a libsql-shaped client
 * @param {string} id the `report_sends` row id
 * @param {"failed"|"refused"} status the terminal status to settle it as
 * @param {string} reason the short internal reason code
 * @param {number} now one clock for the row's own timestamp
 * @returns {Promise<void>}
 */
async function settlePendingRow(db, id, status, reason, now) {
  if (typeof id !== "string" || !id) return;
  try {
    await db.execute({
      sql: `UPDATE report_sends SET status = ?, reason = ?, updated_at = ?
             WHERE id = ? AND status = 'pending'`,
      args: [status, reason, now, id],
    });
  } catch {
    // A row that could not be settled stays `pending`, and a later pass tries again.
  }
}

/** One run's `pending` rows, oldest first: exactly the rows "Send to the rest" wrote. */
async function pendingSendRows(db, reportId, runId) {
  const { rows } = await db.execute({
    sql: `SELECT id, recipient_id FROM report_sends
           WHERE run_id = ? AND report_id = ? AND status = 'pending'
           ORDER BY created_at ASC, id ASC`,
    args: [runId, reportId],
  });
  return rows;
}

/**
 * Send the `pending` rows one finished run already holds: the owner's "Send to the rest", delivered.
 *
 * It reads the run (`getRun`), the report (`getReport`) and the version that run wrote (its document, its
 * recorded links), and then hands every `pending` row of the run to the SAME per-recipient path `deliver`
 * uses: the link, the mail, and the hold on the version that was sent. Nothing here makes a row, so a
 * recipient with no `pending` row is never written to (a run's own delivery owns that write), and a
 * recipient whose row is beside a `sent`, `sending` or `unknown` one is never mailed twice: its row
 * settles `refused` / `not_pending`. Every other row this pass cannot send settles too, by
 * `settlePendingRow`: `refused` / `recipient_not_approved` for a recipient that is no longer approved or
 * whose seal no longer verifies, and `failed` / `no_link` for one this instance has no link for, which
 * still counts as a skip and still rings the one skipped-emails notice. A row settles only from
 * `pending`, so nothing a door or another pass moved is ever rewritten here.
 *
 * A preview run and a run that has not finished send nothing. `crow_only` sends nothing either: that
 * report has no mail, so every `pending` row of its run settles `refused` / `not_live` (nothing will
 * ever claim one) and no notice is written. A failed run's body is the honest line and nothing else,
 * exactly as in `deliver`.
 *
 * The reports scheduler hook's tick calls this (`reports/schedule-hook.js`), for the pairs the rows
 * `send-log.js` wrote; a caller may also drive it directly. The run's own notice was written when the
 * run happened, so none is written here; the "some emails were not sent" notice still is, because a row
 * that failed now is news.
 *
 * @param {object} db a libsql-shaped client
 * @param {object} [deps] the seam (see the module comment)
 * @param {{reportId: string, runId: string}} input
 * @returns {Promise<{sent: number, refused: number, failed: number, unknown: number, skipped: number}>}
 *   never rejects for a per-recipient problem
 * @throws {Error} `bad_input` for a missing id, `not_found` when the run or the report is not there,
 *   and `read_failed` when the recipient list could not be read: no row is settled then, because a
 *   question that could not be answered says nothing about who may be mailed
 */
export async function deliverPending(db, deps, { reportId, runId } = {}) {
  const d = resolveDeps(db, deps);
  const counts = zeroCounts();
  if (typeof reportId !== "string" || !reportId) throw fail("bad_input", "reportId");
  if (typeof runId !== "string" || !runId) throw fail("bad_input", "runId");

  const run = await d.getRun(db, runId);
  if (!run || text(run.reportId) !== reportId) throw fail("not_found", "run");
  const report = await getReport(db, reportId);
  if (!report) throw fail("not_found", "report");

  // A preview is never approved mail, and a run that has not finished has nothing to send to the rest of.
  if (text(run.trigger) === "preview") return counts;
  if (!SENDABLE_RUN_STATUSES.includes(text(run.status))) return counts;
  if (text(report.delivery_mode) === "crow_only") {
    // A report with no mail has no row that can ever go: each `pending` row of this run settles
    // `refused` / `not_live` (the door's word for a row nothing will ever claim) instead of sitting in
    // the hook's scan for the life of the log. Nothing is mailed and nothing is rung.
    const at = Number(d.now());
    for (const row of await pendingSendRows(db, reportId, runId)) {
      await settlePendingRow(db, text(row.id), "refused", "not_live", at);
    }
    return counts;
  }

  const status = text(run.status);
  const title = noticeTitleOf(report);
  const actionUrl = await reportPagePath(db, report);
  const { artifactId, pinned, allowedLinks, document } = await runVersionOf(db, reportId, runId);
  const now = Number(d.now());
  const linkDays = await linkDaysOf(db);

  let recipients = [];
  try {
    recipients = await listRecipients(db, reportId, d.approvals);
  } catch {
    // A recipient list that could not be read says nothing about any row: every `pending` row of this
    // run is still owed its send. This throws before a row is touched, so the caller retries.
    throw fail("read_failed", "recipients");
  }
  const byId = new Map();
  for (const recipient of recipients) {
    if (recipient == null) continue;
    byId.set(text(recipient.id), recipient);
  }

  let linkSkips = 0;
  for (const row of await pendingSendRows(db, reportId, runId)) {
    const rowId = text(row.id);
    const recipient = byId.get(text(row.recipient_id)) ?? null;
    // A pending row whose recipient is not approved (or whose seal no longer verifies) is not mail and
    // never will be: it settles `refused` / `recipient_not_approved`, the door's own word for exactly
    // that refusal, so it leaves `pending` instead of being offered again for the life of the log.
    if (!recipient || recipient.state !== "approved" || recipient.verified !== true) {
      await settlePendingRow(db, rowId, "refused", "recipient_not_approved", now);
      counts.skipped += 1;
      continue;
    }
    // A `sent`, `sending` or `unknown` row already answers for this recipient: this row can never go,
    // so it settles `refused` / `not_pending` (the door's word for a row that lost its turn) rather
    // than sitting in the scan for ever.
    if (await alreadySpokenFor(db, runId, recipient.id)) {
      await settlePendingRow(db, rowId, "refused", "not_pending", now);
      counts.skipped += 1;
      continue;
    }

    const outcome = await deliverToRecipient(db, d, {
      report, run, status, recipient, document, allowedLinks, override: null, artifactId, pinned,
      now, linkDays, sendId: rowId,
    });
    if (outcome === "nolink") {
      // Nothing was claimed and nothing was mailed: the row settles `failed` / `no_link`, so it stops
      // being offered (and stops blocking the owner's next tap) and the notice below stays its record.
      await settlePendingRow(db, rowId, "failed", "no_link", now);
      counts.skipped += 1;
      linkSkips += 1;
      continue;
    }
    if (outcome === "skipped") {
      counts.skipped += 1;
      continue;
    }
    if (DELIVERY_OUTCOMES.includes(outcome)) counts[outcome] += 1;
  }

  if (counts.failed + counts.unknown + counts.refused > 0) {
    await ring(db, d, {
      title: emailsNotSentNotice(title),
      body: countsText({
        sent: counts.sent,
        unknown: counts.unknown,
        notSent: counts.failed + counts.refused,
      }),
      priority: "high",
      essential: true,
      action_url: actionUrl,
      metadata: { reportId: text(report.id), runId },
    });
  }

  // The same rule as `deliver`: a recipient this instance has no link for is a mail that did not go.
  // Its row settles `failed` / `no_link` above (or it owns no row at all, in `deliver`), so this notice
  // is the one thing that says so, and it is counted as a skip rather than as a failed send.
  if (linkSkips > 0) {
    await ring(db, d, {
      title: emailsSkippedNotice(title),
      body: EMAILS_SKIPPED_BODY,
      priority: "high",
      essential: true,
      action_url: actionUrl,
      metadata: { reportId: text(report.id), runId },
    });
  }

  return counts;
}

/**
 * The `(db, payload)` seam `run.js` calls, with boot's own deps already in place.
 *
 * @param {object} [baseDeps] anything `deliver` takes (`adapterFor`, `approvals`, `localInstanceId`, ...)
 * @returns {(db: object, payload: object) => Promise<object>}
 */
export function makeDeliver(baseDeps = {}) {
  const base = baseDeps == null ? {} : baseDeps;
  return function deliverRun(db, payload) {
    return deliver(db, base, payload);
  };
}

/**
 * The `(db, {reportId, runId})` seam a caller with boot's deps calls to send the `pending` rows one run
 * already holds (the owner's "Send to the rest").
 *
 * @param {object} [baseDeps] anything `deliverPending` takes (`sendMail`, `adapterFor`, `approvals`, ...)
 * @returns {(db: object, input: {reportId: string, runId: string}) => Promise<object>}
 */
export function makeDeliverPending(baseDeps = {}) {
  const base = baseDeps == null ? {} : baseDeps;
  return function deliverPendingRun(db, { reportId, runId } = {}) {
    return deliverPending(db, base, { reportId, runId });
  };
}

export default deliver;