/**
 * Recipient comments: what a reader who opened a report from a mail may write, what that reader may see,
 * and how old reader threads close on their own.
 *
 * WHY A RECIPIENT'S COMMENT IS AN ARTIFACTS COMMENT: a report is an artifact version (see
 * `artifact-bridge.js`), and the owner and the report's bot already talk about it in the artifacts thread
 * store. A reader's comment therefore goes into that same store, as an author `{kind: "contact", id:
 * <recipient row id>}` with `tainted: true` (the text is one outside person's words: it is never treated
 * as trusted input, and a bot's later reply to it inherits that). Two consequences are on purpose:
 *   - the owner sees a reader's thread in the report page and in the artifacts panel with no new UI, and
 *     the report's bot can answer it through the round it already has;
 *   - a recipient id is `rrc-<16 hex>`, while a real contact id in the bundle is a `crow:<base36>`
 *     string, so the two identities can never collide in `author_id`.
 *
 * THE SIDE TABLE: every comment a recipient writes also records one `report_recipient_comments` row,
 * because the artifacts store knows nothing about reports and tokens. The row is `(comment_id, thread_id,
 * report_id, recipient_id, run_id, via, created_at)`: `comment_id` IS the artifacts comment id (the
 * bundle's ids are INTEGERs), `thread_id` is that comment's artifacts thread id held as TEXT so a
 * visibility lookup joins the bundle store on it instead of re-reading the comment, `via` is `link` for
 * everything this module writes, and `run_id` is the run the token opened. The row is also the log the
 * daily cap counts. Nothing here changes the bundle's shape: a reader's comment costs one row in a table
 * that already exists.
 *
 * THE DAILY CAP IS PER RECIPIENT AND PER REPORT: the artifacts store already caps a contact at 30
 * comments an hour and 20 open threads per artifact (its own abuse rails, shared with the artifact
 * viewer). A public link is reachable by anybody who has it, so the recipient path adds a lower, daily
 * cap of 20 comments in the last 24 hours, counted from this module's own side rows. It is checked BEFORE
 * the bundle call, so a refused comment never reaches the thread store at all. The two other bundle
 * refusals are mapped through unchanged (`rate_limited`, `too_many_threads`) and every other bundle
 * failure becomes the plain `other`, because a reader is shown one fixed line and never a database
 * message.
 *
 * ONE THREAD PER READER, UNTIL IT CLOSES: a follow-up goes into the reader's own OPEN thread on the same
 * artifact version, so the conversation with the bot stays in one place, and a new thread starts only
 * when the previous one was resolved. Two readers never share a thread, so the "own" visibility setting
 * cannot leak one reader's words into another's page.
 *
 * VISIBILITY AND THE WINDOW COME FROM THE SEALED LIVE SET, NEVER FROM THE REPORT ROW: both are live-set
 * fields (see `approvals.js`), so what the owner approved is what a reader's page obeys. A direct UPDATE
 * of `reports.comment_visibility` or `reports.comment_window_runs` therefore changes nothing a reader
 * sees, and neither does a settings write that paused the report and dropped its seal.
 * `verifiedCommentSettings` answers the two values the seal was verified over, or null when the seal does
 * not verify (a draft, a paused report whose live set moved, no keychain seed), and a null answer is the
 * NARROWEST pair: visibility `own` and the default window of four runs.
 *
 * WHAT THE VISIBILITY WORD MEANS: a reader's page only ever shows RECIPIENT THREADS, meaning threads that
 * carry at least one `report_recipient_comments` row (the side table says a recipient wrote in it), and
 * within them every comment, so the reader's own words, the owner's reply and the bot's answer all appear
 * together. A thread with no recipient row (an owner note or a bot note made from the artifacts panel) is
 * never shown to a reader, whatever the visibility: it is the owner's own workspace, not the conversation
 * a mailed reader is part of. `own` (the default) is only the threads THIS recipient wrote in; `all` is
 * every recipient thread on that version, other readers' threads included, each with its own labels.
 * Nothing else is ever included, and a deleted comment never appears (`listThreads` skips it).
 *
 * THE WINDOW: `comment_window_runs` (1 to 50, four by default) says how many of the report's newest
 * non-preview runs still ACCEPT COMMENTS. An older version stays readable and closed: the door renders
 * no comment form for it, `postRecipientComment` refuses a comment on it with `view_only` (the fixed
 * "comments aren't open on this link" line a reader already knows), and after every finished non-preview
 * run `autoResolveRecipientThreads` resolves the threads on versions older than the window, plus any
 * thread on an older version that the bot already answered, so a reader's 20-open-thread cap is never
 * consumed by threads nobody will look at again. A resolved thread stays readable (it renders with the
 * closed tag); it only stops accepting appends.
 *
 * THE OWNER'S NOTICE: a `too_many_threads` refusal means READERS cannot start a new thread until older
 * ones close, which only the owner can do (or the next run's window pass), so the owner is rung once per
 * report per UTC day. The day is remembered in `report_state` under a key this module owns (reserved in
 * `artifact-bridge.js`, so a recipe block cannot write it). The notice text is fixed wording, EN and ES,
 * kept verbatim (a test pins it), and it is rung in the owner's dashboard language, read from
 * `dashboard_settings` the way the bundle pull alert reads it.
 *
 * THE BUNDLE IS LOADED AT RUNTIME, NOT IMPORTED: Crow Artifacts is a bundle installed at runtime, so its
 * `comments.js` is imported by PATH from the installed copy (the artifact bridge's precedent) and cached
 * per process. `deps.comments` (or a `comments` member on an injected `deps.artifacts` runtime) wins, so
 * a test exercises the bundle modules from this repo without an installed copy.
 *
 * Nothing here reads, writes or logs a raw link token: the only token facts used are the report, run,
 * artifact version and scope that `resolveLinkToken` already answered, and nothing here mints, revokes or
 * verifies a token.
 */
import { existsSync } from "node:fs";
import { join } from "node:path";
import { pathToFileURL } from "node:url";
import { resolveCrowHome } from "../../shared/crow-home.js";
import { createNotification } from "../../shared/notifications.js";
import { fill } from "../dashboard/shared/i18n.js";
import { DEFAULT_COMMENT_WINDOW_RUNS, verifiedCommentSettings } from "./approvals.js";
import { loadArtifactsRuntime } from "./artifact-bridge.js";
import { reportPagePath } from "./links.js";
import { copyFor } from "./recipient-copy.js";
import { getReport, getState, setState } from "./store.js";

/** The most characters one comment may hold. Mirrors the bundle's `LIMITS.commentChars`, which cannot be
 *  imported statically because that file lives in the installed bundle; the check runs before any bundle
 *  call, so it is stated here rather than read from a runtime that may not exist yet. */
const COMMENT_MAX_CHARS = 4000;

/** How many comments one recipient may leave on one report in 24 hours. */
const DAILY_COMMENT_CAP = 20;

const DAY_MS = 86_400_000;

/** The `report_state` key that remembers the UTC day the owner's notice last rang for a report. */
export const NOTICE_DAY_STATE_KEY = "recipient_comments_notice_day";

/** The longest report title a notice carries (the title is untrusted text). */
const NOTICE_TITLE_MAX = 80;

/** Control characters removed from a display name or a notice title. */
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g;

/**
 * The owner's notice, EN and ES, kept verbatim (a test pins it). `{report}` is filled with the report's
 * own title, cleaned the way `delivery.js` cleans a title for a notice.
 */
const TOO_MANY_THREADS_NOTICE = Object.freeze({
  en: "{report}: too many open comments. Readers can't start new ones until older ones close.",
  es: "{report}: demasiados comentarios abiertos. Nadie puede empezar uno nuevo hasta que se cierren los anteriores.",
});

/** The page a comment-scope token opens. A token that opens anything else cannot post. */
const COMMENT_SCOPE = "comment";

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

/** Epoch ms from the injected clock, so a test's fake clock moves every time this module writes. */
function clockOf(deps) {
  const value = Number(deps == null || deps.now == null ? NaN : deps.now());
  return Number.isFinite(value) ? value : Date.now();
}

/** The UTC day a moment belongs to, as `YYYY-MM-DD`. One day is one notice, in every host time zone. */
function utcDay(ms) {
  return new Date(ms).toISOString().slice(0, 10);
}

/** `deps` with every member present; a member that is absent falls back to the real thing. */
function resolveDeps(deps) {
  const given = deps == null ? {} : deps;
  const fn = (key, fallback) => (typeof given[key] === "function" ? given[key] : fallback);
  return {
    ...given,
    now: fn("now", Date.now),
    notify: fn("notify", createNotification),
  };
}

/* -------------------------------------------------------------- the settings in force */

/**
 * What a reader's page and a reader's post obey: the visibility and the comment window from the VERIFIED
 * live set, and the NARROWEST pair (`own`, the default window) when the seal does not verify.
 *
 * One read of the verified set per call, so a page never mixes a visible thread list from one approval
 * with a window from another.
 *
 * @param {object} db a libsql-shaped client
 * @param {object} [deps] the seam (`loadSeed` and `now` are the approvals seam this reads the seal with)
 * @param {object|null} report a report row
 * @returns {Promise<{visibility: "own"|"all", windowRuns: number}>}
 */
async function settingsInForce(db, deps, report) {
  const verified = await verifiedCommentSettings(db, deps == null ? {} : deps, report);
  if (!verified) return { visibility: "own", windowRuns: DEFAULT_COMMENT_WINDOW_RUNS };
  const window = Number(verified.commentWindowRuns);
  return {
    visibility: verified.commentVisibility === "all" ? "all" : "own",
    windowRuns: Number.isInteger(window) && window >= 1 ? window : DEFAULT_COMMENT_WINDOW_RUNS,
  };
}

/**
 * The report's newest non-preview version numbers that still accept comments: the window itself, read
 * with the same ordering the window pass uses (`n` descending, previews excluded).
 *
 * An empty set is a report with no run versions at all, and null is a read that failed. A caller decides
 * what a failure means: the window pass closes nothing on it, and a post is refused on it (fail closed).
 *
 * @param {object} db a libsql-shaped client
 * @param {string} reportId
 * @param {number} window how many of the newest run versions still take comments
 * @returns {Promise<Set<number>|null>}
 */
async function openVersionsFor(db, reportId, window) {
  try {
    const { rows } = await db.execute({
      sql: `SELECT DISTINCT n FROM report_versions
             WHERE report_id = ? AND "trigger" <> 'preview'
             ORDER BY n DESC LIMIT ?`,
      args: [reportId, window],
    });
    const open = new Set();
    for (const candidate of rows) {
      const n = Number(candidate.n);
      if (Number.isInteger(n)) open.add(n);
    }
    return open;
  } catch {
    return null;
  }
}

/**
 * Does the version one token opens still accept comments?
 *
 * A page and a post both ask this, so an old link stays readable and closed: the door offers no form and
 * a hand-made post is refused with the same line a view-only link gets. The window is the VERIFIED one
 * (`settingsInForce`), so neither a direct column UPDATE nor a paused report re-opens a page. A read that
 * fails is "no": a comment that nobody can place in the window must not land.
 *
 * @param {object} db a libsql-shaped client
 * @param {object} [deps] the seam (`loadSeed`, `now`)
 * @param {{report?: object, versionN?: number}} input
 * @returns {Promise<boolean>}
 */
export async function commentOpenFor(db, deps, { report = null, versionN = null } = {}) {
  const reportId = text(report == null ? "" : report.id);
  const version = Number(versionN);
  if (!reportId || !Number.isInteger(version)) return false;
  const { windowRuns } = await settingsInForce(db, deps, report);
  const open = await openVersionsFor(db, reportId, windowRuns);
  return open != null && open.has(version);
}

/* ------------------------------------------------------------------ the bundle runtime */

/** The bundle's comments module, once this process loaded it. */
let cachedComments = null;

/**
 * The artifacts bundle's `comments.js`: the functions that own threads and comments, caps included.
 *
 * `deps.comments` wins (a test passes the bundle module from this repo), then a `comments` member on the
 * injected `deps.artifacts` runtime, then the installed copy, imported by PATH the way the artifact
 * bridge loads `store.js`. An instance with no installed bundle answers `artifacts_missing`, which the
 * caller maps to `other`: a recipient page says it did not go through rather than inventing an error.
 *
 * @param {object} [deps]
 * @returns {Promise<object>} `{addThread, addComment, setThreadStatus, listThreads}`
 * @throws {Error} `artifacts_missing`
 */
export async function commentsRuntime(deps = {}) {
  const given = deps == null ? {} : deps;
  if (given.comments) return given.comments;
  const runtime = await loadArtifactsRuntime(given);
  if (runtime && runtime.comments) return runtime.comments;
  if (cachedComments) return cachedComments;
  const dir = join(resolveCrowHome(), "bundles", "artifacts", "server");
  if (!existsSync(join(dir, "comments.js"))) {
    throw fail("artifacts_missing");
  }
  cachedComments = await import(pathToFileURL(join(dir, "comments.js")).href);
  return cachedComments;
}

/** Test seam: forget the comments module this process cached. */
export function _resetCommentsRuntimeForTest() {
  cachedComments = null;
}

/* ------------------------------------------------------------------------- the text */

/**
 * One comment's text as the thread store takes it: `\r\n` and lone `\r` are one line break and the ends
 * are trimmed, exactly the normalisation the bundle's own `cleanText` applies, so what is measured here
 * is what is stored.
 *
 * @param {*} value
 * @returns {string}
 * @throws {Error} `empty` when nothing is left, `too_long` past `COMMENT_MAX_CHARS`
 */
function cleanCommentText(value) {
  const body = String(value == null ? "" : value).replace(/\r\n?/g, "\n").trim();
  if (!body) throw fail("empty");
  if (body.length > COMMENT_MAX_CHARS) throw fail("too_long");
  return body;
}

/* ------------------------------------------------------------------- the side table */

/**
 * How many comments this recipient left on this report in the last 24 hours: the side rows are the log,
 * one per comment, so the cap is a count and not a guess.
 */
async function recentCommentCount(db, reportId, recipientId, now) {
  const { rows } = await db.execute({
    sql: `SELECT COUNT(*) AS n FROM report_recipient_comments
           WHERE report_id = ? AND recipient_id = ? AND created_at > ?`,
    args: [reportId, recipientId, now - DAY_MS],
  });
  return Number(rows[0] == null ? 0 : rows[0].n);
}

/**
 * The recipient's most recent OPEN thread on this artifact version, as the side table knows it, or null.
 *
 * The side row stores the comment's artifacts thread id, so this is "a thread this reader wrote in, still
 * open, on this version" from reports' own rows alone. The bundle's per-contact open-thread cap is
 * counted on `artifact_threads`, which is why a thread the side table has no row for (one made by hand,
 * or by a future path) is never appended to here: it is not this reader's.
 */
async function openThreadOf(db, { reportId, recipientId, artifactId, versionN }) {
  const { rows } = await db.execute({
    sql: `SELECT t.id AS thread_id
            FROM report_recipient_comments rc
            JOIN artifact_threads t ON t.id = CAST(rc.thread_id AS INTEGER)
           WHERE rc.report_id = ? AND rc.recipient_id = ?
             AND t.artifact_id = ? AND t.version_n = ?
             AND t.status <> 'resolved'
             AND t.author_kind = 'contact' AND t.author_id = ?
           ORDER BY t.id DESC
           LIMIT 1`,
    args: [reportId, recipientId, artifactId, versionN, recipientId],
  });
  const id = Number(rows[0] == null ? NaN : rows[0].thread_id);
  return Number.isInteger(id) && id > 0 ? id : null;
}

/** The id of a thread's first comment, which is what a new thread's side row names. */
async function firstCommentId(db, threadId) {
  const { rows } = await db.execute({
    sql: "SELECT MIN(id) AS id FROM artifact_comments WHERE thread_id = ?",
    args: [threadId],
  });
  const id = Number(rows[0] == null ? NaN : rows[0].id);
  return Number.isInteger(id) && id > 0 ? id : null;
}

/**
 * Record one comment in the side table: the artifacts comment id, its thread id as TEXT, the report, the
 * recipient, the run the token opened and how the reader got there (`link`). It is one row per comment,
 * so the daily cap is a count of these rows and a visibility lookup needs no join on the comment.
 */
async function writeSideRow(db, {
  commentId, threadId, reportId, runId, recipientId, createdAt,
}) {
  await db.execute({
    sql: `INSERT INTO report_recipient_comments
            (comment_id, thread_id, report_id, recipient_id, run_id, via, created_at)
          VALUES (?, ?, ?, ?, ?, 'link', ?)`,
    args: [commentId, String(threadId), reportId, recipientId, runId, createdAt],
  });
}

/* ------------------------------------------------------------------------ posting */

/**
 * Post one comment from a reader who opened a report through a comment-scope link.
 *
 * THE ORDER, and why: the scope first (a view-only link has no form, and a hand-made request must not
 * reach a thread), then the WINDOW (a version past it is readable but closed, so a request made by hand
 * is refused here rather than appended to a thread nobody will look at again), then the text (a refusal a
 * reader caused costs no database work past the side table), then the daily cap, then the thread store.
 * Each refusal is an `Error` with a `code` the door maps to one fixed line; the window's code is
 * `view_only`, because the line a reader already knows for "this link doesn't take comments" is exactly
 * what a closed page says.
 *
 * WHERE IT GOES: the reader's own open thread on the token's artifact and version, when there is one,
 * so a follow-up continues the conversation; otherwise a new thread anchored to the report as a whole
 * (`{kind: "whole"}`) on that exact version. A resolved thread starts a new one (the window pass closes
 * old threads; closing must never silently swallow the next question).
 *
 * @param {object} db a libsql-shaped client
 * @param {object} [deps] the seam (`comments`, `artifacts` runtime, `notify`, `now`, `lang`, and the
 *   approvals seam's `loadSeed` that the verified comment window is read with)
 * @param {{resolved: object, text: *}} input `resolved` is a `resolveLinkToken` "ok" answer
 * @returns {Promise<{ok: true, threadId: number, commentId: number}>}
 * @throws {Error} `view_only`, `empty`, `too_long`, `rate_limited`, `too_many_threads`, `other`
 */
export async function postRecipientComment(db, deps, { resolved = null, text: raw = null } = {}) {
  const d = resolveDeps(deps);
  const token = resolved == null ? null : resolved.token;
  const report = resolved == null ? null : resolved.report;
  const recipient = resolved == null ? null : resolved.recipient;
  if (!token || !report || !recipient) throw fail("other");
  if (text(token.scope) !== COMMENT_SCOPE) throw fail("view_only");

  const body = cleanCommentText(raw);

  const reportId = text(report.id);
  const recipientId = text(recipient.id);
  const artifactId = text(token.artifactId);
  const runId = text(token.runId);
  const versionN = Number(token.versionN);
  if (!reportId || !recipientId || !artifactId || !runId) throw fail("other");
  if (!Number.isInteger(versionN) || versionN < 1) throw fail("other");

  const now = clockOf(d);
  // The window: a version outside the report's verified comment window stays readable and closed, whatever
  // the token's scope says. A read that cannot place the version in the window refuses it (fail closed).
  if (!(await commentOpenFor(db, d, { report, versionN }))) throw fail("view_only");

  // The cap and the reader's own open thread are this module's own reads. A read that fails cannot
  // promise either, so the reader is told the plain generic line rather than posting blind.
  let threadId = null;
  try {
    const recent = await recentCommentCount(db, reportId, recipientId, now);
    if (recent >= DAILY_COMMENT_CAP) throw fail("rate_limited");
    threadId = await openThreadOf(db, { reportId, recipientId, artifactId, versionN });
  } catch (err) {
    if (text(err == null ? "" : err.code) === "rate_limited") throw err;
    throw fail("other");
  }

  let comments;
  try {
    comments = await commentsRuntime(d);
  } catch {
    throw fail("other");
  }

  const author = { kind: "contact", id: recipientId };
  let commentId = null;
  try {
    if (threadId != null) {
      const added = await comments.addComment(db, { threadId, text: body, author, tainted: true });
      commentId = Number(added == null ? NaN : added.commentId);
    } else {
      const made = await comments.addThread(db, {
        artifactId, versionN, anchor: { kind: "whole" }, text: body, author, tainted: true,
      });
      threadId = Number(made == null ? NaN : made.threadId);
      if (Number.isInteger(threadId) && threadId > 0) commentId = await firstCommentId(db, threadId);
    }
  } catch (err) {
    const code = text(err == null ? "" : err.code);
    if (code === "too_many_threads") {
      // Best effort: the reader is told the plain line either way, and a notice that cannot be written
      // never changes the refusal.
      try {
        await notifyTooManyThreads(db, d, { report });
      } catch {
        // The refusal stands; the bell is the owner's convenience, the refusal is the reader's answer.
      }
      throw fail("too_many_threads");
    }
    if (code === "rate_limited") throw fail("rate_limited");
    throw fail("other");
  }
  if (!Number.isInteger(threadId) || threadId < 1) throw fail("other");
  if (!Number.isInteger(commentId) || commentId < 1) throw fail("other");

  try {
    await writeSideRow(db, {
      commentId, threadId, reportId, runId, recipientId, createdAt: now,
    });
  } catch {
    // The comment itself landed; without its side row the daily cap and the reader's own visibility
    // cannot see it, so the reader is told the generic line instead of a page that hides their words.
    throw fail("other");
  }
  return { ok: true, threadId, commentId };
}

/* ------------------------------------------------------------------- the error line */

/**
 * The one fixed line a reader sees above the comment box for a refusal code, in the page's language.
 *
 * @param {*} code an `Error.code` from `postRecipientComment` (anything else answers the generic line)
 * @param {*} [lang] "en", "es", or a tag whose language is one of the two
 * @returns {string}
 */
export function commentErrorLine(code, lang = "en") {
  const table = copyFor(lang);
  switch (text(code)) {
    case "rate_limited":
      return table.errRate;
    case "too_many_threads":
      return table.errThreads;
    case "too_long":
      return table.errTooLong;
    case "empty":
      return table.errEmpty;
    case "view_only":
      return table.errViewOnly;
    default:
      return table.errOther;
  }
}

/* ------------------------------------------------------------------ the owner notice */

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

/**
 * The report's title as a notice may carry it: one line, no control characters, bounded. The same rule
 * `delivery.js` applies to every report notice (its own copy of this helper is private to that module,
 * and the fold is small enough that duplicating it is better than making the recipient path import the
 * whole delivery stack).
 */
export function noticeTitleOf(report) {
  const flat = oneLine(report == null ? "" : report.title);
  return bound(flat, NOTICE_TITLE_MAX).trim() || "This report";
}

/** The owner's dashboard language, read from the setting the bundle alerts read, else English. */
export async function ownerLanguage(db) {
  try {
    const { rows } = await db.execute({
      sql: "SELECT value FROM dashboard_settings WHERE key = 'language'",
      args: [],
    });
    const value = text(rows[0] == null ? "" : rows[0].value);
    return value === "es" ? "es" : "en";
  } catch {
    return "en";
  }
}

/**
 * Ring the owner's bell about a report that has too many open reader threads, at most once per UTC day.
 *
 * WHY THE OWNER: `too_many_threads` means READERS cannot start a new thread until older ones close. The
 * report's next run closes the ones past the window on its own, but until then the only person who can
 * act is the owner, so the notice is essential (a switched-off notification type must not hide the one
 * thing nobody else records). The day is stamped in `report_state` only after the notice was written, so
 * a notice that failed to land is offered again.
 *
 * @param {object} db a libsql-shaped client
 * @param {object} [deps] the seam (`notify`, `now`, `lang`)
 * @param {{report: object}} input
 * @returns {Promise<boolean>} true when this call rang the bell
 */
export async function notifyTooManyThreads(db, deps, { report = null } = {}) {
  const d = resolveDeps(deps);
  const reportId = text(report == null ? "" : report.id);
  if (!reportId) return false;
  const day = utcDay(clockOf(d));

  let remembered = null;
  try {
    remembered = await getState(db, reportId, NOTICE_DAY_STATE_KEY);
  } catch {
    // An unreadable memory is not "already told today": a missing bell is the worse error.
    remembered = null;
  }
  if (text(remembered) === day) return false;

  const lang = text(d.lang) === "es" ? "es" : text(d.lang) === "en" ? "en" : await ownerLanguage(db);
  const title = fill(TOO_MANY_THREADS_NOTICE[lang], { report: noticeTitleOf(report) });
  const actionUrl = await reportPagePath(db, report);

  try {
    await d.notify(db, {
      type: "reports",
      source: "reports",
      essential: true,
      priority: "high",
      title,
      body: null,
      action_url: actionUrl,
      metadata: { reportId, kind: "recipient-comments" },
    });
  } catch {
    return false;
  }
  try {
    await setState(db, reportId, NOTICE_DAY_STATE_KEY, day);
  } catch {
    // The stamp is bookkeeping: a bell that rang is not un-rung by a failed write.
  }
  return true;
}

/* ---------------------------------------------------------------------- visibility */

/** A recipient id → display name map for the other readers whose comments a view may show. */
async function displayNames(db, reportId, ids) {
  const out = new Map();
  const wanted = [...new Set(ids.filter((id) => typeof id === "string" && id))];
  if (!wanted.length) return out;
  let rows = [];
  try {
    rows = (await db.execute({
      sql: `SELECT id, display_name FROM report_recipients
             WHERE report_id = ? AND id IN (${wanted.map(() => "?").join(",")})`,
      args: [reportId, ...wanted],
    })).rows;
  } catch {
    return out;
  }
  for (const row of rows) {
    const name = text(row.display_name).replace(/[\p{Cc}\p{Cf}]/gu, "").trim().slice(0, 60).trim();
    if (name) out.set(text(row.id), name);
  }
  return out;
}

/**
 * The thread ids this recipient wrote in, through the side table. Under `own` visibility these are the
 * only threads their page shows, with every comment inside them.
 */
async function startedThreadIds(db, reportId, recipientId) {
  const out = new Set();
  let rows = [];
  try {
    rows = (await db.execute({
      sql: `SELECT DISTINCT thread_id FROM report_recipient_comments
             WHERE report_id = ? AND recipient_id = ?`,
      args: [reportId, recipientId],
    })).rows;
  } catch {
    return out;
  }
  for (const row of rows) {
    const id = Number(row.thread_id);
    if (Number.isInteger(id) && id > 0) out.add(id);
  }
  return out;
}

/**
 * The thread ids that carry at least one recipient comment on this report, through the side table. Under
 * `all` visibility these are the threads a reader's page shows (and nothing else): a thread the owner or
 * the bot started from the artifacts panel has no side row, so it is never a reader's page.
 */
async function recipientThreadIds(db, reportId) {
  const out = new Set();
  let rows = [];
  try {
    rows = (await db.execute({
      sql: `SELECT DISTINCT thread_id FROM report_recipient_comments WHERE report_id = ?`,
      args: [reportId],
    })).rows;
  } catch {
    // A read that fails shows nothing: a page that cannot tell which threads are a reader's own must not
    // guess at one.
    return out;
  }
  for (const row of rows) {
    const id = Number(row.thread_id);
    if (Number.isInteger(id) && id > 0) out.add(id);
  }
  return out;
}

/** One comment's author label, already the words the page shows (the view escapes them). */
function labelFor(comment, table, recipientId, names) {
  const kind = text(comment.author_kind);
  if (kind === "contact") {
    if (text(comment.author_id) === recipientId) return table.you;
    return names.get(text(comment.author_id)) || table.anotherReader;
  }
  if (kind === "owner") return table.sender;
  if (kind === "bot") {
    return fill(table.bot, { bot: text(comment.author_name || comment.author_id) });
  }
  // No other author kind exists in the bundle's store; a row that somehow carries one is shown as
  // somebody else, never as the reader or the sender.
  return table.anotherReader;
}

/**
 * The `threads` array `buildRecipientView` takes: this reader's page of the threads on one version.
 *
 * ONLY RECIPIENT THREADS, NEVER THE OWNER'S OWN NOTES: a thread is shown when it carries a
 * `report_recipient_comments` row, which is what says a recipient wrote in it. A thread the owner or the
 * report's bot started from the artifacts panel has no such row and never reaches a reader's page under
 * either visibility. Inside a shown thread every comment appears (the reader's own, the owner's reply and
 * the bot's answer).
 *
 * `own` (the default, and what an unverified seal falls back to) shows the threads THIS recipient wrote
 * in; `all` shows every recipient thread on the version, other readers' included. Both come from the
 * VERIFIED live set (`settingsInForce`), never from the report row. A thread from outside the allowed set
 * never contributes a comment, whatever its status. Texts are passed through untouched: the view escapes
 * them.
 *
 * @param {object} db a libsql-shaped client
 * @param {object} [deps] the seam (`comments`, `artifacts` runtime, and the approvals seam's `loadSeed`)
 * @param {{report?: object, recipient?: object, artifactId?: string, versionN?: number, lang?: string}} input
 * @returns {Promise<{id: number, status: "open"|"resolved", comments: {label: string, text: string,
 *   createdAt: number}[]}[]>} an empty list for anything unreadable, never a throw
 */
export async function visibleThreadsFor(db, deps, {
  report = null, recipient = null, artifactId = null, versionN = null, lang = "en",
} = {}) {
  const table = copyFor(lang);
  const reportId = text(report == null ? "" : report.id);
  const recipientId = text(recipient == null ? "" : recipient.id);
  const artifact = text(artifactId);
  const version = Number(versionN);
  if (!reportId || !recipientId || !artifact) return [];
  if (!Number.isInteger(version)) return [];

  let comments;
  try {
    comments = await commentsRuntime(deps == null ? {} : deps);
  } catch {
    return [];
  }
  let threads;
  try {
    threads = await comments.listThreads(db, artifact);
  } catch {
    return [];
  }
  if (!Array.isArray(threads)) return [];

  const { visibility } = await settingsInForce(db, deps, report);
  const allowed = visibility === "all"
    ? await recipientThreadIds(db, reportId)
    : await startedThreadIds(db, reportId, recipientId);
  const selected = threads.filter((thread) => {
    if (!thread || typeof thread !== "object") return false;
    if (Number(thread.version_n) !== version) return false;
    const id = Number(thread.id);
    // A thread with no recipient row is nobody's conversation but the owner's: it is never shown.
    return allowed.has(id);
  });

  // The names of the other readers whose comments this page may show, in one read.
  const otherIds = [];
  for (const thread of selected) {
    for (const comment of Array.isArray(thread.comments) ? thread.comments : []) {
      if (comment && text(comment.author_kind) === "contact" && text(comment.author_id) !== recipientId) {
        otherIds.push(text(comment.author_id));
      }
    }
  }
  const names = await displayNames(db, reportId, otherIds);

  return selected.map((thread) => ({
    id: Number(thread.id),
    status: text(thread.status) === "resolved" ? "resolved" : "open",
    comments: (Array.isArray(thread.comments) ? thread.comments : []).map((comment) => ({
      label: labelFor(comment, table, recipientId, names),
      text: text(comment.text),
      createdAt: Number(comment.ts) || 0,
    })),
  }));
}

/* ------------------------------------------------------------------ the window pass */

/**
 * Has the bot answered this thread since the recipient last wrote in it? Used for an older version that
 * is still inside the window: the question was answered, so the thread may close even though its version
 * is not yet past the window.
 */
async function answeredAfterReader(db, threadId) {
  const { rows } = await db.execute({
    sql: `SELECT 1 FROM artifact_comments
           WHERE thread_id = ? AND author_kind = 'bot'
             AND id > (SELECT COALESCE(MAX(id), 0) FROM artifact_comments
                        WHERE thread_id = ? AND author_kind = 'contact')
           LIMIT 1`,
    args: [threadId, threadId],
  });
  return rows.length > 0;
}

/**
 * Close the reader threads a report's comment window has passed, after a finished run.
 *
 * WHAT CLOSES:
 *   - every thread this report's readers wrote in whose version is OLDER than the newest
 *     `comment_window_runs` non-preview versions of the report (the VERIFIED window, so a direct column
 *     UPDATE never moves it), and
 *   - any such thread whose version is not the newest one and that already has a bot comment after the
 *     recipient's last comment (the answer landed, so the thread's work is done).
 *
 * A resolved thread stays readable: closing only stops a new comment from appending to it, and the next
 * question starts a new thread. The pass is idempotent (a resolved thread is skipped by the query) and
 * best effort: one thread that would not close is not the others' problem, and a pass that cannot run
 * never fails the run that triggered it.
 *
 * @param {object} db a libsql-shaped client
 * @param {object} [deps] the seam (`comments`, `artifacts` runtime)
 * @param {{report?: object}} input the report the finished run belongs to
 * @returns {Promise<number>} how many threads this pass resolved
 */
export async function autoResolveRecipientThreads(db, deps, { report = null } = {}) {
  try {
    const reportId = text(report == null ? "" : report.id);
    if (!reportId) return 0;
    let fresh = null;
    try {
      fresh = await getReport(db, reportId);
    } catch {
      fresh = null;
    }
    const row = fresh ?? report;
    const { windowRuns } = await settingsInForce(db, deps, row);

    // The report's newest versions that still accept comments: the window itself. A read that fails closes
    // nothing (a window pass is not the place to guess), and a report with no versions has nothing past it.
    const open = await openVersionsFor(db, reportId, windowRuns);
    if (!open || !open.size) return 0;
    const newest = Math.max(...open);

    // The threads this report's readers wrote in, through the side table, still open.
    const { rows: threadRows } = await db.execute({
      sql: `SELECT DISTINCT t.id AS id, t.artifact_id AS artifact_id, t.version_n AS version_n
              FROM report_recipient_comments rc
              JOIN artifact_threads t ON t.id = CAST(rc.thread_id AS INTEGER)
             WHERE rc.report_id = ? AND t.status <> 'resolved'`,
      args: [reportId],
    });
    if (!threadRows.length) return 0;

    let comments;
    try {
      comments = await commentsRuntime(deps == null ? {} : deps);
    } catch {
      return 0;
    }

    let resolved = 0;
    for (const thread of threadRows) {
      const threadId = Number(thread.id);
      const versionN = Number(thread.version_n);
      const artifactId = text(thread.artifact_id);
      if (!Number.isInteger(threadId) || threadId < 1 || !artifactId) continue;
      const pastWindow = !open.has(versionN);
      const answered = versionN !== newest && (await answeredAfterReader(db, threadId).catch(() => false));
      if (!pastWindow && !answered) continue;
      try {
        await comments.setThreadStatus(db, { threadId, status: "resolved", artifactId });
        resolved += 1;
      } catch {
        // One thread that would not close is not the others' problem.
      }
    }
    return resolved;
  } catch {
    return 0;
  }
}

export default postRecipientComment;