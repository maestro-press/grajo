/**
 * Where one report email sends its reader: the link KIND a recipient's comment tier earns, the URL of
 * that kind for one recipient, and the token that URL carries for a reader outside this instance.
 *
 * THE THREE KINDS (spec R15). A recipient's tier decides what a reader may do with the report:
 *   - `c`: the reader has no page to comment on, so the link is the OWNER-VIEW run page,
 *     `/dashboard/project/<slug>/reports/<report id>/runs/<run id>`, on this instance (`dashboard`);
 *   - `a` and `b`: the reader gets a public page (`public-comment` for tier `a`, `public-view` for tier
 *     `b`), which need a per-recipient, per-run token minted here. The page kind is DERIVED from the
 *     token's scope (`comment` -> `public-comment`, `view` -> `public-view`), never stored as a kind.
 *
 * THE PUBLIC ORIGIN IS A SETTING, NOT A GUESS: `reports.public_origin` (a clean https origin, see
 * `publicOriginOf`) is the only place a public link points. With no setting `publicLinkFor` answers null,
 * which both callers already read as "this recipient cannot be mailed": delivery skips it and rings the
 * owner's notice, and go-live refuses with `link_unavailable`. A report whose recipients are all tier `c`
 * therefore keeps working with no setting at all, and nobody ever mails a link built on an address this
 * instance only guessed at.
 *
 * THE TOKEN (spec R15): 32 random bytes, base64url (43 characters), minted per send row, so per
 * recipient and per run. Only its sha256 is stored (`report_link_tokens.token_hash`, unique): the raw
 * token is returned to the caller that mails it and is never written, logged or named in an error. It
 * opens exactly ONE version, the run's non-preview `report_versions` row AS IT STOOD AT MINT: that
 * artifact id and version number are columns of the token row (`artifact_id`, `version_n`), so a
 * resolve serves what the mail was sent for and never re-derives it from the run, and exactly one
 * reader, a recipient that is still approved with a seal that still verifies. `resolveLinkToken`
 * re-checks all of that on EVERY resolve, with no cache, because a revocation, an expiry and a failed
 * send each have to take effect on the next click rather than at the next restart.
 *
 * TWO MORE BINDINGS THE RESOLVE MAKES, because a token is a promise made when a mail went out and it
 * has to be re-judged against the rows as they stand NOW:
 *
 *   - THE APPROVAL IT WAS MINTED UNDER. Every token stores the recipient's `approval_nonce` at mint time
 *     (`report_link_tokens.approval_nonce`, required), and a resolve requires that value to equal the
 *     nonce the recipient row holds NOW. A revoke, a refusal and a re-approval each write a fresh nonce
 *     or NULL it, so every older token dies on the next click even when the explicit revoke call in
 *     `approvals.js` never landed: that call is best effort, and this binding is the half that cannot
 *     fail open. A recipient row with no nonce cannot mint at all.
 *   - THE TIER IN FORCE NOW. The scope a token opens is the LOWER of what the row STORED (`scope`, the
 *     page it was minted for) and what `commentTierOf(currentReport, currentRecipient)` allows: tier `a`
 *     allows `comment`, tier `b` allows `view`, and tier `c` allows no public page at all, so the answer
 *     is `unknown`. A stored `view` token never RISES to `comment`, so lowering a recipient's tier (or
 *     the report's own default, for a recipient with no tier of their own) narrows or closes a link that
 *     is already in somebody's inbox. The effective scope is returned as `token.scope`, which is the
 *     field the door and the comments module read, and the stored one as `token.storedScope`.
 *   - THE REPORT'S OWN STANDING. A token is only as open as the report it points at:
 *       - `live` (the status word AND a seal that still verifies over the row as it stands now) behaves
 *         as every other binding above says;
 *       - `paused` keeps the page READABLE and stops there: the resolve is `ok` and `token.scope` is
 *         forced to `view`, so the door renders no comment form and a posted comment is refused with the
 *         existing view-only line;
 *       - a status word that still says `live` over a seal that no longer verifies (what a direct UPDATE
 *         of a live-set column leaves behind) is read exactly as `paused`: the seal is the approval, and
 *         a word nobody approved may not keep a page taking comments;
 *       - any other word (a `draft`, an archived report, anything a future PR invents) is `unknown`, the
 *         same answer a token that never existed gets. A link in a mail is a link to an APPROVED report.
 * *
 * THE HOLD: a minted token holds the version it stored for `reports.link_days` (the same setting and the
 * same default `delivery.js` reads for send holds) under the holder `report-link:<token id>`, so retention
 * never prunes a version an email still points at. Revoking, re-minting and expiry release that hold; a
 * version nothing points at is free to prune again.
 *
 * WHY THE ARTIFACT BRIDGE, THE APPROVALS MODULE AND THE REPORT STORE ARE LOADED ON FIRST USE:
 * `approvals.js` imports this module, the artifact bridge imports `approvals.js`, and the report store
 * reaches `approvals.js` through the block registry (`blocks/index.js` -> `present/ai-commentary.js`),
 * so a static import of any of them from here would close a cycle. Loading them where they are used keeps
 * the import graph one-way and costs a boot nothing until a reader clicks a token.
 *
 * WHY TIER `c` IS THE ONLY DASHBOARD PATH: a Crow user on this instance would also get `dashboard`, but
 * this PR has no way to tell that a recipient's address belongs to a Crow user on this instance, so no
 * such reader is recognised yet. Every tier `c` recipient gets the owner-view run page, which is this
 * instance's own dashboard and therefore not something an outside reader can open.
 *
 * THE SLUG comes from `project_spaces` (the report's `project_id` names one), because the dashboard
 * route is keyed by the project's slug, not its id. A report with no project, or a project row this
 * instance no longer has, has no slug: `linkFor` answers null rather than a wrong URL.
 *
 * THE BASE is the caller's (`baseUrl`) when one is given, else the dashboard base
 * `resolveDashboardBase` resolves for this instance (`servers/gateway/dashboard-link-base.js`):
 * `CROW_DASHBOARD_URL`, then this instance's own `crow_instances.gateway_url` (never a wildcard bind or
 * a loopback address), then `CROW_GATEWAY_URL`. A caller that already knows which registry row is this
 * instance's own passes `localInstanceId`, so the own-row step reads that row instead of the
 * instance-id file. The order exists because on a Tailscale install
 * `CROW_GATEWAY_URL` is the PUBLIC Funnel origin on port 443, which serves only the public paths in
 * PUBLIC_FUNNEL_PREFIXES and answers 404 for `/dashboard`: the dashboard lives on its own tailnet-only
 * HTTPS port, and that is the door an email link has to name.
 *
 * With no base at all the answer is NULL, never the path alone: a mail client cannot open a relative
 * path, and both callers read null as "this recipient cannot be mailed" (delivery skips it and rings
 * the owner's own notice; go-live refuses with `link_unavailable`). `isAbsoluteHttpUrl` is the second,
 * independent check a caller makes on a link it was handed.
 *
 * Nothing here sends anything. The dashboard path is two reads (the project's slug and this instance's
 * secret-free base URL) and one string; the public path adds one setting read, the token's own row and,
 * on a click, the checks `resolveLinkToken` makes.
 */
import { createHash, randomBytes } from "node:crypto";
import { resolveDashboardBase } from "../dashboard-link-base.js";
import { findLinkRowByToken, mintReportLinkHash } from "./link-token.js";

/** The link kinds a recipient may get. */
export const LINK_KINDS = Object.freeze(["dashboard", "public-view", "public-comment"]);

/** The tier that needs no token: the reader opens the report's run page on this instance. */
export const DASHBOARD_TIER = "c";

/** The tier whose page lets the reader comment: every other public reader only views. */
export const COMMENT_TIER = "a";

/** The `dashboard_settings` key holding the origin a public report link is built on. */
export const REPORTS_PUBLIC_ORIGIN_KEY = "reports.public_origin";

/**
 * The `dashboard_settings` key holding how long a link stays open, in days, and the value used when the
 * setting is absent or not a usable number. The same key `delivery.js` reads for its send holds: one
 * setting says how long a mailed version is kept alive, and the duplicated read here is that small
 * on purpose, because `delivery.js` imports this module and a shared import back would be a cycle.
 */
const LINK_DAYS_KEY = "reports.link_days";
const DEFAULT_LINK_DAYS = 180;

const DAY_MS = 86_400_000;

/** A token is 32 random bytes in base64url: 43 characters, no padding, nothing else. */
const TOKEN_BYTES = 32;
const TOKEN_RE = /^[A-Za-z0-9_-]{43}$/;

/** The holder prefix a link's version hold carries, so one token's hold is one row (store.js prune). */
const LINK_HOLD_PREFIX = "report-link:";

/** The id prefix a link token row carries, so a log line names the kind of row it is about. */
const LINK_ID_PREFIX = "rlt-";

/** The page kind each scope opens. */
const PUBLIC_KIND_BY_SCOPE = Object.freeze({ comment: "public-comment", view: "public-view" });

/** The tier whose page only views, and how open each scope is (a resolve answers the lower of the two). */
const VIEW_TIER = "b";
const SCOPE_RANK = Object.freeze({ view: 1, comment: 2 });

/** The send row statuses a link may be opened through: the mail went, or nobody knows whether it did. */
const OPENABLE_SEND_STATUSES = Object.freeze(["sent", "unknown"]);

/**
 * Is this string an absolute http(s) URL? The one check a caller makes before mailing a link, because a
 * relative path is not something a mail client can open.
 *
 * @param {*} url
 * @returns {boolean}
 */
export function isAbsoluteHttpUrl(url) {
  if (typeof url !== "string" || !url.trim()) return false;
  let parsed;
  try {
    parsed = new URL(url.trim());
  } catch {
    return false;
  }
  return parsed.protocol === "http:" || parsed.protocol === "https:";
}

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

/** One path segment, encoded. An id or a slug with an odd character cannot move the route. */
function segment(value) {
  return encodeURIComponent(text(value));
}

/* ------------------------------------------------------------------- the token model */

/**
 * A raw token's sha256, hex. NO LONGER what `report_link_tokens.token_hash` stores (that is the keyed
 * `report:link` verifier of `link-token.js`); it stays as the input the public door binds its comment-form
 * nonce to (sha256 of the RAW token from the URL), and as the legacy stored form a lookup also tries.
 * Nothing else in this module ever writes, logs or returns a raw token after the mint that made it hands it
 * to the caller.
 *
 * @param {*} raw the raw token a mail carried
 * @returns {string} 64 lowercase hex characters
 */
export function hashToken(raw) {
  return createHash("sha256").update(text(raw), "utf8").digest("hex");
}

let bridgeModule = null;

/** The artifact bridge, loaded on first use (see WHY ... LOADED ON FIRST USE in the header). */
function loadBridge() {
  if (!bridgeModule) bridgeModule = import("./artifact-bridge.js");
  return bridgeModule;
}

let approvalsModule = null;

/** The approvals module, loaded on first use: it imports this one, so a static import would be a cycle. */
function loadApprovals() {
  if (!approvalsModule) approvalsModule = import("./approvals.js");
  return approvalsModule;
}

/** The whole deps seam with every member present; one that is absent falls back to the real thing. */
function resolveDeps(db, deps) {
  const given = deps == null ? {} : deps;
  const fn = (key, fallback) => (typeof given[key] === "function" ? given[key] : fallback);
  return {
    artifacts: given.artifacts,
    approvals: given.approvals == null ? {} : given.approvals,
    now: fn("now", Date.now),
    holdVersion: fn("holdVersion", (args) => defaultHoldVersion(db, given, args)),
    releaseHolds: fn("releaseHolds", ({ holder }) => defaultReleaseHolds(db, given, holder)),
  };
}

/**
 * The artifacts store's own `holdVersion`, through the bundle runtime. The store validates that the
 * version exists, so a hold here answers null when the run's version is already gone.
 */
async function defaultHoldVersion(db, deps, args) {
  const { loadArtifactsRuntime } = await loadBridge();
  const runtime = await loadArtifactsRuntime(deps == null ? {} : deps);
  if (typeof runtime?.store?.holdVersion !== "function") {
    throw fail("artifacts_outdated");
  }
  return runtime.store.holdVersion(db, args);
}

/** Drop every hold one holder owns. A holder with no row is answered 0, so this is idempotent. */
async function defaultReleaseHolds(db, deps, holder) {
  const { loadArtifactsRuntime } = await loadBridge();
  const runtime = await loadArtifactsRuntime(deps == null ? {} : deps);
  if (typeof runtime?.store?.releaseHolds !== "function") {
    throw fail("artifacts_outdated");
  }
  return runtime.store.releaseHolds(db, { holder });
}

/** How many days a link stays open, from the setting, else the default. Never throws. */
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
    // A setting that cannot be read is the default, never a failed link.
  }
  return DEFAULT_LINK_DAYS;
}

/**
 * The version one run of one report wrote, as a link may pin it: the `report_versions` row whose run and
 * report both match, whose trigger is not `preview`, newest version first. Null when there is no such
 * row: a preview is never a page a reader is shown, and a run that wrote no version has nothing to open.
 *
 * @param {object} db
 * @param {string} reportId
 * @param {string} runId
 * @returns {Promise<{artifactId: string, versionN: number}|null>}
 */
async function runVersionOf(db, reportId, runId) {
  if (!reportId || !runId) return null;
  let row;
  try {
    const { rows } = await db.execute({
      sql: `SELECT artifact_id, n FROM report_versions
             WHERE run_id = ? AND report_id = ? AND "trigger" <> 'preview'
             ORDER BY n DESC LIMIT 1`,
      args: [runId, reportId],
    });
    row = rows[0] ?? null;
  } catch {
    return null;
  }
  const artifactId = text(row?.artifact_id).trim();
  const versionN = Number(row?.n);
  if (!artifactId) return null;
  if (!Number.isInteger(versionN) || versionN <= 0) return null;
  return { artifactId, versionN };
}

/** The scope a token row stored: `comment` only when the row says so, `view` for any other word. A
 *  row somebody edited by hand therefore narrows to the page that shows less, never opens wider. */
function storedScopeOf(row) {
  const stored = text(row == null ? "" : row.scope).trim();
  return SCOPE_RANK[stored] ? stored : "view";
}

/**
 * The scope a token really opens: the LOWER of the scope it was minted with and what the tier in force
 * NOW allows. Tier `c` allows no public page at all (null), so a token minted for an open tier and left
 * behind by a lowered one never keeps a door open on its own say-so.
 *
 * @param {"comment"|"view"|""} storedScope
 * @param {string} tier the recipient's tier now, else the report's default
 * @returns {"comment"|"view"|null} null means this recipient has no public page any more
 */
function effectiveScopeOf(storedScope, tier) {
  const allowed = tier === COMMENT_TIER ? "comment" : tier === VIEW_TIER ? "view" : null;
  if (allowed == null) return null;
  const stored = SCOPE_RANK[storedScope] ? storedScope : "view";
  return SCOPE_RANK[stored] <= SCOPE_RANK[allowed] ? stored : allowed;
}

/**
 * The approval nonce one recipient row holds RIGHT NOW, or "" when it holds none. Read from the stored
 * row rather than taken from a caller's object: the recipient a page reads is mapped without its nonce
 * and seal on purpose, so this binding has to compare against what the database holds.
 */
async function currentApprovalNonce(db, reportId, recipientId) {
  if (!reportId || !recipientId) return "";
  try {
    const { rows } = await db.execute({
      sql: "SELECT approval_nonce FROM report_recipients WHERE id = ? AND report_id = ?",
      args: [recipientId, reportId],
    });
    return text(rows[0]?.approval_nonce).trim();
  } catch {
    return "";
  }
}

/**
 * Write the token row for one send: one fresh row, with the version it opens and the scope it was minted
 * for stored on it.
 *
 * There is no unique key to rewrite any more: a mint is per send, and `mintLinkToken` revokes the earlier
 * unrevoked rows of the same `send_id` before this write, so a retried send leaves one live row and a
 * trail of stamped ones. A row that cannot be written answers null, never a throw.
 *
 * @returns {Promise<string|null>} the token row id, or null when the write failed
 */
async function writeTokenRow(db, {
  reportId, runId, recipientId, sendId, artifactId, versionN, scope, hash, approvalNonce, expiresAt,
  now,
}) {
  const id = `${LINK_ID_PREFIX}${randomBytes(8).toString("hex")}`;
  try {
    await db.execute({
      sql: `INSERT INTO report_link_tokens
              (id, report_id, recipient_id, run_id, send_id, artifact_id, version_n, token_hash, scope,
               approval_nonce, created_at, revoked_at, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, NULL, ?)`,
      args: [id, reportId, recipientId, runId, sendId, artifactId, versionN, hash, scope,
        approvalNonce, now, expiresAt],
    });
  } catch {
    return null;
  }
  return id;
}

/**
 * Mint the link token one send row's mail carries.
 *
 * A token is minted per SEND ROW, so per recipient and per run, and it opens the version that run wrote
 * as it stands AT MINT: there is no version a recipient may be shown, so there is no token. The artifact
 * id and version number are columns of the token row, so a later ask cannot move the page a mail already
 * carries. The raw token is in the answer and nowhere else; only its hash reaches the database.
 *
 * Before the new token is written, every live token this SEND already holds is revoked and its hold
 * released, so a retried `pending` row (or a second delivery of the same run) never leaves two live links
 * behind: the older raw token stops resolving the moment the new one exists. The older rows stay, stamped,
 * as the send's own link log.
 *
 * The token is BOUND to the recipient's current approval nonce (`report_link_tokens.approval_nonce`), so
 * a later revoke, refusal or re-approval takes it out of service even if that path's own token sweep
 * never ran. A recipient row with no nonce (never approved, or revoked and not re-approved since) cannot
 * mint at all: there is no approval to bind to.
 *
 * The version is then held for as long as the token lives (holder `report-link:<token id>`), because a
 * link in a mail is a promise. A hold that cannot be written is answered as a failed mint (the token row
 * is revoked again): a token whose version retention may prune is a dead link nobody was told about.
 *
 * @param {object} db a libsql-shaped client
 * @param {object} [deps] the seam (`artifacts` runtime, `holdVersion`, `releaseHolds`, `now`)
 * @param {{report: object, recipient: object, run: object, sendId: string}} input
 * @returns {Promise<{tokenId: string, token: string, scope: "comment"|"view", artifactId: string,
 *   versionN: number, expiresAt: number}|null>} null when there is nothing a token could open
 */
export async function mintLinkToken(db, deps, {
  report = null, recipient = null, run = null, sendId = null,
} = {}) {
  const d = resolveDeps(db, deps);
  const reportId = text(report == null ? "" : report.id);
  const recipientId = text(recipient == null ? "" : recipient.id);
  const runId = text(run == null ? "" : run.id);
  const send = text(sendId);
  if (!reportId || !recipientId || !runId || !send) return null;

  const version = await runVersionOf(db, reportId, runId);
  if (!version) return null;

  const approvalNonce = await currentApprovalNonce(db, reportId, recipientId);
  if (!approvalNonce) return null;

  const scope = commentTierOf(report, recipient) === COMMENT_TIER ? "comment" : "view";
  const token = randomBytes(TOKEN_BYTES).toString("base64url");
  const asked = Number(d.now());
  const now = Number.isFinite(asked) ? asked : Date.now();
  const expiresAt = now + (await linkDaysOf(db)) * DAY_MS;

  // The STORED verifier is computed FIRST: a key problem is a failed mint (null) that leaves the send's
  // current link alive, and never falls back to sha256.
  let storedHash;
  try {
    storedHash = await mintReportLinkHash(db, token);
  } catch {
    return null;
  }

  // One live token per SEND, stamped and unheld before the new one is written.
  await revokeLinkTokens(db, d, { reportId, sendId: send });

  const tokenId = await writeTokenRow(db, {
    reportId, runId, recipientId, sendId: send, artifactId: version.artifactId,
    versionN: version.versionN, scope, hash: storedHash, approvalNonce, expiresAt, now,
  });
  if (!tokenId) return null;

  try {
    await d.holdVersion({
      artifactId: version.artifactId,
      n: version.versionN,
      holder: `${LINK_HOLD_PREFIX}${tokenId}`,
      until: expiresAt,
    });
  } catch {
    // No hold, no promise: the token is revoked again rather than handed out over a version that
    // retention may prune at any moment.
    await revokeLinkTokens(db, d, { reportId, sendId: send });
    return null;
  }
  return { tokenId, token, scope, artifactId: version.artifactId, versionN: version.versionN, expiresAt };
}

/**
 * Revoke every live token one filter matches, and release the version hold each of them carried.
 *
 * `revoked_at` is a stamp, never a delete: a dead link is a refusal a reader and the owner can both be
 * told about, and the row is also the audit trail of which send went out with which link. The hold goes
 * with it, so retention may prune what nothing points at any more (releasing a hold never deletes a
 * version itself; it only lets the normal retention rule do its work).
 *
 * `reportId` is required: a filter with neither report nor recipient would revoke the instance's whole
 * link log, so it is `bad_input` rather than a wide sweep.
 *
 * @param {object} db
 * @param {object} [deps] the seam (`releaseHolds`, `now`)
 * @param {{reportId: string, recipientId?: string|null, sendId?: string|null, runId?: string|null}} input
 * @returns {Promise<number>} how many tokens this call revoked
 * @throws {Error} `bad_input` when `reportId` is missing
 */
export async function revokeLinkTokens(db, deps, {
  reportId, recipientId = null, sendId = null, runId = null,
} = {}) {
  const d = resolveDeps(db, deps);
  const id = text(reportId);
  if (!id) throw fail("bad_input", "reportId");
  const where = ["report_id = ?", "revoked_at IS NULL"];
  const args = [id];
  if (recipientId != null) {
    where.push("recipient_id = ?");
    args.push(text(recipientId));
  }
  if (sendId != null) {
    where.push("send_id = ?");
    args.push(text(sendId));
  }
  if (runId != null) {
    where.push("run_id = ?");
    args.push(text(runId));
  }
  let rows = [];
  try {
    ({ rows } = await db.execute({
      sql: `SELECT id FROM report_link_tokens WHERE ${where.join(" AND ")}`,
      args,
    }));
  } catch {
    return 0;
  }
  const at = Number(d.now());
  let revoked = 0;
  for (const row of rows) {
    const tokenId = text(row == null ? "" : row.id);
    if (!tokenId) continue;
    // Guarded on the state this read saw, so two revokers racing answer one revocation, not two.
    try {
      const written = await db.execute({
        sql: "UPDATE report_link_tokens SET revoked_at = ? WHERE id = ? AND revoked_at IS NULL",
        args: [Number.isFinite(at) ? at : Date.now(), tokenId],
      });
      if (Number(written?.rowsAffected ?? 0) !== 1) continue;
    } catch {
      continue;
    }
    revoked += 1;
    try {
      await d.releaseHolds({ holder: `${LINK_HOLD_PREFIX}${tokenId}` });
    } catch {
      // A hold that could not be released expires on its own (`until`); the stamp is the decision.
    }
  }
  return revoked;
}

/**
 * Resolve a raw token a reader presented into the version, the report and the recipient it opens.
 *
 * EVERY check runs on EVERY resolve, and nothing is cached, because each of these answers has to be true
 * at the moment of the click rather than when the mail was written:
 *
 *   1. a token that is not a plausible token string, and a hash that names no row, are `unknown`;
 *   2. a revoked token is `unknown`, exactly like one that never existed (a reader is not told that a
 *      link was once good, and neither is a crawler);
 *   3. an expired token is `expired`, and its hold is released here (the row stays: a dead link is a
 *      refusal, and its `revoked_at` is deliberately NOT set, so "expired" and "revoked" stay apart);
 *   4. the send row the token names must have gone (`sent`) or be beyond knowing (`unknown`). A
 *      `sending`, `pending`, `failed` or `refused` send never puts a working link in front of a reader,
 *      and a missing send row is no better;
 *   5. the run must exist, belong to the token's report, and not be a `preview` (a preview is unapproved
 *      text, so even a hand-written row pointing at one resolves to nothing);
 *   6. the recipient must still be `approved` with a seal that verifies over the row as it stands now
 *      (the check `listRecipients` reports as `verified`), so a revoke, a refusal, an address edit or a
 *      state word flipped back by a direct UPDATE with the seal NULLed all read as unknown;
 *   7. the token's stored `approval_nonce` must equal the recipient's CURRENT nonce, so a revoke, a
 *      refusal or a re-approval kills every token minted before it even when the explicit revoke write
 *      in `approvals.js` never landed;
 *   8. the report row must exist, and its status word must be one a mailed link may open: `live` (with a
 *      seal that still verifies), else `paused` (readable, view only), and `unknown` for a draft or any
 *      other word (see THE REPORT'S OWN STANDING above);
 *   9. and the scope answered is the LOWER of the stored `scope` and the tier in force now (see THE TOKEN
 *      above): a dropped tier narrows a live link, and tier `c` closes it (`unknown`) entirely. A paused
 *      report narrows whatever is left to `view`.
 *
 * The version answered is the one the token row stored at mint (`artifact_id`, `version_n`), which is the
 * version whose hold the mint wrote: the run is still checked (it must exist, belong to the report and
 * not be a preview), but its version is never re-derived, so a link can never start showing a later run's
 * page.
 *
 * The stored hash and the hash just computed are compared with `timingSafeEqual`. A row's stored
 * `token_hash` handed in as if it were a token hashes to something else, so it is `unknown` like any
 * other wrong string.
 *
 * @param {object} db a libsql-shaped client
 * @param {object} [deps] the seam (`approvals` for the seal, `releaseHolds`, `now`)
 * @param {*} rawToken the raw token from the URL
 * @returns {Promise<{status: "ok", token: object, report: object, recipient: object}
 *   | {status: "expired"} | {status: "unknown"}>}
 */
export async function resolveLinkToken(db, deps, rawToken) {
  const d = resolveDeps(db, deps);
  const unknown = { status: "unknown" };
  if (typeof rawToken !== "string" || !TOKEN_RE.test(rawToken.trim())) return unknown;
  const raw = rawToken.trim();

  let row;
  try {
    row = await findLinkRowByToken(db, raw, {
      columns: `id, report_id, run_id, recipient_id, send_id, artifact_id, version_n, scope,
                   token_hash, approval_nonce, expires_at, revoked_at, created_at`,
    });
  } catch {
    return unknown;
  }
  if (!row) return unknown;
  if (row.revoked_at != null) return unknown;

  const tokenId = text(row.id);
  const reportId = text(row.report_id);
  const runId = text(row.run_id);
  const recipientId = text(row.recipient_id);
  const sendId = text(row.send_id);
  const artifactId = text(row.artifact_id).trim();
  const versionN = Number(row.version_n);
  if (!tokenId || !reportId || !runId || !recipientId) return unknown;
  // The version the mail was sent for, as the row stored it at mint: a row with none is no page at all.
  if (!artifactId || !Number.isInteger(versionN) || versionN <= 0) return unknown;

  const now = Number(d.now());
  const expiry = row.expires_at == null ? null : Number(row.expires_at);
  const expiresAt = Number.isFinite(expiry) ? expiry : null;
  if (expiresAt != null && expiresAt <= (Number.isFinite(now) ? now : Date.now())) {
    // The row is kept and NOT stamped revoked: "this link ran out" and "this link was withdrawn" are two
    // different answers, and only the hold goes, because the version is no longer promised to anybody.
    try {
      await d.releaseHolds({ holder: `${LINK_HOLD_PREFIX}${tokenId}` });
    } catch {
      // Already released, or the store could not be reached: a stale hold expires on its own `until`.
    }
    return { status: "expired" };
  }

  // 4. The mail the link went out in.
  if (!sendId) return unknown;
  let sendStatus = "";
  try {
    const { rows } = await db.execute({
      sql: "SELECT status FROM report_sends WHERE id = ?",
      args: [sendId],
    });
    sendStatus = text(rows[0] == null ? "" : rows[0].status);
  } catch {
    return unknown;
  }
  if (!OPENABLE_SEND_STATUSES.includes(sendStatus)) return unknown;

  // 5. The run this version came from, and its trigger.
  let runReportId = "";
  let runTrigger = "";
  try {
    const { rows } = await db.execute({
      sql: `SELECT report_id, "trigger" FROM report_runs WHERE id = ?`,
      args: [runId],
    });
    runReportId = text(rows[0] == null ? "" : rows[0].report_id);
    runTrigger = text(rows[0] == null ? "" : rows[0].trigger);
  } catch {
    return unknown;
  }
  if (!runReportId || runReportId !== reportId) return unknown;
  if (runTrigger === "preview") return unknown;

  // 6. The recipient, through the same seal check every other reader uses.
  let recipient = null;
  try {
    const { listRecipients } = await loadApprovals();
    const recipients = await listRecipients(db, reportId, d.approvals);
    recipient = recipients.find((candidate) => candidate != null && text(candidate.id) === recipientId) ?? null;
  } catch {
    return unknown;
  }
  if (!recipient || recipient.state !== "approved" || recipient.verified !== true) return unknown;

  // 7. The approval this token was minted under. Both values are non-secret hex, so a plain compare is
  // enough; what matters is that a fresh nonce (a re-approval) or a NULLed one (a revoke or a refusal)
  // never matches what the token row stored.
  const mintedNonce = text(row.approval_nonce);
  if (!mintedNonce) return unknown;
  const currentNonce = await currentApprovalNonce(db, reportId, recipientId);
  if (!currentNonce || currentNonce !== mintedNonce) return unknown;

  // 8. The report itself.
  let report = null;
  try {
    const { getReport } = await import("./store.js");
    report = await getReport(db, reportId);
  } catch {
    return unknown;
  }
  if (!report) return unknown;

  // 9. The report's standing NOW. Only a live report whose seal still verifies keeps a link fully open; a
  // paused one (or a row whose status word still says live over a seal that no longer verifies, which is
  // what a direct UPDATE of a live-set column leaves behind) keeps its page readable and takes no
  // comment; every other word is not a page a mailed link may open at all. The status words and the seal
  // check belong to `approvals.js`, which is loaded on first use here like the rest of that module.
  let paused = false;
  try {
    const { REPORT_LIVE, REPORT_PAUSED, sealVerifies } = await loadApprovals();
    const status = text(report.status);
    if (status === REPORT_PAUSED) {
      paused = true;
    } else if (status !== REPORT_LIVE) {
      return unknown;
    } else if (!(await sealVerifies(db, d.approvals, report))) {
      // A live word nobody sealed is not an approval: the same answer a paused report gets, so a reader
      // keeps the report and the owner's next pause (or go-live) is what changes it.
      paused = true;
    }
  } catch {
    return unknown;
  }

  // 10. The scope in force now, never the one the row was minted with on its own. A paused report narrows
  // whatever is left to `view`: the door reads `token.scope`, so it renders no form and a post is refused
  // with the fixed view-only line.
  const storedScope = storedScopeOf(row);
  const allowed = effectiveScopeOf(storedScope, commentTierOf(report, recipient));
  if (allowed == null) return unknown;
  const scope = paused ? "view" : allowed;

  return {
    status: "ok",
    token: {
      id: tokenId,
      reportId,
      recipientId,
      runId,
      sendId,
      artifactId,
      versionN,
      scope,
      storedScope,
      expiresAt,
    },
    report,
    recipient,
  };
}

/* ------------------------------------------------------------------- the public origin */

/**
 * The origin a public report link is built on, from the owner's own setting, or null.
 *
 * The setting is a URL and nothing else: exactly one of its parts is used, so the whole thing has to be
 * clean. Only `https` is accepted (a public page over plain http is a link anybody on the way can
 * rewrite), no username or password, no path beyond the bare `/`, no query and no fragment. Anything
 * else, an unreadable setting and one that is simply not there all answer null, which is the "this
 * instance has no public address" the two callers already understand.
 *
 * @param {object} db a libsql-shaped client
 * @returns {Promise<string|null>} a normalised origin, e.g. `https://reports.example.com`
 */
export async function publicOriginOf(db) {
  let raw = "";
  try {
    const { rows } = await db.execute({
      sql: "SELECT value FROM dashboard_settings WHERE key = ?",
      args: [REPORTS_PUBLIC_ORIGIN_KEY],
    });
    raw = text(rows[0] == null ? "" : rows[0].value).trim();
  } catch {
    return null;
  }
  if (!raw) return null;
  let url;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  if (url.protocol !== "https:") return null;
  if (url.username || url.password) return null;
  if (url.pathname !== "" && url.pathname !== "/") return null;
  if (url.search || url.hash) return null;
  return url.origin;
}

/**
 * The link a tier `a` or tier `b` recipient's mail carries: a public comment or public view page on this
 * instance, opened by a token minted for that one recipient and that one run.
 *
 * With no valid public origin the answer is null, and both callers (delivery and go-live) already treat
 * null as "this recipient has no way to open the report yet" rather than mailing or approving a link
 * that goes nowhere.
 *
 * WITH NO SEND ID the answer is only "a link CAN be made": the go-live probe and delivery's pre-claim
 * probe both ask before any send row exists, so nothing is minted and nothing is written, and the URL is
 * the bare `<origin>/r/` prefix. `sendId` given mints the token that goes in the mail; a mint that
 * cannot be made (no version a recipient may be shown, a hold that would not take, a row that would not
 * write) throws `link_mint_failed`, whose message never carries the token.
 *
 * @param {object} db a libsql-shaped client
 * @param {{report?: object|null, recipient?: object|null, run?: object|null, sendId?: string|null,
 *   deps?: object|null}} input
 * @returns {Promise<{kind: "public-view"|"public-comment", url: string}|null>}
 * @throws {Error} `link_mint_failed`
 */
export async function publicLinkFor(db, {
  report = null, recipient = null, run = null, sendId = null, deps = null,
} = {}) {
  const origin = await publicOriginOf(db);
  if (!origin) return null;
  const scope = commentTierOf(report, recipient) === COMMENT_TIER ? "comment" : "view";
  const kind = PUBLIC_KIND_BY_SCOPE[scope];
  const send = text(sendId).trim();
  // The probe: a link of this scope is possible, and nothing is written.
  if (!send) return { kind, url: `${origin}/r/` };

  let minted = null;
  try {
    minted = await mintLinkToken(db, deps, { report, recipient, run, sendId: send });
  } catch {
    minted = null;
  }
  if (!minted || typeof minted.token !== "string" || !minted.token) throw fail("link_mint_failed");
  // The page kind a mail carries is the minted token's own scope, never a second guess from the tier.
  return { kind: PUBLIC_KIND_BY_SCOPE[minted.scope] ?? kind, url: `${origin}/r/${minted.token}` };
}

/* ------------------------------------------------------------------------ the kind and tier */

/**
 * The comment tier in force for one recipient: the recipient's own, else the report's default, else
 * `c` (the report's own schema default). A row may arrive in either case shape (the approvals module
 * maps to camelCase; a stored row is snake_case).
 *
 * @param {object|null} report
 * @param {object|null} recipient
 * @returns {"a"|"b"|"c"}
 */
export function commentTierOf(report, recipient) {
  const own = recipient == null
    ? ""
    : text(recipient.commentTier != null ? recipient.commentTier : recipient.comment_tier).trim();
  if (own) return own;
  const fallback = text(report == null ? "" : report.comment_tier_default).trim();
  return fallback || DASHBOARD_TIER;
}

/** The report's project id, as the column stores it, or null. */
function projectIdOf(report) {
  const raw = report == null
    ? null
    : (report.project_id !== undefined ? report.project_id : report.projectId);
  if (raw == null || raw === "") return null;
  return raw;
}

/**
 * The slug of the project this report belongs to, or null when the report has no project or this
 * instance no longer has that project row. A read that fails is no slug either: a page link is a display
 * concern, never a reason to fail a run.
 *
 * @param {object} db
 * @param {object|null} report
 * @returns {Promise<string|null>}
 */
export async function projectSlug(db, report) {
  const projectId = projectIdOf(report);
  if (projectId == null) return null;
  try {
    const { rows } = await db.execute({
      sql: "SELECT slug FROM project_spaces WHERE id = ?",
      args: [projectId],
    });
    const slug = text(rows[0]?.slug).trim();
    return slug || null;
  } catch {
    return null;
  }
}

/**
 * A caller's explicit base URL with its trailing slashes trimmed, falling back to `CROW_GATEWAY_URL`
 * when none is given. Kept exported for callers that pass their own base: `linkFor` itself resolves a
 * base through `resolveDashboardBase` (`../dashboard-link-base.js`), which is the order the dashboard
 * and the public Funnel address need. "" means no base is known.
 *
 * @param {string|null|undefined} baseUrl
 * @returns {string}
 */
export function baseUrlOf(baseUrl) {
  const given = typeof baseUrl === "string" && baseUrl.trim()
    ? baseUrl.trim()
    : text(process.env.CROW_GATEWAY_URL).trim();
  return given.replace(/\/+$/, "");
}

/**
 * The report's own page on the dashboard (`/dashboard/project/<slug>/reports/<report id>`), which is
 * where the owner's notices for one report send them. The reports list when the report has no project
 * (or the project row is gone), so a notice is never a dead link.
 *
 * @param {object} db
 * @param {object|null} report
 * @returns {Promise<string>} an absolute path beginning with "/"
 */
export async function reportPagePath(db, report) {
  const slug = await projectSlug(db, report);
  const reportId = text(report == null ? "" : report.id);
  if (!slug || !reportId) return "/dashboard/reports";
  return `/dashboard/project/${segment(slug)}/reports/${segment(reportId)}`;
}

/**
 * The link one recipient's email carries, or null when this instance cannot make one for that recipient.
 *
 * @param {object} db a libsql-shaped client
 * @param {{report?: object|null, recipient?: object|null, run?: object|null, sendId?: string|null,
 *   baseUrl?: string|null, localInstanceId?: string|null, deps?: object|null}} input `sendId` is the
 *   recipient's `report_sends` row id (a public link's token is minted per send, so a public link needs
 *   it; null asks only whether a link of this kind could be made), `localInstanceId` is this instance's
 *   own `crow_instances` row id (optional: with none the resolver reads the instance-id file), and
 *   `deps` is the seam the public path needs (the artifacts runtime, the clock, the approval seed)
 * @returns {Promise<{kind: "dashboard"|"public-view"|"public-comment", url: string}|null>}
 * @throws {Error} `link_mint_failed` when a public link's token cannot be minted for this send
 */
export async function linkFor(db, {
  report = null, recipient = null, run = null, sendId = null, baseUrl = null, localInstanceId = null,
  deps = null,
} = {}) {
  const tier = commentTierOf(report, recipient);
  if (tier !== DASHBOARD_TIER) {
    return publicLinkFor(db, { report, recipient, run, sendId, baseUrl, tier, deps });
  }
  const slug = await projectSlug(db, report);
  const reportId = text(report == null ? "" : report.id);
  const runId = text(run == null ? "" : run.id);
  if (!slug || !reportId || !runId) return null;
  const path = `/dashboard/project/${segment(slug)}/reports/${segment(reportId)}/runs/${segment(runId)}`;
  const given = text(baseUrl).trim();
  const base = given ? given.replace(/\/+$/, "") : await resolveDashboardBase(db, { localInstanceId });
  // No base, no link: a relative path in an email is a link nobody can open.
  if (!base) return null;
  return { kind: "dashboard", url: `${base}${path}` };
}

export default linkFor;