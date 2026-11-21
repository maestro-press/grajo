/**
 * Where one report email sends its reader: the link KIND a recipient's comment tier earns, and the URL
 * of that kind for one recipient.
 *
 * THE THREE KINDS (spec R15). A recipient's tier decides what a reader may do with the report:
 *   - `c`: the reader has no page to comment on, so the link is the OWNER-VIEW run page,
 *     `/dashboard/project/<slug>/reports/<report id>/runs/<run id>`, on this instance (`dashboard`);
 *   - `a` and `b`: the reader gets a public view or a public comment page (`public-view`,
 *     `public-comment`), which need a per-recipient token. Tokens arrive in PR 6a, so
 *     `publicLinkFor` answers null in this PR and every tier `a`/`b` recipient is therefore skipped by
 *     delivery (`delivery.js`) and refused at go-live (`approvals.js`): a report that would mail a dead
 *     link is not taken live. PR 6a replaces `publicLinkFor`; nothing else here moves.
 *
 * WHY TIER `c` IS THE ONLY DASHBOARD PATH FOR NOW: a Crow user on this instance would also get
 * `dashboard`, but this PR has no way to tell that a recipient's address belongs to a Crow user on this
 * instance, so no such reader is recognised yet. Every tier `c` recipient gets the owner-view run page,
 * which is this instance's own dashboard and therefore not something an outside reader can open.
 *
 * THE SLUG comes from `project_spaces` (the report's `project_id` names one), because the dashboard
 * route is keyed by the project's slug, not its id. A report with no project, or a project row this
 * instance no longer has, has no slug: `linkFor` answers null rather than a wrong URL.
 *
 * THE BASE is the caller's (`baseUrl`), else `CROW_GATEWAY_URL` (this instance's own address). With no
 * base at all the answer is the PATH only, and `isAbsoluteHttpUrl` is how a caller tells: delivery
 * refuses to mail a link that is not an absolute http(s) URL, so an instance that does not know its own
 * address skips the mail instead of sending a relative one.
 *
 * Nothing here sends anything, writes anything or reads a secret: it is two reads (the project's slug and
 * this instance's secret-free base URL) and one string.
 */
/** The link kinds a recipient may get. `public-comment` and `public-view` arrive with PR 6a's tokens. */
export const LINK_KINDS = Object.freeze(["dashboard", "public-view", "public-comment"]);

/** The tier that needs no token: the reader opens the report's run page on this instance. */
export const DASHBOARD_TIER = "c";

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

/** One path segment, encoded. An id or a slug with an odd character cannot move the route. */
function segment(value) {
  return encodeURIComponent(text(value));
}

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
 * This instance's own base URL as a link builder takes it: the caller's, else `CROW_GATEWAY_URL`, with
 * trailing slashes trimmed. "" means this instance does not know its own address.
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
 * The link a tier `a` or tier `b` recipient's mail carries: a public view or a public comment page on
 * this instance, opened by a token minted for that one recipient and that one version.
 *
 * PR 6a replaces this: the tokens, the routes that accept them and the version they pin arrive there. It
 * answers null until then, and both callers (delivery and go-live) treat null as "this recipient has no
 * way to open the report yet" rather than mailing or approving a link that goes nowhere.
 *
 * @returns {null}
 */
export function publicLinkFor() {
  return null;
}

/**
 * The link one recipient's email carries, or null when this PR cannot make one for that recipient.
 *
 * @param {object} db a libsql-shaped client
 * @param {{report?: object|null, recipient?: object|null, run?: object|null, sendId?: string|null,
 *   baseUrl?: string|null}} input `sendId` is the recipient's `report_sends` row id (the token PR 6a
 *   mints is per send, so a public link needs it)
 * @returns {Promise<{kind: "dashboard"|"public-view"|"public-comment", url: string}|null>}
 */
export async function linkFor(db, { report = null, recipient = null, run = null, sendId = null, baseUrl = null } = {}) {
  const tier = commentTierOf(report, recipient);
  if (tier !== DASHBOARD_TIER) {
    return publicLinkFor(db, { report, recipient, run, sendId, baseUrl, tier });
  }
  const slug = await projectSlug(db, report);
  const reportId = text(report == null ? "" : report.id);
  const runId = text(run == null ? "" : run.id);
  if (!slug || !reportId || !runId) return null;
  const path = `/dashboard/project/${segment(slug)}/reports/${segment(reportId)}/runs/${segment(runId)}`;
  const base = baseUrlOf(baseUrl);
  return { kind: "dashboard", url: base ? `${base}${path}` : path };
}

export default linkFor;