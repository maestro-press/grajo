/**
 * A project's Reports pages (Crow Recurring Reports, task 9b): the list,
 * /dashboard/project/<slug>/reports, and one report, /dashboard/project/<slug>/reports/<id>.
 *
 * ONE PANEL, TWO PAGES: the route's own `id` segment decides which. The run view a history row links to
 * is a different, older page (`/dashboard/project/<slug>/reports/<id>/runs/<runId>`, the report-run
 * panel) and is untouched here.
 *
 * THREE VIEWERS, decided once per request by viewerOf below, before the slug is looked up:
 *   - `owner`: `isLocalPasswordSessionOn`, this machine's own password sign-in from the owner's own
 *     client. The whole page: the buttons and the API paths, the sender, the recipients, the schedule
 *     form, the recipe, the steps and the hosts, the run error text and the send counts.
 *   - `peer`: REFUSED. A request a peer signed (req.crossHostAuth), or a dashboard session whose
 *     oauth_tokens row carries any scope other than exactly "dashboard" or "dashboard onhost" — every
 *     peer sign-in ("dashboard sso src:…") is one, and a session row that is missing or cannot be read
 *     is one too. It answers 404 "Not found" as plain text, with no-store, and before the panel reads
 *     any report or run row (the shell resolves the slug first): such a reader gets nothing at all, not
 *     even a count.
 *   - `member`: any other signed-in local non-owner — a 'dashboard onhost' login, or a request from this
 *     machine itself. READ-ONLY and reduced: the report's name, its status, its next run, the last
 *     result, and run history rows (time, result word, trigger label, version number). No pause reason,
 *     no run error text, no link into the run view, no address, no sender, no recipient count, no
 *     settings, schedule, recipe, step or host list, no write button and no client script. The reduced
 *     shape is what data.js RETURNS for that viewer, so the omitted fields are never read for it.
 *
 * NEVER CACHED: every answer carries `Cache-Control: no-store`, the refusal, the missing page and the
 * classic redirect included, because a page names a report, its schedule and the people it goes to.
 *
 * New shell only: classic mode goes to the Projects page. The scope comes from the path
 * (shell/request.js SLUG_SCOPED_PANELS: the slug wins over the cookie and nothing is written; the GET is
 * read-only because Turbo prefetches it). An unknown or archived slug, and a report id that is not that
 * project's, are the project's missing page.
 *
 * Nothing here writes: the buttons go to the owner API (routes/reports-api.js), which is where every
 * decision and every seal lives. This panel only reads.
 */
import { isLocalPasswordSessionOn } from "../local-session.js";
import { DASHBOARD_SESSION_FAMILY, findTokenRow } from "../../token-store.js";
import { t } from "../shared/i18n.js";
import { projectHomeCss } from "./project-home/css.js";
import { projectMissingHtml } from "./project-home/html.js";
import { projectReportsClientJs, projectReportsDataScript } from "./project-reports/client.js";
import { projectReportsCss } from "./project-reports/css.js";
import { loadReportPage, loadReportsList, liveProject } from "./project-reports/data.js";
import { projectReportPageHtml, projectReportsListHtml } from "./project-reports/html.js";

/** The route's own segment, or "" when it is not a string (a repeated or odd param). */
function segment(value) {
  return typeof value === "string" ? value : "";
}

/**
 * Who is reading this request: "owner", "member" or "peer" (refused). One classification per request.
 * It never throws, and a request it cannot place is never the owner.
 *
 *   - the owner: `isLocalPasswordSessionOn`, this machine's own password sign-in from the owner's client;
 *   - a peer: a request a peer signed (req.crossHostAuth) — no session row is consulted for it — or a
 *     dashboard session whose row carries a scope other than exactly "dashboard"/"dashboard onhost",
 *     and equally a session row that is missing or cannot be read;
 *   - a member: everything else, i.e. the signed-in local sessions above.
 *
 * @param {object} db the request's crow.db client
 * @param {object} req
 * @param {{ownerCheck?: (db: object, req: object) => Promise<boolean>}} [opts]
 * @returns {Promise<"owner"|"member"|"peer">}
 */
export async function viewerOf(db, req, { ownerCheck = isLocalPasswordSessionOn } = {}) {
  try {
    if ((await ownerCheck(db, req)) === true) return "owner";
  } catch {
    // Not the owner's turn; the scope below decides between a reader and a refusal.
  }
  if (!req || req.crossHostAuth) return "peer";
  if (!req.dashboardSession) return "peer";
  let scopes = "";
  try {
    const row = await findTokenRow(db, DASHBOARD_SESSION_FAMILY, req.dashboardSession, {
      extraWhere: " AND julianday(expires_at) > julianday('now')",
    });
    if (!row) return "peer";
    scopes = row.scopes == null ? "" : String(row.scopes);
  } catch {
    return "peer";
  }
  return scopes === "dashboard" || scopes === "dashboard onhost" ? "member" : "peer";
}

export default {
  id: "project-reports",
  name: "Reports",
  icon: "folder",
  route: "/dashboard/project-reports",
  navOrder: 15.7,
  category: "tools",
  hidden: true, // a project's Reports pages in the new shell; never in the classic nav

  async handler(req, res, { db, layout, lang, ownerCheck = isLocalPasswordSessionOn }) {
    res.set("Cache-Control", "no-store");
    const viewer = await viewerOf(db, req, { ownerCheck });
    // A peer-signed call and a peer sign-in get nothing, before any project, report or run row is read.
    if (viewer === "peer") {
      res.status(404).type("text").send("Not found");
      return null;
    }
    if (!req.crowMode || req.crowMode.mode !== "new") return res.redirect(302, "/dashboard/projects");
    const missing = () => {
      res.status(404);
      return layout({ title: t("shell.projectPage", lang), content: projectHomeCss() + projectMissingHtml(lang) });
    };
    const project = await liveProject(db, segment(req.params && req.params.slug));
    if (!project) return missing();
    const owner = viewer === "owner";
    const reportId = segment(req.params && req.params.id);
    const scripts = (view) => (owner ? projectReportsDataScript(view, lang) + projectReportsClientJs() : "");
    if (!reportId) {
      const list = await loadReportsList(db, { project, viewer, lang });
      return layout({
        title: t("projectReports.pageTitle", lang),
        content: projectReportsCss() + projectReportsListHtml(list, lang) + scripts(list),
      });
    }
    const page = await loadReportPage(db, { project, reportId, viewer, lang });
    if (!page) return missing();
    return layout({
      title: page.report.title || t("projectReports.pageTitle", lang),
      content: projectReportsCss() + projectReportPageHtml(page, lang) + scripts(page),
    });
  },
};