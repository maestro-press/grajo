/**
 * The report run page (R2-1): /dashboard/project/<slug>/reports/<id>/runs/<runId>.
 *
 * WHERE IT COMES FROM: a `dashboard` link in a report email opens its report's run view
 * (servers/gateway/reports/links.js builds the path). The reader is the owner, on this instance's own
 * dashboard.
 *
 * GATES, in this order, before ANY read:
 *   - the owner: `isLocalPasswordSessionOn` (this machine's own password sign-in, from the owner's own
 *     client), the same check the reports API and the widgets page use. The /dashboard mount's
 *     `dashboardAuth` alone is not enough: a signed peer call and a session minted by a login on this
 *     machine both pass it too. Anything else is 404 "Not found" with no report, run, project or
 *     version row read;
 *   - the path itself (./report-run/data.js): the slug, the report and the run must all be this
 *     instance's and belong to each other, else the page's own not-found page.
 *
 * NEVER CACHED: every answer of this panel, the 404 page and the gate's refusal included, carries
 * `Cache-Control: no-store`, because a page names a report and the error text of a run.
 *
 * WHY IT IS NOT THE ARTIFACT VIEWER: the viewer's frame may only be `""` or `allow-scripts`, and the
 * artifact origin's responses may not widen it (tests/artifact-origin.test.js), so a version a reader
 * needs to open links from cannot be shown there. This page has its own frame, its own CSP and the run's
 * links listed under it (see ./report-run/html.js).
 *
 * IT NEVER WRITES: a GET renders, and a POST renders the same page (there is no form here), so Turbo's
 * prefetch of the link is harmless either way.
 *
 * Hidden from the nav: reached only through the route (dashboard/index.js) and the email's link, exactly
 * like the project home it belongs to.
 */
import { FALLBACK_SUBJECT, RUN_VIEW_MISSING_TITLE } from "../../reports/email/copy.js";
import { isLocalPasswordSessionOn } from "../local-session.js";
import { loadReportRun } from "./report-run/data.js";
import { reportRunCss, reportRunHtml, reportRunMissingHtml } from "./report-run/html.js";

/** The route's own segment, or "" when it is not a string (a repeated or odd param). */
function segment(value) {
  return typeof value === "string" ? value : "";
}

export default {
  id: "report-run",
  name: "Report run",
  icon: "folder",
  route: "/dashboard/report-run",
  navOrder: 15.6,
  category: "tools",
  hidden: true,

  async handler(req, res, { db, layout, ownerCheck = isLocalPasswordSessionOn }) {
    res.set("Cache-Control", "no-store");
    if ((await ownerCheck(db, req)) !== true) {
      res.status(404).type("text").send("Not found");
      return null;
    }
    const params = req.params || {};
    const view = await loadReportRun(db, {
      slug: segment(params.slug),
      reportId: segment(params.id),
      runId: segment(params.runId),
    });
    if (!view) {
      res.status(404);
      return layout({ title: RUN_VIEW_MISSING_TITLE, content: reportRunCss() + reportRunMissingHtml() });
    }
    return layout({
      title: view.report.title || FALLBACK_SUBJECT,
      content: reportRunCss() + reportRunHtml(view),
    });
  },
};