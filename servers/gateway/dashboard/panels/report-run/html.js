/**
 * The report run page's markup (R2-1): the report's title, the run's status and (when it failed) its
 * error, the version the run wrote in an inert frame, and the list of the run's own links.
 *
 * THE FRAME IS THE POINT. The generic artifact viewer must stay link-inert for every artifact, and the
 * artifact origin's sandbox may not name `allow-popups` (tests/artifact-origin.test.js asserts it), so
 * this page carries its own frame: `sandbox="allow-popups allow-popups-to-escape-sandbox"`, no scripts,
 * no same-origin, no forms, a CSP of its own inside the srcdoc, and EVERY href stripped from the
 * document before it goes in. A link in the stored version is text here; the run's real links are listed
 * under the frame, on the page itself, from `report_versions.allowed_links_json`.
 *
 * Every value that came from a row goes through `escapeHtml`, the document included: the whole srcdoc is
 * written as one escaped attribute value.
 */
import sanitizeHtml from "sanitize-html";
import { renderMarkdown } from "../../../../blog/renderer.js";
import { escapeHtml } from "../../shared/components.js";
import {
  BACK_TO_PROJECT_LINE, LINKS_IN_RUN_HEADING, RUN_FRAME_TITLE, RUN_VIEW_MISSING_LINE,
  VERSION_NOT_AVAILABLE_LINE, moreLinksLine, runStatusLine, versionLine,
} from "../../../reports/email/copy.js";

/**
 * The frame's sandbox. Exactly these two tokens: the document may open a link in a new tab (the run's
 * links are listed outside it anyway), and nothing else: no scripts, no same-origin, no forms.
 */
export const FRAME_SANDBOX = "allow-popups allow-popups-to-escape-sandbox";

/** The policy inside the srcdoc: no network of any kind, inline styles for the renderer's own CSS. */
export const FRAME_CSP = "default-src 'none'; style-src 'unsafe-inline'; img-src data:";

/**
 * The tags the frame keeps: what the owner markdown renderer already sanitized to, plus the GFM shapes
 * its own allow-list carries. Nothing here can run a script; the sanitiser runs again anyway.
 */
const FRAME_TAGS = sanitizeHtml.defaults.allowedTags.concat([
  "img", "h1", "h2", "h3", "h4", "h5", "h6", "details", "summary", "figure", "figcaption",
  "del", "ins", "sup", "sub", "table", "thead", "tbody", "tr", "th", "td", "input",
]);

/**
 * The attributes the frame keeps. `a` keeps no href (and no target): a link in a run's version is inert
 * text inside this frame, because where it may point is decided by the recorded link list, not by the
 * document. `img` keeps src because the frame's own CSP allows `data:` images and nothing else.
 */
const FRAME_ATTRS = Object.freeze({
  a: ["name"],
  img: ["src", "alt", "title", "width", "height", "loading"],
  code: ["class"],
  span: ["class"],
  pre: ["class"],
  input: ["type", "checked", "disabled"],
  th: ["align"],
  td: ["align"],
  figure: ["class"],
});

/** The frame's own reading style. Nothing external: the CSP allows no font, sheet or image fetch. */
const FRAME_STYLE = `body{font-family:system-ui,-apple-system,"Segoe UI",sans-serif;line-height:1.5;margin:0;padding:1rem;color:#1b1b1f;background:#fff}
h1,h2,h3,h4{line-height:1.25}h1{font-size:1.4rem}h2{font-size:1.2rem}h3{font-size:1.05rem}
a{color:inherit;text-decoration:none}img{max-width:100%;height:auto}
pre{overflow-x:auto;padding:.75rem;background:#f4f4f6;border-radius:6px}code{font-family:ui-monospace,monospace}
table{border-collapse:collapse}th,td{border:1px solid #d5d5dc;padding:.35rem .5rem;text-align:left}`;

/**
 * One artifact version's markdown as the frame's document: rendered by the owner renderer, then every
 * href stripped, then wrapped in the CSP meta and the frame's own style.
 *
 * @param {string} markdown
 * @returns {string} the srcdoc's HTML (not yet escaped for the attribute)
 */
export function frameDocument(markdown) {
  const rendered = renderMarkdown(typeof markdown === "string" ? markdown : "");
  const inert = sanitizeHtml(rendered, { allowedTags: FRAME_TAGS, allowedAttributes: FRAME_ATTRS });
  return `<meta http-equiv="Content-Security-Policy" content="${FRAME_CSP}"><style>${FRAME_STYLE}</style>${inert}`;
}

/** The page's own style. */
export function reportRunCss() {
  return `<style>
  .rr { max-width: 60rem; }
  .rr-back { margin-bottom: 0.75rem; font-size: 0.85rem; }
  .rr-title { font-weight: 600; margin-bottom: 0.25rem; }
  .rr-line, .rr-status, .rr-version { margin-bottom: 0.5rem; color: var(--crow-text-secondary); }
  .rr-error { margin-bottom: 0.75rem; padding: 0.6rem 0.75rem; border-radius: var(--crow-radius-card);
    border: 1px solid var(--crow-error); background: rgba(239,68,68,0.08); word-break: break-word; }
  .rr-frame { width: 100%; min-height: 32rem; border: 1px solid var(--crow-border);
    border-radius: var(--crow-radius-card); background: #fff; }
  .rr-links { margin-top: 1.5rem; }
  .rr-links h3 { font-size: 1rem; margin-bottom: 0.5rem; }
  .rr-links ul { list-style: none; }
  .rr-links li { margin-bottom: 0.35rem; word-break: break-all; font-size: 0.85rem; }
  </style>`;
}

/** The 404 body: the path names no report run of this instance. */
export function reportRunMissingHtml() {
  return `<div class="rr rr-missing">
    <p class="rr-line">${escapeHtml(RUN_VIEW_MISSING_LINE)}</p>
    <p class="rr-back"><a href="/dashboard/projects">${escapeHtml(BACK_TO_PROJECT_LINE)}</a></p>
  </div>`;
}

/** The run's links, on the page (never inside the frame). */
function linksSection(view) {
  if (!view.links.length && !view.moreLinks) return "";
  const items = view.links
    .map((url) => `<li><a href="${escapeHtml(url)}" rel="noopener noreferrer" target="_blank">${escapeHtml(url)}</a></li>`)
    .join("");
  const more = view.moreLinks > 0
    ? `<p class="rr-line">${escapeHtml(moreLinksLine(view.moreLinks))}</p>`
    : "";
  return `<section class="rr-links"><h3>${escapeHtml(LINKS_IN_RUN_HEADING)}</h3><ul>${items}</ul>${more}</section>`;
}

/** The version the run wrote: its number, and either the inert frame or the not-available line. */
function versionBlock(view) {
  if (!view.version) return "";
  const line = view.version.n == null ? "" : `<p class="rr-version">${escapeHtml(versionLine(view.version.n))}</p>`;
  const body = view.version.markdown == null
    ? `<p class="rr-line">${escapeHtml(VERSION_NOT_AVAILABLE_LINE)}</p>`
    : `<iframe class="rr-frame" title="${escapeHtml(RUN_FRAME_TITLE)}" sandbox="${FRAME_SANDBOX}" srcdoc="${escapeHtml(frameDocument(view.version.markdown))}"></iframe>`;
  return line + body;
}

/**
 * The run page body.
 *
 * @param {{project: object, report: object, run: object, version: object|null, links: string[],
 *   moreLinks: number}} view `loadReportRun`'s answer
 * @returns {string}
 */
export function reportRunHtml(view) {
  const home = `/dashboard/project/${encodeURIComponent(view.project.slug)}`;
  const error = view.run.errorText
    ? `<p class="rr-error">${escapeHtml(view.run.errorText)}</p>`
    : "";
  return `<div class="rr" data-report-run>
    <p class="rr-back"><a href="${escapeHtml(home)}">${escapeHtml(BACK_TO_PROJECT_LINE)}</a></p>
    <p class="rr-title">${escapeHtml(view.report.title)}</p>
    <p class="rr-status">${escapeHtml(runStatusLine(view.run.status))}</p>
    ${error}
    ${versionBlock(view)}
    ${linksSection(view)}
  </div>`;
}

export default reportRunHtml;