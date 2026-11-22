/**
 * The new shell's Attention sheet (R1.2, spec §13).
 *
 * attentionSheetHtml({ lang, health, issues, fixItHtml, flash, now }) composes
 * everything the sheet shows above the mascot's tray, in order: the welcome
 * block (the greeting and a long date, as the Nest's own welcome draws them),
 * the flash banner one redirect asked for, the Fix-it cards (already rendered by
 * fix-it/index.js's sheet renderer, passed in as fixItHtml), the "Needs
 * attention" group, the signal links the health signals carry, the all-good line
 * (only when health is ok AND no Fix-it card is up) and the collapsed "Status
 * details" block. The links and the detail cards come from the same place the
 * Nest's strip draws them: healthLinkRows (nest/html.js) is the one filter for a
 * link, so the sheet and the Nest cannot disagree about which rows are safe.
 *
 * attentionGroupHtml(issues, lang, back) renders the group itself: a heading,
 * then one row per issue with the severity dot, the label and its one action.
 * The backup issue keeps its POST form (as nest/html.js buildHealthStrip does)
 * and its form comes back to the sheet; an issue that carries `ack` gets a
 * "This is expected" button posting to POST /dashboard/health/ack. `back` is
 * where that POST returns (a /dashboard path; the attention route reopens the
 * sheet). The hidden _csrf is filled by the shell client's capture-phase submit
 * listener, like every shell form.
 *
 * Everything that reaches the markup is escaped.
 */

import { escapeHtml } from "../shared/components.js";
import { t } from "../shared/i18n.js";
import { healthLinkRows } from "../panels/nest/html.js";

const BACKUP_HREF = "/dashboard/nest?action=backup";

/** The sheet's own back path: GET /dashboard/attention reopens it in new mode. */
const SHEET_BACK = "/dashboard/attention";

function actionHtml(issue) {
  // Same-origin paths only ("/x", never "//host"): a link in this group never leaves the dashboard.
  if (!issue.actionLabel || typeof issue.actionHref !== "string" || !/^\/(?!\/)/.test(issue.actionHref)) return "";
  const label = escapeHtml(issue.actionLabel);
  if (issue.actionHref === BACKUP_HREF) {
    return `<form class="shell-attn-form" method="POST" action="/dashboard/nest/backup"><input type="hidden" name="_csrf" value=""><input type="hidden" name="return" value="sheet"><button class="shell-attn-btn" type="submit">${label}</button></form>`;
  }
  return `<a class="shell-attn-action" href="${escapeHtml(issue.actionHref)}">${label}</a>`;
}

function ackHtml(issue, lang, back) {
  const ack = issue.ack;
  if (!ack || typeof ack.kind !== "string" || typeof ack.key !== "string") return "";
  return `<form class="shell-attn-form" method="POST" action="/dashboard/health/ack"><input type="hidden" name="_csrf" value=""><input type="hidden" name="kind" value="${escapeHtml(ack.kind)}"><input type="hidden" name="key" value="${escapeHtml(ack.key)}"><input type="hidden" name="back" value="${escapeHtml(back)}"><button class="shell-attn-btn shell-attn-btn--quiet" type="submit">${escapeHtml(t("signals.ack.expected", lang))}</button></form>`;
}

export function attentionGroupHtml(issues, lang, back = "/dashboard/attention") {
  if (!Array.isArray(issues) || issues.length === 0) return "";
  const rows = issues.map((issue) => {
    const dot = issue.severity === "warn" ? "warn" : "info";
    const acts = actionHtml(issue) + ackHtml(issue, lang, back);
    return `<li class="shell-attn-row"><span class="shell-attn-dot shell-attn-dot--${dot}" aria-hidden="true"></span><span class="shell-attn-text">${escapeHtml(issue.label)}</span>${acts ? `<span class="shell-attn-acts">${acts}</span>` : ""}</li>`;
  }).join("");
  return `<h3 class="shell-heading shell-attn-heading">${escapeHtml(t("shell.attention", lang))}</h3><ul class="shell-attn-list">${rows}</ul><hr class="shell-crow-sep">`;
}

/** `lang` as the copy table knows it. */
function languageOf(lang) {
  return lang === "es" ? "es" : "en";
}

/** A banner tone, from the three flashBanner produces (anything else is the plain one). */
function flashTone(tone) {
  return tone === "success" || tone === "error" ? tone : "info";
}

/** The long date the Nest's welcome shows, in the dashboard's language. */
function longDate(now, lang) {
  const date = now instanceof Date && !Number.isNaN(now.getTime()) ? now : new Date();
  return date.toLocaleDateString(
    lang === "es" ? "es-ES" : "en-US",
    { weekday: "long", month: "long", day: "numeric", year: "numeric" },
  );
}

function welcomeHtml(lang, now) {
  return `<div class="shell-welcome"><div class="shell-welcome-greeting">${escapeHtml(t("health.welcome", lang))}</div><div class="shell-welcome-date">${escapeHtml(longDate(now, lang))}</div></div>`;
}

/** The banner object flashBanner returned for this page's flash code, or "". */
function flashHtmlOf(flash) {
  if (!flash || typeof flash !== "object" || typeof flash.text !== "string") return "";
  return `<div class="shell-attn-flash shell-attn-flash--${flashTone(flash.tone)}" role="status">${escapeHtml(flash.text)}</div>`;
}

/** The signal links, through the Nest's own filter (healthLinkRows). */
function linksHtmlOf(health) {
  const rows = healthLinkRows(health).map((l) => {
    const anchor = l.label ? ` <a class="shell-attn-action" href="${escapeHtml(l.href)}">${escapeHtml(l.label)}</a>` : "";
    return `<div class="shell-attn-link"><span class="shell-attn-link-text">${escapeHtml(l.text)}</span>${anchor}</div>`;
  }).join("");
  return rows ? `<div class="shell-attn-links">${rows}</div>` : "";
}

/** One detail card: the label and the value, colored by the signal's state. */
function detailCardHtml(detail) {
  const d = detail && typeof detail === "object" ? detail : {};
  const state = d.state === "ok" || d.state === "warn" || d.state === "info" ? d.state : "off";
  return `<div class="shell-attn-detail"><div class="shell-attn-detail-label">${escapeHtml(d.label)}</div><div class="shell-attn-detail-value shell-attn-detail-value--${state}">${escapeHtml(String(d.value ?? ""))}</div></div>`;
}

/** The collapsed Status details block (one card per health detail). */
function detailsHtmlOf(health, lang) {
  if (!health || typeof health !== "object") return "";
  const cards = (Array.isArray(health.details) ? health.details : []).map(detailCardHtml).join("");
  return `<details class="shell-attn-details"><summary>${escapeHtml(t("health.statusDetails", lang))}</summary><div class="shell-attn-detail-grid">${cards}</div></details>`;
}

/** The all-good line, shown only when health is ok AND no Fix-it card is up. */
function allgoodHtmlOf(health, fixItHtml, lang) {
  if (!health || typeof health !== "object" || !health.ok || fixItHtml) return "";
  return `<div class="shell-attn-allgood"><span class="shell-attn-allgood-dot" aria-hidden="true"></span><span>${escapeHtml(t("health.allgood", lang))}</span></div>`;
}

/**
 * The whole Attention sheet body, in the order the sheet shows it.
 *
 * @param {object} [opts]
 * @param {string} [opts.lang]        "en" | "es"
 * @param {object|null} [opts.health] collectHealthSignals' result ({ ok, issues, links, details })
 * @param {Array} [opts.issues]       the issues the group lists (health.issues)
 * @param {string} [opts.fixItHtml]   renderFixItSheetCards' markup ("" when nothing is pending)
 * @param {{tone: string, text: string}|null} [opts.flash]  flashBanner's banner
 * @param {Date} [opts.now]           the clock (tests)
 * @returns {string}
 */
export function attentionSheetHtml({ lang = "en", health = null, issues = [], fixItHtml = "", flash = null, now } = {}) {
  const language = languageOf(lang);
  const fixIt = typeof fixItHtml === "string" ? fixItHtml : "";
  const list = Array.isArray(issues) ? issues : [];
  return welcomeHtml(language, now)
    + flashHtmlOf(flash)
    + fixIt
    + attentionGroupHtml(list, language, SHEET_BACK)
    + linksHtmlOf(health)
    + allgoodHtmlOf(health, fixIt, language)
    + detailsHtmlOf(health, language);
}