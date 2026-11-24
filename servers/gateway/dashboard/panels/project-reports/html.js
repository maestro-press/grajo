/**
 * The markup of a project's Reports list and of one report's page (Crow Recurring Reports, task 9b).
 *
 * Every operator- or bot-written value goes through escapeHtml: a report's title, a pause reason, a
 * recipient's address, a block's settings and a run's error text are all data, never markup.
 *
 * The owner sees the buttons (Pause, Resume, Run now, Preview, Go live, the recipient decisions and
 * "Send to the rest") and the sections that carry addresses, steps and hosts. A reader's page is the
 * reduced one: the report's name, its status chip, its next run, the last result and the history rows
 * (time, result word, trigger label, version number) — no button of any kind, no pause reason, no error
 * text, no address, no schedule input, no settings, recipe, step or host list, and no client script (the
 * panel does not render one for them). The reduced data comes from ./data.js, which does not read the
 * fields that page may not show; a peer-signed call never reaches this file at all (the panel's refusal).
 *
 * The page draws its own header, so the layout's title stays for screen readers only (the CSS makes it
 * visually hidden, never display:none).
 */
import { escapeHtml } from "../../shared/components.js";
import { fill, t } from "../../shared/i18n.js";

/** The status words a report may be in on this page. */
const REPORT_STATUSES = new Set(["draft", "live", "paused"]);

/** The result words one run may be shown with (a late run reads "late", whatever its status was). */
const RESULT_WORDS = new Set(["ok", "empty", "failed", "late", "queued", "running"]);

/** The states a recipient or a step row may be in. */
const STATES = new Set(["proposed", "approved", "refused", "revoked"]);

/** The delivery rules, comment tiers and comment visibilities a report may carry, in the order the
 *  settings form lists them. */
const DELIVERY_ORDER = ["email_full", "email_link", "both", "crow_only"];
const DELIVERY_MODES = new Set(DELIVERY_ORDER);
const TIER_ORDER = ["a", "b", "c"];
const TIERS = new Set(TIER_ORDER);
const VISIBILITY_ORDER = ["own", "all"];
const VISIBILITIES = new Set(VISIBILITY_ORDER);

/** The run triggers a history row may name. */
const TRIGGERS = new Set(["preview", "schedule", "manual"]);

const statusWord = (status) => (REPORT_STATUSES.has(status) ? status : "draft");

const projectHref = (project) => `/dashboard/project/${encodeURIComponent(project.slug)}`;
const listHref = (project) => `${projectHref(project)}/reports`;
const reportHref = (project, report) => `${listHref(project)}/${encodeURIComponent(report.id)}`;

/** One chip: its class carries the word, so the CSS colours it without a second table. */
function chip(kind, word) {
  return `<span class="rp-chip rp-chip--${escapeHtml(kind)}">${escapeHtml(word)}</span>`;
}

/** A report's status chip. */
function statusChip(report, lang) {
  const word = statusWord(report.status);
  return chip(word, t(`projectReports.status.${word}`, lang));
}

/** A run's result chip: a late run reads "late", whatever its status was. */
function resultChip(run, lang) {
  const word = run.late ? "late" : (RESULT_WORDS.has(run.status) ? run.status : "failed");
  return chip(word, t(`projectReports.result.${word}`, lang));
}

/** A recipient's or a step's state chip. */
function stateChip(state, lang) {
  const word = STATES.has(state) ? state : "proposed";
  return chip(`state-${word}`, t(`projectReports.state.${word}`, lang));
}

/**
 * The word a report carries in its next-run place when it is not running a time: a live report whose
 * approval does not verify runs nothing, so it carries the same word a paused report does, and any other
 * report carries its own status word. One rule, for the list row and the page's schedule section alike.
 */
function notRunningWord(report) {
  return report.status === "live" ? "paused" : statusWord(report.status);
}

/** The status sentence a report that is not running carries in its next-run place. */
function notRunningLine(report, lang) {
  return escapeHtml(t(`projectReports.status.${notRunningWord(report)}`, lang));
}

/**
 * The sentence in the next-run place. A time is named only for a report that is live AND whose approval
 * verifies (`report.live`): a report whose seal no longer verifies runs nothing, so it carries the same
 * word a paused report does instead of a time nobody will see.
 */
function nextRunLine(report, lang) {
  if (report.status !== "live" || report.live !== true) return notRunningLine(report, lang);
  if (report.nextRunText) return escapeHtml(fill(t("projectReports.nextRun", lang), { when: report.nextRunText }));
  return escapeHtml(t("projectReports.noSchedule", lang));
}

/** The delivery word a report carries: one this page does not know is the link-only rule. */
const deliveryWord = (mode) => (DELIVERY_MODES.has(mode) ? mode : "email_link");

/** A comment tier's words; a missing tier is the report's own default. */
function tierText(tier, lang) {
  if (tier == null) return t("projectReports.tier.default", lang);
  const word = TIERS.has(tier) ? tier : "c";
  return t(`projectReports.tier.${word}`, lang);
}

/** The comment visibility a report carries: one this page does not know is "each person sees only
 *  their own". */
const visibilityWord = (value) => (VISIBILITIES.has(value) ? value : "own");

/** A button the page's client wires: action, the report it is about, and the words on it. A go-live
 *  button also carries `data-rp-sender`, the sender account id the page showed (the empty string when
 *  the report has none), which the client hands back with the go-live so the route can compare it with
 *  the row it reads. A recipient button may carry `data-rp-name`, the words a confirmation names that
 *  person by (the display name when the row has one, else the address). */
function actionButton(action, report, label, { run = null, recipient = null, sender = null, name = null } = {}) {
  const runAttr = run ? ` data-rp-run="${escapeHtml(run)}"` : "";
  const recipientAttr = recipient ? ` data-rp-recipient="${escapeHtml(recipient)}"` : "";
  const senderAttr = typeof sender === "string" ? ` data-rp-sender="${escapeHtml(sender)}"` : "";
  const nameAttr = typeof name === "string" ? ` data-rp-name="${escapeHtml(name)}"` : "";
  return `<button type="button" class="rp-btn" data-rp-action="${escapeHtml(action)}" data-rp-report="${escapeHtml(report.id)}"${runAttr}${recipientAttr}${senderAttr}${nameAttr}>${escapeHtml(label)}</button>`;
}

/** A link that looks like the buttons beside it. */
function actionLink(cls, href, label) {
  return `<a class="${cls}" href="${escapeHtml(href)}">${escapeHtml(label)}</a>`;
}

/* ------------------------------------------------------------------------ the list */

/** One report's row on the list page. */
function reportRow(report, project, owner, lang) {
  const href = reportHref(project, report);
  // The pause reason is the owner's line: a reader gets no part of it on the list.
  const pause = owner && report.status === "paused" && report.pauseReason
    ? `<span class="rp-reason">${escapeHtml(report.pauseReason)}</span>`
    : "";
  const last = report.lastRun
    ? `<span class="rp-meta">${escapeHtml(t("projectReports.lastRun", lang))} ${resultChip(report.lastRun, lang)}${report.lastRun.endedText ? ` <span class="rp-when">${escapeHtml(report.lastRun.endedText)}</span>` : ""}</span>`
    : "";
  const count = owner && report.recipientCount != null
    ? `<span class="rp-meta">${escapeHtml(fill(t("projectReports.recipientCount", lang), { n: report.recipientCount }))}</span>`
    : "";
  const buttons = [];
  if (owner && report.status === "live") buttons.push(actionButton("pause", report, t("projectReports.pause", lang)));
  if (owner && report.status === "paused") buttons.push(actionButton("resume", report, t("projectReports.resume", lang)));
  if (owner && report.status === "live" && report.live) buttons.push(actionButton("run-now", report, t("projectReports.runNow", lang)));
  if (owner && report.latestRun && report.latestRun.href) {
    buttons.push(actionLink("rp-btn", report.latestRun.href, t("projectReports.openLatest", lang)));
  }
  buttons.push(actionLink("rp-btn", `${href}#history`, t("projectReports.history", lang)));
  return `<li class="rp-row">
      <div class="rp-row-text">
        <a class="rp-name" href="${escapeHtml(href)}">${escapeHtml(report.title)}</a>
        ${pause}
        <span class="rp-meta">${nextRunLine(report, lang)}</span>
        ${last}
        ${count}
      </div>
      ${statusChip(report, lang)}
      <div class="rp-actions">${buttons.join("")}</div>
    </li>`;
}

/**
 * The list page's body.
 *
 * @param {{project: object, owner: boolean, reports: object[]}} view loadReportsList's answer
 * @param {string} lang
 */
export function projectReportsListHtml(view, lang = "en") {
  const { project, owner = false, reports = [] } = view;
  const rows = reports.map((report) => reportRow(report, project, owner, lang)).join("");
  const list = rows
    ? `<ul class="rp-list">${rows}</ul>`
    : `<p class="rp-empty">${escapeHtml(t("projectReports.empty", lang))}</p>`;
  return `<div class="rp" data-rp data-rp-project-slug="${escapeHtml(project.slug)}">
    <p class="rp-back"><a class="rp-project" href="${escapeHtml(projectHref(project))}">${escapeHtml(fill(t("projectReports.back", lang), { project: project.name }))}</a></p>
    <p class="rp-title" aria-hidden="true">${escapeHtml(t("projectReports.pageTitle", lang))}</p>
    ${list}
    ${owner ? '<p class="rp-status" role="status" aria-live="polite" data-rp-status></p>' : ""}
  </div>`;
}

/* ------------------------------------------------------------------- the report page */

/** The pause banner: the row's own reason, above the controls, with the one button that follows it.
 *  A stale reason on a report that is not paused is not a banner. */
function pauseBanner(report, lang) {
  if (report.status !== "paused" || !report.pauseReason) return "";
  return `<div class="rp-banner" role="status">
      <p class="rp-banner-text">${escapeHtml(report.pauseReason)}</p>
      ${actionButton("go-live", report, t("projectReports.checkAndGoLive", lang), { sender: senderId(report) })}
    </div>`;
}

/** The sender account id the page showed, as the go-live button carries it: the owner view's own field,
 *  and the empty string for a report with no sender (or for a view that carries none). */
function senderId(report) {
  return typeof report.senderAccountId === "string" ? report.senderAccountId : "";
}

/** Pause or Resume, Run now, Preview, Go live, and who the report sends from. */
function controls(report, owner, lang) {
  if (!owner) return "";
  const buttons = [];
  if (report.status === "live") buttons.push(actionButton("pause", report, t("projectReports.pause", lang)));
  if (report.status === "paused") buttons.push(actionButton("resume", report, t("projectReports.resume", lang)));
  if (report.status === "live" && report.live) buttons.push(actionButton("run-now", report, t("projectReports.runNow", lang)));
  buttons.push(actionButton("preview", report, t("projectReports.preview", lang)));
  if (report.status === "draft" || (report.status === "paused" && !report.pauseReason)) {
    buttons.push(actionButton("go-live", report, t("projectReports.goLive", lang), { sender: senderId(report) }));
  }
  const sender = report.sender
    ? escapeHtml(fill(t("projectReports.sender", lang), { address: report.sender.address }))
    : escapeHtml(t("projectReports.sender.none", lang));
  return `<section class="rp-section rp-controls">
      <div class="rp-actions">${buttons.join("")}</div>
      <p class="rp-sender">${sender}</p>
    </section>`;
}

/**
 * The schedule: the next run in the report's own zone, and the cron and zone the owner may save.
 *
 * A next-run time is named only for a report that is actually running (./data.js names one only for a live
 * report whose approval verifies), so its absence is not the same thing as having no schedule. With a
 * schedule row the section reads exactly what the list row reads beside it — the time, the word a report
 * that runs nothing carries ("Draft", "Paused"), or "No schedule yet." for a live report whose approval
 * verifies but whose window has passed (or whose row is switched off) — and only a report with no schedule
 * row at all reads "No schedule yet." for that reason alone.
 */
function scheduleSection(report, owner, lang) {
  if (!owner) return "";
  const schedule = report.schedule;
  const cron = schedule ? schedule.cron : "";
  const tz = schedule ? schedule.tz || "" : "";
  const next = schedule
    ? nextRunLine(report, lang)
    : escapeHtml(t("projectReports.noSchedule", lang));
  return `<section class="rp-section" id="schedule">
      <h3 class="rp-label">${escapeHtml(t("projectReports.section.schedule", lang))}</h3>
      <p class="rp-meta">${next}</p>
      <form class="rp-form" method="post" data-rp-schedule data-rp-report="${escapeHtml(report.id)}">
        <label class="rp-field"><span>${escapeHtml(t("projectReports.schedule.cron", lang))}</span>
          <input class="rp-input" type="text" data-rp-cron value="${escapeHtml(cron)}" autocomplete="off" spellcheck="false"></label>
        <label class="rp-field"><span>${escapeHtml(t("projectReports.schedule.tz", lang))}</span>
          <input class="rp-input" type="text" data-rp-tz value="${escapeHtml(tz)}" autocomplete="off" spellcheck="false"></label>
        <button type="submit" class="rp-btn">${escapeHtml(t("projectReports.schedule.save", lang))}</button>
      </form>
    </section>`;
}

/**
 * How many recent runs keep comments open, as the page reads it. ./data.js already answers the
 * report's own `comment_window_runs`, defaulted to the same number when the column is empty; this falls
 * back to that number for a view a caller built by hand, so no page ever prints "{n}".
 */
const DEFAULT_COMMENT_WINDOW_RUNS = 4;

function commentWindowRunsOf(report) {
  const runs = Number(report.commentWindowRuns);
  return Number.isInteger(runs) && runs > 0 ? runs : DEFAULT_COMMENT_WINDOW_RUNS;
}

/* --------------------------------------------------------------- the settings form */

/** One <option> of a settings menu: the value a save writes, and the words a person reads. */
function settingOption(value, label, selected) {
  return `<option value="${escapeHtml(value)}"${selected ? " selected" : ""}>${escapeHtml(label)}</option>`;
}

/**
 * One setting's menu. `choices` is a list of [value, words] pairs, so a caller says the words the page
 * already carries and this says the markup; the choice whose value is `current` is the selected one.
 */
function settingSelect(setting, current, choices) {
  const options = choices.map(([value, label]) => settingOption(value, label, value === current)).join("");
  return `<select class="rp-input" data-rp-setting="${escapeHtml(setting)}" data-rp-current="${escapeHtml(current)}">${options}</select>`;
}

/**
 * The sending-account menu: the accounts that can send right now, then the report's own sender when it
 * is not one of them any more (a person must be able to see and change what the report sends from), and
 * "No sending account chosen yet." as the first choice when the report has no sender at all.
 */
function senderSelect(report, lang) {
  const current = senderId(report);
  const choices = [];
  const seen = new Set();
  if (!current) choices.push(["", t("projectReports.sender.none", lang)]);
  const options = Array.isArray(report.senderOptions) ? report.senderOptions : [];
  for (const option of options) {
    const id = option && typeof option.id === "string" ? option.id : "";
    if (!id || seen.has(id)) continue;
    seen.add(id);
    choices.push([id, option.address ? String(option.address) : id]);
  }
  if (current && !seen.has(current)) {
    const address = report.sender && report.sender.address ? String(report.sender.address) : current;
    choices.push([current, address]);
  }
  return settingSelect("sender_account_id", current, choices);
}

/** The delivery menu. */
function deliverySelect(report, lang) {
  return settingSelect("delivery_mode", deliveryWord(report.deliveryMode),
    DELIVERY_ORDER.map((word) => [word, t(`projectReports.delivery.${word}`, lang)]));
}

/** The comment-tier menu: always the three tiers, a, b and c, and never an empty choice. The column is
 *  TEXT NOT NULL DEFAULT 'c', so a report always holds one of the three. A stored tier this page cannot use
 *  shows `c` selected: an empty or missing value is `c`, as in `commentTierOf` in
 *  `servers/gateway/reports/links.js`, and an unknown word also shows `c` here, which is this form's own
 *  choice (`commentTierOf` returns a non-empty unknown word unchanged). */
function tierSelect(report, lang) {
  const stored = report.commentTierDefault;
  const current = TIERS.has(stored) ? stored : "c";
  return settingSelect("comment_tier_default", current,
    TIER_ORDER.map((tier) => [tier, t(`projectReports.tier.${tier}`, lang)]));
}

/** The comment-visibility menu. */
function visibilitySelect(report, lang) {
  return settingSelect("comment_visibility", visibilityWord(report.commentVisibility),
    VISIBILITY_ORDER.map((word) => [word, t(`projectReports.visibility.${word}`, lang)]));
}

/** The AI commentary menu: "1" and "0", which is what the save writes. */
function aiSelect(report, lang) {
  return settingSelect("ai_commentary", report.aiCommentary ? "1" : "0", [
    ["1", t("projectReports.settings.on", lang)],
    ["0", t("projectReports.settings.off", lang)],
  ]);
}

/**
 * The comment window (6a C4): one sentence with the number box in the place the copy leaves for it. The
 * sentence is translated as a whole, so it is split on its one placeholder here and each part escaped. A
 * sentence that carries no placeholder is rendered as it is with the box after it, so the box is never
 * dropped.
 */
function windowField(report, lang) {
  const runs = commentWindowRunsOf(report);
  const sentence = t("projectReports.settings.commentWindow", lang);
  const parts = sentence.split("{n}");
  const input = `<input class="rp-input rp-input--inline" type="number" min="1" max="50" step="1" inputmode="numeric" data-rp-setting="comment_window_runs" data-rp-current="${escapeHtml(runs)}" value="${escapeHtml(runs)}">`;
  if (parts.length < 2) return `<span>${escapeHtml(sentence)}${input}</span>`;
  const head = escapeHtml(parts[0] || "");
  const tail = escapeHtml(parts.slice(1).join("{n}"));
  return `<span>${head}${input}${tail}</span>`;
}

/**
 * The settings the owner may change: the sending account, the delivery rule, the comment defaults, the
 * AI switch and how many recent runs keep comments open. One form and one Save; the three empty status
 * lines are where the client writes the answer (a bad number, a sender that cannot send, what the save
 * did). Everything here is the owner's: a reader gets no settings section at all.
 *
 * The comment-tier menu always offers exactly a, b and c (tierSelect), because `reports.comment_tier_default`
 * is TEXT NOT NULL DEFAULT 'c' and a report therefore always holds one of them; a stored value this page
 * cannot use shows `c` selected, where an empty or missing value is the column's own default and an unknown
 * word is this form's own choice.
 */
function settingsSection(report, owner, lang) {
  if (!owner) return "";
  const live = report.status === "live";
  const liveWarning = live
    ? `<p class="rp-meta" data-rp-settings-live>${escapeHtml(t("projectReports.settings.liveWarning", lang))}</p>`
    : "";
  return `<section class="rp-section" id="settings">
      <h3 class="rp-label">${escapeHtml(t("projectReports.section.settings", lang))}</h3>
      <form class="rp-form" method="post" data-rp-settings data-rp-report="${escapeHtml(report.id)}"${live ? ' data-rp-live="1"' : ""}>
        <label class="rp-field"><span>${escapeHtml(t("projectReports.settings.senderLabel", lang))}</span>
          ${senderSelect(report, lang)}</label>
        <label class="rp-field"><span>${escapeHtml(t("projectReports.settings.delivery", lang))}</span>
          ${deliverySelect(report, lang)}</label>
        <label class="rp-field"><span>${escapeHtml(t("projectReports.settings.tier", lang))}</span>
          ${tierSelect(report, lang)}</label>
        <label class="rp-field"><span>${escapeHtml(t("projectReports.settings.visibility", lang))}</span>
          ${visibilitySelect(report, lang)}</label>
        <label class="rp-field"><span>${escapeHtml(t("projectReports.settings.ai", lang))}</span>
          ${aiSelect(report, lang)}</label>
        <label class="rp-field">${windowField(report, lang)}</label>
        <p class="rp-status rp-status--error" role="status" aria-live="polite" data-rp-window-error></p>
        ${liveWarning}
        <p class="rp-status rp-status--error" role="status" aria-live="polite" data-rp-settings-note></p>
        <button type="submit" class="rp-btn">${escapeHtml(t("projectReports.settings.save", lang))}</button>
        <p class="rp-status" role="status" aria-live="polite" data-rp-settings-result></p>
      </form>
    </section>`;
}

/**
 * One recipient: the address, its state, its tier and the decisions that fit its state. An approved
 * recipient has two: Revoke (the approval itself) and Revoke links (only the links already sent, which
 * leaves the approval in place so the next run mints new ones). The links button names the person as
 * the page knows them (the display name, else the address) for the confirmation the client asks first.
 */
function recipientRow(recipient, report, lang) {
  const actions = [];
  const name = recipient.displayName || recipient.address;
  if (recipient.state === "proposed") {
    actions.push(actionButton("approve", report, t("projectReports.recipients.approve", lang), { recipient: recipient.id }));
    actions.push(actionButton("refuse", report, t("projectReports.recipients.refuse", lang), { recipient: recipient.id }));
  } else if (recipient.state === "approved") {
    actions.push(actionButton("revoke", report, t("projectReports.recipients.revoke", lang), { recipient: recipient.id }));
    actions.push(actionButton("revoke-links", report, t("projectReports.recipients.revokeLinks", lang), { recipient: recipient.id, name }));
  }
  const tier = `<span class="rp-meta">${escapeHtml(tierText(recipient.tier, lang))}</span>`;
  return `<li class="rp-recipient">
      <span class="rp-recipient-address">${escapeHtml(recipient.address)}</span>
      ${stateChip(recipient.state, lang)}
      ${tier}
      <div class="rp-actions">${actions.join("")}</div>
    </li>`;
}

/** The recipient list, with the row the owner has not answered yet called out. */
function recipientsSection(report, owner, lang) {
  if (!owner) return "";
  const rows = (report.recipients || []).map((recipient) => recipientRow(recipient, report, lang)).join("");
  const pending = (report.recipients || []).some((recipient) => recipient.state === "proposed")
    ? `<p class="rp-meta">${escapeHtml(t("projectReports.recipients.pending", lang))}</p>`
    : "";
  const body = rows ? `<ul class="rp-list rp-recipients">${rows}</ul>` : `<p class="rp-meta">${escapeHtml(t("projectReports.recipients.empty", lang))}</p>`;
  return `<section class="rp-section" id="recipients">
      <h3 class="rp-label">${escapeHtml(t("projectReports.section.recipients", lang))}</h3>
      ${pending}
      ${body}
    </section>`;
}

/** The recipe as a read-only list: each block's type and id, and its settings as short text. */
function recipeSection(report, owner, lang) {
  if (!owner) return "";
  const blocks = report.recipe || [];
  const body = blocks.length
    ? `<ul class="rp-list rp-blocks">${blocks.map((block) => {
      const settings = block.settings.length
        ? `<ul class="rp-settings">${block.settings.map((pair) => `<li><span class="rp-setting-key">${escapeHtml(pair.key)}</span>: ${escapeHtml(pair.value)}</li>`).join("")}</ul>`
        : "";
      return `<li class="rp-block"><span class="rp-block-type">${escapeHtml(block.type || "?")}</span> <span class="rp-block-id">${escapeHtml(block.id || "?")}</span>${settings}</li>`;
    }).join("")}</ul>`
    : `<p class="rp-meta">${escapeHtml(t("projectReports.recipe.empty", lang))}</p>`;
  return `<section class="rp-section" id="recipe">
      <h3 class="rp-label">${escapeHtml(t("projectReports.section.recipe", lang))}</h3>
      ${body}
    </section>`;
}

/** The custom steps and the sites they may reach, each with its approval state. */
function stepsSection(report, owner, lang) {
  if (!owner) return "";
  const steps = report.steps || [];
  const hosts = report.hosts || [];
  const stepList = steps.length
    ? `<ul class="rp-list rp-steps">${steps.map((step) => `<li class="rp-step"><span class="rp-step-key">${escapeHtml(step.key)}</span> <span class="rp-meta">${escapeHtml(fill(t("projectReports.steps.rev", lang), { n: step.rev }))}</span> ${stateChip(step.state, lang)}</li>`).join("")}</ul>`
    : `<p class="rp-meta">${escapeHtml(t("projectReports.steps.empty", lang))}</p>`;
  const hostList = hosts.length
    ? `<ul class="rp-list rp-hosts">${hosts.map((host) => `<li class="rp-host"><span class="rp-host-name">${escapeHtml(host.host)}</span> ${stateChip(host.state, lang)}</li>`).join("")}</ul>`
    : `<p class="rp-meta">${escapeHtml(t("projectReports.hosts.empty", lang))}</p>`;
  return `<section class="rp-section" id="steps">
      <h3 class="rp-label">${escapeHtml(t("projectReports.section.steps", lang))}</h3>
      ${stepList}
      <h3 class="rp-label">${escapeHtml(t("projectReports.section.hosts", lang))}</h3>
      ${hostList}
    </section>`;
}

/** The version cell of one history row: the run's version as a link, "expired", or a bare number.
 *  A reader's version carries neither a state nor a link (./data.js), so it is the number alone. */
function versionCell(version, lang) {
  if (!version) return "";
  const label = fill(t("projectReports.version.n", lang), { n: version.n });
  if (version.state === "expired") {
    return ` <span class="rp-version rp-version--expired">${escapeHtml(t("projectReports.version.expired", lang))}</span>`;
  }
  if (version.href) {
    return ` <a class="rp-version" href="${escapeHtml(version.href)}">${escapeHtml(label)}</a>`;
  }
  return ` <span class="rp-version">${escapeHtml(label)}</span>`;
}

/** The send log's counts for one run, as "{n} sent, {n} unknown". */
function sendsLine(sends, lang) {
  if (!sends) return "";
  const parts = [];
  if (sends.sent) parts.push(fill(t("projectReports.sends.sent", lang), { n: sends.sent }));
  if (sends.unknown) parts.push(fill(t("projectReports.sends.unknown", lang), { n: sends.unknown }));
  if (sends.failed) parts.push(fill(t("projectReports.sends.failed", lang), { n: sends.failed }));
  if (sends.pending) parts.push(fill(t("projectReports.sends.pending", lang), { n: sends.pending }));
  return parts.length ? `<span class="rp-sends">${escapeHtml(parts.join(", "))}</span>` : "";
}

/** One run of the history: the result word, the time, the trigger label, the version number, and —
 *  for the owner only — the error line, the send counts and the "Send to the rest" button. */
function runRow(run, report, owner, lang) {
  const trigger = TRIGGERS.has(run.trigger)
    ? `<span class="rp-trigger">${escapeHtml(t(`projectReports.trigger.${run.trigger}`, lang))}</span>`
    : "";
  const error = owner && run.errorText
    ? `<p class="rp-run-error">${escapeHtml(run.errorText)}</p>`
    : "";
  const sends = owner ? sendsLine(run.sends, lang) : "";
  const rest = owner && run.canSendRest
    ? actionButton("send-rest", report, t("projectReports.sendRest", lang), { run: run.id })
    : "";
  return `<li class="rp-run">
      <div class="rp-run-main">
        ${resultChip(run, lang)}
        <span class="rp-when">${escapeHtml(run.timeText || "")}</span>
        ${trigger}
        ${versionCell(run.version, lang)}
      </div>
      ${error}
      ${sends ? `<div class="rp-run-meta">${sends}</div>` : ""}
      ${rest ? `<div class="rp-actions">${rest}</div>` : ""}
    </li>`;
}

/** The run history, anchored so a list row's History link lands on it. */
function historySection(report, owner, lang) {
  const runs = report.runs || [];
  const body = runs.length
    ? `<ul class="rp-list rp-runs">${runs.map((run) => runRow(run, report, owner, lang)).join("")}</ul>`
    : `<p class="rp-meta">${escapeHtml(t("projectReports.history.empty", lang))}</p>`;
  return `<section class="rp-section" id="history">
      <h3 class="rp-label">${escapeHtml(t("projectReports.section.history", lang))}</h3>
      ${body}
    </section>`;
}

/**
 * The report page's body.
 *
 * @param {{project: object, owner: boolean, report: object}} view loadReportPage's answer
 * @param {string} lang
 */
export function projectReportPageHtml(view, lang = "en") {
  const { project, owner = false, report } = view;
  const preview = owner && report.preview && report.preview.runId
    ? ` data-rp-preview="${escapeHtml(report.preview.runId)}"`
    : "";
  return `<div class="rp" data-rp data-rp-report-id="${escapeHtml(report.id)}" data-rp-project-slug="${escapeHtml(project.slug)}"${preview}>
    <p class="rp-back"><a class="rp-project" href="${escapeHtml(listHref(project))}">${escapeHtml(t("projectReports.backToReports", lang))}</a></p>
    <header class="rp-head">
      <p class="rp-title" aria-hidden="true">${escapeHtml(report.title)}</p>
      ${statusChip(report, lang)}
    </header>
    <p class="rp-next">${nextRunLine(report, lang)}</p>
    ${owner ? pauseBanner(report, lang) : ""}
    ${controls(report, owner, lang)}
    ${scheduleSection(report, owner, lang)}
    ${settingsSection(report, owner, lang)}
    ${recipientsSection(report, owner, lang)}
    ${recipeSection(report, owner, lang)}
    ${stepsSection(report, owner, lang)}
    ${historySection(report, owner, lang)}
    ${owner ? '<p class="rp-status" role="status" aria-live="polite" data-rp-status></p>' : ""}
  </div>`;
}