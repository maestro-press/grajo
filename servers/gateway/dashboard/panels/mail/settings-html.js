/**
 * Crow Mail's account settings page (plan 2, Task 7): one card per account and, below them, the
 * "Add an account" form. The page is drawn by the panel at `/dashboard/mail?view=settings`; every
 * control on it is a hook the client script reads (`data-ml-*`) and the request it makes goes to
 * `/dashboard/mail/api`, never to this page.
 *
 * A card shows the owner's own label (editable) and the mailbox address, a status in words — working,
 * a sign-in that needs the password again, or an account another instance holds — the last sync time
 * under its own "Last checked" label, the sync control, the local-models switch with its helper line,
 * the Sent-copy rule, the update-password control (only for an account the server refused), the
 * senders whose images show unasked (under their own heading), and remove behind its own sentence.
 * Nothing drawn here is a
 * connection setting: `accountsOverview` carries no host, port or username, and this module never asks
 * the account store for one. The senders arrive from the caller as `allow[accountId] = [sender, …]`,
 * already lower-cased and sorted.
 *
 * Above the accounts sits the owner-wide mail settings card (plan 3, Task 13): working hours, which the
 * schedule sheet's shortcuts use, and the cloud-drafting switch (off until the owner turns it on). Its
 * controls carry no stored value in this markup — the client reads them from
 * `GET /dashboard/mail/api/settings` when the settings view is shown and saves them with one PATCH — so
 * the page never has to be handed a setting to draw, and a value never ends up in an attribute.
 *
 * Every value that came from the owner or from the wire (a label, an address, a sender) is escaped:
 * a label is text in the heading and an attribute in the rename field, and no value is ever used for
 * markup or an event handler. The page makes no request of its own and holds no script; its header row
 * carries the same settings gear every other view has.
 *
 * The add-account area (plan 5, Task 5) is the Gmail card, the Microsoft card and — for every other
 * provider — the generic form below them, whose field names plan 2 fixed. The two cards' sentences
 * are the operator-approved copy and live in `wizard-html.js`; they carry no host, port or credential,
 * because a password connection is made against the provider preset the server applies. The area is
 * drawn with this instance's own redirect address (the one `GET /dashboard/mail/api/oauth/redirect-uri`
 * answers with), or with none at all when the machine has no dashboard address: then each card shows
 * C19 and keeps its app-password path usable. The client script (`wizard-client.js`) is emitted with
 * the page; it owns every action, and every sentence it can show rides the markup as a data attribute.
 *
 * The page also shows the callback's fixed status key (`?mailStatus=oauth_connected` and the rest) as
 * its approved sentence above the cards, and nothing at all for a key it has no sentence for.
 */
import { escapeHtml } from "../../shared/components.js";
import { t, fill } from "../../shared/i18n.js";
import { anotherCrow, mailGearLink } from "./html.js";
import { mailStatusHtml, wizardsHtml } from "./wizard-html.js";
import { mailWizardClientJs } from "./wizard-client.js";
import { dashboardRedirectUri } from "../../../routes/mail-api-oauth.js";

const e = escapeHtml;

const LOCALES = { en: "en-US", es: "es-ES" };

function localeOf(lang) {
  return LOCALES[lang] ?? LOCALES.en;
}

/** The owner's own label, trimmed, and empty when they left it blank: the rename field's value. */
function typedLabelOf(account) {
  return typeof account?.label === "string" ? account.label.trim() : "";
}

/** The account's heading: the owner's words, else the mailbox address (never the blank label itself). */
function labelOf(account, lang) {
  const address = typeof account?.address === "string" ? account.address.trim() : "";
  return typedLabelOf(account) || address || anotherCrow(lang);
}

/** The name of the instance an account is connected on, or the fallback when none is stored. */
function heldNameOf(account, lang) {
  const name = typeof account?.heldBy === "string" ? account.heldBy.trim() : "";
  return name || anotherCrow(lang);
}

/** The status in words: working, a sign-in that needs the owner, or held by another instance. */
function statusWord(account, lang) {
  const status = typeof account?.status === "string" ? account.status : "active";
  if (status === "auth_failed") {
    // An OAuth account's sign-in is fixed by signing in again, never by typing a password: it shows
    // the approved C29 sentence instead (plan 5, Task 6), and the card carries the Reconnect control.
    return account?.authKind === "xoauth2" ? t("mail.statusAuthFailedOauth", lang) : t("mail.statusAuthFailed", lang);
  }
  if (status === "claimed_elsewhere") {
    return fill(t("mail.statusHeld", lang), { instance: heldNameOf(account, lang) });
  }
  return t("mail.statusWorking", lang);
}

/** One status line, carrying its code as data so a reload can be read without parsing the sentence. */
function statusHtml(account, lang) {
  const status = typeof account?.status === "string" ? account.status : "active";
  return `<p class="ml-note ml-status" data-ml-status="${e(status)}">${e(statusWord(account, lang))}</p>`;
}

/**
 * The last check as its own visible label and then a whole date and time in the instance's zone;
 * nothing at all when there is none.
 */
function lastSyncHtml(value, { lang, tz }) {
  const ms = Number(value);
  if (value == null || !Number.isFinite(ms)) return "";
  let formatter;
  try {
    formatter = new Intl.DateTimeFormat(localeOf(lang), tz
      ? { dateStyle: "medium", timeStyle: "short", timeZone: tz }
      : { dateStyle: "medium", timeStyle: "short" });
  } catch {
    return "";
  }
  let text;
  try {
    text = formatter.format(new Date(ms));
  } catch {
    return "";
  }
  return `<p class="ml-note ml-synced">${e(t("mail.lastChecked", lang))} <time datetime="${e(new Date(ms).toISOString())}">${e(text)}</time></p>`;
}

/**
 * The senders whose remote images show unasked on this account, under their own heading, each with its
 * own remove control. The list is context-free without that heading, so the whole block — heading and
 * list — is drawn only when there is something to remove.
 */
function allowListHtml(accountId, senders, lang) {
  const list = (Array.isArray(senders) ? senders : [])
    .filter((sender) => typeof sender === "string" && sender !== "");
  if (!list.length) return "";
  const items = list.map((sender) => `<li class="ml-allow-item">`
    + `<span class="ml-allow-sender">${e(sender)}</span>`
    + `<button class="ml-btn" type="button" data-ml-remove-sender data-account="${e(accountId)}" data-sender="${e(sender)}">${e(t("mail.remove", lang))}</button>`
    + "</li>").join("");
  return `<h3 class="ml-allow-title">${e(t("mail.allowedSendersHeading", lang))}</h3>`
    + `<ul class="ml-allow" data-ml-allow-list>${items}</ul>`;
}

/**
 * The reconnect block (plan 5, Task 6): one button that starts the same sign-in the wizard does, for an
 * account that already exists. It is drawn for a grant Google is about to end (C28's sentence above
 * it) and for an OAuth account whose sign-in already stopped (C29 is the card's status line).
 *
 * The card names the account, its provider and the address it already has, and nothing else: the
 * client id and the client secret are read server-side from the sealed keychain when the start route
 * runs, so no registration and no secret is ever drawn onto this page. The refusal line is the
 * approved K3 sentence (`data-ml-hint-flow_failed`), carried here so the client script needs no text
 * of its own.
 */
function reconnectHtml(account, lang) {
  const id = String(account?.id ?? "");
  const provider = typeof account?.oauthProvider === "string" ? account.oauthProvider : "";
  const address = typeof account?.address === "string" ? account.address : "";
  const soon = account?.reconnectDue === true ? `<p class="ml-note">${e(t("mail.wizard.reconnectSoon", lang))}</p>` : "";
  return `<div class="ml-reconnect" data-ml-reconnect-banner data-ml-hint-flow_failed="${e(t("mail.wizard.oauthFailed", lang))}">`
    + soon
    + `<button class="ml-btn ml-btn--primary" type="button" data-ml-reconnect data-account="${e(id)}"`
    + ` data-ml-reconnect-provider="${e(provider)}" data-ml-reconnect-address="${e(address)}">${e(t("mail.wizard.reconnect", lang))}</button>`
    + `<p class="ml-note ml-wizard-check" data-ml-reconnect-result role="status" hidden></p>`
    + "</div>";
}

/**
 * The password control, drawn only for an account the server refused: the field the new password is
 * typed into, and the button the client sends it with. An account that signs in has nothing here, and
 * neither has an OAuth account (its control is the reconnect block above).
 */
function updatePasswordHtml(accountId, lang) {
  return `<details class="ml-update-password" data-ml-update-password data-account="${e(accountId)}">`
    + `<summary class="ml-field-label">${e(t("mail.updatePassword", lang))}</summary>`
    + `<label class="ml-field"><span class="ml-field-label">${e(t("mail.fieldPassword", lang))}</span>`
    + `<input class="ml-input" type="password" name="password" autocomplete="new-password" data-ml-password-input></label>`
    + `<button class="ml-btn" type="button" data-ml-password-save data-account="${e(accountId)}">${e(t("mail.updatePassword", lang))}</button>`
    + "</details>";
}

/**
 * Remove, behind its own sentence. The sentence stays hidden until the client's own first click on the
 * button, which is inert until then; the client sends the delete only on a later click.
 */
function removeAccountHtml(accountId, lang) {
  return `<div class="ml-danger" data-ml-remove-account data-account="${e(accountId)}">`
    + `<p class="ml-note" data-ml-confirm-sentence hidden>${e(t("mail.removeAccountConfirm", lang))}</p>`
    + `<button class="ml-btn" type="button" data-ml-remove-account-btn data-account="${e(accountId)}">${e(t("mail.removeAccount", lang))}</button>`
    + "</div>";
}

/**
 * The Sent-copy rule of one account: two words the account store accepts, drawn as a select so the
 * choice is one tap. The value the page can know (`account.sentCopy`) is selected here; the settings
 * view's own read (`GET /dashboard/mail/api/settings`) corrects it on load, so a page drawn from a
 * summary without the field still ends up showing the stored rule.
 */
function sentCopyHtml(account, lang) {
  const id = String(account?.id ?? "");
  const current = account?.sentCopy === "append" ? "append" : "provider";
  const option = (value, label) => `<option value="${value}"${value === current ? " selected" : ""}>${e(label)}</option>`;
  return `<label class="ml-field"><span class="ml-field-label">${e(t("mail.sentCopy", lang))}</span>`
    + `<select class="ml-input" name="sentCopy" data-ml-sent-copy data-account="${e(id)}">`
    + option("provider", t("mail.sentCopyProvider", lang))
    + option("append", t("mail.sentCopyAppend", lang))
    + "</select></label>"
    + `<p class="ml-help">${e(t("mail.sentCopyHelp", lang))}</p>`;
}

/**
 * The owner-wide mail settings: working hours (which the schedule sheet's shortcuts use) and the
 * cloud-drafting switch (Q1: off until the owner turns it on). The controls carry no values here — the
 * client reads them from `GET /dashboard/mail/api/settings` when the settings view is shown — and the
 * save control sends all of them, so the two working-hour fields always travel together.
 */
function mailSettingsHtml(lang) {
  return `<section class="ml-card" data-ml-mail-settings>`
    + `<h2 class="ml-card-title">${e(t("mail.mailSettings", lang))}</h2>`
    + `<h3 class="ml-card-subtitle">${e(t("mail.workingHoursHeading", lang))}</h3>`
    + `<label class="ml-field"><span class="ml-field-label">${e(t("mail.workingHoursStart", lang))}</span>`
    + `<input class="ml-input" type="time" name="workingHoursStart" data-ml-working-start></label>`
    + `<label class="ml-field"><span class="ml-field-label">${e(t("mail.workingHoursEnd", lang))}</span>`
    + `<input class="ml-input" type="time" name="workingHoursEnd" data-ml-working-end></label>`
    + `<p class="ml-help">${e(t("mail.workingHoursHelp", lang))}</p>`
    + `<div class="ml-field">`
    + `<label class="ml-switch"><input type="checkbox" name="cloudDrafting" data-ml-cloud-drafting> ${e(t("mail.cloudDrafting", lang))}</label>`
    + `<p class="ml-help">${e(t("mail.cloudDraftingHelp", lang))}</p>`
    + "</div>"
    + `<div class="ml-actions">`
    + `<button class="ml-btn ml-btn--primary" type="button" data-ml-settings-save>${e(t("common.save", lang))}</button>`
    + "</div>"
    + "</section>";
}

/**
 * The test-message control (plan 5's C21), which is optional and runs only at a person's tap: it is a
 * button and a hidden line, never a request from this page, and its two result sentences travel as
 * data attributes so the client script has no text of its own.
 */
function selftestHtml(accountId, lang) {
  return `<div class="ml-actions">`
    + `<button class="ml-btn" type="button" data-ml-selftest data-account="${e(accountId)}"`
    + ` data-ml-selftest-sent="${e(t("mail.wizard.selftestSent", lang))}"`
    + ` data-ml-selftest-failed="${e(t("mail.wizard.selftestFailed", lang))}">${e(t("mail.wizard.selftest", lang))}</button>`
    + "</div>";
}

/** One account's card: its label, address, status and every control the owner may use on it. */
function accountCard(account, { senders = [], lang, tz }) {
  const id = String(account?.id ?? "");
  const label = labelOf(account, lang);
  const typedLabel = typedLabelOf(account);
  const address = typeof account?.address === "string" ? account.address : "";
  const checked = account?.localModelsOnly ? " checked" : "";
  const isOauth = account?.authKind === "xoauth2";
  const update = account?.status === "auth_failed" && !isOauth ? updatePasswordHtml(id, lang) : "";
  // A grant Google will end (the reconnect watch's predicate) or a sign-in that already stopped: both
  // are fixed by the same one-tap sign-in, so both draw the same control — and only when the account
  // names a provider that sign-in can be started for.
  const canReconnect = isOauth && typeof account?.oauthProvider === "string" && account.oauthProvider !== "";
  const reconnect = canReconnect && (account?.reconnectDue === true || account?.status === "auth_failed")
    ? reconnectHtml(account, lang)
    : "";
  return `<section class="ml-card" data-ml-account="${e(id)}">
      <h2 class="ml-card-title">${e(label)}</h2>
      <p class="ml-note ml-address">${e(address)}</p>
      ${statusHtml(account, lang)}
      ${reconnect}
      ${lastSyncHtml(account?.lastSyncAt, { lang, tz })}
      <label class="ml-field"><span class="ml-field-label">${e(t("mail.fieldLabel", lang))}</span>
        <input class="ml-input" type="text" name="label" data-ml-rename data-account="${e(id)}" value="${e(typedLabel)}"></label>
      <div class="ml-actions">
        <button class="ml-btn" type="button" data-ml-sync data-account="${e(id)}">${e(t("mail.syncNow", lang))}</button>
      </div>
      <div class="ml-field">
        <label class="ml-switch"><input type="checkbox" name="localModelsOnly" data-ml-local-models data-account="${e(id)}"${checked}> ${e(t("mail.localModelsOnly", lang))}</label>
        <p class="ml-help">${e(t("mail.localModelsOnlyHelp", lang))}</p>
      </div>
      ${sentCopyHtml(account, lang)}
      ${selftestHtml(id, lang)}
      ${update}
      ${allowListHtml(id, senders, lang)}
      ${removeAccountHtml(id, lang)}
    </section>`;
}

/**
 * The generic add-account form, kept for every provider the wizard cards do not cover (plan 5): the
 * smallest set a password account needs, with `ssl` and `starttls` only.
 *
 * The form is a set of fields for the client script, which cancels the submit and posts them to the
 * mail API's accounts route itself (that route is hardcoded in the script, not read from this markup,
 * so the markup names no target). It carries no `action` and names `method="post"`: without the
 * client handler a native submit would otherwise be a GET that puts the password in the URL.
 *
 * @param {string} [lang]
 * @returns {string}
 */
export function addAccountForm(lang = "en") {
  const text = (name, label, extra = "", type = "text") => `<label class="ml-field"><span class="ml-field-label">${e(label)}</span>`
    + `<input class="ml-input" type="${type}" name="${name}"${extra}></label>`;
  const security = (name) => `<label class="ml-field"><span class="ml-field-label">${e(t("mail.fieldSecurity", lang))}</span>`
    + `<select class="ml-input" name="${name}"><option value="ssl">ssl</option><option value="starttls">starttls</option></select></label>`;
  return `<form class="ml-add" data-ml-add-account method="post">
      <h2 class="ml-card-title">${e(t("mail.addAccount", lang))}</h2>
      ${text("label", t("mail.fieldLabel", lang))}
      ${text("address", t("mail.fieldAddress", lang), ' autocomplete="email"', "email")}
      <label class="ml-field"><span class="ml-field-label">${e(t("mail.fieldPassword", lang))}</span>
        <input class="ml-input" type="password" name="password" autocomplete="new-password"></label>
      ${text("imap-host", t("mail.fieldImapHost", lang))}
      ${text("imap-port", t("mail.fieldImapPort", lang), ' inputmode="numeric"')}
      ${security("imap-security")}
      ${text("smtp-host", t("mail.fieldSmtpHost", lang))}
      ${text("smtp-port", t("mail.fieldSmtpPort", lang), ' inputmode="numeric"')}
      ${security("smtp-security")}
      <button class="ml-btn ml-btn--primary" type="submit">${e(t("mail.addAccount", lang))}</button>
    </form>`;
}

/**
 * The add-account area: the Gmail card, the Microsoft card, then the generic form.
 *
 * @param {string} [lang]
 * @param {string|null} [redirectUri] this instance's callback address, or null when it has none
 * @returns {string}
 */
export function addAccountArea(lang = "en", redirectUri = null) {
  return wizardsHtml({ lang, redirectUri }) + addAccountForm(lang);
}

/**
 * The settings view: the "Mail is set up on <instance>" lines for mail another live instance holds,
 * one card per account (any status — an account held elsewhere still needs its remove control), the
 * owner-wide mail settings, and the add-account area, which stays available even when every account is
 * held elsewhere: only the same address is refused, by the connect route itself.
 *
 * `redirectUri` is the address the sign-in wizards must show. Left out, it is computed from this
 * process's own environment with `dashboardRedirectUri` — the same answer the redirect-uri route
 * gives; a caller that knows the request (the panel, which also knows whether it arrived through
 * Funnel) passes it in. `mailStatus` is the callback's fixed key from `?mailStatus=`.
 *
 * @param {{
 *   accounts?: object[], elsewhere?: {instanceName?: string}[], allow?: Record<string, string[]>,
 *   lang?: string, tz?: string, redirectUri?: string|null, mailStatus?: string
 * }} [options]
 * @returns {string}
 */
export function settingsHtml({
  accounts = [],
  elsewhere = [],
  allow = {},
  lang = "en",
  tz = undefined,
  redirectUri = undefined,
  mailStatus = "",
} = {}) {
  const held = (Array.isArray(elsewhere) ? elsewhere : []).map((entry) => {
    const name = typeof entry?.instanceName === "string" && entry.instanceName.trim() !== ""
      ? entry.instanceName.trim()
      : anotherCrow(lang);
    return `<p class="ml-note">${e(fill(t("mail.elsewhereOn", lang), { instance: name }))}</p>`;
  }).join("");
  const cards = (Array.isArray(accounts) ? accounts : [])
    .map((account) => accountCard(account, { senders: allow?.[account?.id] ?? [], lang, tz }))
    .join("");
  const uri = redirectUri === undefined ? dashboardRedirectUri(process.env).redirectUri : redirectUri;
  return `<div class="ml" data-ml>
    <div class="ml-page-head">
      <h1 class="ml-title">${e(t("mail.title", lang))}</h1>
      ${mailGearLink(lang)}
    </div>
    <div class="ml-settings" data-ml-settings>${held}${mailStatusHtml({ status: mailStatus, lang })}${mailSettingsHtml(lang)}${cards}${addAccountArea(lang, uri)}</div>
    ${mailWizardClientJs(lang)}
  </div>`;
}

export default settingsHtml;