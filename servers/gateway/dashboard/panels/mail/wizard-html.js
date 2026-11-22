/**
 * Crow Mail's Gmail and Microsoft setup cards (plan 5, Task 5): the markup the settings page draws
 * above its own generic add-account form, and the one place the approved copy of those cards lives.
 *
 * Every sentence on these cards is the operator-approved copy verbatim (C1-C26 and K3/K4 of the
 * approved file, and its third and fourth cards' N1-N6): the Gmail card offers TWO paths with the app
 * password first (C3-C8) and the bring-your-own-OAuth-client "Sign in with Google" path second
 * (C9-C13); the Microsoft card is one OAuth path (C14-C18), with the optional tenant field N4
 * approved and its own refusal N6. Nothing is
 * written here — a sentence that is not in that file is not drawn — and the two cards carry no host,
 * port or credential of their own: a password connection is made against the provider PRESET the
 * server applies (`servers/gateway/mail/providers/presets.js`), and the only address either card
 * shows is this instance's own redirect URI.
 *
 * The redirect URI is `dashboardRedirectUri`'s answer — the same function the
 * `GET /dashboard/mail/api/oauth/redirect-uri` route answers with — so what the page shows is exactly
 * what the provider must be told, and a page drawn before (or after) a change of the dashboard
 * address is corrected by the client, which reads that route on load. A `null` redirect URI (this
 * machine has no dashboard address, or the page was opened through Funnel) draws C19 and the app
 * password path alone: the OAuth paths are left out entirely, because a sign-in that cannot come back
 * is not offered.
 *
 * The client script (`wizard-client.js`) owns every action: nothing here is a request, an event
 * handler or a stored value. The sentences the client may have to show later (an app password the
 * provider refused, a redirect that no longer matches, a client id of the wrong shape, the
 * no-address line) travel as `data-ml-*` attributes on the card, so the script has no text of its
 * own; the tenant field's refusal (N6) is the one sentence DRAWN here, in that field's own line and
 * hidden, because it belongs to that field and not to the form's shared line. A check that PASSED
 * shows the tick glyph with the approved N1 sentence beside it, and the tick
 * stays hidden until the check passes, so neither is read before it is true.
 */
import { escapeHtml } from "../../shared/components.js";
import { t } from "../../shared/i18n.js";

const e = escapeHtml;

/** Where the dashboard address is set (C19's link). */
export const DASHBOARD_SETTINGS_HREF = "/dashboard/settings";

/** The one place an owner creates an app password (C5's link). */
export const APP_PASSWORDS_HREF = "https://myaccount.google.com/apppasswords";

/** The cards this module draws, and the OAuth provider each one signs in with. */
const CARDS = Object.freeze({
  gmail: { provider: "google", preset: "gmail", title: "mail.wizard.gmailTitle" },
  google: { provider: "google", preset: "gmail", title: "mail.wizard.gmailTitle" },
  microsoft: { provider: "microsoft", preset: "outlook", title: "mail.wizard.microsoftTitle" },
  outlook: { provider: "microsoft", preset: "outlook", title: "mail.wizard.microsoftTitle" },
});

/**
 * The status keys the settings page and the wizard can be handed, each with the approved sentence it
 * shows. `redirect_mismatch` and `client_id_shape` are the per-step check's hint keys
 * (`MAIL_OAUTH_HINT_KEYS`); the rest are the callback's own status keys
 * (`MAIL_OAUTH_STATUS_KEYS`) — `oauth_no_refresh` among them, in N3's sentence: a grant with no
 * refresh token that stored nothing. A key this page has no sentence for draws nothing at all rather
 * than an invented line.
 */
export const WIZARD_STATUS_KEYS = Object.freeze({
  oauth_connected: "mail.wizard.connected",
  oauth_denied: "mail.wizard.denied",
  oauth_expired: "mail.wizard.expired",
  oauth_no_refresh: "mail.wizard.noRefresh",
  oauth_probe_failed: "mail.wizard.probeFailed",
  oauth_failed: "mail.wizard.oauthFailed",
  redirect_mismatch: "mail.wizard.redirectMismatch",
  client_id_shape: "mail.wizard.clientIdShape",
});

/**
 * The sentence for one status key, or "" when the key names something this page has no approved
 * sentence for. The key must be one of the fixed strings above, so nothing a URL carries can be
 * echoed back.
 *
 * @param {{status?: string, lang?: string}} [options]
 * @returns {string}
 */
export function mailStatusSentence({ status = "", lang = "en" } = {}) {
  const key = typeof status === "string" ? WIZARD_STATUS_KEYS[status] : undefined;
  return key ? t(key, lang) : "";
}

/**
 * The page-level status line: the callback's (`mailStatus`) or a check's fixed key, in the approved
 * sentence for it, and nothing at all for a key this page does not know.
 *
 * @param {{status?: string, lang?: string}} [options]
 * @returns {string}
 */
export function mailStatusHtml({ status = "", lang = "en" } = {}) {
  const text = mailStatusSentence({ status, lang });
  if (text === "") return "";
  const safe = String(status);
  return `<p class="ml-note ml-wizard-status" role="status" data-ml-mail-status="${e(safe)}">${e(text)}</p>`;
}

/**
 * One step of a numbered list that has to show the redirect address and the control that copies it
 * (C11 step 5 and C16 step 2). The approved sentence carries the address as `{address}` and ends with
 * a bracketed "(Copy)"; that bracketed word is drawn as the Copy BUTTON rather than as text, so the
 * sentence reads exactly as approved and the control sits where the sentence says it is. A sentence
 * with no `{address}` still renders (the address follows its text) — nothing is dropped.
 *
 * @param {string} text the approved sentence, with `{address}` where the address belongs
 * @param {{uri: string, lang: string}} options
 */
function copyStepHtml(text, { uri, lang }) {
  const rendered = String(text);
  const match = /\(([^()]*)\)\s*$/.exec(rendered);
  const head = match ? rendered.slice(0, match.index) : rendered;
  const at = head.indexOf("{address}");
  const before = (at >= 0 ? head.slice(0, at) : head).replace(/\s+$/, "");
  const after = at >= 0 ? head.slice(at + "{address}".length).replace(/^\s+/, "") : "";
  const copyLabel = t("mail.wizard.copy", lang);
  return `<li class="ml-wizard-step" data-ml-copy-step>`
    + (before === "" ? "" : `<span class="ml-wizard-step-text">${e(before)}</span> `)
    + `<code class="ml-wizard-uri" data-ml-redirect-uri>${e(uri)}</code>`
    + (after === "" ? "" : ` <span class="ml-wizard-step-text">${e(after)}</span>`)
    + ` <button class="ml-btn ml-wizard-copy" type="button" data-ml-copy-redirect>${e(copyLabel)}</button>`
    // Its OWN tick, beside the control: the card's first tick belongs to a passed check, and a copy
    // is not one (plan 5's review nit — lighting that one read as "the connection succeeded"). The
    // glyph is painted by the stylesheet so the step's own text stays the approved sentence.
    + `<span class="ml-wizard-tick ml-copy-tick" data-ml-copy-tick aria-hidden="true" hidden></span>`
    // N2, "Copied.", right after the control and hidden until a copy really happened.
    + ` <span class="ml-note ml-copy-said" data-ml-copied role="status" hidden>${e(t("mail.wizard.copied", lang))}</span></li>`;
}

/** One numbered step, plain: the approved sentence as text. */
function stepHtml(text) {
  return `<li class="ml-wizard-step">${e(text)}</li>`;
}

/** A field the client reads by its `data-ml-*` hook; the label is an approved sentence. */
function fieldHtml({ hook, label, type = "text", name, autocomplete = "" }) {
  const extra = autocomplete ? ` autocomplete="${e(autocomplete)}"` : "";
  return `<label class="ml-field"><span class="ml-field-label">${e(label)}</span>`
    + `<input class="ml-input" type="${e(type)}" name="${e(name)}" data-ml-${e(hook)}${extra}></label>`;
}

/** The status line one path writes its own refusal into (never in the markup until it has one). */
function resultHtml(attribute = "data-ml-result") {
  return `<p class="ml-note ml-wizard-check" ${attribute} role="status" hidden></p>`;
}

/**
 * The tick a passed check shows: the glyph (hidden from assistive technology, which it is not a word
 * for) and, beside it, N1's approved sentence — both hidden until the check passes.
 *
 * @param {string} lang
 * @returns {string}
 */
function checkTickHtml(lang) {
  return `<span class="ml-wizard-tick" data-ml-check-tick role="status" hidden>`
    + `<span class="ml-tick-glyph" aria-hidden="true">\u2713</span>`
    + `<span class="ml-tick-said">${e(t("mail.wizard.checkPassed", lang))}</span></span>`;
}

/** The Gmail card's first path: Google's own app-password steps and the two fields (C3-C7). */
function appPasswordPathHtml(lang) {
  return `<div class="ml-wizard-path" data-ml-path="password">
      <h3 class="ml-card-subtitle">${e(t("mail.wizard.appPasswordTitle", lang))}</h3>
      <ol class="ml-wizard-steps">
        ${stepHtml(t("mail.wizard.appPasswordStep1", lang))}
        ${`<li class="ml-wizard-step">${e(t("mail.wizard.appPasswordStep2", lang))} `
          + `<a class="ml-wizard-link" href="${e(APP_PASSWORDS_HREF)}" rel="noopener noreferrer" target="_blank">${e(t("mail.wizard.appPasswordLink", lang))}</a></li>`}
        ${stepHtml(t("mail.wizard.appPasswordStep3", lang))}
      </ol>
      <form class="ml-wizard-form" method="post" data-ml-connect-password>
        ${fieldHtml({ hook: "address", label: t("mail.wizard.fieldGmailAddress", lang), type: "email", name: "address", autocomplete: "email" })}
        ${fieldHtml({ hook: "password", label: t("mail.wizard.fieldAppPassword", lang), type: "password", name: "password", autocomplete: "new-password" })}
        <button class="ml-btn ml-btn--primary" type="submit" data-ml-connect-password-btn>${e(t("mail.wizard.connect", lang))}</button>
        ${checkTickHtml(lang)}
        ${resultHtml()}
      </form>
    </div>`;
}

/** The Gmail card's second path: the owner's own Google Cloud project, screen by screen (C9-C13). */
function googlePathHtml({ lang, step, uri }) {
  return `<div class="ml-wizard-path" data-ml-path="google" data-ml-oauth-path>
      <h3 class="ml-card-subtitle">${e(t("mail.wizard.googleTitle", lang))}</h3>
      <p class="ml-note">${e(t("mail.wizard.googleIntro", lang))}</p>
      <ol class="ml-wizard-steps">
        ${stepHtml(t("mail.wizard.googleStep1", lang))}
        ${stepHtml(t("mail.wizard.googleStep2", lang))}
        ${stepHtml(t("mail.wizard.googleStep3", lang))}
        ${stepHtml(t("mail.wizard.googleStep4", lang))}
        ${copyStepHtml(t("mail.wizard.googleStep5", lang), { uri, lang })}
        ${stepHtml(t("mail.wizard.googleStep6", lang))}
      </ol>
      <form class="ml-wizard-form" method="post" data-ml-oauth data-ml-step="${e(step)}">
        ${fieldHtml({ hook: "address", label: t("mail.wizard.fieldGmailAddress", lang), type: "email", name: "address", autocomplete: "email" })}
        ${fieldHtml({ hook: "client-id", label: t("mail.wizard.fieldClientId", lang), name: "clientId", autocomplete: "off" })}
        ${fieldHtml({ hook: "client-secret", label: t("mail.wizard.fieldClientSecret", lang), type: "password", name: "clientSecret", autocomplete: "new-password" })}
        <button class="ml-btn ml-btn--primary" type="submit" data-ml-oauth-connect>${e(t("mail.wizard.connect", lang))}</button>
        ${checkTickHtml(lang)}
        ${resultHtml()}
      </form>
      <p class="ml-note">${e(t("mail.wizard.googleTestingNote", lang))}</p>
    </div>`;
}

/**
 * The Microsoft card's tenant field (N4), with its own refusal line (N6): the directory a work or
 * school account signs in against. Its label and hint are N4's approved rows, and the client script
 * owns the field's rule (`data-ml-tenant`) — an empty field sends no tenant, a GUID or a domain
 * travels, and anything else starts nothing and shows N6 in this field's own line (the server refuses
 * the same values with `400 bad_input`, which the client shows there too).
 *
 * @param {string} lang
 * @returns {string}
 */
function tenantFieldHtml(lang) {
  return fieldHtml({ hook: "tenant", label: t("mail.wizard.tenantLabel", lang), name: "tenant", autocomplete: "off" })
    + `<p class="ml-help" data-ml-tenant-hint>${e(t("mail.wizard.tenantHint", lang))}</p>`
    // N6, the field's own line: hidden until a value typed into the field (or the server's 400 for
    // one) is refused, and the only sentence a tenant refusal ever shows.
    + `<p class="ml-note ml-wizard-check" data-ml-tenant-invalid role="status" hidden>${e(t("mail.wizard.tenantInvalid", lang))}</p>`;
}

/** The Microsoft card's one path: an Entra app registration, screen by screen (C14-C18). */
function microsoftPathHtml({ lang, step, uri }) {
  return `<div class="ml-wizard-path" data-ml-path="microsoft" data-ml-oauth-path>
      <ol class="ml-wizard-steps">
        ${stepHtml(t("mail.wizard.microsoftStep1", lang))}
        ${copyStepHtml(t("mail.wizard.microsoftStep2", lang), { uri, lang })}
        ${stepHtml(t("mail.wizard.microsoftStep3", lang))}
      </ol>
      <form class="ml-wizard-form" method="post" data-ml-oauth data-ml-step="${e(step)}">
        ${fieldHtml({ hook: "address", label: t("mail.fieldAddress", lang), type: "email", name: "address", autocomplete: "email" })}
        <p class="ml-help">${e(t("mail.wizard.microsoftStep4", lang))}</p>
        ${fieldHtml({ hook: "client-id", label: t("mail.wizard.fieldClientId", lang), name: "clientId", autocomplete: "off" })}
        ${tenantFieldHtml(lang)}
        <button class="ml-btn ml-btn--primary" type="submit" data-ml-oauth-connect>${e(t("mail.wizard.connect", lang))}</button>
        ${checkTickHtml(lang)}
        ${resultHtml()}
      </form>
      <p class="ml-note">${e(t("mail.wizard.microsoftAdminNote", lang))}</p>
      <p class="ml-note">${e(t("mail.wizard.microsoftSendingNote", lang))}</p>
    </div>`;
}

/** C19: this machine has no dashboard address, so no sign-in can come back to it. */
function noAddressHtml(lang) {
  return `<div class="ml-wizard-path" data-ml-no-address>
      <p class="ml-note">${e(t("mail.wizard.noDashboardAddress", lang))}</p>
      <a class="ml-btn" href="${DASHBOARD_SETTINGS_HREF}" data-ml-open-setting>${e(t("mail.wizard.openSetting", lang))}</a>
    </div>`;
}

/**
 * One setup card.
 *
 * `presetId` names the card ("gmail" — "google" is accepted too — or "microsoft"/"outlook"); `step`
 * is which path of that card the client starts on (defaults to the card's first: the app password for
 * Gmail, the one sign-in path for Microsoft) and is what the card's `data-ml-step` says. `redirectUri`
 * is this instance's own callback address, or `null` when it has none — a null one draws C19 and no
 * OAuth path at all, leaving the app-password path usable.
 *
 * @param {{presetId?: string, step?: string, lang?: string, redirectUri?: string|null}} [options]
 * @returns {string}
 */
export function wizardHtml({ presetId = "gmail", step = null, lang = "en", redirectUri = null } = {}) {
  const card = CARDS[String(presetId).toLowerCase()];
  if (!card) return "";
  const isGmail = card.provider === "google";
  const firstStep = isGmail ? "password" : "microsoft";
  const chosen = typeof step === "string" && step !== "" ? step : firstStep;
  const uri = typeof redirectUri === "string" && redirectUri !== "" ? redirectUri : null;
  const name = isGmail ? "gmail" : "microsoft";
  // The sentences the client may need to show later, one attribute each, all of them approved copy.
  const hints = [
    ["connect-failed", t("mail.wizard.appPasswordFailed", lang)],
    ["hint-client_id_shape", t("mail.wizard.clientIdShape", lang)],
    ["hint-redirect_mismatch", t("mail.wizard.redirectMismatch", lang)],
    ["hint-no_dashboard_address", t("mail.wizard.noDashboardAddress", lang)],
    // The start route answered an authorization URL that is not the provider's own https page: the
    // approved copy's K3 sentence ("could not finish connecting this account").
    ["hint-flow_failed", t("mail.wizard.oauthFailed", lang)],
    ["selftest-sent", t("mail.wizard.selftestSent", lang)],
    ["selftest-failed", t("mail.wizard.selftestFailed", lang)],
  ].map(([key, value]) => ` data-ml-${key}="${e(value)}"`).join("");

  const paths = isGmail
    ? appPasswordPathHtml(lang) + (uri === null ? noAddressHtml(lang) : googlePathHtml({ lang, step: chosen, uri }))
    : (uri === null ? noAddressHtml(lang) : microsoftPathHtml({ lang, step: chosen, uri }));

  return `<section class="ml-card ml-wizard" data-ml-wizard="${e(name)}" data-ml-provider="${e(card.provider)}" data-ml-preset="${e(card.preset)}" data-ml-step="${e(chosen)}" data-ml-redirect="${e(uri ?? "")}"${hints}>
      <h2 class="ml-card-title">${e(t(card.title, lang))}</h2>
      <p class="ml-note">${e(t(isGmail ? "mail.wizard.gmailIntro" : "mail.wizard.microsoftIntro", lang))}</p>
      ${paths}
    </section>`;
}

/**
 * Both cards, in the order the settings page draws them: Gmail (whose app password is the shortest
 * way to a working mailbox) and then Microsoft. Each card carries this instance's redirect address
 * itself, so every card shows the same one value.
 *
 * @param {{lang?: string, redirectUri?: string|null}} [options]
 * @returns {string}
 */
export function wizardsHtml({ lang = "en", redirectUri = null } = {}) {
  const uri = typeof redirectUri === "string" && redirectUri !== "" ? redirectUri : null;
  return wizardHtml({ presetId: "gmail", lang, redirectUri: uri })
    + wizardHtml({ presetId: "microsoft", lang, redirectUri: uri });
}

export default wizardHtml;