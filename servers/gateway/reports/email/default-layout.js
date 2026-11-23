/**
 * The email one run sends: its subject, its html and its text.
 *
 * WHAT THE BODY IS depends on the delivery mode the report was approved with:
 *   - `email_full` and `both` carry the run's document. Its markdown is rendered by the blog renderer
 *     (`renderMarkdown`) and the rendered html is then judged by `sanitizeOutgoing` against the run's own
 *     allowed URLs, so a URL a model wrote (or a table cell whose value is a whole URL the run's items do
 *     not carry) is replaced by `[link removed]` in the email, and a report email reads as the report
 *     does. The TEXT half is the document's own plain text (the markdown as the assembly wrote it), which
 *     is judged as it is sent: the characters nobody sees stripped, then every refused `http(s)://` or
 *     `www.` run replaced by `[link removed]`. That half is judged on its FINAL text, because it is what a
 *     mail client autolinks, and nothing there is decoded or joined. No footer line is ever judged,
 *     because the footer is Crow's own and goes on after;
 *   - `email_link` carries no report content at all: the reader gets the honest line and the link.
 * The honest line is the failure's own error text (the run engine stored it redacted; it is collapsed to
 * one line and bounded to 500 characters, and the fallback line is used when it is empty), the document's
 * empty line for a run that found nothing, or the "a new run is ready" line for a finished one. A run the
 * engine marked LATE starts with the late line, unless the document the assembly wrote already starts
 * with it.
 *
 * A CUSTOM STEP'S OWN EMAIL (`override`) replaces the document body, not the footer: it is sanitised and
 * judged the same way any outgoing body is, and an override that is empty on both halves falls back to
 * the default body, so an empty template can never empty the email. A FAILED run's body is the honest
 * line and nothing else, so neither the override nor the document replaces it there.
 *
 * THE FOOTER IS ADDED AFTER SANITISING and is never removable: "Open this report: <link>", on its own
 * line, then the one comment line the recipient's tier earns. The link is Crow's own, made for this one
 * recipient, so it is written into the footer directly and is not run through the link judge. That is
 * also why the body is sanitised before the footer goes on: nothing in the body can rewrite, drop or
 * imitate the footer, and the footer is the last thing in both the html and the text.
 *
 * A FAILED RUN MAY CARRY NO LINK AT ALL. A run that did not finish writes no version, so a reader whose
 * page would be a public one has nothing to open: the failed-run mail is the honest line and nothing else,
 * and it is built with no footer rather than a link that goes nowhere. Nothing else may be linkless: any
 * other run without a link is a caller mistake and stays `bad_input`.
 *
 * The subject is the report's title with its control characters removed, its whitespace collapsed and its
 * length bounded; a title with nothing usable in it becomes the fallback subject. A title is never put
 * into the html body, so markup in it cannot reach the email at all.
 */
import { renderMarkdown } from "../../../blog/renderer.js";
import { redactSecrets } from "../../../shared/redact-secrets.js";
import { getSecretValues } from "../../../shared/secret-values.js";
import { LATE_LINE } from "../document.js";
import {
  COMMENT_THERE_LINE,
  EMAIL_LINK_REMOVED,
  EMPTY_LINE,
  FALLBACK_SUBJECT,
  LINK_MODE_OK_LINE,
  OPEN_REPORT_PREFIX,
  REPLY_TO_COMMENT_LINE,
  RUN_FAILED_FALLBACK_LINE,
} from "./copy.js";
import { neutralizeTextRuns, sanitizeOutgoing } from "./sanitize-outgoing.js";

/**
 * The one text a refused link leaves in a mail (copy.js). The judging itself lives in sanitize-outgoing.js,
 * and this module names the constant so both halves of one mail are read from the one place; it is
 * exported so a test can name the wording without a second literal in the tree.
 */
export { EMAIL_LINK_REMOVED };

/** The delivery modes this layout builds a body for. `crow_only` never reaches it. */
export const LAYOUT_DELIVERY_MODES = Object.freeze(["email_full", "email_link", "both"]);

/** The longest subject this layout writes. */
export const SUBJECT_MAX = 150;

/** The longest failure text this layout puts in a body. */
export const RUN_ERROR_MAX = 500;

/** Control characters, with `\n` and `\t` kept (whitespace is collapsed where a line is wanted). */
const CONTROL = /[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f-\u009f]/g;

function fail(code, message) {
  const err = new Error(message || code);
  err.code = code;
  return err;
}

/** Text for display: the characters that would otherwise start markup or end an attribute. */
function escapeHtml(value) {
  return String(value == null ? "" : value)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

/** The same text with its control characters dropped, `\n` and `\t` kept. */
function stripControl(value) {
  return String(value == null ? "" : value).replace(CONTROL, "");
}

/** One line: control characters dropped and every run of whitespace made one space. */
function oneLine(value) {
  return stripControl(value).replace(/\s+/g, " ").trim();
}

/** At most `max` characters, never through a surrogate pair (a lone half is not a character). */
function bound(value, max) {
  const text = String(value);
  if (text.length <= max) return text;
  let end = max;
  const code = text.charCodeAt(end - 1);
  if (code >= 0xd800 && code <= 0xdbff) end -= 1;
  return text.slice(0, end);
}

/** The report's title as a subject line, or the fallback when nothing usable is left. */
function subjectOf(report) {
  const title = oneLine(report != null && report.title != null ? report.title : "");
  return bound(title, SUBJECT_MAX).trim() || FALLBACK_SUBJECT;
}

/** The instance's secret values, for the belt-and-braces redaction of a failure's text. */
function secretsOf() {
  try {
    const values = getSecretValues();
    return Array.isArray(values) ? values : [];
  } catch {
    return [];
  }
}

/**
 * A failed run's honest line: the error text the run engine recorded, redacted here as well (it is
 * stored redacted; this pass costs nothing and keeps a secret from a caller-built run row out of a mail),
 * collapsed to one line and bounded. The row arrives camelCase (`errorText`); a stored row's
 * `error_text` is read too.
 */
function errorLine(run) {
  const raw = oneLine(run == null ? "" : (run.errorText ?? run.error_text));
  const line = bound(redactSecrets(raw, secretsOf()), RUN_ERROR_MAX).trim();
  return line || RUN_FAILED_FALLBACK_LINE;
}

/** The one line a body carries when it carries no document. */
function honestLine(status, run) {
  if (status === "failed") return errorLine(run);
  if (status === "empty") return EMPTY_LINE;
  return LINK_MODE_OK_LINE;
}

/** Is this the run the engine marked late? The row stores 1, a mapped row either. */
function isLate(run) {
  return run != null && (run.late === true || Number(run.late) === 1);
}

/** The document's markdown, or "" when the run left no document. */
function markdownOf(document) {
  return document != null && typeof document === "object" && typeof document.markdown === "string"
    ? document.markdown
    : "";
}

/** The custom step's own body, sanitised, or null when it carries nothing at all. */
function overrideBody(override, allowedLinks) {
  if (override == null || typeof override !== "object") return null;
  const body = sanitizeOutgoing(override, allowedLinks);
  return body.html || body.text ? body : null;
}

/** The one comment line this recipient's tier earns, or "". */
function commentLine(tier) {
  if (tier === "a") return COMMENT_THERE_LINE;
  if (tier === "b") return REPLY_TO_COMMENT_LINE;
  return "";
}

/** The footer's html: the link, then the tier's line, each on its own paragraph. */
function footerHtml(link, tier) {
  const href = escapeHtml(link);
  const lines = [`<p>${OPEN_REPORT_PREFIX}<a href="${href}">${href}</a></p>`];
  const comment = commentLine(tier);
  if (comment) lines.push(`<p>${escapeHtml(comment)}</p>`);
  return lines.join("\n");
}

/** The footer's text: the same words, the link bare. */
function footerText(link, tier) {
  const lines = [OPEN_REPORT_PREFIX + link];
  const comment = commentLine(tier);
  if (comment) lines.push(comment);
  return lines.join("\n");
}

/**
 * Build one report email.
 *
 * @param {object} input
 * @param {{title?: string}|null} [input.report] the report row (its title is the subject)
 * @param {{status?: string, late?: boolean|number, errorText?: string}|null} [input.run] the run row
 * @param {{markdown?: string, title?: string}|null} [input.document] the run's document, or null
 * @param {string} input.link the recipient's link (required, except for a failed run, which has no version
 *   to point at and is mailed without a footer)
 * @param {"email_full"|"email_link"|"both"} input.deliveryMode the report's approved delivery mode
 * @param {"a"|"b"|"c"|null} [input.tier] the recipient's tier, which picks the footer's comment line
 * @param {string[]|Set<string>} [input.allowedLinks] the URLs the run's own items carry
 * @param {{html?: string, text?: string}|null} [input.override] a custom step's own email body
 * @returns {{subject: string, html: string, text: string}}
 * @throws {Error} `bad_input` when the link is empty (on a run that did not fail) or the delivery mode is
 *   not one this layout builds
 */
export function defaultLayout(input) {
  const given = input != null && typeof input === "object" ? input : {};
  const { report = null, run = null, document = null, link = "", deliveryMode, tier = null, allowedLinks = [], override = null } = given;
  const status = run != null && typeof run.status === "string" ? run.status : "";
  const url = typeof link === "string" ? link.trim() : "";
  // A failed run's body is the honest line and nothing else, so it is also the one mail that can be built
  // with no link: the run wrote no version, and a link to nothing is worse than none.
  if (!url && status !== "failed") throw fail("bad_input", "defaultLayout: the link is required");
  if (!LAYOUT_DELIVERY_MODES.includes(deliveryMode)) {
    throw fail("bad_input", `defaultLayout: ${String(deliveryMode)} is not a delivery mode this layout builds`);
  }
  const subject = subjectOf(report);
  const markdown = markdownOf(document);
  const withDocument = deliveryMode === "email_full" || deliveryMode === "both";
  // A failed run's body is the honest line and nothing else: a half report is worse than no report, and
  // a custom template must not replace the sentence that says the run did not finish.
  const failed = status === "failed";
  const custom = withDocument && !failed ? overrideBody(override, allowedLinks) : null;

  let body;
  if (custom) {
    body = custom;
  } else if (withDocument && markdown && !failed) {
    // The document's html is rendered and then judged: the email's html is the report as a reader sees it,
    // with every address the run's items do not carry replaced by the one refusal text. Its text half is
    // the document's own plain text, judged as it is sent further down.
    body = {
      html: sanitizeOutgoing({ html: renderMarkdown(markdown) }, allowedLinks).html,
      text: markdown,
    };
  } else {
    // email_link, a run with no document, or a failed or empty run: the honest line and nothing else.
    const line = honestLine(status, run);
    body = sanitizeOutgoing({ html: `<p>${escapeHtml(line)}</p>`, text: line }, allowedLinks);
  }

  let bodyHtml = body.html;
  let bodyText = body.text;
  // The late line comes first, unless the document the assembly wrote already starts with it (and it is
  // the document this body carries: a custom template replaces it, so the line is put back).
  const documentIsLate = markdown.trimStart().startsWith(LATE_LINE);
  if (isLate(run) && !(documentIsLate && !custom)) {
    bodyHtml = `<p>${escapeHtml(LATE_LINE)}</p>` + (bodyHtml ? `\n${bodyHtml}` : "");
    bodyText = bodyText ? `${LATE_LINE}\n\n${bodyText}` : LATE_LINE;
  }

  // The FINAL plain-text body is judged exactly as a plain-text client receives it (after the late line,
  // before the footer): the characters nobody sees stripped, then every refused run replaced. Whatever the
  // body half was, its text goes through the one rule; the footer lines below are Crow's own and are never
  // judged.
  bodyText = neutralizeTextRuns(bodyText, allowedLinks);
  // The footer goes on after the body is sanitised, so nothing in the body can drop it or pass for it.
  // A linkless failed-run mail has no footer at all: no link line, and no comment line pointing at a page
  // that does not exist.
  const footer = url
    ? { html: footerHtml(url, tier), text: footerText(url, tier) }
    : { html: "", text: "" };
  return {
    subject,
    html: footer.html ? (bodyHtml ? `${bodyHtml}\n${footer.html}` : footer.html) : bodyHtml,
    text: footer.text ? (bodyText ? `${bodyText}\n\n${footer.text}` : footer.text) : bodyText,
  };
}