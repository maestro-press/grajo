/**
 * The words a report puts in front of a reader, in one place: every string Crow writes into a report
 * email, into an owner notice about a run, and onto the run view page a dashboard link opens.
 *
 * Every string is a named constant here (or a small pure function of one value), so a person can read all
 * of them at once and no route, layout or delivery path invents its own wording. Plain words only: no
 * dash, no emoji, no markup. The one string this module does not own is the empty run's line, which
 * document.js already writes into the document; it is re-exported rather than copied, so the two cannot
 * drift apart.
 *
 * What is NOT here: the report's own title (the email's subject, read from the report row) and the
 * link (made by Crow for this recipient, never neutralised).
 */

/** The body of a run that found nothing: document.js's own line, re-exported, never re-typed. */
export { DEFAULT_EMPTY_TEXT as EMPTY_LINE } from "../document.js";

/** The footer's first words, immediately followed by the report's link and nothing else. */
export const OPEN_REPORT_PREFIX = "Open this report: ";

/** Tier a: the report's own page takes comments, so the reader is told where. */
export const COMMENT_THERE_LINE = "You can comment there.";

/** Tier b: the reader has no page to comment on, so answering the email is how they comment. */
export const REPLY_TO_COMMENT_LINE = "Reply to this email to comment.";

/** An email_link run that finished: the email carries this line and the link, no report content. */
export const LINK_MODE_OK_LINE = "A new run of this report is ready.";

/** A failed run whose recorded error text is empty: the email still says the run did not finish. */
export const RUN_FAILED_FALLBACK_LINE = "This run did not finish.";

/** The subject of a report whose title is empty after trimming. */
export const FALLBACK_SUBJECT = "This report";

/**
 * What a web address a report may not carry becomes in an outgoing report email: the whole address, host
 * and all, is replaced by these words. No host is named, and the words are the one replacement both halves
 * of the mail use (sanitize-outgoing.js owns the rule).
 */
export const EMAIL_LINK_REMOVED = "[link removed]";

/* ------------------------------------------------------------------- owner notices */

/**
 * The owner's notices for one run, one function per thing that happened. Each takes the report's title
 * as delivery.js has already cleaned it (whitespace collapsed, control characters gone, 80 characters at
 * most), so the sentence reads as the report's own. Nothing here is a sentence about a person: a notice
 * says what this run did.
 */

/** A run that failed: the owner hears about it whatever their notification type settings say. */
export function runFailedNotice(title) {
  return `${title}: this run failed`;
}

/** A run that found nothing: still an honest run, and still the owner's to hear. */
export function runEmptyNotice(title) {
  return `${title}: nothing new this time`;
}

/** A run that finished: written only when the report's notify-every-run switch is on. */
export function runReadyNotice(title) {
  return `${title} is ready`;
}

/** A run some of whose emails did not go out: the body carries the counts. */
export function emailsNotSentNotice(title) {
  return `${title}: some emails were not sent`;
}

/**
 * A recipient this run could not mail because there was no link to put in it (no link kind yet, or a
 * relative path because the instance does not know its own address): the owner has to hear this,
 * because nothing was attempted and no send row was written. The words are the counts notice's own
 * ("were not sent"), said differently, because the two notices are told apart by their titles.
 */
export function emailsSkippedNotice(title) {
  return `${title}: some emails could not be sent, no link`;
}

/** The body of that notice: the one thing about it the owner can act on. */
export const EMAILS_SKIPPED_BODY =
  "A recipient has no way to open the report. Check the gateway address setting.";

/* ------------------------------------------------------------------ the run view */

/**
 * The run view page (`/dashboard/project/<slug>/reports/<id>/runs/<runId>`): the page a dashboard link
 * in a report email opens. Plain lines only, because every value shown beside them is the report's own.
 */

/** The page title when the slug, the report or the run on the path is not this instance's. */
export const RUN_VIEW_MISSING_TITLE = "Run not found";

/** The sentence that page shows instead of the run. */
export const RUN_VIEW_MISSING_LINE = "This report run is not here.";

/** The heading above the list of the run's own links. */
export const LINKS_IN_RUN_HEADING = "Links in this run";

/** Shown in place of the document when the run's version cannot be read. */
export const VERSION_NOT_AVAILABLE_LINE = "This version is not available.";

/** The frame's own title, for a reader who cannot see it. */
export const RUN_FRAME_TITLE = "Report version";

/** The way back to the project the report belongs to. */
export const BACK_TO_PROJECT_LINE = "Back to the project";

/** The line above the document: which version of the report this page shows. */
export function versionLine(n) {
  return `Version ${n}`;
}

/** The line that closes a link list that was cut at the frame's own cap. */
export function moreLinksLine(n) {
  return `and ${n} more`;
}

/** One plain line per run status the run engine writes. */
export const RUN_STATUS_LINES = Object.freeze({
  ok: "This run is ok",
  empty: "This run is empty",
  failed: "This run failed",
  running: "This run is running",
  queued: "This run is queued",
});

/** A status word this module does not know: the page still says what it can. */
export const RUN_STATUS_OTHER_LINE = "This run has no recorded status";

/** The status line for one run: the plain sentence for a known status, else the fallback line. */
export function runStatusLine(status) {
  const word = typeof status === "string" ? status.trim() : "";
  return Object.prototype.hasOwnProperty.call(RUN_STATUS_LINES, word)
    ? RUN_STATUS_LINES[word]
    : RUN_STATUS_OTHER_LINE;
}