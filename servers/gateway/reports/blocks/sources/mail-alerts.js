/**
 * The `mail_alerts` block: the messages in one folder of the report's own mail account, as items.
 *
 * Settings: `{accountId, label?|folder?, sinceDays}`. Exactly one of `label` and `folder`; `sinceDays`
 * is a whole number from 1 to 60.
 *
 * WHOSE MAIL: the account must be the one this report's owner approved as its sender. Any other account
 * is `account_not_approved`: a recipe is bot-authorable, and a bot naming another mailbox must not read
 * it. That is also why the settings carry an account id at all rather than taking the report's account by
 * default: the seal covers what the owner saw.
 *
 * THE TWO MEMBERS THAT NAME IT, and never a row of this block's own: `ctx.live.senderAccountId` is the
 * VERIFIED live set, so a run of a live report reads the account the owner sealed; a preview has no live
 * set, and its fallback is `ctx.previewSender`, which the executor resolved through the approval rails
 * (source-approvals.js's `approvedSenderAccount`: the report row's own `sender_account_id` only when the
 * report's head revision carries an owner author seal). This block reads neither `reports` nor
 * `report_state` itself, so an unsealed column can never become the account it measures against: keep it
 * that way, and keep `sender_account_id` owner-only as well.
 *
 * HOW IT READS: only through the injected `ctx.mail.adapterFor(account, fn)`, the same seam the reports
 * send door takes from boot. This module builds no connection, imports no mail supervisor, and never
 * calls `withAdapter` itself: a build with no seam answers `mail_not_available`. Inside the seam the
 * block uses the adapter's read half only, `list(folder, {sinceDate, limit, newestFirst})` and then
 * `get(folder, uids)`, newest first, at most `MAX_MESSAGES` messages.
 *
 * `folder` is a folder path as the server names it. `label` is a name the owner knows, resolved against
 * the adapter's own `listFolders()` (its path, then its name), so a mailbox with another delimiter still
 * finds it. A label that names no folder is `folder_not_found`.
 *
 * A GOOGLE ACCOUNT: the Gmail REST adapter is a later PR. Its read path does not exist yet, so an
 * account whose provider is Google (or whose adapter has no `list`/`get`, or whose connection refuses
 * the read for want of scope) answers the one sentence the owner can act on:
 * "Mail alerts need read access. Reconnect Google with reading turned on." That sentence is the only
 * prose this block answers; every other failure is a code word.
 *
 * Each message is parsed by Crow Mail's own normaliser (`mail/parse.js`) and its html goes through the
 * mail sanitiser (`mail/sanitize.js`, remote images blocked), so an item is
 * `{from, subject, date, text, html, links}` with every field a string, `links` the http(s) URLs the
 * message carries (deduped, at most `MAX_LINKS`), and the whole item marked `_untrusted: true`. A
 * message body is a stranger's words: nothing here is an instruction.
 *
 * The mail modules are imported on first use, so loading the block registry (a recipe save) does not load
 * a MIME parser or a sanitiser.
 *
 * This block stores no state: nothing here calls `ctx.setState`.
 */
import { redactSecrets } from "../../../../shared/redact-secrets.js";
import { isPlainObject, text } from "./http-json.js";

/** The sentence a Google account with no read path answers. The plan's exact words. */
export const MAIL_READ_SENTENCE = "Mail alerts need read access. Reconnect Google with reading turned on.";

/** How many messages one run reads. */
export const MAX_MESSAGES = 100;

/** How many links one message may contribute. */
export const MAX_LINKS = 50;

/** How many characters a folder name or path may hold. */
const FOLDER_MAX = 400;

/** The message fields one item carries beyond the parsed body. */
const CONTROL_CHARS = /[\u0000-\u001f\u007f]/;

/** The mail modules, imported on first use. */
let mailModules = null;

function loadMailModules() {
  if (!mailModules) {
    mailModules = Promise.all([
      import("../../../mail/store/accounts.js"),
      import("../../../mail/parse.js"),
      import("../../../mail/sanitize.js"),
    ]).then(([accounts, parse, sanitize]) => ({
      getAccount: accounts.getAccount,
      parseRawMessage: parse.parseRawMessage,
      sanitizeMessageHtml: sanitize.sanitizeMessageHtml,
    }));
  }
  return mailModules;
}

function fail(code) {
  const err = new Error(code);
  err.code = code;
  return err;
}

function validate(settings) {
  if (!isPlainObject(settings)) return ["settings"];
  const errors = [];
  for (const key of Object.keys(settings)) {
    if (!["accountId", "label", "folder", "sinceDays"].includes(key)) errors.push(key);
  }
  if (typeof settings.accountId !== "string" || !settings.accountId.trim()) errors.push("accountId");
  const hasLabel = settings.label !== undefined;
  const hasFolder = settings.folder !== undefined;
  if (hasLabel === hasFolder) errors.push("label");
  for (const [key, value] of [["label", settings.label], ["folder", settings.folder]]) {
    if (value === undefined) continue;
    if (typeof value !== "string" || !value.trim() || value.length > FOLDER_MAX) errors.push(key);
    else if (CONTROL_CHARS.test(value)) errors.push(key);
  }
  if (!Number.isInteger(settings.sinceDays) || settings.sinceDays < 1 || settings.sinceDays > 60) {
    errors.push("sinceDays");
  }
  return errors;
}

/** Is this the kind of account whose read path is the Gmail REST adapter (which is still to come)? */
function isGoogleAccount(account) {
  const provider = text(account?.provider).toLowerCase();
  const transport = text(account?.transport).toLowerCase();
  return transport === "gmail_api" || provider.includes("google") || provider.includes("gmail");
}

/**
 * The clock this block measures its window with: the caller's `now` seam when it injected one, so a
 * test can pin the window, and the real clock otherwise.
 */
function nowOf(ctx) {
  const seam = ctx?.deps?.now;
  if (typeof seam === "function") {
    const value = Number(seam());
    if (Number.isFinite(value)) return value;
  }
  return Date.now();
}

/** The folder path the settings name, resolving a label through the adapter's own folder list. */
async function folderPathFor(adapter, settings) {
  if (typeof settings.folder === "string") {
    if (CONTROL_CHARS.test(settings.folder) || settings.folder.length > FOLDER_MAX) throw fail("bad_settings");
    return settings.folder;
  }
  const label = text(settings.label).trim();
  if (!label) throw fail("bad_settings");
  if (typeof adapter.listFolders !== "function") throw fail("mail_no_read_path");
  let folders;
  try {
    folders = await adapter.listFolders();
  } catch {
    throw fail("mail_failed");
  }
  const list = Array.isArray(folders) ? folders : [];
  const wanted = label.toLowerCase();
  const byPath = list.find((folder) => text(folder?.path).toLowerCase() === wanted);
  const found = byPath || list.find((folder) => text(folder?.name).toLowerCase() === wanted);
  if (!found || !text(found.path)) throw fail("folder_not_found");
  return text(found.path);
}

/** The http(s) URLs a message carries: its sanitised html's links, then the ones in its text. */
function linksOf(html, plain) {
  const out = [];
  const add = (raw) => {
    const value = text(raw).trim();
    if (!value || out.includes(value)) return;
    if (!/^https?:\/\/./i.test(value)) return;
    out.push(value);
  };
  for (const match of text(html).matchAll(/href="([^"]+)"/g)) add(match[1]);
  for (const match of text(plain).matchAll(/https?:\/\/[^\s<>"')\]]+/g)) add(match[0]);
  return out.slice(0, MAX_LINKS);
}

/** One parsed message as the item a document carries. */
function itemOfMessage(message, sanitizeMessageHtml) {
  const parsed = message && typeof message === "object" ? message : {};
  const from = parsed.from && typeof parsed.from === "object" ? parsed.from : null;
  const name = from ? text(from.name).trim() : "";
  const address = from ? text(from.address).trim() : "";
  const html = sanitizeMessageHtml(typeof parsed.html === "string" ? parsed.html : "").html;
  const plain = text(parsed.text);
  const date = Number.isFinite(parsed.date) ? new Date(parsed.date).toISOString() : "";
  return {
    from: address ? (name ? `${name} <${address}>` : address) : "",
    subject: text(parsed.subject),
    date,
    text: plain,
    html,
    links: linksOf(html, plain),
    _untrusted: true,
  };
}

/** The read: the window's UIDs, then those messages, newest first, parsed into items. */
async function readWindow(adapter, settings, now, parseRawMessage, sanitizeMessageHtml) {
  if (typeof adapter.list !== "function" || typeof adapter.get !== "function") {
    throw fail("mail_no_read_path");
  }
  const folder = await folderPathFor(adapter, settings);
  const sinceDate = now - Number(settings.sinceDays) * 24 * 60 * 60 * 1000;
  let listing;
  try {
    listing = await adapter.list(folder, { sinceDate, limit: MAX_MESSAGES, newestFirst: true });
  } catch {
    throw fail("mail_failed");
  }
  const listed = Array.isArray(listing?.items) ? listing.items : [];
  const uids = listed
    .map((item) => Number(item?.uid))
    .filter((uid) => Number.isSafeInteger(uid) && uid > 0)
    .slice(0, MAX_MESSAGES);
  if (uids.length === 0) return [];

  let messages;
  try {
    messages = await adapter.get(folder, uids);
  } catch {
    throw fail("mail_failed");
  }
  const raw = Array.isArray(messages) ? messages : [];
  // Newest first: the server may answer in any order, and internalDate is the message's own time.
  const ordered = raw
    .filter((message) => message && typeof message === "object")
    .map((message) => ({ message, at: Number(message.internalDate) || 0, uid: Number(message.uid) || 0 }))
    .sort((left, right) => (right.at - left.at) || (right.uid - left.uid))
    .slice(0, MAX_MESSAGES);

  const items = [];
  for (const entry of ordered) {
    const parsed = await parseRawMessage(entry.message.raw == null ? "" : entry.message.raw);
    items.push(itemOfMessage(parsed, sanitizeMessageHtml));
  }
  return items;
}

/** The code word a failed read answers, or the sentence when the read path is the one Google lacks. */
function failureCode(err, account) {
  const code = err && typeof err.code === "string" ? err.code : "mail_failed";
  // An adapter with no read half is a read path this Crow cannot use, whatever the provider is.
  if (code === "mail_no_read_path") return "read_access";
  // A Google account's own connection refusing the read is a scope the owner has to grant.
  if (code === "AUTH_FAILED" || code === "NOT_FOUND") {
    return isGoogleAccount(account) ? "read_access" : "mail_failed";
  }
  return code;
}

async function run(ctx, input) {
  const settings = isPlainObject(ctx.block?.settings) ? ctx.block.settings : {};
  const refuse = (code) => ({ sourceError: { message: redactSecrets(code, []) } });
  const missingReadPath = () => ({ sourceError: { message: redactSecrets(MAIL_READ_SENTENCE, []) } });

  const reportId = text(ctx?.report?.id);
  if (!reportId) return refuse("bad_settings");

  // The account the owner approved for this report, and no other: the sealed live set's sender, or the
  // account the executor resolved through the approval rails for a preview. Never the report row here.
  const approvedAccountId = text(ctx?.live?.senderAccountId) || text(ctx?.previewSender);
  const accountId = text(settings.accountId).trim();
  if (!approvedAccountId || accountId !== approvedAccountId) return refuse("account_not_approved");

  const seam = ctx?.mail;
  const adapterFor = typeof seam === "function"
    ? seam
    : (seam && typeof seam.adapterFor === "function" ? seam.adapterFor : null);
  if (!adapterFor) return refuse("mail_not_available");

  let account;
  try {
    account = await (await loadMailModules()).getAccount(ctx.db, accountId);
  } catch {
    return refuse("account_unavailable");
  }
  if (!account) return refuse("account_unavailable");

  const modules = await loadMailModules();
  try {
    const items = await adapterFor(account, async (adapter) => readWindow(
      adapter, settings, nowOf(ctx), modules.parseRawMessage, modules.sanitizeMessageHtml,
    ));
    return { items: Array.isArray(items) ? items.slice(0, MAX_MESSAGES) : [] };
  } catch (err) {
    const code = failureCode(err, account);
    return code === "read_access" ? missingReadPath() : refuse(code);
  }
}

export const mailAlertsBlock = Object.freeze({
  type: "mail_alerts",
  kind: "source",
  sourceBearing: true,
  validate,
  run,
});