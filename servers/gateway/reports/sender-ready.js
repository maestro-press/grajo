/**
 * Whether a Crow Mail account can send right now, for Crow Recurring Reports.
 *
 * This is the one place in the reports code that reaches into Crow Mail. It lives in its own file so
 * `reports/approvals.js` imports nothing under `mail/`: the approval module owns seals and the live set,
 * the routes own the wiring, and the mail read stays a small, separately readable seam. A test reads the
 * reports modules' import text to keep it that way.
 *
 * The rule: the account row must exist, be `active` (not signed out, not claimed by another instance)
 * and carry an auth kind this Crow signs in with, and the account's credential must be present in the
 * keychain. Crow Mail has no single "send-ready" predicate to reuse (the send path reads the account and
 * then the secrets, one step at a time), so this reads the same two things through the same accessors.
 * Any failure, including a missing keychain key, is a plain false: go-live then refuses rather than
 * approving a sender nobody looked at.
 *
 * `listSendReadyAccounts` is the same rule over the account list, for the sender menu on a report's
 * page: the accounts that can send right now, as ids and addresses only. It never throws (an answer of
 * no accounts is the same as a report nobody can send from). It reads the rows `listAccounts` already
 * answered and asks the keychain once per account with ONE credentials object, concurrently, so the page
 * does not pay a second account read per row on every owner load.
 */
import { getAccount, listAccounts, MAIL_AUTH_KINDS } from "../mail/store/accounts.js";
import { createMailCredentials } from "../mail/credentials.js";

/** How many accounts the sender menu considers, counted from the first one the owner added. The menu is
 *  built on every owner load of a report page and is not meant to carry more than a handful of accounts;
 *  a list longer than this is a list nobody picks from, so only the first rows are read. */
const SEND_READY_LIMIT = 50;

/**
 * One account row's own rule, with a credentials reader in hand: active, an auth kind this Crow signs in
 * with, and its credential present in the keychain. Any failure is a plain false.
 */
async function readyWith(credentials, account) {
  if (!account || account.status !== "active") return false;
  if (!MAIL_AUTH_KINDS.includes(account.authKind)) return false;
  try {
    const secrets = await credentials.getSecrets(account.id);
    const key = account.authKind === "xoauth2" ? "MAIL_REFRESH_TOKEN" : "MAIL_PASSWORD";
    return typeof secrets?.[key] === "string" && secrets[key] !== "";
  } catch {
    return false;
  }
}

/**
 * Can this mail account send right now?
 *
 * @param {object} db a libsql-shaped client
 * @param {string} accountId a Crow Mail account id (`ma-<16 hex>`)
 * @returns {Promise<boolean>}
 */
export async function senderReady(db, accountId) {
  if (typeof accountId !== "string" || !accountId) return false;
  let account;
  try {
    account = await getAccount(db, accountId);
  } catch {
    return false;
  }
  try {
    return await readyWith(createMailCredentials({ db }), account);
  } catch {
    return false;
  }
}

/**
 * The mail accounts that can send right now, in the order the owner added them.
 *
 * Each entry is `{id, address}` and nothing else: the id is what a settings save writes in
 * `sender_account_id`, and the address is what the owner reads in the menu. The rows come from the one
 * `listAccounts` read and are checked side by side with a single credentials object, which keeps the
 * order of that list. An unreadable account list, or any failure while reading one account, leaves that
 * account out instead of failing the page.
 *
 * @param {object} db a libsql-shaped client
 * @returns {Promise<Array<{id: string, address: string}>>}
 */
export async function listSendReadyAccounts(db) {
  let accounts;
  try {
    accounts = await listAccounts(db);
  } catch {
    return [];
  }
  let credentials;
  try {
    credentials = createMailCredentials({ db });
  } catch {
    return [];
  }
  const rows = (Array.isArray(accounts) ? accounts : []).slice(0, SEND_READY_LIMIT);
  const ready = await Promise.all(rows.map(async (account) => {
    const id = account && typeof account.id === "string" ? account.id : "";
    if (!id) return null;
    let ok = false;
    try {
      ok = (await readyWith(credentials, account)) === true;
    } catch {
      ok = false;
    }
    if (!ok) return null;
    return { id, address: typeof account.address === "string" ? account.address : "" };
  }));
  return ready.filter(Boolean);
}

export default senderReady;