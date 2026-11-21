/**
 * The report's sender seal: proof that the OWNER chose the mail account a report is about.
 *
 * WHY THIS EXISTS: a live report's sender is part of the go-live seal, so a live report needs no other
 * proof of which mailbox it is about. A report that was never live (or one paused, or one whose seal no
 * longer verifies) has no such proof, and a draft's `mail_alerts` block is exactly what a preview runs.
 * The column `reports.sender_account_id` alone says nothing about who wrote it: it is a plain column, and
 * a direct UPDATE of it would point a never-live report's mail block at another mailbox. So the owner's
 * settings save seals the account it writes (approvals.js's `updateSettings` is the only writer here),
 * and the approval rails trust the row's sender only behind that seal (source-approvals.js's
 * `approvedSenderAccount`).
 *
 * WHERE THE SEAL LIVES: `report_state` under `sender_seal`, as JSON `{accountId, nonce, seal}` (no
 * column, and no schema change). The key is RESERVED: a recipe block's `setState` refuses it
 * (`isReservedStateKey`, artifact-bridge.js), and the run engine's buffered flush refuses it with the
 * same list, so no bot-authored recipe can write it.
 *
 * THE SEAL is seal.js's `sender` kind over `{reportId, accountId, nonce}`: the report id is inside it, so
 * a seal copied from another report names no account of this one, and the account id is inside it, so a
 * seal left behind by an earlier sender seals nothing after the column moves.
 *
 * READING IS FAIL CLOSED, ALWAYS: a report that names no account, a missing state row, a value that is not
 * `{accountId, nonce, seal}` in hex, an `accountId` that is not the row's CURRENT `sender_account_id`, a
 * seal that does not verify, a missing keychain seed and a database error all answer "not sealed".
 * Nothing here throws.
 *
 * A REPORT WHOSE SENDER PREDATES THIS SEAL has no `sender_seal` row, so its row sender is not trusted by a
 * draft preview: the owner re-saves the sender in the report's settings (the same value is fine) and it is
 * sealed. A live report is unaffected, because the live seal already covers the sender.
 *
 * NO SEAL, NO STALE SEAL: a settings save that sets a sender but ends up writing no seal for it (a missing
 * keychain key, or any failure making or writing the seal) CLEARS the stored one (approvals.js's
 * `sealSenderOnSettings` writes `null` here). The settings are still saved. Otherwise the seal the previous
 * sender left behind would sit in the row, and a later direct UPDATE of the column back to that sender
 * would verify against an approval the owner made for a sender the report no longer had.
 *
 * THE SEED IS A PARAMETER, not a deps member: the module that holds the approvals seam (approvals.js, and
 * source-approvals.js for the read) loads it with `approvalInternals.seedOf` and hands it over, so this
 * module imports nothing from them and there is no cycle.
 */
import { approvalSeal, newApprovalNonce, verifyApprovalSeal } from "./seal.js";
import { getState } from "./store.js";

/** The `report_state` key a report's sender seal lives under (reserved: no block may write it). */
export const SENDER_SEAL_KEY = "sender_seal";

/** The kind tag the shared encoder seals a report's sender under (seal.js's `sender` field list). */
const SENDER_SEAL_KIND = "sender";

/** A seal is 32 bytes as 64 lower-case hex; a nonce is 16 bytes as 32 lower-case hex. */
const SEAL_HEX = /^[0-9a-f]{64}$/;
const NONCE_HEX = /^[0-9a-f]{32}$/;

function text(value) {
  if (value == null) return "";
  return typeof value === "string" ? value : String(value);
}

/** Are these usable keychain seed bytes? Anything else proves nothing. */
function isSeed(seed) {
  if (Buffer.isBuffer(seed)) return seed.length > 0;
  return seed instanceof Uint8Array && seed.length > 0;
}

/**
 * Make a report's sender seal: a fresh nonce and the hex HMAC over the report and the account.
 *
 * Only the owner's settings save calls this, and it only reaches here with a loaded keychain seed: a
 * missing one throws from the caller's own seed reader (`keychain_key_missing`), and a seed that is not
 * bytes throws `bad_seal_seed` from seal.js.
 *
 * @param {Buffer|Uint8Array} seed the keychain key's seed
 * @param {{reportId: string, accountId: string}} fields
 * @returns {{accountId: string, nonce: string, seal: string}}
 * @throws {Error} `bad_seal_field` / `bad_seal_seed`
 */
export function sealSender(seed, { reportId, accountId } = {}) {
  const account = text(accountId);
  const nonce = newApprovalNonce();
  const seal = approvalSeal(SENDER_SEAL_KIND, { reportId: text(reportId), accountId: account, nonce }, seed);
  return { accountId: account, nonce, seal };
}

/**
 * Is this report's row sender the account the OWNER sealed?
 *
 * `true` only when the row names a non-empty `sender_account_id`, the `sender_seal` state row parses to
 * `{accountId, nonce (32 hex), seal (64 hex)}`, that `accountId` is the row's CURRENT value, and the seal
 * verifies over the report id, that account and the nonce under this keychain seed.
 *
 * Never throws: anything else (a missing seed included) is `false`.
 *
 * @param {object} db
 * @param {Buffer|Uint8Array|null} seed the keychain key's seed, loaded by the caller; null means none
 * @param {object|null} report a report row
 * @returns {Promise<boolean>}
 */
export async function senderSealVerifies(db, seed, report) {
  try {
    if (!isSeed(seed)) return false;
    if (report == null || typeof report !== "object") return false;
    const reportId = text(report.id);
    if (!reportId) return false;
    const accountId = text(report.sender_account_id);
    if (!accountId) return false;
    const row = await getState(db, reportId, SENDER_SEAL_KEY);
    if (row == null || typeof row !== "object" || Array.isArray(row)) return false;
    const sealedAccount = text(row.accountId);
    const nonce = text(row.nonce);
    const seal = text(row.seal);
    if (!sealedAccount || sealedAccount !== accountId) return false;
    if (!NONCE_HEX.test(nonce) || !SEAL_HEX.test(seal)) return false;
    return verifyApprovalSeal(
      SENDER_SEAL_KIND,
      { reportId, accountId, nonce },
      seal,
      seed,
    );
  } catch {
    return false;
  }
}