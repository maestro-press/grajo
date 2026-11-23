/**
 * The reports approval seal.
 *
 * Every owner approval in Crow Recurring Reports (go-live, a recipient, a custom-step bundle, a host, a
 * credential binding, a proposal, a draft source's settings, the author seal over one owner-written
 * recipe revision, and the sender a report is about) is stored with an HMAC over the content the
 * owner approved plus a fresh approval nonce, under a subkey derived from the keychain's own seed:
 * `HMAC(keychain seed, "crow-reports-approval-v1")`. The keychain key is the one secret this Crow holds
 * that no bot can read through the database, so a seal is the run-time half of the rule that a bot
 * cannot approve anything. The approvals module and the owner-only routes are the other half.
 *
 * This is the mail tap seal's pattern, copied on purpose (servers/gateway/mail/drafts/seal.js), under
 * its own domain and with its own per-kind field lists. The mail module is inside Crow Mail's
 * anti-goal invariant and `tapSealKey` is hard-wired to the tap domain, so nothing here imports it: a
 * mail seal and a reports seal are different keys even when the field text is the same.
 *
 * The one sibling here is not an approval: a recipient page's comment form carries a NONCE keyed by
 * the same keychain seed under its own domain (`formNonceKey`), so a page this instance rendered can be
 * told from a page an attacker made, without giving the reader a session. See the form-nonce section at
 * the bottom of this file.
 *
 * Encoding: length-prefixed (a 4-byte big-endian length, then the UTF-8 bytes), type-tagged (`s` for a
 * string, `n` for a finite number), in a fixed per-kind order, with the payload version and the KIND
 * itself part of the MAC input. A seal made for one kind therefore never verifies as another, and two
 * spellings of the same characters cannot produce the same payload.
 *
 * One difference from mail: an EMPTY string is allowed here, because callers pass "" for "none"
 * (no sender account yet, no model, no proposal base). null, undefined, a non-finite number and any
 * other type are refused in the signing path with `code: "bad_seal_field"`.
 *
 * A kind's field list covers everything the owner's tap was about, which is why two of them carry a
 * digest of a structured value rather than the value: a step's `language` and `entry` say WHICH file of
 * the approved bundle runs and in which runtime, and a credential's `injectHash` is the sha256 of the
 * canonical text of its rule (its own module writes that text: fixed key order, sorted path prefixes,
 * sorted methods, no other keys), so widening a path prefix, adding a method or moving the header is a
 * different approval.
 *
 * The honest limit: this is a tamper check, not a capability. A process that can read the keychain key
 * file could mint a seal, and a writer that copied a row could replay it until the row changes. What
 * the nonce buys is that every approval is a distinct seal; what the stores buy is that refusing or
 * revoking an approval nulls the seal, so an old seal cannot re-approve anything THROUGH the module
 * that owns the kind. A direct SQL writer that put an old approval row (its seal and nonce included)
 * back after a revoke would be re-approving with it until that row changes again: every kind here
 * shares that limit, because a seal binds content and a nonce, never a moment in time.
 */
import { createHmac, randomBytes, timingSafeEqual } from "node:crypto";

/** The MAC domain the subkey is derived under; bumping it invalidates every seal ever made. */
export const APPROVAL_SEAL_DOMAIN = "crow-reports-approval-v1";

/**
 * The MAC domain a recipient form's nonce is derived under.
 *
 * A form nonce is a DIFFERENT key from an approval seal even under the same keychain seed, because it is
 * a different question: a seal says the owner approved this content, a nonce says a page this instance
 * rendered was actually rendered here. Sharing a domain would let one artefact be read as the other.
 */
export const FORM_NONCE_DOMAIN = "crow-reports-form-v1";

/** The approvals that carry a seal. */
export const APPROVAL_KINDS = Object.freeze([
  "live", "recipient", "step", "host", "credential", "proposal", "source", "author", "sender",
]);

/**
 * Each kind's fields, in the one order they are encoded. Every list ends with `nonce`, so every seal
 * binds one approval rather than a content pair.
 */
export const SEAL_FIELDS = Object.freeze({
  // The live set: what the owner approved the report to read, send and say, and whose report it is.
  // `botId`, `projectId`, `artifactId` and `scheduleId` are here so a report repointed at another bot,
  // moved to another project, or attached to another artifact or schedule row is a different report to
  // approve. `commentWindowRuns` is the number of runs back a reader may still comment on: widening or
  // narrowing that window changes what the report hands out, so it seals as a number (fieldText writes
  // it as `n<value>`). `title` is deliberately NOT sealed: it is a label, the owner renames it without a
  // new approval, and PR 2b must treat it as untrusted text when it is used as a subject line (escaped
  // and bounded like any other stored string, never interpolated into a header or a log).
  live: Object.freeze([
    "reportId", "rev", "recipeHash", "sourcesHash", "cron", "tz", "senderAccountId",
    "botId", "projectId", "artifactId", "scheduleId",
    "deliveryMode", "commentTierDefault", "commentVisibility", "commentWindowRuns", "aiCommentary",
    "modelRef", "nonce",
  ]),
  recipient: Object.freeze(["reportId", "recipientId", "address", "commentTier", "nonce"]),
  // `language` and `entry` are sealed: they choose which file of the approved bundle runs, in which of
  // the two runtimes, so a direct UPDATE of either is a different thing to approve.
  step: Object.freeze(["reportId", "stepId", "bundleHash", "language", "entry", "nonce"]),
  host: Object.freeze(["reportId", "host", "nonce"]),
  // `injectHash` is the digest of the canonical text of the credential's rule (header or query, the
  // format, the sorted path prefixes, the sorted methods), so the SHAPE of what the relay will attach
  // is under the seal and not only the keychain row and the host.
  credential: Object.freeze(["reportId", "credentialRef", "host", "injectHash", "nonce"]),
  proposal: Object.freeze(["reportId", "proposalId", "baseRev", "diffHash", "nonce"]),
  // One draft block's exact settings: the block id is the approval KEY, the hash is the settings the
  // owner's view showed, so a save between that view and the tap is a different thing to approve.
  source: Object.freeze(["reportId", "blockId", "settingsHash", "nonce"]),
  // One saved revision, sealed as OWNER-written (revision-author.js): the revision number and the hash of
  // the recipe that revision holds, so a copied seal names neither another revision nor another recipe.
  author: Object.freeze(["reportId", "rev", "recipeHash", "authorKind", "nonce"]),
  // The mail account a report is about, sealed by the OWNER's settings save (sender-seal.js): a draft's
  // `mail_alerts` block is measured against it, so the account has to be the owner's choice and not a
  // column a direct UPDATE can move. The report id is inside it, so a seal copied between reports names
  // neither one's account.
  sender: Object.freeze(["reportId", "accountId", "nonce"]),
});

/** The payload's own version, so a future shape is a different MAC input. */
const PAYLOAD_VERSION = "v1";

/** An approval nonce is 16 random bytes, written as 32 lower-case hex characters. */
const NONCE_BYTES = 16;
const NONCE_HEX = /^[0-9a-f]{32}$/;

/** A seal is 32 bytes, written as 64 lower-case hex characters: one spelling, one seal. */
const SEAL_HEX = /^[0-9a-f]{64}$/;

function fail(code, detail) {
  const err = new Error(detail ? `${code}: ${detail}` : code);
  err.code = code;
  if (detail) err.detail = detail;
  return err;
}

/** A fresh approval nonce: one approval, one nonce. */
export function newApprovalNonce() {
  return randomBytes(NONCE_BYTES).toString("hex");
}

/**
 * A seed as the bytes a MAC is keyed with. The keychain seed is the one secret this Crow holds that no
 * bot can read through the database, so it is the only key material either derivation accepts: a
 * missing, empty or non-binary seed is `bad_seal_seed` rather than a silently weaker key.
 */
function seedBytes(seed) {
  if (seed == null) throw fail("bad_seal_seed", "seed");
  let bytes;
  if (Buffer.isBuffer(seed)) bytes = seed;
  else if (seed instanceof Uint8Array) bytes = Buffer.from(seed.buffer, seed.byteOffset, seed.byteLength);
  else throw fail("bad_seal_seed", "seed");
  if (!bytes.length) throw fail("bad_seal_seed", "seed");
  return bytes;
}

/** The per-seal subkey: HMAC-SHA256 of the domain under the keychain seed. */
export function approvalSealKey(seed) {
  return createHmac("sha256", seedBytes(seed)).update(APPROVAL_SEAL_DOMAIN, "utf8").digest();
}

/**
 * The per-instance form-nonce subkey: HMAC-SHA256 of the form domain under the keychain seed.
 *
 * The token hash a nonce is bound to is NOT secret (it is a column of `report_link_tokens`), so it is
 * never the key: it is part of the MAC INPUT, and only this seed can make a nonce verify.
 *
 * @param {Buffer|Uint8Array} seed the keychain key's seed
 * @returns {Buffer} 32 bytes
 * @throws {Error} `code: "bad_seal_seed"`
 */
export function formNonceKey(seed) {
  return createHmac("sha256", seedBytes(seed)).update(FORM_NONCE_DOMAIN, "utf8").digest();
}

/** The field list for a kind, refusing anything that is not one of APPROVAL_KINDS. */
function fieldsOf(kind) {
  if (typeof kind !== "string" || !APPROVAL_KINDS.includes(kind)) throw fail("bad_seal_kind", "kind");
  return SEAL_FIELDS[kind];
}

/**
 * One field as its tagged text: `s` for a string (the empty string included), `n` for a finite number.
 * Anything else is refused rather than sealed as something it is not.
 */
function fieldText(fields, name) {
  const value = fields[name];
  if (typeof value === "string") return `s${value}`;
  if (typeof value === "number" && Number.isFinite(value)) return `n${value}`;
  throw fail("bad_seal_field", name);
}

/** Every field, length-prefixed and in the kind's fixed order, after the version and the kind. */
function sealPayload(kind, fields) {
  const names = fieldsOf(kind);
  if (fields == null || typeof fields !== "object" || Array.isArray(fields)) {
    throw fail("bad_seal_field", "fields");
  }
  const nonce = fields.nonce;
  if (typeof nonce !== "string" || !NONCE_HEX.test(nonce)) throw fail("bad_seal_field", "nonce");
  const chunks = [];
  const push = (text) => {
    const body = Buffer.from(text, "utf8");
    const head = Buffer.alloc(4);
    head.writeUInt32BE(body.length, 0);
    chunks.push(head, body);
  };
  push(`v${PAYLOAD_VERSION}`);
  push(`k${kind}`);
  for (const name of names) push(fieldText(fields, name));
  return Buffer.concat(chunks);
}

/**
 * Seal one approval: the hex HMAC over the kind's fields under the keychain seed.
 *
 * @param {"live"|"recipient"|"step"|"host"|"credential"|"proposal"|"source"|"author"|"sender"} kind
 * @param {object} fields the kind's field list, `nonce` included
 * @param {Buffer|Uint8Array} seed the keychain key's seed
 * @returns {string} 64 lower-case hex characters
 * @throws {Error} `code: "bad_seal_kind"` / `"bad_seal_field"` / `"bad_seal_seed"`
 */
export function approvalSeal(kind, fields, seed) {
  const key = approvalSealKey(seed);
  return createHmac("sha256", key).update(sealPayload(kind, fields)).digest("hex");
}

/**
 * Does `seal` seal exactly these fields of this kind under this seed? The stored seal must be one
 * lower-case hex string of 64 characters before anything is compared; then the two MACs are compared
 * in constant time. Never throws: an unverifiable seal (a wrong length, an upper-case copy, a padded
 * one, a missing nonce, a string where a number was sealed, another kind) is a refusal, not an error.
 *
 * @param {"live"|"recipient"|"step"|"host"|"credential"|"proposal"|"source"|"author"|"sender"} kind
 * @param {object} fields the kind's field list
 * @param {string} seal the hex seal stored on the row
 * @param {Buffer|Uint8Array} seed the keychain key's seed
 * @returns {boolean}
 */
export function verifyApprovalSeal(kind, fields, seal, seed) {
  if (typeof seal !== "string" || !SEAL_HEX.test(seal)) return false;
  let expected;
  try {
    expected = Buffer.from(approvalSeal(kind, fields, seed), "hex");
  } catch {
    return false;
  }
  const given = Buffer.from(seal, "hex");
  if (given.length !== expected.length) return false;
  return timingSafeEqual(given, expected);
}

/* ---------------------------------------------------------------- the recipient form nonce */

/**
 * A recipient page's form is open for one ten-minute window and accepted for one more.
 *
 * WHY A WINDOW AND NOT A MOMENT: the form is rendered into a page a person may leave open while they
 * read the report and think about what to say, so a nonce that died with the page would refuse an
 * ordinary comment. WHY NOT A LONGER ONE: a nonce is not a session and does not identify the reader (the
 * link token does that), so the shorter it lives the less a copied page is worth. Ten minutes makes a
 * form good for 10 to 20 minutes, which matches the notice a reader gets when the page was left open
 * too long ("This page was open too long. Reload it and try again.").
 */
export const FORM_NONCE_WINDOW_MS = 600_000;

/** A form nonce is 32 bytes, written as 64 lower-case hex characters: one spelling, one nonce. */
const FORM_NONCE_HEX = /^[0-9a-f]{64}$/;

/** The window a moment falls in. A non-finite clock is "now", never NaN. */
function windowOf(now) {
  const value = Number(now);
  const ms = Number.isFinite(value) ? value : Date.now();
  return Math.floor(ms / FORM_NONCE_WINDOW_MS);
}

/** The nonce for one token hash and one window number, as hex. The only place the MAC is computed. */
function formNonceAt(tokenHash, seed, window) {
  const key = formNonceKey(seed);
  return createHmac("sha256", key).update(`${tokenHash}:${window}`, "utf8").digest("hex");
}

/**
 * The form nonce a recipient page carries for one token, in the window `now` falls in.
 *
 * The token hash is part of the MAC input, so a nonce made for one link never opens another link's form,
 * and the keychain seed is the key, so nothing outside this process can mint one. The hash is not a
 * secret and is never used as key material (see `formNonceKey`).
 *
 * @param {string} tokenHash the raw token's sha256, as `hashToken` answers it
 * @param {Buffer|Uint8Array} seed the keychain key's seed
 * @param {number} [now] epoch ms
 * @returns {string} 64 lower-case hex characters
 * @throws {Error} `code: "bad_seal_seed"` for an unusable seed, `bad_seal_hash` for no token hash
 */
export function formNonceFor(tokenHash, seed, now = Date.now()) {
  if (typeof tokenHash !== "string" || !tokenHash) throw fail("bad_seal_hash", "tokenHash");
  return formNonceAt(tokenHash, seed, windowOf(now));
}

/**
 * Does `nonce` name this token in the current or the previous form window?
 *
 * Two windows, so a form is good for 10 to 20 minutes: a person who took a while to write a comment is
 * not sent back to the report, and a page left open for an hour is not a page that still posts. Both
 * windows are compared in constant time and neither comparison short-circuits the other. Never throws:
 * a wrong length, an upper-case copy, a non-hex string, a missing hash, garbage for a seed and a
 * non-finite clock are all `false`, because a caller reads `false` as the approved "this page was open
 * too long" line and a reader must never see a database or keychain message.
 *
 * @param {*} nonce the value the form posted
 * @param {*} tokenHash the raw token's sha256
 * @param {*} seed the keychain key's seed
 * @param {*} [now] epoch ms
 * @returns {boolean}
 */
export function verifyFormNonce(nonce, tokenHash, seed, now = Date.now()) {
  if (typeof nonce !== "string" || !FORM_NONCE_HEX.test(nonce)) return false;
  if (typeof tokenHash !== "string" || !tokenHash) return false;
  const given = Buffer.from(nonce, "hex");
  const window = windowOf(now);
  let ok = false;
  for (const candidate of [window, window - 1]) {
    let expected;
    try {
      expected = Buffer.from(formNonceAt(tokenHash, seed, candidate), "hex");
    } catch {
      // An unusable seed cannot verify anything; the second window is not worth a second throw.
      return false;
    }
    if (given.length === expected.length && timingSafeEqual(given, expected)) ok = true;
  }
  return ok;
}