/**
 * Crow Mail's OAuth meta: the few non-secret facts about a grant that neither `mail_accounts` nor the
 * sealed keychain is the right place for.
 *
 * Four fields, and nothing else is ever stored:
 *
 * - `grantedAt` — when the grant was made (epoch ms), so a card can say how old it is;
 * - `publishing` — `"testing"` or `"production"`, or `"unknown"` when Crow was not told (Google keeps a
 *   consent in testing mode while the app registration is unverified, and its refresh tokens then expire
 *   after seven days: the card has to be able to say which one this is);
 * - `provider` — which provider the grant was made with (`google`, `microsoft`);
 * - `tenant` — the Microsoft tenant, when one was named (`common` otherwise; oauth/flow.js validates it).
 *
 * There is no token and no secret here, by construction: the refresh token, the client id and the
 * client secret live in the sealed keychain (mail/credentials.js), and nothing in this module reads or
 * writes them. The whole map is ONE dashboard setting (`mail_oauth_meta`), a JSON object keyed by
 * account id, written with `scope: "local"` — whether this box traded a grant for an account is this
 * box's fact, never something a paired peer inherits or replicates.
 *
 * Every field is validated on the way in (the value came from a provider's answer, a flow, or a
 * person's JSON, and this module is the last place before it is stored): a bad account id, timestamp,
 * provider or tenant is MailError BAD_INPUT naming the field, and nothing is written. `publishing`
 * reads leniently — anything that is not `testing` or `production` is `unknown` — because the honest
 * answer for "the flow did not say" is "unknown", not an error that would lose the rest of the grant's
 * facts with it. A stored map that cannot be parsed, or an entry that is not an object, reads as absent
 * rather than as a fault: this is a label on an account, and a broken label must not break a sign-in.
 */
import { MailError } from "../errors.js";
import { readSetting, writeSetting } from "../../dashboard/settings/registry.js";
import { tenantFor } from "./flow.js";

/** The one dashboard setting the whole map lives in. Local scope: never synced to a peer. */
export const MAIL_OAUTH_META_SETTING = "mail_oauth_meta";

/** The three values `publishing` may read back as; anything else on the way in is `unknown`. */
export const MAIL_OAUTH_PUBLISHING_VALUES = Object.freeze(["testing", "production", "unknown"]);

/** The account ids mail mints (`ma-<16 hex>`): the map's keys, and nothing else. */
const ACCOUNT_ID_RE = /^ma-[0-9a-f]{16}$/;
const PROVIDER_MAX = 60;

function fail(field) {
  throw new MailError("BAD_INPUT", field);
}

function requireAccountId(value) {
  if (typeof value !== "string" || !ACCOUNT_ID_RE.test(value)) fail("account_id");
  return value;
}

/** Lenient on the way in, fixed on the way out: only the two real answers are kept, else `unknown`. */
function normalizePublishing(value) {
  if (typeof value !== "string") return "unknown";
  const word = value.trim().toLowerCase();
  return word === "testing" || word === "production" ? word : "unknown";
}

function normalizeGrantedAt(value, fallback) {
  if (value === undefined || value === null) return fallback;
  if (!Number.isInteger(value) || value < 0) fail("granted_at");
  return value;
}

function normalizeProvider(value) {
  if (typeof value !== "string") fail("provider");
  const provider = value.trim().toLowerCase();
  if (!provider || provider.length > PROVIDER_MAX) fail("provider");
  return provider;
}

/** A tenant as oauth/flow.js will splice it into a URL (BAD_INPUT for anything else). */
function normalizeTenant(value) {
  if (value === undefined || value === null || value === "") return null;
  return tenantFor(value);
}

async function readMap(db) {
  const raw = await readSetting(db, MAIL_OAUTH_META_SETTING);
  if (typeof raw !== "string" || raw === "") return {};
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return {};
  }
  if (parsed == null || typeof parsed !== "object" || Array.isArray(parsed)) return {};
  return parsed;
}

/** One stored entry as this module's own shape, or null when there is not a usable one. */
function normalizeEntry(value) {
  if (value == null || typeof value !== "object" || Array.isArray(value)) return null;
  const grantedAt = Number.isInteger(value.grantedAt) && value.grantedAt >= 0 ? value.grantedAt : null;
  const publishing = MAIL_OAUTH_PUBLISHING_VALUES.includes(value.publishing) ? value.publishing : "unknown";
  const provider = typeof value.provider === "string" ? value.provider : null;
  const tenant = typeof value.tenant === "string" && value.tenant !== "" ? value.tenant : null;
  const entry = { grantedAt, publishing, provider };
  if (tenant != null) entry.tenant = tenant;
  return entry;
}

/**
 * One account's OAuth meta, or null when none was recorded. Never throws for a stored entry that is
 * malformed: an unreadable label is absence, not a fault in the sign-in.
 *
 * @param {object} db
 * @param {string} accountId
 * @returns {Promise<{grantedAt: number|null, publishing: string, provider: string|null, tenant?: string}|null>}
 */
export async function getOauthMeta(db, accountId) {
  const id = requireAccountId(accountId);
  const map = await readMap(db);
  if (!Object.hasOwn(map, id)) return null;
  return normalizeEntry(map[id]);
}

/**
 * Record (or replace) one account's OAuth meta. Every field is validated before anything is written,
 * and the map is one local-scope setting, so a write is one row and a peer never inherits it.
 *
 * @param {object} db
 * @param {string} accountId
 * @param {{grantedAt?: number, publishing?: string, provider: string, tenant?: string}} entry
 * @returns {Promise<{grantedAt: number, publishing: string, provider: string, tenant?: string}>}
 */
export async function setOauthMeta(db, accountId, entry = {}) {
  const id = requireAccountId(accountId);
  if (entry == null || typeof entry !== "object" || Array.isArray(entry)) fail("meta");
  const grantedAt = normalizeGrantedAt(entry.grantedAt, Date.now());
  const publishing = normalizePublishing(entry.publishing);
  const provider = normalizeProvider(entry.provider);
  const tenant = normalizeTenant(entry.tenant);

  const stored = { grantedAt, publishing, provider };
  if (tenant != null) stored.tenant = tenant;

  const map = await readMap(db);
  map[id] = stored;
  await writeSetting(db, MAIL_OAUTH_META_SETTING, JSON.stringify(map), { scope: "local" });
  return { ...stored };
}

/**
 * Drop one account's meta (the account's removal). Idempotent: an account with nothing recorded writes
 * nothing at all.
 *
 * @param {object} db
 * @param {string} accountId
 * @returns {Promise<boolean>} whether an entry was removed
 */
export async function deleteOauthMeta(db, accountId) {
  const id = requireAccountId(accountId);
  const map = await readMap(db);
  if (!Object.hasOwn(map, id)) return false;
  delete map[id];
  await writeSetting(db, MAIL_OAUTH_META_SETTING, JSON.stringify(map), { scope: "local" });
  return true;
}