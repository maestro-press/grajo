/**
 * Crow keychain — human-facing passwords, sealed with secret-box under the keychain's OWN
 * key (keychain/key.js), LOCAL ONLY (instance-sync LOCAL_ONLY_TABLES). Secrets leave this
 * module only through openEntrySecret / consumeFirstView / exportableEntries, whose callers
 * gate and audit them; through serviceSecretsFor, which only the gateway's own connection test
 * and child spawn read (a project connection's secrets, kind 'service', keyed by connection
 * uuid); through extensionSecretsFor, which only the gateway's own project connect route
 * reads when the owner picks a key they already saved for that service (kind 'extension',
 * bundle id + env key); and through extensionSecretsSync, the SYNCHRONOUS all-or-nothing
 * reader of one add-on's listed env keys whose only callers are spawn hydration
 * (servers/shared/addon-secrets.js readAddonSecretsSync), the Bot Builder's add-on probe,
 * and the seal and migration read-back proofs. Rows sealed under another key (a crow.db
 * restored onto a machine without the key file) are listed as readable:false and throw
 * KeychainKeyMissingError on open — never a crash, never a wrong plaintext.
 *
 * EVERY sealed value is BOUND to its row (secret-box v2, `enc:v2:`): the AAD is
 * `rowAad(row, keyId)` over the row's own (kind, bundle_id, env_key, connection_uuid), so a
 * blob copied into another row — or a row whose bound columns were changed under it — fails
 * its tag check instead of yielding a plaintext. Every seal in this file uses the AAD of the
 * row's FINAL bound columns, and every open uses the AAD of the row it READ, so the two can
 * never drift. `enc:v1:` rows are still opened (no AAD) BEFORE the conversion era and are
 * REFUSED after it (`keychain/aad-era.js`): the era records that nothing this release writes
 * is v1 any more, so a v1 blob is a value something else put there.
 */
import { timingSafeEqual } from "node:crypto";
import {
  isCanonicalSealed, isSealedV1, isSealedV2, openSecret, openSecretBound, sealSecretBound,
} from "../../sharing/secret-box.js";
import { resolveCrowHome } from "../../shared/crow-home.js";
import {
  aadSecretsDirFromHome, eraConvertedAsync, eraConvertedFromFile, eraConvertedSync,
  raiseLegacyFormAlarmAsync, raiseLegacyFormAlarmSync,
} from "./aad-era.js";
import { serviceById, isPanelService } from "../../shared/service-catalog.js";
import { KEYCHAIN_DDL, KEYCHAIN_CONNECTION_COLUMN, KEYCHAIN_SERVICE_INDEX_DDL } from "./schema.js";
import { keychainKeyState, createKeychainKey, KeychainKeyInvalidError } from "./key.js";

export const KEYCHAIN_TABLE = "crow_keychain";
export const FIRST_VIEW_MS = 30 * 60 * 1000;
const KINDS = new Set(["extension", "manual", "service"]);
const ORIGINS = new Set(["typed", "generated", "manual"]);

export class KeychainKeyMissingError extends Error {
  constructor() {
    super("The keychain key for this password is not on this machine.");
    this.code = "KEYCHAIN_KEY_MISSING";
  }
}

/** A kind 'service' row belongs to a project connection: it goes only with that connection. */
export class KeychainServiceRowError extends Error {
  constructor() {
    super("This key belongs to a project connection. Disconnect it on the project's Services page instead.");
    this.code = "KEYCHAIN_SERVICE_ROW";
  }
}

/**
 * A Crow Mail password is a `service` row whose connection is a `mail_accounts` row, not a
 * `service_connections` one, so the orphan rule in deleteEntry would call a mailbox's password
 * purgeable from the keychain page and silently break the account. Such a row never goes from
 * here, whatever its status (and whether or not its account row is still there): it goes with its
 * account, through the mail credentials module's deleteSecrets.
 */
export class KeychainMailRowError extends Error {
  constructor() {
    super("This password belongs to a Mail account. Remove the account in Mail settings.");
    this.code = "KEYCHAIN_MAIL_ROW";
  }
}

/**
 * One or more of an add-on's listed env keys has no usable row: missing, not 'active' (an
 * uninstall's extension_removed), sealed under another key id (a crow.db restored without
 * its key file), or unreadable/empty. All or nothing — callers never start an add-on with a
 * partial env. `names` are env NAMES; the message carries no value and no driver error.
 */
export class KeychainRowsMissingError extends Error {
  constructor(names) {
    super("The keychain has no readable secret for every saved key of this extension.");
    this.code = "KEYCHAIN_ROWS_MISSING";
    this.names = (Array.isArray(names) ? names : []).filter((n) => typeof n === "string");
  }
}

/**
 * A keychain row that holds an `enc:v1:` blob after the conversion era: nothing this release
 * writes is v1 any more, so the row is refused exactly like an unreadable one — never
 * opened, never handed to an add-on child. The same refusal covers a `enc:v2:` value whose
 * base64 body is not the canonical form this release writes (whitespace added around it, its
 * `=` pad stripped): Node's decoder ignores both, so such a value WOULD open, and it is a
 * spelling no Crow wrote. The message is internal (no client shows it; the
 * keychain API answers with its fixed "nothing was revealed" line) and carries no value.
 */
export class KeychainLegacyFormError extends Error {
  constructor() {
    super("This saved password is in the old sealed form, which this database now refuses.");
    this.code = "KEYCHAIN_LEGACY_FORM";
  }
}

const META_COLS = "id, kind, label, bundle_id, env_key, username, url, origin, status, key_id, created_at, updated_at, first_view_until, connection_uuid";
/** The `crow_keychain` columns a seal is BOUND to (every SELECT that feeds an open reads them). */
const BOUND_COLS = "kind, bundle_id, env_key, connection_uuid";
const iso = (d) => (d instanceof Date ? d : new Date()).toISOString();
const cleanText = (v, max = 512) => (v === undefined || v === null || String(v).trim() === "" ? null : String(v).slice(0, max));
const box = (key) => ({ seed: key.seed });

/**
 * The associated data a sealed keychain value is bound to: this row's own identity plus the
 * key id. A blob copied into ANY other row (another kind, bundle, env key or connection, or
 * another key) has a different AAD, so AES-GCM's tag check fails and the copy opens nothing.
 *
 * Not bound, deliberately: label, username, url, status and first_view_until — those change
 * legitimately on a row whose secret did not. `manual` rows therefore bind only their kind:
 * their values only ever go to the owner, so a manual-to-manual copy gains a bot nothing,
 * while every manual<->extension/service swap fails on `kind`.
 */
export function rowAad(row, keyId) {
  return Buffer.from(JSON.stringify([
    "crow-keychain-v2",
    row?.kind ?? null,
    row?.bundle_id ?? null,
    row?.env_key ?? null,
    row?.connection_uuid ?? null,
    keyId ?? null,
  ]), "utf8");
}

/** The bound-column object for a row an operation is about to WRITE (its final values). */
const boundRow = (kind, bundleId, envKey, connectionUuid) => ({
  kind,
  bundle_id: bundleId ?? null,
  env_key: envKey ?? null,
  connection_uuid: connectionUuid ?? null,
});

/** Seal one value for the row it is about to be written to. */
function sealRow(row, key, plaintext) {
  return sealSecretBound(plaintext, box(key), rowAad(row, key.id));
}

/** The SECRETS dir whose era state file decides whether a v1 row still opens (null: none). */
function eraDirOf(crowHome) {
  if (typeof crowHome === "string" && crowHome !== "") return aadSecretsDirFromHome(crowHome);
  try { return aadSecretsDirFromHome(resolveCrowHome()); } catch { return null; }
}

/**
 * Open ONE row's value with the AAD of the row that was READ. v2 opens only with that AAD, and
 * only in the CANONICAL base64 form (`isCanonicalSealed`): `"<blob>\n"`, a space after the prefix
 * and a padding-stripped body are different strings that the decoder opens to the same plaintext,
 * so a value in any other spelling is refused like an old-form one. v1 opens with no AAD before
 * the era and is refused (and alarmed) after it. `legacyRefused` is the caller's era verdict;
 * `alarm` records a refusal (best effort, never throws).
 */
function openSealedRow(row, key, { legacyRefused = false, alarm = null } = {}) {
  const blob = row?.secret_sealed;
  if (isSealedV1(blob)) {
    if (legacyRefused) {
      try { alarm?.(row); } catch { /* an alarm never changes the refusal */ }
      throw new KeychainLegacyFormError();
    }
    return openSecret(blob, box(key));
  }
  if (isSealedV2(blob)) {
    if (!isCanonicalSealed(blob)) {
      try { alarm?.(row); } catch { /* an alarm never changes the refusal */ }
      throw new KeychainLegacyFormError();
    }
    return openSecretBound(blob, box(key), rowAad(row, key.id));
  }
  // Not sealed at all (a legacy plaintext cell): the v1 opener's answer is null.
  return openSecret(blob, box(key));
}

function requireKey(key) {
  if (!key || typeof key.id !== "string" || !Buffer.isBuffer(key.seed)) throw new KeychainKeyMissingError();
}

// Per client, the in-flight (then settled) ensure. Concurrent first callers share one promise, so
// the PRAGMA-then-ALTER below runs once; a failed ensure is forgotten, so the next call retries.
const ensuring = new WeakMap();
export function ensureKeychainTable(db) {
  let p = ensuring.get(db);
  if (!p) {
    p = runKeychainEnsure(db);
    ensuring.set(db, p);
    p.catch(() => { if (ensuring.get(db) === p) ensuring.delete(db); });
  }
  return p;
}

async function runKeychainEnsure(db) {
  await db.executeMultiple(KEYCHAIN_DDL);
  // A table created before migration 0019 lacks connection_uuid: add it before the index on it.
  const cols = (await db.execute("PRAGMA table_info(crow_keychain)")).rows.map((r) => r.name);
  if (!cols.includes(KEYCHAIN_CONNECTION_COLUMN.column)) await db.execute(KEYCHAIN_CONNECTION_COLUMN.ddl);
  await db.executeMultiple(KEYCHAIN_SERVICE_INDEX_DDL);
}

function toEntry(r, { now, keyId } = {}) {
  if (!r) return null;
  const { first_view_until: fvu, key_id: kid, ...rest } = r;
  return { ...rest, id: Number(r.id), readable: !!keyId && kid === keyId, first_view_pending: !!fvu && fvu > iso(now) };
}

export async function countEntries(db) {
  await ensureKeychainTable(db);
  return Number((await db.execute("SELECT COUNT(*) AS n FROM crow_keychain")).rows[0].n);
}

/**
 * The key to SAVE with (re-review m1/m2). Missing → created. Invalid (empty/damaged file) →
 * replaced only while the table is empty; otherwise KeychainKeyInvalidError, because those
 * rows may still be recoverable by restoring the file. When a key is created while rows
 * already exist (the old key was lost), onNewKey({ orphaned }) lets the caller audit it and
 * tell the user those entries need an Import.
 */
export async function ensureWriteKey(db, { crowHome, onNewKey } = {}) {
  const st = keychainKeyState({ crowHome });
  if (st.state === "ok") return st.key;
  const n = await countEntries(db);
  if (st.state === "invalid" && n > 0) throw new KeychainKeyInvalidError(st.path);
  const key = createKeychainKey({ crowHome, replaceInvalid: st.state === "invalid" });
  if (n > 0 && typeof onNewKey === "function") {
    try { await onNewKey({ orphaned: n }); } catch { /* reporting must never block a save */ }
  }
  return key;
}

/** The bundle id Crow Mail's keychain rows carry (servers/gateway/mail/credentials.js, MAIL_BUNDLE_ID). */
export const MAIL_BUNDLE = "crow-mail";

/** The bundle id a Crow Recurring Reports credential's keychain row carries (env key
 *  `REPORT_CREDENTIAL`, kind 'service', keyed by the report_credentials row's connection uuid; written
 *  by the `report-credential` secret target). Like Crow Mail's rows, no installed bundle stands behind
 *  it, so it is a Crow-owned id: an add-on may neither overwrite it nor be handed it. */
export const REPORTS_BUNDLE = "crow-reports";

/** Keychain "bundle ids" that belong to Crow itself, never to an add-on: the off-site backup key
 *  (servers/shared/crow-vault.js OFFSITE_KEY) and Crow Mail's own rows (kind 'service', bundle id
 *  MAIL_BUNDLE, written by the mail credentials module; no installed bundle stands behind them).
 *  An add-on installed under such an id must neither overwrite the entry, be handed it, revive it
 *  from 'extension_removed' nor mark it removed, so every add-on path skips or refuses these ids. */
export const SYSTEM_BUNDLE_IDS = Object.freeze(new Set(["offsite-backup", MAIL_BUNDLE, REPORTS_BUNDLE]));
export const isSystemBundleId = (id) => SYSTEM_BUNDLE_IDS.has(String(id));

/** The reserved-id refusal, kept ahead of any DB work, exactly as saveExtensionSecret had it. */
function assertExtensionOwner(bundleId, systemOwner) {
  if (isSystemBundleId(bundleId) && systemOwner !== true) throw new Error("keychain: that id is reserved for Crow itself");
}

/**
 * The validation + sealing both extension writers do, so neither can drift from the other.
 * A caller that must KEEP an existing row's one-time window does it with `keepFirstView` on
 * the write (saveExtensionSecret), never by passing a timestamp back: an earlier read can be
 * stale by the time the row is written.
 */
function extensionValues(key, { bundleId, envKey, label, username = null, url = null, secret, origin, firstView = false, now }) {
  requireKey(key);
  if (!bundleId || !envKey || typeof secret !== "string" || secret === "") throw new Error("keychain: bundleId, envKey and a secret are required");
  if (!ORIGINS.has(origin) || origin === "manual") throw new Error("keychain: origin must be typed or generated");
  return {
    label: cleanText(label) || envKey,
    username: cleanText(username),
    url: cleanText(url, 2048),
    sealed: sealRow(boundRow("extension", bundleId, envKey, null), key, secret),
    ts: iso(now),
    fvu: firstView ? new Date((now || new Date()).getTime() + FIRST_VIEW_MS).toISOString() : null,
  };
}

/**
 * Does this row hold exactly `plaintext` under `key`? The seal asks it before it decides
 * whether a re-save may carry a row's identity forward. False for another key id, a damaged
 * row, a non-string plaintext, and — deliberately — a value of a different LENGTH
 * (timingSafeEqual needs equal-length buffers): a different length is a different value.
 * Never returns, logs or throws the value itself.
 */
export function rowSecretEquals(row, key, plaintext, { legacyRefused = null, crowHome = null } = {}) {
  if (!row || !key || row.key_id !== key.id || typeof plaintext !== "string") return false;
  if (isSealedV1(row.secret_sealed) && (legacyRefused ?? eraConvertedFromFile(eraDirOf(crowHome)))) return false;
  let current;
  try {
    current = openSealedRow(row, key);
  } catch {
    return false;
  }
  if (typeof current !== "string") return false;
  const a = Buffer.from(current, "utf8");
  const b = Buffer.from(plaintext, "utf8");
  if (a.length !== b.length) return false;
  return timingSafeEqual(a, b);
}

export async function saveExtensionSecret(db, key, opts = {}) {
  const { bundleId, envKey } = opts;
  assertExtensionOwner(bundleId, opts.systemOwner);
  // A keep must NAME the row it was judged on, before anything is written: the caller compared
  // the value it writes against a blob it read earlier, and only that blob can say whether the
  // row still holds that value. Pinning on this call's own read would be a pin on a fresh
  // observation — it would always match, and the race the pin exists for would go unnoticed.
  if (opts.keepFirstView === true && (typeof opts.keepFirstViewPinnedTo !== "string" || opts.keepFirstViewPinnedTo === "")) {
    throw new Error("keepFirstView needs keepFirstViewPinnedTo");
  }
  await ensureKeychainTable(db);
  const v = extensionValues(key, opts);
  const { label, username, url, sealed, ts, fvu } = v;
  // `keepFirstView` KEEPS an existing row's one-time window, and it is decided INSIDE the
  // UPDATE — never by writing back a timestamp a caller read earlier. A window that a
  // concurrent consumeFirstView NULLs between the caller's read and this write therefore
  // stays spent (`first_view_until = first_view_until` copies the CURRENT value: NULL), and
  // a caller may pass it only when the value it writes equals the row's current value (a
  // NEW value must not become viewable inside an OLD window). Without it the window becomes
  // this write's own: `fvu` is the window a `firstView: true` save just computed (a fresh
  // save — a reinstall reusing an extension_removed row, a re-run first-admin setup — grants
  // its own), NULL otherwise.
  //
  // The keep is also PINNED to the row it was decided on (`secret_sealed = ?`): the keeper
  // compared the value it writes against a blob it read earlier, and another writer can
  // replace that value in between. Sealed blobs carry a random nonce, so an equality match
  // names exactly the row that was read; a replaced blob turns the keep off and the window
  // becomes `fvu`, which is what a value the keeper never looked at must get. The pin is
  // ALWAYS the caller's own blob (`keepFirstViewPinnedTo`, the seal's read) — never the blob
  // this function reads, which would match by construction and defeat the pin — so a keep
  // without one is refused above, before any write. NOT pinned: label/username/url/origin — a
  // stale label is harmless, and this call's metadata is the only one it has to write.
  const keepFirstView = opts.keepFirstView === true;
  const existing = (await db.execute({ sql: "SELECT id, secret_sealed FROM crow_keychain WHERE kind = 'extension' AND bundle_id = ? AND env_key = ?", args: [bundleId, envKey] })).rows[0];
  if (existing) {
    await db.execute({
      sql: `UPDATE crow_keychain SET label = ?, username = ?, url = ?, secret_sealed = ?, key_id = ?, origin = ?, status = 'active',
              connection_uuid = NULL,
              first_view_until = CASE WHEN ? AND secret_sealed = ? THEN first_view_until ELSE ? END, updated_at = ? WHERE id = ?`,
      args: [label, username, url, sealed, key.id, opts.origin, keepFirstView ? 1 : 0, keepFirstView ? opts.keepFirstViewPinnedTo : null, fvu, ts, existing.id],
    });
    return { id: Number(existing.id), created: false };
  }
  const r = await db.execute({
    sql: "INSERT INTO crow_keychain (kind, label, bundle_id, env_key, username, url, secret_sealed, key_id, origin, first_view_until, created_at, updated_at) VALUES ('extension', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
    args: [label, bundleId, envKey, username, url, sealed, key.id, opts.origin, fvu, ts, ts],
  });
  return { id: Number(r.lastInsertRowid), created: true };
}

/**
 * The atomic "first typed key wins" write of one extension row (kind 'extension', bundle id +
 * env key): ONE INSERT … ON CONFLICT on the partial unique index idx_crow_keychain_ext, so two
 * concurrent saves of the same pair can neither both insert (one unique-constraint throw) nor
 * overwrite each other's first value. The DO UPDATE's WHERE leaves an ACTIVE row sealed under the
 * SAME key id untouched; a missing row is inserted; a row that is not active (extension_removed)
 * or sealed under a different key id is overwritten and becomes active. Validation and sealing
 * are saveExtensionSecret's own (reserved id, key required, origin, seal).
 * @returns {Promise<number|null>} the id of the row written, or null when nothing was written —
 *   never the value
 */
export async function rememberExtensionSecret(db, key, opts = {}) {
  const { bundleId, envKey } = opts;
  assertExtensionOwner(bundleId, opts.systemOwner);
  await ensureKeychainTable(db);
  const v = extensionValues(key, opts);
  const r = await db.execute({
    sql: `INSERT INTO crow_keychain (kind, label, bundle_id, env_key, username, url, secret_sealed, key_id, origin, status, first_view_until, created_at, updated_at)
          VALUES ('extension', ?, ?, ?, ?, ?, ?, ?, ?, 'active', ?, ?, ?)
          ON CONFLICT (bundle_id, env_key) WHERE kind = 'extension' DO UPDATE SET
            label = excluded.label, username = excluded.username, url = excluded.url, secret_sealed = excluded.secret_sealed,
            key_id = excluded.key_id, origin = excluded.origin, status = 'active', connection_uuid = NULL,
            first_view_until = excluded.first_view_until, updated_at = excluded.updated_at
          WHERE crow_keychain.status != 'active' OR crow_keychain.key_id != excluded.key_id
          RETURNING id`,
    args: [v.label, bundleId, envKey, v.username, v.url, v.sealed, key.id, opts.origin, v.fvu, v.ts, v.ts],
  });
  return r.rows.length > 0 ? Number(r.rows[0].id) : null;
}

/**
 * A project connection's secret (kind 'service'), keyed by the connection's uuid, never its local
 * id: an id differs between machines, so an imported row could otherwise attach to someone else's
 * connection. Upsert on (connection_uuid, env_key). A row without a uuid is refused (the unique
 * index treats NULL uuids as distinct, so it could not stop duplicates).
 */
export async function saveServiceSecret(db, key, { connectionUuid, bundleId, envKey, label, secret, now } = {}) {
  await ensureKeychainTable(db);
  requireKey(key);
  const uuid = typeof connectionUuid === "string" ? connectionUuid.trim() : "";
  if (!uuid) throw new Error("keychain: a service secret needs a connection uuid");
  // A row without a bundle would never be marked removed on uninstall, and would still be served.
  const bundle = typeof bundleId === "string" ? cleanText(bundleId.trim(), 200) : null;
  if (!bundle) throw new Error("keychain: a service secret needs a bundle id");
  if (!envKey || typeof envKey !== "string" || typeof secret !== "string" || secret === "") throw new Error("keychain: envKey and a secret are required");
  // The row this write lands on is keyed by (kind 'service', connection uuid, env key) and its
  // bundle is this call's: that is the row's FINAL bound identity, so that is its AAD.
  const sealed = sealRow(boundRow("service", bundle, envKey, uuid), key, secret);
  const ts = iso(now);
  const lbl = cleanText(label) || envKey;
  // `created` comes from this pre-read, so two concurrent FIRST saves of one pair may both report
  // created:true. The row itself is still right: ON CONFLICT on the partial unique index makes the
  // second one an update. Callers use `created` for wording only, never for correctness.
  const existing = (await db.execute({ sql: "SELECT id FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ? AND env_key = ?", args: [uuid, envKey] })).rows[0];
  const r = await db.execute({
    sql: `INSERT INTO crow_keychain (kind, label, bundle_id, env_key, secret_sealed, key_id, origin, status, connection_uuid, created_at, updated_at)
          VALUES ('service', ?, ?, ?, ?, ?, 'typed', 'active', ?, ?, ?)
          ON CONFLICT (connection_uuid, env_key) WHERE kind = 'service' DO UPDATE SET
            label = excluded.label, bundle_id = excluded.bundle_id, secret_sealed = excluded.secret_sealed, key_id = excluded.key_id,
            origin = 'typed', status = 'active', first_view_until = NULL, updated_at = excluded.updated_at
          RETURNING id`,
    args: [lbl, bundle, envKey, sealed, key.id, uuid, ts, ts],
  });
  return { id: Number(r.rows[0].id), created: !existing };
}

/**
 * Gateway-internal: a connection's secrets as {envKey: plaintext}, for the connection's own child
 * and live test only (never a response, log or audit row). Only active rows sealed under this key,
 * and only env keys the service itself declares (allowedKeys): any other key on a row is never
 * returned. No uuid or no allowedKeys → {} (fails closed); no rows → {}. A missing key, or rows
 * that exist but none sealed under this key (a crow.db restored without its key file), throws
 * KeychainKeyMissingError (code KEYCHAIN_KEY_MISSING): the fault is the key, not the token, so a
 * caller must not report it as a bad token or spawn a child with no credentials. A row that fails
 * to open is skipped.
 */
export async function serviceSecretsFor(db, key, connectionUuid, { allowedKeys } = {}) {
  await ensureKeychainTable(db);
  if (typeof connectionUuid !== "string" || connectionUuid === "" || !Array.isArray(allowedKeys) || allowedKeys.length === 0) return {};
  if (!key || typeof key.id !== "string" || !Buffer.isBuffer(key.seed)) throw new KeychainKeyMissingError();
  const allowed = new Set(allowedKeys.filter((k) => typeof k === "string" && k));
  const { rows } = await db.execute({
    sql: `SELECT env_key, key_id, secret_sealed, ${BOUND_COLS} FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ? AND status = 'active' ORDER BY id`,
    args: [connectionUuid],
  });
  const mine = rows.filter((r) => r.key_id === key.id);
  if (rows.length > 0 && mine.length === 0) throw new KeychainKeyMissingError();
  const legacyRefused = await eraConvertedAsync(db, eraDirOf());
  const out = {};
  for (const r of mine) {
    if (!allowed.has(r.env_key)) continue;
    try {
      const v = openSealedRow(r, key, { legacyRefused, alarm: (row) => raiseLegacyFormAlarmAsync(db, row) });
      if (typeof v === "string" && v) out[r.env_key] = v;
    } catch { /* damaged or refused row: skip, never log */ }
  }
  return out;
}

/**
 * Gateway-internal: the keys the owner saved for a whole service (kind 'extension', one row per
 * bundle id + env key), as {envKey: plaintext}. Only the connect route reads this, and only for
 * a request the owner made with useSavedKey: the service's own declared env keys are the only
 * ones returned (allowedKeys), never a row's other key. Active rows only: an
 * uninstall (extension_removed) or a deleted row leaves nothing to read. No bundle id, no
 * allowedKeys or no rows → {}. A missing key, or rows that exist but none sealed under this key
 * (a crow.db restored without its key file), throws KeychainKeyMissingError (code
 * KEYCHAIN_KEY_MISSING), the same way serviceSecretsFor does: the fault is the key, not the
 * token. A row that fails to open is skipped, never logged.
 */
export async function extensionSecretsFor(db, key, bundleId, allowedKeys) {
  await ensureKeychainTable(db);
  if (typeof bundleId !== "string" || bundleId === "" || isSystemBundleId(bundleId) || !Array.isArray(allowedKeys) || allowedKeys.length === 0) return {};
  if (!key || typeof key.id !== "string" || !Buffer.isBuffer(key.seed)) throw new KeychainKeyMissingError();
  const allowed = new Set(allowedKeys.filter((k) => typeof k === "string" && k));
  const { rows } = await db.execute({
    sql: `SELECT env_key, key_id, secret_sealed, ${BOUND_COLS} FROM crow_keychain WHERE kind = 'extension' AND bundle_id = ? AND status = 'active' ORDER BY id`,
    args: [bundleId],
  });
  const mine = rows.filter((r) => r.key_id === key.id);
  if (rows.length > 0 && mine.length === 0) throw new KeychainKeyMissingError();
  const legacyRefused = await eraConvertedAsync(db, eraDirOf());
  const out = {};
  for (const r of mine) {
    if (!allowed.has(r.env_key)) continue;
    try {
      const v = openSealedRow(r, key, { legacyRefused, alarm: (row) => raiseLegacyFormAlarmAsync(db, row) });
      if (typeof v === "string" && v) out[r.env_key] = v;
    } catch { /* damaged or refused row: skip, never log */ }
  }
  return out;
}

/**
 * An add-on's listed env keys, SYNCHRONOUSLY, from a better-sqlite3 handle: `{envKey: plaintext}`
 * for every requested name, or a throw (0.4 — never a partial env, never a fallback).
 *
 * Only active rows of this kind and bundle id are candidates; `key` must be the keychain key
 * (a missing/invalid one is KeychainKeyMissingError). A requested name that has no row, a row
 * under a DIFFERENT key id, a row that fails openSecret, or one that opens to "" fails the
 * whole read with KeychainRowsMissingError(names) — every requested name, so a caller can list
 * them. A missing table or an unreadable DB is the same error (nothing to prove). A system
 * bundle id (offsite-backup) and an empty name list yield {} before the key is even looked at.
 *
 * Callers: servers/shared/addon-secrets.js readAddonSecretsSync (spawn hydration, the Bot
 * Builder probe, the seal's and the migration's read-back proofs); the satellite agent's
 * reader. There is no async equivalent for a plaintext add-on secret.
 *
 * `eraDir` names the SECRETS dir whose era state file decides whether an `enc:v1:` row is
 * still openable; addon-secrets.js passes `dirname(keyPath)`, which is the same dir for a plain
 * path, the pibot host's anchored `/proc/self/fd/<N>` path and the satellite's own key path.
 */
export function extensionSecretsSync(rawDb, key, bundleId, names, { kind = "extension", eraDir = null } = {}) {
  const wanted = [...new Set((Array.isArray(names) ? names : []).filter((n) => typeof n === "string" && n !== ""))];
  if (typeof bundleId !== "string" || bundleId === "" || isSystemBundleId(bundleId) || wanted.length === 0) return {};
  requireKey(key);
  let rows;
  try {
    rows = rawDb.prepare(`SELECT env_key, key_id, secret_sealed, ${BOUND_COLS} FROM crow_keychain WHERE kind = ? AND bundle_id = ? AND status = 'active'`).all(kind, bundleId);
  } catch {
    throw new KeychainRowsMissingError(wanted);
  }
  const legacyRefused = eraConvertedSync(rawDb, eraDir ?? eraDirOf());
  const byName = new Map();
  for (const r of rows) if (r && typeof r.env_key === "string") byName.set(r.env_key, r);
  const out = {};
  for (const name of wanted) {
    const r = byName.get(name);
    if (!r || r.key_id !== key.id) throw new KeychainRowsMissingError(wanted);
    let v;
    try {
      v = openSealedRow(r, key, { legacyRefused, alarm: (row) => raiseLegacyFormAlarmSync(rawDb, row) });
    } catch {
      throw new KeychainRowsMissingError(wanted);
    }
    if (typeof v !== "string" || v === "") throw new KeychainRowsMissingError(wanted);
    out[name] = v;
  }
  return out;
}

/**
 * The env key names a connection has a secret saved for, from metadata only: nothing is decrypted
 * and no key is needed (for a set/unset view). Every saved row counts whatever its key or an
 * uninstall (needs_install, key_missing are the connection's status, not this answer), except a
 * disconnected row: that one is kept only so its value stays masked, and is never served.
 */
export async function serviceSecretKeys(db, connectionUuid) {
  await ensureKeychainTable(db);
  if (typeof connectionUuid !== "string" || connectionUuid === "") return new Set();
  const { rows } = await db.execute({ sql: "SELECT env_key FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ? AND env_key IS NOT NULL AND status != 'disconnected'", args: [connectionUuid] });
  return new Set(rows.map((r) => r.env_key));
}

/**
 * Disconnect: every secret row of one connection becomes status 'disconnected' (never deleted
 * here). Such a row is never served (serviceSecretsFor reads active rows only, serviceSecretKeys
 * skips it) and never reactivated by a reinstall (reactivateBundleEntries reads extension_removed
 * only), but the masking reader (readableSecretsSync) still opens it, so a value the operator saved
 * stays hidden in logs and on approval cards. The owner purges it for good from the keychain page
 * (deleteEntry allows a disconnected service row). Safe to repeat.
 */
export async function disconnectServiceSecrets(db, connectionUuid) {
  await ensureKeychainTable(db);
  if (typeof connectionUuid !== "string" || connectionUuid === "") return { disconnected: 0 };
  const r = await db.execute({
    sql: "UPDATE crow_keychain SET status = 'disconnected', first_view_until = NULL, updated_at = ? WHERE kind = 'service' AND connection_uuid = ? AND status != 'disconnected'",
    args: [iso(), connectionUuid],
  });
  return { disconnected: r.rowsAffected };
}

/** Removes every secret of one connection (a connect that failed part way: undoCreate). */
export async function deleteServiceSecrets(db, connectionUuid) {
  await ensureKeychainTable(db);
  if (typeof connectionUuid !== "string" || connectionUuid === "") return { deleted: 0 };
  const r = await db.execute({ sql: "DELETE FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ?", args: [connectionUuid] });
  return { deleted: r.rowsAffected };
}

/**
 * Removes ONE secret of one connection: the key a re-keyed grant no longer has (a fresh OAuth grant
 * that names no client secret must not keep the old registration's). Idempotent; no key is needed,
 * because nothing is unsealed.
 *
 * The delete is scoped to the BUNDLE as well as the connection uuid and the env key (Crow Mail's rows
 * are `crow-mail`), so a row another bundle wrote under the same uuid is never removed by a mail
 * re-key: the read and the upsert are by (kind, uuid, env key), so without this one a project
 * connection whose uuid happened to equal an account id could lose its own secret here.
 * `bundleId` is the caller's own id, defaulting to Crow Mail's, the only bundle this function serves.
 */
export async function deleteServiceSecret(db, connectionUuid, envKey, { bundleId = MAIL_BUNDLE } = {}) {
  await ensureKeychainTable(db);
  if (typeof connectionUuid !== "string" || connectionUuid === "") return { deleted: 0 };
  if (typeof envKey !== "string" || envKey === "") return { deleted: 0 };
  const bundle = typeof bundleId === "string" && bundleId !== "" ? bundleId : MAIL_BUNDLE;
  const r = await db.execute({
    sql: "DELETE FROM crow_keychain WHERE kind = 'service' AND connection_uuid = ? AND env_key = ? AND bundle_id = ?",
    args: [connectionUuid, envKey, bundle],
  });
  return { deleted: r.rowsAffected };
}

export async function addManualSecret(db, key, { label, username = null, url = null, secret }) {
  await ensureKeychainTable(db);
  requireKey(key);
  if (!cleanText(label) || typeof secret !== "string" || secret === "") throw new Error("keychain: a label and a secret are required");
  const ts = iso();
  const r = await db.execute({
    sql: "INSERT INTO crow_keychain (kind, label, username, url, secret_sealed, key_id, origin, created_at, updated_at) VALUES ('manual', ?, ?, ?, ?, ?, 'manual', ?, ?)",
    args: [cleanText(label), cleanText(username), cleanText(url, 2048), sealRow(boundRow("manual", null, null, null), key, secret), key.id, ts, ts],
  });
  return { id: Number(r.lastInsertRowid) };
}

export async function listEntries(db, { now, keyId = null } = {}) {
  await ensureKeychainTable(db);
  const { rows } = await db.execute(`SELECT ${META_COLS} FROM crow_keychain ORDER BY status ASC, label COLLATE NOCASE ASC, id ASC`);
  return rows.map((r) => toEntry(r, { now, keyId }));
}

export async function getEntry(db, id, { now, keyId = null } = {}) {
  await ensureKeychainTable(db);
  const { rows } = await db.execute({ sql: `SELECT ${META_COLS} FROM crow_keychain WHERE id = ?`, args: [Number(id)] });
  return toEntry(rows[0], { now, keyId });
}

export async function pendingFirstViews(db, { now, keyId = null } = {}) {
  await ensureKeychainTable(db);
  const { rows } = await db.execute({ sql: `SELECT ${META_COLS} FROM crow_keychain WHERE first_view_until IS NOT NULL AND first_view_until > ? ORDER BY id`, args: [iso(now)] });
  return rows.map((r) => toEntry(r, { now, keyId })).filter((e) => e.readable);
}

async function sealedRow(db, id) {
  const { rows } = await db.execute({ sql: `SELECT secret_sealed, key_id, ${BOUND_COLS} FROM crow_keychain WHERE id = ?`, args: [Number(id)] });
  return rows[0] || null;
}

/** Plaintext; null when the id does not exist; KeychainKeyMissingError when sealed under another key. */
export async function openEntrySecret(db, key, id) {
  await ensureKeychainTable(db);
  const row = await sealedRow(db, id);
  if (!row) return null;
  if (!key || row.key_id !== key.id) throw new KeychainKeyMissingError();
  const legacyRefused = await eraConvertedAsync(db, eraDirOf());
  return openSealedRow(row, key, { legacyRefused, alarm: (r) => raiseLegacyFormAlarmAsync(db, r) });
}

/** Atomically spends a live first-view grant. Plaintext once, then null forever. */
export async function consumeFirstView(db, key, id, { now } = {}) {
  await ensureKeychainTable(db);
  const row = await sealedRow(db, id);
  if (row && (!key || row.key_id !== key.id)) throw new KeychainKeyMissingError();
  // A refused row is refused BEFORE its window is spent: a v1 blob after the era is not a
  // value anybody may look at, and burning the grant would hide that from the owner.
  const legacyRefused = await eraConvertedAsync(db, eraDirOf());
  if (row && isSealedV1(row.secret_sealed) && legacyRefused) {
    try { await raiseLegacyFormAlarmAsync(db, row); } catch { /* see openSealedRow */ }
    throw new KeychainLegacyFormError();
  }
  const { rows } = await db.execute({
    sql: `UPDATE crow_keychain SET first_view_until = NULL WHERE id = ? AND first_view_until IS NOT NULL AND first_view_until > ? RETURNING secret_sealed, ${BOUND_COLS}`,
    args: [Number(id), iso(now)],
  });
  if (!rows[0]) return null;
  return openSealedRow(rows[0], key, { legacyRefused });
}

/**
 * Deletes one entry. A service row of a live (not-disconnected) connection is refused (KeychainServiceRowError):
 * disconnect its connection first. A disconnected service row may be deleted: that is how the
 * owner purges a disconnected connection's secret for good (it then stops being masked).
 *
 * A Crow Mail password is refused outright (KeychainMailRowError), before either rule above runs:
 * its connection is a `mail_accounts` row, so the orphan rule below would call it purgeable and a
 * delete here would silently break the account. It is removed only with its account.
 */
export async function deleteEntry(db, id) {
  await ensureKeychainTable(db);
  const mail = await db.execute({ sql: "SELECT 1 AS mail FROM crow_keychain WHERE id = ? AND bundle_id = ?", args: [Number(id), MAIL_BUNDLE] });
  if (mail.rows.length > 0) throw new KeychainMailRowError();
  // An orphan (its connection row is gone, e.g. a project was deleted) is purgeable like a disconnected one.
  const hasConnections = (await db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'service_connections'")).rows.length > 0;
  const orphan = hasConnections
    ? "NOT EXISTS (SELECT 1 FROM service_connections c WHERE c.uuid = crow_keychain.connection_uuid AND c.status != 'disconnected')"
    : "0"; // no table: nothing proves it an orphan
  const r = await db.execute({ sql: `DELETE FROM crow_keychain WHERE id = ? AND (kind != 'service' OR status = 'disconnected' OR ${orphan})`, args: [Number(id)] });
  if (r.rowsAffected > 0) return true;
  const svc = await db.execute({ sql: "SELECT 1 FROM crow_keychain WHERE id = ? AND kind = 'service'", args: [Number(id)] });
  if (svc.rows.length) throw new KeychainServiceRowError();
  return false;
}

export async function markBundleRemoved(db, bundleId) {
  // A caller that does not check (the satellite's install and uninstall) still never touches Crow's own rows.
  if (isSystemBundleId(bundleId)) return 0;
  await ensureKeychainTable(db);
  const r = await db.execute({ sql: "UPDATE crow_keychain SET status = 'extension_removed', first_view_until = NULL, updated_at = ? WHERE kind IN ('extension', 'service') AND bundle_id = ? AND status = 'active'", args: [iso(), bundleId] });
  return r.rowsAffected;
}

/** Whether an extension entry (any status) exists for bundle+key. */
export async function hasExtensionEntry(db, bundleId, envKey) {
  await ensureKeychainTable(db);
  const r = await db.execute({ sql: "SELECT 1 FROM crow_keychain WHERE kind = 'extension' AND bundle_id = ? AND env_key = ? LIMIT 1", args: [bundleId, envKey] });
  return r.rows.length > 0;
}

export async function reactivateBundleEntries(db, bundleId, envKeys) {
  if (isSystemBundleId(bundleId)) return 0; // Crow's own rows are never an add-on's to revive
  await ensureKeychainTable(db);
  let n = 0;
  for (const k of envKeys || []) {
    const r = await db.execute({ sql: "UPDATE crow_keychain SET status = 'active', updated_at = ? WHERE kind = 'extension' AND bundle_id = ? AND env_key = ? AND status = 'extension_removed'", args: [iso(), bundleId, k] });
    n += r.rowsAffected;
  }
  // A reinstall brings back every project connection's secrets for this bundle.
  const svc = await db.execute({ sql: "UPDATE crow_keychain SET status = 'active', updated_at = ? WHERE kind = 'service' AND bundle_id = ? AND status = 'extension_removed'", args: [iso(), bundleId] });
  return n + svc.rowsAffected;
}

/** Every READABLE entry with its plaintext, for the user's passphrase-encrypted Export. A panel-only
 *  connection's secret is its own bundle panel's and never leaves here.
 *
 *  One refused (`enc:v1:` after the era, a v2 value in a spelling this release never wrote, or a
 *  legacy row under another key) or damaged row must not cost the owner the whole Export: it is
 *  SKIPPED and every other entry still leaves. `onSkipped` gets the COUNT and the IDS of the rows
 *  left out, so the caller can keep them out of the Export's fingerprint snapshot (a row that is
 *  not in the file must not read "exported") as well as log a count (this module logs nothing at
 *  all: a value or a row detail must never reach a log through the store); the export result keeps
 *  its shape, so no user-visible text changes. */
export async function exportableEntries(db, key, { onSkipped = null } = {}) {
  requireKey(key);
  const out = [];
  const skippedIds = [];
  for (const e of await listEntries(db, { keyId: key.id })) {
    if (!e.readable) continue;
    if (e.kind === "service" && await isPanelConnectionSecret(db, e)) continue;
    let secret;
    try {
      secret = await openEntrySecret(db, key, e.id);
    } catch {
      skippedIds.push(Number(e.id));
      continue;
    }
    if (typeof secret !== "string" || secret === "") { skippedIds.push(Number(e.id)); continue; }
    out.push({ kind: e.kind, label: e.label, bundle_id: e.bundle_id, env_key: e.env_key, username: e.username, url: e.url, origin: e.origin, status: e.status, connection_uuid: e.connection_uuid || null, secret });
  }
  if (skippedIds.length > 0 && typeof onSkipped === "function") {
    try { onSkipped(skippedIds.length, skippedIds); } catch { /* reporting never fails an export */ }
  }
  return out;
}

/**
 * Is this a keychain kind 'service' row a panel-only service (connect.method "panel") owns? Such
 * a secret is read only by its own bundle panel (service-connections.js panelSecretsFor), so the
 * keychain UI neither reveals, copies, vault-saves nor exports it.
 *
 * It fails CLOSED: the row's OWN bundle id answers first, so a panel bundle's secret is still a
 * panel's when its connection row is gone (an orphaned row) or when the row was re-pointed at a
 * connection that is not a panel one. Then the connection row (when the row names one): its own
 * `method` column first, the catalog for an older row.
 * @param {object} db
 * @param {{connection_uuid?: string|null, bundle_id?: string|null}|string} entry the keychain entry
 *   (its connection_uuid and bundle_id); a bare uuid is read as before, without the bundle check
 * @returns {Promise<boolean>}
 */
export async function isPanelConnectionSecret(db, entry) {
  const e = typeof entry === "string" ? { connection_uuid: entry } : (entry || {});
  const bundleId = typeof e.bundle_id === "string" ? e.bundle_id : "";
  if (bundleId) {
    const owner = serviceById(bundleId);
    if (owner && isPanelService(owner)) return true;
  }
  const connectionUuid = e.connection_uuid;
  if (typeof connectionUuid !== "string" || connectionUuid === "") return false;
  const hasTable = (await db.execute("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'service_connections'")).rows.length > 0;
  if (!hasTable) return false;
  const r = (await db.execute({ sql: "SELECT service_id, method FROM service_connections WHERE uuid = ?", args: [connectionUuid] })).rows[0];
  if (!r) return false;
  if (r.method === "panel") return true;
  const service = serviceById(r.service_id);
  return !!service && isPanelService(service);
}

/**
 * Every readable entry's plaintext, SYNCHRONOUSLY, from a better-sqlite3 handle (the bot
 * engine's driver). Only for the bot secret-values file (servers/shared/secret-values-collect.js),
 * which hides these values from approval cards and pushes; never returned to a client.
 * Rows sealed under another key, a missing table, or a row that fails to open are skipped.
 */
export function readableSecretsSync(rawDb, key, { eraDir = null } = {}) {
  if (!key || typeof key.id !== "string" || !Buffer.isBuffer(key.seed)) return [];
  let rows;
  try {
    rows = rawDb.prepare(`SELECT id, kind, label, secret_sealed, ${BOUND_COLS} FROM crow_keychain WHERE key_id = ?`).all(key.id);
  } catch {
    return [];
  }
  const legacyRefused = eraConvertedSync(rawDb, eraDir ?? eraDirOf());
  const out = [];
  for (const r of rows) {
    try {
      const v = openSealedRow(r, key, { legacyRefused, alarm: (row) => raiseLegacyFormAlarmSync(rawDb, row) });
      if (typeof v === "string" && v) out.push({ id: Number(r.id), kind: r.kind, label: r.label, secret: v });
    } catch { /* damaged or refused row: skip */ }
  }
  return out;
}

/**
 * The ids of this key's rows the era REFUSES: an `enc:v1:` blob after the conversion. Such a
 * row is unreadable for every purpose that decides whether a row already HOLDS a value (an
 * Import restoring an Export over it). Empty before the era, when v1 still opens.
 */
async function refusedLegacyIds(db, key) {
  if (!(await eraConvertedAsync(db, eraDirOf()))) return new Set();
  const { rows } = await db.execute({ sql: "SELECT id FROM crow_keychain WHERE key_id = ? AND substr(secret_sealed, 1, 7) = 'enc:v1:'", args: [key.id] });
  return new Set(rows.map((r) => Number(r.id)));
}

/**
 * Import entries from a decrypted Export. Never overwrites a READABLE entry: an extension
 * entry whose bundle+key already has a readable row is skipped, and so is a manual entry
 * with the same label+username+url as a readable one. Unreadable rows (old key) for the
 * same bundle+key ARE replaced — that is the "restored on a new machine" recovery path.
 * A service entry keeps its connection_uuid as is and is matched on (uuid, env_key) only: it is
 * never attached to a local connection by id or label. A uuid no local connection has stays
 * unattached for good (uuids are never reused), so its secret reaches no child.
 *
 * A row the era REFUSES (`enc:v1:` after the conversion) counts as UNREADABLE here, so an
 * Export restores over it instead of being skipped as "already saved".
 */
export async function importEntries(db, key, entries) {
  requireKey(key);
  const current = await listEntries(db, { keyId: key.id });
  const refused = await refusedLegacyIds(db, key);
  const readableRow = (c) => c.readable && !refused.has(Number(c.id));
  let imported = 0;
  let skipped = 0;
  const ids = [];
  for (let e of Array.isArray(entries) ? entries : []) {
    // A non-http(s) url is dropped (not the entry) so an otherwise-good export still imports.
    if (e && typeof e.url === "string" && e.url && !/^https?:\/\//i.test(e.url)) e = { ...e, url: null };
    if (!e || typeof e.secret !== "string" || e.secret === "" || !KINDS.has(e.kind) || !cleanText(e.label)) { skipped++; continue; }
    if (e.kind === "extension") {
      if (!e.bundle_id || !e.env_key) { skipped++; continue; }
      if (current.some((c) => c.kind === "extension" && c.bundle_id === e.bundle_id && c.env_key === e.env_key && readableRow(c))) { skipped++; continue; }
      const origin = e.origin === "generated" ? "generated" : "typed";
      // The owner's re-authenticated import of their own export is the recovery path, so it may
      // bring back a Crow-owned entry (the off-site key); add-on paths never may.
      const { id } = await saveExtensionSecret(db, key, { bundleId: e.bundle_id, envKey: e.env_key, label: e.label, username: e.username, url: e.url, secret: e.secret, origin, systemOwner: isSystemBundleId(e.bundle_id) });
      if (e.status === "extension_removed") await db.execute({ sql: "UPDATE crow_keychain SET status = 'extension_removed' WHERE id = ?", args: [id] });
      ids.push(id);
      imported++;
    } else if (e.kind === "service") {
      const uuid = typeof e.connection_uuid === "string" ? e.connection_uuid.trim() : "";
      if (!uuid || !e.env_key || !e.bundle_id) { skipped++; continue; }
      if (current.some((c) => c.kind === "service" && c.connection_uuid === uuid && c.env_key === e.env_key && readableRow(c))) { skipped++; continue; }
      const { id } = await saveServiceSecret(db, key, { connectionUuid: uuid, bundleId: e.bundle_id || null, envKey: e.env_key, label: e.label, secret: e.secret });
      // A disconnected row stays disconnected (never served) after an import, as an uninstalled one stays removed.
      if (e.status === "extension_removed" || e.status === "disconnected") await db.execute({ sql: "UPDATE crow_keychain SET status = ? WHERE id = ?", args: [e.status, id] });
      ids.push(id);
      imported++;
    } else {
      const dup = current.some((c) => c.kind === "manual" && readableRow(c) && c.label === cleanText(e.label) && (c.username || null) === cleanText(e.username) && (c.url || null) === cleanText(e.url, 2048));
      if (dup) { skipped++; continue; }
      await addManualSecret(db, key, { label: e.label, username: e.username, url: e.url, secret: e.secret });
      imported++;
    }
  }
  return { imported, skipped, ids };
}
