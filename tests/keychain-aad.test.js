/**
 * The keychain's AAD envelope (secret-box v2) and its conversion era.
 *
 * What this file pins, in the order the bug report asked for it:
 *
 *   1. THE RED TEST. A bot with raw `crow.db` access copies a Mail-style `service` row's blob
 *      (and a `manual` row's, another add-on's, and a sibling env key's) into its own add-on's
 *      `extension` row. After the conversion the real pibot read path
 *      (`servers/shared/addon-secrets.js` readAddonSecretsSync → extensionSecretsSync) must NOT
 *      return that password: the copied blob is bound to the row it came from.
 *   2. A swap of a row's BOUND columns (bundle id / env key) is refused for the same reason.
 *   3. An old-style (`enc:v1:`) row AFTER the era is refused like an unreadable one, recorded
 *      as `keychain_legacy_form` and reported once in the bell; before the era it still opens.
 *   4. The boot converter: happy path (every kind and status, a foreign-key row untouched), a
 *      no-op second boot, a rolled-back verify failure, a crash between the commit and the
 *      marker (a post-snapshot v1 write is not laundered), a refused state file (symlink/0666),
 *      the DB mirror on its own, a missing key (skipped, not marked) and a fresh install.
 *   5. Round trips through every store.js function that seals or opens, after the era.
 *   6. secret-box v2 unit behaviour.
 *   7. The operator dry-run tool: PASS, and STOP when a row fails to verify.
 *
 * Every fixture is a scratch instance under os.tmpdir() (CROW_HOME per test, a real keychain
 * key, a copy of the repo's own init-db database). Nothing here touches ~/.crow, and no test
 * prints, names or asserts a secret value.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import {
  chmodSync, closeSync, constants as fsConstants, existsSync, lstatSync, mkdirSync, mkdtempSync,
  openSync, readFileSync, readdirSync, statSync, symlinkSync, unlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { randomUUID } from "node:crypto";
import Database from "better-sqlite3";
import { rmScratch } from "./helpers/safe-rm.js";

const REPO = join(import.meta.dirname, "..");
const SENTINEL = "sentinel-" + randomUUID();
const MAIL_PW = "sentinel-" + randomUUID();
const OTHER_PW = "sentinel-" + randomUUID();

// One pristine instance database for the whole file: init-db's real schema (crow_keychain,
// audit_log, notifications, dashboard_settings and its overrides table).
const FILE_HOME = mkdtempSync(join(tmpdir(), "crow-kc-aad-file-"));
const PRISTINE_DATA = join(FILE_HOME, "pristine");
mkdirSync(PRISTINE_DATA, { recursive: true, mode: 0o700 });
process.env.CROW_HOME = FILE_HOME;
execFileSync(process.execPath, ["scripts/init-db.js"], {
  env: { ...process.env, CROW_HOME: FILE_HOME, CROW_DATA_DIR: PRISTINE_DATA },
  stdio: "pipe",
  cwd: REPO,
});
const PRISTINE_DB = join(PRISTINE_DATA, "crow.db");
delete process.env.CROW_DATA_DIR;
delete process.env.CROW_DB_PATH;

const SB = await import("../servers/sharing/secret-box.js");
const { createKeychainKey, keychainKeyPath } = await import("../servers/gateway/keychain/key.js");
const K = await import("../servers/gateway/keychain/store.js");
const { runKeychainAadBoot } = await import("../servers/gateway/boot/keychain-aad.js");
const ERA = await import("../servers/gateway/keychain/aad-era.js");
const { readAddonSecretsSync } = await import("../servers/shared/addon-secrets.js");
const { sealEntrySecrets } = await import("../servers/gateway/addon-secrets-seal.js");
const { sealExport, openExport } = await import("../servers/gateway/keychain/export.js");

const DRY_RUN = join(REPO, "scripts", "ops", "keychain-aad-dryrun.mjs");
const DOWNGRADE = join(REPO, "scripts", "ops", "keychain-aad-downgrade.mjs");

after(() => {
  try { rmScratch(FILE_HOME); } catch { /* already gone */ }
});

/** better-sqlite3 behind the small async libsql surface the keychain store uses. */
function libsql(raw) {
  return {
    async execute(q) {
      const { sql, args = [] } = typeof q === "string" ? { sql: q } : q;
      const st = raw.prepare(sql);
      if (st.reader) return { rows: st.all(...args) };
      const r = st.run(...args);
      return { rows: [], lastInsertRowid: r.lastInsertRowid, rowsAffected: r.changes };
    },
    async executeMultiple(sql) { raw.exec(sql); },
  };
}

/**
 * A scratch instance: a copy of the pristine crow.db, a scratch CROW_HOME, and (unless
 * `key: false`) a real keychain key. The home is a CONSTANT per test, so cleanup can never be
 * pointed anywhere else.
 */
async function instance(t, { key = true } = {}) {
  const home = mkdtempSync(join(tmpdir(), "crow-kc-aad-"));
  const dataDir = join(home, "data");
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const dbPath = join(dataDir, "crow.db");
  const source = new Database(PRISTINE_DB, { readonly: true, fileMustExist: true });
  try { await source.backup(dbPath); } finally { source.close(); }
  const raw = new Database(dbPath);
  raw.pragma("busy_timeout = 5000");
  const savedHome = process.env.CROW_HOME;
  process.env.CROW_HOME = home;
  ERA._resetAadStateCacheForTest();
  t.after(() => {
    process.env.CROW_HOME = savedHome;
    ERA._resetAadStateCacheForTest();
    try { raw.close(); } catch { /* already closed */ }
    try { rmScratch(home); } catch { /* already gone */ }
  });
  const kcKey = key ? createKeychainKey({ crowHome: home }) : null;
  return {
    home, dataDir, dbPath, raw, key: kcKey, keyPath: keychainKeyPath(home), db: libsql(raw),
    secretsDir: join(home, "secrets"),
    statePath: ERA.keychainAadStatePath(join(home, "secrets")),
  };
}

const addonRead = (ctx, bundleId, names) => readAddonSecretsSync(bundleId, names, {
  unsealer: "gateway", dbPath: ctx.dbPath, keyPath: ctx.keyPath,
});

const blobOf = (ctx, id) => ctx.raw.prepare("SELECT secret_sealed FROM crow_keychain WHERE id = ?").get(id).secret_sealed;
const rowsMissing = (e) => e && e.code === "ROWS_MISSING";
const v1For = (ctx, value) => SB.sealSecret(value, { seed: ctx.key.seed });

/** Rewrite one row's blob to the OLD (v1) form, as a database from before the upgrade holds it. */
function setV1(ctx, id, value) {
  ctx.raw.prepare("UPDATE crow_keychain SET secret_sealed = ? WHERE id = ?").run(v1For(ctx, value), id);
}

/** Insert a v1 (old-style) row directly, as a pre-era Crow or a bot would have left it. */
function insertV1(ctx, { kind = "extension", bundleId = "v1addon", envKey = "V1_KEY", label = "v1", uuid = null, value = SENTINEL, keyId = null, keySeed = null } = {}) {
  const sealed = SB.sealSecret(value, { seed: keySeed || ctx.key.seed });
  const r = ctx.raw.prepare(
    `INSERT INTO crow_keychain (kind, label, bundle_id, env_key, secret_sealed, key_id, origin, status, connection_uuid)
     VALUES (?, ?, ?, ?, ?, ?, 'typed', 'active', ?)`,
  ).run(kind, label, bundleId, envKey, sealed, keyId || ctx.key.id, uuid);
  return { id: Number(r.lastInsertRowid), sealed };
}

const runBoot = (ctx, extra = {}) => runKeychainAadBoot({ dbPath: ctx.dbPath, crowHome: ctx.home, mirror: false, log: () => {}, ...extra });

// ─── 6. secret-box v2 itself ────────────────────────────────────────────────

test("secret-box v2: a round trip needs the same AAD; the form prefixes never open each other", () => {
  const identity = { seed: Buffer.alloc(32, 9) };
  const aad = Buffer.from("row-a", "utf8");
  const sealed = SB.sealSecretBound("hunter2", identity, aad);
  assert.match(sealed, /^enc:v2:/);
  assert.equal(SB.openSecretBound(sealed, identity, aad), "hunter2");
  assert.throws(() => SB.openSecretBound(sealed, identity, Buffer.from("row-b", "utf8")), /unable to authenticate|bad decrypt|authenticate/i);

  const v1 = SB.sealSecret("hunter2", identity);
  assert.match(v1, /^enc:v1:/);
  assert.equal(SB.isSealed(v1), true);
  assert.equal(SB.isSealed(sealed), true);
  assert.equal(SB.isSealedV1(v1), true);
  assert.equal(SB.isSealedV2(sealed), true);
  assert.equal(SB.isSealedV2(v1), false);

  // The two openers are not interchangeable, and neither answers null for the other's form.
  assert.throws(() => SB.openSecret(sealed, identity), /openSecretBound/);
  assert.throws(() => SB.openSecretBound(v1, identity, aad), /enc:v1/);

  // An empty / missing AAD is refused on both sides: a v2 blob with no AAD is a v1 blob.
  for (const bad of ["", Buffer.alloc(0), null, undefined, 42]) {
    assert.throws(() => SB.sealSecretBound("x", identity, bad), /aad/i);
    assert.throws(() => SB.openSecretBound(sealed, identity, bad), /aad/i);
  }

  // v1 stays byte-compatible: the same key opens a v1 blob sealed the old way, with no AAD.
  assert.equal(SB.openSecret(v1, identity), "hunter2");
});

// ─── 1. the red test: a copied blob opens nothing ────────────────────────────

test("RED: a bot that copies another row's blob into its add-on's row gets no password after the conversion", async (t) => {
  const ctx = await instance(t);
  const key = ctx.key;

  const mail = await K.saveServiceSecret(ctx.db, key, {
    connectionUuid: "ma-0123456789abcdef", bundleId: "crow-mail", envKey: "MAIL_PASSWORD",
    label: "Mail: alex@example.com", secret: MAIL_PW,
  });
  const manual = await K.addManualSecret(ctx.db, key, { label: "Phone", secret: OTHER_PW });
  const b = await K.saveExtensionSecret(ctx.db, key, { bundleId: "addon-b", envKey: "BAR", label: "B BAR", secret: "b-value", origin: "typed" });
  // The bot's own add-on, with the env keys it will try to launder a blob into.
  for (const envKey of ["FOO", "FOO_MANUAL", "FOO_OTHER", "FOO_SIBLING"]) {
    await K.saveExtensionSecret(ctx.db, key, { bundleId: "addon-a", envKey, label: `A ${envKey}`, secret: `a-${envKey}`, origin: "typed" });
  }
  const siblingSource = await K.saveExtensionSecret(ctx.db, key, { bundleId: "addon-a", envKey: "SIBLING_SOURCE", label: "A sibling", secret: "sibling-value", origin: "typed" });

  const converted = await runBoot(ctx);
  assert.equal(existsSync(ctx.statePath), true, "the era is recorded");
  assert.ok(["converted", "marked"].includes(converted.state));

  const copyInto = (envKey, sourceId) => {
    ctx.raw.prepare(
      `UPDATE crow_keychain SET secret_sealed = (SELECT secret_sealed FROM crow_keychain WHERE id = ?),
              key_id = (SELECT key_id FROM crow_keychain WHERE id = ?)
        WHERE kind = 'extension' AND bundle_id = 'addon-a' AND env_key = ?`,
    ).run(sourceId, sourceId, envKey);
  };

  // THE attack the report describes: a Mail password into the bot's own add-on.
  copyInto("FOO", mail.id);
  assert.throws(() => addonRead(ctx, "addon-a", ["FOO"]), rowsMissing, "the Mail password is never handed to the bot");
  // A human 'manual' password.
  copyInto("FOO_MANUAL", manual.id);
  assert.throws(() => addonRead(ctx, "addon-a", ["FOO_MANUAL"]), rowsMissing);
  // Another add-on's secret.
  copyInto("FOO_OTHER", b.id);
  assert.throws(() => addonRead(ctx, "addon-a", ["FOO_OTHER"]), rowsMissing);
  // The same add-on's other env key.
  copyInto("FOO_SIBLING", siblingSource.id);
  assert.throws(() => addonRead(ctx, "addon-a", ["FOO_SIBLING"]), rowsMissing);

  // The legitimate rows still read: the refusal is the copy, not the reader.
  assert.deepEqual(addonRead(ctx, "addon-b", ["BAR"]), { BAR: "b-value" });

  // And the audit/bell rows never carry a value.
  const audit = ctx.raw.prepare("SELECT details FROM audit_log WHERE event_type = 'keychain_legacy_form'").all();
  for (const row of audit) {
    assert.equal(String(row.details).includes(MAIL_PW) || String(row.details).includes(OTHER_PW), false);
  }
});

test("RED: a bound-column swap (bundle id / env key) is refused after the conversion", async (t) => {
  const ctx = await instance(t);
  await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed" });
  await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-b", envKey: "BAR", label: "B BAR", secret: "b-value", origin: "typed" });
  assert.equal((await runBoot(ctx)).state, "converted");

  // Point A/FOO's row at the bot's add-on.
  ctx.raw.prepare("UPDATE crow_keychain SET bundle_id = 'addon-b', env_key = 'FOO' WHERE bundle_id = 'addon-a' AND env_key = 'FOO'").run();
  assert.throws(() => addonRead(ctx, "addon-b", ["FOO"]), rowsMissing, "the moved row is not the row the blob was sealed for");
  // And renaming the env key under the same add-on.
  ctx.raw.prepare("UPDATE crow_keychain SET bundle_id = 'addon-a', env_key = 'BAR' WHERE bundle_id = 'addon-b' AND env_key = 'FOO'").run();
  assert.throws(() => addonRead(ctx, "addon-a", ["BAR"]), rowsMissing);
});

// ─── 3. the era: v1 is refused after it, accepted before ────────────────────

test("era: an enc:v1 row is refused after the conversion, recorded and belled once; before it, v1 opens", async (t) => {
  const ctx = await instance(t);

  // BEFORE the era: a v1 row is an ordinary row.
  const pre = ctx.raw.prepare(
    "INSERT INTO crow_keychain (kind, label, bundle_id, env_key, secret_sealed, key_id, origin, status) VALUES ('extension','v1','v1addon','V1_KEY',?,?,'typed','active')",
  ).run(v1For(ctx, SENTINEL), ctx.key.id);
  assert.equal(Number(pre.lastInsertRowid) > 0, true);
  assert.deepEqual(addonRead(ctx, "v1addon", ["V1_KEY"]), { V1_KEY: SENTINEL }, "before the era, v1 opens as it always did");
  const preConversionBlob = blobOf(ctx, Number(pre.lastInsertRowid));

  // Convert (this row included), then plant v1 blobs afterwards — a bot's own v1 seal of a value
  // it chose, and the pre-conversion blob copied back in from somewhere else.
  await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: "a-value", origin: "typed" });
  assert.equal((await runBoot(ctx)).state, "converted");

  ctx.raw.prepare("UPDATE crow_keychain SET secret_sealed = ? WHERE bundle_id = 'addon-a' AND env_key = 'FOO'").run(v1For(ctx, "attacker-chosen"));
  assert.throws(() => addonRead(ctx, "addon-a", ["FOO"]), rowsMissing, "a v1 seal of the bot's own value is refused");
  const auditAfterOwn = ctx.raw.prepare("SELECT COUNT(*) AS n FROM audit_log WHERE event_type = 'keychain_legacy_form'").get().n;
  assert.ok(auditAfterOwn > 0, "the refusal is recorded as keychain_legacy_form");
  const bells = ctx.raw.prepare("SELECT source, title FROM notifications WHERE source = 'security'").all();
  assert.equal(bells.length, 1, "one bell");
  assert.equal(bells[0].title, ERA.LEGACY_FORM_BELL, "with the bare alert title");

  // A SECOND refused row in the same day must not ring again.
  ctx.raw.prepare("UPDATE crow_keychain SET secret_sealed = ? WHERE bundle_id = 'addon-a' AND env_key = 'FOO'").run(preConversionBlob);
  assert.throws(() => addonRead(ctx, "addon-a", ["FOO"]), rowsMissing, "a copied pre-conversion v1 blob is refused too");
  assert.equal(ctx.raw.prepare("SELECT COUNT(*) AS n FROM notifications WHERE source = 'security'").get().n, 1, "still one bell (24 h dedupe)");
  const details = ctx.raw.prepare("SELECT details FROM audit_log WHERE event_type = 'keychain_legacy_form' ORDER BY id").all().map((r) => JSON.parse(r.details));
  assert.ok(details.every((d) => d && typeof d.id === "number" && typeof d.kind === "string"), "audit rows name the row id and kind only");
});

// ─── 4. the boot converter ──────────────────────────────────────────────────

test("converter: every kind and status converts, a foreign-key row is left alone, and the era is recorded", async (t) => {
  const ctx = await instance(t);
  const key = ctx.key;
  const OTHER = { id: "fedcba9876543210", seed: Buffer.alloc(32, 3) };
  const ext = await K.saveExtensionSecret(ctx.db, key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed" });
  const extGone = await K.saveExtensionSecret(ctx.db, key, { bundleId: "addon-b", envKey: "BAR", label: "B BAR", secret: OTHER_PW, origin: "generated" });
  ctx.raw.prepare("UPDATE crow_keychain SET status = 'extension_removed' WHERE id = ?").run(extGone.id);
  const svc = await K.saveServiceSecret(ctx.db, key, { connectionUuid: "conn-1", bundleId: "svc-addon", envKey: "SVC_TOKEN", label: "svc", secret: "svc-value" });
  ctx.raw.prepare("UPDATE crow_keychain SET status = 'disconnected' WHERE id = ?").run(svc.id);
  // A service row must name a real connection (the conversion's bound-row check): give it one.
  serviceConnection(ctx, "conn-1", "svc");
  const manual = await K.addManualSecret(ctx.db, key, { label: "Phone", secret: "manual-value" });
  // Rows an older key sealed: unreadable here, and never this pass's to rewrite.
  const foreign = insertV1(ctx, { kind: "manual", label: "Old", value: "old-value", keyId: OTHER.id, keySeed: OTHER.seed });
  // This instance's rows are v2 already; a database from before the upgrade holds them as v1.
  setV1(ctx, ext.id, SENTINEL);
  setV1(ctx, extGone.id, OTHER_PW);
  setV1(ctx, svc.id, "svc-value");
  setV1(ctx, manual.id, "manual-value");

  const out = await runBoot(ctx);
  assert.equal(out.state, "converted");
  assert.equal(out.converted, 4);
  assert.equal(out.verified, 4);
  assert.equal(out.foreignKey, 1, "the foreign-key row is counted and left untouched");
  assert.equal(out.alarms, 0);
  assert.equal(out.backup !== null, true, "a verified copy was taken");

  for (const id of [ext.id, extGone.id, svc.id, manual.id]) assert.match(blobOf(ctx, id), /^enc:v2:/);
  assert.match(blobOf(ctx, foreign.id), /^enc:v1:/, "a row under another key is exactly as it was");

  // Every converted row opens through the store's own paths.
  assert.equal(await K.openEntrySecret(ctx.db, key, ext.id), SENTINEL);
  assert.equal(await K.openEntrySecret(ctx.db, key, manual.id), "manual-value");
  assert.equal(await K.openEntrySecret(ctx.db, key, svc.id), "svc-value");
  assert.deepEqual(addonRead(ctx, "addon-a", ["FOO"]), { FOO: SENTINEL });

  // The era state file: 0600 in a 0700 dir, with the key id, the count and the snapshot name.
  const st = lstatSync(ctx.statePath);
  assert.equal(st.isFile(), true);
  assert.equal(st.mode & 0o777, 0o600);
  assert.equal(statSync(join(ctx.home, "secrets")).mode & 0o777, 0o700);
  const doc = JSON.parse(readFileSync(ctx.statePath, "utf8"));
  assert.equal(typeof doc.converted_at, "string");
  assert.equal(doc.key_id, key.id);
  assert.equal(doc.rows, 4);
  assert.match(doc.snapshot, /^keychain-aad-rollback-.+\.json$/);

  // The snapshot holds row identities and blob DIGESTS only.
  const snapshotText = readFileSync(join(ctx.home, "secrets", doc.snapshot), "utf8");
  const snapshot = JSON.parse(snapshotText);
  assert.equal(snapshot.rows.length, 4);
  for (const row of snapshot.rows) {
    assert.match(row.hash, /^[0-9a-f]{64}$/);
    assert.equal("secret_sealed" in row, false);
  }
  for (const value of [SENTINEL, OTHER_PW, "svc-value", "manual-value"]) assert.equal(snapshotText.includes(value), false, "the snapshot never holds a value");

  // The verified copy: 0600 in a 0700 dir.
  assert.equal(statSync(out.backup).mode & 0o777, 0o600);
  assert.equal(statSync(join(ctx.home, "secrets", "backups", "keychain-aad")).mode & 0o777, 0o700);
});

test("converter: a second boot changes nothing (the era is already recorded)", async (t) => {
  const ctx = await instance(t);
  const saved = await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed" });
  setV1(ctx, saved.id, SENTINEL);
  assert.equal((await runBoot(ctx)).state, "converted");
  const again = await runBoot(ctx);
  assert.equal(again.state, "converted-earlier");
  assert.equal(again.converted, 0);
  assert.equal(again.alarms, 0);
  assert.equal(again.changed, false);
  assert.deepEqual(addonRead(ctx, "addon-a", ["FOO"]), { FOO: SENTINEL });
});

test("converter: a proof that does not verify rolls back, writes no marker, and leaves v1 accepted", async (t) => {
  const ctx = await instance(t);
  const ext = await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed" });
  const manual = await K.addManualSecret(ctx.db, ctx.key, { label: "Phone", secret: "manual-value" });
  // A pre-upgrade database: both rows are in the old (v1) form.
  setV1(ctx, ext.id, SENTINEL);
  setV1(ctx, manual.id, "manual-value");

  const out = await runBoot(ctx, { verifyProof: () => { throw new Error("injected verify failure"); } });
  assert.equal(out.state, "verify-failed");
  assert.equal(out.converted, 0);
  assert.equal(existsSync(ctx.statePath), false, "no era was recorded");
  assert.equal(ctx.raw.prepare("SELECT COUNT(*) AS n FROM crow_keychain WHERE secret_sealed LIKE 'enc:v1:%'").get().n, 2, "every row is still v1");
  const leftovers = readdirSync(join(ctx.home, "secrets")).filter((n) => n.startsWith("keychain-aad-rollback-"));
  assert.deepEqual(leftovers, [], "the snapshot this pass wrote was removed");
  assert.deepEqual(addonRead(ctx, "addon-a", ["FOO"]), { FOO: SENTINEL }, "and the value still opens (pre-era)");
});

test("converter: a crash between the commit and the marker does not launder a v1 row written after the snapshot", async (t) => {
  const ctx = await instance(t);
  const first = await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed" });
  const second = await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "FOO2", label: "A FOO2", secret: "second", origin: "typed" });
  setV1(ctx, first.id, SENTINEL);
  setV1(ctx, second.id, "second");
  assert.equal((await runBoot(ctx)).state, "converted");

  // The crash shape: the rows are converted and a snapshot exists, but the marker never landed.
  unlinkSync(ctx.statePath);
  ERA._resetAadStateCacheForTest();

  // A bot writes a v1 row AFTER the snapshot (this one is not in it, so it must never convert).
  const late = insertV1(ctx, { bundleId: "addon-a", envKey: "LATE", value: "bot-chosen" });

  const retry = await runBoot(ctx);
  assert.equal(retry.state, "converted");
  assert.equal(retry.converted, 0, "nothing was converted: the only v1 row is not in the snapshot");
  assert.ok(retry.alarms >= 1, "and it was reported");
  assert.match(blobOf(ctx, late.id), /^enc:v1:/, "the post-snapshot row was NOT laundered into v2");
  assert.match(blobOf(ctx, first.id), /^enc:v2:/, "the rows the snapshot names are already bound");
  assert.equal(existsSync(ctx.statePath), true, "the era is recorded now");
  assert.throws(() => addonRead(ctx, "addon-a", ["LATE"]), rowsMissing, "and the late v1 row is refused from now on");
  assert.deepEqual(addonRead(ctx, "addon-a", ["FOO"]), { FOO: SENTINEL }, "the converted rows still read");
});

test("converter: a symlinked or group-writable state file is no proof, a 0600 one is", async (t) => {
  const ctx = await instance(t);
  const row = insertV1(ctx, { bundleId: "v1addon", envKey: "V1_KEY" });
  const doc = JSON.stringify({ converted_at: new Date().toISOString(), key_id: ctx.key.id, rows: 1, snapshot: null }) + "\n";
  const target = join(ctx.home, "elsewhere.json");
  mkdirSync(join(ctx.home, "secrets"), { recursive: true, mode: 0o700 });

  // A SYMLINK to a perfectly valid document is refused by the hardened reader.
  writeFileSync(target, doc, { mode: 0o600 });
  symlinkSync(target, ctx.statePath);
  ERA._resetAadStateCacheForTest();
  assert.equal(lstatSync(ctx.statePath).isSymbolicLink(), true);
  assert.equal(ERA.readAadState(ctx.secretsDir).state, "unreadable");
  assert.deepEqual(addonRead(ctx, "v1addon", ["V1_KEY"]), { V1_KEY: SENTINEL }, "no proof, no era: v1 still opens");

  // A group/world-writable file is refused as well.
  unlinkSync(ctx.statePath);
  writeFileSync(ctx.statePath, doc, { mode: 0o600 });
  chmodSync(ctx.statePath, 0o666);
  ERA._resetAadStateCacheForTest();
  assert.equal(ERA.readAadState(ctx.secretsDir).state, "unreadable");
  assert.deepEqual(addonRead(ctx, "v1addon", ["V1_KEY"]), { V1_KEY: SENTINEL });

  // The real thing (0600) decides the era.
  chmodSync(ctx.statePath, 0o600);
  ERA._resetAadStateCacheForTest();
  assert.equal(ERA.readAadState(ctx.secretsDir).state, "converted");
  assert.throws(() => addonRead(ctx, "v1addon", ["V1_KEY"]), rowsMissing);
  assert.equal(blobOf(ctx, row.id), row.sealed, "the row itself was never touched");
});

test("era: the DB mirror alone enforces it (a crow.db restored without the state file)", async (t) => {
  const ctx = await instance(t);
  insertV1(ctx, { bundleId: "v1addon", envKey: "V1_KEY" });
  assert.deepEqual(addonRead(ctx, "v1addon", ["V1_KEY"]), { V1_KEY: SENTINEL }, "no marker anywhere: v1 opens");

  ctx.raw.prepare("INSERT INTO dashboard_settings_overrides (key, instance_id, value, updated_at) VALUES (?, 'inst-a', ?, datetime('now'))")
    .run(ERA.AAD_ERA_SETTING, new Date().toISOString());
  ERA._resetAadStateCacheForTest();
  assert.throws(() => addonRead(ctx, "v1addon", ["V1_KEY"]), rowsMissing, "the mirror alone is enough");

  ctx.raw.prepare("DELETE FROM dashboard_settings_overrides WHERE key = ?").run(ERA.AAD_ERA_SETTING);
  ERA._resetAadStateCacheForTest();
  assert.deepEqual(addonRead(ctx, "v1addon", ["V1_KEY"]), { V1_KEY: SENTINEL }, "removing the mirror restores the pre-era rule");
});

test("converter: no key file → skipped and NOT marked; a fresh install → marked", async (t) => {
  const noKey = await instance(t, { key: false });
  insertV1(noKey, { keyId: "fedcba9876543210", keySeed: Buffer.alloc(32, 4) });
  const skipped = await runBoot(noKey);
  assert.equal(skipped.state, "skipped-key-missing");
  assert.equal(existsSync(noKey.statePath), false, "nothing was recorded");

  const fresh = await instance(t);
  const marked = await runBoot(fresh);
  assert.equal(marked.state, "marked-empty");
  assert.equal(marked.rows, 0);
  assert.equal(marked.changed, true);
  const doc = JSON.parse(readFileSync(fresh.statePath, "utf8"));
  assert.equal(doc.rows, 0);
  assert.equal(doc.key_id, fresh.key.id);
});

// ─── 5. every store.js seal/open round trip, after the era ─────────────────

test("round trips: extension, service, manual, first view, export/import, sync readers and the keep-first-view pin", async (t) => {
  const ctx = await instance(t);
  const key = ctx.key;

  // extension save + update
  const ext = await K.saveExtensionSecret(ctx.db, key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed", firstView: true });
  assert.equal(await K.openEntrySecret(ctx.db, key, ext.id), SENTINEL);
  await K.saveExtensionSecret(ctx.db, key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: "updated", origin: "typed" });
  assert.equal(await K.openEntrySecret(ctx.db, key, ext.id), "updated", "an UPDATE reseals v2 under the same row's AAD");
  assert.equal(await K.consumeFirstView(ctx.db, key, ext.id), null, "the update cleared the window the old value earned");
  const remembered = await K.rememberExtensionSecret(ctx.db, key, { bundleId: "addon-c", envKey: "REMEMBER", label: "L", secret: "first", origin: "typed" });
  assert.equal(typeof remembered, "number");

  // service
  const svc = await K.saveServiceSecret(ctx.db, key, { connectionUuid: "conn-9", bundleId: "svc-addon", envKey: "SVC_TOKEN", label: "svc", secret: "svc-value" });
  assert.deepEqual(await K.serviceSecretsFor(ctx.db, key, "conn-9", { allowedKeys: ["SVC_TOKEN"] }), { SVC_TOKEN: "svc-value" });
  assert.equal(await K.openEntrySecret(ctx.db, key, svc.id), "svc-value");

  // manual + a live first view on an extension row
  const manual = await K.addManualSecret(ctx.db, key, { label: "Phone", secret: OTHER_PW });
  assert.equal(await K.openEntrySecret(ctx.db, key, manual.id), OTHER_PW);
  const windowed = await K.saveExtensionSecret(ctx.db, key, { bundleId: "addon-d", envKey: "VIEW", label: "V", secret: "view-me", origin: "generated", firstView: true });
  assert.equal(await K.consumeFirstView(ctx.db, key, windowed.id), "view-me");
  assert.equal(await K.consumeFirstView(ctx.db, key, windowed.id), null, "single use");

  // sync readers
  assert.deepEqual(addonRead(ctx, "addon-a", ["FOO"]), { FOO: "updated" });
  const rowOf = (id) => ctx.raw.prepare("SELECT kind, bundle_id, env_key, connection_uuid, key_id, secret_sealed FROM crow_keychain WHERE id = ?").get(id);
  assert.equal(K.rowSecretEquals(rowOf(ext.id), key, "updated"), true, "the same value compares equal through the bound opener");
  assert.equal(K.rowSecretEquals(rowOf(ext.id), key, "other"), false);

  // export → import (same key, fresh rows)
  const entries = await K.exportableEntries(ctx.db, key);
  const file = await sealExport(entries, "correct horse battery");
  ctx.raw.prepare("DELETE FROM crow_keychain").run();
  const imported = await K.importEntries(ctx.db, key, await openExport(file, "correct horse battery"));
  assert.equal(imported.imported, entries.length);
  assert.deepEqual(addonRead(ctx, "addon-a", ["FOO"]), { FOO: "updated" });
  assert.deepEqual(await K.serviceSecretsFor(ctx.db, key, "conn-9", { allowedKeys: ["SVC_TOKEN"] }), { SVC_TOKEN: "svc-value" });

  // The add-on seal's keep-first-view pin still works with v2 blobs: a re-save of the SAME value
  // keeps the live window, and the read-back proof passes through the spawn's own path.
  const manifest = { name: "Demo", env_vars: [{ name: "DEMO_TOKEN", secret: true }] };
  const deps = { db: ctx.db, crowHome: () => ctx.home, paths: () => ({ dbPath: ctx.dbPath, keyPath: ctx.keyPath }) };
  await sealEntrySecrets({ bundleId: "addon-e", entry: { command: "node", env: { DEMO_TOKEN: "generated-value" } }, manifest, deps });
  const rowId = ctx.raw.prepare("SELECT id FROM crow_keychain WHERE bundle_id = 'addon-e' AND env_key = 'DEMO_TOKEN'").get().id;
  const pinnedBlob = blobOf(ctx, rowId);
  const fvu = new Date(Date.now() + 20 * 60 * 1000).toISOString();
  ctx.raw.prepare("UPDATE crow_keychain SET first_view_until = ? WHERE id = ?").run(fvu, rowId);
  await sealEntrySecrets({ bundleId: "addon-e", entry: { command: "node", env: { DEMO_TOKEN: "generated-value" } }, manifest, deps });
  assert.equal(ctx.raw.prepare("SELECT first_view_until FROM crow_keychain WHERE id = ?").get(rowId).first_view_until, fvu, "the live window survived the re-save");
  assert.notEqual(blobOf(ctx, rowId), pinnedBlob, "the value was resealed (a fresh v2 blob)");
  assert.deepEqual(addonRead(ctx, "addon-e", ["DEMO_TOKEN"]), { DEMO_TOKEN: "generated-value" });
});

// ─── 7b. the operator downgrade tool (a code revert) ───────────────────────

test("downgrade tool: refuses without --yes, then puts the rows back in the old form and removes the era", async (t) => {
  const ctx = await instance(t);
  const saved = await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed" });
  setV1(ctx, saved.id, SENTINEL);
  assert.equal((await runBoot(ctx)).state, "converted");
  assert.match(blobOf(ctx, saved.id), /^enc:v2:/);

  const runDowngrade = (...extra) => execFileSync(process.execPath, [
    DOWNGRADE, "--crow-home", ctx.home, "--db", ctx.dbPath, ...extra,
  ], { env: { ...process.env, CROW_HOME: ctx.home }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

  let refused = null;
  try { runDowngrade(); } catch (err) { refused = err; }
  assert.ok(refused && refused.status === 1, "--yes is mandatory");
  assert.match(blobOf(ctx, saved.id), /^enc:v2:/, "and nothing was touched");

  const out = runDowngrade("--yes");
  assert.match(out, /outcome: downgraded/);
  assert.match(out, /resealed: 1/);
  assert.equal(out.includes(SENTINEL), false, "no value is printed");
  assert.match(blobOf(ctx, saved.id), /^enc:v1:/, "the row is in the old form again");
  assert.equal(existsSync(ctx.statePath), false, "the era marker is gone");
  ERA._resetAadStateCacheForTest();
  assert.deepEqual(addonRead(ctx, "addon-a", ["FOO"]), { FOO: SENTINEL }, "a pre-era Crow reads it as before");
});

// ─── 7. the operator dry-run tool ───────────────────────────────────────────

test("dry run: PASS on a healthy instance, STOP when a row no longer verifies", async (t) => {
  const ctx = await instance(t);
  const ext = await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed" });
  const manual = await K.addManualSecret(ctx.db, ctx.key, { label: "Phone", secret: OTHER_PW });
  // The tool is for a pre-upgrade database: put the rows in the old (v1) form.
  setV1(ctx, ext.id, SENTINEL);
  setV1(ctx, manual.id, OTHER_PW);
  const scratch = join(ctx.home, "dryrun");

  const runTool = (scratch) => execFileSync(process.execPath, [
    DRY_RUN, "--db", `main=${ctx.dbPath}`, "--key-from", ctx.home, "--home", scratch,
  ], { env: { ...process.env, CROW_HOME: ctx.home }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });

  const ok = runTool(scratch);
  assert.match(ok, /main: .*converted 2; verified 2; refused 0; alarms 0; second-boot changes 0/);
  assert.match(ok, /PASS: 1\/1 label\(s\) passed/);
  // The tool never printed a value.
  assert.equal(ok.includes(SENTINEL), false);
  assert.equal(ok.includes(OTHER_PW), false);
  // L3: the scratch home held copies of the key and the databases; it never survives the run.
  assert.equal(existsSync(scratch), false, "the scratch home was cleared at exit");
  assert.match(ok, /scratch home cleared/, "and the tool said so");

  // Let the source reach the converted state, then break one row's binding (its bundle id no
  // longer matches the one it was sealed for): the tool's own open path must fail, which STOPs.
  assert.equal((await runBoot(ctx)).state, "converted");
  ctx.raw.prepare("UPDATE crow_keychain SET bundle_id = 'moved-elsewhere' WHERE kind = 'extension'").run();
  let failed = null;
  try {
    runTool(join(ctx.home, "dryrun2"));
  } catch (err) {
    failed = err;
  }
  assert.ok(failed, "the tool exits nonzero when a row fails to verify");
  assert.equal(failed.status, 1);
  assert.match(String(failed.stdout), /STOP/);
  assert.match(String(failed.stdout), /failed-open 1/);
  assert.match(String(failed.stdout), /row\(s\) did not open after conversion/);
  assert.equal(String(failed.stdout).includes(SENTINEL), false, "a value never reaches the output");
  assert.equal(existsSync(join(ctx.home, "dryrun2")), false, "the scratch home was cleared on STOP too");
  assert.match(String(failed.stdout), /scratch home cleared/);
});

// ─── review round 1: H1, H2, M1–M4, L1, L4 ─────────────────────────────────

/** One project connection row, so a `service` row keyed by its uuid is a real credential row. */
function serviceConnection(ctx, uuid, serviceId = "svc") {
  ctx.raw.prepare("INSERT OR IGNORE INTO project_spaces (id, slug, name) VALUES (1, 'services', 'Services')").run();
  ctx.raw.prepare(
    "INSERT INTO service_connections (uuid, project_id, service_id, method, account_label, label_slug) VALUES (?, 1, ?, 'api_key', ?, ?)",
  ).run(uuid, serviceId, serviceId, `${serviceId}-${uuid}`);
}

/** One Mail account row, so a `service` row keyed by its id is a real Mail credential row. */
function mailAccount(ctx, id, address) {
  ctx.raw.prepare(
    `INSERT INTO mail_accounts (id, address, label, imap_host, imap_port, smtp_host, smtp_port, created_at, updated_at)
     VALUES (?, ?, 'Mail', 'imap.example.com', 993, 'smtp.example.com', 465, ?, ?)`,
  ).run(id, address, Date.now(), Date.now());
}

/** installed.json as the gateway reads it (an array of entries, or the id-keyed legacy object). */
function installAddons(ctx, ids) {
  writeFileSync(join(ctx.home, "installed.json"), JSON.stringify(ids.map((id) => ({ id }))) + "\n");
}

/** Insert one raw keychain row (a bot or an older Crow wrote it), returning its id and blob. */
function insertRaw(ctx, { kind, label, bundleId = null, envKey = null, uuid = null, sealed, keyId = null }) {
  const r = ctx.raw.prepare(
    `INSERT INTO crow_keychain (kind, label, bundle_id, env_key, secret_sealed, key_id, origin, status, connection_uuid)
     VALUES (?, ?, ?, ?, ?, ?, 'typed', 'active', ?)`,
  ).run(kind, label, bundleId, envKey, sealed, keyId || ctx.key.id, uuid);
  return { id: Number(r.lastInsertRowid), sealed };
}

test("RED H1: the era is read from the fd-anchored SECRETS DIR, so a deleted mirror and a planted v1 copy are still refused", async (t) => {
  const ctx = await instance(t);
  const key = ctx.key;
  mailAccount(ctx, "ma-h1", "h1@example.com");
  const mail = await K.saveServiceSecret(ctx.db, key, { connectionUuid: "ma-h1", bundleId: "crow-mail", envKey: "MAIL_PASSWORD", label: "Mail", secret: MAIL_PW });
  const bot = await K.saveExtensionSecret(ctx.db, key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: "a-value", origin: "typed" });
  // A database from before the upgrade: both rows hold the old form.
  setV1(ctx, mail.id, MAIL_PW);
  setV1(ctx, bot.id, "a-value");
  const preUpgradeMailBlob = blobOf(ctx, mail.id);
  const bootOut = await runBoot(ctx);
  assert.equal(bootOut.state, "converted", JSON.stringify(bootOut));
  assert.equal(bootOut.converted, 2, JSON.stringify(bootOut));
  assert.match(blobOf(ctx, mail.id), /^enc:v2:/);

  // The pibot host's own view of the key: the ANCHORED secrets dir, opened by fd.
  const fd = openSync(ctx.secretsDir, fsConstants.O_RDONLY | fsConstants.O_DIRECTORY);
  t.after(() => { try { closeSync(fd); } catch { /* closed */ } });
  const anchoredKeyPath = `/proc/self/fd/${fd}/keychain.key`;
  const anchoredRead = (bundleId, names) => readAddonSecretsSync(bundleId, names, { unsealer: "gateway", dbPath: ctx.dbPath, keyPath: anchoredKeyPath });
  assert.deepEqual(anchoredRead("addon-a", ["FOO"]), { FOO: "a-value" }, "control: the anchored key path reads a bound row");

  // The bot's strongest move: delete the DB mirror AND every bound row, then re-plant the
  // pre-upgrade Mail blob in its own row. crow.db then proves nothing — only the host state
  // file does, and it is read through the dir the key path names.
  ctx.raw.prepare("DELETE FROM dashboard_settings_overrides WHERE key = ?").run(ERA.AAD_ERA_SETTING);
  ctx.raw.prepare("DELETE FROM crow_keychain").run();
  insertRaw(ctx, { kind: "extension", label: "A FOO", bundleId: "addon-a", envKey: "FOO", sealed: preUpgradeMailBlob });
  ERA._resetAadStateCacheForTest();
  assert.equal(existsSync(ctx.statePath), true, "the host state file is still there");
  assert.equal(ctx.raw.prepare("SELECT COUNT(*) AS n FROM crow_keychain WHERE substr(secret_sealed, 1, 7) = 'enc:v2:'").get().n, 0, "and crow.db holds nothing that proves the era");
  assert.throws(() => anchoredRead("addon-a", ["FOO"]), rowsMissing, "the era is read from the fd-anchored secrets dir, so the copy is refused");
});

test("RED H2: one junk row in the old prefix never blocks the pass — it is refused, the rest convert and the era is recorded", async (t) => {
  const ctx = await instance(t);
  const good = await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed" });
  setV1(ctx, good.id, SENTINEL);
  // Two rows a bot can plant: a real prefix over garbage (opens nothing) and the same form in
  // another case (SQLite's LIKE matches it, the exact prefix does not).
  const junk = insertRaw(ctx, { kind: "manual", label: "Junk", sealed: "enc:v1:" + Buffer.alloc(40, 5).toString("base64") });
  const odd = insertRaw(ctx, { kind: "manual", label: "Odd", sealed: "ENC:V1:" + Buffer.alloc(40, 6).toString("base64") });

  const out = await runBoot(ctx);
  assert.equal(out.state, "converted", "the pass completed and recorded the era");
  assert.equal(out.converted, 1, "the owner's row was converted");
  assert.match(blobOf(ctx, good.id), /^enc:v2:/);
  assert.deepEqual(addonRead(ctx, "addon-a", ["FOO"]), { FOO: SENTINEL });
  assert.ok(out.refused >= 2, `both junk rows are counted as refused (got ${out.refused})`);
  assert.ok(out.alarms >= 2, "and alarmed");
  assert.equal(blobOf(ctx, junk.id), junk.sealed, "the junk row is left exactly as it was");
  assert.equal(blobOf(ctx, odd.id), odd.sealed, "the case-mangled row too");
  // The era is recorded, so an old-form row a bot plants AFTER it is refused.
  insertRaw(ctx, { kind: "manual", label: "Late", sealed: v1For(ctx, "bot-chosen") });
  ERA._resetAadStateCacheForTest();
  assert.equal(await K.openEntrySecret(ctx.db, ctx.key, ctx.raw.prepare("SELECT id FROM crow_keychain WHERE label = 'Late'").get().id).then(() => "opened", (e) => e.code), "KEYCHAIN_LEGACY_FORM");
});

test("RED M1: a copied pre-upgrade blob is not laundered (duplicates, an unknown add-on and an unknown connection are refused)", async (t) => {
  const ctx = await instance(t);
  const key = ctx.key;
  installAddons(ctx, ["addon-a"]);
  mailAccount(ctx, "ma-m1", "m1@example.com");

  const good = await K.saveExtensionSecret(ctx.db, key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed" });
  setV1(ctx, good.id, SENTINEL);
  const mail = await K.saveServiceSecret(ctx.db, key, { connectionUuid: "ma-m1", bundleId: "crow-mail", envKey: "MAIL_PASSWORD", label: "Mail", secret: MAIL_PW });
  setV1(ctx, mail.id, MAIL_PW);

  // (a) The attack: the Mail blob copied into the bot's own (installed) add-on row.
  const stolen = insertRaw(ctx, { kind: "extension", label: "A STOLEN", bundleId: "addon-a", envKey: "STOLEN", sealed: blobOf(ctx, mail.id) });
  // (b) An extension row for an add-on that is not installed.
  const unknownOwner = insertRaw(ctx, { kind: "extension", label: "Rogue", bundleId: "not-installed", envKey: "ROGUE", sealed: v1For(ctx, "rogue-value") });
  // (c) A service row whose connection uuid is nothing.
  const unknownConn = insertRaw(ctx, { kind: "service", label: "Orphan", bundleId: "svc-addon", envKey: "SVC", uuid: "no-such-connection", sealed: v1For(ctx, "svc-value") });
  // (d) A real connection, so the check itself is not refusing everything.
  serviceConnection(ctx, "conn-m1", "svc");
  const realConn = await K.saveServiceSecret(ctx.db, key, { connectionUuid: "conn-m1", bundleId: "svc-addon", envKey: "SVC_TOKEN", label: "svc", secret: "svc-token" });
  setV1(ctx, realConn.id, "svc-token");

  // (e) A custom MCP add-on: it is not in installed.json, its entry is in mcp-addons.json.
  writeFileSync(join(ctx.home, "mcp-addons.json"), JSON.stringify({ "custom-x": { command: "node", args: [], keychainEnv: ["CUSTOM_TOKEN"] } }) + "\n");
  const custom = await K.saveExtensionSecret(ctx.db, key, { bundleId: "custom-x", envKey: "CUSTOM_TOKEN", label: "custom", secret: "custom-token", origin: "typed" });
  setV1(ctx, custom.id, "custom-token");

  const out = await runBoot(ctx);
  assert.ok(["converted", "marked"].includes(out.state));
  assert.match(blobOf(ctx, custom.id), /^enc:v2:/, "a custom MCP add-on's row (mcp-addons.json) converts too");
  assert.ok(out.unsafe >= 3, `the copied blob and the two unknown owners are refused (got ${out.unsafe})`);
  for (const row of [stolen, unknownOwner, unknownConn]) {
    assert.match(blobOf(ctx, row.id), new RegExp("^enc:v1:"), "a refused row stays in the old form (and is refused after the era)");
  }
  assert.match(blobOf(ctx, mail.id), /^enc:v1:/, "the SOURCE of a copied blob is refused too: two rows cannot share one value");
  assert.match(blobOf(ctx, good.id), /^enc:v2:/, "a genuine row still converts");
  assert.match(blobOf(ctx, realConn.id), /^enc:v2:/, "and so does a service row with a real connection");
  assert.deepEqual(addonRead(ctx, "addon-a", ["FOO"]), { FOO: SENTINEL });
  assert.throws(() => addonRead(ctx, "addon-a", ["STOLEN"]), rowsMissing, "the copied value is never handed to the bot");
});

test("RED M2: a planted enc:v2 row is not crash evidence — it is refused, and the owner's v1 rows still convert", async (t) => {
  const ctx = await instance(t);
  const good = await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed" });
  setV1(ctx, good.id, SENTINEL);
  // A v2-SHAPED blob a bot cannot have sealed: no key, so no valid tag.
  const planted = insertRaw(ctx, { kind: "manual", label: "Planted", sealed: "enc:v2:" + Buffer.alloc(48, 3).toString("base64") });

  const out = await runBoot(ctx);
  assert.equal(out.state, "converted");
  assert.equal(out.converted, 1, "the owner's row was converted, not blocked");
  assert.match(blobOf(ctx, good.id), /^enc:v2:/);
  assert.deepEqual(addonRead(ctx, "addon-a", ["FOO"]), { FOO: SENTINEL });
  assert.equal(blobOf(ctx, planted.id), planted.sealed, "the planted row is left as it is");
  assert.ok(out.alarms >= 1, "and it was alarmed");
});

test("RED M3: a row whose bound columns move during the conversion is skipped and alarmed, never a whole-pass rollback", async (t) => {
  const ctx = await instance(t);
  const a = await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed" });
  const b = await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "BAR", label: "A BAR", secret: OTHER_PW, origin: "typed" });
  setV1(ctx, a.id, SENTINEL);
  setV1(ctx, b.id, OTHER_PW);

  const out = await runBoot(ctx, {
    // The race: after the snapshot and before BEGIN IMMEDIATE, another writer renames a row.
    beforeConvert: () => { ctx.raw.prepare("UPDATE crow_keychain SET env_key = 'FOO_MOVED' WHERE id = ?").run(a.id); },
  });
  assert.equal(out.state, "converted", "the pass still completes");
  assert.equal(out.converted, 1, "only the untouched row was converted");
  assert.ok(out.refused >= 1 && out.alarms >= 1, "the moved row is counted and alarmed");
  assert.match(blobOf(ctx, a.id), /^enc:v1:/, "the moved row is left in the old form");
  assert.match(blobOf(ctx, b.id), /^enc:v2:/);
  assert.deepEqual(addonRead(ctx, "addon-a", ["BAR"]), { BAR: OTHER_PW }, "the untouched row still reads");
});

test("RED M4: a converted row keeps its Export fingerprint, so the off-site gate and the Export reminder do not regress", async (t) => {
  const ctx = await instance(t);
  const R = await import("../servers/gateway/keychain/reminder.js");
  const OE = await import("../servers/gateway/satellites/offsite-key.js");
  const created = await OE.ensureOffsiteKey(ctx.db, ctx.key);
  // A database from before the upgrade: the off-site key row holds the old form.
  const plaintext = await K.openEntrySecret(ctx.db, ctx.key, created.id);
  setV1(ctx, created.id, plaintext);
  // The owner exported while it was still v1.
  await R.recordKeychainExport(ctx.db, ctx.key.id);
  assert.equal(await OE.offsiteKeyInExport(ctx.db), true, "the export holds the key");
  assert.equal(await R.unexportedCount(ctx.db, ctx.key.id), 0);

  const out = await runBoot(ctx);
  assert.equal(out.converted, 1);
  assert.match(blobOf(ctx, created.id), /^enc:v2:/);
  assert.equal(await OE.offsiteKeyInExport(ctx.db), true, "the fingerprint moved with the blob: the upload gate stays open");
  assert.equal(await R.unexportedCount(ctx.db, ctx.key.id), 0, "and the reminder shows nothing unexported");
});

test("RED L1: one refused row does not fail the Export, and an Import restores over it", async (t) => {
  const ctx = await instance(t);
  await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed" });
  await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "BAR", label: "A BAR", secret: OTHER_PW, origin: "typed" });
  assert.equal((await runBoot(ctx)).state, "converted");
  // AFTER the era this row is refused (a v1 blob nothing in this release writes).
  ctx.raw.prepare("UPDATE crow_keychain SET secret_sealed = ? WHERE env_key = 'BAR'").run(v1For(ctx, OTHER_PW));

  let reported = 0;
  const entries = await K.exportableEntries(ctx.db, ctx.key, { onSkipped: (n) => { reported = n; } });
  assert.equal(entries.length, 1, "the readable row still leaves, the refused one is skipped");
  assert.equal(reported, 1, "and the refusal is reported as a count");
  assert.equal(entries[0].env_key, "FOO");
  assert.equal(JSON.stringify(entries).includes(OTHER_PW), false);

  // An Import counts the refused row as unreadable, so the Export can restore over it.
  const file = await sealExport([{ kind: "extension", label: "A BAR", bundle_id: "addon-a", env_key: "BAR", secret: "restored", origin: "typed" }], "correct horse battery");
  const done = await K.importEntries(ctx.db, ctx.key, await openExport(file, "correct horse battery"));
  assert.equal(done.imported, 1, "the refused row was replaced, not skipped");
  assert.deepEqual(addonRead(ctx, "addon-a", ["BAR"]), { BAR: "restored" });
});

test("RED L4: the downgrade tool skips and reports a bound row that does not open instead of aborting", async (t) => {
  const ctx = await instance(t);
  const broken = await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed" });
  const fine = await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "BAR", label: "A BAR", secret: OTHER_PW, origin: "typed" });
  setV1(ctx, broken.id, SENTINEL);
  setV1(ctx, fine.id, OTHER_PW);
  assert.equal((await runBoot(ctx)).state, "converted");
  // Damage ONE row's binding: its blob can no longer open under the row it now names.
  ctx.raw.prepare("UPDATE crow_keychain SET bundle_id = 'moved-elsewhere' WHERE id = ?").run(broken.id);

  const out = execFileSync(process.execPath, [
    DOWNGRADE, "--crow-home", ctx.home, "--db", ctx.dbPath, "--yes",
  ], { env: { ...process.env, CROW_HOME: ctx.home }, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] });
  assert.match(out, /outcome: downgraded/);
  assert.match(out, /resealed: 1/);
  assert.match(out, /rows that did not open \(left as they are\): 1/);
  assert.match(blobOf(ctx, fine.id), /^enc:v1:/, "the readable row went back to the old form");
  assert.match(blobOf(ctx, broken.id), /^enc:v2:/, "the damaged row is left as it is");
  assert.equal(existsSync(ctx.statePath), false, "the era is removed");
  assert.equal(out.includes(SENTINEL), false);
});

// ─── review round 2: H1′, M1′, L3′ ─────────────────────────────────────────

/** A v1 seal whose base64 body carries `=` padding, so stripping the pad CHANGES the string. */
function paddedSeal(ctx, base) {
  let value = base;
  for (let i = 0; i < 4; i++) {
    const sealed = v1For(ctx, value);
    if (sealed.endsWith("=")) return { sealed, value };
    value += "x";
  }
  throw new Error("no padded v1 form");
}

test("RED H1′: a re-encoded copy decodes to the same nonce — every spelling is refused, and so is its source", async (t) => {
  const ctx = await instance(t);
  const key = ctx.key;
  installAddons(ctx, ["addon-a"]);
  mailAccount(ctx, "ma-h1b", "h1b@example.com");

  // The Mail password in a v1 form whose body carries `=` padding, so a padding-stripped copy is a
  // DIFFERENT string that Node's decoder still turns into the same bytes.
  const mail = await K.saveServiceSecret(ctx.db, key, { connectionUuid: "ma-h1b", bundleId: "crow-mail", envKey: "MAIL_PASSWORD", label: "Mail", secret: MAIL_PW });
  const padded = paddedSeal(ctx, MAIL_PW);
  ctx.raw.prepare("UPDATE crow_keychain SET secret_sealed = ? WHERE id = ?").run(padded.sealed, mail.id);
  const mailBlob = blobOf(ctx, mail.id);
  const body = mailBlob.slice("enc:v1:".length);
  assert.match(body, /=$/);

  // Four spellings of that one blob, each copied into a row the bot may name.
  const withNewline = insertRaw(ctx, { kind: "extension", label: "N", bundleId: "addon-a", envKey: "N", sealed: mailBlob + "\n" });
  const withSpace = insertRaw(ctx, { kind: "extension", label: "S", bundleId: "addon-a", envKey: "S", sealed: "enc:v1: " + body });
  const withoutPad = insertRaw(ctx, { kind: "extension", label: "P", bundleId: "addon-a", envKey: "P", sealed: "enc:v1:" + body.replace(/=+$/, "") });
  // Same nonce, different ciphertext: byte 12 is the first ciphertext byte after the nonce.
  const tamperedBytes = Buffer.from(body, "base64");
  tamperedBytes[12] = tamperedBytes[12] ^ 0x01;
  const tampered = insertRaw(ctx, { kind: "extension", label: "T", bundleId: "addon-a", envKey: "T", sealed: "enc:v1:" + tamperedBytes.toString("base64") });
  // A genuine row, which must still convert.
  const genuine = await K.saveExtensionSecret(ctx.db, key, { bundleId: "addon-a", envKey: "GOOD", label: "G", secret: SENTINEL, origin: "typed" });
  setV1(ctx, genuine.id, SENTINEL);

  const out = await runBoot(ctx);
  assert.equal(out.state, "converted", JSON.stringify(out));
  assert.ok(out.unsafe >= 5, `the four copies and their source are all refused (got ${out.unsafe})`);
  assert.equal(out.converted, 1, "the genuine row was converted");
  for (const row of [withNewline, withSpace, withoutPad, tampered, { id: mail.id, sealed: mailBlob }]) {
    assert.equal(blobOf(ctx, row.id), row.sealed, "a refused row is left exactly as it was");
  }
  assert.match(blobOf(ctx, genuine.id), /^enc:v2:/);
  assert.deepEqual(addonRead(ctx, "addon-a", ["GOOD"]), { GOOD: SENTINEL });
  // The era is recorded, so the refused spellings stay refused: not one of them is ever handed out.
  for (const envKey of ["N", "S", "P", "T"]) assert.throws(() => addonRead(ctx, "addon-a", [envKey]), rowsMissing, envKey);
});

test("RED H1′: a non-canonical enc:v2 value is refused at open time (the decoder would open it)", async (t) => {
  const ctx = await instance(t);
  const saved = await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed" });
  assert.deepEqual(addonRead(ctx, "addon-a", ["FOO"]), { FOO: SENTINEL }, "control: the canonical blob opens");

  // The row's OWN blob, re-spelled: same AAD, same decoded bytes, so the AAD check would pass.
  ctx.raw.prepare("UPDATE crow_keychain SET secret_sealed = ? WHERE id = ?").run(blobOf(ctx, saved.id) + "\n", saved.id);
  const opened = await K.openEntrySecret(ctx.db, ctx.key, saved.id).then((v) => ({ value: v }), (e) => ({ code: e.code }));
  assert.equal(opened.code, "KEYCHAIN_LEGACY_FORM", "a v2 value in a spelling this release never writes is refused");
  assert.throws(() => addonRead(ctx, "addon-a", ["FOO"]), rowsMissing, "and never handed to an add-on child");
});

test("RED M1′: a mirror planted before the first boot converts nothing — every genuine row converts and the owner reads again", async (t) => {
  const ctx = await instance(t);
  const saved = await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed" });
  setV1(ctx, saved.id, SENTINEL);
  // The bot writes the era mirror BEFORE the upgrade boot: no state file, no bound row yet.
  ctx.raw.prepare("INSERT INTO dashboard_settings_overrides (key, instance_id, value, updated_at) VALUES (?, 'inst-a', ?, datetime('now'))")
    .run(ERA.AAD_ERA_SETTING, new Date().toISOString());
  ERA._resetAadStateCacheForTest();
  assert.equal(existsSync(ctx.statePath), false, "no host state file yet");

  const out = await runBoot(ctx);
  assert.equal(out.converted, 1, `every genuine row is converted (got ${JSON.stringify(out)})`);
  assert.match(blobOf(ctx, saved.id), /^enc:v2:/, "the owner's row is bound now");
  assert.equal(existsSync(ctx.statePath), true, "and the era is recorded properly");
  assert.equal(await K.openEntrySecret(ctx.db, ctx.key, saved.id), SENTINEL, "the owner can still read the password after the boot");
  assert.deepEqual(addonRead(ctx, "addon-a", ["FOO"]), { FOO: SENTINEL });
  // The planted mirror is alarmed like a refused row: one audit row naming it, and the bare bell.
  const audits = ctx.raw.prepare("SELECT details FROM audit_log WHERE event_type = ?").all(ERA.LEGACY_FORM_EVENT).map((r) => JSON.parse(r.details));
  assert.ok(audits.some((d) => d && d.mirror === ERA.AAD_ERA_SETTING), "the mirror is recorded once");
  assert.equal(ctx.raw.prepare("SELECT COUNT(*) AS n FROM notifications WHERE source = 'security'").get().n, 1, "and rings the one bell");
});

test("RED L3′: an entry an Export could not open is not recorded as exported — and the answer counts it", async (t) => {
  const ctx = await instance(t);
  const R = await import("../servers/gateway/keychain/reminder.js");
  const OE = await import("../servers/gateway/satellites/offsite-key.js");
  const express = (await import("express")).default;
  const { keychainApiRouter } = await import("../servers/gateway/keychain/api.js");

  const created = await OE.ensureOffsiteKey(ctx.db, ctx.key);
  const good = await K.saveExtensionSecret(ctx.db, ctx.key, { bundleId: "addon-a", envKey: "FOO", label: "A FOO", secret: SENTINEL, origin: "typed" });
  // A first Export holds everything, so the off-site upload gate is open beforehand.
  await R.recordKeychainExport(ctx.db, ctx.key.id);
  assert.equal(await OE.offsiteKeyInExport(ctx.db), true);

  // The era refuses the off-site key's row now (a v1 blob nothing in this release writes).
  ctx.raw.prepare("UPDATE crow_keychain SET secret_sealed = ? WHERE id = ?").run(v1For(ctx, "moved-elsewhere"), created.id);

  const gate = { method: async () => "password", isGranted: () => true, expiresAt: () => null, verify: async () => ({ ok: true }) };
  const app = express();
  app.use(express.json({ limit: "5mb" }));
  app.use((req, res, next) => { req.dashboardSession = "test-session"; next(); });
  app.use(keychainApiRouter({ gate, openDb: () => ctx.db, isOwner: async () => true, crowHome: ctx.home }));
  const server = await new Promise((r) => { const s = app.listen(0, "127.0.0.1", () => r(s)); });
  try {
    const url = (p) => `http://127.0.0.1:${server.address().port}/dashboard/keychain/api${p}`;
    const prep = await fetch(url("/export"), { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ passphrase: "a long export passphrase" }) });
    assert.equal(prep.status, 200);
    const body = await prep.json();
    assert.equal(body.skipped, 1, "the answer carries a count of the entries left out");
    assert.equal(body.count, 1, "only the readable entry is in the file");
    assert.equal(JSON.stringify(body).includes(SENTINEL), false, "never a value in the answer");
    const dl = await fetch(url(body.download.replace("/dashboard/keychain/api", "")));
    assert.equal(dl.status, 200);
    await new Promise((r) => setTimeout(r, 50)); // the reminder is recorded once the body was sent
  } finally { server.close(); }

  assert.equal(await OE.offsiteKeyInExport(ctx.db), false, "a refused off-site key did NOT go into that Export");
  assert.equal(await R.unexportedCount(ctx.db, ctx.key.id), 1, "the reminder still lists it as not exported");
  assert.equal(await R.entryInLastExport(ctx.db, good.id), true, "the entry that WAS in the file is recorded");
});