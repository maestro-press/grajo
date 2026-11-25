/**
 * §1a / §8 PR 3a of the keyed-token-hashes design: the SETTINGS-BACKED token families.
 *
 * Every per-instance static token the gateway mints keeps its verifier in a dashboard setting
 * (`mcp_local_token_hash` … `kiosk_announce_token_hash`). Those settings are bot-writable, so
 * the verifier is now an `h1.` MAC under `<CROW_HOME>/secrets/token-hmac.key` whose family
 * domain IS the setting key. This file pins, against the real schema, store and validators:
 *
 *   - the pre-listen boot converts every legacy (bare sha256) value, in EITHER settings store,
 *     keeping the raw token working; file-backed families only once the FILE proves the value,
 *     the local MCP token from the stored sha256 itself (design D1);
 *   - a converted family refuses a bare sha256 written afterwards (the forgery a contained bot
 *     can mount) and raises the log+audit alarm — never a credential;
 *   - a value copied from ANOTHER family's setting never verifies (the domain is in the MAC);
 *   - a boot-rotated family is never converted from its stored value, and a rotation failure
 *     restores the old `h1.` value so the previous token keeps working;
 *   - the era is recorded in the secrets-side state file AND the `token_hmac_era:*` mirror,
 *     and is never re-converted;
 *   - a family the boot could not convert refuses its legacy values for the rest of the process.
 *
 * No user-visible text anywhere: the alarm is a console line plus an audit row.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { mkdirSync, mkdtempSync, chmodSync, existsSync, lstatSync, readFileSync, readdirSync, rmSync, statSync, symlinkSync, unlinkSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { dirname, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { createDbClient } from "../servers/db.js";
import { MAX_TOKEN_FILE_BYTES } from "../servers/gateway/token-file-read.js";
import { readSetting, writeSetting } from "../servers/gateway/dashboard/settings/registry.js";
import {
  forgetSettingsTokenEvidence, forgetForcedSettingsLegacyRefusal, ROTATED_AT_BOOT, SETTINGS_TOKEN_FAMILIES,
  settingsTokenRawFile, storedForms,
} from "../servers/gateway/token-settings.js";
import {
  BOOT_ROTATORS, SETTINGS_ROLLBACK_PREFIX, runSettingsTokenHmacBoot,
} from "../servers/gateway/boot/token-hmac-settings.js";
import { readState, tokenMacKeyPath } from "../servers/shared/token-mac.js";
import { TOKEN_STORE_FAMILIES } from "../servers/gateway/token-store.js";
import {
  forgetTokenMacAlarms, forgetTokenMacKey, ensureKey, macToken,
} from "../servers/shared/token-mac.js";
import { isSyncable } from "../servers/gateway/dashboard/settings/sync-allowlist.js";
import {
  generateBoardToken, llmCloudTokenPath, rotateLlmCloudToken, REPORTS_TOKEN, SATELLITE_TOOLS_TOKEN, SECRETS_TOKEN,
  SERVICES_TOKEN, SHARING_BOT_TOKEN,
  validateArtifactsToken, validateBoardToken, validateKioskAnnounceToken, validateLocalToken,
  validateModelsToken, validatePeerRelayToken, validatePhoneToken, generateLocalToken,
  ensureArtifactsToken, ensureBoardToken, ensureKioskAnnounceToken, ensureModelsToken,
} from "../servers/gateway/local-token.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const sha256 = (value) => createHash("sha256").update(String(value)).digest("hex");

const roots = [];
after(() => {
  for (const root of roots) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

const SAVED = {};
for (const key of ["CROW_HOME", "CROW_DATA_DIR", "CROW_DB_PATH"]) SAVED[key] = process.env[key];
after(() => {
  for (const [key, value] of Object.entries(SAVED)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

/**
 * A fresh scratch instance: its own home, data dir and real schema (init-db), and every
 * in-process cache forgotten (the key, the alarm window, the era scan, the §M2 refusal).
 */
function scratch() {
  const home = mkdtempSync(join(tmpdir(), "crow-token-settings-"));
  roots.push(home);
  const dataDir = join(home, "data");
  mkdirSync(dataDir, { recursive: true });
  // The gateway writes `<data dir>/instance-id` on its first boot; `--reset` reads THAT file to
  // target the per-instance settings rows and refuses (exit 1) on a home without one.
  writeFileSync(join(dataDir, "instance-id"), "0123456789abcdef0123456789abcdef", { mode: 0o600 });
  process.env.CROW_HOME = home;
  process.env.CROW_DATA_DIR = dataDir;
  process.env.CROW_DB_PATH = join(dataDir, "crow.db");
  forgetTokenMacKey();
  forgetTokenMacAlarms();
  forgetSettingsTokenEvidence();
  forgetForcedSettingsLegacyRefusal();
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: process.env, cwd: ROOT, stdio: "pipe", timeout: 120_000,
  });
  const db = createDbClient(process.env.CROW_DB_PATH);
  return {
    home,
    db,
    close: () => { try { db.close(); } catch { /* closed */ } },
  };
}

/** The stored value of `family`, from whichever store holds it. */
async function stored(db, family) {
  return readSetting(db, family);
}

/** Plant a legacy verifier the way an install written by the previous release has it. */
async function plantLegacy(db, family, raw) {
  await writeSetting(db, family, sha256(raw), { scope: "local" });
  return sha256(raw);
}

/** Plant a raw token file where that family's mint function writes it. */
function plantTokenFile(family, raw) {
  const path = settingsTokenRawFile(family);
  mkdirSync(dirname(path), { recursive: true });
  writeFileSync(path, raw, { mode: 0o600 });
  return path;
}

const legacyAudits = async (db) => (await db.execute({
  sql: "SELECT details FROM audit_log WHERE event_type = 'token_legacy_form'", args: [],
})).rows;

/** The alarm's audit row is written fire-and-forget, so wait for it instead of racing it. */
async function auditCountAtLeast(db, n, ms = 2_000) {
  const deadline = Date.now() + ms;
  for (;;) {
    // eslint-disable-next-line no-await-in-loop -- a bounded poll
    const count = (await legacyAudits(db)).length;
    if (count >= n || Date.now() > deadline) return count;
    // eslint-disable-next-line no-await-in-loop -- a bounded poll
    await new Promise((r) => { setTimeout(r, 20); });
  }
}

const snapshotFiles = (home) => {
  try {
    return readdirSync(join(home, "secrets")).filter((n) => n.startsWith(SETTINGS_ROLLBACK_PREFIX));
  } catch {
    return [];
  }
};

/** family → the validator a presented raw token goes through. */
const VALIDATORS = {
  "mcp_local_token_hash": validateLocalToken,
  "mcp_board_token_hash": validateBoardToken,
  "mcp_phone_token_hash": validatePhoneToken,
  "mcp_artifacts_token_hash": validateArtifactsToken,
  "mcp_models_token_hash": validateModelsToken,
  "mcp_peer_relay_token_hash": validatePeerRelayToken,
  "kiosk_announce_token_hash": validateKioskAnnounceToken,
};

const FILE_BACKED = [
  "mcp_board_token_hash", "mcp_phone_token_hash", "mcp_artifacts_token_hash",
  "mcp_models_token_hash", "mcp_peer_relay_token_hash", "kiosk_announce_token_hash",
];

/**
 * The six boot-rotated families: how to read the raw token the boot just minted, and the real
 * validator it goes through.
 */
const ROTATED_TOKENS = [
  ["mcp_llm_cloud_token_hash", () => readFileSync(llmCloudTokenPath(), "utf8").trim(),
    (db, token) => validateCloudStored(db, token)],
  ["mcp_services_token_hash", () => readFileSync(SERVICES_TOKEN.path(), "utf8").trim(),
    (db, token) => SERVICES_TOKEN.validate(db, token)],
  ["mcp_satellite_tools_token_hash", () => readFileSync(SATELLITE_TOOLS_TOKEN.path(), "utf8").trim(),
    (db, token) => SATELLITE_TOOLS_TOKEN.validate(db, token)],
  ["mcp_secrets_token_hash", () => readFileSync(SECRETS_TOKEN.path(), "utf8").trim(),
    (db, token) => SECRETS_TOKEN.validate(db, token)],
  ["mcp_sharing_bot_token_hash", () => readFileSync(SHARING_BOT_TOKEN.path(), "utf8").trim(),
    (db, token) => SHARING_BOT_TOKEN.validate(db, token)],
  ["mcp_reports_token_hash", () => readFileSync(REPORTS_TOKEN.path(), "utf8").trim(),
    (db, token) => REPORTS_TOKEN.validate(db, token)],
];

// ─── conversion (§3.2) ────────────────────────────────────────────────────

test("the boot converts every settings family, in place, and every raw token keeps working", async () => {
  const s = scratch();
  try {
    const raws = {};
    for (const family of FILE_BACKED) {
      raws[family] = `raw-${family}`;
      plantTokenFile(family, raws[family]);
      // eslint-disable-next-line no-await-in-loop -- one family at a time, by design
      await plantLegacy(s.db, family, raws[family]);
    }
    // The local MCP token has NO raw copy anywhere: only its stored sha256 (design D1).
    raws["mcp_local_token_hash"] = "raw-mcp_local_token_hash";
    await plantLegacy(s.db, "mcp_local_token_hash", raws["mcp_local_token_hash"]);
    // Boot-rotated families: their stored value is a previous boot's, never converted.
    for (const family of ROTATED_AT_BOOT) {
      raws[family] = `stale-${family}`;
      // eslint-disable-next-line no-await-in-loop -- one family at a time
      await plantLegacy(s.db, family, raws[family]);
    }

    const boot = await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(boot.key, "ok");
    assert.equal(JSON.stringify(boot.families.filter((f) => f.refused || f.state !== "converted")), "[]", "every provable value was converted");

    // Every family whose raw token is known still authenticates, through its own validator.
    for (const [family, validate] of Object.entries(VALIDATORS)) {
      // eslint-disable-next-line no-await-in-loop -- one family at a time
      assert.equal(await validate(s.db, raws[family]), true, `${family}: the raw token still works`);
      // eslint-disable-next-line no-await-in-loop -- one family at a time
      const value = await stored(s.db, family);
      assert.equal(value, macToken(family, raws[family]), `${family}: stored as the family's keyed MAC`);
      assert.match(value, /^h1\.[0-9a-f]{16}\.[0-9a-f]{64}$/);
    }

    // A rotated-at-boot family is NOT converted: THE BOOT ROTATES IT. Its stale value is replaced
    // by a fresh token's keyed verifier (never laundered into a credential the writer of the
    // stale value knows), and because the rotation runs before the era marker, the value in the
    // store when the era appears is already `h1.` — so no later boot can read it as a planted
    // old-style row (that was six false alarms per first upgraded boot).
    for (const [family, freshToken, validate] of ROTATED_TOKENS) {
      // eslint-disable-next-line no-await-in-loop -- one family at a time
      assert.match(String(await stored(s.db, family)), /^h1\./, `${family}: the boot minted the keyed form`);
      // eslint-disable-next-line no-await-in-loop -- one family at a time
      assert.equal(await validate(s.db, raws[family]), false, `${family}: the stale token was not laundered`);
      // eslint-disable-next-line no-await-in-loop -- one family at a time
      assert.equal(await validate(s.db, freshToken()), true, `${family}: the token this boot minted validates`);
      // eslint-disable-next-line no-await-in-loop -- one family at a time
      assert.equal(await validate(s.db, raws[family]), false, `${family}: still not the stale one`);
    }
    assert.ok(boot.families.filter((f) => f.rotated).length === ROTATED_AT_BOOT.length, "every rotated family reports rotated");
    assert.equal(boot.alarms, 0, "no false alarm on the conversion boot");
    // The rotation happens a second time in the pre-listen boot (boot/mcp-mounts.js, h1 -> h1):
    // rotating a keyed family again changes nothing about the form and still validates.
    assert.equal(await rotateLlmCloudToken(s.db).then((t) => validateCloudStored(s.db, t)), true,
      "a later rotation of the keyed family mints a fresh keyed value that validates");
    assert.match(String(await stored(s.db, "mcp_llm_cloud_token_hash")), /^h1\./);

    // The era: the secrets-side state file AND the local-scope DB mirror, for all thirteen.
    const state = readState();
    for (const family of SETTINGS_TOKEN_FAMILIES) {
      assert.ok(state.families[family]?.converted_at, `${family} is marked converted in secrets/`);
      const mirror = (await s.db.execute({
        sql: "SELECT value FROM dashboard_settings_overrides WHERE key = ?",
        args: [`token_hmac_era:${family}`],
      })).rows[0];
      assert.ok(mirror?.value, `${family} is mirrored into the DB`);
    }

    // One snapshot per file-backed + local family, 0600, carrying the PRE-conversion values.
    const files = snapshotFiles(s.home);
    assert.equal(files.length, 7, "board, phone, artifacts, models, peer relay, kiosk and the local token");
    for (const name of files) {
      assert.equal(statSync(join(s.home, "secrets", name)).mode & 0o777, 0o600, `${name} is 0600`);
      const body = JSON.parse(readFileSync(join(s.home, "secrets", name), "utf8"));
      assert.equal(body.v, 1);
      assert.ok(SETTINGS_TOKEN_FAMILIES.includes(body.family));
      for (const row of body.rows) assert.match(row.token, /^[0-9a-f]{64}$/);
    }
    const localSnap = JSON.parse(readFileSync(
      join(s.home, "secrets", files.find((n) => n.includes("mcp-local-token-hash"))), "utf8",
    ));
    assert.deepEqual(localSnap.rows.map((r) => r.token), [sha256(raws["mcp_local_token_hash"])]);

    // A second boot converts NOTHING again (add-only era) and rewrites no value.
    const before = await stored(s.db, "mcp_board_token_hash");
    const second = await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(JSON.stringify(second.families.filter((f) => f.state !== "converted")), "[]", "second boot states");
    assert.equal(second.converted, 0, "never re-converted");
    assert.equal(second.alarms, 0);
    assert.equal(snapshotFiles(s.home).length, files.length, "no second snapshot");
    assert.equal(await stored(s.db, "mcp_board_token_hash"), before);
    assert.equal(await validateBoardToken(s.db, raws["mcp_board_token_hash"]), true);
  } finally {
    s.close();
  }
});

/** The cloud door's validator, imported lazily so the table above stays readable. */
async function validateCloudStored(db, token) {
  const { validateLlmCloudToken } = await import("../servers/gateway/local-token.js");
  return validateLlmCloudToken(db, token);
}

test("a legacy GLOBAL row is moved into this instance's override; one beside an override is anomalous", async () => {
  const s = scratch();
  try {
    // Family A: ONLY the GLOBAL row holds the value (what an older release could have left there).
    // OQ-8: the converter MOVES it into this instance's override, so no working token is lost.
    await s.db.execute({
      sql: "INSERT INTO dashboard_settings (key, value) VALUES (?, ?)",
      args: ["mcp_board_token_hash", sha256("global-board")],
    });
    plantTokenFile("mcp_board_token_hash", "global-board");
    // Family B: the way the product writes (an OVERRIDE) plus a stray GLOBAL row.
    await plantLegacy(s.db, "mcp_phone_token_hash", "override-phone");
    plantTokenFile("mcp_phone_token_hash", "override-phone");
    await s.db.execute({
      sql: "INSERT INTO dashboard_settings (key, value) VALUES (?, ?)",
      args: ["mcp_phone_token_hash", sha256("global-phone")],
    });

    forgetTokenMacAlarms();
    const boot = await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(boot.refusedGlobal, 1, "the global row that coexists with an override is anomalous");
    assert.equal(boot.refused, 1, "and counted as refused, never converted");

    // A: the value lives in the override now, in its keyed form; the global row is gone.
    const boardOverride = (await s.db.execute({
      sql: "SELECT value FROM dashboard_settings_overrides WHERE key = 'mcp_board_token_hash'", args: [],
    })).rows;
    assert.equal(boardOverride.length, 1, "the moved value is this instance's override");
    assert.equal(boardOverride[0].value, macToken("mcp_board_token_hash", "global-board"));
    assert.equal((await s.db.execute({
      sql: "SELECT value FROM dashboard_settings WHERE key = 'mcp_board_token_hash'", args: [],
    })).rows.length, 0, "and the global row was retired");
    assert.equal(await validateBoardToken(s.db, "global-board"), true, "so the raw token still works");

    // B: the override wins, was converted there, and the anomalous global row was deleted — never
    // converted, so the value it held never becomes a credential.
    const phoneOverride = (await s.db.execute({
      sql: "SELECT value FROM dashboard_settings_overrides WHERE key = 'mcp_phone_token_hash'", args: [],
    })).rows[0];
    assert.equal(phoneOverride.value, macToken("mcp_phone_token_hash", "override-phone"), "the override holds the MAC");
    assert.equal((await s.db.execute({
      sql: "SELECT value FROM dashboard_settings WHERE key = 'mcp_phone_token_hash'", args: [],
    })).rows.length, 0, "the anomalous global row is deleted");
    assert.equal(await validatePhoneToken(s.db, "override-phone"), true);
    assert.equal(await validatePhoneToken(s.db, "global-phone"), false, "the global value was never a credential");
    const audits = await legacyAudits(s.db);
    assert.ok(audits.some((row) => JSON.parse(row.details).family === "mcp_phone_token_hash"),
      "the anomaly is alarmed (log + audit only)");
  } finally {
    s.close();
  }
});

test("a file-backed value no file backs is refused, cleared, and the family re-mints", async () => {
  const s = scratch();
  try {
    // A value in the store that the token file does not produce: what a bot would plant.
    const planted = sha256("not-this-instances-token");
    await writeSetting(s.db, "mcp_models_token_hash", planted, { scope: "local" });
    plantTokenFile("mcp_models_token_hash", "the-real-token");

    forgetTokenMacAlarms();
    const boot = await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(boot.refused, 1, "reported, not laundered");
    assert.equal(boot.refusedProofFile, 1, "and attributed to the proof file");
    assert.equal(await stored(s.db, "mcp_models_token_hash"), null,
      "cleared, so the boot's own ensure* has an empty family to mint into");
    assert.equal(await validateModelsToken(s.db, "not-this-instances-token"), false, "never a credential");
    assert.ok(readState().families["mcp_models_token_hash"]?.converted_at, "the era is marked, so it never will be");
    const audits = await legacyAudits(s.db);
    assert.ok(audits.some((row) => JSON.parse(row.details).family === "mcp_models_token_hash"),
      "the alarm is an audit row (log + audit only, no user-visible text)");

    // Leave the family to be RE-MINTED (the pre-listen boot's ensure* runs a moment later): a
    // fresh token, and the file a consumer reads holds it.
    assert.deepEqual(await ensureModelsToken(s.db), { minted: true }, "a fresh token is minted");
    const fresh = readFileSync(settingsTokenRawFile("mcp_models_token_hash"), "utf8").trim();
    assert.equal(await validateModelsToken(s.db, fresh), true, "the re-minted token validates");
    // The planted file's value was never the stored verifier, so it is not one now either.
    assert.equal(await validateModelsToken(s.db, "the-real-token"), false);
  } finally {
    s.close();
  }
});

test("a missing token file refuses the stored value too — and the family re-mints", async () => {
  const s = scratch();
  try {
    await plantLegacy(s.db, "mcp_artifacts_token_hash", "raw-artifacts"); // no file written
    forgetTokenMacAlarms();
    const boot = await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(boot.refused, 1);
    assert.equal(boot.refusedProofFile, 1);
    assert.equal(await validateArtifactsToken(s.db, "raw-artifacts"), false);
    assert.deepEqual(await ensureArtifactsToken(s.db), { minted: true });
    assert.equal(await validateArtifactsToken(s.db, readFileSync(settingsTokenRawFile("mcp_artifacts_token_hash"), "utf8").trim()), true);
    assert.equal(await validateArtifactsToken(s.db, "raw-artifacts"), false);
  } finally {
    s.close();
  }
});

// ─── proof-file trust (a bot-plantable file proves nothing) ────────────────

test("a SYMLINKED token file is not proof: refused, cleared, and a fresh token+file are minted", async () => {
  const s = scratch();
  try {
    // The value's own token sits at a path of the bot's choosing, linked into place: a bot shell
    // can do exactly this, so the link may not launder a value it wrote into the store.
    const raw = "board-raw-behind-a-symlink";
    const real = join(s.home, "bot-owned-token");
    writeFileSync(real, raw, { mode: 0o600 });
    symlinkSync(real, settingsTokenRawFile("mcp_board_token_hash"));
    await plantLegacy(s.db, "mcp_board_token_hash", raw);

    forgetTokenMacAlarms();
    const boot = await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(boot.refusedProofFile, 1, "a symlink proves nothing");
    assert.equal(boot.refused, 1);
    assert.equal(await stored(s.db, "mcp_board_token_hash"), null, "not converted: cleared");
    assert.equal(await validateBoardToken(s.db, raw), false);

    // The boot's own ensure* (boot/mcp-mounts.js) mints: hash absent → a fresh token AND file.
    assert.deepEqual(await ensureBoardToken(s.db), { minted: true });
    const path = settingsTokenRawFile("mcp_board_token_hash");
    assert.equal(lstatSync(path).isSymbolicLink(), false, "the fresh file replaced the symlink");
    assert.equal(statSync(path).mode & 0o777, 0o600);
    const fresh = readFileSync(path, "utf8").trim();
    assert.equal(await validateBoardToken(s.db, fresh), true, "and consumers read a file that validates");
    assert.equal(await validateBoardToken(s.db, raw), false);
  } finally {
    s.close();
  }
});

test("a group/world-writable token file is not proof: refused, cleared, and re-minted 0600", async () => {
  const s = scratch();
  try {
    const raw = "board-raw-in-a-loose-file";
    const path = settingsTokenRawFile("mcp_board_token_hash");
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, raw, { mode: 0o666 });
    chmodSync(path, 0o666);
    await plantLegacy(s.db, "mcp_board_token_hash", raw);

    forgetTokenMacAlarms();
    const boot = await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(boot.refusedProofFile, 1, "anyone with the other bit could point the proof");
    assert.equal(await stored(s.db, "mcp_board_token_hash"), null);
    assert.equal(await validateBoardToken(s.db, raw), false);

    assert.deepEqual(await ensureBoardToken(s.db), { minted: true });
    assert.equal(statSync(path).mode & 0o777, 0o600, "the re-mint is owner-only again");
    assert.equal(await validateBoardToken(s.db, readFileSync(path, "utf8").trim()), true);
    assert.equal(await validateBoardToken(s.db, raw), false);
  } finally {
    s.close();
  }
});

test("a token file inside a group/world-writable directory is not proof either", async () => {
  const s = scratch();
  try {
    const raw = "board-raw-in-a-loose-dir";
    const path = settingsTokenRawFile("mcp_board_token_hash");
    mkdirSync(dirname(path), { recursive: true });
    writeFileSync(path, raw, { mode: 0o600 });
    chmodSync(path, 0o600);
    chmodSync(dirname(path), 0o777);
    await plantLegacy(s.db, "mcp_board_token_hash", raw);

    forgetTokenMacAlarms();
    try {
      const boot = await runSettingsTokenHmacBoot({ db: s.db });
      assert.equal(boot.refusedProofFile, 1, "someone else can replace the file, so it proves nothing");
      assert.equal(await stored(s.db, "mcp_board_token_hash"), null);
      assert.equal(await validateBoardToken(s.db, raw), false);
    } finally {
      chmodSync(dirname(path), 0o700);
    }
    assert.deepEqual(await ensureBoardToken(s.db), { minted: true });
    assert.equal(await validateBoardToken(s.db, readFileSync(path, "utf8").trim()), true);
  } finally {
    s.close();
  }
});

// ─── a planted FIFO may not park a boot (a blocking open hangs before listen) ───

/**
 * Run an ES module body in a child process with a wall-clock cap. A synchronous open that BLOCKS
 * on a FIFO with no writer never settles, so an in-process assertion could not report it — the
 * runner would just sit there until its own timeout. The child makes a hang a FAILURE.
 */
function childRun(code, timeoutMs = 30_000) {
  const r = spawnSync(process.execPath, ["--input-type=module", "-e", code], {
    cwd: ROOT, env: process.env, timeout: timeoutMs, encoding: "utf8", killSignal: "SIGKILL",
  });
  return {
    timedOut: r.error?.code === "ETIMEDOUT" || r.signal === "SIGKILL",
    stdout: r.stdout || "",
    stderr: r.stderr || "",
    status: r.status,
  };
}

/** The child's one result line, or a failure naming what it printed instead. */
function childResult(r) {
  assert.equal(r.timedOut, false, "the child never settled: a read blocked on a planted entry");
  const line = String(r.stdout).split("\n").find((l) => l.startsWith("RESULT:"));
  assert.ok(line, `the child printed no result: ${r.stderr}`);
  return JSON.parse(line.slice("RESULT:".length));
}

/** Can this computer make a FIFO? A host without `mkfifo` reports the FIFO case as skipped. */
function canMakeFifo(dir) {
  const probe = join(dir, `fifo-probe-${process.pid}`);
  try {
    execFileSync("mkfifo", [probe], { stdio: "ignore" });
    return true;
  } catch {
    return false;
  } finally {
    try { unlinkSync(probe); } catch { /* never made */ }
  }
}

/** A FIFO grew no writer, so `openSync` without O_NONBLOCK would park here forever. */
test("a FIFO planted at a proof file's path is refused instead of parking the boot", async (t) => {
  const s = scratch();
  try {
    if (!canMakeFifo(s.home)) return t.skip("mkfifo is not available on this computer");
    // A family the install could legitimately convert, except that the file proving it is a FIFO.
    await plantLegacy(s.db, "mcp_models_token_hash", "the-real-models-token");
    const path = plantTokenFile("mcp_models_token_hash", "the-real-models-token");
    unlinkSync(path);
    execFileSync("mkfifo", [path], { stdio: "ignore" });
    assert.equal(lstatSync(path).isFIFO(), true, "the proof file path is a FIFO");

    const result = childResult(childRun(`
      const { createDbClient } = await import(${JSON.stringify(join(ROOT, "servers/db.js"))});
      const { runSettingsTokenHmacBoot } = await import(${JSON.stringify(join(ROOT, "servers/gateway/boot/token-hmac-settings.js"))});
      const db = createDbClient(process.env.CROW_DB_PATH);
      const boot = await runSettingsTokenHmacBoot({ db });
      db.close();
      console.log("RESULT:" + JSON.stringify({
        key: boot.key, refused: boot.refused, refusedProofFile: boot.refusedProofFile,
      }));
    `));
    assert.deepEqual(result, { key: "ok", refused: 1, refusedProofFile: 1 },
      "the boot finished, and the value no FIFO can prove is refused");
    assert.equal(await stored(s.db, "mcp_models_token_hash"), null, "cleared, so the family re-mints");
    assert.equal(await validateModelsToken(s.db, "the-real-models-token"), false, "never a credential");

    // The pre-listen boot's own ensure* replaces the planted FIFO with a real 0600 file.
    assert.deepEqual(await ensureModelsToken(s.db), { minted: true });
    assert.equal(statSync(path).isFile(), true, "a regular file replaced the FIFO");
    assert.equal(statSync(path).mode & 0o777, 0o600);
    assert.equal(await validateModelsToken(s.db, readFileSync(path, "utf8").trim()), true);
  } finally {
    s.close();
  }
});

// ─── forgery and the family domain (§2.2, §3.3) ───────────────────────────

test("after conversion a bare sha256 planted in EITHER store is refused; a global row is never read", async () => {
  const s = scratch();
  try {
    const boardRaw = "board-token-raw";
    plantTokenFile("mcp_board_token_hash", boardRaw);
    await plantLegacy(s.db, "mcp_board_token_hash", boardRaw);          // this instance's OVERRIDE
    plantTokenFile("mcp_phone_token_hash", "phone-raw");
    await s.db.execute({                                                // a legacy GLOBAL row: moved in
      sql: "INSERT INTO dashboard_settings (key, value) VALUES (?, ?)",
      args: ["mcp_phone_token_hash", sha256("phone-raw")],
    });
    await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(await validateBoardToken(s.db, boardRaw), true);
    assert.equal(await validatePhoneToken(s.db, "phone-raw"), true);

    // The forgery a contained bot can mount: write sha256(its own token) into the setting.
    const botToken = "bot-chosen-token";
    await writeSetting(s.db, "mcp_board_token_hash", sha256(botToken), { scope: "local" });
    forgetTokenMacAlarms();
    assert.equal(await validateBoardToken(s.db, botToken), false, "refused on the override");
    assert.ok(await auditCountAtLeast(s.db, 1) >= 1, "and alarmed");

    // The same write in the GLOBAL row (OQ-8: no validator reads it any more).
    await s.db.execute({
      sql: "INSERT OR REPLACE INTO dashboard_settings (key, value) VALUES (?, ?)",
      args: ["mcp_phone_token_hash", sha256("bot-phone")],
    });
    assert.equal(await validatePhoneToken(s.db, "bot-phone"), false, "never read, so never a credential");
    assert.equal(await validatePhoneToken(s.db, "phone-raw"), true, "and the override beside it is untouched");
    // What reports it is the boot scan (log + audit only).
    const auditsBefore = (await legacyAudits(s.db)).length;
    forgetTokenMacAlarms();
    const boot = await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(boot.refusedGlobal, 1, "the later boot reports the global row");
    assert.ok(await auditCountAtLeast(s.db, auditsBefore + 1) > auditsBefore, "and alarms it");

    // Nor does a planted value survive as an h1 the bot could have computed.
    assert.equal(await validateBoardToken(s.db, boardRaw), false, "the genuine token was replaced");
  } finally {
    s.close();
  }
});

test("a MAC copied across families never verifies: the family is inside the MAC", async () => {
  const s = scratch();
  try {
    const raw = "a-real-board-token";
    plantTokenFile("mcp_board_token_hash", raw);
    await plantLegacy(s.db, "mcp_board_token_hash", raw);
    await plantLegacy(s.db, "mcp_local_token_hash", "local-raw");
    await runSettingsTokenHmacBoot({ db: s.db });

    const boardValue = await stored(s.db, "mcp_board_token_hash");
    assert.match(boardValue, /^h1\./);
    // A bot knows its own board token and can read that token's `h1.` value out of the setting.
    await writeSetting(s.db, "mcp_local_token_hash", boardValue, { scope: "local" });
    assert.equal(await validateLocalToken(s.db, raw), false, "refused under the local-token family");
    // The copy changes nothing about the family it was minted for (the raw token is not a local
    // token, and the board setting was never touched):
    assert.equal(await validateLocalToken(s.db, "local-raw"), false);
  } finally {
    s.close();
  }
});

test("a legacy value in a family converted by a PREVIOUS boot is refused, never accepted", async () => {
  const s = scratch();
  try {
    await plantLegacy(s.db, "mcp_phone_token_hash", "phone-raw");
    plantTokenFile("mcp_phone_token_hash", "phone-raw");
    await runSettingsTokenHmacBoot({ db: s.db });
    // An old-style row written by something without the key, after the era.
    await writeSetting(s.db, "mcp_phone_token_hash", sha256("late-write"), { scope: "local" });
    forgetTokenMacAlarms();
    assert.equal(await validatePhoneToken(s.db, "late-write"), false);
    const boot = await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(boot.alarms, 1, "the boot scan reports it");
    assert.equal(await stored(s.db, "mcp_phone_token_hash"), sha256("late-write"), "still not converted");
  } finally {
    s.close();
  }
});

// ─── the boot-rotated families (§3.2) ─────────────────────────────────────

test("every boot-rotated family has its rotator, and no rotator is orphaned", () => {
  assert.deepEqual([...Object.keys(BOOT_ROTATORS)].sort(), [...ROTATED_AT_BOOT].sort(),
    "a family added to one list and not the other could be marked converted over an old-style value");
});

test("a rotated family is keyed BEFORE its era, so only a later old-style write alarms", async () => {
  const s = scratch();
  try {
    for (const family of ROTATED_AT_BOOT) {
      // eslint-disable-next-line no-await-in-loop -- one family at a time
      await plantLegacy(s.db, family, `stale-${family}`);
    }
    // The first upgraded boot: every one of the six is minted fresh and no alarm is raised for the
    // value the previous release legitimately left there.
    const first = await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(first.alarms, 0, "the conversion boot reports no alarm");
    for (const family of ROTATED_AT_BOOT) {
      // eslint-disable-next-line no-await-in-loop -- one family at a time
      assert.equal((await storedForms(s.db, family)).filter((f) => /^[0-9a-f]{64}$/.test(f.value)).length, 0,
        `${family}: nothing old-style is left when its era appears`);
    }
    const second = await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(second.alarms, 0, "nor does the next boot");
    assert.equal(second.converted, 0, "nothing left to convert");

    // Now something WITHOUT the key writes an old-style value into a converted, rotated family:
    // that is the write the alarm exists for, and it is never converted.
    await writeSetting(s.db, "mcp_reports_token_hash", sha256("late-report"), { scope: "local" });
    forgetTokenMacAlarms();
    const third = await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(third.alarms, 1, "the boot scan reports it");
    assert.equal(await stored(s.db, "mcp_reports_token_hash"), sha256("late-report"), "still not converted");
    assert.equal(await REPORTS_TOKEN.validate(s.db, "late-report"), false, "and never a credential");
  } finally {
    s.close();
  }
});

test("a boot rotation that leaves an old-style value behind records NO era", async () => {
  const s = scratch();
  try {
    await plantLegacy(s.db, "mcp_llm_cloud_token_hash", "stale-cloud");
    // The cloud door's failure path RESTORES the previous value, so a failed rename leaves the
    // old-style form in place — the one case where marking the era would alarm on this box's own
    // previous token. It must fail the family instead: no era, no alarm, refused this process.
    rmSync(llmCloudTokenPath(), { force: true });
    mkdirSync(llmCloudTokenPath());
    const boot = await runSettingsTokenHmacBoot({ db: s.db });
    const entry = boot.families.find((f) => f.family === "mcp_llm_cloud_token_hash");
    assert.equal(entry.state, "failed");
    assert.equal(readState().families.mcp_llm_cloud_token_hash?.converted_at, undefined,
      "no era is recorded over an old-style value");
    assert.equal(boot.alarms, 0, "and nothing is accused of being a planted row");
    assert.equal(await validateCloudStored(s.db, "stale-cloud"), false,
      "the value is refused for the rest of this process (§M2), and the next boot retries");
  } finally {
    s.close();
  }
});

// ─── a §2.6 / §M2 failure stays closed ────────────────────────────────────

test("an unwritable secrets/ SKIPS the family: no era, the legacy value stays accepted", async () => {
  const s = scratch();
  try {
    await plantLegacy(s.db, "kiosk_announce_token_hash", "kiosk-raw");
    plantTokenFile("kiosk_announce_token_hash", "kiosk-raw");
    const boot = await runSettingsTokenHmacBoot({
      db: s.db,
      writeSnapshot: () => { const err = new Error("read-only"); err.code = "EROFS"; throw err; },
    });
    const entry = boot.families.find((f) => f.family === "kiosk_announce_token_hash");
    assert.equal(entry.state, "skipped");
    assert.equal(readState().families.kiosk_announce_token_hash?.converted_at, undefined, "no era recorded");
    assert.equal(await validateKioskAnnounceToken(s.db, "kiosk-raw"), true, "legacy stays accepted (unprotected)");
  } finally {
    s.close();
  }
});

test("a conversion that FAILS (not skips) refuses that family's legacy value for this process", async () => {
  const s = scratch();
  try {
    await plantLegacy(s.db, "mcp_peer_relay_token_hash", "relay-raw");
    plantTokenFile("mcp_peer_relay_token_hash", "relay-raw");
    const realExecute = s.db.execute.bind(s.db);
    const failingDb = {
      execute: async (stmt) => {
        if (/INSERT INTO dashboard_settings_overrides/.test(String(stmt?.sql))
          && stmt?.args?.[0] === "mcp_peer_relay_token_hash") {
          const err = new Error("disk I/O error");
          err.code = "EIO";
          throw err;
        }
        return realExecute(stmt);
      },
    };
    const boot = await runSettingsTokenHmacBoot({ db: failingDb });
    const entry = boot.families.find((f) => f.family === "mcp_peer_relay_token_hash");
    assert.equal(entry.state, "failed");
    assert.equal(readState().families.mcp_peer_relay_token_hash?.converted_at, undefined);
    // The process refuses the value even though the disk says "not converted" (§M2).
    assert.equal(await validatePeerRelayToken(s.db, "relay-raw"), false);
  } finally {
    s.close();
  }
});

// ─── rotation restore (§3.2) ──────────────────────────────────────────────

test("a rotation that fails at the rename puts the old h1 value back, and it still validates", async () => {
  const s = scratch();
  try {
    // The cloud-door family is rotated at every boot, so a boot leaves it keyed.
    await plantLegacy(s.db, "mcp_llm_cloud_token_hash", "stale-cloud");
    await runSettingsTokenHmacBoot({ db: s.db });
    const before = await rotateLlmCloudToken(s.db);
    const hashBefore = await readSetting(s.db, "mcp_llm_cloud_token_hash");
    assert.match(String(hashBefore), /^h1\./, "the stored form is the keyed MAC");
    // Make the rename fail: the destination is a directory.
    rmSync(llmCloudTokenPath(), { force: true });
    mkdirSync(llmCloudTokenPath());
    await assert.rejects(() => rotateLlmCloudToken(s.db));
    assert.equal(await readSetting(s.db, "mcp_llm_cloud_token_hash"), hashBefore, "the old h1 value is back");
    assert.equal(await validateCloudStored(s.db, before), true, "and the previous token still validates");
  } finally {
    s.close();
  }
});

// ─── the unconverted install (§2.6 row 4) ─────────────────────────────────

test("an UNCONVERTED install still accepts its legacy value (no key, no era, no h1 value)", async () => {
  const s = scratch();
  try {
    const raw = "legacy-only-token";
    await plantLegacy(s.db, "mcp_local_token_hash", raw);
    // No boot has run: no key, no era marker, no keyed value anywhere.
    assert.equal(await validateLocalToken(s.db, raw), true, "§2.6 row 4 keeps an unconverted install working");
    assert.equal(await validateLocalToken(s.db, "wrong"), false);
    // The boot converts the stored value (it needs no raw token), so the same raw token goes on
    // working — but a bare sha256 written AFTER the era is refused.
    await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(await validateLocalToken(s.db, raw), true, "the converted value is still this token");
    await writeSetting(s.db, "mcp_local_token_hash", sha256(raw), { scope: "local" });
    forgetTokenMacAlarms();
    assert.equal(await validateLocalToken(s.db, raw), false, "the boot's era refuses the bare sha256");
  } finally {
    s.close();
  }
});

// ─── a writer mints the way the product does ──────────────────────────────

test("every mint writes the keyed form, so a generated token validates and a copied one does not", async () => {
  const s = scratch();
  try {
    const token = await generateBoardToken(s.db);
    assert.match(String(await stored(s.db, "mcp_board_token_hash")), /^h1\./);
    assert.equal(await validateBoardToken(s.db, token), true);
    const local = await generateLocalToken(s.db);
    assert.equal(await validateLocalToken(s.db, local), true);
    assert.equal(await validateLocalToken(s.db, token), false, "a board token is never the local token");
    // The raw token still reaches the file a bot's config reads.
    assert.equal(readFileSync(settingsTokenRawFile("mcp_board_token_hash"), "utf8").trim(), token);
  } finally {
    s.close();
  }
});

// ─── the reset rail (§2.6) ────────────────────────────────────────────────

test("`token-hmac.mjs --reset` drops the settings verifiers and KEEPS the era, so each family re-mints", async () => {
  const s = scratch();
  try {
    const raw = "board-raw-before-reset";
    plantTokenFile("mcp_board_token_hash", raw);
    await plantLegacy(s.db, "mcp_board_token_hash", raw);
    await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(await validateBoardToken(s.db, raw), true);
    s.close();
    execFileSync(process.execPath, [
      join(ROOT, "scripts/token-hmac.mjs"), "--reset", "--yes", "--force-while-running",
    ], { cwd: ROOT, env: process.env, stdio: "pipe", timeout: 120_000 });

    const db = createDbClient(process.env.CROW_DB_PATH);
    try {
      // The verifier is gone (the next boot re-mints it), and the token it stood for no longer
      // validates — the key it was minted under was retired.
      assert.equal(await readSetting(db, "mcp_board_token_hash"), null);
      assert.equal(await validateBoardToken(db, raw), false);
      // The ERA is not cleared: a bare sha256 written now is still a forgery, not a credential.
      assert.ok(readState().families.mcp_board_token_hash?.converted_at, "still converted");
      await writeSetting(db, "mcp_board_token_hash", sha256(raw), { scope: "local" });
      forgetTokenMacAlarms();
      assert.equal(await validateBoardToken(db, raw), false, "refused after the reset too");
    } finally {
      db.close();
    }
  } finally {
    s.close();
  }
});

test("`token-hmac.mjs --reset` marks EVERY family converted, so a settings value planted afterwards is never laundered", async () => {
  const s = scratch();
  try {
    // The box this protects: the key was lost BEFORE the settings conversion ever ran, so no
    // settings family has an era and the stored verifier is still the previous release's form.
    await plantLegacy(s.db, "mcp_local_token_hash", "pre-era-local");
    assert.equal(existsSync(tokenMacKeyPath()), false, "the modelled box has no key at all");
    s.close();
    execFileSync(process.execPath, [
      join(ROOT, "scripts/token-hmac.mjs"), "--reset", "--yes", "--force-while-running",
    ], { cwd: ROOT, env: process.env, stdio: "pipe", timeout: 120_000 });

    // Step 4 marked all sixteen families — the three oauth_tokens ones and the thirteen settings
    // ones — in the secrets-side state file AND the `token_hmac_era:*` DB mirror.
    const state = readState();
    const db = createDbClient(process.env.CROW_DB_PATH);
    try {
      for (const family of [...TOKEN_STORE_FAMILIES, ...SETTINGS_TOKEN_FAMILIES]) {
        assert.ok(state.families[family]?.converted_at, `${family} is converted after the reset`);
        // eslint-disable-next-line no-await-in-loop -- sixteen families, one assertion each
        const mirror = (await db.execute({
          sql: "SELECT value FROM dashboard_settings_overrides WHERE key = ?",
          args: [`token_hmac_era:${family}`],
        })).rows[0];
        assert.ok(mirror?.value, `${family}'s DB mirror is written as converted`);
      }

      // What a bot can do while the gateway is stopped (its units keep running): write the legacy
      // form of a token IT chose into the local MCP token's setting. No raw file ever backed that
      // family, so an unmarked family would be CONVERTED into `h1.sha256(sha256(x))` by the next
      // boot — owner authority from a row the bot wrote.
      const chosen = "bot-chosen-local-token";
      await writeSetting(db, "mcp_local_token_hash", sha256(chosen), { scope: "local" });
      forgetTokenMacAlarms();
      const boot = await runSettingsTokenHmacBoot({ db });
      const entry = boot.families.find((f) => f.family === "mcp_local_token_hash");
      assert.equal(entry.state, "converted");
      assert.equal(entry.count ?? 0, 0, "nothing was converted: the era was already recorded");
      assert.equal(entry.alarms, 1, "the planted value is refused and reported");
      assert.equal(await validateLocalToken(db, chosen), false, "and it is never a credential");
      assert.equal(await stored(db, "mcp_local_token_hash"), sha256(chosen), "left exactly as written");
      assert.ok((await legacyAudits(db)).some((row) => JSON.parse(row.details).family === "mcp_local_token_hash"),
        "the alarm is an audit row");
    } finally {
      db.close();
    }
  } finally {
    s.close();
  }
});

test("`--reset` refuses on a home with no instance-id: a made-up id would delete nothing", async () => {
  const s = scratch();
  try {
    const legacy = await plantLegacy(s.db, "mcp_board_token_hash", "board-before-the-refusal");
    s.close();
    // A home the gateway never gave an id (its first boot writes that file).
    unlinkSync(join(s.home, "data", "instance-id"));
    let out;
    try {
      execFileSync(process.execPath, [
        join(ROOT, "scripts/token-hmac.mjs"), "--reset", "--yes", "--force-while-running",
      ], { cwd: ROOT, env: process.env, stdio: "pipe", timeout: 120_000 });
      out = { code: 0, text: "" };
    } catch (err) {
      out = { code: err.status, text: `${err.stdout || ""}${err.stderr || ""}` };
    }
    assert.equal(out.code, 1, out.text);
    assert.match(out.text, /instance-id/, "the refusal names the missing file");
    assert.match(out.text, /Nothing was changed/);
    assert.equal(existsSync(tokenMacKeyPath()), false, "no key was minted");
    const db = createDbClient(process.env.CROW_DB_PATH);
    try {
      // Read by VALUE, not through `readSetting`: with the id file gone, a settings read mints a
      // fresh per-process id and finds nothing — which is exactly the bug this refusal prevents.
      const rows = (await db.execute({
        sql: "SELECT value FROM dashboard_settings_overrides WHERE key = ?", args: ["mcp_board_token_hash"],
      })).rows;
      assert.equal(rows[0]?.value, legacy, "the verifier was not touched");
    } finally {
      db.close();
    }
  } finally {
    s.close();
  }
});

// ─── ensure*: the file and the stored verifier must AGREE (§3.4) ──────────

test("ensure* re-checks the file against the stored verifier and re-mints on a mismatch", async () => {
  const s = scratch();
  try {
    const first = await generateBoardToken(s.db);
    assert.deepEqual(await ensureBoardToken(s.db), { minted: false }, "a matching file is a no-op");

    // A bot writes junk into the setting (it can reach crow.db; the file still holds the real
    // token). Merely checking that the file EXISTS would leave the board door verifying a value
    // no token can satisfy — a dead door reported as healthy.
    await writeSetting(s.db, "mcp_board_token_hash", "planted-junk", { scope: "local" });
    forgetTokenMacAlarms();
    assert.deepEqual(await ensureBoardToken(s.db), { minted: true }, "the mismatch is re-minted");
    const fresh = readFileSync(settingsTokenRawFile("mcp_board_token_hash"), "utf8").trim();
    assert.notEqual(fresh, first, "a fresh token, not the old one");
    assert.equal(await validateBoardToken(s.db, fresh), true, "the board door works with the new file");
    assert.equal(await validateBoardToken(s.db, first), false, "the previous token is gone with it");
    assert.deepEqual(await ensureBoardToken(s.db), { minted: false }, "and it settles: file and verifier agree");

    // The same rule from the file's side, on another family of the shared helper: a file that
    // holds something that does not verify (another family's token, a stale value, junk) is
    // replaced, not trusted.
    await ensureKioskAnnounceToken(s.db);
    const kioskPath = settingsTokenRawFile("kiosk_announce_token_hash");
    writeFileSync(kioskPath, "another-family-token", { mode: 0o600 });
    forgetTokenMacAlarms();
    assert.deepEqual(await ensureKioskAnnounceToken(s.db), { minted: true }, "a file that does not verify is replaced");
    assert.equal(await validateKioskAnnounceToken(s.db, readFileSync(kioskPath, "utf8").trim()), true);
    assert.equal(await validateKioskAnnounceToken(s.db, "another-family-token"), false);
  } finally {
    s.close();
  }
});

test("ensure* leaves the token alone when the verifier cannot answer: a lock is not a mismatch", async () => {
  const s = scratch();
  try {
    const token = await generateBoardToken(s.db);
    const path = settingsTokenRawFile("mcp_board_token_hash");
    const storedBefore = await readSetting(s.db, "mcp_board_token_hash");
    const fileBefore = readFileSync(path, "utf8");
    assert.match(String(storedBefore), /^h1\./, "the family starts keyed and settled");

    // A slow writer (a bot holding a write lock) at boot: the ensure's OWN read gets through, then
    // the VERIFIER's read of the same row fails with SQLITE_BUSY. Answering "false" there — what
    // the old catch did — rotated the board/models/peer-relay/kiosk/phone token over a lock that
    // clears in milliseconds, breaking every consumer of the file for nothing.
    const realExecute = s.db.execute.bind(s.db);
    let familyReads = 0;
    const busyDb = {
      execute: async (stmt) => {
        const sql = String(stmt?.sql || "");
        const args = Array.isArray(stmt?.args) ? stmt.args : [];
        if (/FROM dashboard_settings_overrides WHERE key = \? AND instance_id = \?/.test(sql)
          && args[0] === "mcp_board_token_hash") {
          familyReads += 1;
          if (familyReads > 1) {
            const err = new Error("SQLITE_BUSY: database is locked");
            err.code = "SQLITE_BUSY";
            throw err;
          }
        }
        return realExecute(stmt);
      },
    };
    const warnings = [];
    const realWarn = console.warn;
    console.warn = (...parts) => { warnings.push(parts.join(" ")); };
    let result;
    try {
      result = await ensureBoardToken(busyDb);
    } finally {
      console.warn = realWarn;
    }

    assert.deepEqual(result, { minted: false }, "cannot tell is never a re-mint");
    assert.equal(await readSetting(s.db, "mcp_board_token_hash"), storedBefore, "the stored verifier is untouched");
    assert.equal(readFileSync(path, "utf8"), fileBefore, "and so is the file the bots read");
    assert.equal(await validateBoardToken(s.db, token), true, "the same token still opens the board door");

    // One fixed line, and never the token or a hash in it.
    assert.equal(warnings.filter((w) => w.includes(path)).length, 1, "exactly one line about this file");
    const line = warnings.find((w) => w.includes(path));
    assert.match(line, /could not be checked/);
    assert.ok(!line.includes(token) && !/[0-9a-f]{64}/.test(line), "the line carries no value");

    // The real mismatch is still a re-mint (the "could not tell" path did not become a no-op).
    writeFileSync(path, "not-this-instances-token", { mode: 0o600 });
    assert.deepEqual(await ensureBoardToken(s.db), { minted: true }, "a real mismatch still re-mints");
    assert.equal(await validateBoardToken(s.db, token), false, "and the old token is gone with it");
  } finally {
    s.close();
  }
});

/**
 * The other half of the same hole: `ensure*` re-checks the raw file against the stored verifier,
 * and a plain `readFileSync` there followed a symlink, blocked forever on a FIFO and slurped a
 * file of any size. Every kind of them is a DEFINITE mismatch (the file is not this instance's
 * token), so the family is re-minted — and re-minting replaces the entry, never writes through it.
 * Each ensure runs in a child, so a blocking open is a failure instead of a stalled runner.
 */
test("a FIFO, an oversized file or a symlink at the board-token path re-mints, without hanging", async (t) => {
  const s = scratch();
  try {
    const path = settingsTokenRawFile("mcp_board_token_hash");
    let current = await generateBoardToken(s.db);
    assert.equal(readFileSync(path, "utf8").trim(), current);

    const ensureInChild = () => childResult(childRun(`
      const { createDbClient } = await import(${JSON.stringify(join(ROOT, "servers/db.js"))});
      const { ensureBoardToken, validateBoardToken } = await import(${JSON.stringify(join(ROOT, "servers/gateway/local-token.js"))});
      const { readFileSync } = await import("node:fs");
      const db = createDbClient(process.env.CROW_DB_PATH);
      const result = await ensureBoardToken(db);
      const fresh = readFileSync(${JSON.stringify(path)}, "utf8").trim();
      const ok = await validateBoardToken(db, fresh);
      db.close();
      console.log("RESULT:" + JSON.stringify({ minted: result.minted, ok }));
    `));

    const kinds = [];
    if (canMakeFifo(s.home)) kinds.push("fifo");
    else t.diagnostic("mkfifo is not available on this computer: the FIFO kind is not covered here");
    kinds.push("oversize", "symlink");

    for (const kind of kinds) {
      try { unlinkSync(path); } catch { /* already gone: the plant decides */ }
      if (kind === "fifo") execFileSync("mkfifo", [path], { stdio: "ignore" });
      if (kind === "oversize") writeFileSync(path, "x".repeat(MAX_TOKEN_FILE_BYTES + 1), { mode: 0o600 });
      if (kind === "symlink") {
        // The link's target holds the CURRENT token, so following the link would have matched:
        // a re-mint here proves the link is refused, not merely that its bytes disagree.
        const target = join(s.home, "bot-owned-board-token");
        writeFileSync(target, current, { mode: 0o600 });
        symlinkSync(target, path);
      }

      // eslint-disable-next-line no-await-in-loop -- one planted kind at a time, by design
      const result = await ensureInChild();
      assert.deepEqual(result, { minted: true, ok: true }, `${kind}: re-minted, and the new file validates`);
      assert.equal(lstatSync(path).isSymbolicLink(), false, `${kind}: replaced by a plain file of ours`);
      assert.equal(statSync(path).isFile(), true, `${kind}: a regular file now`);
      assert.equal(statSync(path).mode & 0o777, 0o600, `${kind}: owner-only again`);
      const fresh = readFileSync(path, "utf8").trim();
      assert.match(fresh, /^[0-9a-f]{64}$/, `${kind}: a fresh token`);
      assert.notEqual(fresh, current, `${kind}: not the value that was planted`);
      // eslint-disable-next-line no-await-in-loop -- one planted kind at a time
      assert.equal(await validateBoardToken(s.db, fresh), true, `${kind}: the board door works off the new file`);
      // eslint-disable-next-line no-await-in-loop -- one planted kind at a time
      assert.equal(await validateBoardToken(s.db, current), false, `${kind}: the previous token is gone`);
      current = fresh;
    }
  } finally {
    s.close();
  }
});

// ─── a crash between the snapshot and the era (§3.2 step 6) ───────────────

test("a crash re-run converts ONLY the snapshot's rows and alarms anything written since", async () => {
  const s = scratch();
  try {
    // Exactly the state a crash between the rewrite and `markConverted` leaves: a key, no era for
    // this family, the family's snapshot on disk, and a value something wrote AFTER the snapshot.
    const key = ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    const snapshotValue = sha256("snapshot-local");
    const plantedLater = sha256("planted-after-the-snapshot");
    await writeSetting(s.db, "mcp_local_token_hash", snapshotValue, { scope: "local" });
    await s.db.execute({
      sql: "INSERT INTO dashboard_settings (key, value) VALUES (?, ?)",
      args: ["mcp_local_token_hash", plantedLater],
    });
    writeFileSync(join(s.home, "secrets", `${SETTINGS_ROLLBACK_PREFIX}2026-01-02T03-04-05-000Z-mcp-local-token-hash.json`), JSON.stringify({
      v: 1,
      family: "mcp_local_token_hash",
      key_id: key.id,
      created_at: "2026-01-02T03:04:05.000Z",
      rows: [{ store: "local", key: "mcp_local_token_hash", token: snapshotValue }],
    }), { mode: 0o600 });

    forgetTokenMacAlarms();
    const boot = await runSettingsTokenHmacBoot({ db: s.db });
    const entry = boot.families.find((f) => f.family === "mcp_local_token_hash");
    assert.equal(entry.count, 1, "only the snapshot's row is converted");
    assert.match(String((await storedForms(s.db, "mcp_local_token_hash"))[0].value), /^h1\./);
    assert.equal(entry.refused, 1, "the post-snapshot write is refused");
    assert.equal(entry.refusedGlobal, 1, "it sat in the global row, which is never read");
    assert.equal(entry.alarms, 1, "and reported, not laundered");
    assert.equal((await storedForms(s.db, "mcp_local_token_hash")).length, 1,
      "the anomalous global row was deleted by value, so nothing of it is left to read");
    assert.ok(readState().families.mcp_local_token_hash?.converted_at, "the era is recorded now");
  } finally {
    s.close();
  }
});

test("a value written over the snapshot's row between crash and restart is never converted", async () => {
  const s = scratch();
  try {
    // The snapshot names ONE value in the override; the store now holds a DIFFERENT one. Nothing
    // may be converted — converting the new value would launder a bot's write into a credential.
    const key = ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    const snapshotValue = sha256("snapshot-local-overwritten");
    const botChosen = sha256("bot-chosen-after-the-crash");
    await writeSetting(s.db, "mcp_local_token_hash", botChosen, { scope: "local" });
    writeFileSync(join(s.home, "secrets", `${SETTINGS_ROLLBACK_PREFIX}2026-01-03T03-04-05-000Z-mcp-local-token-hash.json`), JSON.stringify({
      v: 1,
      family: "mcp_local_token_hash",
      key_id: key.id,
      created_at: "2026-01-03T03:04:05.000Z",
      rows: [{ store: "local", key: "mcp_local_token_hash", token: snapshotValue }],
    }), { mode: 0o600 });

    forgetTokenMacAlarms();
    const boot = await runSettingsTokenHmacBoot({ db: s.db });
    const entry = boot.families.find((f) => f.family === "mcp_local_token_hash");
    assert.equal(entry.count, 0, "the snapshot's value is gone, so nothing may be converted");
    assert.equal(entry.refused, 1);
    assert.equal(entry.alarms, 1);
    assert.equal(await stored(s.db, "mcp_local_token_hash"), botChosen, "left exactly as it was written");
    assert.equal(await validateLocalToken(s.db, "bot-chosen-after-the-crash"), false, "and never a credential");
  } finally {
    s.close();
  }
});

test("an EMPTY snapshot is still pending: a value written after it is refused, not converted, and the family is marked", async () => {
  const s = scratch();
  try {
    // The family held no old-style value when the snapshot was taken; the process died before the
    // era marker. A restart must not read the empty file as "no snapshot" and convert whatever
    // was written since.
    const key = ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    const plantedLater = sha256("planted-after-an-empty-snapshot");
    await writeSetting(s.db, "mcp_local_token_hash", plantedLater, { scope: "local" });
    writeFileSync(join(s.home, "secrets", `${SETTINGS_ROLLBACK_PREFIX}2026-01-04T03-04-05-000Z-mcp-local-token-hash.json`), JSON.stringify({
      v: 1,
      family: "mcp_local_token_hash",
      key_id: key.id,
      created_at: "2026-01-04T03:04:05.000Z",
      rows: [],
    }), { mode: 0o600 });

    forgetTokenMacAlarms();
    const boot = await runSettingsTokenHmacBoot({ db: s.db });
    const entry = boot.families.find((f) => f.family === "mcp_local_token_hash");
    assert.equal(entry.count, 0, "the snapshot lists nothing, so nothing is converted");
    assert.equal(entry.refused, 1, "the post-snapshot value is refused");
    assert.equal(entry.alarms, 1, "and reported, not laundered");
    assert.equal(await stored(s.db, "mcp_local_token_hash"), plantedLater, "left exactly as it was written");
    assert.equal(await validateLocalToken(s.db, "planted-after-an-empty-snapshot"), false, "never a credential");
    assert.ok(readState().families.mcp_local_token_hash?.converted_at, "the family is marked converted now");
    assert.equal(snapshotFiles(s.home).length, 1, "the empty snapshot is reused, not replaced");
  } finally {
    s.close();
  }
});

// ─── sync (§6.9, OQ-4) ────

test("no verifier key, no password and no device record is ever syncable", () => {
  for (const key of [...SETTINGS_TOKEN_FAMILIES, "password_hash", "meta_glasses_devices"]) {
    assert.equal(isSyncable(key), false, `${key} must never leave through instance-sync`);
  }
});

// ─── the operator dry run (§8) ────────────────────────────────────────────

const DRYRUN = join(ROOT, "scripts/ops/settings-token-hmac-dryrun.mjs");

/** Run the dry run against a COPY label of the scratch DB; returns {code, out}. */
function dryrun(s, label, filesFrom) {
  try {
    const out = execFileSync(process.execPath, [
      DRYRUN, "--db", `${label}=${join(dirname(process.env.CROW_DB_PATH), "crow.db")}`,
      "--files-from", filesFrom,
    ], { cwd: ROOT, encoding: "utf8", stdio: "pipe", timeout: 120_000 });
    return { code: 0, out };
  } catch (err) {
    return { code: err.status ?? 1, out: `${err.stdout || ""}${err.stderr || ""}` };
  }
}

test("the dry run rehearses a copy: PASS when every value converts, STOP when one would be refused", async () => {
  const s = scratch();
  try {
    plantTokenFile("mcp_board_token_hash", "board-raw");
    await plantLegacy(s.db, "mcp_board_token_hash", "board-raw");
    await plantLegacy(s.db, "mcp_local_token_hash", "local-raw");
    // A real instance's store also holds each boot-rotated family's PREVIOUS boot value. The
    // rehearsal must simulate the rotation exactly as the real boot does — in its own scratch
    // home — or it would report six old-style values and STOP on a box where nothing is wrong.
    for (const family of ROTATED_AT_BOOT) {
      // eslint-disable-next-line no-await-in-loop -- one family at a time
      await plantLegacy(s.db, family, `stale-${family}`);
    }
    s.close();

    const pass = dryrun(s, "crow", s.home);
    assert.equal(pass.code, 0, pass.out);
    assert.match(pass.out, /^PASS:/m, "one verdict line");
    assert.match(pass.out, /converted 1/);
    assert.match(pass.out, /rotated \(the boot mints a fresh keyed value\)/, "the rotation is rehearsed too");
    assert.match(pass.out, /0 refused \(0 by proof file, 0 as an anomalous global row\)/, "refusals are split by reason");
    // Never a token or a hash on stdout.
    assert.ok(!/[0-9a-f]{64}/.test(pass.out), "the rehearsal prints no hash and no token");
    assert.ok(!pass.out.includes("board-raw") && !pass.out.includes("local-raw"));
    // The rehearsal changed nothing at the source: the era there is untouched, and the rotation
    // minted its fresh tokens into the SCRATCH home, never the source instance's files.
    assert.equal(readState().families.mcp_board_token_hash, undefined);
    assert.equal(existsSync(join(s.home, "llm-cloud-token")), false, "no token file minted at the source home");
    assert.equal(existsSync(join(s.home, "secrets", "services-token")), false, "no family token minted at the source home");

    // Now a stored value that its token file does not back: the run must STOP, not report PASS.
    const s2 = scratch();
    try {
      await writeSetting(s2.db, "mcp_models_token_hash", sha256("planted"), { scope: "local" });
      plantTokenFile("mcp_models_token_hash", "the-real-token");
      s2.close();
      const stop = dryrun(s2, "r4", s2.home);
      assert.equal(stop.code, 1, stop.out);
      assert.match(stop.out, /^STOP:/m);
      assert.match(stop.out, /1 by proof file/, "the reason is reported");
      assert.ok(!/[0-9a-f]{64}/.test(stop.out), "the rehearsal prints no hash and no token");
    } finally {
      /* s2 closed above */
    }

    // And a value in the GLOBAL row beside an override: anomalous, so the rehearsal STOPs too
    // (the real boot deletes it and alarms; the operator has to know before the upgrade).
    const s3 = scratch();
    try {
      await plantLegacy(s3.db, "mcp_models_token_hash", "models-raw");
      plantTokenFile("mcp_models_token_hash", "models-raw");
      await s3.db.execute({
        sql: "INSERT INTO dashboard_settings (key, value) VALUES (?, ?)",
        args: ["mcp_models_token_hash", sha256("global-side")],
      });
      s3.close();
      const stop = dryrun(s3, "raven", s3.home);
      assert.equal(stop.code, 1, stop.out);
      assert.match(stop.out, /^STOP:/m);
      assert.match(stop.out, /1 as an anomalous global row/, "the reason is reported");
      assert.ok(!/[0-9a-f]{64}/.test(stop.out), "the rehearsal prints no hash and no token");
    } finally {
      /* s3 closed above */
    }

    // And the REAL file: a token file that is a SYMLINK proves nothing to the real boot — but the
    // rehearsal COPIES the file, following the link, so its own proof would succeed. The source
    // trust check is what turns that into a STOP, so a PASS covers the box's actual files.
    const s4 = scratch();
    try {
      await plantLegacy(s4.db, "mcp_board_token_hash", "symlinked-raw");
      const target = join(s4.home, "not-the-token-file");
      writeFileSync(target, "symlinked-raw", { mode: 0o600 });
      symlinkSync(target, settingsTokenRawFile("mcp_board_token_hash"));
      s4.close();
      const stop = dryrun(s4, "rook", s4.home);
      assert.equal(stop.code, 1, stop.out);
      assert.match(stop.out, /^STOP:/m);
      assert.match(stop.out, /SOURCE token file/, "the real file is named as the reason");
      assert.ok(!/[0-9a-f]{64}/.test(stop.out), "the rehearsal prints no hash and no token");
    } finally {
      /* s4 closed above */
    }
  } finally {
    s.close();
  }
});

// ─── static guards ────────────────────────────────────────────────────────

function walk(dir, out = []) {
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const path = join(dir, entry.name);
    if (entry.isDirectory()) {
      if (entry.name === "node_modules") continue;
      walk(path, out);
    } else if (entry.name.endsWith(".js") || entry.name.endsWith(".mjs")) {
      out.push(path);
    }
  }
  return out;
}

/** Comments stripped, so a prose mention of a setting key is not a validator. */
function code(src) {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/(^|[^:])\/\/[^\n]*/g, "$1");
}

test("static: only the owning modules name a settings token family, and none of them compares hashes itself", () => {
  const owners = new Set([
    "servers/shared/token-mac.js",
    "servers/gateway/token-settings.js",
    "servers/gateway/boot/token-hmac-settings.js",
    "servers/gateway/local-token.js",
  ]);
  const familyLiteral = /"(?:mcp_[a-z0-9_]+_token_hash|kiosk_announce_token_hash)"/;
  for (const path of [...walk(join(ROOT, "servers")), ...walk(join(ROOT, "scripts")), ...walk(join(ROOT, "bundles"))]) {
    const rel = relative(ROOT, path);
    if (owners.has(rel)) continue;
    const src = code(readFileSync(path, "utf8"));
    assert.ok(!familyLiteral.test(src),
      `${rel} names a settings token family: every read of one must go through verifySettingsToken `
      + "(servers/gateway/token-settings.js), which is verifyStored under that family's domain");
  }

  const local = readFileSync(join(ROOT, "servers/gateway/local-token.js"), "utf8");
  assert.ok(!/timingSafeEqual|createHash/.test(local),
    "local-token.js compares no hash itself: every validator delegates to verifySettingsToken");
  // The six single-family validators, the path-scoped factory, the cloud door and the peer-relay
  // legacy-file check: every one of them goes through the same keyed compare.
  assert.ok((local.match(/verifySettingsToken\(/g) || []).length >= 8,
    "every family in local-token.js validates through verifySettingsToken");
});

test("static: the settings boot runs before the gateway listens, after the oauth_tokens one", () => {
  const index = readFileSync(join(ROOT, "servers/gateway/index.js"), "utf8");
  const oauthBoot = index.indexOf("runTokenHmacBoot");
  const settingsBoot = index.indexOf("runSettingsTokenHmacBoot");
  const listen = index.indexOf("app.listen(PORT, BIND");
  assert.ok(oauthBoot > 0 && settingsBoot > oauthBoot, "the §1a boot follows the oauth_tokens boot");
  assert.ok(settingsBoot < listen, "and both run before the gateway listens (zero window)");
});

test("static: storedForms is what the converter reads, so a planted value in either store is seen", async () => {
  const s = scratch();
  try {
    await plantLegacy(s.db, "mcp_board_token_hash", "override-side");
    await s.db.execute({
      sql: "INSERT INTO dashboard_settings (key, value) VALUES (?, ?)",
      args: ["mcp_phone_token_hash", sha256("global-side")],
    });
    const board = await storedForms(s.db, "mcp_board_token_hash");
    assert.deepEqual(board.map((f) => f.store), ["local"]);
    const phone = await storedForms(s.db, "mcp_phone_token_hash");
    assert.deepEqual(phone.map((f) => f.store), ["global"]);
  } finally {
    s.close();
  }
});
// ─── round 2 (H1) ─────────────────────────────────────────────────────────

test("H1: an era recorded ONLY in the database is adopted into the state file; a sha256 value planted after the mirror is deleted stays refused and is never converted", async () => {
  const s = scratch();
  try {
    ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    const { eraSettingKey } = await import("../servers/shared/token-mac.js");
    for (const family of SETTINGS_TOKEN_FAMILIES) {
      // eslint-disable-next-line no-await-in-loop -- thirteen families
      await writeSetting(s.db, eraSettingKey(family), new Date().toISOString(), { scope: "local" });
    }
    assert.equal(readState().families.mcp_board_token_hash, undefined, "precondition: the state file has no era");
    const first = await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(first.key, "ok");
    for (const family of SETTINGS_TOKEN_FAMILIES) {
      assert.ok(readState().families[family]?.converted_at, `${family}: the era is now in the state file`);
    }
    assert.deepEqual(snapshotFiles(s.home), [], "adopted, not converted: no snapshot");
    assert.ok((await legacyAudits(s.db)).some((r) => JSON.parse(r.details).mirror === true));

    await s.db.execute({ sql: "DELETE FROM dashboard_settings_overrides WHERE key LIKE 'token_hmac_era:%'", args: [] });
    forgetTokenMacAlarms();
    await plantLegacy(s.db, "mcp_board_token_hash", "bot-board-after-mirror-delete");
    assert.equal(await validateBoardToken(s.db, "bot-board-after-mirror-delete"), false, "refused at runtime");
    const second = await runSettingsTokenHmacBoot({ db: s.db });
    assert.equal(await stored(s.db, "mcp_board_token_hash"), sha256("bot-board-after-mirror-delete"), "not converted");
    assert.ok(second.alarms >= 1, "and alarmed");
    assert.equal(await validateBoardToken(s.db, "bot-board-after-mirror-delete"), false);
  } finally {
    s.close();
  }
});

// ─── round 3 ──────────────────────────────────────────────────────────────

function withUnreadableMirror(db) {
  return new Proxy(db, {
    get(target, prop) {
      if (prop !== "execute") return target[prop];
      return (statement) => {
        const sql = String(typeof statement === "string" ? statement : statement?.sql ?? "");
        const args = Array.isArray(statement?.args) ? statement.args : [];
        if (/^\s*SELECT/i.test(sql) && args.some((a) => String(a).startsWith("token_hmac_era:"))) {
          throw new Error("disk I/O error (simulated)");
        }
        return target.execute(statement);
      };
    },
  });
}

test("M-B: an unreadable mirror does not postpone the era: with no marker the boot converts and records it", async () => {
  const s = scratch();
  try {
    ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    plantTokenFile("mcp_board_token_hash", "board-raw-r3");
    await plantLegacy(s.db, "mcp_board_token_hash", "board-raw-r3");
    const boot = await runSettingsTokenHmacBoot({ db: withUnreadableMirror(s.db) });
    assert.equal(boot.key, "ok");
    assert.ok(readState().families.mcp_board_token_hash?.converted_at, "the state file has the marker");
    assert.equal(await stored(s.db, "mcp_board_token_hash"), macToken("mcp_board_token_hash", "board-raw-r3"));
    assert.equal(await validateBoardToken(s.db, "board-raw-r3"), true);
  } finally {
    s.close();
  }
});

test("M-B: a failed adoption write still takes the conversion path", async () => {
  const s = scratch();
  try {
    ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    const { eraSettingKey } = await import("../servers/shared/token-mac.js");
    for (const family of SETTINGS_TOKEN_FAMILIES) {
      // eslint-disable-next-line no-await-in-loop -- thirteen families
      await writeSetting(s.db, eraSettingKey(family), new Date().toISOString(), { scope: "local" });
    }
    plantTokenFile("mcp_board_token_hash", "board-raw-r3b");
    await plantLegacy(s.db, "mcp_board_token_hash", "board-raw-r3b");
    const { adoptMirrorOnlyEra } = await import("../servers/gateway/boot/token-hmac-era-adopt.js");
    await runSettingsTokenHmacBoot({
      db: s.db,
      adoptEra: (family, opts) => adoptMirrorOnlyEra(family, { ...opts, mark: async () => { throw new Error("state write failed (simulated)"); } }),
    });
    assert.ok(readState().families.mcp_board_token_hash?.converted_at);
    assert.equal(await stored(s.db, "mcp_board_token_hash"), macToken("mcp_board_token_hash", "board-raw-r3b"), "converted, not scanned");
  } finally {
    s.close();
  }
});
