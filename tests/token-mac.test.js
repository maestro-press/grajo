/**
 * The keyed (HMAC) verifier core — PR 1 of the keyed-token-hashes design (§8).
 *
 * What these tests pin, in the design's own terms:
 *   - the key file (`secrets/token-hmac.key`, 0600 in a 0700 dir) is created once and reused;
 *   - the stored form is `h1.<keyId>.<hex HMAC-SHA256(K, "crow-token-mac-v1\0" + family + "\0" +
 *     sha256hex(token))>` (§2.2), deterministic, and the legacy sha256 converts offline;
 *   - the FAMILY DOMAIN stops the copy attack (§2.3): a board token's stored value does not
 *     verify under the local-token family or an OAuth access row;
 *   - the FORGERY is refused after conversion and a bare-hex row raises exactly one alarm per
 *     family per 24 h; before conversion the same legacy value still authenticates (§3.3);
 *   - the state file's era markers are add-only and survive a reload, and either copy of the
 *     marker (secrets or the `token_hmac_era:<family>` DB mirror) makes a family converted
 *     (§2.5);
 *   - `keyState()` is first-boot / lost / invalid, and a key is created ONLY in first-boot
 *     (§2.6) — never silently after an era, never against a state file (even one that records
 *     only the key id), and never to replace an unreadable, loose, foreign or symlinked file;
 *   - a corrupt state file fails CLOSED: every writer throws and leaves the bytes alone, every
 *     era query answers "converted", and keyState never answers first-boot;
 *   - the state file's read-modify-write takes a cross-process lock, so two owner CLIs marking
 *     different families keep both;
 *   - `converted` is a required boolean, and with no key and no era the legacy form is still
 *     accepted (§2.6 row 4);
 *   - the key is loaded once per process and a changed file fails closed on an explicit reload;
 *   - the password pepper's `p2$` round-trip (salt bound into the input), and a wrong password
 *     fails.
 *
 * Everything runs in a scratch CROW_HOME; nothing here touches a real instance.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn } from "node:child_process";
import {
  chmodSync, existsSync, lstatSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync,
  statSync, symlinkSync, utimesSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createHash, randomBytes, scrypt } from "node:crypto";
import { promisify } from "node:util";
import {
  TOKEN_MAC_FAMILIES, PASSWORD_FAMILY, TOKEN_MAC_ALARM_WINDOW_MS, TokenMacKeyError,
  TokenMacStateError, ensureKey, eraSettingKey, familyConverted, forgetTokenMacAlarms,
  forgetTokenMacKey, keyState, legacyAlarm, macFromLegacy, macToken, markConverted,
  noteEraEvidence, parsePepper,
  pepperFromLegacy, pepperPassword, readState, reloadTokenMacKey, tokenMacKeyPath,
  tokenMacStatePath, verifyPepper, verifyPepperPassword, verifyStored,
} from "../servers/shared/token-mac.js";

const scryptAsync = promisify(scrypt);
const MODULE_PATH = new URL("../servers/shared/token-mac.js", import.meta.url).pathname;

function scratch() {
  const home = mkdtempSync(join(tmpdir(), "crow-token-mac-"));
  const secrets = join(home, "secrets");
  forgetTokenMacKey();
  forgetTokenMacAlarms();
  return {
    home,
    secrets,
    keyPath: join(secrets, "token-hmac.key"),
    statePath: join(secrets, "token-hmac-state.json"),
    cleanup: () => { forgetTokenMacKey(); forgetTokenMacAlarms(); rmSync(home, { recursive: true, force: true }); },
  };
}

const sha256Hex = (s) => createHash("sha256").update(s).digest("hex");

/** The only key-creation call shape: `allowCreate` demands both era-evidence flags (M5). */
const CREATE = { allowCreate: true, mirrorConverted: false, h1ValuesExist: false };
const IS_ROOT = typeof process.getuid === "function" && process.getuid() === 0;

// ─── the key file ──────────────────────────────────────────────────────────

test("the key is created 0600 inside a 0700 secrets dir, then reused with a stable keyId", () => {
  const s = scratch();
  try {
    assert.equal(keyState({ crowHome: s.home }), "first-boot", "no key, no era");
    const first = ensureKey({ crowHome: s.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    assert.equal(first.secret.length, 32);
    assert.match(first.id, /^[0-9a-f]{16}$/);
    assert.equal((statSync(s.secrets).mode & 0o777), 0o700, "secrets dir is 0700");
    assert.equal((statSync(s.keyPath).mode & 0o777), 0o600, "key file is 0600");
    const j = JSON.parse(readFileSync(s.keyPath, "utf8"));
    assert.equal(j.v, 1);
    assert.equal(j.id, first.id, "the id is written beside the key");
    assert.equal(Buffer.from(j.key, "base64").length, 32);
    assert.equal(first.id, createHash("sha256").update(first.secret).digest("hex").slice(0, 16), "keyId = sha256(key)[0:16]");

    // A second load in the same process hits the cache; a fresh process re-reads the same key.
    assert.equal(ensureKey({ crowHome: s.home }).id, first.id, "cached");
    forgetTokenMacKey();
    const again = ensureKey({ crowHome: s.home });
    assert.equal(again.id, first.id, "reused from disk");
    assert.ok(again.secret.equals(first.secret));
    // The state file records the key's identity (and is 0600).
    const st = readState({ crowHome: s.home });
    assert.equal(st.key_id, first.id);
    assert.ok(st.created_at);
    assert.equal((statSync(s.statePath).mode & 0o777), 0o600);
  } finally { s.cleanup(); }
});

// ─── the MAC and the family domain ─────────────────────────────────────────

test("macToken is deterministic and is exactly the §2.2 byte layout", async () => {
  const s = scratch();
  try {
    const key = ensureKey({ crowHome: s.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    const token = "a".repeat(64);
    const family = "mcp_board_token_hash";
    const value = macToken(family, token, { crowHome: s.home });
    assert.equal(value, macToken(family, token, { crowHome: s.home }), "deterministic");
    assert.match(value, /^h1\.[0-9a-f]{16}\.[0-9a-f]{64}$/);

    // Recomputed here from the spec line, byte for byte, with the raw HMAC (not the module).
    const { createHmac } = await import("node:crypto");
    const expected = createHmac("sha256", key.secret)
      .update("crow-token-mac-v1\0" + family + "\0" + sha256Hex(token))
      .digest("hex");
    assert.equal(value, `h1.${key.id}.${expected}`);
  } finally { s.cleanup(); }
});

test("THE COPY ATTACK: a value minted for one family never verifies under another (§2.3)", () => {
  const s = scratch();
  try {
    ensureKey({ crowHome: s.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    const boardToken = "board-token-" + "b".repeat(48);
    const boardStored = macToken("mcp_board_token_hash", boardToken, { crowHome: s.home });

    for (const family of ["mcp_local_token_hash", "oauth:access", "dashboard:session", "peer:inbound"]) {
      const r = verifyStored(family, boardToken, boardStored, { converted: true, crowHome: s.home });
      assert.deepEqual(r, { ok: false, form: "h1" }, family + " must refuse a copied h1 value");
    }
    // The same value is fine in its own family, and a different family mints a different value.
    assert.equal(verifyStored("mcp_board_token_hash", boardToken, boardStored, { converted: true, crowHome: s.home }).ok, true);
    assert.notEqual(macToken("mcp_local_token_hash", boardToken, { crowHome: s.home }), boardStored);
    assert.notEqual(macToken("oauth:access", boardToken, { crowHome: s.home }), boardStored);
  } finally { s.cleanup(); }
});

test("THE FORGERY: a bot's own sha256 is refused after conversion, alarms once, and works before it", () => {
  const s = scratch();
  try {
    ensureKey({ crowHome: s.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    const botToken = "bot-planted-" + "c".repeat(48);
    const planted = sha256Hex(botToken); // what a bot with only DB write access can compute
    const audits = [];
    const audit = (eventType, details) => { audits.push({ eventType, details }); };
    const family = "mcp_local_token_hash";

    // Pre-conversion: exactly today's behaviour, so no client breaks and the converter has time.
    assert.deepEqual(
      verifyStored(family, botToken, planted, { converted: false, crowHome: s.home }),
      { ok: true, form: "legacy" },
    );

    // Post-conversion: refused, form "legacy", one audit row.
    const once = verifyStored(family, botToken, planted, { converted: true, rowRef: "r1", audit, crowHome: s.home });
    assert.deepEqual(once, { ok: false, form: "legacy" });
    assert.equal(audits.length, 1);
    assert.equal(audits[0].eventType, "token_legacy_form");
    assert.equal(audits[0].details.family, family);
    assert.equal(audits[0].details.row, "r1");

    // The console line is de-duplicated per family per 24 h — retrying cannot flush it — but
    // every DISTINCT row reference still gets its own audit row.
    verifyStored(family, botToken, planted, { converted: true, rowRef: "r2", audit, crowHome: s.home });
    verifyStored(family, botToken, planted, { converted: true, audit, crowHome: s.home });
    assert.equal(audits.length, 3, "one audit row per distinct row ref (r1, r2, null)");
    assert.equal(legacyAlarm(family, "r3", { audit }), false, "still inside the window: no console line");
    assert.equal(audits.length, 4, "...but the new row r3 was audited");
    // Another family has its own window.
    assert.equal(legacyAlarm("oauth:access", "row-9", { audit }), true);
    assert.equal(audits.length, 5);
    // A window is 24 hours; just past it the alarm fires again.
    assert.equal(legacyAlarm(family, "r4", { audit, now: Date.now() + TOKEN_MAC_ALARM_WINDOW_MS + 1 }), true);
    assert.equal(audits.length, 6, "a new window re-arms the console line and audits r4");
    // The legacy value never authenticates through a converted family, whatever is presented.
    const legits = sha256Hex("some other token");
    assert.deepEqual(
      verifyStored(family, "some other token", legits, { converted: true, crowHome: s.home }),
      { ok: false, form: "legacy" },
    );
  } finally { s.cleanup(); }
});

test("the alarm is log-only: it writes an audit row and never throws without one", () => {
  const s = scratch();
  try {
    ensureKey({ crowHome: s.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    forgetTokenMacAlarms();
    assert.equal(legacyAlarm("report:link", "link-1"), true, "no audit injected is fine");
    let calls = 0;
    const throwingAudit = () => { calls += 1; throw new Error("db closed"); };
    forgetTokenMacAlarms();
    assert.equal(legacyAlarm("password", null, { audit: throwingAudit }), true, "an audit failure never breaks the refusal");
    assert.equal(calls, 1);
    forgetTokenMacAlarms();
    const asyncAudit = () => Promise.reject(new Error("nope"));
    assert.equal(legacyAlarm("peer:inbound", "row", { audit: asyncAudit }), true);
    // A family carrying the MAC's field separator is refused outright (domain collision).
    assert.throws(() => legacyAlarm("oauth\0access"), TypeError);
  } finally { s.cleanup(); }
});

test("macFromLegacy(family, sha256(token)) === macToken(family, token) — the offline conversion", () => {
  const s = scratch();
  try {
    ensureKey({ crowHome: s.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    for (const family of ["mcp_board_token_hash", "oauth:refresh", "report:link"]) {
      const token = randomBytes(32).toString("hex");
      assert.equal(
        macFromLegacy(family, sha256Hex(token), { crowHome: s.home }),
        macToken(family, token, { crowHome: s.home }),
        family + ": the stored legacy value IS the MAC input",
      );
      // Uppercase hex converts to the same value (the input is normalised).
      assert.equal(
        macFromLegacy(family, sha256Hex(token).toUpperCase(), { crowHome: s.home }),
        macToken(family, token, { crowHome: s.home }),
      );
    }
    assert.throws(() => macFromLegacy("oauth:access", "not-hex", { crowHome: s.home }), TypeError);
    // A converted row verifies with the raw token afterwards.
    const token = "t-" + randomBytes(16).toString("hex");
    const stored = macFromLegacy("oauth:access", sha256Hex(token), { crowHome: s.home });
    assert.deepEqual(verifyStored("oauth:access", token, stored, { converted: true, crowHome: s.home }), { ok: true, form: "h1" });
  } finally { s.cleanup(); }
});

test("a foreign keyId, a malformed value and a wrong token are all refused", () => {
  const s = scratch();
  try {
    const key = ensureKey({ crowHome: s.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    const token = "tok-" + "d".repeat(48);
    const stored = macToken("mcp_local_token_hash", token, { crowHome: s.home });

    // Another key's id: a restore mismatch, refused and named as such.
    const foreign = stored.replace(`h1.${key.id}.`, "h1." + "0".repeat(16) + ".");
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", token, foreign, { converted: true, crowHome: s.home }),
      { ok: false, form: "foreign" },
    );
    // Right key, wrong token.
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", token + "x", stored, { converted: true, crowHome: s.home }),
      { ok: false, form: "h1" },
    );
    // Malformed values.
    for (const bad of ["", "h1", "h1.abc.def", "h2." + key.id + "." + "0".repeat(64), "00ff", null, undefined, 42]) {
      assert.equal(verifyStored("mcp_local_token_hash", token, bad, { converted: true, crowHome: s.home }).ok, false, String(bad));
      assert.equal(verifyStored("mcp_local_token_hash", token, bad, { converted: true, crowHome: s.home }).form, "invalid", String(bad));
    }
    // A legacy value is only ever compared to sha256(token).
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", token, sha256Hex(token), { converted: false, crowHome: s.home }),
      { ok: true, form: "legacy" },
    );
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", "nope", sha256Hex(token), { converted: false, crowHome: s.home }),
      { ok: false, form: "legacy" },
    );
  } finally { s.cleanup(); }
});

test("the verifier compares secrets in constant time (a code scan of verifyStored)", () => {
  const src = readFileSync(MODULE_PATH, "utf8");
  // The comparison helper is real timingSafeEqual, never a string compare.
  const helper = src.slice(src.indexOf("function safeEqualHex("), src.indexOf("}", src.indexOf("function safeEqualHex(")));
  assert.match(helper, /timingSafeEqual\(/, "safeEqualHex uses crypto.timingSafeEqual");
  assert.match(helper, /left\.length !== right\.length/, "length guard, so timingSafeEqual cannot throw");
  // And every branch of verifyStored goes through it: the only `ok: true` returns are after a
  // safeEqualHex() call on the very same expression.
  const start = src.indexOf("export function verifyStored(");
  const end = src.indexOf("\n}\n", start);
  const body = src.slice(start, end);
  const okLines = body.split("\n").filter((line) => line.includes("ok: true"));
  assert.ok(okLines.length >= 2, "verifyStored has its success returns: " + okLines.length);
  for (const line of okLines) {
    assert.match(line, /safeEqualHex\(/, "an ok: true return must be a timing-safe compare: " + line.trim());
  }
  assert.equal(/stored\s*===\s*[^"\s]|===\s*stored/.test(body), false, "never a direct string compare of the stored value");
});

// ─── the state file (§2.5) ─────────────────────────────────────────────────

test("markConverted is add-only, survives a reload, and either copy of the era makes it converted", async () => {
  const s = scratch();
  try {
    ensureKey({ crowHome: s.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    const mirror = new Map();
    const readSetting = async (key) => mirror.get(key) ?? null;
    const writeSetting = async (key, value, opts) => { assert.deepEqual(opts, { scope: "local" }); mirror.set(key, value); };

    assert.equal(await familyConverted("oauth:access", { crowHome: s.home, readSetting }), false);
    const first = await markConverted("oauth:access", {
      count: 12, rollbackFile: "token-hmac-rollback-1.json", writeSetting, crowHome: s.home,
    });
    assert.equal(first.changed, true);
    assert.ok(first.converted_at);
    assert.equal(mirror.get(eraSettingKey("oauth:access")), first.converted_at, "mirrored to the DB setting key");
    assert.equal(await familyConverted("oauth:access", { crowHome: s.home, readSetting }), true);
    // The secrets copy alone is enough (a bot can delete the DB mirror).
    assert.equal(await familyConverted("oauth:access", { crowHome: s.home }), true);

    const st = readState({ crowHome: s.home });
    assert.deepEqual(st.families["oauth:access"], {
      converted_at: first.converted_at, count: 12, rollback_file: "token-hmac-rollback-1.json",
    });
    assert.equal((statSync(s.statePath).mode & 0o777), 0o600, "state file is 0600");

    // Add-only: marking again keeps the FIRST converted_at and changes nothing.
    const second = await markConverted("oauth:access", { count: 99, writeSetting, crowHome: s.home });
    assert.equal(second.changed, false);
    assert.equal(second.converted_at, first.converted_at);
    assert.equal(readState({ crowHome: s.home }).families["oauth:access"].count, 12, "the first record stands");

    // A reload (a fresh read) still sees it.
    assert.equal(readState({ crowHome: s.home }).families["oauth:access"].converted_at, first.converted_at);
    // An unrelated family is still pending.
    assert.equal(await familyConverted("report:link", { crowHome: s.home, readSetting }), false);

    // The mirror ALONE is enough when the secrets copy was restored from an older backup.
    const other = scratch();
    try {
      ensureKey({ crowHome: other.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
      mirror.set(eraSettingKey("peer:inbound"), "2026-11-23T00:00:00.000Z");
      assert.equal(await familyConverted("peer:inbound", { crowHome: other.home, readSetting }), true);
      // "0" / "" / false are NOT an era.
      mirror.set(eraSettingKey("password"), "0");
      assert.equal(await familyConverted("password", { crowHome: other.home, readSetting }), false);
      // A reader that throws fails CLOSED: "we could not tell" is not "not converted".
      const broken = async () => { throw new Error("db closed"); };
      assert.equal(await familyConverted(PASSWORD_FAMILY, { crowHome: other.home, readSetting: broken }), true);
    } finally { other.cleanup(); }

    // A family string that could collide with the MAC domain is refused.
    await assert.rejects(() => markConverted("oauth\0access", { crowHome: s.home }), TypeError);
    await assert.rejects(() => familyConverted("", { crowHome: s.home }), TypeError);
  } finally { s.cleanup(); }
});

// ─── key states (§2.6) ────────────────────────────────────────────────────

test("keyState: first-boot creates; lost refuses and never auto-creates; invalid is never replaced", async () => {
  const s = scratch();
  try {
    // first-boot: the only state that may create.
    assert.equal(keyState({ crowHome: s.home }), "first-boot");
    assert.throws(() => ensureKey({ crowHome: s.home }), (err) => err.code === "TOKEN_MAC_KEY_MISSING");
    const key = ensureKey({ crowHome: s.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    assert.equal(keyState({ crowHome: s.home }), "ok");

    // Lost: the state file shows an era, the key file is gone.
    const lostHome = scratch();
    try {
      ensureKey({ crowHome: lostHome.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
      await markConverted("mcp_local_token_hash", { count: 1, crowHome: lostHome.home });
      forgetTokenMacKey();
      rmSync(lostHome.keyPath);
      assert.equal(keyState({ crowHome: lostHome.home }), "lost");
      assert.throws(
        () => ensureKey({ crowHome: lostHome.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: false }),
        (err) => err instanceof TokenMacKeyError && err.code === "TOKEN_MAC_KEY_LOST",
        "an era exists: a new key is NEVER created silently",
      );
      assert.equal(keyState({ crowHome: lostHome.home }), "lost", "and it is still lost afterwards");
      // h1 values in a store are evidence too, and a DB mirror alone is as well.
      const fresh = scratch();
      try {
        assert.equal(keyState({ crowHome: fresh.home, h1ValuesExist: true }), "lost");
        assert.equal(keyState({ crowHome: fresh.home, mirrorConverted: true }), "lost");
        assert.throws(
          () => ensureKey({ crowHome: fresh.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: true }),
          (err) => err.code === "TOKEN_MAC_KEY_LOST",
        );
      } finally { fresh.cleanup(); }
      // verifyStored fails closed on a lost key, with the reason, never a sha256 fallback.
      const token = "t0k3n-" + "e".repeat(40);
      const r = verifyStored("mcp_local_token_hash", token, sha256Hex(token), { converted: false, crowHome: lostHome.home });
      assert.deepEqual(r, { ok: false, form: "invalid", reason: "key-lost" });
    } finally { lostHome.cleanup(); }

    // Invalid: wrong length / bad JSON is refused and the file is left exactly as it was.
    for (const body of [
      JSON.stringify({ v: 1, id: "0".repeat(16), key: Buffer.alloc(8).toString("base64") }),
      JSON.stringify({ v: 1, id: "nothex", key: randomBytes(32).toString("base64") }),
      "not json at all",
      "",
    ]) {
      const bad = scratch();
      try {
        mkdirSync(bad.secrets, { recursive: true, mode: 0o700 });
        writeFileSync(bad.keyPath, body, { mode: 0o600 });
        assert.equal(keyState({ crowHome: bad.home }), "invalid", "invalid key file: " + JSON.stringify(body));
        assert.throws(
          () => ensureKey({ crowHome: bad.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: false }),
          (err) => err instanceof TokenMacKeyError && err.code === "TOKEN_MAC_KEY_INVALID",
          "an invalid key is NEVER replaced automatically",
        );
        assert.equal(readFileSync(bad.keyPath, "utf8"), body, "the file is untouched, for the operator");
      } finally { bad.cleanup(); }
    }

    // A DIRECTORY where the key belongs is invalid too (and not replaced).
    const dirCase = scratch();
    try {
      mkdirSync(dirCase.keyPath, { recursive: true });
      assert.equal(keyState({ crowHome: dirCase.home }), "invalid");
      assert.throws(() => ensureKey({ crowHome: dirCase.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: false }), (err) => err.code === "TOKEN_MAC_KEY_INVALID");
      assert.equal(statSync(dirCase.keyPath).isDirectory(), true, "still a directory: nothing was created in its place");
    } finally { dirCase.cleanup(); }

    // A corrupt STATE file with no key is fail-closed: "lost", never first-boot.
    const corrupt = scratch();
    try {
      mkdirSync(corrupt.secrets, { recursive: true, mode: 0o700 });
      writeFileSync(corrupt.statePath, "{ this is not json", { mode: 0o600 });
      assert.equal(keyState({ crowHome: corrupt.home }), "lost");
      assert.throws(() => ensureKey({ crowHome: corrupt.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: false }), (err) => err.code === "TOKEN_MAC_KEY_LOST");
      assert.equal(await familyConverted("oauth:access", { crowHome: corrupt.home }), true, "a corrupt era record refuses legacy");
    } finally { corrupt.cleanup(); }
  } finally { s.cleanup(); }
});

test("the key path is <CROW_HOME>/secrets/token-hmac.key and resolves from CROW_HOME at call time", () => {
  assert.equal(tokenMacKeyPath({ crowHome: "/tmp/x" }), "/tmp/x/secrets/token-hmac.key");
  assert.equal(tokenMacStatePath({ crowHome: "/tmp/x" }), "/tmp/x/secrets/token-hmac-state.json");
  assert.equal(tokenMacKeyPath({ path: "/tmp/y/token-hmac.key" }), "/tmp/y/token-hmac.key");
  assert.equal(tokenMacStatePath({ path: "/tmp/y/token-hmac.key" }), "/tmp/y/token-hmac-state.json", "beside the key it describes");
  const previous = process.env.CROW_HOME;
  process.env.CROW_HOME = "/tmp/env-home";
  try {
    assert.equal(tokenMacKeyPath(), "/tmp/env-home/secrets/token-hmac.key");
  } finally {
    if (previous === undefined) delete process.env.CROW_HOME; else process.env.CROW_HOME = previous;
  }
});

test("TOKEN_MAC_FAMILIES lists every store's domain, including the table-backed ones", () => {
  for (const family of [
    "mcp_local_token_hash", "mcp_board_token_hash", "mcp_phone_token_hash", "mcp_artifacts_token_hash",
    "mcp_models_token_hash", "mcp_peer_relay_token_hash", "mcp_llm_cloud_token_hash",
    "mcp_services_token_hash", "mcp_satellite_tools_token_hash", "mcp_secrets_token_hash",
    "mcp_sharing_bot_token_hash", "mcp_reports_token_hash", "mcp_mail_hook_token_hash",
    "kiosk_announce_token_hash", "oauth:access", "oauth:refresh", "dashboard:session",
    "peer:inbound", "report:link", "password",
  ]) {
    assert.ok(TOKEN_MAC_FAMILIES.includes(family), family + " is in TOKEN_MAC_FAMILIES");
  }
  assert.equal(new Set(TOKEN_MAC_FAMILIES).size, TOKEN_MAC_FAMILIES.length, "no duplicates");
  assert.ok(TOKEN_MAC_FAMILIES.includes(PASSWORD_FAMILY));
  assert.equal(Object.isFrozen(TOKEN_MAC_FAMILIES), true, "the list is a constant");
});

// ─── the password pepper (§2.2) — implemented, not wired ──────────────────

test("the password pepper round-trips, and a wrong password fails", async () => {
  const s = scratch();
  try {
    ensureKey({ crowHome: s.home, allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    const password = "correct horse battery staple";
    const salt = randomBytes(16).toString("hex");
    const scryptKeyHex = (await scryptAsync(password, salt, 64)).toString("hex");

    const stored = pepperPassword(scryptKeyHex, { salt, crowHome: s.home });
    assert.match(stored, /^p2\$[0-9a-f]+\$[0-9a-f]{64}$/, "p2$<salt>$<hex mac>");
    assert.deepEqual(parsePepper(stored), { salt, mac: stored.split("$")[2] });
    assert.equal(verifyPepper(stored, scryptKeyHex, { crowHome: s.home }), true);
    assert.equal(await verifyPepperPassword(password, stored, { crowHome: s.home }), true, "scrypt then the MAC");
    assert.equal(await verifyPepperPassword("wrong password", stored, { crowHome: s.home }), false);

    // A legacy `salt:key` value converts offline, and keeps verifying.
    const legacy = `${salt}:${scryptKeyHex}`;
    const converted = pepperFromLegacy(legacy, { crowHome: s.home });
    assert.equal(converted, stored, "the converter needs no password");
    assert.equal(await verifyPepperPassword(password, converted, { crowHome: s.home }), true);

    // Shapes that are not this form answer false, never throw.
    assert.equal(verifyPepper(legacy, scryptKeyHex, { crowHome: s.home }), false, "a legacy salt:key is not a p2 value");
    assert.equal(await verifyPepperPassword(password, legacy, { crowHome: s.home }), false);
    assert.equal(await verifyPepperPassword(password, "p2$zz$00", { crowHome: s.home }), false);
    assert.equal(verifyPepper(stored, "not-hex", { crowHome: s.home }), false);
    // Missing salt / bad key hex are programmer errors, said so plainly.
    assert.throws(() => pepperPassword(scryptKeyHex, { crowHome: s.home }), TypeError);
    assert.throws(() => pepperPassword("abc", { salt, crowHome: s.home }), TypeError);
    assert.throws(() => pepperFromLegacy("nocolon", { crowHome: s.home }), TypeError);
  } finally { s.cleanup(); }
});

test("the password pepper fails closed without a key (it never mints one)", async () => {
  const s = scratch();
  try {
    const salt = randomBytes(16).toString("hex");
    const keyHex = randomBytes(64).toString("hex");
    assert.throws(() => pepperPassword(keyHex, { salt, crowHome: s.home }), (err) => err.code === "TOKEN_MAC_KEY_MISSING");
    assert.equal(keyState({ crowHome: s.home }), "first-boot", "and it left no key behind");
    assert.equal(verifyPepper(`p2$${salt}$${"0".repeat(64)}`, keyHex, { crowHome: s.home }), false);
    assert.equal(await verifyPepperPassword("pw", `p2$${salt}$${"0".repeat(64)}`, { crowHome: s.home }), false);
  } finally { s.cleanup(); }
});
// ─── review fixes: corrupt state, minted key, cache, lock, strict flags ────

test("H1: an UNREADABLE state file makes writers throw and loses no other family's era", { skip: IS_ROOT }, async () => {
  const s = scratch();
  try {
    ensureKey({ ...CREATE, crowHome: s.home });
    await markConverted("oauth:access", { count: 1, crowHome: s.home });
    chmodSync(s.statePath, 0o000);
    // EACCES is transient, never "corrupt" and never "absent": the writer must refuse.
    await assert.rejects(
      () => markConverted("report:link", { count: 2, crowHome: s.home }),
      (err) => err instanceof TokenMacStateError && err.code === "TOKEN_MAC_STATE_UNREADABLE",
    );
    // Every era query fails CLOSED while the state cannot be read.
    assert.equal(await familyConverted("report:link", { crowHome: s.home }), true);
    assert.equal(await familyConverted("oauth:access", { crowHome: s.home }), true);
    // And a key-less process never reads an unreadable state as first-boot.
    rmSync(s.keyPath);
    forgetTokenMacKey();
    assert.equal(keyState({ crowHome: s.home }), "lost");
    assert.throws(() => ensureKey({ ...CREATE, crowHome: s.home }), (err) => err.code === "TOKEN_MAC_KEY_LOST");
    // The bytes were never touched: the other family's era is still there.
    chmodSync(s.statePath, 0o600);
    const st = readState({ crowHome: s.home });
    assert.ok(st.families["oauth:access"]?.converted_at, "the sibling era survived");
    assert.equal(st.families["report:link"], undefined, "nothing was written for the refused family");
    assert.equal(existsSync(`${s.statePath}.lock`), false, "the lock was released");
  } finally { s.cleanup(); }
});

test("H1: a CORRUPT state file is refused by every writer and left byte-for-byte intact", async () => {
  const s = scratch();
  try {
    mkdirSync(s.secrets, { recursive: true, mode: 0o700 });
    const body = '{"v":1,"families":{"oauth:access":{"converted_at":"2026-01-01T00:00:00.000Z"}}, BROKEN';
    writeFileSync(s.statePath, body, { mode: 0o600 });
    const mirrored = [];
    await assert.rejects(
      () => markConverted("report:link", { writeSetting: async (k, v) => mirrored.push([k, v]), crowHome: s.home }),
      (err) => err instanceof TokenMacStateError && err.code === "TOKEN_MAC_STATE_CORRUPT",
    );
    assert.equal(readFileSync(s.statePath, "utf8"), body, "byte-for-byte untouched");
    assert.deepEqual(readdirSync(s.secrets), ["token-hmac-state.json"], "never renamed aside, never a fresh file");
    assert.deepEqual(mirrored, [], "no DB mirror was written either");
    // Fail closed for EVERY family, not just the one being marked.
    for (const family of ["report:link", "oauth:access", "password", "peer:inbound"]) {
      assert.equal(await familyConverted(family, { crowHome: s.home }), true, family);
    }
    assert.equal(keyState({ crowHome: s.home }), "lost", "corrupt state is never first-boot");
    assert.throws(() => ensureKey({ ...CREATE, crowHome: s.home }), (err) => err.code === "TOKEN_MAC_KEY_LOST");
    // An unparseable families value is corrupt too.
    writeFileSync(s.statePath, JSON.stringify({ v: 1, families: ["not", "an", "object"] }), { mode: 0o600 });
    assert.equal(readState({ crowHome: s.home }).corrupt, true);
    assert.equal(keyState({ crowHome: s.home }), "lost");
  } finally { s.cleanup(); }
});

test("H2: a state file that records the key means 'lost' when the key file is gone — never a re-mint", () => {
  const s = scratch();
  try {
    const key = ensureKey({ ...CREATE, crowHome: s.home });
    assert.ok(existsSync(s.statePath));
    rmSync(s.keyPath);
    forgetTokenMacKey(); // a fresh process: no cache to hide behind
    assert.equal(keyState({ crowHome: s.home }), "lost", "key_id alone is evidence an era began");
    assert.throws(
      () => ensureKey({ ...CREATE, crowHome: s.home }),
      (err) => err instanceof TokenMacKeyError && err.code === "TOKEN_MAC_KEY_LOST",
    );
    assert.equal(existsSync(s.keyPath), false, "no new key file was minted");
    assert.equal(readState({ crowHome: s.home }).key_id, key.id, "the old key_id is still recorded");
  } finally { s.cleanup(); }

  // password_set_at alone, and even an empty-but-present state file, are not first boots.
  const p = scratch();
  try {
    mkdirSync(p.secrets, { recursive: true, mode: 0o700 });
    writeFileSync(p.statePath, JSON.stringify({ v: 1, password_set_at: "2026-11-23T00:00:00.000Z" }), { mode: 0o600 });
    assert.equal(keyState({ crowHome: p.home }), "lost");
    writeFileSync(p.statePath, JSON.stringify({ v: 1 }), { mode: 0o600 });
    forgetTokenMacKey();
    assert.equal(keyState({ crowHome: p.home }), "lost", "first-boot needs NO state file at all");
    assert.throws(() => ensureKey({ ...CREATE, crowHome: p.home }), (err) => err.code === "TOKEN_MAC_KEY_LOST");
    assert.equal(existsSync(p.keyPath), false);
  } finally { p.cleanup(); }
});

test("M1: the key is loaded once per process; a changed key file fails closed on reload", () => {
  const s = scratch();
  try {
    ensureKey({ ...CREATE, crowHome: s.home });
    const token = "m1-token";
    const before = macToken("mcp_local_token_hash", token, { crowHome: s.home });

    // Replace the key file underneath the running process.
    const secret = randomBytes(32);
    const id = createHash("sha256").update(secret).digest("hex").slice(0, 16);
    writeFileSync(s.keyPath, JSON.stringify({ v: 1, id, key: secret.toString("base64") }) + "\n", { mode: 0o600 });

    // Cached: minting and verifying stay on the loaded key (never a mix of two eras)...
    assert.equal(keyState({ crowHome: s.home }), "ok", "the cache answers without touching the disk");
    assert.equal(macToken("mcp_local_token_hash", token, { crowHome: s.home }), before);
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", token, before, { converted: true, crowHome: s.home }),
      { ok: true, form: "h1" },
    );
    // ...and an explicit reload refuses the swap, leaving the loaded key in place.
    assert.throws(
      () => reloadTokenMacKey({ crowHome: s.home }),
      (err) => err instanceof TokenMacKeyError && err.code === "TOKEN_MAC_KEY_CHANGED",
    );
    assert.equal(macToken("mcp_local_token_hash", token, { crowHome: s.home }), before, "still the loaded key");

    // A fresh process adopts the new key: old values are FOREIGN, not silently re-minted.
    forgetTokenMacKey();
    assert.equal(ensureKey({ crowHome: s.home }).id, id);
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", token, before, { converted: true, crowHome: s.home }),
      { ok: false, form: "foreign" },
    );
    assert.notEqual(macToken("mcp_local_token_hash", token, { crowHome: s.home }), before);
  } finally { s.cleanup(); }
});

test("M2: no key and no era still accepts the legacy form (§2.6 row 4); lost/invalid refuse", () => {
  const s = scratch();
  try {
    const token = "legacy-token";
    const legacy = sha256Hex(token);
    assert.equal(keyState({ crowHome: s.home }), "first-boot");
    // §2.6 row 4 needs a boot that actually looked: the scan is what authorises the fall-through.
    assert.equal(noteEraEvidence({ mirrorConverted: false, h1ValuesExist: false, crowHome: s.home }), "no-evidence");
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", token, legacy, { converted: false, crowHome: s.home }),
      { ok: true, form: "legacy" },
      "an install whose secrets were never written is not locked out",
    );
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", "wrong", legacy, { converted: false, crowHome: s.home }),
      { ok: false, form: "legacy" },
    );
    // An h1 value cannot be checked without a key, so it is still refused.
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", token, "h1." + "0".repeat(16) + "." + "0".repeat(64), { converted: false, crowHome: s.home }),
      { ok: false, form: "invalid", reason: "key-missing" },
    );

    // Once any era evidence exists there is NO fall-through, even with converted:false.
    ensureKey({ ...CREATE, crowHome: s.home });
    rmSync(s.keyPath);
    forgetTokenMacKey();
    assert.equal(keyState({ crowHome: s.home }), "lost");
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", token, legacy, { converted: false, crowHome: s.home }),
      { ok: false, form: "invalid", reason: "key-lost" },
    );
    // An invalid key refuses too.
    const bad = scratch();
    try {
      mkdirSync(bad.secrets, { recursive: true, mode: 0o700 });
      writeFileSync(bad.keyPath, "not json", { mode: 0o600 });
      assert.deepEqual(
        verifyStored("mcp_local_token_hash", token, legacy, { converted: false, crowHome: bad.home }),
        { ok: false, form: "invalid", reason: "key-invalid" },
      );
    } finally { bad.cleanup(); }
  } finally { s.cleanup(); }
});

test("M3: verifyStored requires an explicit boolean `converted` (no fail-open default)", () => {
  const s = scratch();
  try {
    ensureKey({ ...CREATE, crowHome: s.home });
    const token = "m3-token";
    const legacy = sha256Hex(token);
    for (const converted of [undefined, null, 0, 1, "false", "true", {}, []]) {
      assert.throws(
        () => verifyStored("mcp_local_token_hash", token, legacy, { converted, crowHome: s.home }),
        TypeError,
        "converted = " + String(converted),
      );
    }
    assert.throws(() => verifyStored("mcp_local_token_hash", token, legacy, { crowHome: s.home }), TypeError, "omitted");
    // The explicit booleans keep working.
    assert.equal(verifyStored("mcp_local_token_hash", token, legacy, { converted: false, crowHome: s.home }).ok, true);
    assert.equal(verifyStored("mcp_local_token_hash", token, legacy, { converted: true, crowHome: s.home }).ok, false);
  } finally { s.cleanup(); }
});

test("M4: two processes marking different families concurrently keep BOTH eras", async () => {
  const s = scratch();
  try {
    const marker = join(s.home, "mark.mjs");
    writeFileSync(marker, [
      `import { markConverted } from ${JSON.stringify(MODULE_PATH)};`,
      "const [statePath, family] = process.argv.slice(2);",
      "for (let i = 0; i < 40; i += 1) await markConverted(family, { count: i, statePath });",
      "",
    ].join("\n"));
    const run = (family) => new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [marker, s.statePath, family], { stdio: "ignore" });
      child.on("error", reject);
      child.on("close", (code) => (code === 0
        ? resolve()
        : reject(new Error(`marker child for ${family} exited ${code}`))));
    });
    await Promise.all([run("oauth:access"), run("report:link")]);

    const st = readState({ crowHome: s.home });
    assert.ok(st.families["oauth:access"]?.converted_at, "oauth:access survived the race");
    assert.ok(st.families["report:link"]?.converted_at, "report:link survived the race");
    assert.equal(existsSync(`${s.statePath}.lock`), false, "the lock was released");
  } finally { s.cleanup(); }
});

test("M5: creating a key needs explicit mirrorConverted and h1ValuesExist booleans", () => {
  const s = scratch();
  try {
    assert.equal(keyState({ crowHome: s.home }), "first-boot");
    assert.throws(() => ensureKey({ crowHome: s.home, allowCreate: true }), TypeError, "both omitted");
    assert.throws(() => ensureKey({ crowHome: s.home, allowCreate: true, mirrorConverted: false }), TypeError, "h1ValuesExist omitted");
    assert.throws(() => ensureKey({ crowHome: s.home, allowCreate: true, h1ValuesExist: false }), TypeError, "mirrorConverted omitted");
    assert.throws(
      () => ensureKey({ crowHome: s.home, allowCreate: true, mirrorConverted: "false", h1ValuesExist: false }),
      TypeError,
      "a non-boolean is a programmer error",
    );
    // The refusals created nothing.
    assert.equal(existsSync(s.keyPath), false);
    assert.equal(keyState({ crowHome: s.home }), "first-boot");
    // The explicit pair is what creates, and the verifier path needs no flags.
    const key = ensureKey({ ...CREATE, crowHome: s.home });
    assert.equal(keyState({ crowHome: s.home }), "ok");
    assert.equal(ensureKey({ crowHome: s.home }).id, key.id);
  } finally { s.cleanup(); }
});

// ─── review round 3: the boot verdict (M2), the lock and the reload (L1/L2) ─

test("M2: a boot that found the key LOST keeps this process lost, with or without evidence", () => {
  const s = scratch();
  try {
    const botToken = "bot-planted-token";
    const planted = sha256Hex(botToken); // what a bot with DB write access can compute
    // The boot scans the DB, sees h1. rows, and correctly refuses to mint a key.
    assert.throws(
      () => ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: true, crowHome: s.home }),
      (err) => err instanceof TokenMacKeyError && err.code === "TOKEN_MAC_KEY_LOST",
    );
    // A validator asking LATER, without the evidence, must not see "first-boot".
    assert.equal(keyState({ crowHome: s.home }), "lost");
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", botToken, planted, { converted: false, crowHome: s.home }),
      { ok: false, form: "invalid", reason: "key-lost" },
    );
    // ...even after the bot deletes the evidence it CAN reach (the DB mirror, its h1. rows):
    // the verdict is sticky for the process, and nothing downgrades it.
    assert.equal(noteEraEvidence({ mirrorConverted: false, h1ValuesExist: false, crowHome: s.home }), "lost");
    assert.equal(keyState({ crowHome: s.home }), "lost");
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", botToken, planted, { converted: false, crowHome: s.home }),
      { ok: false, form: "invalid", reason: "key-lost" },
    );
    // And no key is minted over the verdict, even with a clean-looking evidence pair.
    assert.throws(
      () => ensureKey({ ...CREATE, crowHome: s.home }),
      (err) => err instanceof TokenMacKeyError && err.code === "TOKEN_MAC_KEY_LOST",
    );
    assert.equal(existsSync(s.keyPath), false, "nothing was minted");
  } finally { s.cleanup(); }
});

test("M2: no recorded boot verdict means no key-less legacy fall-through", () => {
  const s = scratch();
  try {
    const token = "cold-validator";
    const legacy = sha256Hex(token);
    // keyState alone is not a boot scan: it must not vouch for "new" by itself.
    assert.equal(keyState({ crowHome: s.home }), "first-boot");
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", token, legacy, { converted: false, crowHome: s.home }),
      { ok: false, form: "invalid", reason: "key-missing" },
      "no boot said the box is new, so the legacy form is refused",
    );
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", token, legacy, { converted: false, crowHome: s.home }),
      { ok: false, form: "invalid", reason: "key-missing" },
      "and it stays refused",
    );
  } finally { s.cleanup(); }
});

test("M2: a boot that checked BOTH evidence pieces and found none keeps §2.6 row 4", () => {
  const s = scratch();
  try {
    const token = "first-boot-legacy";
    const legacy = sha256Hex(token);
    assert.equal(
      noteEraEvidence({ mirrorConverted: false, h1ValuesExist: false, crowHome: s.home }),
      "no-evidence",
    );
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", token, legacy, { converted: false, crowHome: s.home }),
      { ok: true, form: "legacy" },
      "a checked first boot is not locked out",
    );
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", "wrong", legacy, { converted: false, crowHome: s.home }),
      { ok: false, form: "legacy" },
    );
    // An h1 value is unverifiable without a key, and `converted: true` still refuses.
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", token, "h1." + "0".repeat(16) + "." + "0".repeat(64), { converted: false, crowHome: s.home }),
      { ok: false, form: "invalid", reason: "key-missing" },
    );
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", token, legacy, { converted: true, crowHome: s.home }),
      { ok: false, form: "invalid", reason: "key-missing" },
      "the no-evidence verdict only covers the pre-conversion row-4 case",
    );
    // A DIFFERENT key path has its own, unrecorded verdict.
    const other = scratch();
    try {
      assert.deepEqual(
        verifyStored("mcp_local_token_hash", token, legacy, { converted: false, crowHome: other.home }),
        { ok: false, form: "invalid", reason: "key-missing" },
        "the verdict is per key path, never global",
      );
    } finally { other.cleanup(); }
  } finally { s.cleanup(); }
});

test("M2: the era-evidence flags are strict booleans, and a bad call records nothing", () => {
  const s = scratch();
  try {
    for (const opts of [
      {},
      { mirrorConverted: false },
      { h1ValuesExist: false },
      { mirrorConverted: 0, h1ValuesExist: false },
      { mirrorConverted: false, h1ValuesExist: null },
      { mirrorConverted: "false", h1ValuesExist: "false" },
    ]) {
      assert.throws(() => noteEraEvidence({ ...opts, crowHome: s.home }), TypeError, JSON.stringify(opts));
    }
    // Nothing was recorded, so the cold refusal still stands.
    assert.equal(keyState({ crowHome: s.home }), "first-boot");
    assert.deepEqual(
      verifyStored("mcp_local_token_hash", "t", sha256Hex("t"), { converted: false, crowHome: s.home }),
      { ok: false, form: "invalid", reason: "key-missing" },
    );
  } finally { s.cleanup(); }
});

// ─── the low-severity items ───────────────────────────────────────────────

test("LOW: only lowercase h1 values are recognised; a non-string or empty token is 'invalid'", () => {
  const s = scratch();
  try {
    const key = ensureKey({ ...CREATE, crowHome: s.home });
    const token = "lowercase-only";
    const good = macToken("oauth:access", token, { crowHome: s.home });
    assert.equal(verifyStored("oauth:access", token, good, { converted: true, crowHome: s.home }).ok, true);

    const upperId = `h1.${key.id.toUpperCase()}.${good.split(".")[2]}`;
    assert.deepEqual(
      verifyStored("oauth:access", token, upperId, { converted: true, crowHome: s.home }),
      { ok: false, form: "invalid" },
      "an uppercase keyId is not the minted form",
    );
    const upperMac = `h1.${key.id}.${good.split(".")[2].toUpperCase()}`;
    assert.deepEqual(
      verifyStored("oauth:access", token, upperMac, { converted: true, crowHome: s.home }),
      { ok: false, form: "invalid" },
      "an uppercase MAC is not the minted form",
    );

    for (const bad of [undefined, null, 42, "", {}, []]) {
      assert.deepEqual(
        verifyStored("oauth:access", bad, good, { converted: true, crowHome: s.home }),
        { ok: false, form: "invalid" },
        "h1 path, token = " + String(bad),
      );
      assert.deepEqual(
        verifyStored("oauth:access", bad, sha256Hex("x"), { converted: false, crowHome: s.home }),
        { ok: false, form: "invalid" },
        "legacy path, token = " + String(bad),
      );
    }
  } finally { s.cleanup(); }
});

test("LOW: the key file must be a regular owner-only file — never a symlink, never group/other", () => {
  const outside = scratch();
  const s = scratch();
  try {
    ensureKey({ ...CREATE, crowHome: outside.home });
    mkdirSync(s.secrets, { recursive: true, mode: 0o700 });
    symlinkSync(outside.keyPath, s.keyPath);
    assert.equal(keyState({ crowHome: s.home }), "invalid", "a symlink is not the key we minted");
    assert.throws(() => ensureKey({ ...CREATE, crowHome: s.home }), (err) => err.code === "TOKEN_MAC_KEY_INVALID");
    assert.equal(lstatSync(s.keyPath).isSymbolicLink(), true, "the link is left for the operator");

    const loose = scratch();
    try {
      ensureKey({ ...CREATE, crowHome: loose.home });
      chmodSync(loose.keyPath, 0o644);
      forgetTokenMacKey(); // a fresh process re-checks the file
      assert.equal(keyState({ crowHome: loose.home }), "invalid", "group/other bits mean it is not ours");
      assert.throws(() => ensureKey({ crowHome: loose.home }), (err) => err.code === "TOKEN_MAC_KEY_INVALID");
    } finally { loose.cleanup(); }
  } finally { s.cleanup(); outside.cleanup(); }
});

test("LOW: the alarm de-dupes only the console line — every distinct row is audited, capped, redacted", () => {
  forgetTokenMacAlarms();
  const audited = [];
  const warnings = [];
  const original = console.warn;
  console.warn = (...args) => { warnings.push(args.join(" ")); };
  try {
    const hashLike = "a".repeat(64);
    assert.equal(legacyAlarm("report:link", hashLike, { audit: (t, d) => audited.push(d.row) }), true);
    assert.equal(warnings.length, 1);
    assert.match(warnings[0], /\[redacted\]/);
    assert.equal(warnings[0].includes(hashLike), false, "never print a stored verifier");

    // A second distinct row inside the window: no console line, but its own audit row.
    assert.equal(legacyAlarm("report:link", "row-2", { audit: (t, d) => audited.push(d.row) }), false);
    assert.equal(warnings.length, 1, "the console line is once per family per window");
    assert.deepEqual(audited, [hashLike, "row-2"]);
    // A repeat of a seen row is not audited again.
    assert.equal(legacyAlarm("report:link", "row-2", { audit: (t, d) => audited.push(d.row) }), false);
    assert.equal(audited.length, 2);

    // An h1 value is redacted too.
    assert.equal(legacyAlarm("peer:inbound", "h1." + "0".repeat(16) + "." + "0".repeat(64)), true);
    assert.match(warnings[1], /\[redacted\]/);

    // At most 100 distinct rows are audited per family per window.
    forgetTokenMacAlarms();
    const capped = [];
    for (let i = 0; i < 105; i += 1) {
      legacyAlarm("password", `row-${i}`, { audit: (t, d) => capped.push(d.row) });
    }
    assert.equal(capped.length, 100, "the per-family audit cap holds");
  } finally {
    console.warn = original;
    forgetTokenMacAlarms();
  }
});

test("LOW: the password pepper binds the scrypt salt into the MAC input", async () => {
  const s = scratch();
  try {
    const key = ensureKey({ ...CREATE, crowHome: s.home });
    const password = "salt-bound";
    const saltA = randomBytes(16).toString("hex");
    const saltB = randomBytes(16).toString("hex");
    const keyHex = (await scryptAsync(password, saltA, 64)).toString("hex");

    const a = pepperPassword(keyHex, { salt: saltA, crowHome: s.home });
    const b = pepperPassword(keyHex, { salt: saltB, crowHome: s.home });
    assert.notEqual(a, b, "the same scrypt output under another salt is another verifier");

    // Recomputed here from the documented layout, byte for byte.
    const { createHmac } = await import("node:crypto");
    const expected = createHmac("sha256", key.secret)
      .update("crow-token-mac-v1\0password\0" + saltA + "\0" + keyHex)
      .digest("hex");
    assert.equal(a, `p2$${saltA}$${expected}`);

    // A salt swapped onto another MAC does not verify.
    const swapped = a.replace(`p2$${saltA}$`, `p2$${saltB}$`);
    assert.equal(verifyPepper(swapped, keyHex, { crowHome: s.home }), false);
    assert.equal(await verifyPepperPassword(password, a, { crowHome: s.home }), true);
    assert.equal(await verifyPepperPassword(password, swapped, { crowHome: s.home }), false);
    assert.equal(pepperFromLegacy(`${saltA}:${keyHex}`, { crowHome: s.home }), a);
  } finally { s.cleanup(); }
});

test("L1: a stale lock is taken over once (inode-checked); a symlink at the lock path is LOCKED", async () => {
  const s = scratch();
  try {
    ensureKey({ ...CREATE, crowHome: s.home });
    // A lock abandoned by a crashed writer: 60 s old, past the 30 s stale threshold.
    writeFileSync(`${s.statePath}.lock`, JSON.stringify({ pid: 999999, ts: "2026-01-01T00:00:00.000Z" }), { mode: 0o600 });
    const old = new Date(Date.now() - 60 * 1000);
    utimesSync(`${s.statePath}.lock`, old, old);
    const marked = await markConverted("oauth:access", { count: 3, crowHome: s.home });
    assert.equal(marked.changed, true, "the stale lock was taken over and the write succeeded");
    assert.equal(readState({ crowHome: s.home }).families["oauth:access"].count, 3);
    assert.equal(existsSync(`${s.statePath}.lock`), false, "the lock was released");
    assert.deepEqual(
      readdirSync(s.secrets).filter((name) => name.includes(".stale-")),
      [],
      "no take-over leftovers",
    );

    // A symlink where the lock belongs is NOT our lock: never stale, never removed, fail closed.
    const target = join(s.home, "not-a-lock");
    writeFileSync(target, "leave me alone");
    symlinkSync(target, `${s.statePath}.lock`);
    await assert.rejects(
      () => markConverted("report:link", { crowHome: s.home }),
      (err) => err instanceof TokenMacStateError && err.code === "TOKEN_MAC_STATE_LOCKED",
    );
    assert.equal(lstatSync(`${s.statePath}.lock`).isSymbolicLink(), true, "the link was left for the operator");
    assert.equal(readFileSync(target, "utf8"), "leave me alone", "the link target was never touched");
    assert.equal(readState({ crowHome: s.home }).families["report:link"], undefined, "nothing was written");
  } finally { s.cleanup(); }
});

test("L2: a reload never adopts a missing or replaced key file — the loaded key stays authoritative", () => {
  const s = scratch();
  try {
    const key = ensureKey({ ...CREATE, crowHome: s.home });
    const token = "l2-token";
    const keyIdOf = (value) => value.split(".")[1];
    const before = macToken("mcp_local_token_hash", token, { crowHome: s.home });
    assert.equal(keyIdOf(before), key.id);

    // The file disappears: the reload reports LOST, keeps the cached key, and later use is
    // unchanged (it must never fall back to "no key" and adopt whatever appears next).
    rmSync(s.keyPath);
    assert.throws(
      () => reloadTokenMacKey({ crowHome: s.home }),
      (err) => err instanceof TokenMacKeyError && err.code === "TOKEN_MAC_KEY_LOST" && err.state === "lost",
    );
    assert.equal(macToken("mcp_local_token_hash", token, { crowHome: s.home }), before, "same verifier");
    assert.equal(keyIdOf(macToken("mcp_local_token_hash", token, { crowHome: s.home })), key.id);
    assert.equal(keyState({ crowHome: s.home }), "ok", "the cache still answers");

    // A DIFFERENT key file appearing is still refused as KEY_CHANGED, cache retained.
    const secret = randomBytes(32);
    const id = createHash("sha256").update(secret).digest("hex").slice(0, 16);
    writeFileSync(s.keyPath, JSON.stringify({ v: 1, id, key: secret.toString("base64") }) + "\n", { mode: 0o600 });
    assert.throws(
      () => reloadTokenMacKey({ crowHome: s.home }),
      (err) => err instanceof TokenMacKeyError && err.code === "TOKEN_MAC_KEY_CHANGED",
    );
    assert.equal(keyIdOf(macToken("mcp_local_token_hash", token, { crowHome: s.home })), key.id, "still the old key");

    // An unreadable file is INVALID, and also keeps the key.
    writeFileSync(s.keyPath, "not json", { mode: 0o600 });
    assert.throws(
      () => reloadTokenMacKey({ crowHome: s.home }),
      (err) => err instanceof TokenMacKeyError && err.code === "TOKEN_MAC_KEY_INVALID" && err.state === "invalid",
    );
    assert.equal(keyIdOf(macToken("mcp_local_token_hash", token, { crowHome: s.home })), key.id);
  } finally { s.cleanup(); }
});
