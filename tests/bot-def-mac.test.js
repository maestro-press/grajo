/**
 * Bot definition tamper evidence (`bot:def` of the keyed-hash design).
 *
 * A contained bot has crow.db bound read-write, and `pi_bot_defs` is AUTHORITY: `tools.crow_mcp`,
 * `permission_policy`, `write_paths`, `project_id` and `tools.remote_mcp` decide what the bot may
 * do, and a raise takes effect at its next spawn. So every row carries a keyed MAC over its WHOLE
 * definition (under <CROW_HOME>/secrets/token-hmac.key, a file no bot can read) plus a monotonic
 * generation kept OUTSIDE crow.db, and the spawn gate refuses a row that does not verify.
 *
 * This file pins, against the real schema, the real store and the real converter:
 *   - the canonical form (key order and whitespace independent, the WHOLE definition covered);
 *   - the copy attack (another bot's trio written into this row) and self-escalation;
 *   - the replay (an owner edit, then the bot writing back the older valid pair);
 *   - the write path: one statement, the generation bumped only when the row landed, and the
 *     caller's own optimistic concurrency preserved;
 *   - the crash-safe write order (`pending`), and the missing generations file;
 *   - a lost key refusing every row with ONE loud line;
 *   - the boot converter: snapshot, crash-between-commit-and-marker re-run (snapshot rows only),
 *     and the un-writable-secrets skip.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, writeFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { createDbClient } from "../servers/db.js";
import {
  forgetTokenMacKey, adoptOperatorKey, ensureKey, readState, resetFamiliesForOperator, tokenMacKeyPath,
  tokenMacStatePath, TOKEN_MAC_FAMILIES, macToken, verifyStored,
} from "../servers/shared/token-mac.js";
import {
  BOT_DEF_FAMILY, abandonBotDefGeneration, botDefEraSettingKey, botDefGenerationsPath, canonicalBotDef,
  canonicalDefinitionText, canonicalJson, botDefEraConvertedSync, readBotDefEraState, writeBotDefEraState, botDefEraStatePath,
  reconcileBotDefPending, CANONICAL_MAX_DEPTH, forgetBotDefAlarms, forgetBotDefForcedRefusal,
  macBotDef, planBotDefGeneration, readBotDefGenerations, settleBotDefGeneration, verifyBotDef, verifyBotDefSync,
} from "../servers/shared/bot-def-mac.js";
import {
  BOT_DEF_FOREIGN_TRIGGER, readVerifiedBotDef, resealAllBotDefs, setBotEnabled, signBotDef, sqliteDbFacade,
  verifyAllBotDefs, writeBotDef,
} from "../servers/shared/bot-def-store.js";
import {
  expectedTriggersOnTable, reachableTriggerTables, unexpectedTriggers,
} from "../servers/shared/trigger-catalog.js";
import { verifyBotDefSealed } from "../servers/shared/bot-def-seal.js";
import { main as reapproveMain } from "../scripts/cli/bot-def-reapprove.mjs";
import { BOT_DEF_ROLLBACK_PREFIX, runBotDefMacBoot } from "../servers/gateway/boot/bot-def-mac.js";
import { writeSetting } from "../servers/gateway/dashboard/settings/registry.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const sha256 = (value) => createHash("sha256").update(String(value)).digest("hex");

const roots = [];
const SAVED = {};
for (const key of ["CROW_HOME", "CROW_DATA_DIR", "CROW_DB_PATH"]) SAVED[key] = process.env[key];
after(() => {
  for (const root of roots) {
    try { rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
  }
  for (const [key, value] of Object.entries(SAVED)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
});

/** A fresh scratch instance with the REAL schema (init-db), and every in-process cache forgotten. */
function scratch() {
  const home = mkdtempSync(join(tmpdir(), "crow-botdef-"));
  roots.push(home);
  const dataDir = join(home, "data");
  mkdirSync(dataDir, { recursive: true });
  writeFileSync(join(dataDir, "instance-id"), "0123456789abcdef0123456789abcdef", { mode: 0o600 });
  process.env.CROW_HOME = home;
  process.env.CROW_DATA_DIR = dataDir;
  process.env.CROW_DB_PATH = join(dataDir, "crow.db");
  forgetTokenMacKey();
  forgetBotDefAlarms();
  forgetBotDefForcedRefusal();
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: process.env, cwd: ROOT, stdio: "pipe", timeout: 120_000,
  });
  const db = createDbClient(process.env.CROW_DB_PATH);
  return { home, db, close: () => { try { db.close(); } catch { /* closed */ } } };
}

/** A definition with a few nested keys, so "the whole object" is visible in the MAC. */
const DEF = {
  system_prompt: "you help",
  models: { default: "provider/model-a", escalation: "provider/model-b" },
  tools: { crow_mcp: ["crow-memory"], remote_mcp: [] },
  permission_policy: { write_paths: ["~/a"], confirm: [] },
};

/** Insert a row through the one writer (this creates the key on a genuinely new box). */
async function createBot(db, botId, overrides = {}) {
  const res = await writeBotDef(db, {
    bot_id: botId,
    display_name: overrides.display_name ?? botId,
    definition: overrides.definition ?? DEF,
    enabled: overrides.enabled ?? 1,
    project_id: overrides.project_id ?? null,
    mode: "insert",
  });
  assert.equal(res.rowsAffected, 1, "the insert landed");
  return res;
}

/** Read a row the way the spawn gate does. */
async function rowOf(db, botId) {
  const { rows } = await db.execute({ sql: "SELECT * FROM pi_bot_defs WHERE bot_id=?", args: [botId] });
  return rows[0] || null;
}

/** Mark the `bot:def` era (what the pre-listen boot converter does at the end). */
async function markEra(db) {
  const { markConverted } = await import("../servers/shared/token-mac.js");
  await markConverted(BOT_DEF_FAMILY, { writeSetting: (k, v, o) => writeSetting(db, k, v, o) });
}

/** A box whose era record explicitly allows unsealed rows (an install this release has never booted on). */
function allowPreEra() {
  writeBotDefEraState("pre-era");
}

/** The synchronous gate the bridge's `loadBot` uses. */
function gate(row) {
  return verifyBotDefSync(row, { converted: botDefEraConvertedSync() });
}

test("canonical form: key order and whitespace do not matter, the WHOLE definition does", () => {
  const a = { b: 1, a: [{ y: 2, x: 1 }], c: null };
  const b = { a: [{ x: 1, y: 2 }], c: null, b: 1 };
  assert.equal(canonicalJson(a), canonicalJson(b), "the same value canonicalises identically");
  assert.equal(canonicalJson(a), '{"a":[{"x":1,"y":2}],"b":1,"c":null}');

  const row = { bot_id: "b1", enabled: 1, project_id: 2, def_generation: 3, definition: JSON.stringify(a) };
  const pretty = { ...row, definition: JSON.stringify(a, null, 2) };
  assert.equal(canonicalBotDef(row), canonicalBotDef(pretty), "whitespace in the stored text does not move the MAC");

  // An UNKNOWN field — one this module has never heard of — is inside the MAC. No field list.
  const withUnknown = { ...row, definition: JSON.stringify({ ...a, brand_new_authority_key: "on" }) };
  assert.notEqual(canonicalBotDef(row), canonicalBotDef(withUnknown));

  // An unparsable definition canonicalises as the raw string (a stable, verifiable form).
  const broken = { ...row, definition: "{not json" };
  assert.equal(canonicalBotDef(broken), canonicalBotDef({ ...broken }));
  assert.match(canonicalBotDef(broken), /not json/);
});

test("a pre-era row (no MAC, no era) is accepted; a MAC'd row is accepted only with its own key", async () => {
  const s = scratch();
  try {
    allowPreEra();
    // A row seeded directly (an install that upgraded but has not booted this release).
    await s.db.execute({
      sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('legacy','Legacy',?,1)",
      args: [JSON.stringify(DEF)],
    });
    let verdict = await verifyBotDef(await rowOf(s.db, "legacy"), { db: s.db });
    assert.deepEqual(verdict, { ok: true, reason: "pre-era" });

    // The writer seals a row and the same row then verifies as a keyed MAC.
    await createBot(s.db, "sealed");
    const row = await rowOf(s.db, "sealed");
    assert.match(String(row.def_mac), /^h1\.[0-9a-f]{16}\.[0-9a-f]{64}$/);
    assert.equal(Number(row.def_generation), 1);
    verdict = await verifyBotDef(row, { db: s.db });
    assert.equal(verdict.ok, true, "sealed rows verify even before the era is marked");

    // A row whose definition was edited under the MAC is refused — before AND after the era.
    await s.db.execute({ sql: "UPDATE pi_bot_defs SET definition=? WHERE bot_id='sealed'", args: [JSON.stringify({ ...DEF, permission_policy: { write_paths: ["/"] } })] });
    verdict = await verifyBotDef(await rowOf(s.db, "sealed"), { db: s.db });
    assert.deepEqual(verdict, { ok: false, reason: "mac-mismatch" });
  } finally {
    s.close();
  }
});

test("self-escalation after the era: definition, enabled and project_id are all refused", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "helper", { project_id: null });
    await markEra(s.db);
    const clean = await rowOf(s.db, "helper");
    assert.deepEqual(await verifyBotDef(clean, { db: s.db }), { ok: true, reason: "mac" });

    // A contained bot's writes: widen the policy, switch it on/off, re-file it in another project.
    for (const [sql, args] of [
      ["UPDATE pi_bot_defs SET definition=? WHERE bot_id='helper'", [JSON.stringify({ ...DEF, permission_policy: { write_paths: ["/"] } })]],
      ["UPDATE pi_bot_defs SET definition=? WHERE bot_id='helper'", [JSON.stringify({ ...DEF, tools: { crow_mcp: ["crow-sharing", "crow-secrets"] } })]],
      ["UPDATE pi_bot_defs SET enabled = 1 - enabled WHERE bot_id='helper'", []],
      ["UPDATE pi_bot_defs SET project_id=? WHERE bot_id='helper'", [7]],
    ]) {
      // eslint-disable-next-line no-await-in-loop -- one attack at a time
      await s.db.execute({ sql, args });
      // eslint-disable-next-line no-await-in-loop
      const verdict = await verifyBotDef(await rowOf(s.db, "helper"), { db: s.db });
      assert.equal(verdict.ok, false, `refused: ${sql}`);
      assert.equal(verdict.reason, "mac-mismatch", `refused as a MAC mismatch: ${sql}`);
      // eslint-disable-next-line no-await-in-loop
      await s.db.execute({ sql: "UPDATE pi_bot_defs SET definition=?, enabled=?, project_id=? WHERE bot_id='helper'", args: [clean.definition, clean.enabled, clean.project_id] });
    }

    // A MISSING MAC on a converted box is a refusal too, never an accepted "pre-era" row.
    await s.db.execute({ sql: "UPDATE pi_bot_defs SET def_mac=NULL WHERE bot_id='helper'" });
    assert.deepEqual(await verifyBotDef(await rowOf(s.db, "helper"), { db: s.db }), { ok: false, reason: "no-mac" });
  } finally {
    s.close();
  }
});

test("copy attack: another bot's (definition, MAC, generation) written into this row is refused", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "guest");
    await createBot(s.db, "trusted");
    await markEra(s.db);
    const guest = await rowOf(s.db, "guest");
    const trusted = await rowOf(s.db, "trusted");

    // The bot copies the OTHER row's trio into its own row: the canonical form carries bot_id.
    await s.db.execute({
      sql: "UPDATE pi_bot_defs SET definition=?, def_mac=?, def_generation=? WHERE bot_id='guest'",
      args: [trusted.definition, trusted.def_mac, trusted.def_generation],
    });
    assert.deepEqual(await verifyBotDef(await rowOf(s.db, "guest"), { db: s.db }), { ok: false, reason: "mac-mismatch" });

    // Its OWN trio moved to another bot id is refused the same way.
    await s.db.execute({
      sql: "UPDATE pi_bot_defs SET definition=?, def_mac=?, def_generation=? WHERE bot_id='trusted'",
      args: [guest.definition, guest.def_mac, guest.def_generation],
    });
    assert.deepEqual(await verifyBotDef(await rowOf(s.db, "trusted"), { db: s.db }), { ok: false, reason: "mac-mismatch" });
  } finally {
    s.close();
  }
});

test("replay: the older valid pair written back after an owner edit is refused (generation-behind)", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "worker");
    await markEra(s.db);
    const gen1 = await rowOf(s.db, "worker");

    // The owner tightens the policy through the one writer: generation 2, a fresh MAC. The write
    // states the row it read (`expect*`, round D item F1).
    const write = await writeBotDef(s.db, {
      bot_id: "worker",
      definition: { ...DEF, permission_policy: { write_paths: [], confirm: ["crow_sharing/crow_send_message"] } },
      expectDefinition: gen1.definition,
      expectEnabled: gen1.enabled,
      expectProjectId: gen1.project_id ?? null,
    });
    assert.equal(write.rowsAffected, 1);
    assert.equal(write.generation, 2);
    const gen2 = await rowOf(s.db, "worker");
    assert.deepEqual(await verifyBotDef(gen2, { db: s.db }), { ok: true, reason: "mac" });

    // The bot writes the gen-1 pair back: its MAC verifies, but the counter is at 2.
    await s.db.execute({
      sql: "UPDATE pi_bot_defs SET definition=?, def_mac=?, def_generation=? WHERE bot_id='worker'",
      args: [gen1.definition, gen1.def_mac, gen1.def_generation],
    });
    assert.deepEqual(await verifyBotDef(await rowOf(s.db, "worker"), { db: s.db }), { ok: false, reason: "generation-behind" });

    // A row claiming to be AHEAD of the counter (a restored older generations file, while the
    // database kept the newer row) is refused too — and only a key holder can even construct it,
    // because the generation is inside the MAC.
    const aheadMac = macBotDef({ ...gen2, def_generation: Number(gen2.def_generation) + 1 });
    await s.db.execute({
      sql: "UPDATE pi_bot_defs SET definition=?, def_mac=?, def_generation=? WHERE bot_id='worker'",
      args: [gen2.definition, aheadMac, Number(gen2.def_generation) + 1],
    });
    assert.deepEqual(await verifyBotDef(await rowOf(s.db, "worker"), { db: s.db }), { ok: false, reason: "generation-ahead" });
  } finally {
    s.close();
  }
});

test("cross-family separation: a def_mac is no token verifier, and no token MAC is a def_mac", async () => {
  // The families share ONE key, so what keeps them apart is the MAC domain (the family string is
  // inside the HMAC). A contained bot can read a token MAC out of crow.db and a definition MAC out
  // of pi_bot_defs; neither may verify in the other's place.
  const s = scratch();
  try {
    await createBot(s.db, "family");
    const row = await rowOf(s.db, "family");
    assert.match(String(row.def_mac), /^h1\.[0-9a-f]{16}\.[0-9a-f]{64}$/, "the fixture really carries a sealed definition");
    const others = TOKEN_MAC_FAMILIES.filter((family) => family !== BOT_DEF_FAMILY);
    assert.ok(others.length > 15, "every other family in the list is exercised");

    // The definition's MAC presented to each other family's verifier: refused under the same key.
    for (const family of others) {
      const verdict = verifyStored(family, "a presented token", row.def_mac, { converted: true, alarm: false });
      assert.equal(verdict.ok, false, `${family} accepted a bot definition's MAC as a token verifier (${verdict.form})`);
    }

    // A token MAC from each other family written into `def_mac`: refused as a MAC mismatch.
    for (const family of others) {
      const foreign = macToken(family, `token-for-${family}`);
      const verdict = await verifyBotDef({ ...row, def_mac: foreign }, { db: s.db });
      assert.equal(verdict.ok, false, `a ${family} token MAC verified as a bot definition`);
      assert.equal(verdict.reason, "mac-mismatch", `${family}: refused as a MAC mismatch, not as a missing/short value`);
    }

    // Positive control: the row's OWN MAC still verifies as a bot definition (the loop above is
    // not passing because verification is broken for this fixture).
    assert.equal((await verifyBotDef(row, { db: s.db })).ok, true);
  } finally {
    s.close();
  }
});

test("E1: a caller that read a DIFFERENT row than the one verifying is refused (caller-read-differs)", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "cas", { display_name: "Cas" });
    const before = await rowOf(s.db, "cas");
    const genBefore = Number(before.def_generation);

    // A compare-and-swap on a definition the caller read that is NOT the row this write verifies
    // (a page whose row moved, a bot that flipped it): the write refuses with its OWN reason instead
    // of re-signing content built from something nothing vouched for. Nothing is written, and the
    // generation counter is never even planned.
    await assert.rejects(
      () => writeBotDef(s.db, {
        bot_id: "cas",
        definition: { ...DEF, system_prompt: "stale" },
        expectDefinition: '"an older text"',
        expectEnabled: before.enabled,
        expectProjectId: before.project_id ?? null,
      }),
      (err) => err.code === "BOT_DEF_UNVERIFIED" && err.reason === "caller-read-differs",
      "a caller-read mismatch is a refusal, not a silent 0-row save",
    );
    assert.equal(Number((await rowOf(s.db, "cas")).def_generation), genBefore, "and nothing was bumped");

    // …while the live expectation lands, and the row's MAC covers the new definition.
    const ok = await writeBotDef(s.db, {
      bot_id: "cas",
      definition: { ...DEF, system_prompt: "fresh" },
      expectDefinition: before.definition,
      expectEnabled: before.enabled,
      expectProjectId: before.project_id ?? null,
    });
    assert.equal(ok.rowsAffected, 1);
    assert.equal(ok.generation, genBefore + 1);
    const after = await rowOf(s.db, "cas");
    assert.deepEqual(await verifyBotDef(after, { db: s.db }), { ok: true, reason: "mac" });
    assert.match(String(after.definition), /fresh/);
    // A toggle re-signs too: `enabled` is inside the MAC (and states the row it read).
    await setBotEnabled(s.db, "cas", 0, {
      expectDefinition: after.definition,
      expectEnabled: after.enabled,
      expectProjectId: after.project_id ?? null,
    });
    const off = await rowOf(s.db, "cas");
    assert.equal(Number(off.enabled), 0);
    assert.notEqual(off.def_mac, after.def_mac, "the toggle produced a fresh MAC");
    assert.deepEqual(await verifyBotDef(off, { db: s.db }), { ok: true, reason: "mac" });

    // The store's own concurrency check on the generation FILE is the counter for a CAS miss and
    // for a rollback: nothing is left "pending".
    const gens = JSON.parse(readFileSync(botDefGenerationsPath(), "utf8"));
    assert.equal(gens.bots.cas.pending, null, "a settled write leaves no pending mark");
    assert.equal(Number(gens.bots.cas.generation), Number(off.def_generation));
  } finally {
    s.close();
  }
});

test("crash-safe order: a write that died between the counter bump and the row is accepted as pending", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "atlas");
    await markEra(s.db);
    const row = await rowOf(s.db, "atlas");
    const gen = Number(row.def_generation);

    // A writer bumped the counter and then died before its statement ran.
    const planned = planBotDefGeneration("atlas");
    assert.equal(planned.generation, gen + 1);
    assert.deepEqual(await verifyBotDef(row, { db: s.db }), { ok: true, reason: "pending" },
      "the previous row is still the last good one while that write is pending");

    // The normal case after a settle: the counter and the row agree.
    settleBotDefGeneration("atlas", planned.generation);
    assert.deepEqual(await verifyBotDef(row, { db: s.db }), { ok: false, reason: "generation-behind" });

    // A write that never landed puts the counter back, so nothing was bumped.
    const second = planBotDefGeneration("atlas");
    abandonBotDefGeneration("atlas", second.generation, second.previous);
    assert.equal(Number(JSON.parse(readFileSync(botDefGenerationsPath(), "utf8")).bots.atlas.generation), planned.generation);
  } finally {
    s.close();
  }
});

test("I1: a generation a failed write planned is never signed twice, so a stashed tuple cannot be replayed", async () => {
  // THE ATTACK (reviewer's PoC, round I). A contained bot installs a BEFORE UPDATE trigger on
  // `pi_bot_defs` that copies NEW.definition/NEW.def_mac/NEW.def_generation into a stash table and
  // RAISE(IGNORE)s, so the owner's write lands 0 rows. While the counter wound back on a failed write,
  // the owner's NEXT write planned the SAME generation again, signed it, and the stashed tuple was then
  // a valid pair AT the accepted generation — a replay that undid the disable. The planning high-water
  // is never lowered, so every abandoned generation is refused instead.
  const s = scratch();
  try {
    await createBot(s.db, "stasher");
    await markEra(s.db);
    const sealed = await rowOf(s.db, "stasher");
    const accepted = Number(sealed.def_generation);

    await s.db.execute({ sql: "CREATE TABLE bot_stash (definition TEXT, enabled INTEGER, def_mac TEXT, def_generation INTEGER)", args: [] });
    await s.db.execute({
      sql: "CREATE TRIGGER stash_def BEFORE UPDATE ON pi_bot_defs BEGIN "
        + "INSERT INTO bot_stash (definition, enabled, def_mac, def_generation) "
        + "VALUES (NEW.definition, NEW.enabled, NEW.def_mac, NEW.def_generation); "
        + "SELECT RAISE(IGNORE); END",
      args: [],
    });

    // Write A (the tuple the bot will later replay: the bot left armed) is signed and swallowed.
    const first = planBotDefGeneration("stasher");
    assert.equal(first.generation, accepted + 1, "the first planned generation is one past the accepted one");
    const armedText = canonicalDefinitionText({ ...DEF, system_prompt: "armed by the owner" });
    const armedMac = macBotDef({
      bot_id: "stasher", definition: armedText, enabled: 1, project_id: null, def_generation: first.generation,
    });
    const swallowed = await s.db.execute({
      sql: "UPDATE pi_bot_defs SET definition=?, enabled=1, def_mac=?, def_generation=? WHERE bot_id='stasher'",
      args: [armedText, armedMac, first.generation],
    });
    assert.equal(Number(swallowed.rowsAffected), 0, "the trigger swallowed the owner's write");
    abandonBotDefGeneration("stasher", first.generation, first.previous);

    // The counter did NOT wind back: the accepted generation is where it was and the high-water is the
    // abandoned plan, so the next plan is one FURTHER on.
    const afterFailure = JSON.parse(readFileSync(botDefGenerationsPath(), "utf8")).bots.stasher;
    assert.equal(Number(afterFailure.generation), accepted, "a failed write does not move the accepted generation");
    assert.equal(afterFailure.pending, null, "and leaves nothing pending");
    assert.equal(Number(afterFailure.planned), first.generation, "the planned generation stays the high-water");

    // The stashed tuple, written straight back, is refused on its own (ahead of the accepted
    // generation, and not the generation in flight).
    const stash = (await s.db.execute({ sql: "SELECT definition, enabled, def_mac, def_generation FROM bot_stash ORDER BY rowid DESC LIMIT 1", args: [] })).rows[0];
    assert.equal(Number(stash.def_generation), first.generation, "the stash holds the signed tuple");
    await s.db.execute({ sql: "DROP TRIGGER stash_def", args: [] });
    const writeStashBack = async () => {
      await s.db.execute({
        sql: "UPDATE pi_bot_defs SET definition=?, enabled=?, def_mac=?, def_generation=? WHERE bot_id='stasher'",
        args: [stash.definition, stash.enabled, stash.def_mac, stash.def_generation],
      });
      return verifyBotDef(await rowOf(s.db, "stasher"), { db: s.db });
    };
    assert.deepEqual(await writeStashBack(), { ok: false, reason: "generation-ahead" }, "the abandoned tuple never verifies on its own");

    // Put the accepted row back, then the OWNER disables the bot through the store: it lands at the
    // NEXT generation (with the wind-back it would land at the stashed one).
    await s.db.execute({
      sql: "UPDATE pi_bot_defs SET definition=?, enabled=?, def_mac=?, def_generation=? WHERE bot_id='stasher'",
      args: [sealed.definition, sealed.enabled, sealed.def_mac, sealed.def_generation],
    });
    const own = await writeBotDef(s.db, {
      bot_id: "stasher",
      enabled: 0,
      expectDefinition: sealed.definition,
      expectEnabled: sealed.enabled,
      expectProjectId: sealed.project_id ?? null,
    });
    assert.equal(own.rowsAffected, 1);
    assert.equal(own.generation, first.generation + 1, "the owner's write skips every planned-and-abandoned generation");
    assert.equal(Number((await rowOf(s.db, "stasher")).enabled), 0);

    // …and the stashed tuple replayed AFTER it is a replay the spawn gate refuses, so the disable
    // stands: the row the bot wrote back is not a row anything acts on.
    assert.deepEqual(await writeStashBack(), { ok: false, reason: "generation-behind" });
    const readBack = await readVerifiedBotDef(s.db, "stasher");
    assert.equal(readBack.ok, false, "the replayed row is refused (no bot spawns from it)");
    assert.equal(readBack.reason, "generation-behind");

    // A future generation (a key holder could construct one) is still refused as ahead.
    const current = await rowOf(s.db, "stasher");
    const aheadMac = macBotDef({ ...current, def_generation: own.generation + 5 });
    await s.db.execute({
      sql: "UPDATE pi_bot_defs SET def_mac=?, def_generation=? WHERE bot_id='stasher'",
      args: [aheadMac, own.generation + 5],
    });
    assert.deepEqual(await verifyBotDef(await rowOf(s.db, "stasher"), { db: s.db }), { ok: false, reason: "generation-ahead" });
  } finally {
    s.close();
  }
});

test("I2: a write is refused while pi_bot_defs carries a trigger Crow did not install", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "guarded");
    await markEra(s.db);
    const before = await rowOf(s.db, "guarded");
    const gensBefore = JSON.parse(readFileSync(botDefGenerationsPath(), "utf8")).bots.guarded;

    // The stash-and-ignore trigger of the PoC: a plain foreign trigger on the authority table.
    await s.db.execute({ sql: "CREATE TABLE bot_stash (definition TEXT)", args: [] });
    await s.db.execute({
      sql: "CREATE TRIGGER stash_def BEFORE UPDATE ON pi_bot_defs BEGIN "
        + "INSERT INTO bot_stash (definition) VALUES (NEW.definition); SELECT RAISE(IGNORE); END",
      args: [],
    });

    const warns = [];
    const realWarn = console.warn;
    console.warn = (m) => warns.push(String(m));
    try {
      await assert.rejects(
        () => writeBotDef(s.db, {
          bot_id: "guarded",
          enabled: 0,
          expectDefinition: before.definition,
          expectEnabled: before.enabled,
          expectProjectId: before.project_id ?? null,
        }),
        (err) => err.code === BOT_DEF_FOREIGN_TRIGGER && err.trigger === "stash_def",
        "a foreign trigger on the table refuses the write instead of being written through",
      );
      // …and a CREATE (an insert) is refused by the same rule.
      await assert.rejects(
        () => writeBotDef(s.db, { bot_id: "newcomer", definition: DEF, enabled: 1, project_id: null, mode: "insert" }),
        (err) => err.code === BOT_DEF_FOREIGN_TRIGGER,
      );
    } finally {
      console.warn = realWarn;
    }
    assert.equal(warns.filter((m) => m.includes("stash_def")).length, 1, "ONE line names the trigger");
    assert.ok(!warns.some((m) => /crow_mcp|permission_policy|system_prompt/.test(m)),
      "and it names the trigger only, never row content");

    // NOTHING was written, and no generation was even planned for it.
    const after = await rowOf(s.db, "guarded");
    assert.equal(after.def_mac, before.def_mac);
    assert.equal(Number(after.def_generation), Number(before.def_generation));
    assert.deepEqual(JSON.parse(readFileSync(botDefGenerationsPath(), "utf8")).bots.guarded, gensBefore,
      "a refused write plans nothing");
    assert.equal((await s.db.execute({ sql: "SELECT bot_id FROM pi_bot_defs WHERE bot_id='newcomer'", args: [] })).rows.length, 0);
    // The trigger is still there: Crow never drops one.
    assert.equal((await s.db.execute({ sql: "SELECT name FROM sqlite_master WHERE type='trigger' AND name='stash_def'", args: [] })).rows.length, 1);

    // Removing the foreign trigger makes writes work again.
    await s.db.execute({ sql: "DROP TRIGGER stash_def", args: [] });
    const ok = await writeBotDef(s.db, {
      bot_id: "guarded",
      enabled: 0,
      expectDefinition: before.definition,
      expectEnabled: before.enabled,
      expectProjectId: before.project_id ?? null,
    });
    assert.equal(ok.rowsAffected, 1);
  } finally {
    s.close();
  }
});

test("I2: a KNOWN Crow trigger whose body changed is refused too (name AND normalised SQL)", async () => {
  const s = scratch();
  try {
    // The history migration is what installs the three capture triggers on pi_bot_defs (with item_versions
    // to write into). With those there, a sealed write lands as usual.
    const { run: migrateMore } = await import("../scripts/migrations/0025-item-versions-more.mjs");
    migrateMore({ dbPath: process.env.CROW_DB_PATH, tasksDbPath: join(s.home, "data", "tasks.db"), log: () => {} });
    await createBot(s.db, "hist");
    const row = await rowOf(s.db, "hist");
    const write = await writeBotDef(s.db, {
      bot_id: "hist",
      enabled: 0,
      expectDefinition: row.definition,
      expectEnabled: row.enabled,
      expectProjectId: row.project_id ?? null,
    });
    assert.equal(write.rowsAffected, 1, "Crow's own triggers do not block the write");

    // The SAME NAME with a different body: a trigger Crow installs, rewritten by somebody else.
    const after = await rowOf(s.db, "hist");
    await s.db.execute({ sql: "DROP TRIGGER hist_pi_bot_defs_au", args: [] });
    await s.db.execute({
      sql: "CREATE TRIGGER hist_pi_bot_defs_au AFTER UPDATE ON pi_bot_defs WHEN 0 BEGIN SELECT 1; END",
      args: [],
    });
    const warns = [];
    const realWarn = console.warn;
    console.warn = (m) => warns.push(String(m));
    try {
      await assert.rejects(
        () => writeBotDef(s.db, {
          bot_id: "hist",
          enabled: 1,
          expectDefinition: after.definition,
          expectEnabled: after.enabled,
          expectProjectId: after.project_id ?? null,
        }),
        (err) => err.code === BOT_DEF_FOREIGN_TRIGGER && err.trigger === "hist_pi_bot_defs_au" && err.reason === "body-changed",
      );
    } finally { console.warn = realWarn; }
    assert.ok(warns.some((m) => m.includes("hist_pi_bot_defs_au")));
    // The body-changed trigger is left exactly as it is (never dropped, never rewritten).
    const stored = await s.db.execute({ sql: "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='hist_pi_bot_defs_au'", args: [] });
    assert.match(String(stored.rows[0].sql), /WHEN 0/);
  } finally {
    s.close();
  }
});

// ─── round J: a trigger INSIDE the write ─────────────────────────────────

/** The history migration, so Crow's own `hist_pi_bot_defs_a[diu]` (which write `item_versions`) exist. */
async function withHistory(s) {
  const { run: migrateMore } = await import("../scripts/migrations/0025-item-versions-more.mjs");
  migrateMore({ dbPath: process.env.CROW_DB_PATH, tasksDbPath: join(s.home, "data", "tasks.db"), log: () => {} });
  return s;
}

test("J1: a statement that throws AFTER the row landed settles instead of abandoning (a RAISE(FAIL) down the trigger chain)", async () => {
  // THE BUG (reviewer's PoC). Crow's own `hist_pi_bot_defs_au` inserts into `item_versions`, so a
  // trigger THERE fires inside the owner's UPDATE. SQLite's `RAISE(FAIL)` aborts the statement but
  // KEEPS the row change already made, so the update throws having landed; the store's catch then
  // abandoned the planned generation, leaving the landed row one generation AHEAD of the counter
  // ("generation-ahead", so no bot spawns) while the tuple it replaced stayed the accepted one — so
  // a bot writing its old row back undid the owner's change. The catch now re-reads the row: it
  // carries the pair this write signed, so the counter SETTLES on it.
  const s = await withHistory(scratch());
  try {
    await createBot(s.db, "failer");
    await markEra(s.db);
    const before = await rowOf(s.db, "failer");
    const accepted = Number(before.def_generation);
    // The aborting trigger is created by the client JUST BEFORE the update: the trigger check and the
    // statement are two steps on one connection (`executeGuarded`), so a trigger created in that
    // window is the one case the refusal cannot see — and the statement then throws with the row
    // already changed. That is the J1 case.
    let armed = false;
    const client = {
      execute: async (query) => {
        if (!armed && /^UPDATE pi_bot_defs SET definition/.test(String(query?.sql ?? ""))) {
          armed = true;
          await s.db.execute({
            sql: "CREATE TRIGGER bot_history_fail AFTER INSERT ON item_versions BEGIN "
              + "SELECT RAISE(FAIL, 'history refused'); END",
            args: [],
          });
        }
        return s.db.execute(query);
      },
    };
    await assert.rejects(
      () => writeBotDef(client, {
        bot_id: "failer",
        enabled: 0,
        expectDefinition: before.definition,
        expectEnabled: before.enabled,
        expectProjectId: before.project_id ?? null,
      }),
      (err) => /history refused/.test(String(err?.message ?? "")),
      "the trigger's failure is still reported to the caller",
    );

    // THE OWNER'S CHANGE IS THE ROW, and the counter settled on it (accepted = planned).
    const landed = await rowOf(s.db, "failer");
    assert.equal(Number(landed.enabled), 0, "the disable landed (RAISE(FAIL) keeps the row change)");
    assert.equal(Number(landed.def_generation), accepted + 1, "the row is at the generation this write signed");
    const gens = JSON.parse(readFileSync(botDefGenerationsPath(), "utf8")).bots.failer;
    assert.equal(Number(gens.generation), accepted + 1, "the accepted generation settled on the landed row");
    assert.equal(gens.pending, null, "nothing is left pending");
    assert.equal(Number(gens.planned), accepted + 1, "the high-water is the landed generation");
    assert.deepEqual(await verifyBotDef(landed, { db: s.db }), { ok: true, reason: "mac" },
      "the row the owner's change left verifies, so the bot still runs");

    // …and the tuple it replaced is refused, so writing the old row back cannot undo the change.
    await s.db.execute({ sql: "DROP TRIGGER bot_history_fail", args: [] });
    await s.db.execute({
      sql: "UPDATE pi_bot_defs SET definition=?, enabled=?, def_mac=?, def_generation=? WHERE bot_id='failer'",
      args: [before.definition, before.enabled, before.def_mac, before.def_generation],
    });
    assert.deepEqual(await verifyBotDef(await rowOf(s.db, "failer"), { db: s.db }),
      { ok: false, reason: "generation-behind" }, "the replaced tuple is behind the landed one");
  } finally {
    s.close();
  }
});

test("J2: the refusal covers every table the write reaches (item_versions) and compares table names case-insensitively", async () => {
  const s = await withHistory(scratch());
  try {
    // (1) THE CATALOGUE is case-insensitive: SQLite keeps `sqlite_master.tbl_name` as it was WRITTEN.
    const expected = expectedTriggersOnTable("Pi_Bot_Defs");
    assert.equal(expected.size, expectedTriggersOnTable("pi_bot_defs").size, "the table name's case is not a different table");
    const capture = expected.get("hist_pi_bot_defs_au");
    assert.ok(capture, "the capture trigger is expected on the table");
    assert.deepEqual(
      unexpectedTriggers([{ name: "hist_pi_bot_defs_au", tbl_name: "PI_BOT_DEFS", sql: capture.sql }], expected),
      [],
      "a trigger on PI_BOT_DEFS is the trigger Crow installs on pi_bot_defs",
    );

    // (2) THE REACHABLE SET is derived from the catalogue, never copied: Crow's own capture trigger
    // writes item_versions, whose append-only guards are the next hop.
    const reached = reachableTriggerTables("pi_bot_defs");
    assert.ok(reached.has("pi_bot_defs"), [...reached].join(","));
    assert.ok(reached.has("item_versions"), `item_versions is reached: ${[...reached].join(",")}`);

    await createBot(s.db, "reached");
    await markEra(s.db);
    const row = await rowOf(s.db, "reached");
    const write = (db) => writeBotDef(db, {
      bot_id: "reached",
      enabled: 0,
      expectDefinition: row.definition,
      expectEnabled: row.enabled,
      expectProjectId: row.project_id ?? null,
    });

    // (3) A foreign trigger on item_versions refuses the write before anything is planned.
    await s.db.execute({
      sql: "CREATE TRIGGER rogue_versions_ai AFTER INSERT ON item_versions BEGIN SELECT 1; END", args: [],
    });
    await assert.rejects(
      () => write(s.db),
      (err) => err.code === BOT_DEF_FOREIGN_TRIGGER && err.trigger === "rogue_versions_ai" && err.table === "item_versions",
    );
    assert.equal(Number((await rowOf(s.db, "reached")).def_generation), Number(row.def_generation), "nothing was written");
    await s.db.execute({ sql: "DROP TRIGGER rogue_versions_ai", args: [] });

    // …and a trigger whose CREATE names the guarded table in CAPITALS is not a different trigger.
    await s.db.execute({
      sql: "CREATE TRIGGER rogue_caps_ai AFTER INSERT ON PI_BOT_DEFS BEGIN SELECT 1; END", args: [],
    });
    await assert.rejects(
      () => write(s.db),
      (err) => err.code === BOT_DEF_FOREIGN_TRIGGER && err.trigger === "rogue_caps_ai",
      "an upper-case table name is the same table",
    );
    await s.db.execute({ sql: "DROP TRIGGER rogue_caps_ai", args: [] });

    // (4) A Crow GUARD whose body changed is refused the same way (name AND normalised SQL).
    await s.db.execute({ sql: "DROP TRIGGER hist_item_versions_guard_ad", args: [] });
    await s.db.execute({
      sql: "CREATE TRIGGER hist_item_versions_guard_ad BEFORE DELETE ON item_versions WHEN 0 BEGIN SELECT 1; END",
      args: [],
    });
    await assert.rejects(
      () => write(s.db),
      (err) => err.code === BOT_DEF_FOREIGN_TRIGGER
        && err.trigger === "hist_item_versions_guard_ad" && err.reason === "body-changed",
    );
    await s.db.execute({ sql: "DROP TRIGGER hist_item_versions_guard_ad", args: [] });

    // (5) With the reached tables clean again the write lands (the check refuses nothing twice).
    const ok = await write(s.db);
    assert.equal(ok.rowsAffected, 1);
    const written = await rowOf(s.db, "reached");
    assert.equal(Number(written.enabled), 0);
    assert.deepEqual(await verifyBotDef(written, { db: s.db }), { ok: true, reason: "mac" });
  } finally {
    s.close();
  }
});

test("a write re-signs when another writer took a higher generation while it was in flight", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "racer");
    const racer = await rowOf(s.db, "racer");
    // A second writer (another process, another tab) plans a generation WHILE our statement is in
    // flight. The row must never be left behind the counter — verification would refuse it as a
    // replay and the bot could not spawn until somebody saved it again.
    let raced = false;
    const racing = {
      execute: async (q) => {
        if (/^UPDATE pi_bot_defs SET definition/.test(q.sql) && !raced) {
          raced = true;
          planBotDefGeneration("racer");
        }
        return s.db.execute(q);
      },
    };
    const res = await writeBotDef(racing, {
      bot_id: "racer",
      definition: { ...DEF, system_prompt: "raced" },
      expectDefinition: racer.definition,
      expectEnabled: racer.enabled,
      expectProjectId: racer.project_id ?? null,
    });
    assert.equal(res.rowsAffected, 1);
    const row = await rowOf(s.db, "racer");
    assert.equal(Number(row.def_generation), res.generation, "the row sits at the generation the store last signed");
    assert.equal((await verifyBotDef(row, { db: s.db })).ok, true);
    const gens = JSON.parse(readFileSync(botDefGenerationsPath(), "utf8"));
    assert.equal(Number(gens.bots.racer.generation), res.generation);
  } finally {
    s.close();
  }
});

test("an OR IGNORE insert that matched an existing row bumps nothing", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "dup");
    const before = JSON.parse(readFileSync(botDefGenerationsPath(), "utf8")).bots.dup.generation;
    const res = await writeBotDef(s.db, { bot_id: "dup", definition: DEF, mode: "insert", orIgnore: true });
    assert.equal(res.rowsAffected, 0);
    assert.equal(JSON.parse(readFileSync(botDefGenerationsPath(), "utf8")).bots.dup.generation, before,
      "a write that landed nothing bumps nothing");
  } finally {
    s.close();
  }
});

test("the generations file missing after the era refuses every row (never silently accepts)", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "solo");
    await markEra(s.db);
    const row = await rowOf(s.db, "solo");
    assert.deepEqual(await verifyBotDef(row, { db: s.db }), { ok: true, reason: "mac" });
    rmSync(botDefGenerationsPath(), { force: true });
    const errs = [];
    const realError = console.error;
    console.error = (m) => errs.push(String(m));
    try {
      assert.deepEqual(await verifyBotDef(row, { db: s.db }), { ok: false, reason: "generations-missing" });
    } finally {
      console.error = realError;
    }
    assert.ok(errs.some((m) => m.includes("bot-def-generations.json")), "and it says so, once");
  } finally {
    s.close();
  }
});

test("J5: an old-format generations entry {generation: g, pending: g} reads as accepted g-1 with the high-water at g", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "legacy");
    await markEra(s.db);
    const row = await rowOf(s.db, "legacy");
    assert.equal(Number(row.def_generation), 1);
    // A file written before the planning high-water existed stored the PLANNED generation in
    // `generation` and the in-flight mark in `pending`; a crash before that write landed leaves the
    // row at g-1. Reading `generation` as the accepted one would refuse the row as
    // "generation-behind" and no bot would spawn.
    writeFileSync(
      botDefGenerationsPath(),
      JSON.stringify({ v: 1, bots: { legacy: { generation: 2, pending: 2 } } }, null, 2) + "\n",
      { mode: 0o600 },
    );
    const st = readBotDefGenerations();
    assert.equal(Number(st.bots.legacy.generation), 1, "the accepted generation is the row's (g-1)");
    assert.equal(Number(st.bots.legacy.planned), 2, "the high-water keeps the planned generation");
    assert.equal(Number(st.bots.legacy.pending), 2, "and it stays the generation in flight");
    // So the row at g-1 verifies (the "pending" case), instead of being refused.
    assert.deepEqual(await verifyBotDef(row, { db: s.db }), { ok: true, reason: "pending" });
    // …and the next write plans PAST the old high-water, never re-issuing g.
    const next = await writeBotDef(s.db, {
      bot_id: "legacy",
      enabled: 0,
      expectDefinition: row.definition,
      expectEnabled: row.enabled,
      expectProjectId: row.project_id ?? null,
    });
    assert.equal(next.generation, 3, "the abandoned plan is never signed twice");
    assert.deepEqual(await verifyBotDef(await rowOf(s.db, "legacy"), { db: s.db }), { ok: true, reason: "mac" });
  } finally {
    s.close();
  }
});

test("a lost key refuses every row, with ONE loud line naming the key and the reset command", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "kilo");
    await markEra(s.db);
    const row = await rowOf(s.db, "kilo");

    // Lose the key: the file is gone, the state file is not (a restore of crow.db without secrets/).
    const keyPath = tokenMacKeyPath();
    rmSync(keyPath, { force: true });
    forgetTokenMacKey();
    forgetBotDefAlarms();

    const errs = [];
    const realError = console.error;
    console.error = (m) => errs.push(String(m));
    try {
      for (let i = 0; i < 3; i += 1) {
        // eslint-disable-next-line no-await-in-loop -- the same refusal, three times
        assert.deepEqual(await verifyBotDef(row, { db: s.db }), { ok: false, reason: "key-lost" });
      }
      assert.equal(errs.filter((m) => m.includes("token-hmac.key")).length, 1,
        "one loud line per process per 24 h, however often it refuses");
      assert.ok(errs[0].includes("scripts/token-hmac.mjs --reset"), "and it names the operator's way out");
      // A row written AFTER the era is refused on its own (no MAC at all), and one written before
      // it — while this box already had a key and then lost it — is not accepted as "pre-era":
      // a box that lost its key is not a new box. (The generations file is era evidence on its own,
      // so the era has to go with the marker: a real `secrets/` loss takes the generations file too.)
      await s.db.execute({ sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('new','New',?,1)", args: [JSON.stringify(DEF)] });
      assert.deepEqual(await verifyBotDef(await rowOf(s.db, "new"), { db: s.db }), { ok: false, reason: "no-mac" });
      await resetFamiliesForOperator([BOT_DEF_FAMILY]);
      await s.db.execute({ sql: "DELETE FROM dashboard_settings_overrides WHERE key=?", args: [botDefEraSettingKey()] });
      await s.db.execute({ sql: "DELETE FROM dashboard_settings WHERE key=?", args: [botDefEraSettingKey()] });
      rmSync(botDefGenerationsPath(), { force: true });
      allowPreEra();
      assert.deepEqual(await verifyBotDef(await rowOf(s.db, "new"), { db: s.db }), { ok: false, reason: "key-lost" });
    } finally {
      console.error = realError;
    }
  } finally {
    s.close();
  }
});

test("the converter seals every row, marks the era, and writes a hashes-only snapshot", async () => {
  const s = scratch();
  try {
    await s.db.execute({
      sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled, project_id) VALUES ('one','One',?,1,NULL), ('two','Two',?,0,3)",
      args: [JSON.stringify(DEF), JSON.stringify({ ...DEF, system_prompt: "two", gateways: [{ type: "discord", token: "a-secret-token" }] })],
    });
    const result = await runBotDefMacBoot({ db: s.db });
    assert.equal(result.key, "ok");
    assert.equal(result.count, 2, "both rows sealed");

    for (const id of ["one", "two"]) {
      // eslint-disable-next-line no-await-in-loop -- two bots
      const row = await rowOf(s.db, id);
      assert.match(String(row.def_mac), /^h1\./);
      assert.equal(Number(row.def_generation), 1);
      // eslint-disable-next-line no-await-in-loop
      assert.deepEqual(await verifyBotDef(row, { db: s.db }), { ok: true, reason: "mac" });
    }
    assert.equal(botDefEraConvertedSync(), true, "the secrets-side era marker is there");
    const { rows } = await s.db.execute({ sql: "SELECT value FROM dashboard_settings_overrides WHERE key=?", args: [botDefEraSettingKey()] });
    assert.ok(rows.length, "and the DB mirror agrees");
    const st = readState();
    assert.ok(st.families[BOT_DEF_FAMILY]?.rollback_file?.startsWith(BOT_DEF_ROLLBACK_PREFIX));

    // The snapshot is hashes only — a definition can carry a gateway token, which must not land in it.
    const snapshot = readFileSync(join(s.home, "secrets", st.families[BOT_DEF_FAMILY].rollback_file), "utf8");
    assert.ok(!snapshot.includes("a-secret-token"), "no definition text in the rollback file");
    const body = JSON.parse(snapshot);
    assert.equal(body.rows.length, 2);
    assert.ok(body.rows.every((r) => /^[0-9a-f]{64}$/.test(r.sha256)));
  } finally {
    s.close();
  }
});

test("converter crash between commit and marker: the re-run seals ONLY the snapshot rows", async () => {
  const s = scratch();
  try {
    await s.db.execute({
      sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('early','Early',?,1)",
      args: [JSON.stringify(DEF)],
    });
    const first = await runBotDefMacBoot({ db: s.db });
    assert.equal(first.count, 1);
    const snapshotFile = first.rollbackFile;

    // Model the crash: the rows are sealed but the era marker never got written. The generations
    // file the converter wrote IS era evidence (`botDefEraConvertedSync`), so an honest "the era never
    // happened" fixture removes it with the marker — a real crash before step 3 never wrote it.
    await resetFamiliesForOperator([BOT_DEF_FAMILY]);
    await s.db.execute({ sql: "DELETE FROM dashboard_settings_overrides WHERE key=?", args: [botDefEraSettingKey()] });
    await s.db.execute({ sql: "DELETE FROM dashboard_settings WHERE key=?", args: [botDefEraSettingKey()] });
    rmSync(botDefGenerationsPath(), { force: true });
    rmSync(botDefEraStatePath(), { force: true });
    assert.equal(readBotDefEraState().state, "absent", "the host era record is gone again");

    // A raw writer plants a row between the snapshot and the re-run (a bot, while the gateway was down).
    await s.db.execute({
      sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('planted','Planted',?,1)",
      args: [JSON.stringify({ ...DEF, tools: { crow_mcp: ["crow-secrets"] } })],
    });

    const second = await runBotDefMacBoot({ db: s.db });
    assert.equal(second.state, "converted");
    assert.equal(String(second.rollbackFile), String(snapshotFile), "the interrupted snapshot is resumed, not replaced");
    const planted = await rowOf(s.db, "planted");
    assert.equal(planted.def_mac, null, "the post-snapshot row is NOT blessed");
    assert.deepEqual(await verifyBotDef(planted, { db: s.db }), { ok: false, reason: "no-mac" });
    const early = await rowOf(s.db, "early");
    assert.equal(Number(early.def_generation), 1, "the snapshot row keeps its generation");
    assert.deepEqual(await verifyBotDef(early, { db: s.db }), { ok: true, reason: "mac" });
  } finally {
    s.close();
  }
});

test("converter: an un-writable secrets/ SKIPS the conversion, records \"skipped\", and unsealed rows are refused (§2.6)", async () => {
  const s = scratch();
  try {
    await s.db.execute({
      sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('skip','Skip',?,1)",
      args: [JSON.stringify(DEF)],
    });
    const result = await runBotDefMacBoot({
      db: s.db,
      writeSnapshot: () => { throw Object.assign(new Error("read-only"), { code: "EROFS" }); },
    });
    assert.equal(result.state, "skipped");
    assert.equal(readBotDefEraState().state, "skipped");
    assert.equal(botDefEraConvertedSync(), true, "skipped refuses unsealed rows");
    assert.equal((await rowOf(s.db, "skip")).def_mac, null);
    assert.deepEqual(await verifyBotDef(await rowOf(s.db, "skip"), { db: s.db }), { ok: false, reason: "no-mac" });
  } finally {
    s.close();
  }
});

test("converter: a throwing row read fails CLOSED for this process and records no era", async () => {
  const s = scratch();
  const realError = console.error;
  console.error = () => {};
  try {
    await s.db.execute({
      sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('rd','Rd',?,1)",
      args: [JSON.stringify(DEF)],
    });
    const failing = {
      execute: (q) => (/def_generation FROM pi_bot_defs$/.test(String(q?.sql || q))
        ? Promise.reject(new Error("no such column: def_generation"))
        : s.db.execute(q)),
      runTransaction: (r) => s.db.runTransaction(r),
    };
    const result = await runBotDefMacBoot({ db: failing });
    assert.equal(result.state, "failed");
    assert.equal(readBotDefEraState().state, "failed", "the failure is recorded; no converted era");
    assert.equal(readState().families?.[BOT_DEF_FAMILY]?.converted_at, undefined, "no era marker was written");
    assert.deepEqual(
      await verifyBotDef(await rowOf(s.db, "rd"), { db: s.db }),
      { ok: false, reason: "no-mac" },
      "an unsealed row is refused in this process",
    );
  } finally {
    console.error = realError;
    s.close();
  }
});

test("converter: a row edited after the snapshot is not sealed", async () => {
  const s = scratch();
  try {
    await s.db.execute({
      sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('drift','Drift',?,1)",
      args: [JSON.stringify(DEF)],
    });
    // The snapshot is written, then the row changes (a bot, mid-conversion), then the transaction.
    const result = await runBotDefMacBoot({
      db: s.db,
      writeSnapshot: (name, body) => {
        const here = join(process.env.CROW_HOME, "secrets");
        mkdirSync(here, { recursive: true });
        writeFileSync(join(here, name), JSON.stringify(body), { mode: 0o600 });
        return join(here, name);
      },
      runTransaction: async (runner) => {
        await s.db.execute({ sql: "UPDATE pi_bot_defs SET definition=? WHERE bot_id='drift'", args: [JSON.stringify({ ...DEF, permission_policy: { write_paths: ["/"] } })] });
        return s.db.runTransaction(runner);
      },
    });
    assert.equal(result.refused, 1, "the changed row was refused");
    assert.equal((await rowOf(s.db, "drift")).def_mac, null);
  } finally {
    s.close();
  }
});

test("the verified read, the history-restore signer and the key-reset reseal all agree", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "reader");
    await markEra(s.db);

    const good = await readVerifiedBotDef(s.db, "reader");
    assert.equal(good.ok, true);
    assert.equal(good.def.system_prompt, "you help");
    assert.equal((await readVerifiedBotDef(s.db, "nobody")).reason, "unknown-bot");

    // A restore that writes its own statement: sign, write, settle (what history/api.js does). The
    // signer returns the CANONICAL definition text it signed, and that is what the caller writes —
    // verification refuses any other text after the era (`definition-text`).
    const seal = signBotDef({ bot_id: "reader", definition: JSON.stringify({ ...DEF, system_prompt: "restored" }), enabled: 1, project_id: null });
    assert.equal(seal.definition, canonicalDefinitionText({ ...DEF, system_prompt: "restored" }));
    await s.db.execute({
      sql: "UPDATE pi_bot_defs SET definition=?, def_mac=?, def_generation=?, updated_at=datetime('now') WHERE bot_id=?",
      args: [seal.definition, seal.def_mac, seal.generation, "reader"],
    });
    assert.deepEqual(await verifyBotDef(await rowOf(s.db, "reader"), { db: s.db }), { ok: true, reason: "mac" },
      "the signed row is at the counter's generation, so it verifies as the normal equal case");
    seal.settle();
    assert.deepEqual(await verifyBotDef(await rowOf(s.db, "reader"), { db: s.db }), { ok: true, reason: "mac" });

    // The operator key reset: every row re-signed under a key that still verifies — from the tuples
    // step 0 verified, which is what the reset's reseal takes (there is no verified-again path).
    const check = await verifyAllBotDefs(s.db);
    assert.deepEqual(check.verified.map((row) => row.bot_id), ["reader"]);
    const resealed = await resealAllBotDefs(s.db, {
      at: new Date("2026-01-01T00:00:00Z"), verifiedRows: check.verified,
    });
    assert.equal(resealed.resealed, 1);
    assert.deepEqual(await verifyBotDef(await rowOf(s.db, "reader"), { db: s.db }), { ok: true, reason: "mac" });

    // The sqlite facade the CLIs use speaks the same contract as the gateway client.
    const sync = (await import("better-sqlite3")).default;
    const conn = new sync(process.env.CROW_DB_PATH);
    try {
      const facade = sqliteDbFacade(conn);
      const { rows } = await facade.execute({ sql: "SELECT bot_id FROM pi_bot_defs", args: [] });
      assert.deepEqual(rows.map((r) => r.bot_id), ["reader"]);
    } finally {
      conn.close();
    }
  } finally {
    s.close();
  }
});

// ── round C/D: the race, the column, the reset, the way back ────────────────

test("E1: a row flipped between the caller's read and the write is never re-signed", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "flip");
    await markEra(s.db);
    const sealed = await rowOf(s.db, "flip");
    const expectsOfSealed = {
      expectDefinition: sealed.definition,
      expectEnabled: sealed.enabled,
      expectProjectId: sealed.project_id ?? null,
    };
    // T: a definition a bot wrote into its own row (a widened policy), leaving def_mac/def_generation
    // exactly as they were, so the row no longer verifies.
    const tamperedText = JSON.stringify({ ...DEF, permission_policy: { write_paths: ["/"] } });

    // 1. THE CALLER'S READ. A tab save (or the artifacts house style) read the TAMPERED row and built
    //    its new content from it; the bot then puts the SEALED definition back, so the store's own
    //    read verifies S while the caller's content came from T. Under the old CAS (def_mac +
    //    def_generation only) the UPDATE matched T and signed the tampered content.
    await s.db.execute({ sql: "UPDATE pi_bot_defs SET definition=? WHERE bot_id='flip'", args: [tamperedText] });
    const callerRead = tamperedText;
    await s.db.execute({ sql: "UPDATE pi_bot_defs SET definition=? WHERE bot_id='flip'", args: [sealed.definition] });
    await assert.rejects(
      () => writeBotDef(s.db, {
        bot_id: "flip",
        definition: { ...DEF, permission_policy: { write_paths: ["/"] }, system_prompt: "saved from the tampered read" },
        expectDefinition: callerRead,
        expectEnabled: sealed.enabled,
        expectProjectId: sealed.project_id ?? null,
      }),
      (err) => err.code === "BOT_DEF_UNVERIFIED" && err.reason === "caller-read-differs",
      "a caller whose read is not the verified row is refused, not signed",
    );
    const after = await rowOf(s.db, "flip");
    assert.equal(after.def_mac, sealed.def_mac, "nothing was re-signed");
    assert.equal(after.definition, sealed.definition, "and the row still holds the sealed content");
    assert.equal(Number(after.def_generation), Number(sealed.def_generation), "and nothing was bumped");

    // 2. A DERIVED writer with the row flipping between the store's verify and its statement: the
    //    UPDATE pins the VERIFIED content, so it lands on nothing and the tampered row keeps its old
    //    MAC (it stays refused) instead of being stamped with a fresh one.
    const racing = {
      execute: async (q) => {
        if (/^UPDATE pi_bot_defs SET definition/.test(q.sql)) {
          await s.db.execute({ sql: "UPDATE pi_bot_defs SET definition=? WHERE bot_id='flip'", args: [tamperedText] });
        }
        return s.db.execute(q);
      },
    };
    const res = await writeBotDef(racing, { bot_id: "flip", enabled: 0, ...expectsOfSealed });
    assert.equal(res.rowsAffected, 0, "the pinned-content CAS matched nothing");
    const tampered = await rowOf(s.db, "flip");
    assert.equal(tampered.def_mac, sealed.def_mac, "the tampered row keeps its old MAC");
    assert.equal(tampered.definition, tamperedText);
    assert.deepEqual(await verifyBotDef(tampered, { db: s.db }), { ok: false, reason: "mac-mismatch" },
      "so it is still refused rather than laundered into a valid row");

    // 3. THE DERIVED WRITERS THAT USED TO PASS A TRANSFORM NOW READ, BUILD AND STATE (round D, item
    //    F1): the `transform` mode is GONE, so neither of them has a way to build content from a read
    //    the store made for it — and a tampered row is refused instead of quietly rewritten.
    for (const rel of ["scripts/pi-bots/artifacts-companions.mjs", "scripts/init-pi-bots.mjs"]) {
      const src = readFileSync(join(ROOT, rel), "utf8");
      assert.equal(/transform:\s*\(?(async\s*)?\(?verified/.test(src), false, `${rel} passes no transform: the mode is gone`);
      assert.ok(/expectDefinition:/.test(src) && /expectEnabled:/.test(src) && /expectProjectId:/.test(src),
        `${rel} states the row it read (expectDefinition/expectEnabled/expectProjectId)`);
    }
    assert.equal(/json_extract\(definition, '\$\.project_id'\)/.test(
      readFileSync(join(ROOT, "scripts/init-pi-bots.mjs"), "utf8"),
    ), false, "the project_id backfill parses the definition it read, never json_extract");
    // The store itself has no transform mode left.
    const store = readFileSync(join(ROOT, "servers/shared/bot-def-store.js"), "utf8");
    assert.equal(/args\.transform/.test(store), false, "writeBotDef runs no caller-supplied transform");
  } finally {
    s.close();
  }
});

test("F1: a partial write whose expect* differs from the verified row is refused (caller-read-differs)", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "stated");
    await markEra(s.db);
    const row = await rowOf(s.db, "stated");
    const gen = Number(row.def_generation);

    // EVERY marked expectation is `expect* NOW, not an optional extra (round D, item F1): a write
    // whose read of `enabled`, `project_id` or the definition is not the row it verified refuses.
    for (const [label, expect] of [
      ["enabled", { expectEnabled: 0 }],
      ["project_id", { expectProjectId: 7 }],
      ["definition", { expectDefinition: JSON.stringify({ ...DEF, system_prompt: "an older read" }) }],
    ]) {
      const stated = {
        expectDefinition: row.definition,
        expectEnabled: row.enabled,
        expectProjectId: row.project_id ?? null,
        ...expect,
      };
      await assert.rejects(
        () => writeBotDef(s.db, { bot_id: "stated", enabled: 1, ...stated }),
        (err) => err.code === "BOT_DEF_UNVERIFIED" && err.reason === "caller-read-differs",
        `a stale ${label} read refuses the write`,
      );
    }
    const still = await rowOf(s.db, "stated");
    assert.equal(still.def_mac, row.def_mac, "no refused write re-signed anything");
    assert.equal(Number(still.def_generation), gen, "and the generation never moved");

    // A toggle states the same three values (setBotEnabled is a partial write too).
    await assert.rejects(
      () => setBotEnabled(s.db, "stated", 0, { ...{ expectDefinition: row.definition, expectEnabled: row.enabled, expectProjectId: row.project_id ?? null }, expectProjectId: 3 }),
      (err) => err.code === "BOT_DEF_UNVERIFIED" && err.reason === "caller-read-differs",
    );
    const off = await rowOf(s.db, "stated");
    assert.equal(Number(off.enabled), 1, "the refused toggle left the switch alone");
  } finally {
    s.close();
  }
});

test("F1: an update with no expect* throws (programming error), and the source has no such call", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "bare");
    await markEra(s.db);
    await assert.rejects(
      () => writeBotDef(s.db, { bot_id: "bare", definition: { ...DEF, system_prompt: "unstated" } }),
      (err) => err.code === "BOT_DEF_EXPECT_REQUIRED" && err.missing.includes("expectDefinition")
        && err.missing.includes("expectEnabled") && err.missing.includes("expectProjectId"),
      "a partial write that states nothing is a programming error",
    );
    await assert.rejects(
      () => setBotEnabled(s.db, "bare", 0),
      (err) => err.code === "BOT_DEF_EXPECT_REQUIRED",
      "a toggle without a read to point at is the same error",
    );
    // An INSERT (a create) and a full-form owner save are structurally exempt, and they still land.
    const created = await writeBotDef(s.db, {
      bot_id: "born", definition: DEF, enabled: 1, project_id: null, mode: "insert",
    });
    assert.equal(created.rowsAffected, 1, "a create needs no read: it takes nothing from a row");
    const replaced = await writeBotDef(s.db, {
      bot_id: "born", definition: { ...DEF, system_prompt: "full form" }, enabled: 1, project_id: null, ownerFullReplace: true,
    });
    assert.equal(replaced.rowsAffected, 1, "a full-form owner save supplies the whole content itself");
    // …and nothing was written by the two refusals.
    assert.match(String((await rowOf(s.db, "bare")).definition), /you help/);
  } finally {
    s.close();
  }
});

test("E3: a row without the def_mac COLUMN is refused after the era, and only accepted before it", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "col");
    await markEra(s.db);
    // A contained bot shakes its MAC off with one ALTER TABLE.
    await s.db.execute({ sql: "ALTER TABLE pi_bot_defs DROP COLUMN def_mac", args: [] });
    const columnless = await rowOf(s.db, "col");
    assert.equal(Object.prototype.hasOwnProperty.call(columnless, "def_mac"), false, "the column is really gone");
    assert.deepEqual(verifyBotDefSync(columnless, { converted: botDefEraConvertedSync() }),
      { ok: false, reason: "no-mac-column" }, "the ERA decides, not the row's shape");
    const read = await readVerifiedBotDef(s.db, "col");
    assert.equal(read.ok, false, "the verified read refuses it too");
    assert.equal(read.reason, "no-mac-column");
    // The write path refuses as well: an unsealed row could never be verified again.
    const warns = [];
    const realWarn = console.warn;
    console.warn = (m) => warns.push(String(m));
    try {
      await assert.rejects(
        () => writeBotDef(s.db, { bot_id: "col", definition: { ...DEF, system_prompt: "x" } }),
        (err) => err.code === "BOT_DEF_UNVERIFIED" && err.reason === "no-mac-column",
      );
    } finally { console.warn = realWarn; }
    assert.ok(warns.some((m) => m.includes("--show")), "and the one line names the re-approve command");
    // The seam (every bot-loadable verifier: skill promotion, the history restore) makes the same
    // decision from the secrets-side evidence alone.
    assert.deepEqual(verifyBotDefSealed(columnless), { ok: false, reason: "no-mac-column" });
  } finally {
    s.close();
  }
});

test("E3: a columnless store before the era is still the pre-era shape it is", async () => {
  const s = scratch();
  try {
    await s.db.execute({ sql: "ALTER TABLE pi_bot_defs DROP COLUMN def_mac", args: [] });
    await s.db.execute({ sql: "ALTER TABLE pi_bot_defs DROP COLUMN def_generation", args: [] });
    await s.db.execute({
      sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('plain','Plain',?,1)",
      args: [JSON.stringify(DEF)],
    });
    allowPreEra();
    assert.equal(botDefEraConvertedSync(), false, "an explicit pre-era record");
    const read = await readVerifiedBotDef(s.db, "plain");
    assert.equal(read.ok, true, "the pre-era shape is accepted (a migration that has not run yet)");
    assert.equal(read.reason, "pre-era");
    const warn = [];
    const realWarn = console.warn;
    console.warn = (m) => warn.push(String(m));
    let res;
    try {
      // A pre-era store still needs the read stated (round D, item F1): the rule is about the caller,
      // not about whether the row happens to be sealable.
      res = await writeBotDef(s.db, {
        bot_id: "plain",
        definition: { ...DEF, system_prompt: "still writable" },
        expectDefinition: read.row.definition,
        expectEnabled: read.row.enabled,
        expectProjectId: read.row.project_id ?? null,
      });
    } finally { console.warn = realWarn; }
    assert.equal(res.rowsAffected, 1, "and a write still lands (unsealed), so a mid-migration box keeps working");
    assert.ok(warn.some((m) => m.includes("npm run init-db")), "with the one warning that names the fix");
  } finally {
    s.close();
  }
});

test("E5: the key reset keeps the replay floor, and its reseal is a compare-and-swap on the verified row", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "keeper");
    await markEra(s.db);
    const start = await rowOf(s.db, "keeper");
    // Put the counter ahead of the row and settle it: the row is now a REPLAY (generation-behind),
    // exactly what a bot writing an old pair back produces.
    const planned = planBotDefGeneration("keeper");
    settleBotDefGeneration("keeper", planned.generation);
    assert.deepEqual(await verifyBotDef(start, { db: s.db }), { ok: false, reason: "generation-behind" });
    // The reset's own check must NOT turn that into a "verified" row (no `replay: false`), so it is
    // never re-sealed.
    const check = await verifyAllBotDefs(s.db);
    assert.deepEqual(check.verified, [], "a replay is not verified by the reset's check");
    assert.deepEqual(check.unverified, ["keeper"]);
    const resealed = await resealAllBotDefs(s.db, { verifiedRows: check.verified });
    assert.equal(resealed.resealed, 0);
    assert.deepEqual(resealed.refused, ["keeper"]);
    // Put the row back into a genuinely verifiable state at the counter (a full-form write signs what
    // it stores), and prove the reseal CAS: a row that changes between the verify and the statement is
    // skipped and named, never re-signed with its new content.
    await writeBotDef(s.db, {
      bot_id: "keeper", definition: DEF, enabled: 1, project_id: null, ownerFullReplace: true,
    });
    let raced = false;
    const racing = {
      execute: async (q) => {
        if (/^UPDATE pi_bot_defs SET def_mac=/.test(q.sql) && !raced) {
          raced = true;
          await s.db.execute({ sql: "UPDATE pi_bot_defs SET enabled=0 WHERE bot_id='keeper'", args: [] });
        }
        return s.db.execute(q);
      },
    };
    const verifiedAgain = await verifyAllBotDefs(s.db);
    assert.deepEqual(verifiedAgain.verified.map((row) => row.bot_id), ["keeper"]);
    const out = await resealAllBotDefs(racing, { verifiedRows: verifiedAgain.verified });
    assert.equal(out.resealed, 0, "the reseal did not land on the row that moved");
    assert.equal(out.failed, 1);
    assert.deepEqual(out.skipped, ["keeper"], "and it is listed, not silently blessed");
    const after = await rowOf(s.db, "keeper");
    assert.equal(Number(after.enabled), 0, "the other writer's row is exactly as it left it");
  } finally {
    s.close();
  }
});

test("L1: a row rewritten between the reset's verify and its reseal is not sealed under the new key", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "step0");
    await createBot(s.db, "steady");
    await markEra(s.db);

    // STEP 0 of `--reset`: verify every row while the OLD key is still loadable. What comes back is the
    // CONTENT that was vouched for, so the reseal can write exactly that.
    const check = await verifyAllBotDefs(s.db);
    assert.deepEqual(check.verified.map((row) => row.bot_id).sort(), ["steady", "step0"]);
    assert.deepEqual(check.unverified, []);
    const step0 = check.verified.find((row) => row.bot_id === "step0");
    assert.equal(step0.definition, canonicalDefinitionText(DEF), "the tuple carries the definition it verified");
    assert.ok(step0.def_mac && step0.def_generation, "the tuple carries the seal it verified at");

    // BETWEEN THE STEPS a contained bot rewrites its own row, keeping `def_mac`/`def_generation` exactly
    // as they were: it can write the columns, it cannot sign. A reseal that re-read the table here
    // would sign THIS content under the new key.
    const tamperedText = JSON.stringify({ ...DEF, permission_policy: { write_paths: ["/"] } });
    await s.db.execute({
      sql: "UPDATE pi_bot_defs SET definition=? WHERE bot_id='step0'", args: [tamperedText],
    });

    // The key swap the reset makes between step 0 and step 3b: the old key moves aside, a new one is
    // minted, and the reseal is handed the step-0 tuples.
    const oldKeyId = ensureKey().id;
    const keyPath = tokenMacKeyPath();
    renameSync(keyPath, `${keyPath}.lost`);
    const newKey = adoptOperatorKey();
    assert.notEqual(newKey.id, oldKeyId, "a different key is in place for the reseal");

    const out = await resealAllBotDefs(s.db, { verifiedRows: check.verified });
    assert.equal(out.resealed, 1, "only the row that is still what step 0 verified was re-sealed");
    assert.equal(out.failed, 1);
    assert.deepEqual(out.skipped, ["step0"], "the rewritten row is named, not sealed under the new key");
    assert.deepEqual(out.refused, [], "it was verified at step 0, so it is not reported as never-verified");

    // The rewritten row is exactly as the bot left it: same content, same (old-key) MAC, and it does
    // not verify under the new key — a reset is a key change, never an amnesty.
    const raced = await rowOf(s.db, "step0");
    assert.equal(raced.definition, tamperedText, "the content the bot wrote was never re-signed");
    assert.equal(raced.def_mac, step0.def_mac, "its step-0 (old-key) MAC is untouched");
    assert.equal(Number(raced.def_generation), Number(step0.def_generation), "and nothing was bumped");
    assert.deepEqual(await verifyBotDef(raced, { db: s.db }), { ok: false, reason: "foreign-mac" },
      "the row does not verify under the new key");

    // The row that did not move was re-sealed, and it verifies under the new key at a later generation.
    const steady = await rowOf(s.db, "steady");
    assert.match(String(steady.def_mac), new RegExp(`^h1\\.${newKey.id}\\.`), "sealed under the NEW key");
    assert.ok(Number(steady.def_generation) > Number(check.verified.find((r) => r.bot_id === "steady").def_generation));
    assert.deepEqual(await verifyBotDef(steady, { db: s.db }), { ok: true, reason: "mac" });
  } finally {
    s.close();
  }
});

test("E6: bot-def-reapprove shows the stored content and re-seals exactly that content", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "lost");
    await markEra(s.db);
    const tamperedText = JSON.stringify({ ...DEF, permission_policy: { write_paths: ["/"] } });
    await s.db.execute({ sql: "UPDATE pi_bot_defs SET definition=? WHERE bot_id='lost'", args: [tamperedText] });
    assert.equal((await readVerifiedBotDef(s.db, "lost")).ok, false, "the bot is refused today");

    const out = [];
    const err = [];
    const io = () => ({ stdout: { write: (x) => out.push(String(x)) }, stderr: { write: (x) => err.push(String(x)) } });
    assert.equal(await reapproveMain({ argv: ["lost", "--show"], ...io() }), 0, err.join(""));
    const shown = out.join("");
    assert.match(shown, /verification:\s+REFUSED — mac-mismatch/);
    assert.ok(shown.includes('"write_paths"') && shown.includes('"/"'), "the operator sees the whole stored definition");
    // I4: the digest is the FULL sha256 hex — 64 characters, and --approve takes nothing shorter.
    const digest = /digest:\s+([0-9a-f]{64})/.exec(shown)[1];
    assert.equal(digest.length, 64);
    assert.equal(await reapproveMain({ argv: ["lost", "--approve", digest.slice(0, 16)], ...io() }), 1,
      "a truncated digest is not accepted");

    // A digest from an older --show is refused when the row has moved since (a compare-and-swap on
    // the whole content), and nothing is written.
    await s.db.execute({ sql: "UPDATE pi_bot_defs SET definition=? WHERE bot_id='lost'", args: [JSON.stringify({ ...DEF, system_prompt: "moved" })] });
    out.length = 0;
    assert.equal(await reapproveMain({ argv: ["lost", "--approve", digest], ...io() }), 1, "a changed row is refused");
    assert.ok(err.join("").includes("changed since"));
    assert.equal((await readVerifiedBotDef(s.db, "lost")).ok, false);

    // The digest of what is stored NOW re-seals exactly that content.
    out.length = 0;
    err.length = 0;
    assert.equal(await reapproveMain({ argv: ["lost", "--show"], ...io() }), 0);
    const digest2 = /digest:\s+([0-9a-f]{64})/.exec(out.join(""))[1];
    out.length = 0;
    assert.equal(await reapproveMain({ argv: ["lost", "--approve", digest2], ...io() }), 0, err.join(""));
    assert.match(out.join(""), new RegExp(`re-approved lost at ${digest2}`));
    const read = await readVerifiedBotDef(s.db, "lost");
    assert.equal(read.ok, true, "the bot is verifiable again");
    assert.equal(read.def.system_prompt, "moved", "and it is the content the operator approved, not a reset");
    assert.deepEqual(read.def.permission_policy, DEF.permission_policy);
    // The approval is in the instance's audit log.
    const { rows } = await s.db.execute({
      sql: "SELECT event_type, details FROM audit_log WHERE event_type='bot_def.reapprove'", args: [],
    });
    assert.equal(rows.length, 1);
    assert.ok(String(rows[0].details).includes(digest2));
    // An unknown bot is a refusal, not a crash.
    err.length = 0;
    assert.equal(await reapproveMain({ argv: ["nobody", "--show"], ...io() }), 1);
  } finally {
    s.close();
  }
});

test("static: the spawn gate verifies before it spawns, and the MAC covers generation 1 for the converter", () => {
  // The converter hashes what the MAC covers: the SAME canonical form at generation 1, and the
  const row = { bot_id: "b", definition: JSON.stringify(DEF), enabled: 1, project_id: null, def_generation: 1 };
  assert.equal(
    sha256(canonicalBotDef(row)),
    createHash("sha256").update(canonicalBotDef({ ...row, def_generation: 1 })).digest("hex"),
  );
  assert.match(macBotDef(row), /^h1\./);

  // The bridge is the spawn: its `loadBot` must verify (sync) and log the one line before refusing.
  const bridge = readFileSync(join(ROOT, "scripts", "pi-bots", "bridge.mjs"), "utf8");
  assert.ok(/verifyBotDefSync\(/.test(bridge), "bridge.loadBot verifies the definition");
  assert.ok(/botDefRefusalAlarm\(/.test(bridge), "and logs ONE line per bot per reason");
  assert.ok(/"def_mac, def_generation FROM pi_bot_defs/.test(bridge) || /def_mac, def_generation FROM pi_bot_defs/.test(bridge),
    "and reads the MAC columns");

  // Every writer module named in the design goes through the store or the store's seam.
  for (const rel of [
    "servers/gateway/dashboard/panels/bot-builder/api-handlers.js",
    "servers/gateway/dashboard/panels/bot-builder/move-bot.js",
    "servers/gateway/dashboard/panels/bot-builder/voice-bot-editor.js",
    "servers/gateway/dashboard/panels/bot-builder/wizard.js",
    "servers/gateway/dashboard/panels/onboarding/starter-content.js",
    "servers/gateway/fix-it/remedies/remove-bot-sharing.js",
    "servers/gateway/routes/bot-federation-routes.js",
    "servers/gateway/satellites/grants.js",
  ]) {
    const src = readFileSync(join(ROOT, rel), "utf8");
    assert.ok(/bot-def-store\.js/.test(src), `${rel} imports the one writer`);
  }
  // The bot-loadable writers reach the seam instead (they must never hold the key).
  for (const rel of [
    "bundles/studio/server/give-tools.js",
    "scripts/pi-bots/artifacts-companions.mjs",
    "scripts/pi-bots/skill_promote.mjs",
    "servers/shared/voice-bot.js",
  ]) {
    const src = readFileSync(join(ROOT, rel), "utf8");
    assert.ok(/bot-def-seal\.js/.test(src), `${rel} writes through the seam`);
    assert.ok(!/bot-def-store\.js|token-mac\.js/.test(src), `${rel} never reaches the store or the key`);
  }

  // The converter's rollback files are their own prefix, so the oauth_tokens rollback tool never
  // reads one as its own.
  assert.ok(!BOT_DEF_ROLLBACK_PREFIX.startsWith("token-hmac-rollback-"));
  assert.ok(readdirSync(join(ROOT, "servers", "gateway", "boot")).includes("bot-def-mac.js"));
});
// ─── round E: the host-side era record, the bounded canonical form, stale pending ────────────

const quiet = async (fn) => {
  const w = console.warn; const l = console.log; const e = console.error;
  console.warn = () => {}; console.log = () => {}; console.error = () => {};
  try { return await fn(); } finally { console.warn = w; console.log = l; console.error = e; }
};

test("H1: a planted DB mirror never skips the conversion; the host record decides, and nulling every def_mac opens nothing", async () => {
  const s = scratch();
  try {
    await s.db.execute({
      sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('victim','V',?,1)",
      args: [JSON.stringify(DEF)],
    });
    ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false }); // the box's key exists
    // The bot plants the mirror (it can write crow.db) and the converter must STILL run.
    await writeSetting(s.db, botDefEraSettingKey(), "1", { scope: "local" });
    const warns = [];
    const realWarn = console.warn;
    console.warn = (m) => warns.push(String(m));
    let result;
    try { result = await runBotDefMacBoot({ db: s.db }); } finally { console.warn = realWarn; }
    assert.ok(warns.some((m) => m.includes("era mirror present without host state; converting")));
    assert.equal(result.state, "converted");
    assert.equal(readBotDefEraState().state, "converted", "the host record is written");
    assert.match(String((await rowOf(s.db, "victim")).def_mac), /^h1\./, "the row was sealed");

    // The bot now edits its own row and nulls EVERY def_mac so no sealed row is left to see.
    await s.db.execute({ sql: "UPDATE pi_bot_defs SET definition=?, def_mac=NULL, def_generation=NULL", args: [JSON.stringify({ ...DEF, tools: { crow_mcp: ["*"] } })] });
    const tampered = await rowOf(s.db, "victim");
    // The bridge-side check reads the host record directly: still refused.
    assert.equal(botDefEraConvertedSync(), true);
    assert.deepEqual(verifyBotDefSync(tampered, { converted: botDefEraConvertedSync() }), { ok: false, reason: "no-mac" });
    // Source pins: the bridge decides the era from the record alone.
    const bridge = readFileSync(join(ROOT, "scripts", "pi-bots", "bridge.mjs"), "utf8");
    assert.ok(/botDefEraConvertedSync\(\)/.test(bridge) && !/anyMac/.test(bridge));
  } finally { s.close(); }
});

test("H1 (lane C repro): a mock DB that answers the planted mirror still gets a converted record", async () => {
  const s = scratch();
  try {
    ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false }); // the box's key exists
    const rows = [{ bot_id: "victim", display_name: "v", definition: '{"a":1}', enabled: 1, project_id: null, def_generation: null }];
    const db = {
      execute: async ({ sql, args }) => {
        if (/dashboard_settings/.test(sql) && args?.[0] === "token_hmac_era:bot:def") return { rows: [{ value: "1" }] };
        if (/def_mac IS NULL/.test(sql)) return { rows: rows.map((r) => ({ bot_id: r.bot_id })) };
        if (/FROM pi_bot_defs/.test(sql) && /def_mac IS NOT NULL/.test(sql)) return { rows: [] };
        if (/FROM pi_bot_defs/.test(sql)) return { rows };
        return { rows: [] };
      },
      runTransaction: async (fn) => fn(() => ({ rows: [] })),
    };
    const r = await quiet(() => runBotDefMacBoot({ db, audit: () => {} }));
    assert.equal(r.state, "converted");
    assert.equal(readBotDefEraState().state, "converted");
    assert.equal(botDefEraConvertedSync(), true);
    assert.deepEqual(
      verifyBotDefSync({ ...rows[0], definition: '{"a":"widened"}', def_mac: null }, { converted: botDefEraConvertedSync() }),
      { ok: false, reason: "no-mac" },
    );
  } finally { s.close(); }
});

test("H2: a definition nested past the bound completes the conversion with that row refused, and nothing throws", async () => {
  const s = scratch();
  try {
    const deep = "[".repeat(6000) + "]".repeat(6000);
    await s.db.execute({
      sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('victim','v',?,1), ('zz-junk','j',?,0)",
      args: [JSON.stringify(DEF), deep],
    });
    const warns = [];
    const realWarn = console.warn;
    console.warn = (m) => warns.push(String(m));
    let result;
    try { result = await runBotDefMacBoot({ db: s.db }); } finally { console.warn = realWarn; }
    assert.equal(result.state, "converted", "one bad row never stops the era");
    assert.equal(readBotDefEraState().state, "converted");
    assert.equal(warns.filter((m) => m.includes("zz-junk") && m.includes("too complex")).length, 1, "listed once");
    assert.match(String((await rowOf(s.db, "victim")).def_mac), /^h1\./, "the good row sealed");
    const junk = await rowOf(s.db, "zz-junk");
    assert.equal(junk.def_mac, null);

    const read = await readVerifiedBotDef(s.db, "zz-junk");
    assert.equal(read.ok, false);
    const listed = await (await import("../servers/shared/bot-def-store.js")).verifyBotRows(s.db, [await rowOf(s.db, "victim"), junk]);
    assert.deepEqual(listed.map((r) => r.ok), [true, false]);
    const all = await verifyAllBotDefs(s.db);
    assert.deepEqual(all.unverified, ["zz-junk"]);
    assert.equal(all.verified.length, 1);
    // A deep row that carries a MAC copied from elsewhere is refused with the fixed reason, never a throw.
    const forged = { ...(await rowOf(s.db, "victim")), definition: deep };
    assert.deepEqual(verifyBotDefSync(forged, { converted: true }), { ok: false, reason: "definition-too-complex" });
    assert.throws(() => canonicalJson(JSON.parse(deep)), /definition-too-complex/);
    assert.equal(CANONICAL_MAX_DEPTH, 64);
  } finally { s.close(); }
});

test("a fresh install's first boot writes the converted record (0 rows) and a bot created afterwards verifies", async () => {
  const s = scratch();
  try {
    const result = await quiet(() => runBotDefMacBoot({ db: s.db }));
    assert.equal(result.state, "converted");
    assert.equal(result.count, 0);
    assert.equal(readBotDefEraState().state, "converted");
    await createBot(s.db, "later");
    assert.deepEqual(await verifyBotDef(await rowOf(s.db, "later"), { db: s.db }), { ok: true, reason: "mac" });
  } finally { s.close(); }
});

test("a MISSING era record refuses an unsealed row in the gateway verifier and in the bridge's check", async () => {
  const s = scratch();
  try {
    await s.db.execute({ sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('u','U',?,1)", args: [JSON.stringify(DEF)] });
    assert.equal(readBotDefEraState().state, "absent");
    const row = await rowOf(s.db, "u");
    assert.deepEqual(await verifyBotDef(row, { db: s.db }), { ok: false, reason: "no-mac" });
    assert.deepEqual(gate(row), { ok: false, reason: "no-mac" }, "the bridge's decision");
    // A corrupt or loose record is refused the same way.
    mkdirSync(join(s.home, "secrets"), { recursive: true, mode: 0o700 });
    writeFileSync(botDefEraStatePath(), "{nope", { mode: 0o600 });
    assert.equal(readBotDefEraState().state, "unreadable");
    assert.deepEqual(gate(row), { ok: false, reason: "no-mac" });
  } finally { s.close(); }
});

test("a failed outcome is recorded and refuses unsealed rows; converted is never downgraded", async () => {
  const s = scratch();
  try {
    assert.equal(writeBotDefEraState("failed", { reason: "x" }), true);
    assert.equal(readBotDefEraState().state, "failed");
    assert.equal(botDefEraConvertedSync(), true);
    assert.equal(writeBotDefEraState("converted"), true);
    assert.equal(writeBotDefEraState("failed"), false, "once converted, never back");
    assert.equal(writeBotDefEraState("pre-era"), false);
    assert.equal(readBotDefEraState().state, "converted");
  } finally { s.close(); }
});

test("M1: a stale pending mark is settled when the row carries it and verifies, abandoned otherwise", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "landed");
    await createBot(s.db, "lost");
    const before = Number((await rowOf(s.db, "landed")).def_generation);
    // landed: the writer planned a generation and the row write WENT THROUGH, but it died before settling.
    const plan = planBotDefGeneration("landed");
    const row = await rowOf(s.db, "landed");
    const mac = macBotDef({ ...row, def_generation: plan.generation });
    await s.db.execute({ sql: "UPDATE pi_bot_defs SET def_generation=?, def_mac=? WHERE bot_id='landed'", args: [plan.generation, mac] });
    // lost: planned, never written.
    const planLost = planBotDefGeneration("lost");
    const rows = [await rowOf(s.db, "landed"), await rowOf(s.db, "lost")];
    const out = reconcileBotDefPending(rows, { abandon: true });
    assert.deepEqual(out.settled, ["landed"]);
    assert.deepEqual(out.abandoned, ["lost"]);
    const gens = readBotDefGenerations();
    assert.equal(gens.bots.landed.generation, before + 1);
    assert.equal(gens.bots.landed.pending, null);
    assert.equal(gens.bots.lost.pending, null);
    assert.equal(gens.bots.lost.planned, planLost.generation, "the high-water stays");
    // The abandoned generation can never verify again.
    const stash = { ...(await rowOf(s.db, "lost")), def_generation: planLost.generation };
    stash.def_mac = macBotDef(stash);
    assert.equal(verifyBotDefSync(stash, { converted: true }).ok, false);
    // A live reader (abandon: false) settles but never abandons.
    const p2 = planBotDefGeneration("lost");
    assert.deepEqual(reconcileBotDefPending(rows, { abandon: false }), { settled: [], abandoned: [] });
    assert.equal(readBotDefGenerations().bots.lost.pending, p2.generation);
  } finally { s.close(); }
});

test("M1: the converter's boot reconciles stale pending marks before the gateway listens", async () => {
  const s = scratch();
  try {
    await createBot(s.db, "crashed");
    await quiet(() => runBotDefMacBoot({ db: s.db }));
    const plan = planBotDefGeneration("crashed");
    assert.equal(readBotDefGenerations().bots.crashed.pending, plan.generation);
    await quiet(() => runBotDefMacBoot({ db: s.db }));
    assert.equal(readBotDefGenerations().bots.crashed.pending, null);
  } finally { s.close(); }
});

test("L2: a planted def_generation alone does not count as sealed on a conversion re-run", async () => {
  const s = scratch();
  try {
    await s.db.execute({ sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('early','E',?,1)", args: [JSON.stringify(DEF)] });
    await quiet(() => runBotDefMacBoot({ db: s.db }));
    await resetFamiliesForOperator([BOT_DEF_FAMILY]);
    await s.db.execute({ sql: "DELETE FROM dashboard_settings_overrides WHERE key=?", args: [botDefEraSettingKey()] });
    await s.db.execute({ sql: "DELETE FROM dashboard_settings WHERE key=?", args: [botDefEraSettingKey()] });
    rmSync(botDefEraStatePath(), { force: true });
    rmSync(botDefGenerationsPath(), { force: true }); // an honest "never converted" fixture: no host evidence left
    // The bot plants a generation and a junk MAC on the snapshot row.
    await s.db.execute({ sql: "UPDATE pi_bot_defs SET def_generation=7, def_mac='h1.0000000000000000.00' WHERE bot_id='early'" });
    const result = await quiet(() => runBotDefMacBoot({ db: s.db }));
    assert.equal(result.state, "converted");
    assert.equal(result.refused, 1, "refused, not counted as sealed");
    assert.equal(result.count, 0);
    assert.equal((await verifyBotDef(await rowOf(s.db, "early"), { db: s.db })).ok, false);
  } finally { s.close(); }
});

test("L3: non-JSON definition text cannot collide with a JSON string of the same characters", () => {
  const base = { bot_id: "b", enabled: 1, project_id: null, def_generation: 1 };
  assert.notEqual(canonicalBotDef({ ...base, definition: "x" }), canonicalBotDef({ ...base, definition: '"x"' }));
  assert.match(canonicalBotDef({ ...base, definition: "{not json" }), /definition_kind/);
  const raw = canonicalBotDef({ ...base, definition: "x" });
  const jsonStr = canonicalBotDef({ ...base, definition: '"x"' });
  const jsonObj = canonicalBotDef({ ...base, definition: '{"__raw":"x"}' });
  assert.equal(new Set([raw, jsonStr, jsonObj]).size, 3, "raw x, JSON x and JSON {__raw:x} are all distinct");
  assert.equal(
    canonicalBotDef({ ...base, definition: '{"a":1}' }),
    '{"bot_id":"b","definition":{"a":1},"enabled":1,"generation":1,"project_id":null}',
    "JSON rows keep their canonical form byte for byte",
  );
});

/** The tampered-unsealed-row fixture shared by the "converted evidence" tests. */
async function convertedEvidenceCase(s, removeEvidence) {
  await s.db.execute({
    sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('victim','V',?,1)",
    args: [JSON.stringify(DEF)],
  });
  const first = await quiet(() => runBotDefMacBoot({ db: s.db }));
  assert.equal(first.count, 1);
  removeEvidence();
  rmSync(botDefEraStatePath(), { force: true });
  await s.db.execute({ sql: "UPDATE pi_bot_defs SET definition=?, def_mac=NULL, def_generation=NULL", args: [JSON.stringify({ ...DEF, tools: { crow_mcp: ["*"] } })] });
  const warns = [];
  const realWarn = console.warn;
  console.warn = (m) => warns.push(String(m));
  let r;
  try { r = await runBotDefMacBoot({ db: s.db }); } finally { console.warn = realWarn; }
  assert.ok(warns.some((m) => m.includes("era state missing but this box converted before; not re-sealing")));
  assert.equal(r.state, "converted");
  assert.equal(readBotDefEraState().state, "converted", "the record is restored");
  const row = await rowOf(s.db, "victim");
  assert.equal(row.def_mac, null, "the tampered row was not sealed");
  assert.equal(row.def_generation, null);
  assert.deepEqual(verifyBotDefSync(row, { converted: botDefEraConvertedSync() }), { ok: false, reason: "no-mac" });
}

test("converted evidence: generations file + rollback snapshot, era file missing, unsealed tampered row -> no re-seal", async () => {
  const s = scratch();
  try {
    await convertedEvidenceCase(s, async () => {
      await resetFamiliesForOperator([BOT_DEF_FAMILY]); // marker gone; generations file + the converter's snapshot remain
    });
  } finally { s.close(); }
});

test("converted evidence: a generations file ALONE (no marker, no snapshot) converts for the first time", async () => {
  const s = scratch();
  try {
    await s.db.execute({
      sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('victim','V',?,1)",
      args: [JSON.stringify(DEF)],
    });
    const first = await quiet(() => runBotDefMacBoot({ db: s.db }));
    assert.equal(first.count, 1);
    await resetFamiliesForOperator([BOT_DEF_FAMILY]);
    rmSync(botDefEraStatePath(), { force: true });
    for (const n of readdirSync(join(s.home, "secrets"))) if (n.startsWith("bot-def-rollback-")) rmSync(join(s.home, "secrets", n), { force: true });
    assert.ok(Object.keys(readBotDefGenerations().bots || {}).length > 0, "fixture: generations file is non-empty");
    await s.db.execute({ sql: "UPDATE pi_bot_defs SET def_mac=NULL, def_generation=NULL" });
    const r = await quiet(() => runBotDefMacBoot({ db: s.db }));
    assert.equal(r.state, "converted");
    assert.equal(r.count, 1, "first-time conversion ran");
  } finally { s.close(); }
});

test("converted evidence: token-mac bot:def secrets marker present, era file missing, generations gone -> no re-seal", async () => {
  const s = scratch();
  try {
    await convertedEvidenceCase(s, () => {
      rmSync(botDefGenerationsPath(), { force: true }); // only the secrets-side marker remains
      for (const n of readdirSync(join(s.home, "secrets"))) if (n.startsWith("bot-def-rollback-")) rmSync(join(s.home, "secrets", n), { force: true });
    });
  } finally { s.close(); }
});

test("converted evidence: the DB mirror alone still converts for the first time", async () => {
  const s = scratch();
  try {
    await s.db.execute({
      sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('victim','V',?,1)",
      args: [JSON.stringify(DEF)],
    });
    ensureKey({ allowCreate: true, mirrorConverted: false, h1ValuesExist: false });
    await writeSetting(s.db, botDefEraSettingKey(), "1", { scope: "local" });
    const r = await quiet(() => runBotDefMacBoot({ db: s.db }));
    assert.equal(r.state, "converted");
    assert.equal(r.count, 1);
    assert.match(String((await rowOf(s.db, "victim")).def_mac), /^h1\./);
  } finally { s.close(); }
});

test("converted evidence: a fresh home converts for the first time", async () => {
  const s = scratch();
  try {
    await s.db.execute({
      sql: "INSERT INTO pi_bot_defs (bot_id, display_name, definition, enabled) VALUES ('victim','V',?,1)",
      args: [JSON.stringify(DEF)],
    });
    const r = await quiet(() => runBotDefMacBoot({ db: s.db }));
    assert.equal(r.count, 1);
    assert.match(String((await rowOf(s.db, "victim")).def_mac), /^h1\./);
  } finally { s.close(); }
});
