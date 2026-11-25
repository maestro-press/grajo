// A REPORT PICKUP runs in the CONTAINED tier only, and the endpoint its local-model floor judged is
// PINNED (S1 ruling).
//
// Why: a pickup's prompt carries text written by people outside this instance, so its kind carries the
// `local-only` model floor — and that floor reads a `providers` row from crow.db, which every contained
// bot has bound read-write. A bot can therefore flip the row between the floor's judgement and the
// dial. Contained spawns reach models only through this gateway's provider door, which reads the row AT
// REQUEST TIME, so the endpoint dialled would be the flipped one. Two rules close that:
//
//   1. the kind requires the contained tier (`requiresContained`), refused BEFORE anything is written
//      or spawned and again against the tier the launch really got (bridge.mjs), and
//   2. the floor's own row snapshot pins the endpoint: sha256 of the judged base URL rides the
//      generated models.json provider entry as a header, and the door refuses a request whose row no
//      longer hashes to it.
//
// This file pins all of it: the table, the uncontained refusal (nothing written, nothing spawned), the
// mail kind unchanged in both tiers, the snapshot/pin seam, the door's refusal of a flipped row, and
// the late belt. A contained SPAWN cannot run in the test runner's own sandbox (no bubblewrap) and the
// mail/pickup spawns here use the same stub-pi harness tests/locked-turn-kinds.test.js uses; the one
// test that needs the real contain tier is skipped with its reason printed, and the belt tests drive a
// launch through the test-only seam (`_setWrapPiSpawnForTest`, scripts/pi-bots/bridge.mjs) so a
// forced-tier launch is judged by the real belt.
import { test, describe, before, after } from "node:test";
import { signBotDef } from "../servers/shared/bot-def-store.js";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import express from "express";
import Database from "better-sqlite3";

const REPO = new URL("..", import.meta.url).pathname.replace(/\/$/, "");

// ---------------------------------------------------------------- scratch env
//
// Before ANY import of bridge.mjs / mcp_writer.mjs: mcp_writer captures `CANONICAL_MCP_PATH`
// (`HOME + "/.pi/agent/mcp.json"`) at module load, so a `process.env.HOME =` after a static import
// would always be too late.
for (const k of Object.keys(process.env)) if (/^(PI_|PIBOT_)/.test(k)) delete process.env[k];

const ROOT = mkdtempSync(join(tmpdir(), "locked-turn-contained-"));
const HOME_DIR = join(ROOT, "home");
mkdirSync(join(HOME_DIR, ".pi", "agent"), { recursive: true });
writeFileSync(join(HOME_DIR, ".pi", "agent", "mcp.json"), JSON.stringify({ mcpServers: {} }));
const ORIGINAL_HOME = process.env.HOME;
process.env.HOME = HOME_DIR;
process.env.CROW_HOME = join(ROOT, "crowhome");
process.env.CROW_DATA_DIR = join(ROOT, "data");
delete process.env.CROW_DB_PATH;
delete process.env.CROW_TASKS_DB_PATH;
delete process.env.CROW_BOT_ENV_PASSTHROUGH;
// The whole file runs UNCONTAINED unless a test says otherwise: that is the case the ruling refuses,
// and it is the only one this host can execute (a contained spawn needs bubblewrap + a PID namespace).
process.env.CROW_PI_SANDBOX = "off";
delete process.env.CROW_PI_CONTAIN_BOTS;
delete process.env.CROW_PI_CONTAIN_EXCLUDE;
process.env.PIBOT_MAX_PI = "99";
process.env.PIBOT_WARM_GATEWAY_URL = "http://127.0.0.1:1";
process.env.PIBOT_WARM_TIMEOUT_MS = "300";
process.env.PIBOT_PROMPT_ACK_TIMEOUT_MS = "8000";
process.env.PIBOT_TURN_TIMEOUT_MS = "5000";
process.env.PIBOT_MCP_CONFIG_DELIVERY = "fd";
process.env.PI_MODELS_JSON = join(ROOT, "models.json");
mkdirSync(process.env.CROW_HOME, { recursive: true });
mkdirSync(process.env.CROW_DATA_DIR, { recursive: true });
writeFileSync(process.env.PI_MODELS_JSON, JSON.stringify({
  providers: {
    stub: { models: [{ id: "m1" }] },
    cloudy: { models: [{ id: "m1" }] },
    publiclit: { models: [{ id: "m1" }] },
    // The one-hop / two-hop / door-URL rows section 4b judges. They are declared here so pi's model
    // catalog answers from this file (its fast path) instead of spawning `pi --list-models`: the only
    // pi process a test in this file should be able to observe is a TURN.
    "chain-first": { models: [{ id: "m1" }] },
    "chain-second": { models: [{ id: "m1" }] },
    "door-direct": { models: [{ id: "m1" }] },
  },
}));
process.on("exit", () => {
  try { rmSync(ROOT, { recursive: true, force: true }); } catch { /* gone */ }
  if (ORIGINAL_HOME === undefined) delete process.env.HOME; else process.env.HOME = ORIGINAL_HOME;
});

const CROW_DB = join(process.env.CROW_DATA_DIR, "crow.db");
const CROW_HOME = process.env.CROW_HOME;
const PICKUP_ID = "rpu-0000000000000d01";
const DRAFT_ID = "md-0000000000000d01";
const TURN_ID = "mt-0123456789abcdef";
const RPK = "rpk_" + "d".repeat(64);
const MDT = "mdt_" + "d".repeat(64);
const PICKUP_THREAD = "report-pickup:" + PICKUP_ID;
const MAIL_THREAD = "mail-draft:" + DRAFT_ID;
const PICKUP_DIR = join(CROW_HOME, "report-pickup-turns", "draftbot", PICKUP_ID);
const MAIL_DIR = join(CROW_HOME, "mail-draft-turns", "draftbot", DRAFT_ID);
const BOT_ROOT = join(ROOT, "bots", "draftbot");
/** The ONE sentence a kind-requiring-containment refusal throws, asserted by exact equality. */
const CONTAINED_REFUSAL = "lockedTurn refused: this kind runs only in the contained tier";

// ---------------------------------------------------------------- modules
const {
  LOCKED_TURN_KINDS, REPORT_PICKUP_TURN_TOOLS, DRAFTING_TURN_TOOLS,
  reportPickupBlock, mailDraftBlock, lockedTurnKindOf,
} = await import("../scripts/pi-bots/mcp_writer.mjs");
const {
  handleInbound, judgeLocalModelFloor, lockedTurnPin, pinSnapshotRows, PiRpc, _setWrapPiSpawnForTest,
} = await import("../scripts/pi-bots/bridge.mjs");
const { buildContainedAgentDir, pinOfBaseUrl, CONTAINED_PIN_HEADER } = await import("../scripts/pi-bots/pi_contain_agent.mjs");
const { probePiSandbox, _resetPiSandboxForTest } = await import("../scripts/pi-bots/pi_sandbox.mjs");
const { initGatewayActorKey } = await import("../scripts/pi-bots/actor-sig.mjs");
const llmRouterRouter = (await import("../servers/gateway/routes/llm-router.js")).default;
const { pinBaseValue, LOCKED_TURN_PIN_HEADER } = await import("../servers/gateway/routes/llm-router.js");
// #117's own predicate: the vouch + listener rule every own-host forward now goes through, defaulted
// into the door's `knownLocalTargetFn` seam and stubbed here with this file's own scratch home.
const { isKnownLocalModelTarget } = await import("../servers/gateway/models/local-model-servers.js");
// The consent entry's ONE builder (sealed-key fingerprint form, migration 0040): a fixture never
// hand-rolls that HMAC.
const { consentEntryFor } = await import("../servers/shared/cloud-consent.js");
// A same-uid listener in its own process — the squatter #117's listener half exists for.
const { spawnUntrustedListener } = await import("./fixtures/untrusted-listener.mjs");

_resetPiSandboxForTest();
/** Can this host spawn a REAL contained pi? A contained spawn needs bwrap with a PID namespace. */
const CONTAIN_TIER = (() => { const p = probePiSandbox({ force: true }); return p.ok === true && p.pidns === true; })();

// ---------------------------------------------------------------- fixtures

function botDef(overrides = {}) {
  return {
    system_prompt: "You answer inside one turn.",
    models: { default: "stub/m1" },
    tools: { pi_builtin: ["bash", "read", "write", "edit"], crow_mcp: ["gmail/gmail_search"] },
    permission_policy: { bash: "deny", write_paths: [], multi_agent: true },
    session_dir: BOT_ROOT,
    ...overrides,
  };
}

function seedBot(id, def) {
  // SIGNED, as Bot Builder stores it (servers/shared/bot-def-store.js `signBotDef`): the spawn gate
  // verifies the row's keyed MAC, and once any row in the store is sealed an unsealed one is refused.
  const seal = signBotDef({ bot_id: id, definition: JSON.stringify(def), enabled: 1, project_id: null });
  const c = new Database(CROW_DB);
  c.prepare("INSERT OR REPLACE INTO pi_bot_defs (bot_id, display_name, definition, enabled, project_id, def_mac, def_generation) VALUES (?,?,?,1,NULL,?,?)")
    .run(id, id, seal.definition, seal.def_mac, seal.generation);
  c.close();
}

function sessionRows(thread) {
  const c = new Database(CROW_DB);
  const n = c.prepare("SELECT COUNT(*) AS n FROM bot_sessions WHERE gateway_thread_id = ?").get(thread).n;
  c.close();
  return n;
}

function clearSessions(thread) {
  const c = new Database(CROW_DB);
  c.prepare("DELETE FROM bot_sessions WHERE gateway_thread_id = ?").run(thread);
  c.close();
}

function pickupOption({ botId = "draftbot", checkModel } = {}) {
  return {
    kind: "report-pickup",
    exactTools: [...REPORT_PICKUP_TURN_TOOLS],
    mcpBlock: reportPickupBlock({ botId, pickupId: PICKUP_ID, turnId: TURN_ID, token: RPK }),
    sessionDir: join(CROW_HOME, "report-pickup-turns", botId, PICKUP_ID),
    checkModel: checkModel === undefined ? () => ({ ok: true, local: true, key: "stub/m1" }) : checkModel,
  };
}

function mailOption() {
  return {
    exactTools: [...DRAFTING_TURN_TOOLS],
    mcpBlock: mailDraftBlock({ botId: "draftbot", draftId: DRAFT_ID, turnId: TURN_ID, token: MDT }),
    sessionDir: MAIL_DIR,
    checkModel: () => ({ ok: true, local: true, key: "stub/m1" }),
  };
}

function inbound({ gatewayType = "report-pickup", thread = PICKUP_THREAD, userMessage = "answer the comment" } = {}) {
  return { bot_id: "draftbot", gateway_type: gatewayType, gateway_thread_id: thread, user_message: userMessage, log: () => {}, sendReply: async () => {} };
}

async function refusalMessage(opts) {
  try {
    await handleInbound(opts);
  } catch (err) {
    return String(err.message);
  }
  assert.fail("expected the turn to be refused");
}

/** A protocol-speaking stub pi: records argv and the MCP config it was handed. */
function stubPiSource() {
  return [
    'import { readFileSync, writeFileSync } from "node:fs";',
    'const out = (o) => process.stdout.write(JSON.stringify(o) + "\\n");',
    'try { writeFileSync(process.env.PIBOT_TEST_ARGV, JSON.stringify(process.argv.slice(2))); } catch {}',
    'let cfg = null;',
    'try {',
    '  if (process.env.PI_BOT_MCP_CONFIG_FD) cfg = readFileSync(Number(process.env.PI_BOT_MCP_CONFIG_FD), "utf8");',
    '  else if (process.env.PI_BOT_MCP_CONFIG) cfg = readFileSync(process.env.PI_BOT_MCP_CONFIG, "utf8");',
    '} catch { cfg = null; }',
    'let buf = "";',
    'process.stdin.on("data", (chunk) => {',
    '  buf += chunk.toString("utf8");',
    '  let nl;',
    '  while ((nl = buf.indexOf("\\n")) >= 0) {',
    '    const line = buf.slice(0, nl); buf = buf.slice(nl + 1);',
    '    let m; try { m = JSON.parse(line); } catch { continue; }',
    '    if (m.type === "get_state") {',
    '      out({ type: "response", command: "get_state", data: { sessionId: "stub-session" } });',
    '    } else if (m.type === "get_session_stats") {',
    '      out({ type: "response", command: "get_session_stats", id: m.id, data: { tokens: { input: 1, output: 1, cacheRead: 0 } } });',
    '    } else if (m.type === "prompt") {',
    '      if (process.env.PIBOT_TEST_MCPCAP) { try { writeFileSync(process.env.PIBOT_TEST_MCPCAP, cfg == null ? "null" : cfg); } catch {} }',
    '      out({ type: "response", command: "prompt" });',
    '      out({ type: "agent_end", messages: [{ role: "assistant", content: [{ type: "text", text: "ok" }] }] });',
    '    } else if (m.type === "abort") {',
    '      out({ type: "response", command: "abort" });',
    '    }',
    '  }',
    '});',
    'process.stdin.resume();',
    "",
  ].join("\n");
}

let captureN = 0;
const CAPTURE_DIR = join(ROOT, "captures");
mkdirSync(CAPTURE_DIR, { recursive: true });
function capturePaths(tag = "turn") {
  const n = ++captureN;
  const paths = { argvPath: join(CAPTURE_DIR, `argv-${tag}-${n}.json`), mcpPath: join(CAPTURE_DIR, `mcp-${tag}-${n}.json`) };
  process.env.PIBOT_TEST_ARGV = paths.argvPath;
  process.env.PIBOT_TEST_MCPCAP = paths.mcpPath;
  return paths;
}

/* ---------------------------------------------------------------- the #117 vouch
 * An OWN-HOST model target counts as local only when Crow KNOWS it and OWNS the connection
 * (servers/gateway/models/local-model-servers.js): a port vouched from OUTSIDE crow.db — a
 * Docker/bundle publish, a live native reservation, an operator pin — and a listener that is not a
 * bot's. `buildContainedAgentDir` decides a row has a door with the SYNC half of that rule
 * (`isKnownLocalModelTargetCached`, pi_contain_agent.mjs `doorRow`) and takes no deps, so a fixture
 * vouches a port the way an operator does: an endpoint pin under THIS file's own
 * `<CROW_HOME>/secrets` (read fresh on every call, and nothing outside this scratch home is ever
 * consulted). The tests below judge the PIN and the door, never the vouch source.
 */
const VOUCH_EXE = join(ROOT, "vouched-llama-server");
function vouchPort({ address = "127.0.0.1", port = 8011 } = {}) {
  const dir = join(CROW_HOME, "secrets");
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  const path = join(dir, "local-model-endpoints.json");
  const entries = existsSync(path) ? JSON.parse(readFileSync(path, "utf8")) : [];
  if (!entries.some((e) => e && e.address === address && Number(e.port) === port)) {
    entries.push({ address, port, exe: VOUCH_EXE });
  }
  writeFileSync(path, JSON.stringify(entries), { mode: 0o600 });
  return path;
}

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: process.env.CROW_DATA_DIR }, stdio: "pipe", cwd: REPO,
  });
  const c = new Database(CROW_DB);
  const insert = c.prepare("INSERT OR REPLACE INTO providers (id, base_url, api_key, host, models, disabled) VALUES (?,?,?,?,?,0)");
  insert.run("stub", "http://127.0.0.1:8003/v1", "none", "local", JSON.stringify([{ id: "m1" }]));
  insert.run("cloudy", "https://api.example.test/v1", "none", "cloud", JSON.stringify([{ id: "m1" }]));
  insert.run("publiclit", "http://8.8.8.8:8004/v1", "none", "local", JSON.stringify([{ id: "m1" }]));
  c.close();
  seedBot("draftbot", botDef());
  seedBot("otherbot", botDef({ session_dir: join(ROOT, "bots", "otherbot") }));
  initGatewayActorKey();
  const stub = join(ROOT, "stub-pi.mjs");
  writeFileSync(stub, stubPiSource());
  process.env.PIBOT_PI_CLI = stub;
});

after(() => { clearSessions(PICKUP_THREAD); clearSessions(MAIL_THREAD); });

/* ============================================================ 1. the table */

test("report-pickup requires the contained tier; mail-draft does not; both rows stay frozen data", () => {
  assert.ok(Object.isFrozen(LOCKED_TURN_KINDS), "the table itself cannot be edited at runtime");
  const pickup = LOCKED_TURN_KINDS["report-pickup"];
  const mail = LOCKED_TURN_KINDS["mail-draft"];
  assert.ok(Object.isFrozen(pickup) && Object.isFrozen(mail), "each row is frozen");
  assert.equal(pickup.requiresContained, true, "a pickup runs only in the contained tier");
  assert.equal(mail.requiresContained, false, "mail is explicit: the tier is the operator's business");
  assert.equal(typeof pickup.requiresContained, "boolean", "a value, never a function");
  assert.equal(typeof mail.requiresContained, "boolean");
  assert.equal(pickup.refusals.contained, "this kind runs only in the contained tier",
    "the sentence the bridge throws, carried by the row itself");
  assert.equal(Object.hasOwn(mail.refusals, "contained"), false, "mail has no contained-tier refusal at all");
  assert.equal(pickup.refusalLabel + " refused: " + pickup.refusals.contained, CONTAINED_REFUSAL);
  // The floor and the tier travel together: a kind cannot require containment without a floor to
  // justify it, and it cannot carry a floor without the pin that keeps it true at dial time.
  assert.equal(pickup.modelFloor, "local-only");
  assert.equal(mail.modelFloor, null);
  assert.equal(lockedTurnKindOf("report-pickup").requiresContained, true);
});

/* ============================================================ 2. the uncontained refusal */

describe("an uncontained pickup is refused before anything is written or spawned", () => {
  test("CROW_PI_SANDBOX=off: the fixed sentence, no spawn, no world, no session row", async () => {
    clearSessions(PICKUP_THREAD);
    rmSync(PICKUP_DIR, { recursive: true, force: true });
    const botConfig = join(BOT_ROOT, ".mcp.json");
    rmSync(botConfig, { force: true });
    const paths = capturePaths("pickup-refused");
    assert.equal(process.env.CROW_PI_SANDBOX, "off");

    const message = await refusalMessage({ ...inbound(), lockedTurn: pickupOption() });
    assert.equal(message, CONTAINED_REFUSAL);
    assert.equal(existsSync(paths.argvPath), false, "nothing was spawned");
    assert.equal(existsSync(paths.mcpPath), false);
    assert.equal(existsSync(PICKUP_DIR), false, "the turn's own world root was never created");
    assert.equal(existsSync(botConfig), false, "buildBotWorld never wrote the bot's config");
    assert.equal(sessionRows(PICKUP_THREAD), 0, "no session row was stamped");
  });

  test("a sandbox mode the bot is NOT selected for refuses it just the same", async () => {
    clearSessions(PICKUP_THREAD);
    const saved = { mode: process.env.CROW_PI_SANDBOX, bots: process.env.CROW_PI_CONTAIN_BOTS };
    try {
      // The same expression PiRpc decides containment with: a mode that is not "off" AND this bot
      // selected. A mode that names a DIFFERENT bot is not containment for this turn.
      process.env.CROW_PI_SANDBOX = "auto";
      process.env.CROW_PI_CONTAIN_BOTS = "otherbot";
      const paths = capturePaths("pickup-unselected");
      assert.equal(await refusalMessage({ ...inbound(), lockedTurn: pickupOption() }), CONTAINED_REFUSAL);
      assert.equal(existsSync(paths.argvPath), false);

      // Selected, then exempted: an exemption wins over the selector, so the turn is refused too.
      process.env.CROW_PI_CONTAIN_BOTS = "draftbot";
      process.env.CROW_PI_CONTAIN_EXCLUDE = "draftbot";
      const paths2 = capturePaths("pickup-excluded");
      assert.equal(await refusalMessage({ ...inbound(), lockedTurn: pickupOption() }), CONTAINED_REFUSAL);
      assert.equal(existsSync(paths2.argvPath), false);
    } finally {
      if (saved.mode === undefined) delete process.env.CROW_PI_SANDBOX; else process.env.CROW_PI_SANDBOX = saved.mode;
      if (saved.bots === undefined) delete process.env.CROW_PI_CONTAIN_BOTS; else process.env.CROW_PI_CONTAIN_BOTS = saved.bots;
      delete process.env.CROW_PI_CONTAIN_EXCLUDE;
      clearSessions(PICKUP_THREAD);
    }
  });

  test("the refusal comes before the model gate: the caller's checkModel is never consulted", async () => {
    clearSessions(PICKUP_THREAD);
    let checkCalls = 0;
    const message = await refusalMessage({
      ...inbound(),
      lockedTurn: pickupOption({ checkModel: () => { checkCalls += 1; return { ok: true, local: true, key: "stub/m1" }; } }),
    });
    assert.equal(message, CONTAINED_REFUSAL);
    assert.equal(checkCalls, 0, "nothing about the model was even asked");
    assert.equal(sessionRows(PICKUP_THREAD), 0);
  });
});

/* ============================================================ 3. mail is untouched */

describe("the mail kind is unaffected in both tiers", () => {
  test("an uncontained mail turn still runs, with its own tools and its own world root", async () => {
    clearSessions(MAIL_THREAD);
    rmSync(MAIL_DIR, { recursive: true, force: true });
    const paths = capturePaths("mail-uncontained");
    const result = await handleInbound({ ...inbound({ gatewayType: "mail-draft", thread: MAIL_THREAD, userMessage: "draft it" }), draftingTurn: mailOption() });
    assert.notEqual(result.action, "error", "the mail kind carries no tier requirement");
    const argv = JSON.parse(readFileSync(paths.argvPath, "utf8"));
    const at = argv.indexOf("--tools");
    assert.equal(argv[at + 1], [
      "mcp__crow-mail-draft__mail_draft_propose",
      "mcp__crow-mail-draft__mail_draft_read_context",
      "mcp__crow-mail-draft__mail_draft_read_thread",
    ].join(","), "still the drafting turn's own three tools");
    assert.ok(argv.includes(join(MAIL_DIR, "sessions")), "still its own session dir");
    const config = JSON.parse(readFileSync(paths.mcpPath, "utf8"));
    const enabled = Object.entries(config.mcpServers).filter(([, b]) => !(b && b.disabled === true)).map(([n]) => n);
    assert.deepEqual(enabled, ["crow-mail-draft"]);
    clearSessions(MAIL_THREAD);
  });

  test("containment selected for the bot: a mail turn is never refused by the kind rule", { skip: CONTAIN_TIER ? "this host HAS the contain tier, so this case (what a host WITHOUT one does) cannot be the assertion here" : false }, async () => {
    // This case needs the contain tier to be MISSING (the runner's own sandbox): with the bot selected
    // for containment and no bubblewrap the spawn dies in the contain request ("bubblewrap is
    // unavailable") — a host fault, and proof the turn got PAST the kind's tier rule, which is exactly
    // what "unchanged in both tiers" means. Where a real contain tier exists the spawn would instead
    // run, and this file does not attempt that (its stub pi writes captures to a host path).
    const saved = { mode: process.env.CROW_PI_SANDBOX, bots: process.env.CROW_PI_CONTAIN_BOTS };
    try {
      process.env.CROW_PI_SANDBOX = "contain";
      process.env.CROW_PI_CONTAIN_BOTS = "draftbot";
      const paths = capturePaths("mail-contain-request");
      await assert.rejects(
        handleInbound({ ...inbound({ gatewayType: "mail-draft", thread: MAIL_THREAD, userMessage: "draft it" }), draftingTurn: mailOption() }),
        (err) => /bubblewrap is unavailable|pid namespace|cannot make a PID namespace/i.test(String(err.message)),
        "the mail turn reaches the contain spawn: it is not refused by any locked-turn rule",
      );
      assert.equal(existsSync(paths.argvPath), false, "and nothing was spawned");
    } finally {
      if (saved.mode === undefined) delete process.env.CROW_PI_SANDBOX; else process.env.CROW_PI_SANDBOX = saved.mode;
      if (saved.bots === undefined) delete process.env.CROW_PI_CONTAIN_BOTS; else process.env.CROW_PI_CONTAIN_BOTS = saved.bots;
      clearSessions(MAIL_THREAD);
    }
  });
});

/* ============================================================ 4. the floor's snapshot and the pin */

const ROW = (over = {}) => ({
  id: "pickup-local", baseUrl: "http://127.0.0.1:8011/v1", apiKey: "none", host: "local", bundleId: "vllm-pickup",
  provider_type: "openai-compat", models: [{ id: "m1" }], gpuPolicy: null, disabled: false, ...over,
});

describe("the floor returns the rows it judged, and the pin comes from exactly those rows", () => {
  test("judgeLocalModelFloor: local only on a proven row, and always the snapshot it read", () => {
    const rows = [ROW(), ROW({ id: "cloud", baseUrl: "https://api.example.com/v1", host: "cloud", bundleId: null })];
    const local = judgeLocalModelFloor("pickup-local/m1", { rows });
    assert.equal(local.local, true);
    assert.equal(local.rows, rows, "the SAME snapshot is returned, never a re-read");
    // A stored cloud row, a public IP literal and a row that is not there are all refused.
    assert.equal(judgeLocalModelFloor("cloud/m1", { rows }).local, false);
    assert.equal(judgeLocalModelFloor("pickup-local/m1", { rows: [ROW({ baseUrl: "http://8.8.8.8:8011/v1" })] }).local, false);
    assert.equal(judgeLocalModelFloor("nowhere/m1", { rows }).local, false);
    assert.equal(judgeLocalModelFloor("role:everyday", { rows }).local, false);
    // A row whose base URL LOOKS local while the store says the model runs elsewhere is refused too.
    assert.equal(judgeLocalModelFloor("pickup-local/m1", { rows: [ROW({ host: "cloud" })] }).local, false);
  });

  test("lockedTurnPin names the judged provider and base URL, or nothing at all", () => {
    const rows = [ROW(), ROW({ id: "other", baseUrl: "http://192.168.1.9:8012/v1" })];
    const pin = lockedTurnPin(rows, "pickup-local/m1");
    assert.equal(pin.providerId, "pickup-local");
    assert.equal(pin.baseUrl, "http://127.0.0.1:8011/v1");
    assert.equal(pin.pinBase, pinOfBaseUrl("http://127.0.0.1:8011/v1"));
    assert.equal(pin.rows, rows, "the snapshot travels with the pin");
    // Trailing slashes are the same endpoint to the door, so they are the same pin.
    assert.equal(lockedTurnPin([ROW({ baseUrl: "http://127.0.0.1:8011/v1///" })], "pickup-local/m1").pinBase, pin.pinBase);
    // A key with no row (or no model part) has no pin: the caller fails closed rather than run unpinned.
    assert.equal(lockedTurnPin(rows, "nowhere/m1"), null);
    assert.equal(lockedTurnPin(rows, "pickup-local"), null);
    assert.equal(lockedTurnPin(rows, ""), null);
    assert.equal(lockedTurnPin(null, "pickup-local/m1"), null);
  });

  test("pinSnapshotRows marks ONLY the judged row", () => {
    const rows = [ROW(), ROW({ id: "other", baseUrl: "http://192.168.1.9:8012/v1" })];
    const pin = lockedTurnPin(rows, "pickup-local/m1");
    const marked = pinSnapshotRows(pin);
    assert.equal(marked.length, 2);
    assert.equal(marked[0].pinBase, pin.pinBase, "the judged row carries the pin");
    assert.equal(marked[1].pinBase, undefined, "no other row is ever pinned");
    assert.equal(rows[0].pinBase, undefined, "and the snapshot itself is not mutated");
  });

  test("the pin reaches the generated models.json as that entry's header, and nothing else", () => {
    // #117: the row's own endpoint must be a model server Crow knows (a pin, here) or the door row
    // has no door — that decision is not what this test judges.
    vouchPort({ port: 8011 });
    const rows = [ROW(), ROW({ id: "other", baseUrl: "http://192.168.1.9:8012/v1" })];
    const pin = lockedTurnPin(rows, "pickup-local/m1");
    const dir = join(ROOT, "agent-pinned");
    const res = buildContainedAgentDir({
      piAgentDir: join(HOME_DIR, ".pi", "agent"), dir, providerIds: ["pickup-local", "other"],
      rows: pinSnapshotRows(pin), gatewayPort: 3199, cloudTokenPath: null,
    });
    assert.deepEqual(res.missing, []);
    const models = JSON.parse(readFileSync(join(dir, "models.json"), "utf8"));
    const pinnedEntry = models.providers["pickup-local"];
    assert.match(pinnedEntry.baseUrl, /^http:\/\/127\.0\.0\.1:3199\/llm\/p\/pickup-local\/v1$/);
    assert.deepEqual(pinnedEntry.headers, { [CONTAINED_PIN_HEADER]: pin.pinBase }, "the judged endpoint rides the entry");
    assert.equal(models.providers.other.headers, undefined, "an unpinned provider entry is unchanged");
    assert.ok(!JSON.stringify(models).includes("127.0.0.1:8011"), "the endpoint itself never lands in the file");
    // An UNPINNED spawn (every other bot) is byte-identical to before: no headers key anywhere.
    const plainDir = join(ROOT, "agent-plain");
    buildContainedAgentDir({
      piAgentDir: join(HOME_DIR, ".pi", "agent"), dir: plainDir, providerIds: ["pickup-local"],
      rows: [ROW()], gatewayPort: 3199, cloudTokenPath: null,
    });
    const plain = JSON.parse(readFileSync(join(plainDir, "models.json"), "utf8"));
    assert.equal(plain.providers["pickup-local"].headers, undefined);
  });

  test("a pinned row with no pinned door fails the spawn closed instead of running unpinned", async () => {
    // The cloud door does not check a pin, so a pinned row that only resolves to the consented /llm/c
    // entry cannot carry one: it is reported as missing, and wrapPiSpawn refuses the spawn (never a
    // silent unpinned run). A consented cloud row is the one shape that reaches a door WITHOUT /llm/p.
    const tokenPath = join(ROOT, "llm-cloud-token");
    writeFileSync(tokenPath, "cloud-door-token", { mode: 0o600 });
    const key = "sk-pickup-cloud";
    const salt = "e".repeat(64);
    const baseUrl = "https://api.example.test/v1";
    const cloud = ROW({ id: "pickup-cloud", baseUrl, apiKey: key, host: "cloud", bundleId: null });
    const cloudPinned = { ...cloud, pinBase: "a".repeat(64) };
    // The ONE consent-entry builder (shared/cloud-consent.js): since migration 0040 the fingerprint is
    // HMAC(salt, "fp1:" + fp16) over the trimmed key, so a hand-rolled HMAC(salt, key) — the pre-seal
    // form — reads as "key_changed" and the row would quietly get no cloud door at all.
    const consent = { "pickup-cloud": consentEntryFor(cloud, salt, "operator") };
    assert.equal(typeof consent["pickup-cloud"].keyFp, "string");
    assert.equal(consent["pickup-cloud"].keyFp.length, 16, "the entry carries the sealed-key fingerprint form");
    // The control first: the same row WITHOUT a pin generates its consented cloud-door entry.
    const plain = buildContainedAgentDir({
      piAgentDir: join(HOME_DIR, ".pi", "agent"), dir: join(ROOT, "agent-cloud-plain"), providerIds: ["crow-c-pickup-cloud"],
      rows: [cloud], consent, consentSalt: salt, gatewayPort: 3199, cloudTokenPath: tokenPath,
    });
    assert.deepEqual(plain.missing, [], "the fixture really does produce a cloud-door entry");
    const res = buildContainedAgentDir({
      piAgentDir: join(HOME_DIR, ".pi", "agent"), dir: join(ROOT, "agent-cloud-pin"), providerIds: ["crow-c-pickup-cloud"],
      rows: [cloudPinned], consent, consentSalt: salt, gatewayPort: 3199, cloudTokenPath: tokenPath,
    });
    assert.deepEqual(res.missing, [{ provider: "pickup-cloud", reason: "provider pickup-cloud has no pinned door" }]);
  });
});

/* ============================================================ 4b. a pin fits ONE hop only */

// The pin holds ONE endpoint still: the door dials the judged row's base URL. A row whose base URL is
// ITSELF a door (`…/llm/p/<id>/v1`, or a bare `…/llm/v1`) leaves every hop behind that URL decided per
// request, so a pin on it would match the first hop while the traffic walked on somewhere the floor
// never judged. Both shapes are refused, and a pickup turn on either fails closed at the existing pin
// refusal. Mail has no pin at all (it does not require containment), so a mail turn on the very same
// row still runs — the refusal belongs to the pickup kind, not to the row.
const DOOR_PICKUP = "rpu-0000000000000d02";
const DOOR_PICKUP_THREAD = "report-pickup:" + DOOR_PICKUP;
const DOOR_MAIL_THREAD = "mail-draft:md-0000000000000d02";

/** The exact sentence a turn with no pinnable endpoint throws. */
const PIN_REFUSAL = LOCKED_TURN_KINDS["report-pickup"].refusalLabel + " refused: " + LOCKED_TURN_KINDS["report-pickup"].refusals.pin;

/** The rows this section judges, exactly as the floor's snapshot would carry them. */
const CHAIN_ROWS = () => [
  // Row A is itself a DOOR: another gateway's /llm/p/chain-second/v1 door, upstream row B.
  ROW({ id: "chain-first", baseUrl: "http://127.0.0.1:8010/llm/p/chain-second/v1", bundleId: "vllm-chain" }),
  // Row B: the direct server at the end of that chain.
  ROW({ id: "chain-second", baseUrl: "http://127.0.0.1:8006/v1", bundleId: "vllm-chain2" }),
];
/** One row that IS a door URL, with no upstream row in the snapshot (a door nobody can resolve). */
const DOOR_ONLY_ROWS = () => [ROW({ id: "door-direct", baseUrl: "http://127.0.0.1:8009/llm/v1", bundleId: null })];

describe("a pin fits one hop to a direct server, so a door in the chain is refused", () => {
  before(() => {
    const c = new Database(CROW_DB);
    const insert = c.prepare("INSERT OR REPLACE INTO providers (id, base_url, api_key, host, models, bundle_id, disabled) VALUES (?,?,?,?,?,?,0)");
    for (const row of [...CHAIN_ROWS(), ...DOOR_ONLY_ROWS()]) {
      insert.run(row.id, row.baseUrl, "none", "local", JSON.stringify([{ id: "m1" }]), row.bundleId || null);
    }
    c.close();
    seedBot("chainbot", botDef({ models: { default: "chain-first/m1" }, session_dir: join(ROOT, "bots", "chainbot") }));
    seedBot("doorbot", botDef({ models: { default: "door-direct/m1" }, session_dir: join(ROOT, "bots", "doorbot") }));
  });

  /** One pickup turn's option for a bot of this section: the kind's own tool set and block. */
  function doorPickupOption(botId) {
    return {
      kind: "report-pickup",
      exactTools: [...REPORT_PICKUP_TURN_TOOLS],
      mcpBlock: reportPickupBlock({ botId, pickupId: DOOR_PICKUP, turnId: TURN_ID, token: RPK }),
      sessionDir: join(CROW_HOME, "report-pickup-turns", botId, DOOR_PICKUP),
      checkModel: () => ({ ok: true, local: true, key: "stub/m1" }),
    };
  }

  /**
   * Run `run` with the containment selection the kind's early rule reads, so the turn gets PAST it and
   * reaches the pin. Nothing else is forced: a refused pin throws before any launch is built, which is
   * what makes "nothing was spawned" an assertion about the pin rather than about the contain tier.
   */
  async function inContainSelection(botId, run) {
    const saved = { mode: process.env.CROW_PI_SANDBOX, bots: process.env.CROW_PI_CONTAIN_BOTS };
    process.env.CROW_PI_SANDBOX = "contain";
    process.env.CROW_PI_CONTAIN_BOTS = botId;
    try { return await run(); } finally {
      if (saved.mode === undefined) delete process.env.CROW_PI_SANDBOX; else process.env.CROW_PI_SANDBOX = saved.mode;
      if (saved.bots === undefined) delete process.env.CROW_PI_CONTAIN_BOTS; else process.env.CROW_PI_CONTAIN_BOTS = saved.bots;
    }
  }

  test("a two-hop chain is local all the way down, and still has no pin", () => {
    const rows = CHAIN_ROWS();
    assert.equal(judgeLocalModelFloor("chain-first/m1", { rows }).local, true,
      "both rows are loopback: the floor admits the chain");
    assert.equal(lockedTurnPin(rows, "chain-first/m1"), null,
      "a pin names one endpoint; a second hop behind it would go unpinned");
    // The direct row at the end of the chain is still pinnable: the refusal is the CHAIN's, not the row's.
    assert.ok(lockedTurnPin(rows, "chain-second/m1"), "a one-hop direct-server row still pins");
  });

  test("a pickup turn on the two-hop chain fails closed at the pin, and nothing is spawned", async () => {
    clearSessions(DOOR_PICKUP_THREAD);
    const paths = capturePaths("chain-two-hop");
    const message = await inContainSelection("chainbot", () => refusalMessage({
      ...inbound({ thread: DOOR_PICKUP_THREAD }), bot_id: "chainbot", lockedTurn: doorPickupOption("chainbot"),
    }));
    assert.equal(message, PIN_REFUSAL);
    assert.equal(existsSync(paths.argvPath), false, "nothing was spawned");
    assert.equal(sessionRows(DOOR_PICKUP_THREAD), 0, "no session row was stamped");
  });

  test("a ONE-row door URL whose upstream is not in the snapshot has no pin either", () => {
    const rows = DOOR_ONLY_ROWS();
    // The walk visits this one row (an unmanaged door resolves to itself), which is exactly why the
    // decision is made on the URL: a one-row chain alone does not prove a direct server.
    assert.equal(judgeLocalModelFloor("door-direct/m1", { rows }).local, true,
      "the floor sees a loopback row; nothing in the chain tells it the URL is a door");
    assert.equal(lockedTurnPin(rows, "door-direct/m1"), null, "a door URL is never pinned");
  });

  test("a pickup turn on that door row is refused the same way, and nothing is spawned", async () => {
    clearSessions(DOOR_PICKUP_THREAD);
    const paths = capturePaths("door-one-row");
    const message = await inContainSelection("doorbot", () => refusalMessage({
      ...inbound({ thread: DOOR_PICKUP_THREAD }), bot_id: "doorbot", lockedTurn: doorPickupOption("doorbot"),
    }));
    assert.equal(message, PIN_REFUSAL);
    assert.equal(existsSync(paths.argvPath), false, "nothing was spawned");
    assert.equal(sessionRows(DOOR_PICKUP_THREAD), 0, "no session row was stamped");
  });

  test("mail-draft on the SAME door-URL row still runs: it carries no pin", async () => {
    clearSessions(DOOR_MAIL_THREAD);
    const paths = capturePaths("mail-door-row");
    const result = await handleInbound({
      ...inbound({ gatewayType: "mail-draft", thread: DOOR_MAIL_THREAD, userMessage: "draft it" }),
      bot_id: "doorbot",
      draftingTurn: {
        exactTools: [...DRAFTING_TURN_TOOLS],
        mcpBlock: mailDraftBlock({ botId: "doorbot", draftId: "md-0000000000000d02", turnId: TURN_ID, token: MDT }),
        sessionDir: join(CROW_HOME, "mail-draft-turns", "doorbot", "md-0000000000000d02"),
        checkModel: () => ({ ok: true, local: true, key: "door-direct/m1" }),
      },
    });
    assert.notEqual(result.action, "error", "mail has no pin to lose, so this row is no reason to refuse it");
    const argv = JSON.parse(readFileSync(paths.argvPath, "utf8"));
    const at = argv.indexOf("--tools");
    assert.deepEqual(String(argv[at + 1]).split(",").sort(), [...DRAFTING_TURN_TOOLS].sort(),
      "it ran as the drafting turn it is");
    clearSessions(DOOR_MAIL_THREAD);
  });
});

/* ============================================================ 5. THE FLIP, at the door */

describe("THE FLIP: the row is re-pointed between the judgement and the dial", () => {
  let up, upUrl, seen, srv, appUrl, providers;

  before(async () => {
    up = http.createServer((req, res) => {
      let raw = "";
      req.on("data", (c) => { raw += c; });
      req.on("end", () => {
        seen.push({ path: req.url, headers: req.headers, body: raw ? JSON.parse(raw) : null });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ ok: true }));
      });
    });
    await new Promise((r) => up.listen(0, "127.0.0.1", r));
    upUrl = `http://127.0.0.1:${up.address().port}/v1`;
    // The instance's providers map, exactly as the door reads it at request time.
    providers = {
      pickup: { baseUrl: upUrl, apiKey: "none", models: [{ id: "m1" }], gpuPolicy: { door_forward: true } },
    };
    const router = llmRouterRouter({
      acquireFn: async () => true,
      resolveKeyFn: async (key) => ({ baseUrl: upUrl, model: key.split("/")[1], apiKey: null }),
      probeReadyFn: async () => true,
      warmFn: async () => true,
      loadProvidersFn: () => ({ providers }),
      remoteAddressFn: () => "127.0.0.1",
      doorAuthFn: async () => false,
      // #117: an own-host target is "local" only when a source outside crow.db vouches its port AND
      // a trusted process holds the socket. THIS section judges the PIN, not the vouch, so the door is
      // handed the vouched answer for the fixture's own endpoint through #117's own seam (the same
      // `knownLocalTargetFn` local-model-allowlist.test.js stubs); section 5b below drives the real
      // predicate for the vouch and the listener instead.
      knownLocalTargetFn: async () => ({ local: true, reason: "vouched", address: "127.0.0.1" }),
    });
    const app = express();
    app.use(router);
    srv = http.createServer(app);
    await new Promise((r) => srv.listen(0, "127.0.0.1", r));
    appUrl = `http://127.0.0.1:${srv.address().port}`;
  });

  after(() => { srv?.close(); up?.close(); });

  const post = (path, body, headers = {}) => {
    seen = [];
    return fetch(`${appUrl}${path}`, { method: "POST", headers: { "content-type": "application/json", ...headers }, body: JSON.stringify(body) });
  };
  const chat = { model: "m1", messages: [{ role: "user", content: "hi" }] };

  test("the judged row forwards, with the pin", async () => {
    const judged = "http://127.0.0.1:8011/v1";
    const pin = lockedTurnPin([ROW({ id: "pickup", baseUrl: judged })], "pickup/m1");
    providers.pickup.baseUrl = judged;
    const r = await post("/llm/p/pickup/v1/chat/completions", chat, { [LOCKED_TURN_PIN_HEADER]: pin.pinBase });
    // The judged endpoint is 127.0.0.1:8011 (nothing listens there): the point here is only that the
    // door accepted the pin and tried to dial, not that the dial worked.
    assert.notEqual(r.status, 409, "a matching pin is never refused");
    assert.equal(r.status, 502, "the judged endpoint is not listening in this fixture");
  });

  test("a flipped row with the pin is refused, and nothing is dialled", async () => {
    const judged = "http://127.0.0.1:8011/v1";
    const pin = lockedTurnPin([ROW({ id: "pickup", baseUrl: judged })], "pickup/m1");
    // THE FLIP: another local-class address (a different box on the LAN), which no address rule
    // refuses — the pin is the only thing that catches it.
    providers.pickup.baseUrl = "http://192.168.1.77:8011/v1";
    const r = await post("/llm/p/pickup/v1/chat/completions", chat, { [LOCKED_TURN_PIN_HEADER]: pin.pinBase });
    assert.equal(r.status, 409);
    const body = await r.json();
    assert.equal(body.error.code, "LOCKED_TURN_PIN_MISMATCH");
    assert.equal(seen.length, 0, "the flipped endpoint was never dialled");

    // THE CONTROL, same flipped row, no pin header: today's behaviour for every other caller.
    const plain = await post("/llm/p/pickup/v1/chat/completions", chat);
    assert.notEqual(plain.status, 409, "a request with no pin keeps the door's old behaviour");
  });

  test("a pin that is not a hash of the endpoint is refused too (fail closed, no forward)", async () => {
    providers.pickup.baseUrl = upUrl;
    // An unknown value, another endpoint's pin, and an empty value: a request that carries the header
    // at all must match. Only a request with NO header keeps the old path (the control above).
    for (const value of ["", "nonsense", pinOfBaseUrl("http://192.168.1.9:1/v1")]) {
      const r = await post("/llm/p/pickup/v1/chat/completions", chat, { [LOCKED_TURN_PIN_HEADER]: value });
      assert.equal(r.status, 409, JSON.stringify(value));
      assert.equal(seen.length, 0, "nothing was dialled for " + JSON.stringify(value));
    }
    // The matching pin on the SAME endpoint forwards (the door is not simply refusing every pinned
    // request): the fixture's upstream answers 200.
    const ok = await post("/llm/p/pickup/v1/chat/completions", chat, { [LOCKED_TURN_PIN_HEADER]: pinBaseValue(upUrl) });
    assert.equal(ok.status, 200);
    assert.equal(seen.length, 1, "the endpoint that WAS judged is the one dialled");
  });

  test("the door and the writer hash the same string", () => {
    for (const url of ["http://127.0.0.1:8011/v1", "http://127.0.0.1:8011/v1/", "http://192.168.1.9:8011/v1///", "http://box.example.ts.net:8011/v1"]) {
      assert.equal(pinBaseValue(url), pinOfBaseUrl(url), url);
    }
    assert.equal(pinBaseValue("http://h:1/v1/"), pinBaseValue("http://h:1/v1"), "trailing slashes are the same endpoint");
    assert.notEqual(pinBaseValue("http://h:1/v1"), pinBaseValue("http://h:2/v1"), "another port is another endpoint");
  });
});

/* ============================================================ 5b. #117: the vouch and the socket */

// A PIN is not a substitute for #117's own rule. A locked turn's pin says "the endpoint my floor
// judged is still the endpoint this row names" — nothing about WHO is listening there, or whether
// Crow ever knew the port. So a PINNED request still goes through the own-host vouch, and is refused
// exactly as any other own-host forward is (the door's NOT_FORWARDABLE, one `[door] own-host target`
// line naming the reason) when the port nothing vouches ("not-vouched") or the process holding it is
// not Crow's ("listener-not-trusted").
describe("#117: a pinned pickup request still has to reach a model server Crow knows and owns", () => {
  // A home that vouches NOTHING: no pin file, no bundles, no native reservations, no Docker snapshot.
  const EMPTY_HOME = join(ROOT, "crow-home-no-vouch");
  mkdirSync(EMPTY_HOME, { recursive: true });

  /** The door on one own-host fixture: `known` is the predicate half, `vouchDeps` the socket half. */
  async function doorFor({ known, vouchDeps, baseUrl, logs }) {
    const providers = { pickup: { baseUrl, apiKey: "none", models: [{ id: "m1" }], gpuPolicy: { door_forward: true } } };
    const router = llmRouterRouter({
      acquireFn: async () => true,
      resolveKeyFn: async (key) => ({ baseUrl, model: key.split("/")[1], apiKey: null }),
      probeReadyFn: async () => true,
      warmFn: async () => true,
      loadProvidersFn: () => ({ providers }),
      remoteAddressFn: () => "127.0.0.1",
      doorAuthFn: async () => false,
      knownLocalTargetFn: known,
      vouchDeps,
      logFn: (line) => logs.push(line),
    });
    const app = express();
    app.use(router);
    const srv = http.createServer(app);
    await new Promise((r) => srv.listen(0, "127.0.0.1", r));
    return {
      appUrl: `http://127.0.0.1:${srv.address().port}`,
      close: () => new Promise((r) => { try { srv.closeAllConnections?.(); } catch { /* gone */ } srv.close(() => r()); }),
    };
  }

  /** A PINNED chat request to the pickup door, the shape a locked turn's generated models.json sends. */
  function pinnedChat(appUrl, baseUrl) {
    return fetch(`${appUrl}/llm/p/pickup/v1/chat/completions`, {
      method: "POST",
      headers: { "content-type": "application/json", [LOCKED_TURN_PIN_HEADER]: pinBaseValue(baseUrl) },
      body: JSON.stringify({ model: "m1", messages: [{ role: "user", content: "a comment" }] }),
    });
  }

  test("(a) a PINNED request to an own-host listener nothing vouches for is refused as not-vouched", async () => {
    // The listener is a real HTTP server in its OWN process of the same uid — the squatter shape #117
    // exists for — and NOTHING vouches its port, so the reason the door gives must be the VOUCH.
    const bot = await spawnUntrustedListener();
    const baseUrl = `http://127.0.0.1:${bot.port}/v1`;
    const logs = [];
    const door = await doorFor({
      known: (url, dials) => isKnownLocalModelTarget(url, { crowHome: EMPTY_HOME, dialAddresses: dials }),
      vouchDeps: { crowHome: EMPTY_HOME },
      baseUrl, logs,
    });
    try {
      const r = await pinnedChat(door.appUrl, baseUrl);
      const text = await r.text();
      assert.equal(r.status, 400, text);
      assert.equal(JSON.parse(text).error.code, "NOT_FORWARDABLE", "the door's existing not-forwardable answer");
      await bot.settle();
      assert.deepEqual(bot.hits, [], "SECURITY: nothing reached the unvouched listener");
      assert.deepEqual(logs, [`[door] own-host target 127.0.0.1:${bot.port} is not a known model server (provider pickup, not-vouched)`],
        "one line, naming the vouch as the reason");
      // CONTROL: the fixture is alive and reachable from this process.
      await bot.control({ method: "POST", path: "/v1/chat/completions" });
      assert.deepEqual(bot.hits, ["POST /v1/chat/completions"], "CONTROL: the listener answers a request the door never sent");
    } finally {
      await door.close();
      await bot.close();
    }

    // THE OTHER CONTROL, on the vouch alone: a listener THIS process holds under the very same
    // nothing-vouches home is a model server (vouch (e) is the socket itself — nothing a bot writes can
    // make the gateway open one), so the same pinned request is answered. "Refused" above is therefore
    // the vouch, never a door that refuses every own-host forward.
    const hits = [];
    const up = http.createServer((req, res) => {
      hits.push(req.url);
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
    await new Promise((r) => up.listen(0, "127.0.0.1", r));
    const ownUrl = `http://127.0.0.1:${up.address().port}/v1`;
    const controlLogs = [];
    const control = await doorFor({
      known: (url, dials) => isKnownLocalModelTarget(url, { crowHome: EMPTY_HOME, dialAddresses: dials }),
      vouchDeps: { crowHome: EMPTY_HOME },
      baseUrl: ownUrl, logs: controlLogs,
    });
    try {
      const ok = await pinnedChat(control.appUrl, ownUrl);
      assert.equal(ok.status, 200, "the gateway's own listening socket is the vouch");
      assert.deepEqual(hits, ["/v1/chat/completions"], "CONTROL: the same request is answered once a trusted socket is there");
      assert.deepEqual(controlLogs, [], "nothing was refused");
    } finally {
      await control.close();
      await new Promise((r) => { try { up.closeAllConnections?.(); } catch { /* gone */ } up.close(() => r()); });
    }
  });

  test("(b) a same-uid squatter on a VOUCHED port is refused as listener-not-trusted, and receives nothing", async () => {
    // THE SQUAT: the port legitimately IS a model server's (a Docker publish vouches it), and a
    // process Crow never started holds the socket — a real HTTP server in its OWN process, same uid.
    const bot = await spawnUntrustedListener();
    const port = bot.port;
    const dockerEntries = [{ address: "127.0.0.1", port }];
    const baseUrl = `http://127.0.0.1:${port}/v1`;
    const logs = [];
    const door = await doorFor({
      known: (url, dials) => isKnownLocalModelTarget(url, { crowHome: EMPTY_HOME, dockerEntries, dialAddresses: dials }),
      vouchDeps: { crowHome: EMPTY_HOME, dockerEntries },
      baseUrl, logs,
    });
    try {
      const r = await pinnedChat(door.appUrl, baseUrl);
      const text = await r.text();
      assert.equal(r.status, 400, text);
      assert.equal(JSON.parse(text).error.code, "NOT_FORWARDABLE");
      await bot.settle();
      assert.deepEqual(bot.hits, [], "SECURITY: the squatter received no request byte");
      assert.deepEqual(logs, [`[door] own-host target 127.0.0.1:${port} is not a known model server (provider pickup, listener-not-trusted)`],
        "one line, naming the socket as the reason — never a 502, which would read like a broken model server");
      // CONTROL: the fixture is alive and reachable from this process.
      await bot.control({ method: "POST", path: "/v1/chat/completions" });
      assert.deepEqual(bot.hits, ["POST /v1/chat/completions"], "CONTROL: the squatter answers a request the door never sent");
    } finally {
      await door.close();
      await bot.close();
    }
  });
});

/* ============================================================ 6. the late belt */

/**
 * A launch object PiRpc can use that claims the contain tier and starts `cmd` UNWRAPPED, for the
 * test-only seam `_setWrapPiSpawnForTest` (scripts/pi-bots/bridge.mjs). Every field PiRpc reads is
 * here: `tier` (the belt and the identity check), `sandboxed` (stdio pipes), `wrapper`, `pidNamespace`,
 * the mask report (`masked` / `maskedFiles` / `unreachable` — the contain tier binds nothing under this
 * instance's Crow home, so a hidden dir is absent from its empty root: `unreachable`), `exposed`, and
 * `cmd` / `args` / `env` as passed. `over` lets a test claim a tier the seam should NOT be believed
 * about.
 */
function forcedLaunch(cmd, args, opts = {}, over = {}) {
  return {
    cmd, args, env: opts.env,
    tier: "contain", sandboxed: true, wrapper: "bwrap", pidNamespace: true, reason: null,
    masked: [], maskedFiles: [], exposed: [],
    unreachable: [...(opts.hideDirs || [])].filter(Boolean),
    droppedWrites: [],
    ...over,
  };
}

describe("the late belt: a launch that is not the contained tier dies before pi exists", () => {
  test("PiRpc refuses a locked turn whose launch is uncontained, and spawns nothing", () => {
    const sessionDir = join(ROOT, "belt-session");
    mkdirSync(join(sessionDir, "sessions"), { recursive: true });
    const marker = join(ROOT, "belt-stub-started.json");
    const stub = join(ROOT, "belt-stub-pi.mjs");
    writeFileSync(stub, 'import { writeFileSync } from "node:fs"; try { writeFileSync(' + JSON.stringify(marker) + ', "started"); } catch {}\n');
    assert.equal(process.env.CROW_PI_SANDBOX, "off", "the launch here is the plain tier");
    assert.throws(() => new PiRpc({
      def: { bot_id: "draftbot", permission_policy: { bash: "deny", write_paths: [] } },
      sessionDir, resolved: { provider: "stub", model: "m1", key: "stub/m1" },
      nodeBin: process.execPath, cliPath: stub,
      // What handleInbound hands a kind that requires containment: the kind's own sentence.
      lockedRequiresContained: LOCKED_TURN_KINDS["report-pickup"].refusals.contained,
    }), (err) => err.message === CONTAINED_REFUSAL, "the fixed sentence, from the row");
    assert.equal(existsSync(marker), false, "pi was never started");

    // A MAIL turn passes the same construction: no requirement, so an uncontained launch is fine.
    const pi = new PiRpc({
      def: { bot_id: "draftbot", permission_policy: { bash: "deny", write_paths: [] } },
      sessionDir, resolved: { provider: "stub", model: "m1", key: "stub/m1" },
      nodeBin: process.execPath, cliPath: stub,
      lockedRequiresContained: null,
    });
    assert.equal(pi.sandboxTier, "none");
    try { pi.close(); } catch { /* nothing started */ }
  });

  test("the seam cannot talk the belt out of it: a forced launch that reports no tier is refused", async () => {
    // The seam replaces the LAUNCH only. The env selection below is the real one, so handleInbound's
    // early check passes and the turn really reaches PiRpc; the forced launch then answers a tier that
    // is not the contain tier, and the belt — which reads the tier the launch got — is the ONLY thing
    // that can stop this turn. If it did not, a pickup could be run uncontained by a launch that lied.
    clearSessions(PICKUP_THREAD);
    const paths = capturePaths("belt-forced-none");
    const saved = { mode: process.env.CROW_PI_SANDBOX, bots: process.env.CROW_PI_CONTAIN_BOTS };
    process.env.CROW_PI_SANDBOX = "contain";
    process.env.CROW_PI_CONTAIN_BOTS = "draftbot";
    _setWrapPiSpawnForTest((cmd, args, opts) => forcedLaunch(cmd, args, opts, {
      tier: "none", sandboxed: false, wrapper: null, pidNamespace: false, reason: "forced for the belt",
    }));
    try {
      await assert.rejects(
        handleInbound({ ...inbound(), lockedTurn: pickupOption() }),
        (err) => err.message === CONTAINED_REFUSAL,
        "the belt refused a launch that reported no contain tier",
      );
      assert.equal(existsSync(paths.argvPath), false, "pi was never started");
    } finally {
      _setWrapPiSpawnForTest(null);
      if (saved.mode === undefined) delete process.env.CROW_PI_SANDBOX; else process.env.CROW_PI_SANDBOX = saved.mode;
      if (saved.bots === undefined) delete process.env.CROW_PI_CONTAIN_BOTS; else process.env.CROW_PI_CONTAIN_BOTS = saved.bots;
      clearSessions(PICKUP_THREAD);
    }
  });
});

/* ============================================================ 7. the launch seam's reset */

test("with the seam null the real launcher is used again (no seam leaks into a later spawn)", () => {
  // The seam is set and reset by every test that uses it; this proves the reset is real: with it null,
  // the same construction gets whatever THIS host's real `wrapPiSpawn` answers — the plain tier here,
  // since this file runs with CROW_PI_SANDBOX=off — and the seam is never called again.
  const sessionDir = join(ROOT, "seam-revert-session");
  mkdirSync(join(sessionDir, "sessions"), { recursive: true });
  const stub = join(ROOT, "seam-revert-stub.mjs");
  writeFileSync(stub, "process.exit(0);\n");
  const spawnOpts = () => ({
    def: { bot_id: "draftbot", permission_policy: { bash: "deny", write_paths: [] } },
    sessionDir, resolved: { provider: "stub", model: "m1", key: "stub/m1" },
    nodeBin: process.execPath, cliPath: stub, lockedRequiresContained: null,
  });
  let calls = 0;
  try {
    _setWrapPiSpawnForTest((cmd, args, opts) => { calls += 1; return forcedLaunch(cmd, args, opts); });
    const forced = new PiRpc(spawnOpts());
    assert.equal(calls, 1, "the seam was used while it was set");
    assert.match(forced.sandboxTier, /^contain/, "and the launch it answered is the one PiRpc used");
    try { forced.close(); } catch { /* nothing started */ }

    _setWrapPiSpawnForTest(null);
    const real = new PiRpc(spawnOpts());
    try {
      assert.equal(calls, 1, "the real launcher ran: the seam was not consulted after the reset");
      assert.equal(real.sandboxTier, "none", "CROW_PI_SANDBOX=off, the plain tier the host really answers");
    } finally { try { real.close(); } catch { /* nothing started */ } }
  } finally {
    _setWrapPiSpawnForTest(null);
  }
});