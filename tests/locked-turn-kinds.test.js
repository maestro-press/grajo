// A LOCKED TURN is a turn pinned to one kind's exact tool set and to ONE MCP server, run in its own
// world root outside every bot-writable one. Two kinds exist: Crow Mail's drafting turn (`mdt_`, three
// draft tools, `/mail-draft/mcp`) and a report pickup (`rpk_`, ONE reply tool, `/report-pickup/mcp`).
//
// This file pins three things:
//   1. the kind table in scripts/pi-bots/mcp_writer.mjs is the whole of the difference between kinds
//      (frozen rows; every field; the exact tool set, accepted in any order and nothing else);
//   2. `draftingTurn` and `lockedTurn` of kind `mail-draft` are the SAME turn — same validated shape,
//      byte-identical refusal sentences — so generalising the option changed no mail behaviour;
//   3. a `report-pickup` turn refuses every other kind's door, token, actor, thread and dir, and gets
//      the same containment a drafting turn gets (no escalation, no def.spawn_env, no card set,
//      fd-only MCP delivery, one enabled server, its own session dir).
//
// The turn-level cases drive the REAL `handleInbound` through the stub-pi harness the mail-draft turn
// test uses (the stub records its argv, the MCP config it was handed and its env, and answers one
// prompt), so no model is contacted. Refusals are asserted without a spawn: they are thrown before
// `buildBotWorld` writes anything. A pickup turn is CONTAINED on every host — the tier is selected
// with the real env and the LAUNCH is forced through the test-only seam
// (`_setWrapPiSpawnForTest`, scripts/pi-bots/bridge.mjs), so the same assertions hold on a host with
// bubblewrap and on one without (see pickupTier), while the product's own rules — the contained-only
// belt, `hidden`, the card-values fd gate — stay the code under test.
import { test, describe, before, after } from "node:test";
import { signBotDef } from "../servers/shared/bot-def-store.js";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";

// The pickup turn's exact tools, spelled out here (not read from the module) so this pin means something.
const PICKUP_TOOLS = [
  "mcp__crow-report-pickup__report_reply",
  "mcp__crow-report-pickup__report_make_card",
  "mcp__crow-report-pickup__report_propose_change",
];
const PICKUP_CSV = [...PICKUP_TOOLS].sort().join(",");
const REPO = new URL("..", import.meta.url).pathname.replace(/\/$/, "");

// ---------------------------------------------------------------- scratch env
//
// Before ANY import of bridge.mjs / mcp_writer.mjs: mcp_writer captures
// `CANONICAL_MCP_PATH` (`HOME + "/.pi/agent/mcp.json"`) at module load, so a
// `process.env.HOME =` made after a static import would always be too late.
for (const k of Object.keys(process.env)) if (/^(PI_|PIBOT_)/.test(k)) delete process.env[k];

const ROOT = mkdtempSync(join(tmpdir(), "locked-turn-kinds-"));
// $HOME is a scratch home inside the same root (its own 0700-shaped `home/`, beside CROW_HOME and the
// bot world roots, never an existing operator home): mcp_writer's canonical path and pi's agent dir
// hang off it, and no test here may read or write the real one.
const HOME_DIR = join(ROOT, "home");
mkdirSync(join(HOME_DIR, ".pi", "agent"), { recursive: true });
const CANONICAL = join(HOME_DIR, ".pi", "agent", "mcp.json");
writeFileSync(CANONICAL, JSON.stringify({ mcpServers: {} }));
const ORIGINAL_HOME = process.env.HOME;
process.env.HOME = HOME_DIR;
process.env.CROW_HOME = join(ROOT, "crowhome");
process.env.CROW_DATA_DIR = join(ROOT, "data");
delete process.env.CROW_DB_PATH;
delete process.env.CROW_TASKS_DB_PATH;
delete process.env.CROW_BOT_ENV_PASSTHROUGH;
process.env.CROW_PI_SANDBOX = "off";
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
    // The floor's own rows (a public IP literal, and one stored as host cloud) are declared here too, so
    // `checkPiModel` answers from pi's models file instead of spawning `pi --list-models` for them.
    publiclit: { models: [{ id: "m1" }] },
    liar: { models: [{ id: "m1" }] },
  },
}));
process.on("exit", () => {
  try { rmSync(ROOT, { recursive: true, force: true }); } catch { /* gone */ }
  if (ORIGINAL_HOME === undefined) delete process.env.HOME; else process.env.HOME = ORIGINAL_HOME;
});

const CROW_DB = join(process.env.CROW_DATA_DIR, "crow.db");
const CROW_HOME = process.env.CROW_HOME;
const DRAFTBOT_ROOT = join(ROOT, "bots", "draftbot");
const ENVBOT_ROOT = join(ROOT, "bots", "envbot");
const ESCBOT_ROOT = join(ROOT, "bots", "escbot");
const CLOUDBOT_ROOT = join(ROOT, "bots", "cloudbot");
const REVIEWBOT_ROOT = join(ROOT, "bots", "reviewbot");

/** A def granting gmail, web, files and messaging: a locked turn must pin none of it. */
function botDef(overrides = {}) {
  return {
    system_prompt: "You answer inside one turn.",
    models: { default: "stub/m1" },
    tools: {
      pi_builtin: ["bash", "read", "write", "edit"],
      crow_mcp: [
        "gmail/gmail_search",
        "gmail/gmail_create_draft",
        "brave-search/brave_web_search",
        "storage/storage_write_file",
        "messaging/messages_send",
      ],
    },
    permission_policy: { bash: "deny", write_paths: [], multi_agent: true },
    session_dir: DRAFTBOT_ROOT,
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

/** Drop every session row on `thread`, so the next turn of that thread starts fresh. */
function clearSessions(thread) {
  const c = new Database(CROW_DB);
  c.prepare("DELETE FROM bot_sessions WHERE gateway_thread_id = ?").run(thread);
  c.close();
}

/** How many session rows a thread has (a refusal must stamp none). */
function sessionRows(thread) {
  const c = new Database(CROW_DB);
  const n = c.prepare("SELECT COUNT(*) AS n FROM bot_sessions WHERE gateway_thread_id = ?").get(thread).n;
  c.close();
  return n;
}

/** Bind one model role (a `dashboard_settings` row the role resolver reads) to a raw model key. */
function setRoleBinding(id, key) {
  const c = new Database(CROW_DB);
  c.prepare("INSERT OR REPLACE INTO dashboard_settings (key, value) VALUES (?, ?)")
    .run("model_role." + id, JSON.stringify({ model: key }));
  c.close();
}

// ---------------------------------------------------------------- modules (dynamic)
const {
  MAIL_DRAFT_SERVER,
  DRAFTING_TURN_TOOLS,
  REPORT_PICKUP_SERVER,
  REPORT_PICKUP_TURN_TOOLS,
  MAIL_DRAFT_TURNS_DIRNAME,
  REPORT_PICKUP_TURNS_DIRNAME,
  LOCKED_TURN_KINDS,
  lockedTurnKindOf,
  isLockedTurnTools,
  isDraftingTurnTools,
  mailDraftBlock,
  reportPickupBlock,
  mailDraftTurnDir,
  resolvedMailDraftTurnDir,
  resolvedLockedTurnDir,
  lockedTurnDir,
  draftingTurnMcpConfig,
  lockedTurnMcpConfig,
} = await import("../scripts/pi-bots/mcp_writer.mjs");
const { buildToolsCsv, toolAllowlist, handleInbound, _setWrapPiSpawnForTest, _setSkillReviewForTest } = await import("../scripts/pi-bots/bridge.mjs");
const { _setSystemScanDirsForTest } = await import("../servers/shared/secret-values.js");

/** The one sentence a pickup's tier requirement throws. */
const CONTAINED_REFUSAL = "lockedTurn refused: this kind runs only in the contained tier";
// The co-host scan must not read this host's /etc (a dev box that declares another Crow home would
// change what a spawn has to mask): point its /etc half at scratch, empty dirs. $HOME is scratch too.
const SCAN_UNITS = join(ROOT, "scan-units");
const SCAN_ENV = join(ROOT, "scan-etc-crow");
mkdirSync(SCAN_UNITS, { recursive: true });
mkdirSync(SCAN_ENV, { recursive: true });
_setSystemScanDirsForTest({ unitDirs: [SCAN_UNITS], envFileDirs: [SCAN_ENV] });
const {
  initGatewayActorKey, _resetActorKeyForTest, signMailDraftActor,
  verifyMailDraftActorSig, verifyReportPickupActorSig,
} = await import("../scripts/pi-bots/actor-sig.mjs");

const DRAFT_ID = "md-0000000000000c01";
const PICKUP_ID = "rpu-0000000000000c01";
const TURN_ID = "mt-0123456789abcdef";
const MDT = "mdt_" + "c".repeat(64);
const RPK = "rpk_" + "c".repeat(64);

const MAIL_THREAD = "mail-draft:" + DRAFT_ID;
const PICKUP_THREAD = "report-pickup:" + PICKUP_ID;

const MAIL_DIR = join(CROW_HOME, MAIL_DRAFT_TURNS_DIRNAME, "draftbot", DRAFT_ID);
const PICKUP_DIR = join(CROW_HOME, REPORT_PICKUP_TURNS_DIRNAME, "draftbot", PICKUP_ID);

/** One draftingTurn option, built the way turn.js builds it. */
function mailOption({ botId = "draftbot", draftId = DRAFT_ID, turnId = TURN_ID, token = MDT, sessionDir, checkModel } = {}) {
  return {
    exactTools: [...DRAFTING_TURN_TOOLS],
    mcpBlock: mailDraftBlock({ botId, draftId, turnId, token }),
    sessionDir: sessionDir === undefined ? join(CROW_HOME, MAIL_DRAFT_TURNS_DIRNAME, botId, draftId) : sessionDir,
    checkModel: checkModel === undefined ? () => ({ ok: true, local: true, key: "stub/m1" }) : checkModel,
  };
}

/** One report-pickup lockedTurn option, built the way a pickup launcher would build it. */
function pickupOption({ botId = "draftbot", pickupId = PICKUP_ID, turnId = TURN_ID, token = RPK, sessionDir, checkModel } = {}) {
  return {
    kind: "report-pickup",
    exactTools: [...REPORT_PICKUP_TURN_TOOLS],
    mcpBlock: reportPickupBlock({ botId, pickupId, turnId, token }),
    sessionDir: sessionDir === undefined ? join(CROW_HOME, REPORT_PICKUP_TURNS_DIRNAME, botId, pickupId) : sessionDir,
    checkModel: checkModel === undefined ? () => ({ ok: true, local: true, key: "stub/m1" }) : checkModel,
  };
}

/** `handleInbound` arguments for one turn, without the locked-turn option itself. */
function inbound({ botId = "draftbot", gatewayType = "mail-draft", thread = MAIL_THREAD, userMessage = "draft it", log = () => {} } = {}) {
  return {
    bot_id: botId, gateway_type: gatewayType, gateway_thread_id: thread,
    user_message: userMessage, log, sendReply: async () => {},
  };
}

/** The message a refused turn throws (and a failure when it was not refused at all). */
async function refusalMessage(opts) {
  try {
    await handleInbound(opts);
  } catch (err) {
    return String(err.message);
  }
  assert.fail("expected the turn to be refused");
}

/**
 * The same gate for a pickup test whose ASSERTION IS THE RESULT of the turn (a model refusal, which
 * happens before any spawn): the turn runs inside the containing rollout env and its result is
 * returned.
 */
async function pickupTierResult(opts, { botId = "draftbot" } = {}) {
  let result = null;
  await pickupTier(async () => { result = await handleInbound(opts); }, { botId });
  return result;
}

/**
 * The launch a contained turn runs with here: the contain tier the kind requires, with the stub pi
 * started UNWRAPPED.
 *
 * `_setWrapPiSpawnForTest` (scripts/pi-bots/bridge.mjs) puts this in place of the real `wrapPiSpawn`
 * for one turn, so the child really is the recording stub whatever this host can sandbox. Every rule
 * AROUND the launch stays the product's own code, and this object is the whole launch surface PiRpc
 * reads: `tier` (isContainTier and the `startsWith("contain")` identity check), `sandboxed` (which
 * stdio slots are pipes), `wrapper`, `pidNamespace`, the mask report (`masked` / `maskedFiles` /
 * `unreachable` — the contain tier binds nothing under this instance's Crow home, so a dir the
 * caller asked to hide is ABSENT from the empty root: `unreachable`, which is what the `hidden`
 * computation accepts for a contained launch), `exposed` (the fd-7 git-key test), `droppedWrites`
 * (the containment line), and `cmd` / `args` / `env` — the same argv and the SAME env object PiRpc
 * passed, because it keeps mutating that env after the launch.
 */
function forcedContainLaunch(cmd, args, opts = {}) {
  return {
    cmd, args, env: opts.env,
    tier: "contain", sandboxed: true, wrapper: "bwrap", pidNamespace: true, reason: null,
    masked: [], maskedFiles: [], exposed: [],
    unreachable: [...(opts.hideDirs || [])].filter(Boolean),
    droppedWrites: [],
  };
}

/** Run `run` with the forced contained launch in place (no env selection: a turn that is not a locked
 *  turn, compared against one under the same containment). Always restored. */
async function forcedLaunch(run) {
  _setWrapPiSpawnForTest(forcedContainLaunch);
  try { await run(); } finally { _setWrapPiSpawnForTest(null); }
}

/**
 * Run a report-pickup turn CONTAINED, on both kinds of host.
 *
 * A pickup runs ONLY in the contained tier (`LOCKED_TURN_KINDS["report-pickup"].requiresContained`),
 * and two gates read the SPAWNER's env for it: `handleInbound`, before it writes or spawns anything,
 * and the belt in PiRpc against the tier the launch really got. The env selection is the real one and
 * works everywhere: `CROW_PI_SANDBOX=contain` plus `CROW_PI_CONTAIN_BOTS=<bot>` (containSelected).
 *
 * What differs per host is only the LAUNCH: without bubblewrap (the test runner's own sandbox) a real
 * contain launch is refused, and with bubblewrap this file's stub pi could not write its captures from
 * inside the empty root. So the launch is forced (`forcedContainLaunch` above, via the test-only seam)
 * while the child is the real recording stub — and everything the product does around it stays the
 * code under test. The belt is proven to still bite when a launch comes back uncontained by its own
 * tests (tests/locked-turn-contained.test.js).
 *
 * The seam and the env are restored in `finally`, so no later turn in this file runs on a forced
 * launch or in a contain selection this test did not ask for.
 */
async function pickupTier(run, { botId = "draftbot" } = {}) {
  const saved = { mode: process.env.CROW_PI_SANDBOX, bots: process.env.CROW_PI_CONTAIN_BOTS };
  process.env.CROW_PI_SANDBOX = "contain";
  process.env.CROW_PI_CONTAIN_BOTS = botId;
  _setWrapPiSpawnForTest(forcedContainLaunch);
  try {
    await run();
  } finally {
    _setWrapPiSpawnForTest(null);
    if (saved.mode === undefined) delete process.env.CROW_PI_SANDBOX; else process.env.CROW_PI_SANDBOX = saved.mode;
    if (saved.bots === undefined) delete process.env.CROW_PI_CONTAIN_BOTS; else process.env.CROW_PI_CONTAIN_BOTS = saved.bots;
  }
}

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: process.env.CROW_DATA_DIR }, stdio: "pipe", cwd: REPO,
  });
  const c = new Database(CROW_DB);
  // `stub` carries a bundle marker so the CONTAINED branch of a pickup test has a provider DOOR
  // (pi_contain_agent.mjs doorRow): a contained spawn's generated models.json is door-only, and a row
  // no door forwards for fails the spawn. Every uncontained turn reads the same row unchanged.
  c.prepare("INSERT OR REPLACE INTO providers (id, base_url, api_key, host, models, bundle_id, disabled) VALUES (?,?,?,?,?,?,0)")
    .run("stub", "http://127.0.0.1:8003/v1", "none", "local", JSON.stringify([{ id: "m1" }]), "vllm-stub");
  c.prepare("INSERT OR REPLACE INTO providers (id, base_url, api_key, host, models, disabled) VALUES (?,?,?,?,?,0)")
    .run("cloudy", "https://api.example.test/v1", "none", "cloud", JSON.stringify([{ id: "m1" }]));
  // A public IP literal (documentation-range-free): the address itself proves it is not this box.
  c.prepare("INSERT OR REPLACE INTO providers (id, base_url, api_key, host, models, disabled) VALUES (?,?,?,?,?,0)")
    .run("publiclit", "http://8.8.8.8:8004/v1", "none", "local", JSON.stringify([{ id: "m1" }]));
  // A row whose base URL LOOKS local while the operator's own store records the model as running in the
  // cloud (host "cloud"): the floor must refuse it too, whatever the URL says.
  c.prepare("INSERT OR REPLACE INTO providers (id, base_url, api_key, host, models, disabled) VALUES (?,?,?,?,?,0)")
    .run("liar", "http://127.0.0.1:8004/v1", "none", "cloud", JSON.stringify([{ id: "m1" }]));
  c.close();
  seedBot("draftbot", botDef());
  seedBot("envbot", botDef({ session_dir: ENVBOT_ROOT, spawn_env: { DRAFT_TEST_MARKER: "1" } }));
  seedBot("escbot", botDef({ session_dir: ESCBOT_ROOT, models: { default: "stub/m1", escalation: "cloudy/m1" } }));
  // A bot whose DEFAULT model is the cloud row: the kind floor has to refuse it on its own.
  seedBot("cloudbot", botDef({ session_dir: CLOUDBOT_ROOT, models: { default: "cloudy/m1" } }));
  // A bot on a public IP-literal row, one on a row whose base URL looks local but is stored as cloud, and
  // one whose model is a ROLE REF (resolved before the floor sees a key).
  seedBot("publiclitbot", botDef({ session_dir: join(ROOT, "bots", "publiclitbot"), models: { default: "publiclit/m1" } }));
  seedBot("liarbot", botDef({ session_dir: join(ROOT, "bots", "liarbot"), models: { default: "liar/m1" } }));
  seedBot("rolebot", botDef({ session_dir: join(ROOT, "bots", "rolebot"), models: { default: "role:everyday" } }));
  // Self-learning on, so the post-turn skill review WOULD fire on any turn the bridge lets reach it.
  // A locked turn of ANY kind must not: its transcript carries words other people wrote.
  seedBot("reviewbot", botDef({
    session_dir: REVIEWBOT_ROOT,
    permission_policy: { bash: "deny", write_paths: [], multi_agent: true, skill_learning: "auto", skill_learning_auto_override: true },
  }));
  initGatewayActorKey();
});

/* =========================================================== (a) the kind table */

test("LOCKED_TURN_KINDS is frozen, and its rows are the whole difference between kinds", () => {
  assert.ok(Object.isFrozen(LOCKED_TURN_KINDS), "the table itself cannot be edited at runtime");
  assert.deepEqual(Object.keys(LOCKED_TURN_KINDS).sort(), ["mail-draft", "report-pickup"]);
  for (const [kind, row] of Object.entries(LOCKED_TURN_KINDS)) {
    assert.ok(Object.isFrozen(row), kind + "'s row is frozen");
    assert.ok(Object.isFrozen(row.exactTools), kind + "'s tool list is frozen");
    assert.equal(row.kind, kind, kind + "'s row names its own kind");
    assert.equal(typeof row.server, "string");
    assert.ok(row.urlPath.startsWith("/") && row.urlPath.endsWith("/mcp"), kind + " names a mount path");
    assert.ok(row.tokenRe instanceof RegExp, kind + " names its bearer shape");
    assert.equal(typeof row.dirname, "string");
    assert.ok(Object.hasOwn(row, "modelFloor"), kind + " names its local-model floor (null when none)");
    assert.ok(row.modelFloor === null || typeof row.modelFloor === "string", kind + "'s floor is a value, never a function");
    assert.ok(Object.isFrozen(row.refusals), kind + "'s refusal sentences are frozen");
    assert.equal(typeof row.refusalLabel, "string");
  }

  const mail = LOCKED_TURN_KINDS["mail-draft"];
  assert.equal(mail.server, MAIL_DRAFT_SERVER);
  assert.equal(mail.server, "crow-mail-draft");
  assert.equal(mail.exactTools, DRAFTING_TURN_TOOLS, "the mail row reuses the existing constant");
  assert.deepEqual([...mail.exactTools].sort(), [
    "mcp__crow-mail-draft__mail_draft_propose",
    "mcp__crow-mail-draft__mail_draft_read_context",
    "mcp__crow-mail-draft__mail_draft_read_thread",
  ]);
  assert.equal(mail.urlPath, "/mail-draft/mcp");
  assert.equal(mail.tokenRe.source, "^mdt_[0-9a-f]{64}$");
  assert.equal(mail.tokenRe.test("mdt_" + "a".repeat(64)), true);
  assert.equal(mail.tokenRe.test("rpk_" + "a".repeat(64)), false);
  assert.equal(mail.actorKind, "mail-draft");
  assert.equal(mail.threadPrefix, "mail-draft:");
  assert.equal(mail.dirname, MAIL_DRAFT_TURNS_DIRNAME);
  assert.equal(mail.dirname, "mail-draft-turns");
  assert.equal(mail.refusalLabel, "draftingTurn", "a mail refusal keeps its own prefix");
  assert.equal(mail.modelFloor, null, "Crow Mail keeps NO local-model floor: its own gate is unchanged");

  const pickup = LOCKED_TURN_KINDS["report-pickup"];
  assert.equal(pickup.server, REPORT_PICKUP_SERVER);
  assert.equal(pickup.server, "crow-report-pickup");
  assert.deepEqual([...pickup.exactTools], PICKUP_TOOLS, "exactly the three pickup tools, never more");
  assert.equal(pickup.exactTools.length, 3);
  assert.equal(pickup.urlPath, "/report-pickup/mcp");
  assert.equal(pickup.tokenRe.source, "^rpk_[0-9a-f]{64}$");
  assert.equal(pickup.tokenRe.test("rpk_" + "a".repeat(64)), true);
  assert.equal(pickup.tokenRe.test("mdt_" + "a".repeat(64)), false);
  assert.equal(pickup.actorKind, "report-pickup");
  assert.equal(pickup.threadPrefix, "report-pickup:");
  assert.equal(pickup.dirname, REPORT_PICKUP_TURNS_DIRNAME);
  assert.equal(pickup.dirname, "report-pickup-turns");
  assert.equal(pickup.refusalLabel, "lockedTurn");
  assert.equal(pickup.modelFloor, "local-only",
    "a pickup's prompt is written by outside people: it must run on a provably local model");

  // Nothing a kind owns is shared with the other: no door, token, actor, thread or dir is reusable.
  for (const [a, b] of [["mail-draft", "report-pickup"], ["report-pickup", "mail-draft"]]) {
    for (const field of ["server", "urlPath", "actorKind", "threadPrefix", "dirname", "tokenPrefix"]) {
      assert.notEqual(LOCKED_TURN_KINDS[a][field], LOCKED_TURN_KINDS[b][field], `${a}.${field} is its own`);
    }
  }
});

test("lockedTurnKindOf answers own keys only", () => {
  assert.equal(lockedTurnKindOf("mail-draft"), LOCKED_TURN_KINDS["mail-draft"]);
  assert.equal(lockedTurnKindOf("report-pickup"), LOCKED_TURN_KINDS["report-pickup"]);
  for (const bad of ["__proto__", "constructor", "prototype", "toString", "hasOwnProperty", "reports", "", 42, null, undefined, {}]) {
    assert.equal(lockedTurnKindOf(bad), null, JSON.stringify(bad));
  }
});

test("neither kind's tools are ever in a bot's envelope", () => {
  const defs = [
    botDef(),
    botDef({ tools: { pi_builtin: ["read"], crow_mcp: [] } }),
    botDef({ tools: { crow_mcp: ["crow-browser/browser_navigate"] } }),
    { tools: {} },
    {},
  ];
  for (const def of defs) {
    const csv = toolAllowlist(def, { remoteEnabled: true });
    for (const name of [...DRAFTING_TURN_TOOLS, ...REPORT_PICKUP_TURN_TOOLS]) {
      assert.ok(!csv.includes(name), "the envelope never carries a locked-turn tool: " + name);
    }
    assert.ok(!/crow-mail-draft|crow-report-pickup/.test(csv));
  }
});

/* =========================================================== (b) the exact tool set */

test("isLockedTurnTools accepts exactly each kind's set, in any order, and nothing else", () => {
  for (const [kind, row] of Object.entries(LOCKED_TURN_KINDS)) {
    const want = [...row.exactTools];
    assert.equal(isLockedTurnTools(kind, want), true, kind + ": the canonical order");
    assert.equal(isLockedTurnTools(kind, [...want].reverse()), true, kind + ": reversed");
    if (want.length > 2) {
      const rotated = [...want.slice(1), want[0]];
      assert.equal(isLockedTurnTools(kind, rotated), true, kind + ": rotated");
    }
    // Subsets, supersets, duplicates, the other kind's tools and non-arrays are all refused.
    assert.equal(isLockedTurnTools(kind, want.slice(0, -1)), false, kind + ": a subset");
    assert.equal(isLockedTurnTools(kind, [...want, "bash"]), false, kind + ": a superset");
    assert.equal(isLockedTurnTools(kind, [...want, want[0]]), false, kind + ": a duplicate");
    assert.equal(isLockedTurnTools(kind, [want[0].replace(/^mcp__/, "mcp__other__")]), false, kind + ": a renamed tool");
    assert.equal(isLockedTurnTools(kind, []), false, kind + ": an empty list");
    assert.equal(isLockedTurnTools(kind, want.join(",")), false, kind + ": a csv string");
    assert.equal(isLockedTurnTools(kind, null), false, kind + ": null");
    assert.equal(isLockedTurnTools(kind, [42]), false, kind + ": a non-string");
    assert.equal(isLockedTurnTools(kind, [...want.slice(0, -1), 42]), false, kind + ": one non-string among names");
    for (const other of Object.keys(LOCKED_TURN_KINDS)) {
      if (other === kind) continue;
      assert.equal(isLockedTurnTools(kind, [...LOCKED_TURN_KINDS[other].exactTools]), false,
        kind + " refuses " + other + "'s tools");
    }
  }
  assert.equal(isLockedTurnTools("nope", [...DRAFTING_TURN_TOOLS]), false, "an unknown kind accepts nothing");
  assert.equal(isLockedTurnTools("__proto__", [...DRAFTING_TURN_TOOLS]), false);
  // The mail helper and the generic one are the same check.
  for (const value of [null, [], ["read"], [...DRAFTING_TURN_TOOLS], [...DRAFTING_TURN_TOOLS].reverse()]) {
    assert.equal(isDraftingTurnTools(value), isLockedTurnTools("mail-draft", value));
  }
});

test("buildToolsCsv pins a kind's csv, and refuses any other list or an unknown kind", () => {
  const def = botDef();
  const resolved = { provider: "stub", model: "m1", key: "stub/m1" };
  const pickup = buildToolsCsv(def, {
    resolved, interactive: true, narrowedTools: JSON.stringify(["read"]),
    exactTools: [...REPORT_PICKUP_TURN_TOOLS], exactToolsKind: "report-pickup",
  });
  assert.equal(pickup.csv, PICKUP_CSV);
  assert.equal(pickup.maOptIn, false);
  assert.equal(pickup.maCapable, false);
  // The mail default is unchanged: no kind means the drafting turn.
  const mail = buildToolsCsv(def, { resolved, exactTools: [...DRAFTING_TURN_TOOLS] });
  assert.equal(mail.csv, [
    "mcp__crow-mail-draft__mail_draft_propose",
    "mcp__crow-mail-draft__mail_draft_read_context",
    "mcp__crow-mail-draft__mail_draft_read_thread",
  ].join(","));
  // A list that is not the named kind's set is refused, whichever kind is named.
  assert.throws(() => buildToolsCsv(def, {
    resolved, exactTools: [...DRAFTING_TURN_TOOLS], exactToolsKind: "report-pickup",
  }), /exactTools is not the pickup turn's tool set/);
  assert.throws(() => buildToolsCsv(def, {
    resolved, exactTools: [...REPORT_PICKUP_TURN_TOOLS], exactToolsKind: "mail-draft",
  }), /exactTools is not the drafting tool set/);
  assert.throws(() => buildToolsCsv(def, {
    resolved, exactTools: [...REPORT_PICKUP_TURN_TOOLS], exactToolsKind: "__proto__",
  }), /unknown locked-turn kind/);
});

test("buildToolsCsv infers the kind from exactTools, and refuses a list that is no kind's", () => {
  const def = botDef();
  const resolved = { provider: "stub", model: "m1", key: "stub/m1" };
  // A caller that names NO kind is accepted only when the list IS exactly one kind's frozen set — the
  // sets are disjoint, so the inference is never a guess. Same csv and same flags as the explicit call.
  const explicitMail = buildToolsCsv(def, { resolved, exactTools: [...DRAFTING_TURN_TOOLS], exactToolsKind: "mail-draft" });
  const inferredMail = buildToolsCsv(def, { resolved, exactTools: [...DRAFTING_TURN_TOOLS] });
  assert.deepEqual(inferredMail, explicitMail, "the mail set infers mail-draft");
  const explicitPickup = buildToolsCsv(def, { resolved, exactTools: [...REPORT_PICKUP_TURN_TOOLS], exactToolsKind: "report-pickup" });
  const inferredPickup = buildToolsCsv(def, { resolved, exactTools: [...REPORT_PICKUP_TURN_TOOLS] });
  assert.deepEqual(inferredPickup, explicitPickup, "the pickup set infers report-pickup");
  assert.equal(inferredPickup.csv, PICKUP_CSV);

  // An explicit kind is still checked against ITS OWN set, unchanged: naming the other kind's set is
  // refused by that kind's own sentence.
  assert.throws(() => buildToolsCsv(def, {
    resolved, exactTools: [...DRAFTING_TURN_TOOLS], exactToolsKind: "report-pickup",
  }), /exactTools is not the pickup turn's tool set/);
  assert.throws(() => buildToolsCsv(def, {
    resolved, exactTools: [...REPORT_PICKUP_TURN_TOOLS], exactToolsKind: "mail-draft",
  }), /exactTools is not the drafting tool set/);
  assert.throws(() => buildToolsCsv(def, {
    resolved, exactTools: [...DRAFTING_TURN_TOOLS], exactToolsKind: "__proto__",
  }), /unknown locked-turn kind/);

  // A list that matches no kind is refused by ONE exact sentence, never pinned to a guess: a subset, a
  // superset, the two kinds' tools together, an empty list, an unrelated name and a non-array.
  for (const exactTools of [
    [...DRAFTING_TURN_TOOLS].slice(0, 2),
    [...DRAFTING_TURN_TOOLS, "bash"],
    [...DRAFTING_TURN_TOOLS, ...REPORT_PICKUP_TURN_TOOLS],
    [...REPORT_PICKUP_TURN_TOOLS, ...DRAFTING_TURN_TOOLS.slice(0, 1)],
    [],
    ["read"],
    "mcp__crow-mail-draft__mail_draft_propose",
    [42],
  ]) {
    assert.throws(() => buildToolsCsv(def, { resolved, exactTools }),
      (err) => err.message === "buildToolsCsv refused: exactTools names no locked-turn kind",
      JSON.stringify(exactTools));
  }

  // exactTools absent (or null) is still the ordinary envelope: no kind is inferred, nothing is refused.
  for (const exactTools of [undefined, null]) {
    const csv = buildToolsCsv(def, { resolved, exactTools }).csv;
    assert.ok(csv.includes("mcp__gmail__gmail_search"), "the bot's own envelope");
    assert.equal(csv.includes("report_reply"), false, "and no locked-turn tool");
  }
});

/* =========================================================== (c) draftingTurn === lockedTurn(mail-draft) */

describe("a lockedTurn of kind mail-draft IS the draftingTurn", () => {
  /** Every refusal a drafting turn can make, as an option value (or a mutation of a good one). */
  function badMailOptions() {
    const good = mailOption();
    const headers = good.mcpBlock.headers;
    return [
      ["no exactTools", { ...good, exactTools: undefined }],
      ["a foreign tool", { ...good, exactTools: ["read"] }],
      ["a subset", { ...good, exactTools: DRAFTING_TURN_TOOLS.slice(0, 2) }],
      ["a superset", { ...good, exactTools: [...DRAFTING_TURN_TOOLS, "bash"] }],
      ["a duplicate", { ...good, exactTools: [DRAFTING_TURN_TOOLS[0], DRAFTING_TURN_TOOLS[0], DRAFTING_TURN_TOOLS[1]] }],
      ["the pickup tool", { ...good, exactTools: [...REPORT_PICKUP_TURN_TOOLS] }],
      ["no model check", { ...good, checkModel: null }],
      ["a non-function model check", { ...good, checkModel: "yes" }],
      ["no mcpBlock", { ...good, mcpBlock: null }],
      ["an extra block key", { ...good, mcpBlock: { ...good.mcpBlock, command: "node" } }],
      ["the board mount", { ...good, mcpBlock: { url: "http://127.0.0.1:3001/board/mcp", headers } }],
      ["a remote host", { ...good, mcpBlock: { ...good.mcpBlock, url: "http://example.test:3001/mail-draft/mcp" } }],
      ["the pickup mount", { ...good, mcpBlock: { ...good.mcpBlock, url: "http://127.0.0.1:3001/report-pickup/mcp" } }],
      ["no headers", { ...good, mcpBlock: { url: good.mcpBlock.url } }],
      ["a board token", { ...good, mcpBlock: { ...good.mcpBlock, headers: { ...headers, Authorization: "Bearer board-token" } } }],
      ["a pickup bearer", { ...good, mcpBlock: { ...good.mcpBlock, headers: { ...headers, Authorization: "Bearer " + RPK } } }],
      ["a wrong actor kind", { ...good, mcpBlock: { ...good.mcpBlock, headers: { ...headers, "X-Crow-Actor-Kind": "bot" } } }],
      ["the pickup actor kind", { ...good, mcpBlock: { ...good.mcpBlock, headers: { ...headers, "X-Crow-Actor-Kind": "report-pickup" } } }],
      ["an empty actor id", { ...good, mcpBlock: { ...good.mcpBlock, headers: { ...headers, "X-Crow-Actor-Id": "" } } }],
      ["a colon in the actor id", { ...good, mcpBlock: { ...good.mcpBlock, headers: { ...headers, "X-Crow-Actor-Id": "a:b" } } }],
      ["another bot's actor", { ...good, mcpBlock: { ...good.mcpBlock, headers: { ...headers, "X-Crow-Actor-Id": "otherbot" } } }],
      ["no signature", { ...good, mcpBlock: { ...good.mcpBlock, headers: { ...headers, "X-Crow-Actor-Sig": "zz" } } }],
      ["a relative dir", { ...good, sessionDir: "relative/dir" }],
      ["a null dir", { ...good, sessionDir: null }],
      ["a dir in the scratch root", { ...good, sessionDir: join(ROOT, "draftturn", DRAFT_ID) }],
      ["another bot's dir", { ...good, sessionDir: join(CROW_HOME, MAIL_DRAFT_TURNS_DIRNAME, "otherbot", DRAFT_ID) }],
      ["a dotted dir", { ...good, sessionDir: good.sessionDir + "/../../escape" }],
      ["a trailing slash", { ...good, sessionDir: good.sessionDir + "/" }],
      ["the pickup dirname", { ...good, sessionDir: join(CROW_HOME, REPORT_PICKUP_TURNS_DIRNAME, "draftbot", DRAFT_ID) }],
      ["the pickup thread", { ...good, sessionDir: join(CROW_HOME, MAIL_DRAFT_TURNS_DIRNAME, "draftbot", PICKUP_ID) }],
    ];
  }

  test("every refusal is the same sentence for both options, with the draftingTurn prefix", async () => {
    const cases = badMailOptions();
    assert.ok(cases.length >= 25, "the matrix really covers the refusals");
    for (const [label, value] of cases) {
      const viaDrafting = await refusalMessage({ ...inbound(), draftingTurn: value });
      const viaLocked = await refusalMessage({ ...inbound(), lockedTurn: { kind: "mail-draft", ...value } });
      assert.equal(viaLocked, viaDrafting, label);
      assert.ok(viaDrafting.startsWith("draftingTurn refused: "), label + ": " + viaDrafting);
    }
  });

  test("a value that is not an object is refused by both options (each naming its own option)", async () => {
    assert.equal(await refusalMessage({ ...inbound(), draftingTurn: "nope" }), "draftingTurn refused: not an object");
    assert.equal(await refusalMessage({ ...inbound(), lockedTurn: "nope" }), "lockedTurn refused: not an object");
    assert.equal(sessionRows(MAIL_THREAD), 0, "no refusal stamped a session row");
  });

  test("a valid lockedTurn(mail-draft) and a valid draftingTurn produce the identical validated turn", async () => {
    const STUB_PI = join(ROOT, "stub-pi-shape.mjs");
    writeFileSync(STUB_PI, stubPiSource());
    const before = process.env.PIBOT_PI_CLI;
    process.env.PIBOT_PI_CLI = STUB_PI;
    process.env.PIBOT_TEST_SESSION_ID = "shape-session";
    try {
      const run = async (option) => {
        clearSessions(MAIL_THREAD);
        const paths = capturePaths("shape");
        await handleInbound({ ...inbound(), ...option });
        return {
          argv: JSON.parse(readFileSync(paths.argvPath, "utf8")),
          csv: toolsOf(paths.argvPath).csv,
          config: readFileSync(paths.mcpPath, "utf8"),
        };
      };
      const viaDrafting = await run({ draftingTurn: mailOption() });
      const viaLocked = await run({ lockedTurn: { kind: "mail-draft", ...mailOption() } });
      assert.equal(viaLocked.csv, viaDrafting.csv, "the same pinned csv");
      assert.equal(viaLocked.config, viaDrafting.config, "the same delivered MCP config, byte for byte");
      // The system-prompt file lives in a per-turn temp dir (bot-world's own mkdtemp): normalise that
      // one path, so everything else in the argv is compared as it is.
      const shapeOf = (argv) => argv.map((a) => a.replace(/\/pibot-[A-Za-z0-9]+\//g, "/pibot-*/"));
      assert.deepEqual(shapeOf(viaLocked.argv), shapeOf(viaDrafting.argv), "the same pi argv");
      assert.equal(viaDrafting.csv, [
        "mcp__crow-mail-draft__mail_draft_propose",
        "mcp__crow-mail-draft__mail_draft_read_context",
        "mcp__crow-mail-draft__mail_draft_read_thread",
      ].join(","));
    } finally {
      clearSessions(MAIL_THREAD);
      delete process.env.PIBOT_TEST_SESSION_ID;
      if (before === undefined) delete process.env.PIBOT_PI_CLI; else process.env.PIBOT_PI_CLI = before;
    }
  });

  test("both options at once are refused: a turn cannot be two kinds", async () => {
    for (const [name, opts] of [
      ["two pickup options", { draftingTurn: mailOption(), lockedTurn: pickupOption() }],
      ["two mail options", { draftingTurn: mailOption(), lockedTurn: { kind: "mail-draft", ...mailOption() } }],
    ]) {
      const message = await refusalMessage({ ...inbound(), ...opts });
      assert.equal(message, "lockedTurn refused: a turn cannot be two kinds", name);
    }
    assert.equal(sessionRows(MAIL_THREAD), 0);
  });

  test("no locked turn is ever built from an option an outsider can pass by injection", () => {
    // A REAL run of bridge.mjs's --inject entry with a pickup `lockedTurn` in the payload. The CLI
    // strips it (like `draftingTurn`), so the turn that actually runs is the bot's ordinary one: the
    // stub pi is pinned with the bot's OWN envelope, never the pickup's single tool, and no pickup
    // turn dir is ever created. No model is needed (the stub answers the one prompt).
    const stub = join(ROOT, "stub-pi-inject.mjs");
    writeFileSync(stub, stubPiSource());
    const paths = capturePaths("inject-pickup");
    const injectedPickupDir = join(CROW_HOME, REPORT_PICKUP_TURNS_DIRNAME, "draftbot", PICKUP_ID);
    rmSync(injectedPickupDir, { recursive: true, force: true });
    const thread = "inject-chat-thread";
    clearSessions(thread);
    const payload = {
      bot_id: "draftbot", gateway_type: "gmail", gateway_thread_id: thread,
      user_message: "hello", lockedTurn: pickupOption(),
    };
    const out = execFileSync(process.execPath, ["scripts/pi-bots/bridge.mjs", "--inject", JSON.stringify(payload)], {
      cwd: REPO,
      env: {
        ...process.env,
        PIBOT_PI_CLI: stub,
        PIBOT_TEST_ARGV: paths.argvPath,
        PIBOT_TEST_MCPCAP: paths.mcpPath,
        PIBOT_TEST_ENVCAP: paths.envPath,
      },
      encoding: "utf8",
      timeout: 60000,
    });
    try {
      assert.match(out, /RESULT \{/, "the injected turn really ran");
      const { argv, csv } = toolsOf(paths.argvPath);
      assert.ok(csv, "an ORDINARY turn was pinned with a tool csv: " + argv.join(" "));
      assert.notEqual(csv, PICKUP_CSV, "never the pickup's tools");
      assert.equal(String(csv).includes("report_reply"), false, "no pickup tool anywhere in the csv");
      assert.ok(String(csv).includes("mcp__gmail__gmail_search"), "the bot's own envelope, not a locked turn's");
      assert.ok(argv.join(" ").includes(join(DRAFTBOT_ROOT, "sessions")), "the bot's own session dir");
      assert.equal(argv.join(" ").includes(REPORT_PICKUP_TURNS_DIRNAME), false, "never a pickup turn dir");
      assert.equal(existsSync(injectedPickupDir), false, "the injected pickup turn built nothing");
    } finally {
      clearSessions(thread);
    }
  });
});

/* =========================================================== (d) report-pickup refusals */

describe("a report-pickup lockedTurn refuses every other kind's turn", () => {
  async function refusePickup(value, label) {
    const message = await refusalMessage({ ...inbound({ gatewayType: "report-pickup", thread: PICKUP_THREAD }), lockedTurn: value });
    assert.ok(message.startsWith("lockedTurn refused: "), label + ": " + message);
    assert.ok(!message.includes("drafting"), label + " does not borrow the drafting wording");
    return message;
  }

  test("the kind must be an own key of the table", async () => {
    for (const kind of ["reports", "", "mail-drafting", "__proto__", "constructor", "prototype", "toString", 42, null, undefined, {}]) {
      const message = await refusePickup({ ...pickupOption(), kind }, JSON.stringify(kind));
      assert.match(message, /unknown turn kind$/, JSON.stringify(kind));
    }
    // No kind at all is the same refusal.
    const withoutKind = pickupOption();
    delete withoutKind.kind;
    assert.match(await refusePickup(withoutKind, "no kind"), /unknown turn kind$/);
    assert.equal(sessionRows(PICKUP_THREAD), 0, "no refusal stamped a session row");
  });

  test("the door, token, actor, thread and dir must all be this kind's", async () => {
    const good = pickupOption();
    const headers = good.mcpBlock.headers;
    const cases = [
      ["the mail-draft mount", { ...good, mcpBlock: { ...good.mcpBlock, url: "http://127.0.0.1:3001/mail-draft/mcp" } }, /not this box's \/report-pickup\/mcp$/],
      ["another mount", { ...good, mcpBlock: { ...good.mcpBlock, url: "http://127.0.0.1:3001/reports/mcp" } }, /not this box's \/report-pickup\/mcp$/],
      ["a remote host", { ...good, mcpBlock: { ...good.mcpBlock, url: "http://example.test:3001/report-pickup/mcp" } }, /not this box's \/report-pickup\/mcp$/],
      ["an mdt_ bearer", { ...good, mcpBlock: { ...good.mcpBlock, headers: { ...headers, Authorization: "Bearer " + MDT } } }, /bearer is not a turn token$/],
      ["a bare token", { ...good, mcpBlock: { ...good.mcpBlock, headers: { ...headers, Authorization: RPK } } }, /bearer is not a turn token$/],
      ["a short rpk_", { ...good, mcpBlock: { ...good.mcpBlock, headers: { ...headers, Authorization: "Bearer rpk_abc" } } }, /bearer is not a turn token$/],
      ["the mail-draft actor kind", { ...good, mcpBlock: { ...good.mcpBlock, headers: { ...headers, "X-Crow-Actor-Kind": "mail-draft" } } }, /actor kind is not report-pickup$/],
      ["another bot's actor", { ...good, mcpBlock: { ...good.mcpBlock, headers: { ...headers, "X-Crow-Actor-Id": "otherbot" } } }, /actor is not the bot of this turn$/],
      ["a colon in the actor id", { ...good, mcpBlock: { ...good.mcpBlock, headers: { ...headers, "X-Crow-Actor-Id": "a:b" } } }, /names no bot$/],
      ["no signature", { ...good, mcpBlock: { ...good.mcpBlock, headers: { ...headers, "X-Crow-Actor-Sig": "zz" } } }, /carries no actor signature$/],
      ["an extra block key", { ...good, mcpBlock: { ...good.mcpBlock, command: "node" } }, /the block carries command$/],
      ["no headers", { ...good, mcpBlock: { url: good.mcpBlock.url } }, /has no headers$/],
      ["a mail-draft tool set", { ...good, exactTools: [...DRAFTING_TURN_TOOLS] }, /exactTools is not the pickup turn's tool set$/],
      ["a widened tool set", { ...good, exactTools: [...REPORT_PICKUP_TURN_TOOLS, ...DRAFTING_TURN_TOOLS.slice(0, 1)] }, /pickup turn's tool set$/],
      ["no tools", { ...good, exactTools: [] }, /pickup turn's tool set$/],
      ["no model check", { ...good, checkModel: null }, /no model check$/],
      ["the mail-draft dirname", { ...good, sessionDir: join(CROW_HOME, MAIL_DRAFT_TURNS_DIRNAME, "draftbot", PICKUP_ID) }, /session dir is not <CROW_HOME>\/report-pickup-turns/],
      ["a dot-dot dir", { ...good, sessionDir: good.sessionDir + "/../../escape" }, /session dir is not <CROW_HOME>\/report-pickup-turns/],
      ["a trailing slash", { ...good, sessionDir: good.sessionDir + "/" }, /session dir is not <CROW_HOME>\/report-pickup-turns/],
      ["another bot's dir", { ...good, sessionDir: join(CROW_HOME, REPORT_PICKUP_TURNS_DIRNAME, "otherbot", PICKUP_ID) }, /session dir is not <CROW_HOME>\/report-pickup-turns/],
      ["a relative dir", { ...good, sessionDir: "relative/dir" }, /session dir is not <CROW_HOME>\/report-pickup-turns/],
    ];
    for (const [label, value, pattern] of cases) {
      const message = await refusePickup(value, label);
      assert.match(message, pattern, label);
    }
    assert.equal(sessionRows(PICKUP_THREAD), 0, "no refusal stamped a session row");
  });

  test("the thread is the pickup's, and it decides the dir", async () => {
    const good = pickupOption();
    for (const [thread, pattern] of [
      [MAIL_THREAD, /thread is not a pickup thread$/],
      ["report-pickup:", /thread names no pickup$/],
      ["report-pickup:../escape", /thread names no pickup$/],
      ["chat-thread-1", /thread is not a pickup thread$/],
    ]) {
      const message = await refusalMessage({ ...inbound({ gatewayType: "report-pickup", thread }), lockedTurn: good });
      assert.ok(message.startsWith("lockedTurn refused: "), thread);
      assert.match(message, pattern, thread);
    }
    // The thread names a different pickup than the session dir: the dir is refused, not silently used.
    const other = "rpu-0000000000000d02";
    const message = await refusalMessage({
      ...inbound({ gatewayType: "report-pickup", thread: "report-pickup:" + other }), lockedTurn: good,
    });
    assert.match(message, /session dir is not <CROW_HOME>\/report-pickup-turns/);
  });
});

/* =========================================================== (e) the block builder */

test("reportPickupBlock is the pickup's own door: one url, its bearer, its actor headers", () => {
  const block = reportPickupBlock({ botId: "draftbot", pickupId: PICKUP_ID, turnId: TURN_ID, token: RPK, port: 3999 });
  assert.equal(block.url, "http://127.0.0.1:3999/report-pickup/mcp");
  assert.deepEqual(Object.keys(block.headers).sort(), [
    "Authorization", "X-Crow-Actor-Id", "X-Crow-Actor-Kind", "X-Crow-Actor-Sig",
  ]);
  assert.equal(block.headers.Authorization, "Bearer " + RPK);
  assert.equal(block.headers["X-Crow-Actor-Kind"], "report-pickup");
  assert.equal(block.headers["X-Crow-Actor-Id"], "draftbot");
  const sig = block.headers["X-Crow-Actor-Sig"];
  assert.match(sig, /^[0-9a-f]{64}$/);
  assert.equal(verifyReportPickupActorSig({ botId: "draftbot", pickupId: PICKUP_ID, turnId: TURN_ID, sig }), true);
  // Another turn, another pickup, another bot: none of them verify.
  assert.equal(verifyReportPickupActorSig({ botId: "draftbot", pickupId: PICKUP_ID, turnId: "mt-ffffffffffffffff", sig }), false);
  assert.equal(verifyReportPickupActorSig({ botId: "draftbot", pickupId: "rpu-0000000000000d02", turnId: TURN_ID, sig }), false);
  assert.equal(verifyReportPickupActorSig({ botId: "otherbot", pickupId: PICKUP_ID, turnId: TURN_ID, sig }), false);
  // A signature of the OTHER kind never verifies here, and this one never verifies as mail-draft.
  const mailSig = signMailDraftActor({ botId: "draftbot", draftId: PICKUP_ID, turnId: TURN_ID });
  assert.equal(verifyReportPickupActorSig({ botId: "draftbot", pickupId: PICKUP_ID, turnId: TURN_ID, sig: mailSig }), false,
    "a mail-draft signature is not a pickup signature");
  assert.equal(verifyMailDraftActorSig({ botId: "draftbot", draftId: PICKUP_ID, turnId: TURN_ID, sig }), false,
    "a pickup signature is not a mail-draft signature");
  // And the mail builder still builds the mail door.
  const mailBlock = mailDraftBlock({ botId: "draftbot", draftId: PICKUP_ID, turnId: TURN_ID, token: MDT, port: 3999 });
  assert.equal(mailBlock.url, "http://127.0.0.1:3999/mail-draft/mcp");
  assert.equal(mailBlock.headers["X-Crow-Actor-Kind"], "mail-draft");
  assert.equal(verifyMailDraftActorSig({
    botId: "draftbot", draftId: PICKUP_ID, turnId: TURN_ID, sig: mailBlock.headers["X-Crow-Actor-Sig"],
  }), true);
  assert.equal(Object.hasOwn(block.headers, "X-Crow-Job-Id"), false, "nothing but the actor headers and the bearer");
});

test("reportPickupBlock refuses a token, id or key that cannot be one", () => {
  const valid = { botId: "draftbot", pickupId: PICKUP_ID, turnId: TURN_ID, token: RPK };
  _resetActorKeyForTest();
  // No key in this process: the block would be unsigned, so it is refused instead.
  assert.throws(() => reportPickupBlock(valid), /actor key/);
  initGatewayActorKey();
  for (const [name, over] of [
    ["an mdt_ token", { token: MDT }],
    ["a board token", { token: "board-token" }],
    ["a short token", { token: "rpk_abc" }],
    ["no bot", { botId: "" }],
    ["no pickup", { pickupId: "" }],
    ["a colon in the pickup id", { pickupId: "a:b" }],
    ["no turn", { turnId: "" }],
    ["a colon in the turn id", { turnId: "mt:1" }],
  ]) {
    assert.throws(() => reportPickupBlock({ ...valid, ...over }), (err) => err instanceof TypeError, name);
  }
  assert.ok(reportPickupBlock(valid).url.startsWith("http://127.0.0.1:"));
});

/* =========================================================== (f) the config and the dirs */

test("lockedTurnMcpConfig for a pickup has exactly one enabled server, and every canonical server disabled", () => {
  const block = reportPickupBlock({ botId: "draftbot", pickupId: PICKUP_ID, turnId: TURN_ID, token: RPK, port: 3001 });
  const canonical = { mcpServers: { "team-wiki": { command: "node", args: ["/tmp/wiki.js"] }, notes: { url: "http://example.test/mcp" } } };
  const config = lockedTurnMcpConfig("report-pickup", block, { canonical });
  assert.deepEqual(Object.keys(config.mcpServers).sort(), ["crow-report-pickup", "notes", "team-wiki"]);
  const enabled = Object.entries(config.mcpServers).filter(([, b]) => !(b && b.disabled === true)).map(([n]) => n);
  assert.deepEqual(enabled, [REPORT_PICKUP_SERVER], "exactly one server is active");
  for (const name of ["team-wiki", "notes"]) assert.deepEqual(config.mcpServers[name], { disabled: true }, name);
  assert.equal(config.mcpServers[REPORT_PICKUP_SERVER].url, "http://127.0.0.1:3001/report-pickup/mcp");
  // The mail config is the same algorithm on the mail row.
  const mailBlock = mailDraftBlock({ botId: "draftbot", draftId: DRAFT_ID, turnId: TURN_ID, token: MDT, port: 3001 });
  assert.deepEqual(draftingTurnMcpConfig(mailBlock, { canonical }), lockedTurnMcpConfig("mail-draft", mailBlock, { canonical }));
  assert.deepEqual(Object.keys(draftingTurnMcpConfig(mailBlock, { canonical }).mcpServers).sort(), ["crow-mail-draft", "notes", "team-wiki"]);
  // Unknown kinds and a missing block are refused.
  assert.throws(() => lockedTurnMcpConfig("__proto__", block, { canonical }), /unknown locked-turn kind/);
  assert.throws(() => lockedTurnMcpConfig("report-pickup", null, { canonical }), /lockedTurnMcpConfig needs the turn's server block/);
  assert.throws(() => draftingTurnMcpConfig(null, { canonical }), /draftingTurnMcpConfig needs the turn's server block/);
});

test("each kind's session dir is its own, and the segment rules are the same", () => {
  assert.equal(mailDraftTurnDir(CROW_HOME, "draftbot", DRAFT_ID), MAIL_DIR);
  assert.equal(lockedTurnDir("report-pickup", CROW_HOME, "draftbot", PICKUP_ID), PICKUP_DIR);
  assert.equal(resolvedLockedTurnDir("report-pickup", CROW_HOME, "draftbot", PICKUP_ID), PICKUP_DIR);
  assert.equal(resolvedMailDraftTurnDir(CROW_HOME, "draftbot", DRAFT_ID), MAIL_DIR);
  assert.notEqual(MAIL_DIR, PICKUP_DIR);
  assert.ok(PICKUP_DIR.startsWith(CROW_HOME + "/"), "under the instance's own home");
  assert.ok(!PICKUP_DIR.startsWith(DRAFTBOT_ROOT + "/"), "never inside a bot's world root");
  for (const [botId, id] of [["..", PICKUP_ID], ["a/b", PICKUP_ID], ["draftbot", ".."], ["draftbot", "../x"], ["draftbot", ".hidden"], ["draftbot", "a:b"]]) {
    assert.equal(lockedTurnDir("report-pickup", CROW_HOME, botId, id), null, botId + "/" + id);
  }
  assert.throws(() => lockedTurnDir("constructor", CROW_HOME, "draftbot", PICKUP_ID), /unknown locked-turn kind/);
  assert.throws(() => resolvedLockedTurnDir("__proto__", CROW_HOME, "draftbot", PICKUP_ID), /unknown locked-turn kind/);
});

/* =========================================================== (g) containment at the bridge */

/** A protocol-speaking stub pi: records argv, the MCP config it was handed, its env and the prompt. */
function stubPiSource() {
  return [
    'import { readFileSync, writeFileSync } from "node:fs";',
    'const out = (o) => process.stdout.write(JSON.stringify(o) + "\\n");',
    'try { writeFileSync(process.env.PIBOT_TEST_ARGV, JSON.stringify(process.argv.slice(2))); } catch {}',
    'try {',
    '  if (process.env.PIBOT_TEST_ENVCAP) {',
    '    const env = {};',
    '    for (const k of ["DRAFT_TEST_MARKER", "PI_BOT_SECRET_VALUES_FD", "PI_BOT_SECRET_VALUES_FILE"]) {',
    '      if (Object.hasOwn(process.env, k)) env[k] = process.env[k];',
    '    }',
    '    writeFileSync(process.env.PIBOT_TEST_ENVCAP, JSON.stringify(env));',
    '  }',
    '} catch {}',
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
    '      out({ type: "response", command: "get_state", data: { sessionId: process.env.PIBOT_TEST_SESSION_ID || "stub-session" } });',
    '    } else if (m.type === "get_session_stats") {',
    '      out({ type: "response", command: "get_session_stats", id: m.id, data: { tokens: { input: 1, output: 1, cacheRead: 0 } } });',
    '    } else if (m.type === "prompt") {',
    '      if (process.env.PIBOT_TEST_MCPCAP) { try { writeFileSync(process.env.PIBOT_TEST_MCPCAP, cfg == null ? "null" : cfg); } catch {} }',
    '      if (process.env.PIBOT_TEST_PROMPTCAP) { try { writeFileSync(process.env.PIBOT_TEST_PROMPTCAP, JSON.stringify({ prompt: m.message })); } catch {} }',
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
  const argvPath = join(CAPTURE_DIR, `argv-${tag}-${n}.json`);
  const mcpPath = join(CAPTURE_DIR, `mcp-${tag}-${n}.json`);
  const envPath = join(CAPTURE_DIR, `env-${tag}-${n}.json`);
  process.env.PIBOT_TEST_ARGV = argvPath;
  process.env.PIBOT_TEST_MCPCAP = mcpPath;
  process.env.PIBOT_TEST_ENVCAP = envPath;
  return { argvPath, mcpPath, envPath };
}

function toolsOf(argvPath) {
  const argv = JSON.parse(readFileSync(argvPath, "utf8"));
  const at = argv.indexOf("--tools");
  return { argv, csv: at === -1 ? undefined : argv[at + 1] };
}

/**
 * What a "the floor passed, so the turn went on to the spawn" test can prove. The floor's own
 * refusals (`model not allowed`) and the kind's tier refusal (`contained tier`) both come back as
 * `action: "error"` BEFORE PiRpc is constructed, so neither may be the outcome here; the stub's argv
 * capture then proves the spawn really was reached, and any other error is reported (never silently
 * accepted): a launch that fails for an unrelated reason would still be visible in the message.
 *
 * @returns {string|null} the turn's error, when it reported one (a spawn-stage failure).
 */
function assertPastTheFloor(result, paths) {
  const error = result && result.action === "error" ? String(result.error || "") : null;
  if (error !== null) {
    assert.doesNotMatch(error, /model not allowed/, "the kind's floor refused a model it should have proved local: " + error);
    assert.doesNotMatch(error, /contained tier|bubblewrap|PID namespace/i, "the launch was refused by the tier rule: " + error);
  }
  assert.equal(existsSync(paths.argvPath), true, "the turn reached the spawn"
    + (error === null ? "; the turn answered " + JSON.stringify(result) : "; the turn then failed with: " + error));
  return error;
}

describe("a pickup turn at the bridge", () => {
  let previousCli = null;

  /**
   * The stub pi every test in this describe drives. It needs no packaging beside it: the forced contain
   * launch starts it unwrapped, so it is never inside a sandbox's empty root and is always at this exact
   * host path.
   */
  function writeStubPi() {
    const dir = join(ROOT, "stub-pi");
    mkdirSync(dir, { recursive: true });
    const file = join(dir, "stub-pi.mjs");
    writeFileSync(file, stubPiSource());
    return file;
  }

  before(() => {
    previousCli = process.env.PIBOT_PI_CLI;
    process.env.PIBOT_PI_CLI = writeStubPi();
  });

  after(() => {
    if (previousCli === undefined) delete process.env.PIBOT_PI_CLI; else process.env.PIBOT_PI_CLI = previousCli;
  });

  test("a pickup turn is refused outright when the bot is not selected for containment", async () => {
    // The kind's own early refusal (bridge.mjs handleInbound), and the one thing a host that cannot
    // contain the tier gets: CROW_PI_SANDBOX=off is this file's env, so no pickup turn runs without the
    // selection pickupTier makes for it. Nothing is written and nothing is spawned.
    clearSessions(PICKUP_THREAD);
    rmSync(PICKUP_DIR, { recursive: true, force: true });
    const paths = capturePaths("pickup-uncontained");
    await assert.rejects(
      handleInbound({ ...inbound({ gatewayType: "report-pickup", thread: PICKUP_THREAD, userMessage: "answer the comment" }), lockedTurn: pickupOption() }),
      (err) => err.message === CONTAINED_REFUSAL,
      "no contain selection for this bot, so the turn is refused",
    );
    assert.equal(existsSync(paths.argvPath), false, "no pi was spawned");
    assert.equal(existsSync(PICKUP_DIR), false, "the turn's own dir was never created");
    assert.equal(sessionRows(PICKUP_THREAD), 0, "no session row was stamped");
  });

  test("its argv pins three tools, its own session dir, and none of the bot's tools", async () => {
    clearSessions(PICKUP_THREAD);
    const paths = capturePaths("pickup-argv");
    let result = null;
    await pickupTier(async () => {
      result = await handleInbound({
        ...inbound({ gatewayType: "report-pickup", thread: PICKUP_THREAD, userMessage: "answer the comment" }),
        lockedTurn: pickupOption(),
      });
    });
    assertPastTheFloor(result, paths);
    const { argv, csv } = toolsOf(paths.argvPath);
    assert.equal(csv, PICKUP_CSV);
    for (const builtin of ["bash", "read", "write", "edit", "subagent", "ask_user", "send_user_file", "crow_request_secret"]) {
      assert.ok(!String(csv).split(",").includes(builtin), "no " + builtin + " on a pickup turn");
    }
    assert.ok(!argv.join(" ").includes("gmail"), "none of the bot's own tools are pinned: " + argv.join(" "));
    assert.equal(argv.includes("--session"), false, "the first pickup turn starts fresh");
    assert.ok(argv.includes(join(PICKUP_DIR, "sessions")), "its --session-dir is the pickup's own dir");
    assert.ok(!argv.join(" ").includes(join(CROW_HOME, MAIL_DRAFT_TURNS_DIRNAME)), "never the mail-draft turns root");
    clearSessions(PICKUP_THREAD);
  });

  test("its delivered config has exactly one enabled server, signed for the pickup", async () => {
    clearSessions(PICKUP_THREAD);
    const before = readFileSync(CANONICAL, "utf8");
    writeFileSync(CANONICAL, JSON.stringify({ mcpServers: { "team-wiki": { command: "node", args: ["/tmp/wiki.js"] } } }));
    try {
      const paths = capturePaths("pickup-config");
      const option = pickupOption();
      let result = null;
      await pickupTier(async () => {
        result = await handleInbound({
          ...inbound({ gatewayType: "report-pickup", thread: PICKUP_THREAD, userMessage: "answer the comment" }),
          lockedTurn: option,
        });
      });
      // The config reaches pi on its fd (PI_BOT_MCP_CONFIG_FD): a stub that could not read it writes
      // the string "null".
      assertPastTheFloor(result, paths);
      const rawConfig = readFileSync(paths.mcpPath, "utf8");
      assert.notEqual(rawConfig, "null", "pi was handed the MCP config on its fd");
      const config = JSON.parse(rawConfig);
      const enabled = Object.entries(config.mcpServers).filter(([, b]) => !(b && b.disabled === true)).map(([n]) => n);
      assert.deepEqual(enabled, [REPORT_PICKUP_SERVER], "exactly one server is active");
      assert.deepEqual(config.mcpServers["team-wiki"], { disabled: true }, "the operator's global server is disabled");
      const block = config.mcpServers[REPORT_PICKUP_SERVER];
      assert.match(block.url, /^http:\/\/127\.0\.0\.1:\d+\/report-pickup\/mcp$/);
      assert.equal(block.headers.Authorization, "Bearer " + RPK);
      assert.equal(block.headers["X-Crow-Actor-Kind"], "report-pickup");
      assert.equal(block.headers["X-Crow-Actor-Id"], "draftbot");
      assert.equal(verifyReportPickupActorSig({
        botId: "draftbot", pickupId: PICKUP_ID, turnId: TURN_ID, sig: block.headers["X-Crow-Actor-Sig"],
      }), true, "the mount's own verifier accepts the delivered signature");
      assert.equal(verifyMailDraftActorSig({
        botId: "draftbot", draftId: PICKUP_ID, turnId: TURN_ID, sig: block.headers["X-Crow-Actor-Sig"],
      }), false, "and the mail door's does not");
      const text = JSON.stringify(config);
      for (const name of ["gmail", "brave-search", "storage", "messaging", "board", "phone", "artifacts", "mail-draft"]) {
        assert.ok(!text.includes(`"${name}"`), "no " + name + " block on a pickup turn");
      }
    } finally {
      writeFileSync(CANONICAL, before);
      clearSessions(PICKUP_THREAD);
    }
  });

  test("its world root is its own, outside every bot-writable root, and holds no config of its own", async () => {
    clearSessions(PICKUP_THREAD);
    await pickupTier(async () => {
      await handleInbound({
        ...inbound({ gatewayType: "report-pickup", thread: PICKUP_THREAD, userMessage: "answer the comment" }),
        lockedTurn: pickupOption(),
      });
    });
    assert.equal(existsSync(PICKUP_DIR), true, "the turn's own dir was created");
    assert.equal(existsSync(join(PICKUP_DIR, "sessions")), true, "pi's --session-dir has a place to write");
    assert.deepEqual(readdirSync(PICKUP_DIR), ["sessions"],
      "nothing but pi's session dir: the config reaches pi on the fd, never as a file");
    assert.equal(existsSync(join(PICKUP_DIR, ".mcp.json")), false);
    assert.equal(statSync(PICKUP_DIR).mode & 0o777, 0o700, "the turn's own directory is private");
    clearSessions(PICKUP_THREAD);
  });

  test("a file-delivery host refuses a pickup turn before anything is written or spawned", async () => {
    clearSessions(PICKUP_THREAD);
    const paths = capturePaths("pickup-filemode");
    const botConfig = join(DRAFTBOT_ROOT, ".mcp.json");
    rmSync(botConfig, { force: true });
    rmSync(PICKUP_DIR, { recursive: true, force: true });
    process.env.PIBOT_MCP_CONFIG_DELIVERY = "file";
    try {
      await assert.rejects(
        handleInbound({
          ...inbound({ gatewayType: "report-pickup", thread: PICKUP_THREAD, userMessage: "answer the comment" }),
          lockedTurn: pickupOption(),
        }),
        (err) => err.name === "MailError" && err.code === "delivery_unsupported",
      );
    } finally {
      process.env.PIBOT_MCP_CONFIG_DELIVERY = "fd";
    }
    assert.equal(existsSync(paths.argvPath), false, "no pi was spawned");
    assert.equal(existsSync(botConfig), false, "the bot's world was never written");
    assert.equal(existsSync(PICKUP_DIR), false, "the turn's own dir was never created");
    assert.equal(sessionRows(PICKUP_THREAD), 0, "no session row was stamped");
  });

  test("a pickup turn's prompt is exactly the caller's message; a mail-draft turn keeps the generic framing", async () => {
    const STUB_PI = join(ROOT, "stub-pi-bare.mjs");
    writeFileSync(STUB_PI, stubPiSource());
    const before = process.env.PIBOT_PI_CLI;
    process.env.PIBOT_PI_CLI = STUB_PI;
    const promptPath = join(CAPTURE_DIR, "prompt-bare.json");
    process.env.PIBOT_TEST_PROMPTCAP = promptPath;
    process.env.PIBOT_TEST_SESSION_ID = "bare-session";
    const message = "Readers left comments on Monday. Answer with report_reply.";
    try {
      clearSessions("report-pickup:" + PICKUP_ID);
      const paths = capturePaths("pickup-bare");
      let result = null;
      await pickupTier(async () => {
        result = await handleInbound({
          ...inbound({ gatewayType: "report-pickup", thread: "report-pickup:" + PICKUP_ID, userMessage: message }),
          lockedTurn: pickupOption(),
        });
      });
      assertPastTheFloor(result, paths);
      const prompt = JSON.parse(readFileSync(promptPath, "utf8")).prompt;
      assert.equal(prompt, message, "the prompt is the caller's message and nothing else");
      for (const frag of ["GATEWAY:", "PROJECT:", "Kanban", "Reply on the gateway thread", "[Dates]"]) {
        assert.equal(prompt.includes(frag), false, "no " + frag);
      }

      // The mail-draft kind is unchanged: its prompt still carries the generic framing.
      rmSync(promptPath, { force: true });
      clearSessions(MAIL_THREAD);
      capturePaths("mail-framing");
      await handleInbound({ ...inbound(), lockedTurn: { kind: "mail-draft", ...mailOption() } });
      const mailPrompt = JSON.parse(readFileSync(promptPath, "utf8")).prompt;
      assert.ok(mailPrompt.includes("User said: \"draft it\""), mailPrompt);
      assert.ok(mailPrompt.includes("Reply on the gateway thread"), "the mail-draft tail is unchanged");
      assert.ok(/PROJECT/.test(mailPrompt), "the mail-draft header is unchanged");
    } finally {
      delete process.env.PIBOT_TEST_PROMPTCAP;
      delete process.env.PIBOT_TEST_SESSION_ID;
      if (before === undefined) delete process.env.PIBOT_PI_CLI; else process.env.PIBOT_PI_CLI = before;
      clearSessions("report-pickup:" + PICKUP_ID);
      clearSessions(MAIL_THREAD);
    }
  });

  test("a pickup turn never escalates, and its def's spawn_env never reaches it (an unlocked turn of the same bot keeps both)", async () => {
    clearSessions("report-pickup:" + PICKUP_ID);
    const escalatePaths = capturePaths("pickup-env-escalate");
    // A capture the stub writes as it handles the prompt. Any path the child can write works: the
    // forced launch starts it unwrapped, outside every sandbox.
    const promptPath = join(CAPTURE_DIR, "prompt-pickup-escalate.json");
    process.env.PIBOT_TEST_PROMPTCAP = promptPath;
    process.env.PIBOT_TEST_SESSION_ID = "pickup-session-1";
    try {
      let escalateResult = null;
      await pickupTier(async () => {
        // escbot has a cloud ESCALATION model; envbot's def carries a spawn_env marker.
        escalateResult = await handleInbound({
          ...inbound({
            botId: "escbot", gatewayType: "report-pickup", thread: "report-pickup:" + PICKUP_ID,
            userMessage: "!escalate answer the comment",
          }),
          lockedTurn: pickupOption({ botId: "escbot" }),
        });
      }, { botId: "escbot" });
      assertPastTheFloor(escalateResult, escalatePaths);
      const { argv } = toolsOf(escalatePaths.argvPath);
      assert.equal(argv.join(" ").includes("cloudy"), false, "the cloud escalation model is never spawned: " + argv.join(" "));
      assert.ok(argv.join(" ").includes("stub"), "the turn ran the local default");
      const prompt = JSON.parse(readFileSync(promptPath, "utf8")).prompt;
      assert.equal(prompt.includes("!escalate"), false, "the token is stripped before the prompt");
      assert.ok(prompt.includes("answer the comment"), "the caller's words are still there");

      let envResult = null;
      const envPaths = capturePaths("pickup-env-spawnenv");
      await pickupTier(async () => {
        envResult = await handleInbound({
          ...inbound({
            botId: "envbot", gatewayType: "report-pickup", thread: "report-pickup:" + PICKUP_ID,
            userMessage: "answer the comment",
          }),
          lockedTurn: pickupOption({ botId: "envbot" }),
        });
      }, { botId: "envbot" });
      assertPastTheFloor(envResult, envPaths);
      const turnEnv = JSON.parse(readFileSync(envPaths.envPath, "utf8"));
      assert.equal(turnEnv.DRAFT_TEST_MARKER, undefined, "no def.spawn_env key reaches a pickup turn");
      assert.equal(turnEnv.PI_BOT_SECRET_VALUES_FD, undefined, "and no card-values fd");
      // The one env name a contained launch is allowed to add is the MASKING file (the card values as
      // a file pi-lab reads), which every sandboxed spawn gets — locked or not — so a locked turn gets
      // nothing its unlocked control would not (the fd is the card SET, and that is the gate below).
      assert.deepEqual(Object.keys(turnEnv).filter((k) => k !== "PI_BOT_SECRET_VALUES_FILE"), [],
        "and nothing else the stub could see: " + JSON.stringify(turnEnv));

      // THE CONTROL, so the empty capture above cannot pass for the wrong reason: an UNLOCKED turn of
      // the same bot DOES get its def's spawn_env (the capture really fires, and only the locked turn
      // is stripped of it). It is not a locked turn, so no tier rule touches it.
      const control = capturePaths("env-control");
      await handleInbound(inbound({ botId: "envbot", gatewayType: "gmail", thread: "envbot-chat-thread", userMessage: "hello" }));
      const controlEnv = JSON.parse(readFileSync(control.envPath, "utf8"));
      assert.equal(controlEnv.DRAFT_TEST_MARKER, "1", "an unlocked channel turn keeps its def's spawn_env");
    } finally {
      delete process.env.PIBOT_TEST_PROMPTCAP;
      delete process.env.PIBOT_TEST_SESSION_ID;
      clearSessions("report-pickup:" + PICKUP_ID);
      clearSessions("envbot-chat-thread");
      clearSessions(MAIL_THREAD);
    }
  });

  test("a pickup turn gets no card-values fd, while an unlocked turn of the same bot does", async () => {
    // The REAL seam for the card set: the values payload is gated on `!lockedSpawn && hidden &&
    // piLabSupportsSecretValuesFd()` (bridge.mjs PiRpc). `hidden` is the launch's own mask report (a
    // secrets dir masked, or — in the contain tier — absent from the empty root), and the pi-lab arm is
    // the fd-support marker in its secret-mask.ts, which a fake pi-lab checkout with the marker
    // supplies, exactly as pibot-secret-values-spawn.test.js does it. Both turns below run under the
    // SAME forced contained launch (forcedLaunch), so the one thing that differs between them is the
    // turn's kind — which is the whole point — and this states the same thing on every host.
    const fakePiLab = join(ROOT, "fake-pi-lab");
    mkdirSync(join(fakePiLab, "extensions", "shared"), { recursive: true });
    writeFileSync(join(fakePiLab, "extensions", "shared", "secret-mask.ts"),
      "export const SECRET_VALUES_FD_SUPPORT = 1;\n");
    // The secrets dir has to EXIST: the values file is written into it, and an absent one is not a
    // secrets dir to hide.
    mkdirSync(join(CROW_HOME, "secrets"), { recursive: true, mode: 0o700 });
    const before = {
      sandbox: process.env.CROW_PI_SANDBOX, piLab: process.env.PIBOT_PI_LAB_DIR, session: process.env.PIBOT_TEST_SESSION_ID,
    };
    process.env.CROW_PI_SANDBOX = "auto";
    process.env.PIBOT_PI_LAB_DIR = fakePiLab;
    process.env.PIBOT_TEST_SESSION_ID = "pickup-env-fd";
    try {
      const unlocked = capturePaths("env-fd-unlocked");
      await forcedLaunch(() => handleInbound(
        inbound({ botId: "envbot", gatewayType: "gmail", thread: "envbot-chat-thread", userMessage: "hello" })));
      const unlockedEnv = JSON.parse(readFileSync(unlocked.envPath, "utf8"));

      clearSessions(PICKUP_THREAD);
      const locked = capturePaths("env-fd-locked");
      let lockedResult = null;
      await pickupTier(async () => {
        lockedResult = await handleInbound({
          ...inbound({
            botId: "envbot", gatewayType: "report-pickup", thread: PICKUP_THREAD,
            userMessage: "answer the comment",
          }),
          lockedTurn: pickupOption({ botId: "envbot" }),
        });
      }, { botId: "envbot" });

      // The card SET never reaches a locked turn: that is the fd below, and only the fd half is gated
      // on !lockedSpawn. The values FILE (PI_BOT_SECRET_VALUES_FILE) is a different thing: it is a
      // MASKING file, and the bridge sets it for every sandboxed spawn of every kind
      // (`if (hidden && secretValues)`), locked or not — pre-existing behaviour, exactly as the
      // mail-draft kind has it. A locked turn therefore gets nothing EXTRA, not nothing: it must see
      // the very same masking file its unlocked control saw.
      assertPastTheFloor(lockedResult, locked);
      const lockedEnv = JSON.parse(readFileSync(locked.envPath, "utf8"));
      assert.equal(lockedEnv.PI_BOT_SECRET_VALUES_FD, undefined, "a locked turn never gets the card set on an fd");
      assert.equal(lockedEnv.DRAFT_TEST_MARKER, undefined, "and still none of the def's spawn_env");
      assert.notEqual(unlockedEnv.PI_BOT_SECRET_VALUES_FILE, undefined,
        "the control really was a sandboxed spawn whose mask report made `hidden` true");
      assert.equal(lockedEnv.PI_BOT_SECRET_VALUES_FILE, unlockedEnv.PI_BOT_SECRET_VALUES_FILE,
        "the values FILE is only a masking file every sandboxed spawn gets: the locked turn's is never more than the unlocked control's");

      // THE CONTROL: the same containment, the same bot, an UNLOCKED turn — and it does get the card
      // set, on the engine's own fd number.
      assert.equal(unlockedEnv.PI_BOT_SECRET_VALUES_FD, "5",
        "an unlocked turn of the same bot gets the card set on the engine's own fd number");
      assert.equal(unlockedEnv.DRAFT_TEST_MARKER, "1", "and its def's spawn_env");
    } finally {
      for (const [k, v] of [
        ["CROW_PI_SANDBOX", before.sandbox], ["PIBOT_PI_LAB_DIR", before.piLab], ["PIBOT_TEST_SESSION_ID", before.session],
      ]) { if (v === undefined) delete process.env[k]; else process.env[k] = v; }
      clearSessions(PICKUP_THREAD);
      clearSessions("envbot-chat-thread");
    }
  });

  test("the model gate refuses the turn on the model the resolver produced", async () => {
    clearSessions(PICKUP_THREAD);
    const paths = capturePaths("pickup-model");
    let sawResolved = null;
    const result = await pickupTierResult({
      ...inbound({ gatewayType: "report-pickup", thread: PICKUP_THREAD, userMessage: "answer the comment" }),
      lockedTurn: pickupOption({
        checkModel: (resolvedModel) => { sawResolved = resolvedModel; return { ok: false, code: "local_models_only" }; },
      }),
    });
    assert.equal(result.action, "error");
    assert.equal(result.error, "locked turn (report-pickup) model not allowed: local_models_only");
    assert.equal(sawResolved.key, "stub/m1", "the check sees the model handleInbound resolved");
    assert.equal(existsSync(paths.argvPath), false, "nothing was spawned");
    assert.equal(sessionRows(PICKUP_THREAD), 0, "and no session row was stamped");
  });

  test("the kind's local-model floor refuses a cloud model even when the caller's check says yes", async () => {
    // cloudbot's DEFAULT model is the cloud row, so nothing but the floor stands in the way.
    clearSessions(PICKUP_THREAD);
    const paths = capturePaths("pickup-floor-cloud");
    let checkCalls = 0;
    const result = await pickupTierResult({
      ...inbound({ botId: "cloudbot", gatewayType: "report-pickup", thread: PICKUP_THREAD, userMessage: "answer the comment" }),
      lockedTurn: pickupOption({
        botId: "cloudbot",
        checkModel: () => { checkCalls += 1; return { ok: true, local: true, key: "cloudy/m1" }; },
      }),
    }, { botId: "cloudbot" });
    assert.equal(result.action, "error");
    assert.equal(result.error, "locked turn (report-pickup) model not allowed: model_not_local");
    assert.equal(checkCalls, 0, "the floor runs first: a refused floor never consults the caller's check");
    assert.equal(existsSync(paths.argvPath), false, "nothing was spawned");
    assert.equal(sessionRows(PICKUP_THREAD), 0, "and no session row was stamped");
  });

  test("the floor refuses a model whose base URL is a public IP literal", async () => {
    // The row's base URL is a public literal and nothing else could prove it local: the address itself is
    // the refusal (its stored host says "local", so this is the address rule alone).
    clearSessions(PICKUP_THREAD);
    const paths = capturePaths("pickup-floor-public-ip");
    let checkCalls = 0;
    const result = await pickupTierResult({
      ...inbound({ botId: "publiclitbot", gatewayType: "report-pickup", thread: PICKUP_THREAD, userMessage: "answer the comment" }),
      lockedTurn: pickupOption({
        botId: "publiclitbot",
        checkModel: () => { checkCalls += 1; return { ok: true, local: true, key: "publiclit/m1" }; },
      }),
    }, { botId: "publiclitbot" });
    assert.equal(result.action, "error");
    assert.equal(result.error, "locked turn (report-pickup) model not allowed: model_not_local");
    assert.equal(checkCalls, 0, "the floor refuses before the caller's check runs");
    assert.equal(existsSync(paths.argvPath), false, "nothing was spawned");
    assert.equal(sessionRows(PICKUP_THREAD), 0, "and no session row was stamped");
  });

  test("the floor refuses a model whose provider row is STORED as host cloud, though its base URL looks local", async () => {
    clearSessions(PICKUP_THREAD);
    const paths = capturePaths("pickup-floor-stored-cloud");
    const result = await pickupTierResult({
      ...inbound({ botId: "liarbot", gatewayType: "report-pickup", thread: PICKUP_THREAD, userMessage: "answer the comment" }),
      lockedTurn: pickupOption({
        botId: "liarbot",
        checkModel: () => ({ ok: true, local: true, key: "liar/m1" }),
      }),
    }, { botId: "liarbot" });
    // THE CONTROL below is a MAIL turn (unchanged by the pickup's tier rule).
    assert.equal(result.action, "error");
    assert.equal(result.error, "locked turn (report-pickup) model not allowed: model_not_local",
      "a stored host:cloud is cloud whatever the base URL says");
    assert.equal(existsSync(paths.argvPath), false, "nothing was spawned");
    assert.equal(sessionRows(PICKUP_THREAD), 0, "and no session row was stamped");

    // THE CONTROL: the mail-draft kind has no floor, so the same model on a mail turn is not refused by
    // that rule (mail's own gate is the caller's check, which says yes here).
    clearSessions(MAIL_THREAD);
    const mailPaths = capturePaths("mail-stored-cloud");
    let checkCalls = 0;
    const mailResult = await handleInbound({
      ...inbound({ botId: "liarbot", thread: MAIL_THREAD }),
      draftingTurn: mailOption({
        botId: "liarbot",
        checkModel: () => { checkCalls += 1; return { ok: true, local: true, key: "liar/m1" }; },
      }),
    });
    assert.notEqual(mailResult.action, "error", "the mail kind's model gate is unchanged");
    assert.equal(checkCalls, 1, "mail's own gate is still the caller's check");
    assert.ok(toolsOf(mailPaths.argvPath).argv.join(" ").includes("liar"),
      "the mail turn really spawned that model");
    clearSessions(MAIL_THREAD);
  });

  test("a role ref is resolved before the floor, and a role bound to a cloud model is refused", async () => {
    // THE REAL SEAM: `handleInbound` resolves `role:<id>` to a raw key through the role resolver, so the
    // floor never sees a role ref for a role that RESOLVES. The local binding below is the control that
    // proves that path is wired (the resolved key is stub/m1 and the turn runs); the cloud binding then
    // proves the floor refuses the resolved model.
    setRoleBinding("everyday", "stub/m1");
    clearSessions(PICKUP_THREAD);
    const localPaths = capturePaths("pickup-floor-role-local");
    let sawResolved = null;
    const localResult = await pickupTierResult({
      ...inbound({ botId: "rolebot", gatewayType: "report-pickup", thread: PICKUP_THREAD, userMessage: "answer the comment" }),
      lockedTurn: pickupOption({
        botId: "rolebot",
        checkModel: (resolved) => { sawResolved = resolved; return { ok: true, local: true, key: resolved.key }; },
      }),
    }, { botId: "rolebot" });
    // The floor did not refuse the resolved model and the launch was not refused by the tier rule (both
    // happen before PiRpc exists), and the stub's argv capture proves the turn really got as far as the
    // spawn — the same proof every other contained test here uses.
    assertPastTheFloor(localResult, localPaths);
    assert.ok(sawResolved, "the caller's check ran, so the floor had let the model through");
    assert.equal(sawResolved.key, "stub/m1", "the resolver turned the role ref into its raw key before the floor");
    assert.equal(sawResolved.role, "everyday", "and the resolved handle names the role it walked");
    assert.equal(toolsOf(localPaths.argvPath).csv, PICKUP_CSV,
      "and the turn it spawned is still the pickup's three tools");
    clearSessions(PICKUP_THREAD);

    setRoleBinding("everyday", "cloudy/m1");
    const cloudPaths = capturePaths("pickup-floor-role-cloud");
    let checkCalls = 0;
    const cloudResult = await pickupTierResult({
      ...inbound({ botId: "rolebot", gatewayType: "report-pickup", thread: PICKUP_THREAD, userMessage: "answer the comment" }),
      lockedTurn: pickupOption({
        botId: "rolebot",
        checkModel: () => { checkCalls += 1; return { ok: true, local: true, key: "cloudy/m1" }; },
      }),
    }, { botId: "rolebot" });
    assert.equal(cloudResult.action, "error");
    assert.equal(cloudResult.error, "locked turn (report-pickup) model not allowed: model_not_local",
      "the role resolved to a cloud provider, so the floor refused it");
    assert.equal(checkCalls, 0, "the floor refuses before the caller's check runs");
    assert.equal(existsSync(cloudPaths.argvPath), false, "nothing was spawned");
    assert.equal(sessionRows(PICKUP_THREAD), 0, "and no session row was stamped");
  });

  test("the same pickup turn on a local model passes the floor and spawns", async () => {
    clearSessions(PICKUP_THREAD);
    const paths = capturePaths("pickup-floor-local");
    let checkCalls = 0;
    let result = null;
    await pickupTier(async () => {
      result = await handleInbound({
        ...inbound({ gatewayType: "report-pickup", thread: PICKUP_THREAD, userMessage: "answer the comment" }),
        lockedTurn: pickupOption({
          checkModel: () => { checkCalls += 1; return { ok: true, local: true, key: "stub/m1" }; },
        }),
      });
    });
    assertPastTheFloor(result, paths);
    assert.equal(checkCalls, 1, "the caller's own check still runs after the floor passes");
    assert.equal(toolsOf(paths.argvPath).csv, PICKUP_CSV, "still the pickup's three tools");
    clearSessions(PICKUP_THREAD);
  });

  test("both the floor and the caller's check must pass: a local model the caller refuses is refused", async () => {
    clearSessions(PICKUP_THREAD);
    const paths = capturePaths("pickup-floor-and-check");
    const result = await pickupTierResult({
      ...inbound({ gatewayType: "report-pickup", thread: PICKUP_THREAD, userMessage: "answer the comment" }),
      lockedTurn: pickupOption({ checkModel: () => ({ ok: false, code: "local_models_only" }) }),
    });
    assert.equal(result.action, "error");
    assert.equal(result.error, "locked turn (report-pickup) model not allowed: local_models_only");
    assert.equal(existsSync(paths.argvPath), false, "nothing was spawned");
    assert.equal(sessionRows(PICKUP_THREAD), 0, "and no session row was stamped");
  });

  test("the floor fails closed when no providers row can prove the model local", async () => {
    clearSessions(PICKUP_THREAD);
    const paths = capturePaths("pickup-floor-noproviders");
    // Empty the instance's providers table: nothing is left that could prove any model local (the
    // model still resolves, from the models file). The rows come back in the finally.
    const drop = new Database(CROW_DB);
    const saved = drop.prepare("SELECT * FROM providers").all();
    drop.prepare("DELETE FROM providers").run();
    drop.close();
    try {
      const result = await pickupTierResult({
        ...inbound({ gatewayType: "report-pickup", thread: PICKUP_THREAD, userMessage: "answer the comment" }),
        lockedTurn: pickupOption(),
      });
      assert.equal(result.action, "error");
      assert.equal(result.error, "locked turn (report-pickup) model not allowed: model_not_local",
        "no row proves the model local, so the floor refuses");
      assert.equal(existsSync(paths.argvPath), false, "nothing was spawned");
    } finally {
      const restore = new Database(CROW_DB);
      const cols = Object.keys(saved[0] || { id: "" });
      const ins = restore.prepare("INSERT OR REPLACE INTO providers (" + cols.join(",") + ") VALUES ("
        + cols.map(() => "?").join(",") + ")");
      for (const row of saved) ins.run(...cols.map((col) => row[col]));
      restore.close();
    }
    assert.equal(sessionRows(PICKUP_THREAD), 0, "and no session row was stamped");
  });

  test("the mail-draft kind has no floor: a cloud model still runs exactly as before", async () => {
    // Mail's own gate is the CALLER's check (turn.js allowDraftModelKey); the row carries no floor, so
    // an always-ok check on a cloud model produces the same turn it produced before the pickup kind.
    clearSessions(MAIL_THREAD);
    const paths = capturePaths("mail-no-floor");
    let checkCalls = 0;
    await handleInbound({
      ...inbound({ botId: "cloudbot", thread: MAIL_THREAD }),
      draftingTurn: mailOption({
        botId: "cloudbot",
        checkModel: () => { checkCalls += 1; return { ok: true, local: false, key: "cloudy/m1" }; },
      }),
    });
    assert.equal(checkCalls, 1, "mail's own gate is still the caller's check, exactly as before");
    const { argv, csv } = toolsOf(paths.argvPath);
    assert.ok(argv.join(" ").includes("cloudy"), "the cloud model really was spawned: " + argv.join(" "));
    assert.equal(csv, [
      "mcp__crow-mail-draft__mail_draft_propose",
      "mcp__crow-mail-draft__mail_draft_read_context",
      "mcp__crow-mail-draft__mail_draft_read_thread",
    ].join(","));
    clearSessions(MAIL_THREAD);
  });

  test("a pickup turn fires no post-turn skill review, even with skill_learning auto", async () => {
    // The same rule mail-draft's own turn test pins, for the other locked kind: a locked turn's
    // transcript carries text people OUTSIDE this instance wrote (a pickup's comments), and the review
    // resolves its own model and gets the bot's spawn_env — so in `skill_learning: auto` mode a review
    // here would turn outside text into standing instructions.
    const seen = [];
    const prev = _setSkillReviewForTest((args) => { seen.push(args); return Promise.resolve(); });
    try {
      clearSessions(PICKUP_THREAD);
      const paths = capturePaths("pickup-skill-review");
      let result = null;
      await pickupTier(async () => {
        result = await handleInbound({
          ...inbound({
            botId: "reviewbot", gatewayType: "report-pickup", thread: PICKUP_THREAD,
            userMessage: "answer the comment",
          }),
          lockedTurn: pickupOption({ botId: "reviewbot" }),
        });
      }, { botId: "reviewbot" });
      assertPastTheFloor(result, paths);
      assert.equal(result.action, "asked", "the pickup turn itself still ran");
      assert.deepEqual(seen, [], "the locked turn carries outside text, so no review is fired");
    } finally {
      _setSkillReviewForTest(prev);
      clearSessions(PICKUP_THREAD);
    }
  });

  test("an ordinary unlocked turn of that same bot still fires the post-turn skill review", async () => {
    // The control for the case above: without it, a bridge that never reviews anything would pass.
    // The seam is NOT forced here and no contain selection is made: this is the plain tier, a plain
    // chat thread, and the bot with `skill_learning: auto` the pickup test used.
    const seen = [];
    const prev = _setSkillReviewForTest((args) => { seen.push(args); return Promise.resolve(); });
    const thread = "reviewbot-chat-thread";
    try {
      capturePaths("pickup-skill-review-control");
      const result = await handleInbound({
        bot_id: "reviewbot", gateway_type: "gmail", gateway_thread_id: thread,
        user_message: "hello", log: () => {}, sendReply: async () => {},
      });
      assert.equal(result.action, "asked", "the plain turn reaches the asked/executed branch");
      assert.equal(seen.length, 1, "exactly one review is fired");
      assert.equal(seen[0].bot_id, "reviewbot");
      assert.equal(seen[0].transcript.user, "hello", "and it is handed this turn's transcript");
    } finally {
      _setSkillReviewForTest(prev);
      clearSessions(thread);
    }
  });

  test("a mail-draft turn is untouched by the pickup kind", async () => {
    // The same bot, the same bridge: the mail door still gets its own three tools and its own dir.
    clearSessions(MAIL_THREAD);
    const paths = capturePaths("mail-untouched");
    await handleInbound({ ...inbound(), draftingTurn: mailOption() });
    const { argv, csv } = toolsOf(paths.argvPath);
    assert.equal(csv, [
      "mcp__crow-mail-draft__mail_draft_propose",
      "mcp__crow-mail-draft__mail_draft_read_context",
      "mcp__crow-mail-draft__mail_draft_read_thread",
    ].join(","));
    assert.ok(argv.includes(join(MAIL_DIR, "sessions")), "the mail turn's own session dir");
    assert.ok(!argv.join(" ").includes(REPORT_PICKUP_TURNS_DIRNAME), "never the pickup turns root");
    clearSessions(MAIL_THREAD);
  });
});

/* =========================================================== the exports that must not drift */

test("every mail-draft export still answers with the same value", () => {
  assert.equal(MAIL_DRAFT_SERVER, "crow-mail-draft");
  assert.equal(MAIL_DRAFT_TURNS_DIRNAME, "mail-draft-turns");
  assert.deepEqual([...DRAFTING_TURN_TOOLS], [
    "mcp__crow-mail-draft__mail_draft_propose",
    "mcp__crow-mail-draft__mail_draft_read_context",
    "mcp__crow-mail-draft__mail_draft_read_thread",
  ]);
  assert.ok(Object.isFrozen(DRAFTING_TURN_TOOLS));
  assert.equal(isDraftingTurnTools([...DRAFTING_TURN_TOOLS]), true);
  assert.equal(isDraftingTurnTools(["read"]), false);
  const block = mailDraftBlock({ botId: "draftbot", draftId: DRAFT_ID, turnId: TURN_ID, token: MDT, port: 3999 });
  assert.equal(block.url, "http://127.0.0.1:3999/mail-draft/mcp");
  assert.equal(mailDraftTurnDir(CROW_HOME, "draftbot", DRAFT_ID), MAIL_DIR);
  assert.equal(resolvedMailDraftTurnDir(CROW_HOME, "draftbot", DRAFT_ID), MAIL_DIR);
  assert.deepEqual(Object.keys(draftingTurnMcpConfig(block, { canonical: { mcpServers: {} } }).mcpServers), [MAIL_DRAFT_SERVER]);
  assert.throws(() => mailDraftBlock({ botId: "draftbot", draftId: DRAFT_ID, turnId: TURN_ID, token: RPK }),
    /needs a turn token \(mdt_ and 32 bytes as hex\)/);
  assert.throws(() => mailDraftBlock({ botId: "draftbot", draftId: DRAFT_ID, turnId: TURN_ID, token: MDT, port: 0 - 1 }),
    (err) => err instanceof TypeError);
});