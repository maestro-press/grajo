// The bot catalog's reports entry (scripts/pi-bots/crow-server-catalog.mjs and mcp_writer.mjs): a bot
// gets the DOOR — an http `{url, headers}` block at this instance's /reports/mcp, under the reports
// token and a signed `reports` actor — and never a spawned server under that name, because no Crow
// server carries it.
//
// Selection is unchanged: like every catalog entry the block reaches a bot's config only when the
// bot's def selects `reports` (buildBotMcp's closed-world pass), and a def that selects nothing gets
// no reports block at all.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  REPORTS_SERVER, crowServerCatalog, instanceBinding,
} from "../scripts/pi-bots/crow-server-catalog.mjs";
import { buildBotMcp, writeBotMcp, serversForBot } from "../scripts/pi-bots/mcp_writer.mjs";
import {
  initGatewayActorKey, signReportsActor, signSharingActor, verifyReportsActorSig, verifySharingActorSig,
  _resetActorKeyForTest,
} from "../scripts/pi-bots/actor-sig.mjs";

const T = mkdtempSync(join(tmpdir(), "crow-reports-door-"));
after(() => {
  _resetActorKeyForTest();
  rmSync(T, { recursive: true, force: true });
});

const CROW_HOME = join(T, ".crow-door");
mkdirSync(join(CROW_HOME, "data"), { recursive: true });
mkdirSync(join(CROW_HOME, "secrets"), { recursive: true, mode: 0o700 });
const TOKEN = "e".repeat(64);
writeFileSync(join(CROW_HOME, "secrets", "reports-token"), TOKEN + "\n", { mode: 0o600 });

/** A def that names the reports tools (both spellings pi uses), and one that names nothing. */
const REPORTS_DEF = {
  bot_id: "hank",
  session_dir: join(T, "sessions", "hank"),
  tools: { pi_builtin: ["read"], crow_mcp: ["reports/crow_report_create", "reports__crow_report_status"] },
  permission_policy: { bash: "deny", write_paths: [], read_paths: [] },
};
const PLAIN_DEF = {
  bot_id: "plain",
  session_dir: join(T, "sessions", "plain"),
  tools: { pi_builtin: ["read"], crow_mcp: ["crow-memory/search_memories"] },
  permission_policy: { bash: "deny", write_paths: [], read_paths: [] },
};

test("with the token, a key and this turn's bot, the catalog offers the DOOR as an http block", () => {
  _resetActorKeyForTest();
  initGatewayActorKey();
  const { servers, unconfigured, coreNames } = crowServerCatalog(CROW_HOME, {
    binding: instanceBinding(CROW_HOME), botId: "hank", threadId: "perch-1", gatewayType: "perch", gatewayPort: 3999,
  });
  const block = servers[REPORTS_SERVER];
  assert.equal(REPORTS_SERVER, "reports", "a bot's tools are mcp__reports__*");
  assert.ok(block, "the reports entry is offered");
  assert.equal(block.command, undefined, "never a stdio spawn");
  assert.equal(block.url, "http://127.0.0.1:3999/reports/mcp");
  assert.equal(block.headers.Authorization, "Bearer " + TOKEN);
  assert.equal(block.headers["X-Crow-Actor-Kind"], "reports");
  assert.equal(block.headers["X-Crow-Actor-Id"], "hank");
  assert.equal(block.headers["X-Crow-Actor-Thread"], "perch-1");
  assert.equal(block.headers["X-Crow-Actor-Gateway"], "perch");
  assert.equal(block.headers["X-Crow-Actor-Sig"], signReportsActor({ botId: "hank", threadId: "perch-1", gatewayType: "perch" }));
  assert.equal(verifyReportsActorSig({
    botId: "hank", threadId: "perch-1", gatewayType: "perch", sig: block.headers["X-Crow-Actor-Sig"],
  }), true, "the block's signature is the tuple's");
  assert.ok(coreNames.includes(REPORTS_SERVER), "and the Bot Builder's probe surface knows it");
  assert.equal(unconfigured[REPORTS_SERVER], undefined, "a door that is offered needs no reason line");
});

test("no token, no key, or no bot id: no door block, and no unconfigured note either", () => {
  // No actor key: a block could not be signed, so it is not emitted.
  _resetActorKeyForTest();
  let catalog = crowServerCatalog(CROW_HOME, { binding: instanceBinding(CROW_HOME), botId: "hank" });
  assert.equal(catalog.servers[REPORTS_SERVER], undefined);
  assert.equal(catalog.unconfigured[REPORTS_SERVER], undefined, "nothing else changes");

  // With a key but no bot id (a GUI/CLI validation build): still no block.
  initGatewayActorKey();
  catalog = crowServerCatalog(CROW_HOME, { binding: instanceBinding(CROW_HOME) });
  assert.equal(catalog.servers[REPORTS_SERVER], undefined);
  assert.equal(catalog.unconfigured[REPORTS_SERVER], undefined);

  // A bot id but no token file at all.
  const tokenless = join(T, ".crow-tokenless");
  mkdirSync(join(tokenless, "data"), { recursive: true });
  const noToken = crowServerCatalog(tokenless, { binding: instanceBinding(tokenless), botId: "hank" });
  assert.equal(noToken.servers[REPORTS_SERVER], undefined);
  assert.equal(noToken.unconfigured[REPORTS_SERVER], undefined);
  assert.equal(noToken.coreNames.includes(REPORTS_SERVER), false, "and it is not offered to the probe either");
});

test("the reports and sharing signatures never cross over", () => {
  _resetActorKeyForTest();
  initGatewayActorKey();
  try {
    const tuple = { botId: "hank", threadId: "perch-1", gatewayType: "perch" };
    const reports = signReportsActor(tuple);
    const sharing = signSharingActor(tuple);
    assert.ok(reports && sharing);
    assert.notEqual(reports, sharing, "each kind has its own MAC domain");
    assert.equal(verifyReportsActorSig({ ...tuple, sig: reports }), true);
    assert.equal(verifySharingActorSig({ ...tuple, sig: sharing }), true);
    assert.equal(verifyReportsActorSig({ ...tuple, sig: sharing }), false, "a sharing signature is not a reports one");
    assert.equal(verifySharingActorSig({ ...tuple, sig: reports }), false, "nor the reverse");
  } finally {
    _resetActorKeyForTest();
  }
});

test("a def that selects reports gets the door and never a stdio server under that name", () => {
  _resetActorKeyForTest();
  initGatewayActorKey();
  const { servers: catalog, unconfigured } = crowServerCatalog(CROW_HOME, {
    binding: instanceBinding(CROW_HOME), botId: "hank", threadId: "perch-1", gatewayType: "perch",
  });
  const built = buildBotMcp(REPORTS_DEF, { mcpServers: {} }, {
    catalog, unconfigured, binding: instanceBinding(CROW_HOME), crowHome: CROW_HOME, interactive: true,
  });
  const block = built.json.mcpServers[REPORTS_SERVER];
  assert.ok(block && block.url, "the door block is active");
  assert.equal(block.disabled, undefined);
  assert.ok(built.servers.includes(REPORTS_SERVER));
  for (const [name, candidate] of Object.entries(built.json.mcpServers)) {
    if (!candidate || candidate.disabled) continue;
    assert.equal(candidate.command, undefined, `${name} must not be a spawned server`);
  }
  assert.deepEqual(serversForBot(REPORTS_DEF).sort(), ["reports", "reports__crow_report_status"],
    "both spellings of the selection reduce to the catalog name");
});

test("a def that does NOT select reports gets no reports block at all", () => {
  _resetActorKeyForTest();
  initGatewayActorKey();
  const { servers: catalog, unconfigured } = crowServerCatalog(CROW_HOME, {
    binding: instanceBinding(CROW_HOME), botId: "plain", threadId: "perch-2", gatewayType: "perch",
  });
  const built = buildBotMcp(PLAIN_DEF, { mcpServers: {} }, {
    catalog, unconfigured, binding: instanceBinding(CROW_HOME), crowHome: CROW_HOME,
  });
  assert.equal(built.json.mcpServers[REPORTS_SERVER], undefined, "not even a disabled marker");
  assert.equal(built.servers.includes(REPORTS_SERVER), false);
});

test("a written .mcp.json carries the door for a reports bot", () => {
  _resetActorKeyForTest();
  initGatewayActorKey();
  const res = writeBotMcp(REPORTS_DEF, {
    canonical: { mcpServers: {} }, crowHome: CROW_HOME, binding: instanceBinding(CROW_HOME),
    sessionDir: REPORTS_DEF.session_dir, write: true, botId: "hank", threadId: "perch-1", gatewayType: "perch",
  });
  const written = JSON.parse(readFileSync(join(REPORTS_DEF.session_dir, ".mcp.json"), "utf8"));
  assert.match(written.mcpServers[REPORTS_SERVER].url, /\/reports\/mcp$/);
  assert.equal(written.mcpServers[REPORTS_SERVER].headers["X-Crow-Actor-Kind"], "reports");
  assert.equal(written.mcpServers[REPORTS_SERVER].command, undefined);
  assert.ok(res.servers.includes(REPORTS_SERVER));
});