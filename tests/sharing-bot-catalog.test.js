// The bot catalog's sharing entry (scripts/pi-bots/crow-server-catalog.mjs and mcp_writer.mjs): a bot
// gets the DOOR — an http `{url, headers}` block at this instance's /sharing-bot/mcp, under the
// sharing-bot token and a signed `sharing` actor — and never the stdio `crow-sharing` server that reads
// the instance's identity.
//
// Selection is unchanged: like every catalog entry the block reaches a bot's config only when the
// bot's def selects `crow-sharing` (buildBotMcp's closed-world pass), and a def that selects nothing
// gets no active sharing block at all. A stdio `crow-sharing` block — the operator's own canonical
// entry — is still disabled for every bot.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  BOT_EXCLUDED_SERVERS, BOT_SHARING_SERVER, SHARING_BOT_DOOR_PATH,
  crowServerCatalog, instanceBinding, isSharingDoorBlock,
} from "../scripts/pi-bots/crow-server-catalog.mjs";
import { buildBotMcp, writeBotMcp, serversForBot } from "../scripts/pi-bots/mcp_writer.mjs";
import { initGatewayActorKey, signSharingActor, _resetActorKeyForTest } from "../scripts/pi-bots/actor-sig.mjs";

const T = mkdtempSync(join(tmpdir(), "crow-sharing-door-"));
after(() => {
  _resetActorKeyForTest();
  rmSync(T, { recursive: true, force: true });
});

const CROW_HOME = join(T, ".crow-door");
mkdirSync(join(CROW_HOME, "data"), { recursive: true });
mkdirSync(join(CROW_HOME, "secrets"), { recursive: true, mode: 0o700 });
const TOKEN = "f".repeat(64);
writeFileSync(join(CROW_HOME, "secrets", "sharing-bot-token"), TOKEN + "\n", { mode: 0o600 });

/** The operator's canonical config: the stdio crow-sharing is what it holds today. */
const CANONICAL = {
  mcpServers: {
    "crow-sharing": { command: "node", args: ["servers/sharing/index.js"], env: { CROW_DB_PATH: "/somewhere/crow.db" } },
    "some-third-party": { command: "node", args: ["srv.js"] },
  },
};

/** A def that names the sharing tools (both spellings pi uses), and one that names nothing. */
const SHARING_DEF = {
  bot_id: "hank",
  session_dir: join(T, "sessions", "hank"),
  tools: { pi_builtin: ["read"], crow_mcp: ["crow-sharing/crow_send_message", "crow-sharing__crow_bot_inbox"] },
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
  const block = servers[BOT_SHARING_SERVER];
  assert.ok(block, "the sharing entry is offered");
  assert.equal(block.command, undefined, "never a stdio spawn");
  assert.equal(block.url, `http://127.0.0.1:3999${SHARING_BOT_DOOR_PATH}`);
  assert.equal(SHARING_BOT_DOOR_PATH, "/sharing-bot/mcp", "the door, never /sharing");
  assert.equal(block.headers.Authorization, "Bearer " + TOKEN);
  assert.equal(block.headers["X-Crow-Actor-Kind"], "sharing");
  assert.equal(block.headers["X-Crow-Actor-Id"], "hank");
  assert.equal(block.headers["X-Crow-Actor-Thread"], "perch-1");
  assert.equal(block.headers["X-Crow-Actor-Gateway"], "perch");
  assert.equal(block.headers["X-Crow-Actor-Sig"], signSharingActor({ botId: "hank", threadId: "perch-1", gatewayType: "perch" }));
  assert.ok(coreNames.includes(BOT_SHARING_SERVER), "and the Bot Builder's probe surface knows it");
  assert.equal(unconfigured[BOT_SHARING_SERVER], undefined);
  assert.equal(isSharingDoorBlock(block), true);
});

test("no token, no key, or no bot id: no door block, and the reason is a line the operator can read", () => {
  // No actor key: a block could not be signed, so it is not emitted.
  _resetActorKeyForTest();
  let catalog = crowServerCatalog(CROW_HOME, { binding: instanceBinding(CROW_HOME), botId: "hank" });
  assert.equal(catalog.servers[BOT_SHARING_SERVER], undefined);
  assert.match(catalog.unconfigured[BOT_SHARING_SERVER], /not available to bots/);

  // With a key but no bot id (a GUI/CLI validation build): still no block.
  initGatewayActorKey();
  catalog = crowServerCatalog(CROW_HOME, { binding: instanceBinding(CROW_HOME) });
  assert.equal(catalog.servers[BOT_SHARING_SERVER], undefined);

  // A bot id but no token file at all.
  const tokenless = join(T, ".crow-tokenless");
  mkdirSync(join(tokenless, "data"), { recursive: true });
  const noToken = crowServerCatalog(tokenless, { binding: instanceBinding(tokenless), botId: "hank" });
  assert.equal(noToken.servers[BOT_SHARING_SERVER], undefined);
  assert.match(noToken.unconfigured[BOT_SHARING_SERVER], /no token/);
});

test("the door block's HOST must be this machine's loopback, not just its path", () => {
  // What the catalog itself mints: this instance's gateway on the loopback interface.
  assert.equal(isSharingDoorBlock({ url: "http://127.0.0.1:3001/sharing-bot/mcp" }), true);
  assert.equal(isSharingDoorBlock({ url: "http://localhost:3001/sharing-bot/mcp/" }), true);
  assert.equal(isSharingDoorBlock({ url: "http://[::1]:3001/sharing-bot/mcp" }), true);
  assert.equal(isSharingDoorBlock({ url: "http://127.0.0.1:3001/sharing-bot/mcp?x=1" }), true,
    "a query string is still the door");
  // The same PATH on another machine is NOT this instance's door: it is somebody else's server wearing
  // the door's address, and a bot handed that block would send the door's bearer and actor headers
  // there. Refused here exactly like a stdio block, so the caller disables it instead.
  for (const url of [
    "https://crow.example.ts.net/sharing-bot/mcp",
    "http://10.0.0.5:3001/sharing-bot/mcp",
    "http://[2001:db8::1]:3001/sharing-bot/mcp",
    "http://127.0.0.1.example.com/sharing-bot/mcp",
    "http://127.0.0.2:3001/sharing-bot/mcp",
    "file:///sharing-bot/mcp",
    "ftp://127.0.0.1/sharing-bot/mcp",
  ]) assert.equal(isSharingDoorBlock({ url }), false, url);
  // And the path still has to be the door's own.
  assert.equal(isSharingDoorBlock({ url: "http://127.0.0.1:3001/sharing/mcp" }), false);
});

test("the operator's stdio crow-sharing is still never handed to a bot", () => {
  // The catalog does not emit the stdio server, under any spelling of the name.
  assert.deepEqual([...BOT_EXCLUDED_SERVERS], ["crow-sharing"]);
  const { servers } = crowServerCatalog(CROW_HOME, { binding: instanceBinding(CROW_HOME), botId: "hank" });
  assert.equal(servers["crow-sharing"].command, undefined, "the entry that exists IS the door");
  assert.equal(isSharingDoorBlock({ command: "node", args: ["servers/sharing/index.js"] }), false);
  assert.equal(isSharingDoorBlock({ url: "http://127.0.0.1:3001/sharing/mcp" }), false, "/sharing is not the door");
});

test("a def that selects sharing gets the door and never a stdio sharing spawn", () => {
  _resetActorKeyForTest();
  initGatewayActorKey();
  const { servers: catalog, unconfigured } = crowServerCatalog(CROW_HOME, {
    binding: instanceBinding(CROW_HOME), botId: "hank", threadId: "perch-1", gatewayType: "perch",
  });
  const built = buildBotMcp(SHARING_DEF, CANONICAL, {
    catalog, unconfigured, binding: instanceBinding(CROW_HOME), crowHome: CROW_HOME, interactive: true,
  });
  const block = built.json.mcpServers[BOT_SHARING_SERVER];
  assert.ok(block && block.url, "the door block is active");
  assert.equal(block.disabled, undefined);
  assert.ok(built.servers.includes(BOT_SHARING_SERVER));
  for (const [name, candidate] of Object.entries(built.json.mcpServers)) {
    if (!candidate || candidate.disabled) continue;
    const argv = [candidate.command, ...(candidate.args || []), candidate.cwd].map((value) => String(value || ""));
    assert.equal(argv.some((value) => /servers\/sharing\b/.test(value)), false, `${name} must not spawn the sharing server`);
  }
  assert.deepEqual(serversForBot(SHARING_DEF).sort(), ["crow-sharing", "crow-sharing__crow_bot_inbox"],
    "both spellings of the selection reduce to the catalog name");
});

test("a def that does NOT select sharing gets no active sharing block at all", () => {
  _resetActorKeyForTest();
  initGatewayActorKey();
  const { servers: catalog, unconfigured } = crowServerCatalog(CROW_HOME, {
    binding: instanceBinding(CROW_HOME), botId: "plain", threadId: "perch-2", gatewayType: "perch",
  });
  const built = buildBotMcp(PLAIN_DEF, CANONICAL, {
    catalog, unconfigured, binding: instanceBinding(CROW_HOME), crowHome: CROW_HOME,
  });
  // The operator's canonical crow-sharing is closed out (a disabled marker), never activated.
  assert.deepEqual(built.json.mcpServers[BOT_SHARING_SERVER], { disabled: true });
  assert.equal(built.servers.includes(BOT_SHARING_SERVER), false);
});

test("a written .mcp.json carries the door for a sharing bot, and a stale stdio canonical entry cannot slip in", () => {
  _resetActorKeyForTest();
  initGatewayActorKey();
  const res = writeBotMcp(SHARING_DEF, {
    canonical: CANONICAL, crowHome: CROW_HOME, binding: instanceBinding(CROW_HOME),
    sessionDir: SHARING_DEF.session_dir, write: true, botId: "hank", threadId: "perch-1", gatewayType: "perch",
  });
  const written = JSON.parse(readFileSync(join(SHARING_DEF.session_dir, ".mcp.json"), "utf8"));
  assert.match(written.mcpServers[BOT_SHARING_SERVER].url, /\/sharing-bot\/mcp$/);
  assert.equal(written.mcpServers[BOT_SHARING_SERVER].headers["X-Crow-Actor-Kind"], "sharing");
  assert.equal(written.mcpServers[BOT_SHARING_SERVER].command, undefined);
  assert.ok(res.servers.includes(BOT_SHARING_SERVER));
});