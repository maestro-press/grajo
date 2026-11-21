/**
 * The bot sharing door is MOUNTED BY THE GATEWAY'S OWN BOOT STEP, through a dynamic import inside a
 * try/catch (servers/gateway/boot/mcp-mounts.js):
 *
 *     try {
 *       const { createSharingBotServer, sharingBotMountAuth } = await import("../sharing-bot-mcp.js");
 *       app.use("/sharing-bot", sharingBotMountAuth({ … }));
 *       mountMcpServer(app, "/sharing-bot", () => createSharingBotServer({ … }), …);
 *     } catch (err) {
 *       console.warn(`[gateway] sharing-bot mount skipped: ${err.message}`);
 *     }
 *
 * That catch is right (a bad door must never stop the gateway from booting) and it is also the one
 * failure no other test in the suite can see: every door test imports `sharing-bot-mcp.js` DIRECTLY, so
 * a syntax error, a missing export, or a renamed symbol would leave them all green while production
 * quietly booted without a door at all — the bots' only way to draft a message would be gone, and the
 * only trace would be one warning line.
 *
 * So this file pins the seam between the two files: the module mcp-mounts.js imports resolves, it
 * exports exactly the two names that mount destructures (plus the mount prefix the routes are keyed
 * on), and the block that does the mounting is still there — naming the same prefix, in an
 * `app.use`/`mountMcpServer` pair, and warning (not failing silently) when it cannot load.
 *
 * `mountMcpServers` itself is deliberately NOT called: it eagerly constructs the sharing managers
 * (`createSharingServer` starts Hyperswarm, Nostr and the sync manager) and mints every boot token, so
 * it is a whole gateway boot, not a unit test's dependency. What can silently drop the door is the
 * import and the names in it, and those are what this test exercises for real.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "sharing-bot-mount-"));
process.env.CROW_HOME = join(root, "home");
process.env.CROW_DATA_DIR = join(root, "data");
delete process.env.CROW_DB_PATH;

after(() => {
  rmSync(root, { recursive: true, force: true });
});

const MOUNTS = new URL("../servers/gateway/boot/mcp-mounts.js", import.meta.url);

/** The one block in mcp-mounts.js that mounts the sharing door: from its comment to the next mount. */
function sharingMountBlock() {
  const src = readFileSync(MOUNTS, "utf8");
  const start = src.indexOf("// Bot sharing door");
  assert.ok(start >= 0, "mcp-mounts.js still has a bot sharing door block");
  const end = src.indexOf("// Phone bundle", start);
  assert.ok(end > start, "the sharing block is closed by the next mount");
  return src.slice(start, end);
}

test("the module the boot step imports resolves, with the exports the mount destructures", async () => {
  // The dynamic import from the boot module — the exact specifier it uses.
  const door = await import("../servers/gateway/sharing-bot-mcp.js");
  assert.equal(typeof door.createSharingBotServer, "function",
    "createSharingBotServer is what the mount hands to mountMcpServer");
  assert.equal(typeof door.sharingBotMountAuth, "function",
    "sharingBotMountAuth is the guard installed in front of the mount");
  assert.equal(door.SHARING_BOT_MCP_PREFIX, "/sharing-bot", "the prefix the guard and the mount are keyed on");
  assert.deepEqual([...door.SHARING_BOT_TOOL_NAMES].sort(),
    ["crow_bot_inbox", "crow_list_contacts", "crow_list_crosspost_transforms", "crow_send_group_message", "crow_send_message"]);
});

test("the boot block mounts it at /sharing-bot, and says so when it cannot", () => {
  const block = sharingMountBlock();
  assert.match(block, /await import\("\.\.\/sharing-bot-mcp\.js"\)/,
    "the boot step imports the door module by the specifier this test just imported");
  assert.match(block, /\{\s*createSharingBotServer,\s*sharingBotMountAuth\s*\}\s*=\s*await import/,
    "and destructures exactly the two names asserted above");

  const guarded = [...block.matchAll(/app\.use\("([^"]+)"/g)].map((m) => m[1]);
  const mounted = [...block.matchAll(/mountMcpServer\(app,\s*"([^"]+)"/g)].map((m) => m[1]);
  assert.deepEqual(guarded, ["/sharing-bot"], "the guard is installed on the door's prefix");
  assert.deepEqual(mounted, ["/sharing-bot"], "and the MCP mount is on the same one");

  assert.match(block, /mountMcpServer\(app,\s*"\/sharing-bot",\s*\(\)\s*=>\s*createSharingBotServer\(/,
    "the mount builds the door server, not some other factory");
  assert.match(block, /sharingBotMountAuth\(\{[^}]*verifyActor:\s*verifySharingActorSig/,
    "and the guard verifies the sharing actor kind, not one of the other doors' signatures");
  // A failure is logged, never silent (the catch that makes the missing-door case invisible to every
  // direct-import test, which is why this file exists).
  assert.match(block, /catch \(err\)\s*\{[^}]*console\.warn\([^)]*sharing-bot mount skipped/,
    "a failed import warns instead of dropping the door without a word");
});

test("the guard the mount installs refuses an unsigned request before any handler", async () => {
  const { sharingBotMountAuth } = await import("../servers/gateway/sharing-bot-mcp.js");
  const seen = [];
  const res = {
    status(code) { seen.push(code); return res; },
    json() { return res; },
  };
  // No bearer at all: refused before the token is even validated (no db client is used).
  let nexted = false;
  const guard = sharingBotMountAuth({ createDb: () => { throw new Error("no db client needed"); } });
  await guard({ headers: {} }, res, () => { nexted = true; });
  assert.deepEqual(seen, [401]);
  assert.equal(nexted, false, "nothing downstream ran");
});