/**
 * Shared bot .mcp.json regeneration (M3b sessionDir rule). Used by the Bot
 * Builder's regen_mcp action and the F4a Layer 3 federation patch endpoint, so
 * both write the bot's MCP config to the exact path the bridge will run from.
 */
import { writeBotMcp } from "../../../../scripts/pi-bots/mcp_writer.mjs";
import { botHoldsLiveShare } from "../../../shared/project-bot-shares.js";
import { readVerifiedBotDef } from "../../../shared/bot-def-store.js";
import { resolveCrowHome } from "../../../../scripts/pi-bots/ext_registry.mjs";
import { mcpConfigDelivery } from "../../../../scripts/pi-bots/mcp-delivery.mjs";
import { worldRootFor } from "../../../../scripts/pi-bots/world-root.mjs";
import { addSkillToolsGuarded } from "../../../../scripts/pi-bots/skill-tools.mjs";

/**
 * Resolve the sessionDir pi runs from — the bot's world root, by the same
 * rule the bridge uses (worldRootFor): project workspace wins, then
 * def.session_dir, then <crowHome>/pi-bots/<botId>.
 */
export async function resolveBotSessionDir(db, botId, def, projectId, crowHome = resolveCrowHome()) {
  let workspaceDir = null;
  if (projectId != null) {
    const ws = (await db.execute({
      sql: "SELECT workspace_dir FROM project_spaces WHERE id=?",
      args: [projectId],
    })).rows[0];
    workspaceDir = (ws && ws.workspace_dir) || null;
  }
  return worldRootFor({ workspaceDir, def, crowHome, botId });
}

/**
 * Regenerate the bot's .mcp.json from its current def+project. Returns
 * writeBotMcp's result WITHOUT the built config (`json` carries signed actor
 * headers and bearer tokens; callers only report path/servers/warnings).
 * S6-CROW: in fd delivery mode nothing is written — the bridge builds and
 * pipes the config per turn — so this validates the selection, removes any
 * stale on-disk copy, and returns path: null.
 *
 * AUTHORITY: the definition decides `session_dir` (the world root pi runs from) and the credentials a
 * regenerated config carries, and a contained bot can write the row — so it is read VERIFIED
 * (servers/shared/bot-def-store.js). An unverified row refuses with the route's existing
 * `bot_not_found` diagnostic (plus the `[bot-def]` line) rather than writing credentials anywhere.
 */
export async function regenerateBotMcp(db, botId, opts = {}) {
  const read = await readVerifiedBotDef(db, botId);
  if (!read.ok) {
    if (read.reason !== "unknown-bot") {
      console.warn(
        `[bot-def] ${botId} was changed outside Crow; review it with `
        + `\`node scripts/cli/bot-def-reapprove.mjs ${botId} --show\``
        + ` (${read.reason}); the MCP config was not regenerated`,
      );
      const err = new Error("bot_not_found");
      err.code = "BOT_DEF_UNVERIFIED";
      throw err;
    }
    throw new Error("bot_not_found");
  }
  const row = read.row;
  const stored = JSON.parse(row.definition || "{}");
  const crowHome = resolveCrowHome();
  // the same repo-skill tool union a spawn applies (bot-world.mjs), so a
  // regenerated config matches what the bot runs with
  let def = stored;
  try { def = (await addSkillToolsGuarded(stored, { crowHome, repoSkillsDir: opts.repoSkillsDir })).def; }
  catch (e) { console.warn("[bot-mcp-regen] skill tools skipped: " + ((e && e.message) || e)); }
  const sessionDir = await resolveBotSessionDir(db, botId, def, row.project_id, crowHome);
  // Phase 1 shares: a bot holding a live share gets no remote-proxy blocks (mcp_writer.mjs). The
  // panel has the DB, so it asks the store's own rule — a re-granted or revoked share is reflected
  // at the next regeneration. FAIL CLOSED: a read error counts as a share, so a broken read can
  // never hand the proxy blocks back; only a DB that predates the table (`no such table`) is "no
  // share".
  let holdsShare = true;
  try { holdsShare = await botHoldsLiveShare(db, botId); } catch (err) { holdsShare = !/no such table/i.test(String((err && err.message) || "")); }
  // The bot's identity rides along: every stdio block the regenerated file carries gets the
  // actor env, exactly as a bridge-written config does (a file with no actor would let its
  // servers resolve the caller from whatever env they happen to inherit).
  const r = writeBotMcp(def, { sessionDir, crowHome, botId, displayName: row.display_name, holdsShare,
    write: mcpConfigDelivery() === "file" });
  const { json: _omit, ...safe } = r;
  return safe;
}
