/**
 * The bot sharing door's audit table, DDL constant only (side-effect free, no imports). One shape,
 * two rails: scripts/init-db.js and scripts/migrations/0037-bot-sharing-audit.mjs both build from
 * this string, the same convention MESSAGE_DRAFTS_DDL and REPORTS_SEND_DDL follow.
 *
 * `bot_sharing_audit` is one row per call to the bot door (servers/gateway/sharing-bot-mcp.js, the
 * narrow MCP mount at /sharing-bot/mcp). It answers three questions an operator has about a bot that
 * can write messages: what did it ask for, was it allowed, and which draft (if any) did the call
 * leave behind.
 *
 *   - WHAT: `bot_id`, `thread` and `gateway` name the actor the call was signed with (the door
 *     refuses an unsigned caller outright, so every row has a real bot behind it), `tool` names the
 *     door tool, and `target` is who the call was aimed at — a contact's crow id, or a group's
 *     numeric id as text.
 *   - WAS IT ALLOWED: `outcome` is `read`, `drafted`, `revised`, or `refused:<code>` (the code is the
 *     door's own refusal word: `not_allowed`, `pubkey_changed`, `blocked`, `owner_draft_open`,
 *     `owner_edited`, `rate_limited`, …). The refusal codes are validated in JS, never by a CHECK.
 *   - WHAT DID IT LEAVE: `draft_id` is the row the call created or revised, and `refs_json` carries
 *     the ids a read returned plus the cursor it answered with (the inbox's `{ids, cursor}`).
 *
 * NEVER TEXT. There is no column for a message body, a subject, a recipient's name or their key:
 * a door call's words land in `message_drafts` (and, after the owner sends, in `messages` /
 * `room_messages`), which is where a reader with database access already knows to look. The audit is
 * the WHAT and the WHETHER, so it can be read and shared without carrying anything the operator wrote
 * or a bot drafted. `refs_json` therefore holds ids only.
 *
 * Epoch-ms `ts`. No foreign keys: a draft lives in another table and is kept after its conversation
 * moves on, and an audit row for a refused call names no draft at all.
 *
 * LOCAL ONLY: `bot_sharing_audit` is in instance-sync's LOCAL_ONLY_TABLES and never in
 * SYNCED_TABLES. The allow-list it is judged against lives in this instance's `secrets/` directory,
 * the targets are this instance's contact ids, and nothing about another instance's bots belongs on a
 * peer.
 *
 * Additive, no SCHEMA_GENERATION bump: init-db.js runs this string on its own rail, so a co-hosted
 * instance converging on its own restart gets it too. DDL only: nothing to backfill, and no schema
 * object or row is removed.
 */
export const BOT_SHARING_AUDIT_DDL = `
  CREATE TABLE IF NOT EXISTS bot_sharing_audit (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    bot_id TEXT NOT NULL,
    thread TEXT,
    gateway TEXT,
    tool TEXT NOT NULL,
    target TEXT,
    outcome TEXT NOT NULL,
    draft_id TEXT,
    refs_json TEXT,
    ts INTEGER NOT NULL
  );

  CREATE INDEX IF NOT EXISTS idx_bot_sharing_audit_bot_ts
    ON bot_sharing_audit(bot_id, ts DESC);

  CREATE INDEX IF NOT EXISTS idx_bot_sharing_audit_draft
    ON bot_sharing_audit(draft_id);

  CREATE INDEX IF NOT EXISTS idx_bot_sharing_audit_outcome
    ON bot_sharing_audit(bot_id, outcome, ts DESC);
`;

/** The one table this DDL owns. Exported so the migration, its test and the sync policy agree. */
export const BOT_SHARING_AUDIT_TABLES = Object.freeze(["bot_sharing_audit"]);