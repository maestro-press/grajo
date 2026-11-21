/**
 * The bot sharing door's trail (bot_sharing_audit): one row per call, written by the door whether the
 * call was allowed or refused.
 *
 * What a row says, and what it deliberately cannot say:
 *
 *   - WHO ASKED: `bot_id`, and the `thread`/`gateway` the signed actor named. A door call is signed
 *     (servers/gateway/sharing-bot-mcp.js refuses an unsigned one), so these are a real bot's real
 *     turn, not a claim in a body.
 *   - WHAT: `tool`, and `target` — a contact's crow id, or a group's numeric id as text.
 *   - WHETHER: `outcome`. `read` for a pure read (the contact list, the transform table, the inbox),
 *     `drafted` for a draft this call created, `revised` for one it updated, and `refused:<code>` for
 *     anything the rules said no to (`not_allowed`, `pubkey_changed`, `blocked`,
 *     `owner_draft_open`, `owner_edited`, `rate_limited`, `group_changed`, `acl_unreadable`, …).
 *   - WHAT IT LEFT: `draft_id` for a draft, and `refs_json` for a read — the ids the inbox returned,
 *     the ids of the bot's OWN drafts whose state moved (`draft_updates`), plus the cursor it answered
 *     with, `{"ids":[…],"drafts":[…],"cursor":"p12.r3.d1767225600000"}`. Ids only.
 *
 * THERE IS NO COLUMN FOR TEXT, and none is ever passed here. A bot's words live in `message_drafts`
 * (and, once the owner sends, in `messages`/`room_messages`); the audit is the record an operator (or
 * the bot's activity view) reads without touching anything anybody wrote. `refs_json` is therefore
 * also validated on the way in: it is JSON built HERE from ids, never a caller's string.
 *
 * The same table is the rate cap's bookkeeping: a bot's drafts in the last hour are counted from the
 * rows it left (countDraftsSince), so the cap survives a gateway restart and is visible to the owner as
 * the same trail. There is no in-memory window to lose. THE RESIDUAL: this table lives in crow.db, which
 * a contained bot has read-write, so a bot writing the database directly can delete its own rows and
 * lower that count — the cap binds a bot's own turns, not a bot with a SQL prompt. The cap's value
 * (`rate.per_hour`) is in the allow-list file under `secrets/`, which no bot can reach.
 *
 * `outcome` is validated in JS against a small shape (`read`, `drafted`, `revised`,
 * `refused:<code>` with a bounded code), never by a CHECK: a new refusal word must not need a
 * migration.
 *
 * LOCAL ONLY (instance-sync's LOCAL_ONLY_TABLES): the targets are this instance's contacts.
 */

/** The outcomes a row may carry besides `refused:<code>`. */
export const BOT_SHARING_OUTCOMES = Object.freeze(["read", "drafted", "revised"]);

/** The outcomes the rate cap counts: both are a draft the bot left for the owner. */
export const DRAFT_OUTCOMES = Object.freeze(["drafted", "revised"]);

const CODE_RE = /^[a-z][a-z0-9_]{0,39}$/;
const TOOL_RE = /^[a-z][a-z0-9_]{0,59}$/;
const TARGET_MAX = 200;

/** A caller's refusal, or an internal bug: never a value from a message. */
export class AuditError extends Error {
  constructor(detail) {
    super(`BAD_INPUT:${detail}`);
    this.name = "AuditError";
    this.code = "BAD_INPUT";
    this.detail = detail;
  }
}

function requireOutcome(value) {
  if (typeof value === "string" && BOT_SHARING_OUTCOMES.includes(value)) return value;
  if (typeof value === "string") {
    const match = /^refused:(.+)$/.exec(value);
    if (match && CODE_RE.test(match[1])) return value;
  }
  throw new AuditError("outcome");
}

/** `{ids, drafts, cursor}` from ids and a cursor string: the ONLY shape refs_json may hold. */
export function inboxRefs(ids, cursor, draftIds = null) {
  // An inbox id is `p<message id>` or `r<room message id>`; a draft id is exactly what the message
  // draft store mints. Anything else is not an id this Crow issued, so it cannot ride into the trail
  // (a caller's own text included).
  const ID_RE = /^[pr][0-9]{1,12}$/;
  const DRAFT_RE = /^msgd-[0-9a-f]{32}$/;
  const list = (Array.isArray(ids) ? ids : [])
    .map((id) => (typeof id === "string" ? id.trim() : ""))
    .filter((id) => ID_RE.test(id))
    .slice(0, 500);
  const refs = { ids: list };
  // The bot's own draft ids whose state this read reported (`draft_updates`): which drafts a bot was
  // told about, never their words.
  const drafts = (Array.isArray(draftIds) ? draftIds : [])
    .map((id) => (typeof id === "string" ? id.trim() : ""))
    .filter((id) => DRAFT_RE.test(id))
    .slice(0, 200);
  if (drafts.length) refs.drafts = drafts;
  // A cursor is `p<id>.r<id>` plus the optional compound draft mark `.d<epoch ms>.i<draft id>`; the
  // longest one this Crow mints is well under 100 characters (see sharing-bot/inbox.js).
  if (typeof cursor === "string" && cursor !== "" && cursor.length <= 128) refs.cursor = cursor;
  return refs;
}

/**
 * Write one door call. Answers the row id.
 *
 * @param {object} db
 * @param {{botId: string, thread?: string|null, gateway?: string|null, tool: string,
 *   target?: string|number|null, outcome: string, draftId?: string|null,
 *   refs?: {ids: string[], cursor?: string}|null, ts: number}} row
 * @returns {Promise<number>}
 */
export async function recordBotSharingCall(db, row = {}) {
  const botId = typeof row.botId === "string" ? row.botId.trim() : "";
  if (!botId || botId.length > 120) throw new AuditError("botId");
  const tool = typeof row.tool === "string" ? row.tool.trim() : "";
  if (!TOOL_RE.test(tool)) throw new AuditError("tool");
  const outcome = requireOutcome(row.outcome);
  const ts = Number(row.ts);
  if (!Number.isFinite(ts) || ts < 0) throw new AuditError("ts");
  const thread = row.thread == null || row.thread === "" ? null : String(row.thread).slice(0, 200);
  const gateway = row.gateway == null || row.gateway === "" ? null : String(row.gateway).slice(0, 60);
  const target = row.target == null || row.target === ""
    ? null
    : String(row.target).slice(0, TARGET_MAX);
  const draftId = row.draftId == null || row.draftId === "" ? null : String(row.draftId).slice(0, 120);
  // refs_json is JSON this module builds from ids; a caller cannot hand it a free-form string.
  const refsJson = row.refs && typeof row.refs === "object"
    ? JSON.stringify(inboxRefs(row.refs.ids, row.refs.cursor, row.refs.drafts))
    : null;
  const res = await db.execute({
    sql: `INSERT INTO bot_sharing_audit
            (bot_id, thread, gateway, tool, target, outcome, draft_id, refs_json, ts)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    args: [botId, thread, gateway, tool, target, outcome, draftId, refsJson, Math.floor(ts)],
  });
  return Number(res.lastInsertRowid) || 0;
}

/**
 * How many drafts this bot left since `sinceTs` (epoch ms). The rate cap is read from the trail
 * itself, so it survives a restart, cannot be reset by the bot, and needs no module state a
 * per-session MCP server instance would lose.
 */
export async function countDraftsSince(db, botId, sinceTs) {
  const { rows } = await db.execute({
    sql: `SELECT COUNT(*) AS n FROM bot_sharing_audit
           WHERE bot_id = ? AND ts >= ? AND outcome IN ('drafted', 'revised')`,
    args: [String(botId), Math.floor(Number(sinceTs))],
  });
  return Number(rows?.[0]?.n) || 0;
}

/**
 * One bot's trail, newest first — the bot's activity view part 2 can draw, and what these tests read.
 * Rows are returned as they were written: ids and words about the call, never the message.
 */
export async function listBotSharingCalls(db, botId, { limit = 50 } = {}) {
  const cap = Number.isInteger(limit) && limit > 0 ? Math.min(limit, 200) : 50;
  const { rows } = await db.execute({
    sql: `SELECT id, bot_id, thread, gateway, tool, target, outcome, draft_id, refs_json, ts
            FROM bot_sharing_audit WHERE bot_id = ? ORDER BY ts DESC, id DESC LIMIT ?`,
    args: [String(botId), cap],
  });
  return (rows || []).map((row) => ({
    id: Number(row.id),
    botId: row.bot_id,
    thread: row.thread ?? null,
    gateway: row.gateway ?? null,
    tool: row.tool,
    target: row.target ?? null,
    outcome: row.outcome,
    draftId: row.draft_id ?? null,
    refs: row.refs_json ? safeJson(row.refs_json) : null,
    ts: Number(row.ts),
  }));
}

function safeJson(text) {
  try {
    return JSON.parse(text);
  } catch {
    return null;
  }
}