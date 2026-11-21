/**
 * One door call, end to end, without MCP: the tool's rules, the per-bot allow-list, the rate cap, and
 * exactly one `bot_sharing_audit` row — allowed or refused.
 *
 * This is the module the door's five tools are thin wrappers over (servers/gateway/sharing-bot-mcp.js),
 * and it exists so the rules can be tested as a unit: `runDoorCall` takes claims and arguments and
 * answers a plain result. Nothing here knows about MCP, HTTP, tokens or actors; the caller has already
 * refused an unsigned caller and pinned `{botId, threadId, gatewayType}`.
 *
 * Four invariants, and where each is kept:
 *
 *   - ONE AUDIT ROW PER CALL, ALWAYS. The row is written here, in `finally`-like fashion, for a draft,
 *     a read, a refusal and an internal error alike (outcome `refused:error`). A caller cannot forget
 *     it, because there is no other path that reaches a rule.
 *   - DRAFTS ONLY. The only tools that change anything are the two that write a `message_drafts` row
 *     (messages.js). Nothing in this module can send, and none of its imports can.
 *   - THE CAP COUNTS THE TRAIL. Drafts per hour come from `countDraftsSince` on the same table, not from
 *     memory: the cap survives a restart and the operator can audit what it counted.
 *   - THE ALLOW-LIST IS READ PER CALL. `secrets/sharing-bot-acl.json` is re-read on every call (it is
 *     small, and a revoked permission has to take effect on the next call, not at the next boot), and a
 *     file that cannot be read is `acl_unreadable` — never "no restrictions".
 */
import { readBotAcl } from "./acl.js";
import { countDraftsSince, inboxRefs, recordBotSharingCall } from "./audit.js";
import { botDisplayName, draftGroupMessage, draftPeerMessage, listContacts } from "./messages.js";
import { readBotInbox } from "./inbox.js";
import { SUPPORTED_PAIRS } from "../crossposting/transforms.js";
import { resolveCrowHome } from "../../shared/crow-home.js";

/** The five door tools, in the order the server registers them. */
export const DOOR_TOOL_NAMES = Object.freeze([
  "crow_send_message",
  "crow_send_group_message",
  "crow_list_contacts",
  "crow_bot_inbox",
  "crow_list_crosspost_transforms",
]);

/** The window the draft cap is measured over. */
export const RATE_WINDOW_MS = 3_600_000;

/** `{draft_id, status}`: what both send tools answer. Nothing was sent; the owner has it. */
export const AWAITING_OWNER = "awaiting_owner";

/** A caller's clock: a number, a function, or the wall clock. Never negative, always finite. */
function clockOf(now) {
  const raw = typeof now === "function" ? now() : now;
  const at = Math.floor(Number(raw == null ? Date.now() : raw));
  return Number.isFinite(at) && at >= 0 ? at : Date.now();
}

/**
 * Run one door call.
 *
 * @param {object} db
 * @param {{tool: string, claims: {botId: string, threadId?: string|null, gatewayType?: string|null},
 *   args?: object}} call
 * @param {{crowHome?: string|Function, now?: Function|number, loadSeed?: Function, emit?: Function}} [options]
 * @returns {Promise<{ok: true, data: object, outcome: string, target?: string|null,
 *   draftId?: string|null, refs?: object|null} | {ok: false, code: string, target?: string|null}>}
 */
export async function runDoorCall(db, call, options = {}) {
  const tool = String(call?.tool ?? "");
  const claims = call?.claims || {};
  const args = call?.args && typeof call.args === "object" ? call.args : {};
  const botId = String(claims.botId ?? "");
  if (!DOOR_TOOL_NAMES.includes(tool) || !botId) {
    // Not reachable from the mount (it refuses an unknown tool and an unsigned caller first), and not
    // worth an audit row that names no bot.
    return { ok: false, code: "unauthorized" };
  }

  const at = clockOf(options.now);
  const home = (typeof options.crowHome === "function" ? options.crowHome() : options.crowHome) || resolveCrowHome();
  let outcome = "refused:error";
  let target = null;
  let draftId = null;
  let refs = null;
  let result;

  try {
    result = await dispatch(db, { tool, botId, args, home, at, options });
    if (result.ok) {
      outcome = result.outcome;
      target = result.target ?? null;
      draftId = result.draftId ?? null;
      refs = result.refs && typeof result.refs === "object"
        ? inboxRefs(result.refs.ids, result.refs.cursor, result.refs.drafts)
        : null;
    } else {
      outcome = `refused:${result.code}`;
      target = result.target ?? null;
    }
  } catch (err) {
    // A bug on the Crow side, not the bot's. One fixed outcome, and the log carries the detail.
    console.warn(`[sharing-bot] ${tool} failed: ${err && err.message ? err.message : err}`);
    result = { ok: false, code: "error" };
    outcome = "refused:error";
  }

  try {
    await recordBotSharingCall(db, {
      botId,
      thread: claims.threadId == null ? null : String(claims.threadId),
      gateway: claims.gatewayType == null ? null : String(claims.gatewayType),
      tool,
      target,
      outcome,
      draftId,
      refs,
      ts: at,
    });
  } catch (err) {
    // The answer still goes back (the work happened), but never silently: a trail that cannot be
    // written is a broken door.
    console.warn(`[sharing-bot] audit row for ${tool} was not written: ${err && err.message ? err.message : err}`);
  }

  return result;
}

/** The bot's allow-list entry, or the reason there is none (both are refusals, never "allow all"). */
function aclFor(home, botId) {
  const read = readBotAcl(home, botId);
  if (read.ok) return { entry: read.entry, aclFailure: null };
  return { entry: null, aclFailure: read.reason === "unreadable" ? "unreadable" : "missing" };
}

/** The rate cap, read from the trail: drafts (created or revised) this bot left in the window. */
async function usedThisHour(db, botId, at) {
  return countDraftsSince(db, botId, at - RATE_WINDOW_MS);
}

async function dispatch(db, { tool, botId, args, home, at, options }) {
  if (tool === "crow_list_crosspost_transforms") {
    return { ok: true, data: { pairs: SUPPORTED_PAIRS }, outcome: "read" };
  }

  const { entry, aclFailure } = aclFor(home, botId);

  if (tool === "crow_list_contacts") {
    if (aclFailure === "unreadable") return { ok: false, code: "acl_unreadable" };
    if (!entry) return { ok: false, code: "no_allowlist" };
    return { ok: true, data: await listContacts(db, entry), outcome: "read" };
  }

  if (tool === "crow_bot_inbox") {
    const page = await readBotInbox(db, {
      entry, aclFailure, botId, cursor: args.cursor ?? null, limit: args.limit,
    });
    if (!page.ok) return { ok: false, code: page.code };
    return {
      ok: true,
      // `draft_updates` is ids and state words only: the bot's own drafts, when they moved. No line
      // of a draft's text ever rides back here.
      data: { messages: page.items, draft_updates: page.draftUpdates, cursor: page.cursor },
      outcome: "read",
      refs: { ids: page.ids, drafts: page.draftIds, cursor: page.cursor },
    };
  }

  // The two drafting tools: they share the bot's budget, the bot's name snapshot and the same rules.
  const botName = await botDisplayName(db, botId);
  const used = entry ? await usedThisHour(db, botId, at) : 0;
  const draft = tool === "crow_send_group_message"
    ? await draftGroupMessage(db, {
      botId, botName, entry, aclFailure, group: args.group, message: args.message,
      now: at, usedThisHour: used, loadSeed: options.loadSeed, emit: options.emit,
    })
    : await draftPeerMessage(db, {
      botId, botName, entry, aclFailure, contact: args.contact, message: args.message,
      now: at, usedThisHour: used, loadSeed: options.loadSeed, emit: options.emit,
    });
  if (!draft.ok) return { ok: false, code: draft.code, target: draft.target ?? null };
  return {
    ok: true,
    data: {
      draft_id: draft.draftId,
      status: AWAITING_OWNER,
      to: draft.label,
      draft: draft.outcome === "revised" ? "revised" : "created",
    },
    outcome: draft.outcome,
    target: draft.target,
    draftId: draft.draftId,
  };
}