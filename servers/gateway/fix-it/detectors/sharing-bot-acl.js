/**
 * Fix-it detector: an enabled bot whose definition still selects `crow-sharing` but which has no
 * Sharing allow-list entry — so every message tool it calls refuses with `no_allowlist`.
 *
 * The door (servers/gateway/sharing-bot-mcp.js) narrows a bot to the contacts and rooms in
 * `<CROW_HOME>/secrets/sharing-bot-acl.json`. That file is written only by the owner (Bot Builder's
 * Sharing section, or the owner route), never seeded by code: a contact id is per install. So a bot
 * that already asks for `crow-sharing/*` — an import, a template, a Bot Builder save before the
 * section existed — starts life unable to message anybody, with the only visible symptom being a
 * refusal in its own turns. This card says it plainly and offers the two things an owner can do:
 * choose who it may message (the Bot Builder page, where the Sharing section lives), or take
 * messaging away from the bot.
 *
 * "SELECTS `crow-sharing`" means any spelling the catalog resolves to that server: the bare server
 * (`crow-sharing`), a tool key (`crow-sharing/crow_send_message`), and pi's own registered spelling
 * (`crow-sharing__crow_send_message`). The reducer the catalog uses (scripts/pi-bots/
 * crow-server-catalog.mjs) folds all three to the server name, so the card must not miss two of them.
 *
 * The card clears ITSELF: an entry in the allow-list (however empty) or a definition that no longer
 * selects `crow-sharing` resolves the item on the next boot pass. An allow-list FILE that cannot be
 * read is not this card's case — the bot did not lose its permission, the file is broken, and undoing
 * the bot's messaging would not fix that.
 *
 * Both card sentences come from the dashboard's i18n table in code, and so do both button labels:
 * this detector stores them in EN, and fix-it/index.js renders the card from code in the dashboard's
 * language (the retired-bundle card's rule), so a Spanish dashboard shows Spanish buttons and title.
 * The bot's display name is the only stored value used, and it is flattened into one line before it
 * goes in — and again before it is rendered.
 */
import { readBotAcl } from "../../sharing-bot/acl.js";
import { BOT_ID_RE } from "../../../../scripts/pi-bots/bot-workspace-env.mjs";
import { fill, t } from "../../dashboard/shared/i18n.js";
import {
  ACTION_ID as REMOVE_ACTION_ID,
  label as removeLabel,
  namesSharingServer,
  sharingSelections,
} from "../remedies/remove-bot-sharing.js";

export const SOURCE = "sharing-bot-acl";

/** One card per bot. */
export const dedupKeyFor = (botId) => `sharing-acl:${botId}`;

/** The link remedy: the Bot Builder page, carrying this bot's id (index.js LINK_REMEDY_TARGETS). */
export const OPEN_BOT_BUILDER_ACTION = "open-bot-builder-page";

const LANG = (lang) => (lang === "es" ? "es" : "en");

/** A name as one plain line: control characters fold to a space, whitespace collapses, capped. */
function oneLine(raw) {
  return String(raw ?? "")
    .replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ")
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 120);
}

// Re-exported: the detector's rule and the remedy's filter are one rule (remove-bot-sharing.js).
export { namesSharingServer, sharingSelections };

/** The card's title, in the dashboard's language. `{bot}` is the bot's display name when it has one,
 *  and otherwise its ID — never a generic English phrase, which would name nobody and would read the
 *  same in a language the card is not being shown in. */
export function cardTitle(botName, botId, lang = "en") {
  return fill(t("botbuilder.sharing.fixitTitle", LANG(lang)), { bot: oneLine(botName) || oneLine(botId) });
}

/** The card's body: what happened, and that nothing was sent. */
export function cardWhy(lang = "en") {
  return t("botbuilder.sharing.intro", LANG(lang));
}

export default {
  source: SOURCE,
  // A def save or an allow-list write emits no event this detector listens to: it is a BOOT check,
  // like the retired-bundle card, and it also clears itself on the next pass.
  events: [],
  async onEvent() {},
  /**
   * One card per enabled bot that selects `crow-sharing` and has no allow-list entry, RESOLVING the
   * card once either side changes. Never throws into boot (runBootChecks isolates a detector).
   *
   * `opts`: { crowHome, readAcl, db } — tests pass their own home and a stub reader; the running
   * gateway takes the defaults (the store's own db client and this process's CROW_HOME).
   */
  async check(store, opts = {}) {
    const db = opts.db || store.db || null;
    if (!db || typeof db.execute !== "function") return { cards: [] };
    const readAcl = typeof opts.readAcl === "function" ? opts.readAcl : readBotAcl;
    let rows = [];
    try {
      ({ rows } = await db.execute({
        sql: "SELECT bot_id, display_name, definition FROM pi_bot_defs WHERE enabled = 1",
        args: [],
      }));
    } catch {
      // No pi_bot_defs (an install that never made a bot): nothing to check.
      return { cards: [] };
    }
    const cards = [];
    for (const row of rows || []) {
      const botId = row && typeof row.bot_id === "string" ? row.bot_id : "";
      if (!botId || !BOT_ID_RE.test(botId)) continue;
      let def = null;
      try { def = JSON.parse(row.definition || "{}"); } catch { def = null; }
      if (!def || !sharingSelections(def).length) {
        try { await store.resolveByKey(SOURCE, dedupKeyFor(botId)); } catch { /* no row yet */ }
        continue;
      }
      const acl = readAcl(opts.crowHome, botId);
      // A file that cannot be read is its own problem, not this card: `unreadable` is skipped rather
      // than read as "no permission" (the door refuses with its own code for it).
      if (acl && acl.ok === false && acl.reason === "unreadable") {
        try { await store.resolveByKey(SOURCE, dedupKeyFor(botId)); } catch { /* no row yet */ }
        continue;
      }
      if (acl && acl.ok === true) {
        try { await store.resolveByKey(SOURCE, dedupKeyFor(botId)); } catch { /* no row yet */ }
        continue;
      }
      const botName = oneLine(row.display_name);
      await store.upsertItem({
        source: SOURCE,
        dedupKey: dedupKeyFor(botId),
        // These three are EN and stay stored that way: the card is rendered from code in the
        // dashboard's own language (fix-it/index.js cardParts, as the retired-bundle card is), and a
        // boot pass has no language to render in. What is stored here is the fallback a non-dashboard
        // reader sees, plus the display name the render needs to write the title with.
        title: cardTitle(botName, botId, "en"),
        why: cardWhy("en"),
        severity: "warn",
        remedies: [
          { actionId: OPEN_BOT_BUILDER_ACTION, kind: "link", label: t("botbuilder.sharing.heading", "en"), args: { bot: botId } },
          { actionId: REMOVE_ACTION_ID, kind: "instant", label: removeLabel("en"), args: { bot: botId } },
        ],
        // `name` is display text only: the render flattens it again (oneLine) and escapes it, and
        // every sentence it lands in comes from the copy table. `bot` stays the id — it is what the
        // link and the undo take, and both re-check it (`BOT_ID_RE`) before acting.
        context: { bot: botId, name: botName },
      });
      cards.push(botId);
    }
    return { cards };
  },
};