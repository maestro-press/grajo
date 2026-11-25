/**
 * What a report pickup's card and suggested change are done WITH.
 *
 * The pickup door (`pickup-mcp.js`) may not import the board service or the approvals module: their
 * import closures reach the bot runtime, the sharing identity module and the secret box, which that door
 * must never reach (tests/mail-no-tap-invariant.test.js case (d)). So the door takes these three
 * functions as an `actions` option, and `boot/mcp-mounts.js` — which is not on the door's import path —
 * loads this module and hands them in.
 *
 *   createCard      one card on the report's bot's board (`createTaskForBot`, the board's own autonomy),
 *                   refused with `project_mismatch` unless the bot's home project is the report's project
 *   saveBotRecipe   `botSaveRecipe`: the bot's save, which lands as the pending free change the owner's
 *                   existing Apply (`POST /:id/apply`) takes
 *   notifyChange    the owner's notice that a change was suggested (copy C1, essential, in the owner's
 *                   language, linking the report page)
 */
import { createDbClient } from "../../db.js";
import { tasksDbPath } from "../../../scripts/pi-bots/instance-paths.mjs";
import { createNotification } from "../../shared/notifications.js";
import { createTaskForBot } from "../board/give-service.js";
import { loadGiveTarget } from "../board/offer-service.js";
import { botSaveRecipe } from "./approvals.js";
import { reportPagePath } from "./links.js";
import { noticeTitleOf } from "./recipient-comments.js";

/** Copy C1: the owner's notice that the bot suggested a change. `{report}` is the report's name. */
export const CHANGE_NOTICE = Object.freeze({
  en: "{report}: the bot suggested a change after a comment. Review it on the report page.",
  es: "{report}: el bot sugirió un cambio a partir de un comentario. Revísalo en la página del informe.",
});

/** The most cards one report's pickups may make in a rolling 24 hours. */
export const DAILY_PICKUP_CARDS = 10;

function refusal(code) {
  return Object.assign(new Error(code), { code });
}

/** A function replacement that cannot read `$` patterns in the report's name. */
function fillReport(template, report) {
  return template.replace("{report}", () => report);
}

/**
 * Make the card. The project check reads the bot's verified home project (the same read the board's own
 * give path uses) and compares it with the report's; any difference is `project_mismatch`.
 */
export async function createCard(db, { botId, reportId, reportProjectId, title, description, tags }) {
  const row = await loadGiveTarget(db, botId);
  if (Number(row.project_id) !== Number(reportProjectId)) throw refusal("project_mismatch");
  const tdb = createDbClient(tasksDbPath());
  try {
    // At most DAILY_PICKUP_CARDS pickup cards per report in any rolling 24 hours, counted from the
    // board's own tagged cards (the in-memory ledger is per pickup and dies with a restart).
    if (reportId) {
      const made = await tdb.execute({
        sql: "SELECT COUNT(*) AS n FROM tasks_items WHERE tags = ? AND created_at >= datetime('now', '-1 day')",
        args: [tags],
      });
      if (Number(made.rows[0]?.n) >= DAILY_PICKUP_CARDS) throw refusal("card_limit");
    }
    const { cardId } = await createTaskForBot(db, tdb, botId, {
      title, description, tags,
      // Not a human: the card's history names the bot, and its audit row says which path made it.
      actor: { kind: "bot", id: botId, jobId: null },
      audit: { via: "report-pickup" },
      autonomy: "gated",
    });
    return { cardId };
  } finally {
    try { tdb.close(); } catch { /* already closed */ }
  }
}

/** The bot's save, exactly as `crow_report_set_recipe` makes it. */
export function saveBotRecipe(db, { reportId, recipe, expectedRev }) {
  return botSaveRecipe(db, {}, { reportId, recipe, expectedRev });
}

/** Ring the owner's bell about a suggested change (copy C1). `deps.notify` is the test seam. */
export async function notifyChange(db, { reportId, lang }, deps = {}) {
  const notify = typeof deps.notify === "function" ? deps.notify : createNotification;
  const { rows } = await db.execute({ sql: "SELECT * FROM reports WHERE id = ?", args: [reportId] });
  const report = rows[0];
  if (!report) return false;
  const language = lang === "es" ? "es" : "en";
  await notify(db, {
    type: "reports",
    source: "reports",
    essential: true,
    priority: "high",
    title: fillReport(CHANGE_NOTICE[language], noticeTitleOf(report)),
    body: null,
    action_url: await reportPagePath(db, report),
    metadata: { reportId, kind: "report-pickup" },
  });
  return true;
}

/** The set boot hands to `createPickupMcpServer({ actions })`. */
export const pickupActions = Object.freeze({ createCard, saveBotRecipe, notifyChange });
