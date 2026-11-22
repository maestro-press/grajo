/**
 * Fix-it detector: an add-on that could not run inside its wall.
 *
 * The gateway raises this event with the id it refused, one line saying why,
 * and the ref of an in-memory failure record. Nothing here reads a path or a
 * stored value: the reason arrives already built (scripts/addon-sandbox/
 * failures.mjs) and the card carries the ref only, which is what the remedy
 * needs to find the add-on the owner is answering about.
 *
 * Round 2: the reason now travels as a CODE with its values as well as the
 * English sentence (`wallFailureReasonCode`), so the card can render it in the
 * dashboard's language at view time (fix-it/card-copy.js `renderWallReason`).
 * The record keeps the code, and `whyTextForRecord` prefers it.
 *
 * One card per add-on (dedupKey `addon-wall:<id>`), and the count on it says
 * how many times the failure repeated. After the card is stored, the live
 * failure record is bound to it, so the card the owner sees and the record the
 * remedy reads are the same pair.
 */
import { CARD_DEDUP_PREFIX, bindWallFailureCard, DEFAULT_REASON as WALL_DEFAULT_REASON } from "../../../../scripts/addon-sandbox/failures.mjs";
import { fill, t } from "../../dashboard/shared/i18n.js";
import { renderWallReason } from "../card-copy.js";

export const SOURCE = "addon-wall";
export const EVENT = "addon-wall-failed";
/** The card's title, from the dashboard's copy table (one source: the i18n key). */
export const TITLE = t("fixit.addonWall.title", "en");
/** The fallback reason when an event carries none (approved W11 English). */
export const DEFAULT_REASON = WALL_DEFAULT_REASON;

/** An add-on id is one lowercase slug. */
const ADDON_ID_RE = /^[a-z0-9][a-z0-9-]*$/;
/** A record ref is 16 random bytes, hex. */
const REF_RE = /^[0-9a-f]{32}$/;

/**
 * The card's body line for `id` and `reason`, in the dashboard's language. The
 * sentence comes from the copy table; the id and the reason are values.
 */
export function whyText(id, reason, lang = "en") {
  return fill(t("fixit.addonWall.why", lang === "es" ? "es" : "en"), { id, reason });
}

/**
 * The body line for a live failure RECORD: the reason is rendered from its
 * code when the record carries one (so a Spanish dashboard says what a Spanish
 * owner expects), and the English sentence it was recorded with otherwise.
 */
export function whyTextForRecord(record, lang = "en") {
  const language = lang === "es" ? "es" : "en";
  const fromCode = record?.reasonCode ? renderWallReason(record.reasonCode, language) : null;
  const reason = fromCode || (typeof record?.reason === "string" && record.reason ? record.reason : DEFAULT_REASON);
  return whyText(record?.id, reason, language);
}

export default {
  source: SOURCE,
  events: [EVENT],
  async onEvent(eventName, payload, store) {
    if (eventName !== EVENT) return null;
    const id = payload?.id;
    const ref = payload?.ref;
    // A payload that is not one of ours names no add-on and cannot be answered.
    if (typeof id !== "string" || !ADDON_ID_RE.test(id)) return null;
    if (typeof ref !== "string" || !REF_RE.test(ref)) return null;
    const reason = typeof payload.reason === "string" && payload.reason ? payload.reason : DEFAULT_REASON;
    const reasonCode = payload.reasonCode && typeof payload.reasonCode.code === "string" ? payload.reasonCode : null;
    const dedupKey = CARD_DEDUP_PREFIX + id;

    const result = await store.upsertItem({
      source: SOURCE,
      dedupKey,
      title: TITLE,
      // The stored English equals what the record renders in English, so an
      // older reader (and the console) sees the same sentence.
      why: whyTextForRecord({ id, reason, reasonCode }, "en"),
      severity: "warn",
      remedies: [
        // The id lives in the failure record this ref names, never in the args.
        { actionId: "addon-unwall", kind: "instant", label: "Run without the wall", args: { ref } },
        { actionId: "addon-keep-off", kind: "instant", label: "Keep it off", args: {} },
      ],
      context: { addonId: id },
    });
    // Bind the record to the card it became; a later forged card naming this
    // ref is refused because the record already belongs to another item.
    bindWallFailureCard(ref, { itemId: Number(result?.id), dedupKey });
    return { id };
  },
};