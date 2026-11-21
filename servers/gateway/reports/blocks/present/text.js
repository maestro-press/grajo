/**
 * The `text` present block: the recipe's own words, with a few numbers filled in.
 *
 * Settings: `{content: string, heading?: string}` (a legacy `text` key is read too). The markdown is the
 * author's; only `{{count}}`, `{{newCount}}` and `{{date}}` are substituted, and every other `{{...}}`
 * stays exactly as written. `{{date}}` is the run's own day (`YYYY-MM-DD`).
 *
 * WHO WROTE IT MATTERS. `saveRecipe` stamps `authoredBy: "owner"|"bot"` on the block when its text or
 * its heading changed in that save, and the stamp rides inside the block object, so it is covered by the
 * recipe hashes. An owner-written block is shown as written. Everything else goes through
 * `neutralizeLinks` against the run's own items, exactly as AI commentary does: a bot-written block, and a
 * block with no stamp at all (a recipe written before the stamp existed, or a row inserted straight into
 * the database). Only an explicit owner stamp keeps its links, so until the owner edits the block, nobody
 * else can put a link in the report that the report's data does not carry. The same pass demotes every
 * heading in that text (`demoteHeadings`), so only an owner's own body may carry one.
 *
 * The HEADING is the recipe's own words and is untrusted whichever stamp the body carries, so it always
 * goes through `escapeRecipeText` (a heading reading `Listings www.evil.example` is not a link). Only an
 * owner-stamped block renders it as a real `##` heading; every other stamp renders it as a bold
 * paragraph, so a bot's heading cannot read as the fixed report's own or as the AI attribution line.
 */
import { escapeRecipeText, itemLinks, runDayText } from "../../document.js";
import { neutralizeLinks } from "../../email/neutralize-links.js";

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

/** The block's authored markdown, from whichever setting key it uses. */
export function textSetting(settings) {
  if (!isPlainObject(settings)) return "";
  if (typeof settings.content === "string") return settings.content;
  if (typeof settings.text === "string") return settings.text;
  return "";
}

function validate(settings) {
  if (!isPlainObject(settings)) return ["settings"];
  const errors = [];
  // An empty text block is valid (it renders nothing); a non-string body is not.
  for (const key of ["content", "text"]) {
    if (Object.hasOwn(settings, key) && typeof settings[key] !== "string") errors.push(key);
  }
  if (Object.hasOwn(settings, "heading") && typeof settings.heading !== "string") errors.push("heading");
  return errors;
}

/** The text with the three placeholders filled in. Nothing else is touched. */
export function fillPlaceholders(body, { count = 0, newCount = 0, date = "" } = {}) {
  return String(body)
    .replace(/\{\{\s*count\s*\}\}/g, String(count))
    .replace(/\{\{\s*newCount\s*\}\}/g, String(newCount))
    .replace(/\{\{\s*date\s*\}\}/g, String(date));
}

function run(ctx, input) {
  const settings = isPlainObject(ctx.block?.settings) ? ctx.block.settings : {};
  const items = Array.isArray(input?.items) ? input.items : [];
  const sections = Array.isArray(input?.sections) ? input.sections : [];
  const count = items.length;
  const newCount = items.filter((item) => isPlainObject(item) && item._diff === "new").length;
  const date = runDayText(ctx.run, ctx.deps);
  let body = fillPlaceholders(textSetting(settings), { count, newCount, date });
  // Only an explicit owner stamp is trusted. A missing stamp (a legacy block, or one that was never
  // stamped) is neutralised like a bot's text: it has not proved that an owner wrote it, so its body
  // loses its links AND its headings (the section's own heading is the recipe's, and stays one).
  if (ctx.block?.authoredBy !== "owner") {
    body = neutralizeLinks(body, itemLinks(items), { demoteHeadings: true });
  }

  const parts = [];
  if (typeof settings.heading === "string" && settings.heading.trim()) {
    const heading = escapeRecipeText(settings.heading.trim());
    parts.push(ctx.block?.authoredBy === "owner" ? `## ${heading}` : `**${heading}**`);
  }
  parts.push(body);
  const markdown = parts.join("\n\n");

  const section = { type: "text", blockId: ctx.blockId, markdown };
  // The stamp rides on the section so the assembly can tell an owner's own markdown (which keeps its links
  // and headings) from every other text block's, without a second read of the recipe.
  if (ctx.block?.authoredBy === "owner") section.authoredBy = "owner";
  return { items, sections: [...sections, section] };
}

export const textBlock = Object.freeze({
  type: "text",
  kind: "present",
  sourceBearing: false,
  validate,
  run,
});