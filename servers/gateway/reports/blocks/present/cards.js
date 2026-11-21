/**
 * The `cards` present block: the run's items as a list of cards, one list item per card.
 *
 * Settings: `{fields: string[], maxRows?: number (default 200), heading?: string}`. The first field is
 * the card's bold line, the rest are nested lines under it (`- label: value`). The escaping and the link
 * rule are the table's (`cellMarkdown`): escaped markdown, and a link only for a whole http(s) URL. A run
 * with more items than `maxRows` cards ends with `and <n> more`.
 *
 * The heading and the field names are the recipe's own words (`escapeRecipeText`, as in the table): a
 * bot-authored recipe must not be able to put a link, a line break or a heading marker in a card.
 */
import { cellMarkdown, escapeRecipeText, readItemField } from "../../document.js";
import { DEFAULT_MAX_ROWS, moreLine } from "./table.js";

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function isFieldList(value) {
  return Array.isArray(value) && value.length > 0
    && value.every((entry) => typeof entry === "string" && entry.trim() !== "");
}

function validate(settings) {
  if (!isPlainObject(settings)) return ["settings"];
  const errors = [];
  if (!isFieldList(settings.fields)) errors.push("fields");
  if (Object.hasOwn(settings, "maxRows")
    && !(Number.isInteger(settings.maxRows) && settings.maxRows > 0)) errors.push("maxRows");
  if (Object.hasOwn(settings, "heading") && typeof settings.heading !== "string") errors.push("heading");
  return errors;
}

function run(ctx, input) {
  const settings = isPlainObject(ctx.block?.settings) ? ctx.block.settings : {};
  const fields = isFieldList(settings.fields) ? settings.fields : [];
  const maxRows = Number.isInteger(settings.maxRows) && settings.maxRows > 0
    ? settings.maxRows
    : DEFAULT_MAX_ROWS;
  const items = Array.isArray(input?.items) ? input.items : [];
  const sections = Array.isArray(input?.sections) ? input.sections : [];
  const shown = items.slice(0, maxRows);

  const lines = [];
  if (typeof settings.heading === "string" && settings.heading.trim()) {
    lines.push(`## ${escapeRecipeText(settings.heading.trim())}`);
    lines.push("");
  }
  const [first, ...rest] = fields;
  for (const item of shown) {
    lines.push(`- ${first ? `**${escapeRecipeText(first)}**: ${cellMarkdown(readItemField(item, first))}` : ""}`);
    for (const field of rest) {
      lines.push(`  - ${escapeRecipeText(field)}: ${cellMarkdown(readItemField(item, field))}`);
    }
  }
  const more = moreLine(items.length - shown.length);
  if (more) {
    lines.push("");
    lines.push(more);
  }

  const section = { type: "cards", blockId: ctx.blockId, markdown: lines.join("\n") };
  return { items, sections: [...sections, section] };
}

export const cardsBlock = Object.freeze({
  type: "cards",
  kind: "present",
  sourceBearing: false,
  validate,
  run,
});