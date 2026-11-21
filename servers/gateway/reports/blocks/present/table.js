/**
 * The `table` present block: the run's items as one markdown table.
 *
 * Settings: `{columns: string[], maxRows?: number (default 200), heading?: string}`. `columns` names the
 * item fields to show, in order (a dotted path walks nested objects). Every cell is escaped markdown
 * (pipes, backticks, brackets and HTML), and a cell that is a whole http(s) URL becomes a link: a
 * `javascript:` or `data:` value is escaped text, so it can never reach a link target. A run with more
 * rows than `maxRows` shows the first `maxRows` and ends with `and <n> more`.
 *
 * The HEADING and the COLUMN NAMES are the recipe's own words, and a recipe is bot-authorable, so both
 * go through `escapeRecipeText`: escaped, one line, and nothing that could autolink (a heading reading
 * `Listings www.evil.example` must not be a link either). A cell's value comes from the run's items and
 * keeps `cellMarkdown`'s rule.
 *
 * The block only arranges data the run already has: it reads nothing, so it is not source-bearing and a
 * failure is a warning, never a failed run.
 */
import { cellMarkdown, escapeRecipeText, readItemField } from "../../document.js";

/** How many rows a table shows when its settings name no `maxRows`. */
export const DEFAULT_MAX_ROWS = 200;

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
  if (!isFieldList(settings.columns)) errors.push("columns");
  if (Object.hasOwn(settings, "maxRows")
    && !(Number.isInteger(settings.maxRows) && settings.maxRows > 0)) errors.push("maxRows");
  if (Object.hasOwn(settings, "heading") && typeof settings.heading !== "string") errors.push("heading");
  return errors;
}

/** The rows one block may show: the setting, else the default. */
function rowCap(settings) {
  return Number.isInteger(settings.maxRows) && settings.maxRows > 0 ? settings.maxRows : DEFAULT_MAX_ROWS;
}

/** `and <n> more` for the rows a cap left out, or "" when nothing was left out. */
export function moreLine(hidden) {
  return hidden > 0 ? `and ${hidden} more` : "";
}

function run(ctx, input) {
  const settings = isPlainObject(ctx.block?.settings) ? ctx.block.settings : {};
  const columns = isFieldList(settings.columns) ? settings.columns : [];
  const maxRows = rowCap(settings);
  const items = Array.isArray(input?.items) ? input.items : [];
  const sections = Array.isArray(input?.sections) ? input.sections : [];
  const shown = items.slice(0, maxRows);

  const lines = [];
  if (typeof settings.heading === "string" && settings.heading.trim()) {
    lines.push(`## ${escapeRecipeText(settings.heading.trim())}`);
    lines.push("");
  }
  lines.push(`| ${columns.map((column) => escapeRecipeText(column)).join(" | ")} |`);
  lines.push(`| ${columns.map(() => "---").join(" | ")} |`);
  for (const item of shown) {
    lines.push(`| ${columns.map((column) => cellMarkdown(readItemField(item, column))).join(" | ")} |`);
  }
  const more = moreLine(items.length - shown.length);
  if (more) {
    lines.push("");
    lines.push(more);
  }

  const section = { type: "table", blockId: ctx.blockId, markdown: lines.join("\n") };
  return { items, sections: [...sections, section] };
}

export const tableBlock = Object.freeze({
  type: "table",
  kind: "present",
  sourceBearing: false,
  validate,
  run,
});