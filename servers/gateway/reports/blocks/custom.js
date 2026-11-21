/**
 * The `custom` block: a report's own approved step, run through `custom-step.js`.
 *
 * The block carries `{step: <step key>, params?: object}` and hands the flow's `{items, sections}` to the
 * step as its input. The step's answer decides what this block adds to the flow:
 *   - `{ok: true, output}`: `items` (when present) replaces the flow's items, `sections` is appended, and
 *     an `email` field is NOT carried in this round (see A STEP'S SECTIONS, AND ITS `email`). Output items
 *     must be an array of plain objects, capped so one step cannot make a run the size of a database.
 *   - `{ok: false, code, error}`: a source error carrying the step's own `error` text. That text is
 *     already redacted by custom-step.js, and for `step_waiting` it is the one sentence the owner reads.
 *     This block does not throw for it: a throw would replace the sentence with a code word.
 *
 * A STEP'S SECTIONS, AND ITS `email` (M10, security): a custom step is bot-approved code, so whatever it
 * answers with is untrusted text, and this block is the one place it becomes a document section:
 *   - every section's `type` is FORCED to `custom`, so a step cannot file its own words as
 *     `ai_commentary` or `annotate` and change where the document puts them or what the heading says;
 *   - `assets` and `specs` are DROPPED: a section's own file list and its own chart count are claims, and
 *     a step could claim a file the version does not carry or hide a chart from the document's limit;
 *   - `markdown` must be a string, a section carries at most 64 KB of it, and the flow takes at most 20
 *     sections from one step;
 *   - the markdown goes through `neutralizeLinks` against the run's own item URLs, exactly as a model's
 *     commentary does, because nothing about this text is approved, and with `demoteHeadings` on: a step
 *     may not put a heading into the report, however it spells it.
 *   - a section's links may come only from items the flow CARRIED INTO this block (`input.items`). The
 *     items this step returns are its own claim, so they are marked untrusted (untrusted-items.js) and
 *     contribute to no allow-list at all: not this block's, not a later present block's, not the
 *     assembly's. They still flow on and are still shown as data.
 *   - `output.email` is DROPPED here. The send path does not take a step's own mail fields in this round;
 *     PR 5 must apply this same rule to whatever it wires there (a step may not hand the send path its
 *     own recipients).
 *
 * THE TRIGGER IS THE RUN ROW'S (M8, security): `custom-step.js` spends the day's `extra_step_runs` on
 * anything that is not the schedule, so a caller that could name the trigger could spend nothing. The
 * trigger is read from `ctx.run.trigger` (the server-side run row the executor was handed) and from
 * nowhere else. `settings.trigger` is not read, not validated and cannot override it: a recipe that
 * writes `trigger: "schedule"` still counts against the cap on a manual run.
 *
 * THE RUN'S ONE CLAIM IS THE EXECUTOR'S: the run executor (`blocks/run-recipe.js`) builds the claim for
 * the run as a whole and hands it on `ctx.extraStepClaim`, with its own `CLAIMED_BY_EXECUTOR` token on
 * `ctx.extraStepClaimToken` (claim-token.js). Both travel to `custom-step.js`, which claims through that
 * function when the pair is there and takes its own claim otherwise: the claim happens AFTER the step's
 * own approval check, so a step that is still waiting spends nothing, and it happens once for the run,
 * so a credentialed `http_json` block in the same recipe spends nothing more. The token alone is worth
 * nothing: without the function the step takes its own claim, so nothing but the executor can hand a
 * claim away.
 *
 * A STEP'S `state` OUTPUT IS NOT STORED IN THIS ROUND: `output.state` is ignored here. `report_state` is
 * written only through the executor's buffered `setState`, and the round that decides what a step's own
 * state means (and under which key) has not shipped.
 *
 * `custom-step.js` is imported on first use, not at module load: the sandbox runner and the steps
 * module sit behind it, and the registry is loaded by the store on every recipe save of every server.
 */
import { itemLinks } from "../document.js";
import { neutralizeLinks } from "../email/neutralize-links.js";
import { markUntrusted } from "../untrusted-items.js";

const STEP_KEY_RE = /^[a-z][a-z0-9_-]{0,31}$/;

/** How many items one step's output may contribute. */
export const MAX_CUSTOM_ITEMS = 5000;

/** How many sections one step's output may contribute, and how many bytes of markdown each may carry. */
export const MAX_CUSTOM_SECTIONS = 20;
export const MAX_SECTION_BYTES = 64 * 1024;

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

function fail(code) {
  const err = new Error(code);
  err.code = code;
  return err;
}

let customStepModule = null;

function loadCustomStep() {
  if (!customStepModule) customStepModule = import("../custom-step.js");
  return customStepModule;
}

/** `{step, params?}`; a `trigger` key in settings is ignored on purpose (see the header). */
function validate(settings) {
  if (!isPlainObject(settings)) return ["settings"];
  const errors = [];
  if (typeof settings.step !== "string" || !STEP_KEY_RE.test(settings.step)) errors.push("step");
  if (settings.params !== undefined && !isPlainObject(settings.params)) errors.push("params");
  return errors;
}

/** A string cut to at most `max` utf8 bytes, never in the middle of a character. */
function truncateBytes(text, max) {
  const buffer = Buffer.from(text, "utf8");
  if (buffer.length <= max) return text;
  const cut = buffer.subarray(0, max).toString("utf8");
  return cut.endsWith("\uFFFD") ? cut.slice(0, -1) : cut;
}

/**
 * A step's sections as the document may carry them: `custom`, no files, no chart claim, bounded, and
 * with every URL that the carried items do not name neutralised. See the header's A STEP'S SECTIONS.
 *
 * @param {*[]} sections the step's own list
 * @param {object[]} items the items the flow carried INTO this block (the only source of an allowed link)
 * @param {string} blockId
 * @returns {{type: string, blockId: string, markdown: string}[]}
 * @throws {Error} `bad_output` for a section that is not an object with a string `markdown`
 */
function sanitizeSections(sections, items, blockId) {
  const allowed = itemLinks(items);
  const out = [];
  for (const section of sections) {
    if (out.length >= MAX_CUSTOM_SECTIONS) break;
    if (!isPlainObject(section) || typeof section.markdown !== "string") throw fail("bad_output");
    const markdown = neutralizeLinks(
      truncateBytes(section.markdown, MAX_SECTION_BYTES),
      allowed,
      { demoteHeadings: true },
    );
    out.push({ type: "custom", blockId, markdown });
  }
  return out;
}

async function run(ctx, input) {
  const settings = isPlainObject(ctx.block?.settings) ? ctx.block.settings : {};
  const { runCustomStepForReport } = await loadCustomStep();
  const answer = await runCustomStepForReport(ctx.db, ctx.deps ?? {}, {
    report: ctx.report,
    stepKey: settings.step,
    input,
    params: settings.params,
    // M8: the run row's own trigger, never a recipe's word.
    trigger: ctx.run == null ? undefined : ctx.run.trigger,
    // The executor's own claim, as the pair it is: the token and the function it minted for this run.
    // `custom-step.js` honours the pair and nothing else, and an unpaired half is not a pass.
    claimToken: ctx.extraStepClaimToken,
    claimExtraStep: ctx.extraStepClaim,
  });
  if (answer == null || answer.ok !== true) {
    const message = typeof answer?.error === "string" && answer.error
      ? answer.error
      : (typeof answer?.code === "string" && answer.code ? answer.code : "custom_step_failed");
    return { sourceError: { message } };
  }
  const output = isPlainObject(answer.output) ? answer.output : {};
  const out = {};
  if (output.items !== undefined) {
    if (!Array.isArray(output.items) || !output.items.every(isPlainObject)) throw fail("bad_output");
    out.items = output.items.slice(0, MAX_CUSTOM_ITEMS);
    // A step's own items are marked BEFORE they leave this block: no allow-list in this run is built
    // from their URLs, including one a later block builds (untrusted-items.js).
    markUntrusted(out.items);
  }
  if (output.sections !== undefined) {
    if (!Array.isArray(output.sections)) throw fail("bad_output");
    // Only what the flow carried INTO this block may approve a link: an item this step produced is its
    // own claim about itself, so it is never part of this list.
    const carried = Array.isArray(input?.items) ? input.items : [];
    out.sections = sanitizeSections(output.sections, carried, ctx.blockId);
  }
  // `output.email` is deliberately not carried in this round: see the header. PR 5 must apply the same
  // rule (a step's own mail fields never reach the send path).
  // `output.state` is deliberately not carried: see the header.
  return out;
}

export const customBlock = Object.freeze({
  type: "custom",
  kind: "custom",
  sourceBearing: true,
  validate,
  run,
});