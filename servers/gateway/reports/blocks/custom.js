/**
 * The `custom` block: a report's own approved step, run through `custom-step.js`.
 *
 * The block carries `{step: <step key>, params?: object}` and hands the flow's `{items, sections}` to the
 * step as its input. The step's answer decides what this block adds to the flow:
 *   - `{ok: true, output}`: `items` (when present) replaces the flow's items, `sections` is appended, and
 *     an `email` field is passed along for the round that sends mail. Output items must be an array of
 *     plain objects, capped so one step cannot make a run the size of a database.
 *   - `{ok: false, code, error}`: a source error carrying the step's own `error` text. That text is
 *     already redacted by custom-step.js, and for `step_waiting` it is the one sentence the owner reads.
 *     This block does not throw for it: a throw would replace the sentence with a code word.
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
const STEP_KEY_RE = /^[a-z][a-z0-9_-]{0,31}$/;

/** How many items one step's output may contribute. */
export const MAX_CUSTOM_ITEMS = 5000;

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
  }
  if (output.sections !== undefined) {
    if (!Array.isArray(output.sections)) throw fail("bad_output");
    out.sections = output.sections.slice(0, MAX_CUSTOM_ITEMS);
  }
  if (output.email !== undefined) out.email = output.email;
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