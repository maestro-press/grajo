/**
 * The one value that says a claim came from a run's own executor.
 *
 * A unique, frozen token. `blocks/run-recipe.js` builds the run's ONE `extra_step_runs` claim and hands
 * it to the blocks as a pair: the function itself (`extraStepClaim` on the block context) and this token
 * (`extraStepClaimToken`). `custom-step.js` honours the pair and nothing else, so a caller that writes
 * `claimToken: true`, or the token with no function beside it, still takes its own claim.
 *
 * The module exports the token and nothing else, so a `servers/` grep for its importers reads as the
 * whole list of code that can hand a claim away.
 */
export const CLAIMED_BY_EXECUTOR = Object.freeze({ token: "claimed_by_executor" });