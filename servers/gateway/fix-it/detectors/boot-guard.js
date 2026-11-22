/**
 * Fix-it detector: the boot guard is installed for this service but did not run.
 *
 * With `CROW_BOOT_GUARD=1` in the unit, an `ExecStartPre=` copy of the launcher
 * should stamp `launcher_ran_at` before this process starts, and an
 * `ExecStopPost=` copy should stamp `recorder_ran_at` after the previous one
 * ended. If either stamp is missing, the drop-in points at something that no
 * longer works (a node path that moved, a deleted launcher copy, a typo in the
 * unit) — and the failure is otherwise silent: the gateway boots fine and the
 * NEXT update that cannot start simply loops forever with no rollback (S13).
 *
 * No event fires for this: `runBootChecks()` calls `check()` once per start.
 */
import { bootGuardProblem } from "../../boot-guard-state.js";
import { bootGuardCardCode, cardContext, cardText } from "../card-copy.js";

export const DEDUP_KEY = "boot-guard:did-not-run";
export const SOURCE = "boot-guard";

export default {
  source: SOURCE,
  // A missing stamp emits no event: runBootChecks() calls check() at gateway start.
  events: [],
  async onEvent() {},
  /**
   * Upsert the card while the guard looks broken, RESOLVE it once a boot was
   * guarded. Never throws into boot.
   */
  async check(store, opts = {}) {
    const problem = bootGuardProblem(opts.bootGuard || {});
    // "unknown": the previous start happened before this boot (a power loss or a
    // reboot), so no recorder stamp was ever due. Raising "the guard did not run"
    // there would be a false alarm on every routine reboot, and resolving would
    // hide a real card, so this case says nothing at all.
    if (problem && problem.reason === "unknown") return null;
    if (!problem) {
      try { await store.resolveByKey(SOURCE, DEDUP_KEY); } catch { /* no row yet, or no store */ }
      return null;
    }
    const code = bootGuardCardCode(problem.reason);
    const text = cardText(code, {}, "en");
    await store.upsertItem({
      source: SOURCE,
      dedupKey: DEDUP_KEY,
      title: text.title,
      why: text.why,
      severity: "warn",
      remedies: [], // needs the unit directory: the gateway cannot write /etc as root
      context: cardContext(code, {}, { reason: problem.reason, detail: String(problem.detail ?? "") }),
    });
    return problem;
  },
};