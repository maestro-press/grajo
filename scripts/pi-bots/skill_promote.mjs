#!/usr/bin/env node
/**
 * Crow Bot Builder — shared skill promotion (self-learning, plan §B4).
 *
 * ONE code path that writes a skill file into ~/.crow/skills and attaches its
 * name to the bot's def (def.skills, the one skills store), used by BOTH:
 *   - the operator approve handler (bot-board-api.js) — mode:"operator"
 *   - the auto-mode review pass (skill_review.mjs)     — mode:"auto"
 *
 * Mode-specific rules (review C5/C6):
 *   operator: never overwrite an existing ~/.crow/skills file (409). Unchanged
 *             semantics from the original approve handler.
 *   auto:     - NEVER write/patch a shipped repo skill (~/crow/skills) — protected.
 *             - create a NEW skill only if no skill of that name exists elsewhere
 *               that this bot didn't author.
 *             - patch an existing ~/.crow/skills file ONLY if provenance shows
 *               this bot created it (botAuthoredSkill). Otherwise refuse so the
 *               caller can downgrade to a propose draft.
 * Repo ~/crow/skills is never a write target in any mode (target is always
 * ~/.crow/skills), so shipped skills are structurally safe.
 *
 * The def update is a BEGIN IMMEDIATE better-sqlite3 transaction (read-modify-
 * write), because the auto path has no human to retry the SSR save path's
 * optimistic-concurrency 409. busy_timeout-only; no journal_mode pragma.
 *
 * Returns { ok:true, action:"create"|"patch", target } or
 * { ok:false, code, message } with code ∈ invalid-name | empty | escape |
 * symlink | exists | protected | not-author | unknown-bot | write-failed |
 * db-failed. The caller maps these (operator → HTTP status; auto → downgrade).
 */
import Database from "better-sqlite3";
import { existsSync, mkdirSync, writeFileSync, readFileSync, unlinkSync, lstatSync, realpathSync } from "node:fs";
import { join } from "node:path";
import { normalizeSkillName } from "./skill_proposals.mjs";
import { resolveSkill, REPO_SKILLS_DIR } from "./skill_resolver.mjs";
import { botAuthoredSkill, recordSkillEvent } from "./skill_provenance.mjs";
import { botsDbPath } from "./instance-paths.mjs";
import { resolveCrowHome } from "../../servers/shared/crow-home.js";
// The bot-definition WRITE SEAM, not the store: this file is on the bot-reachable tree
// (scripts/pi-bots/**), so it must not reach the key. `signBotDefSealed` gives the generation +
// MAC for the row this module writes in its own BEGIN IMMEDIATE transaction, and
// `verifyBotDefSealed` is the seam's synchronous VERIFY, called inside that same transaction.
import { signBotDefSealed, verifyBotDefSealed } from "../../servers/shared/bot-def-seal.js";

const CROW_DB = botsDbPath();
// Sole write target: THIS instance's skills dir (CROW_HOME/skills), the same dir
// the gateway approve handler and Skills panel use. Was hardcoded ~/.crow/skills,
// so a co-hosted instance (CROW_HOME=~/.crow-r4) promoted into the primary's.
const CROW_USER_SKILLS = join(resolveCrowHome(), "skills");
function userSkillsDir(crowHome) { return crowHome ? join(crowHome, "skills") : join(resolveCrowHome(), "skills"); }
const REPO_SKILLS = REPO_SKILLS_DIR;                      // protected (shipped, the running checkout) — never written

function db() { const d = new Database(CROW_DB); d.pragma("busy_timeout = 10000"); return d; }

// Transactional read-modify-write of pi_bot_defs.definition: add `name` to
// def.skills (the one skills store). BEGIN IMMEDIATE so a concurrent SSR save can't
// interleave between our read and write. Returns {ok} / {ok:false,message}.
//
// The row carries a keyed MAC over the whole definition and a replay generation (see
// servers/shared/bot-def-mac.js), so the UPDATE sets both in the same statement as the definition —
// `signBotDefSealed` computes them (through the seam: this file must not hold the key) and the
// generation is settled only once the transaction committed.
//
// THE ROW MUST VERIFY FIRST (inside the transaction, through the seam). This runs host-side after a
// bot's own turn, with NO owner action: attaching a skill to a definition that does not verify would
// re-sign whatever the row holds — including an edit the bot itself made — and hand it back as the
// owner's. An unverified row is refused (one log line, the caller's existing failure path), and the
// planned generation is ABANDONED whenever the statement does not land.
function attachSkillToDef(bot_id, name) {
  const c = db();
  let planned = null;
  let written = 0;
  try {
    // A store shaped before the seal columns exist (an install whose migration has not run, a
    // scratch fixture): the plain update, exactly as before.
    let hasSeal = true;
    try { c.prepare("SELECT def_mac, def_generation FROM pi_bot_defs LIMIT 0"); } catch { hasSeal = false; }
    const tx = c.transaction(() => {
      const row = c.prepare("SELECT bot_id, definition, enabled, project_id, def_mac, def_generation FROM pi_bot_defs WHERE bot_id=?").get(bot_id);
      if (!row) throw new Error("unknown-bot");
      let def; try { def = JSON.parse(row.definition || "{}"); } catch { def = {}; }
      def.skills = Array.isArray(def.skills) ? def.skills : [];
      if (!def.skills.includes(name)) def.skills.push(name);
      if (!hasSeal) {
        const res = c.prepare("UPDATE pi_bot_defs SET definition=?, updated_at=datetime('now') WHERE bot_id=?")
          .run(JSON.stringify(def), bot_id);
        written = Number(res.changes) || 0;
        return null;
      }
      // The seam's verify makes the SAME era decision the bridge's spawn gate makes (round C, items
      // E3/M4): this process has no database scan of its own here, so it says what its own row shows
      // (`anyMac`) and the seam adds the secrets-side evidence (the marker file, the generations file).
      // A row that lost its `def_mac` COLUMN is therefore refused (`no-mac-column`), never accepted as
      // "pre-era".
      const verdict = verifyBotDefSealed(row, { anyMac: row.def_mac != null });
      if (!verdict.ok) {
        const err = new Error(`bot ${bot_id} settings could not be verified (${verdict.reason})`);
        err.code = "BOT_DEF_UNVERIFIED";
        throw err;
      }
      const seal = signBotDefSealed({
        bot_id, definition: def, enabled: row.enabled, project_id: row.project_id ?? null,
      });
      planned = seal;
      // The SEALED row is the one this statement may land on (round C, item E1): the row that was
      // verified, pinned by its own content and its own seal, even though this transaction already
      // holds the write lock.
      const res = c.prepare("UPDATE pi_bot_defs SET definition=?, def_mac=?, def_generation=?, updated_at=datetime('now') WHERE bot_id=?"
        + " AND definition IS ? AND enabled IS ? AND project_id IS ? AND def_mac IS ? AND def_generation IS ?")
        .run(seal.definition, seal.def_mac, seal.generation, bot_id,
          row.definition ?? null, row.enabled ?? null, row.project_id ?? null, row.def_mac ?? null, row.def_generation ?? null);
      written = Number(res.changes) || 0;
      // 0 rows means the row vanished under the transaction: the planned generation must not stand.
      if (written === 0) throw new Error("write-failed");
      return seal;
    });
    const seal = tx.immediate();
    if (seal && typeof seal.settle === "function") seal.settle();
    planned = null;
    return { ok: true };
  } catch (e) {
    // A transaction that threw (including a 0-row update) ABANDONS the planned generation, so the
    // counter never records a write that did not happen.
    if (planned && typeof planned.abandon === "function") { try { planned.abandon(); } catch { /* the counter is a floor */ } }
    if (e && e.code === "BOT_DEF_UNVERIFIED") {
      console.warn(
        `[bot-def] ${bot_id} was changed outside Crow; review it with `
        + `\`node scripts/cli/bot-def-reapprove.mjs ${bot_id} --show\``,
      );
    }
    return { ok: false, message: String((e && e.message) || e) };
  } finally {
    c.close();
  }
}

/**
 * @param {{ bot_id:string, name:string, text:string, mode:"operator"|"auto",
 *           model?:string, flags?:any, crowHome?:string }} opts
 */
export function promoteSkill(opts) {
  const name = normalizeSkillName(opts.name);
  if (!name) return { ok: false, code: "invalid-name", message: "invalid skill name" };
  const text = typeof opts.text === "string" ? opts.text : "";
  if (!text.trim()) return { ok: false, code: "empty", message: "content (non-empty) required" };
  const mode = opts.mode === "operator" ? "operator" : "auto";

  const skillsDir = userSkillsDir(opts.crowHome);
  mkdirSync(skillsDir, { recursive: true });
  // containment: the resolved skills root must be a prefix of the target.
  const realRoot = realpathSync(skillsDir);
  if (!join(realRoot, name + ".md").startsWith(realRoot + "/")) {
    return { ok: false, code: "escape", message: "target escapes the skills dir" };
  }
  const target = join(skillsDir, name + ".md");
  const targetExists = existsSync(target);
  if (targetExists && lstatSync(target).isSymbolicLink()) {
    return { ok: false, code: "symlink", message: "target is a symlink — refusing" };
  }

  // What does this name already resolve to across all skill dirs (first match)?
  const existing = resolveSkill(name, { crowHome: opts.crowHome });

  let action, prevContent = null;
  if (mode === "operator") {
    if (targetExists) {
      return { ok: false, code: "exists", message: "a skill named '" + name + "' already exists in ~/.crow/skills; rename or remove it first (refusing to overwrite)" };
    }
    action = "create";
  } else {
    // auto: protect shipped repo skills; gate patch/create on authorship.
    if (existing && existing.path && existing.path.startsWith(REPO_SKILLS + "/")) {
      return { ok: false, code: "protected", message: "a shipped (repo) skill named '" + name + "' exists; refusing to shadow it" };
    }
    if (targetExists) {
      if (botAuthoredSkill(opts.bot_id, name)) { action = "patch"; prevContent = readFileSync(target, "utf8"); }
      else return { ok: false, code: "not-author", message: "skill '" + name + "' exists in ~/.crow/skills and was not authored by this bot" };
    } else if (existing && !botAuthoredSkill(opts.bot_id, name)) {
      return { ok: false, code: "not-author", message: "skill '" + name + "' exists elsewhere and was not authored by this bot" };
    } else {
      action = "create";
    }
  }

  try { writeFileSync(target, text, "utf8"); }
  catch (e) { return { ok: false, code: "write-failed", message: String((e && e.message) || e) }; }

  const upd = attachSkillToDef(opts.bot_id, name);
  if (!upd.ok) {
    // roll back the file so a failed def update doesn't leave an orphan/clobber.
    try {
      if (action === "create") unlinkSync(target);
      else if (prevContent != null) writeFileSync(target, prevContent, "utf8");
    } catch {}
    return { ok: false, code: upd.message === "unknown-bot" ? "unknown-bot" : "db-failed", message: upd.message };
  }

  recordSkillEvent({ bot_id: opts.bot_id, skill_name: name, action, mode, model: opts.model, flags: opts.flags });
  return { ok: true, action, target };
}

export { CROW_USER_SKILLS, REPO_SKILLS };
