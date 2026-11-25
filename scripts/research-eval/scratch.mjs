/**
 * Research-eval scratch instances: a throwaway CROW_HOME under the temp dir with a real crow.db
 * (init-db + one research project), for one (case, rep) row.
 *
 * A template is built once per run (or per test file) by one scratch-init.mjs child, and each
 * row copies its crow.db. CROW_JOURNAL_MODE=DELETE in the scratch env keeps every write in the
 * single DB file (no -wal), so a plain file copy is a complete database. The copied DBs keep the
 * template's absolute workspace_dir, so a template must outlive every scratch copied from it.
 *
 * Nothing here writes to process.env or keeps module-level state: two scratches built at once
 * are independent. The real ~/.crow is never read or written; every home is refused unless it is
 * strictly below the temp dir and clear of every protected instance directory.
 */
import { execFile } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, readFileSync, readdirSync, rmSync, chmodSync } from "node:fs";
import { join } from "node:path";
import { promisify } from "node:util";
import { freshHome, scratchEnv } from "../lib/eval-scratch.mjs";
import { skillRequiredTools } from "../pi-bots/skill-tools.mjs";

export { scratchEnv };

const execFileP = promisify(execFile);

export const ROOT = join(import.meta.dirname, "..", "..");
export const SKILL = "research-pipeline";
const INIT = join(import.meta.dirname, "scratch-init.mjs");
const INIT_TIMEOUT_MS = 120_000;

/** Runs scratch-init.mjs in `home` (init-db + one project, one child) → its projectId. */
async function initHome(home, botId, { botGrant = false } = {}) {
  const resultPath = join(home, "init-result.json");
  try {
    await execFileP(process.execPath, [INIT, resultPath], {
      env: { ...scratchEnv(home, botId), ...(botGrant ? { CROW_EVAL_BOT_GRANT: "1" } : {}) },
      cwd: ROOT, timeout: INIT_TIMEOUT_MS, maxBuffer: 16 * 1024 * 1024,
    });
  } catch (err) {
    const tail = String(err.stderr || "").trim().split("\n").slice(-5).join("\n");
    throw new Error(`research-eval scratch-init failed: ${err.message}${tail ? `\n${tail}` : ""}`);
  }
  const { projectId } = JSON.parse(readFileSync(resultPath, "utf8"));
  if (!Number.isInteger(projectId)) throw new Error(`research-eval scratch-init returned no project id (${projectId})`);
  return projectId;
}

/**
 * The template home: one scratch-init child, built ONCE per run or per test file. Keep it until
 * the last scratch copied from it is done (the copies keep its workspace_dir).
 *
 * The template is a whole instance, not just a database: scratch-init seeds the acting bot's row
 * through the ONE write path (`writeBotDef`), which seals it with a keyed MAC under
 * `<home>/secrets/token-hmac.key`. The MAC only verifies in a home holding that key, so a scratch
 * copied from the template must copy `secrets/` WITH `crow.db` (see `copyTemplateSecrets`).
 *
 * `botGrant` shares the eval project with the acting bot (level read_write), so the fixture server
 * lets that bot's calls through: the eval flows ask for it, a caller that seeds its own bot row
 * does not, and the grant rides in the template's crow.db into every scratch copied from it.
 * @returns {Promise<{home: string, dbPath: string, projectId: number, botGrant: boolean, cleanup: () => void}>}
 */
export async function makeTemplate({ botId = "research-eval", botGrant = false } = {}) {
  const home = freshHome();
  try {
    const projectId = await initHome(home, botId, { botGrant });
    return {
      home, dbPath: join(home, "data", "crow.db"), projectId, botGrant,
      secretsDir: join(home, "secrets"),
      cleanup: () => rmSync(home, { recursive: true, force: true }),
    };
  } catch (err) {
    rmSync(home, { recursive: true, force: true });
    throw err;
  }
}

/**
 * Copy the template's `secrets/` into a scratch: the token-mac key, its state and the bot-def
 * generation counter are the other half of the crow.db copy. A `pi_bot_defs` row seeded by
 * scratch-init is sealed under that key (and its generation recorded in that file), so a scratch
 * without them cannot verify — or rewrite — the row it just copied. Owner-only modes are
 * re-applied: `copyFileSync` creates the destination with the default umask, and token-mac
 * refuses a key file any other uid/group bit can read.
 */
function copyTemplateSecrets(template, home) {
  const from = template.secretsDir;
  if (!from || !existsSync(from)) return;
  const to = join(home, "secrets");
  mkdirSync(to, { recursive: true, mode: 0o700 });
  chmodSync(to, 0o700);
  for (const entry of readdirSync(from, { withFileTypes: true })) {
    if (!entry.isFile()) continue;
    const dest = join(to, entry.name);
    copyFileSync(join(from, entry.name), dest);
    chmodSync(dest, 0o600);
  }
}

/**
 * One row's scratch instance. With `template`, its crow.db AND the secrets that seal its bot row
 * are copies of the template's; without, it runs its own scratch-init child.
 * @returns {Promise<{home, dataDir, dbPath, projectId, botId, granted: string[], env, sessionPath, fetchLogPath, cleanup}>}
 */
export async function makeScratch({ botId = "research-eval", template, botGrant } = {}) {
  const home = freshHome();
  const cleanup = () => rmSync(home, { recursive: true, force: true });
  try {
    const dataDir = join(home, "data");
    const dbPath = join(dataDir, "crow.db");
    let projectId;
    if (template) {
      mkdirSync(dataDir, { recursive: true });
      copyFileSync(template.dbPath, dbPath);
      copyTemplateSecrets(template, home);
      projectId = template.projectId;
    } else {
      projectId = await initHome(home, botId, { botGrant: botGrant ?? template?.botGrant ?? false });
    }
    return {
      home, dataDir, dbPath, projectId, botId,
      granted: skillRequiredTools(SKILL, { crowHome: home, repoSkillsDir: join(ROOT, "skills") }),
      env: scratchEnv(home, botId),
      sessionPath: join(home, "session.jsonl"),
      fetchLogPath: join(home, "fetch.jsonl"),
      cleanup,
    };
  } catch (err) {
    cleanup();
    throw err;
  }
}
