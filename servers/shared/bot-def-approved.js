/**
 * The APPROVED copy of a bot definition — `<CROW_HOME>/secrets/bot-def-approved/<bot_id>.json`.
 *
 * WHAT IT IS FOR. When Crow refuses a bot definition as unverified, the operator's way back is
 * `node scripts/cli/bot-def-reapprove.mjs <bot_id> --show`, and "what changed?" is the one question
 * that page has to answer: the row it refuses is whatever a bot (or a hand edit) left there, and
 * comparing that against nothing at all tells the operator nothing. So every successful SEALED write
 * drops the content it just approved here, and `--show` prints a FIELD-LEVEL diff of the stored row
 * against it (see the CLI; the security fields are flagged there).
 *
 * WHAT IT IS NOT. It is not authority, not a MAC input and never the row a decision reads: it is a
 * recovery aid stored beside the key, so a bot can neither read it (0700 dir under `secrets/`) nor
 * affect it. Losing it (or failing to write one) only weakens the diff — never a check — which is
 * why `writeApprovedBotDef` swallows its own errors and logs ONE line per bot per process.
 *
 * WHO REFRESHES IT. Every write that goes through `servers/shared/bot-def-store.js` (`writeBotDef`,
 * `setBotEnabled`, `setBotProjectId`, the reapprove CLI), the boot converter's TOFU seal and the
 * operator key reset's reseal. The two writers that issue their OWN statement — the version-history
 * restore and skill promotion, which sign through the seam and hold no database here — do not, so the
 * copy keeps the last owner-approved content and the diff shows their change as a change (the
 * conservative direction: it names what moved, it never hides it).
 *
 * WHERE IT LIVES. `<CROW_HOME>/secrets/bot-def-approved/`, derived exactly like the generations file
 * (`servers/shared/bot-def-mac.js` `botDefGenerationsPath`): the dirname of `tokenMacKeyPath()` —
 * never `dirname(dirname())`, because the key path may be a `/proc/self/fd/N/…` anchored seam. Dir
 * 0700, file 0600, written atomically (temp + fsync + rename + fsync the dir).
 *
 * THE FILE NAME IS SANITISED, and an id that is not `[A-Za-z0-9._@:-]+` is REFUSED (no path
 * separators, no spaces, nothing that could name another file): a bot id is operator/CLI input in
 * places, and this module writes to a path built from it.
 *
 * HOST-ONLY, like the store that calls it: it reaches `tokenMacKeyPath()` (through
 * `servers/shared/token-mac.js`), which no bot-loadable module may import.
 */
import {
  closeSync, fsyncSync, openSync, readFileSync, renameSync, unlinkSync, writeSync,
} from "node:fs";
import { randomBytes } from "node:crypto";
import { dirname, join } from "node:path";

import { tokenMacKeyPath } from "./token-mac.js";
import { ensureSecretsDir } from "./secrets-dir.js";

/** The subdirectory of `secrets/` this module owns. */
export const BOT_DEF_APPROVED_DIRNAME = "bot-def-approved";

/** What a copy file must be to be read back (a future format change bumps this). */
export const BOT_DEF_APPROVED_VERSION = 1;

/**
 * The ids a copy may be stored under. Deliberately narrow: the value becomes a FILE NAME, so
 * anything that is not plainly an id (a `/`, a space, a `..`-only name) is refused rather than
 * sanitised into something that might name a different bot.
 */
const BOT_ID_RE = /^[A-Za-z0-9._@:-]+$/;
const MAX_BOT_ID_LENGTH = 200;

/** Ids this process has already logged a failed copy for (ONE line per bot, per process). */
const warned = new Set();

/**
 * The directory the copies live in: beside the key, like the generations file.
 * `opts` are token-mac's own seams (`path`, `crowHome`) plus `approvedDir` for a test.
 */
export function botDefApprovedDir(opts = {}) {
  return opts.approvedDir || join(dirname(tokenMacKeyPath(opts)), BOT_DEF_APPROVED_DIRNAME);
}

/**
 * The path one bot's copy would live at, or `null` when the id is not storable (see `BOT_ID_RE`).
 */
export function botDefApprovedPath(botId, opts = {}) {
  const id = String(botId ?? "");
  if (!id || id.length > MAX_BOT_ID_LENGTH) return null;
  if (!BOT_ID_RE.test(id) || /^\.+$/.test(id)) return null;
  return join(botDefApprovedDir(opts), `${id}.json`);
}

function warnOnce(botId, err) {
  const id = String(botId ?? "");
  if (warned.has(id)) return;
  warned.add(id);
  console.warn(
    `[bot-def] the approved copy of ${id} could not be written (${String(err?.code || err?.message || err)}); `
    + "bot-def-reapprove --show will have no previous approved version to diff against",
  );
}

/** Test seam: forget this process's one-line-per-bot de-duplication. */
export function forgetApprovedBotDefWarnings() {
  warned.clear();
}

/**
 * Write the approved copy for one bot. NEVER throws and never fails the database write it follows:
 * a lost copy only weakens the recovery diff (see the module header).
 *
 * @param {{bot_id: string, enabled?: number|boolean, project_id?: number|null,
 *          definition?: string|object|null, generation: number|null}} content the values the write
 *          just stored (`definition` is stored as the canonical TEXT the MAC covers)
 * @returns {{ok: boolean, path?: string|null, reason?: string}}
 */
export function writeApprovedBotDef(content = {}, opts = {}) {
  const botId = String(content.bot_id ?? "");
  const path = botDefApprovedPath(botId, opts);
  if (!path) {
    warnOnce(botId, new Error("bot id is not storable as a file name"));
    return { ok: false, path: null, reason: "bot-id" };
  }
  try {
    const definition = content.definition === undefined || content.definition === null
      ? null
      : typeof content.definition === "string"
        ? content.definition
        : JSON.stringify(content.definition);
    const body = {
      v: BOT_DEF_APPROVED_VERSION,
      bot_id: botId,
      enabled: Number(content.enabled) ? 1 : 0,
      project_id: content.project_id === undefined || content.project_id === null || content.project_id === ""
        ? null
        : Number(content.project_id),
      definition,
      generation: Number.isSafeInteger(content.generation) ? content.generation : null,
      approved_at: new Date().toISOString(),
    };
    ensureSecretsDir(dirname(path));
    const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
    const fd = openSync(tmp, "wx", 0o600);
    try {
      writeSync(fd, JSON.stringify(body, null, 2) + "\n");
      fsyncSync(fd);
    } finally {
      closeSync(fd);
    }
    try {
      renameSync(tmp, path);
    } catch (err) {
      try { unlinkSync(tmp); } catch { /* already gone */ }
      throw err;
    }
    try {
      const dfd = openSync(dirname(path), "r");
      fsyncSync(dfd);
      closeSync(dfd);
    } catch { /* best effort */ }
    return { ok: true, path };
  } catch (err) {
    warnOnce(botId, err);
    return { ok: false, path, reason: String(err?.code || err?.message || err) };
  }
}

/**
 * Read one bot's approved copy. Never throws.
 *
 * @returns {{path: string|null, exists: boolean, corrupt: boolean,
 *            content: null|{bot_id: string, enabled: number|null, project_id: number|null,
 *                           definition: string|null, generation: number|null, approved_at: string|null}}}
 *   `exists: false` is the ordinary "no copy yet" (a bot created before this feature, or one whose
 *   copy was removed with it). `corrupt: true` is a file that is there and cannot be read back.
 */
export function readApprovedBotDef(botId, opts = {}) {
  const path = botDefApprovedPath(botId, opts);
  const empty = { path, exists: false, corrupt: false, content: null };
  if (!path) return empty;
  let raw;
  try {
    raw = readFileSync(path, "utf8");
  } catch (err) {
    if (err?.code === "ENOENT") return empty;
    return { ...empty, exists: true, corrupt: true };
  }
  let j;
  try {
    j = JSON.parse(raw);
  } catch {
    return { ...empty, exists: true, corrupt: true };
  }
  if (!j || typeof j !== "object" || Array.isArray(j)) return { ...empty, exists: true, corrupt: true };
  if (j.definition !== null && typeof j.definition !== "string") return { ...empty, exists: true, corrupt: true };
  return {
    path,
    exists: true,
    corrupt: false,
    content: {
      bot_id: String(j.bot_id ?? botId),
      enabled: Number.isInteger(j.enabled) ? j.enabled : null,
      project_id: j.project_id === null || j.project_id === undefined ? null : Number(j.project_id),
      definition: j.definition ?? null,
      generation: Number.isSafeInteger(j.generation) ? j.generation : null,
      approved_at: typeof j.approved_at === "string" ? j.approved_at : null,
    },
  };
}

/**
 * Remove one bot's approved copy — the bot was DELETED, and a copy left behind would be read as a
 * "previous approved version" by a later bot that reuses the id. Never throws; `false` when there
 * was nothing to remove (or the id is not storable).
 */
export function forgetApprovedBotDef(botId, opts = {}) {
  const path = botDefApprovedPath(botId, opts);
  if (!path) return false;
  try {
    unlinkSync(path);
    return true;
  } catch {
    return false;
  }
}