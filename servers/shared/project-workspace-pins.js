/**
 * Project workspace pins: the REAL path of each project's workspace folder, recorded OUTSIDE crow.db.
 *
 * Why. `project_spaces.workspace_dir` lives in crow.db, which a database-bound contained bot can
 * write. The no-database sandbox (scripts/pi-bots/pi_contain.mjs, `noDb`) binds the bot's workspace
 * read-write and only checks that it is strictly below <data>/projects, so a rewritten row could
 * still retarget a bot into ANOTHER project's workspace. The pin is the answer the row is judged
 * against: written at project creation (servers/shared/project-spaces.js) and once at boot for
 * existing projects (servers/gateway/boot/project-workspace-pin-backfill.js), in
 * `<CROW_HOME>/secrets/project-workspaces.json`, a directory no bot sandbox is bound to.
 *
 * Same file conventions as servers/shared/bot-storage-key.js: the secrets directory is a real
 * directory this user owns at mode 0700; the file is opened O_NOFOLLOW, judged on the opened
 * descriptor (this user, no group/other bits, size-capped). A fault is "no pins" with a reason,
 * never a throw into a spawn, and a faulty store is never overwritten.
 *
 * HOST-SIDE ONLY, dependency-free: imports no identity, seal helper or storage client.
 */

import {
  closeSync, constants as fsConstants, fstatSync, lstatSync, mkdirSync, openSync, readSync,
  realpathSync, renameSync, unlinkSync, writeSync, fsyncSync,
} from "node:fs";
import { join, sep } from "node:path";
import { randomBytes } from "node:crypto";

export const WORKSPACE_PINS_FILE = "project-workspaces.json";
export const WORKSPACE_PINS_MAX_BYTES = 4 * 1024 * 1024;
export const WORKSPACE_PINS_MISSING = "missing";

export function workspacePinsPath(crowHome) {
  return join(String(crowHome), "secrets", WORKSPACE_PINS_FILE);
}

const homeOf = (crowHome) => (typeof crowHome === "function" ? crowHome() : crowHome);

function realOrNull(p) {
  try { return realpathSync(p); } catch { return null; }
}

const strictlyBelow = (child, parent) => child !== parent && child.startsWith(parent.endsWith(sep) ? parent : parent + sep);

/** The secrets dir if it is a real dir, this user's, mode 0700. Never created or repaired here. */
function trustedSecretsDir(home) {
  const dir = join(String(home), "secrets");
  let st;
  try { st = lstatSync(dir); } catch (err) {
    if (err && err.code === "ENOENT") return { dir: null, reason: WORKSPACE_PINS_MISSING };
    return { dir: null, reason: "its secrets directory cannot be examined" };
  }
  if (st.isSymbolicLink()) return { dir: null, reason: "its secrets directory is a symbolic link" };
  if (!st.isDirectory()) return { dir: null, reason: "its secrets directory is not a directory" };
  if (typeof process.getuid === "function" && Number(st.uid) !== process.getuid()) {
    return { dir: null, reason: "its secrets directory is not owned by this user" };
  }
  if ((Number(st.mode) & 0o777) !== 0o700) return { dir: null, reason: "its secrets directory is not owner-only" };
  return { dir, reason: null };
}

/** Read a 0600 JSON file through one descriptor. @returns {{raw:string|null, reason:string|null}} */
export function readOwnerOnlyFile(path, maxBytes) {
  let fd;
  try {
    try { fd = openSync(path, fsConstants.O_RDONLY | fsConstants.O_NOFOLLOW); } catch (err) {
      if (err && err.code === "ENOENT") return { raw: null, reason: WORKSPACE_PINS_MISSING };
      if (err && err.code === "ELOOP") return { raw: null, reason: "it is a symbolic link" };
      return { raw: null, reason: "it cannot be opened" };
    }
    const st = fstatSync(fd);
    if (!st.isFile()) return { raw: null, reason: "it is not a regular file" };
    if (typeof process.getuid === "function" && Number(st.uid) !== process.getuid()) return { raw: null, reason: "it is not owned by this user" };
    if ((Number(st.mode) & 0o077) !== 0) return { raw: null, reason: "it is readable by other users" };
    if (Number(st.size) > maxBytes) return { raw: null, reason: "it is too large" };
    if (Number(st.size) === 0) return { raw: null, reason: "it is empty" };
    const buf = Buffer.alloc(Number(st.size));
    let off = 0;
    while (off < buf.length) {
      const n = readSync(fd, buf, off, buf.length - off, off);
      if (n <= 0) break;
      off += n;
    }
    return { raw: buf.subarray(0, off).toString("utf8"), reason: null };
  } catch {
    return { raw: null, reason: "it cannot be read" };
  } finally {
    if (fd !== undefined) { try { closeSync(fd); } catch { /* closed */ } }
  }
}

/**
 * Every pin, or why there are none. `reason` is null for a good store, WORKSPACE_PINS_MISSING when
 * there is simply no file (a normal state), and a short value-free sentence for a fault.
 * @returns {{pins: Record<string, {path: string, pinned_at: string}>, reason: string|null}}
 */
export function readWorkspacePins({ crowHome } = {}) {
  const home = homeOf(crowHome);
  if (typeof home !== "string" || home === "") return { pins: {}, reason: "no Crow home was resolved" };
  const d = trustedSecretsDir(home);
  if (!d.dir) return { pins: {}, reason: d.reason };
  const f = readOwnerOnlyFile(workspacePinsPath(home), WORKSPACE_PINS_MAX_BYTES);
  if (f.raw === null) return { pins: {}, reason: f.reason };
  let parsed;
  try { parsed = JSON.parse(f.raw); } catch { return { pins: {}, reason: "it is not valid JSON" }; }
  if (!parsed || typeof parsed !== "object" || parsed.version !== 1 || !parsed.pins || typeof parsed.pins !== "object" || Array.isArray(parsed.pins)) {
    return { pins: {}, reason: "it is not a version 1 pin store" };
  }
  const pins = {};
  for (const [id, e] of Object.entries(parsed.pins)) {
    if (e && typeof e === "object" && typeof e.path === "string" && e.path.startsWith("/")) pins[id] = { path: e.path, pinned_at: String(e.pinned_at || "") };
  }
  return { pins, reason: null };
}

/** The pinned real path of a project's workspace, or null (no pin, or an unusable store). */
export function readWorkspacePin(projectId, { crowHome } = {}) {
  if (projectId === null || projectId === undefined || projectId === "") return null;
  const { pins } = readWorkspacePins({ crowHome });
  const e = pins[String(projectId)];
  return e ? e.path : null;
}

/**
 * Does this workspace FOLDER name fit this project row? The folder ends with the row's OWN id, or it
 * is the slug / slug-N and does NOT end with the id of ANY other project row (so a row rewritten to
 * another project's default-shaped folder, with its slug set to that folder's name, never fits).
 * Used by the boot backfill and the operator CLI's pin-from-row path.
 */
export function folderFitsProject(folder, row, allRows = []) {
  if (!folder || row == null) return false;
  if (folder.endsWith(`-${row.id}`)) return true;
  const slug = String(row.slug || "");
  if (!slug) return false;
  const esc = slug.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  if (!(folder === slug || new RegExp(`^${esc}-\\d+$`).test(folder))) return false;
  return !allRows.some((r) => String(r.id) !== String(row.id) && folder.endsWith(`-${r.id}`));
}

function sleepSync(ms) { Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms); }

function withLock(home, fn) {
  const lock = join(String(home), "secrets", WORKSPACE_PINS_FILE + ".lock");
  let fd = null;
  for (let i = 0; i < 100 && fd === null; i++) {
    try { fd = openSync(lock, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600); } catch (err) {
      if (!err || err.code !== "EEXIST") throw err;
      if (i === 60) { try { unlinkSync(lock); } catch { /* raced */ } } // a stale lock of a dead writer
      sleepSync(20);
    }
  }
  if (fd === null) throw new Error("lock busy");
  try { return fn(); } finally {
    try { closeSync(fd); } catch { /* closed */ }
    try { unlinkSync(lock); } catch { /* gone */ }
  }
}

function writeStore(home, pins) {
  const dest = workspacePinsPath(home);
  const tmp = `${dest}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
  const fd = openSync(tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
  try {
    writeSync(fd, JSON.stringify({ version: 1, pins }, null, 2) + "\n");
    fsyncSync(fd);
  } finally { closeSync(fd); }
  try { renameSync(tmp, dest); } catch (err) { try { unlinkSync(tmp); } catch { /* gone */ } throw err; }
}

/**
 * Pin a project's workspace: its REAL path must be strictly below realpath(<dataDir>/projects).
 * Never overwrites a different pin. Never throws.
 * @returns {{ok: true, path: string, existed: boolean} | {ok: false, reason: string}}
 */
export function pinProjectWorkspace(projectId, workspaceDir, opts = {}) {
  return pinInner(projectId, workspaceDir, opts, false);
}

/** The operator's re-pin (CLI --replace): same checks, but a different existing pin is replaced. */
export function replaceWorkspacePin(projectId, workspaceDir, opts = {}) {
  return pinInner(projectId, workspaceDir, opts, true);
}

function pinInner(projectId, workspaceDir, { crowHome, dataDir } = {}, replace) {
  try {
    const home = homeOf(crowHome);
    if (typeof home !== "string" || home === "") return { ok: false, reason: "no-home" };
    if (projectId === null || projectId === undefined || projectId === "") return { ok: false, reason: "no-project" };
    if (typeof workspaceDir !== "string" || !workspaceDir || typeof dataDir !== "string" || !dataDir) return { ok: false, reason: "no-workspace" };
    const rdProjects = realOrNull(join(dataDir, "projects"));
    const rdWs = realOrNull(workspaceDir);
    if (!rdProjects || !rdWs) return { ok: false, reason: "missing" };
    if (!strictlyBelow(rdWs, rdProjects)) return { ok: false, reason: "outside-projects" };

    let dir = trustedSecretsDir(home);
    if (!dir.dir && dir.reason === WORKSPACE_PINS_MISSING) {
      mkdirSync(join(home, "secrets"), { recursive: true, mode: 0o700 });
      dir = trustedSecretsDir(home);
    }
    if (!dir.dir) return { ok: false, reason: "store-unsafe" };
    return withLock(home, () => {
      const cur = readWorkspacePins({ crowHome: home });
      if (cur.reason && cur.reason !== WORKSPACE_PINS_MISSING) return { ok: false, reason: "store-unsafe" }; // never clobber a faulty store
      const key = String(projectId);
      for (const [other, e] of Object.entries(cur.pins)) {
        if (other !== key && e.path === rdWs) return { ok: false, reason: "path-pinned-to-another-project" };
      }
      const have = cur.pins[key];
      if (have && replace) { writeStore(home, { ...cur.pins, [key]: { path: rdWs, pinned_at: new Date().toISOString() } }); return { ok: true, path: rdWs, existed: true }; }
      if (have) return have.path === rdWs ? { ok: true, path: rdWs, existed: true } : { ok: false, reason: "pinned-elsewhere" };
      const pins = { ...cur.pins, [key]: { path: rdWs, pinned_at: new Date().toISOString() } };
      writeStore(home, pins);
      return { ok: true, path: rdWs, existed: false };
    });
  } catch {
    return { ok: false, reason: "error" };
  }
}
