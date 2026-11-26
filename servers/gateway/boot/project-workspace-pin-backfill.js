/**
 * boot/project-workspace-pin-backfill.js — pin the workspace real path of every project that
 * existed before the pin did (servers/shared/project-workspace-pins.js).
 *
 * `project_spaces.workspace_dir` is bot-writable (crow.db is bound read-write into a contained
 * bot), so this runs ONCE, before any route serves, and pins a row only when it looks exactly like
 * what project creation makes: the real path is `<real data>/projects/<folder>/workspace`, the
 * folder is the slug, `slug-N` or ends in `-<id>`, and no other row maps to the same real path.
 * Anything else is skipped and counted (never named); a skipped project has no pin, so a no-database
 * bot spawn for it is refused until the owner pins it.
 *
 * ONCE EVER is a marker in its OWN 0600 file (<CROW_HOME>/secrets/project-workspace-pin-backfill.json),
 * never "are there unpinned rows?", so a bot that rewrites a row later cannot get it pinned by a
 * reboot. Fail-soft: errors are logged and swallowed; a DB that could not be read leaves the marker
 * unwritten so the next boot retries.
 */
import { closeSync, constants as fsConstants, fsyncSync, mkdirSync, openSync, realpathSync, renameSync, unlinkSync, writeSync } from "node:fs";
import { basename, dirname, join } from "node:path";
import { randomBytes } from "node:crypto";
import { resolveCrowHome } from "../../shared/crow-home.js";
import { resolveDataDir } from "../../db.js";
import { folderFitsProject, pinProjectWorkspace, readOwnerOnlyFile, readWorkspacePins } from "../../shared/project-workspace-pins.js";

export const PIN_BACKFILL_MARKER_FILE = "project-workspace-pin-backfill.json";
const markerPath = (home) => join(String(home), "secrets", PIN_BACKFILL_MARKER_FILE);

function markerDoneAt(home) {
  const f = readOwnerOnlyFile(markerPath(home), 4096);
  if (f.raw === null) return null;
  try { const j = JSON.parse(f.raw); return typeof j?.done_at === "string" ? j.done_at : null; } catch { return null; }
}

function writeMarker(home) {
  try {
    mkdirSync(join(String(home), "secrets"), { recursive: true, mode: 0o700 });
    const dest = markerPath(home);
    const tmp = `${dest}.${process.pid}.${randomBytes(4).toString("hex")}.tmp`;
    const fd = openSync(tmp, fsConstants.O_WRONLY | fsConstants.O_CREAT | fsConstants.O_EXCL, 0o600);
    try { writeSync(fd, JSON.stringify({ version: 1, done_at: new Date().toISOString() }) + "\n"); fsyncSync(fd); } finally { closeSync(fd); }
    try { renameSync(tmp, dest); } catch (e) { try { unlinkSync(tmp); } catch { /* gone */ } throw e; }
    return true;
  } catch { return false; }
}

const real = (p) => { try { return realpathSync(p); } catch { return null; } };

/**
 * @param {object} o
 * @param {() => object} o.createDbClient
 * @param {string} [o.crowHome] @param {string} [o.dataDir]
 * @returns {Promise<{ran: boolean, pinned: number, skipped: number, counts: object, alreadyDoneAt?: string}>}
 */
export async function runProjectWorkspacePinBackfill({ createDbClient, crowHome, dataDir, log = console.log, warn = console.warn } = {}) {
  const counts = { "no-workspace": 0, missing: 0, shape: 0, slug: 0, shared: 0 };
  const out = { ran: false, pinned: 0, skipped: 0, counts };
  let db = null;
  try {
    const home = crowHome || resolveCrowHome();
    const done = markerDoneAt(home);
    if (done) return { ...out, alreadyDoneAt: done };
    const store = readWorkspacePins({ crowHome: home });
    if (store.reason && store.reason !== "missing") {
      warn("[workspace-pin] backfill skipped: the pin store cannot be used; it will retry on the next boot");
      return out;
    }
    out.ran = true;
    const data = dataDir || resolveDataDir();
    const rdProjects = real(join(data, "projects"));
    db = createDbClient();
    let rows;
    try {
      rows = (await db.execute("SELECT id, slug, workspace_dir FROM project_spaces")).rows;
    } catch {
      warn("[workspace-pin] backfill skipped: the project rows could not be read; it will retry on the next boot");
      return out;
    }
    const resolved = rows.map((r) => ({ id: r.id, slug: String(r.slug ?? ""), ws: r.workspace_dir ? real(String(r.workspace_dir)) : null, set: !!r.workspace_dir }));
    // A row's folder name is judged first; only rows that fit count toward "shared", so a rewritten
    // row pointing at another project's folder is a "slug" skip and never costs the real owner its pin.
    const shapeOf = (r) => {
      if (!r.set) return "no-workspace";
      if (!r.ws) return "missing";
      if (!rdProjects || dirname(dirname(r.ws)) !== rdProjects || basename(r.ws) !== "workspace") return "shape";
      if (!folderFitsProject(basename(dirname(r.ws)), { id: r.id, slug: r.slug }, resolved)) return "slug";
      return null;
    };
    for (const r of resolved) r.why = shapeOf(r);
    const byReal = new Map();
    for (const r of resolved) if (!r.why) byReal.set(r.ws, (byReal.get(r.ws) || 0) + 1);
    let writeFailed = false;
    for (const r of resolved) {
      let why = r.why;
      if (!why && byReal.get(r.ws) > 1) why = "shared";
      if (why) { counts[why]++; out.skipped++; continue; }
      const p = pinProjectWorkspace(r.id, r.ws, { crowHome: home, dataDir: data });
      if (p.ok) out.pinned++;
      else if (p.reason === "pinned-elsewhere") { counts.shared++; out.skipped++; }
      else { writeFailed = true; counts.shape++; out.skipped++; }
    }
    log(`[workspace-pin] backfill: ${out.pinned} pinned, ${out.skipped} skipped (no-workspace: ${counts["no-workspace"]}, missing: ${counts.missing}, shape: ${counts.shape}, slug: ${counts.slug}, shared: ${counts.shared})`);
    if (writeFailed) { warn("[workspace-pin] a pin could not be written; the backfill will run again on the next boot"); return out; }
    if (!writeMarker(home)) warn("[workspace-pin] could not write the one-time marker; the backfill will run again on the next boot");
  } catch {
    warn("[workspace-pin] backfill skipped; it will retry on the next boot");
  } finally {
    try { db?.close?.(); } catch { /* gone */ }
  }
  return out;
}
