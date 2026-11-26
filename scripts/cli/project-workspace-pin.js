#!/usr/bin/env node
/**
 * `project-workspace-pin` — show or set the workspace real path pinned for a project.
 *
 * A no-database contained bot spawn refuses a project whose `project_spaces.workspace_dir` (bot-writable
 * in crow.db) disagrees with the pin in <CROW_HOME>/secrets/project-workspaces.json
 * (servers/shared/project-workspace-pins.js). A project the boot backfill skipped, or one whose folder
 * legitimately moved, is pinned here by the operator.
 *
 * Usage (run in this instance's own environment: CROW_HOME, and CROW_DATA_DIR/CROW_DB_PATH as the gateway has):
 *   node scripts/cli/project-workspace-pin.js --show [--paths]
 *   node scripts/cli/project-workspace-pin.js <project_id> [--yes] [--replace]
 *   node scripts/cli/project-workspace-pin.js <project_id> --path <dir> [--yes] [--replace]
 *
 * --show prints `<project_id> pinned|none` (the path too with --paths).
 * `<project_id>` takes the project's CURRENT row after the backfill's shape checks and prints what it
 * would pin; nothing is written without --yes. `--path` pins an explicit folder, which must resolve
 * strictly below the real <data>/projects. A different existing pin is never overwritten without --replace.
 */
import { realpathSync } from "node:fs";
import { basename, dirname, join, resolve } from "node:path";
import { pathToFileURL } from "node:url";
import { resolveCrowHome } from "../../servers/shared/crow-home.js";
import { resolveDataDir, createDbClient } from "../../servers/db.js";
import { folderFitsProject, pinProjectWorkspace, readWorkspacePins } from "../../servers/shared/project-workspace-pins.js";

const USAGE = `Usage:
  node scripts/cli/project-workspace-pin.js --show [--paths]
  node scripts/cli/project-workspace-pin.js <project_id> [--yes] [--replace]
  node scripts/cli/project-workspace-pin.js <project_id> --path <dir> [--yes] [--replace]`;

const real = (p) => { try { return realpathSync(p); } catch { return null; } };

/** The backfill's shape rule for one row; returns the real path or a reason. */
export function judgeRow(row, dataDir, allRows = []) {
  if (!row.workspace_dir) return { why: "the project has no workspace_dir" };
  const ws = real(String(row.workspace_dir));
  if (!ws) return { why: "the project's workspace folder does not exist" };
  const rdProjects = real(join(dataDir, "projects"));
  if (!rdProjects || dirname(dirname(ws)) !== rdProjects || basename(ws) !== "workspace") return { why: "the workspace is not <data>/projects/<folder>/workspace" };
  if (!folderFitsProject(basename(dirname(ws)), row, allRows)) return { why: "the workspace folder name does not match the project's slug" };
  if (allRows.some((r) => r.id !== row.id && r.workspace_dir && real(String(r.workspace_dir)) === ws
    && folderFitsProject(basename(dirname(ws)), r, allRows))) return { why: "another project maps to the same folder" };
  return { path: ws };
}

export async function main({ argv = process.argv.slice(2), stdout = process.stdout, stderr = process.stderr, createDb = createDbClient } = {}) {
  const out = (s) => stdout.write(s);
  const fail = (s) => { stderr.write(`${s}\n`); return 1; };
  if (argv.includes("--help") || argv.includes("-h")) { out(`${USAGE}\n`); return 0; }
  const crowHome = resolveCrowHome();
  const dataDir = resolveDataDir();
  const flags = new Set(argv.filter((a) => a.startsWith("--") && a !== "--path"));
  const pi = argv.indexOf("--path");
  const explicit = pi >= 0 ? argv[pi + 1] : null;
  if (pi >= 0 && (!explicit || explicit.startsWith("--"))) return fail(`--path needs a directory\n${USAGE}`);
  const positional = argv.filter((a, i) => !a.startsWith("--") && (pi < 0 || i !== pi + 1));

  if (flags.has("--show")) {
    const store = readWorkspacePins({ crowHome });
    if (store.reason && store.reason !== "missing") stderr.write(`the pin store cannot be used (${store.reason})\n`);
    const db = createDb();
    try {
      const rows = (await db.execute("SELECT id, workspace_dir FROM project_spaces ORDER BY id")).rows;
      for (const r of rows) {
        const e = store.pins[String(r.id)];
        const differs = e && (!r.workspace_dir || real(String(r.workspace_dir)) !== e.path);
        out(`${r.id} ${e ? "pinned" : "none"}${differs ? " (row differs from pin)" : ""}${e && flags.has("--paths") ? " " + e.path : ""}\n`);
      }
    } finally { try { db.close?.(); } catch { /* gone */ } }
    return 0;
  }

  if (positional.length !== 1 || !/^\d+$/.test(positional[0])) return fail(`give --show, or a numeric <project_id>\n${USAGE}`);
  const id = Number(positional[0]);
  let target;
  if (explicit) {
    target = real(resolve(explicit));
    if (!target) return fail("that folder does not exist; nothing was written");
  } else {
    const db = createDb();
    try {
      const rows = (await db.execute("SELECT id, slug, workspace_dir FROM project_spaces")).rows;
      const row = rows.find((r) => Number(r.id) === id);
      if (!row) return fail(`project ${id} was not found`);
      const j = judgeRow(row, dataDir, rows);
      if (!j.path) return fail(`project ${id} is not pinned: ${j.why}; use --path to pin an explicit folder`);
      target = j.path;
    } finally { try { db.close?.(); } catch { /* gone */ } }
  }

  const have = readWorkspacePins({ crowHome }).pins[String(id)];
  if (have && have.path !== target && !flags.has("--replace")) return fail(`project ${id} is already pinned to a different folder; nothing was written (--replace to change it)`);
  if (have && have.path === target) { out(`project ${id} is already pinned to ${target}\n`); return 0; }
  if (!flags.has("--yes")) { out(`would pin project ${id} to ${target}\nnothing was written; add --yes to write it\n`); return 0; }

  if (have) {
    // --replace: the store never overwrites on its own, so drop the old pin first through a fresh store write.
    const { replaceWorkspacePin } = await import("../../servers/shared/project-workspace-pins.js");
    const r = replaceWorkspacePin(id, target, { crowHome, dataDir });
    if (!r.ok) return fail(`could not replace the pin (${r.reason}); nothing was written`);
  } else {
    const r = pinProjectWorkspace(id, target, { crowHome, dataDir });
    if (!r.ok) return fail(`could not pin project ${id} (${r.reason}); nothing was written`);
  }
  out(`project ${id} pinned to ${target}\n`);
  return 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then((code) => process.exit(code), (err) => {
    console.error(`FAIL: ${err?.message || err}`);
    process.exit(1);
  });
}
