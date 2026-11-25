#!/usr/bin/env node
/**
 * `report-pickup` — the operator's switch for report comment replies.
 *
 * With the switch on, a bot may answer reader comments on a live report (servers/gateway/reports/pickup.js).
 * It is OFF by default: this box does not run a model on a reader's words until the operator says so.
 *
 * Usage (run in the instance's own environment: CROW_HOME / CROW_DATA_DIR decide which crow.db):
 *   node scripts/cli/report-pickup.js on
 *   node scripts/cli/report-pickup.js off
 *   node scripts/cli/report-pickup.js --show
 *
 * The switch is `reports.pickup_enabled` in `dashboard_settings`, written through the settings registry's
 * own writer as a THIS-INSTANCE setting (whether this box runs a model on comments is this box's
 * decision, so it is never synced to a paired peer). `--show` prints on/off, the quiet minutes and the
 * budget minutes. Exit codes: 0 ok, 1 bad input or a failure.
 */
import { statSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { pathToFileURL } from "node:url";
import { createDbClient } from "../../servers/db.js";
import { resolveInstanceDataDir } from "../../servers/shared/crow-home.js";
import { writeSetting } from "../../servers/gateway/dashboard/settings/registry.js";
import {
  PICKUP_ENABLED_KEY, pickupEnabled, pickupLimits,
} from "../../servers/gateway/reports/pickup.js";

const USAGE = `Usage:
  node scripts/cli/report-pickup.js on
  node scripts/cli/report-pickup.js off
  node scripts/cli/report-pickup.js --show`;

function parse(argv) {
  if (argv.length !== 1) return { error: "give exactly one of on, off, --show" };
  const [a] = argv;
  if (a === "on" || a === "off") return { act: a };
  if (a === "--show") return { act: "show" };
  return { error: `unknown argument ${JSON.stringify(String(a).slice(0, 40))}` };
}

async function show(db, out) {
  const on = await pickupEnabled(db);
  const { quietMinutes, budgetMinutes } = await pickupLimits(db);
  out(`report comment replies: ${on ? "on" : "off"}\n`);
  out(`quiet minutes: ${quietMinutes}\n`);
  out(`budget minutes per report per day: ${budgetMinutes}\n`);
  return 0;
}

/**
 * Run the CLI. `env` and the streams are test seams. Returns the exit code.
 */
export async function main({ argv = process.argv.slice(2), env = process.env, stdout = process.stdout, stderr = process.stderr } = {}) {
  const out = (s) => stdout.write(s);
  const fail = (s) => { stderr.write(`${s}\n`); return 1; };
  const args = parse(argv);
  if (args.error) return fail(`${args.error}\n${USAGE}`);
  const dbPath = env.CROW_DB_PATH || resolvePath(resolveInstanceDataDir(env), "crow.db");
  try { statSync(dbPath); } catch { return fail(`cannot read the database at ${dbPath}`); }

  // The data dir and the instance id resolve from process.env; apply ours for the call.
  const keys = ["CROW_HOME", "CROW_DATA_DIR", "CROW_DB_PATH"];
  const saved = Object.fromEntries(keys.map((k) => [k, process.env[k]]));
  for (const k of keys) { if (env[k] === undefined) delete process.env[k]; else process.env[k] = env[k]; }
  let db;
  try {
    db = createDbClient(dbPath);
    if (args.act === "show") return await show(db, out);
    await writeSetting(db, PICKUP_ENABLED_KEY, args.act === "on" ? "true" : "false", { scope: "local" });
    out(`report comment replies: ${args.act}\n`);
    return 0;
  } catch (err) {
    return fail(`report-pickup failed: ${err?.code || "error"}`);
  } finally {
    try { db?.close?.(); } catch { /* closed */ }
    for (const k of keys) { if (saved[k] === undefined) delete process.env[k]; else process.env[k] = saved[k]; }
  }
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  main().then((code) => process.exit(code), (err) => { console.error(err?.message || err); process.exit(1); });
}
