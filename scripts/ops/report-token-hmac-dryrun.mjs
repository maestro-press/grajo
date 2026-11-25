#!/usr/bin/env node
/**
 * DRY RUN of the `report:link` conversion (§8 PR 5a of the keyed-token-hashes design), for an
 * operator who wants to see what the next gateway boot will do to a real store BEFORE it does it.
 *
 * Nothing outside its own scratch directory is touched. Every `--db` is COPIED (with its instance
 * id, taken from `<db dir>/instance-id` or `<files-from>/data/instance-id`; a DB it cannot
 * attribute STOPS the run) into a scratch CROW_HOME, and the real converter
 * (`runReportLinkTokenHmacBoot`) runs against the copy twice, exactly as the pre-listen boot will.
 *
 * PER LABEL it prints: rows (total, non-revoked, revoked, expired), how many would be converted,
 * how many old-style values are refused, alarms, and
 *   "live links verifying: before N, after M"
 * where a LIVE link is a row that is neither revoked nor expired. The dry run has no raw tokens,
 * only hashes, so a live row counts as verifying BEFORE when its stored value is a 64-hex sha256,
 * and AFTER when its stored value equals the keyed MAC computed from that same legacy hash (the
 * computation the verifier performs on sha256(raw)). M < N is a STOP. Counts only: never a token,
 * a hash, a row id or a key id.
 *
 * STOP (exit 1) when: a DB cannot be read or attributed; the key is lost/unusable; the conversion
 * fails or is skipped; any old-style value is refused or alarmed; live links verifying after is
 * lower than before; the family is not marked converted; or a second pass is not a no-op.
 *
 *   node scripts/ops/report-token-hmac-dryrun.mjs --db crow=/path/copied/crow.db \
 *     [--files-from ~/.crow] [--home <scratch dir>]
 *
 * Run with the gateway STOPPED. A rehearsal, never the migration itself.
 */
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { createDbClient } from "../../servers/db.js";
import { resolveCrowHome } from "../../servers/shared/crow-home.js";
import { forgetTokenMacKey, macFromLegacy, readState } from "../../servers/shared/token-mac.js";
import {
  REPORT_LINK_FAMILY, forgetForcedReportLinkLegacyRefusal, forgetReportLinkEvidence, isLegacyStored,
} from "../../servers/gateway/reports/link-token.js";
import { runReportLinkTokenHmacBoot } from "../../servers/gateway/boot/token-hmac-reports.js";

function usage(code = 2) {
  console.error("usage: node scripts/ops/report-token-hmac-dryrun.mjs --db <label>=<path> [--db ...]");
  console.error("         [--files-from <CROW_HOME>] [--home <scratch dir>]");
  console.error("  --db <label>=<path>   a COPY of one instance's crow.db to rehearse the conversion on");
  console.error("  --files-from <home>   where that instance's data/instance-id lives if none sits beside the DB");
  console.error("  --home <dir>          scratch CROW_HOME for the rehearsal (default: a fresh temp dir)");
  console.error("Prints per-label counts and one PASS/STOP verdict. Changes nothing outside the scratch dir.");
  process.exit(code);
}

function parseArgs(argv) {
  const out = { dbs: [], filesFrom: null, home: null };
  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    const value = () => {
      const v = argv[i + 1];
      if (v === undefined || v.startsWith("--")) usage();
      i += 1;
      return v;
    };
    if (arg === "--db") {
      const spec = value();
      const at = spec.indexOf("=");
      if (at <= 0) usage();
      out.dbs.push({ label: spec.slice(0, at), path: resolve(spec.slice(at + 1)) });
    } else if (arg === "--files-from") out.filesFrom = resolve(value());
    else if (arg === "--home") out.home = resolve(value());
    else if (arg === "--help" || arg === "-h") usage(0);
    else usage();
  }
  if (out.dbs.length === 0) usage();
  return out;
}

const stamp = () => new Date().toISOString().replace(/[:.]/g, "-");
const problems = [];

function instanceIdFor(dbPath, filesFrom) {
  for (const candidate of [join(dirname(dbPath), "instance-id"), join(filesFrom, "data", "instance-id")]) {
    try {
      const id = readFileSync(candidate, "utf8").trim();
      if (id) return id;
    } catch { /* try the next */ }
  }
  return null;
}

/** Every link row as `{id, stored, revoked, expires}`; null when the table does not exist. */
async function linkRows(db) {
  try {
    const { rows } = await db.execute({
      sql: "SELECT id AS id, token_hash AS stored, revoked_at AS revoked, expires_at AS expires FROM report_link_tokens",
      args: [],
    });
    return rows.map((r) => ({
      id: String(r.id ?? ""),
      stored: String(r.stored ?? ""),
      revoked: r.revoked != null,
      expires: r.expires == null ? null : Number(r.expires),
    }));
  } catch (err) {
    if (/no such table/i.test(String(err?.message || ""))) return null;
    throw err;
  }
}

async function rehearse({ label, path }, { filesFrom, root }) {
  const home = join(root, label);
  const dataDir = join(home, "data");
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const dbPath = join(dataDir, "crow.db");
  const sourceDb = resolve(path);
  if (!existsSync(sourceDb)) {
    problems.push(`${label}: the database does not exist`);
    return;
  }
  copyFileSync(sourceDb, dbPath);
  for (const suffix of ["-wal", "-shm"]) {
    const sidecar = `${sourceDb}${suffix}`;
    if (existsSync(sidecar)) {
      try { copyFileSync(sidecar, `${dbPath}${suffix}`); } catch { /* best effort */ }
    }
  }
  const instanceId = instanceIdFor(sourceDb, filesFrom);
  if (!instanceId) {
    problems.push(`${label}: no instance-id beside the DB, so the era mirror could not be attributed`);
    return;
  }
  writeFileSync(join(dataDir, "instance-id"), `${instanceId}\n`, { mode: 0o600 });
  mkdirSync(join(home, "secrets"), { recursive: true, mode: 0o700 });

  process.env.CROW_HOME = home;
  process.env.CROW_DATA_DIR = dataDir;
  process.env.CROW_DB_PATH = dbPath;
  forgetTokenMacKey();
  forgetReportLinkEvidence();
  forgetForcedReportLinkLegacyRefusal();

  const db = createDbClient(dbPath);
  try {
    const before = await linkRows(db);
    const now = Date.now();
    const rows = before ?? [];
    const isLive = (r) => !r.revoked && (r.expires == null || r.expires > now);
    const legacyById = new Map(rows.filter((r) => isLegacyStored(r.stored)).map((r) => [r.id, r.stored.toLowerCase()]));
    const live = rows.filter(isLive);
    const verifyingBefore = live.filter((r) => legacyById.has(r.id)).length;

    const first = await runReportLinkTokenHmacBoot({ db });
    const second = await runReportLinkTokenHmacBoot({ db });

    const after = (await linkRows(db)) ?? [];
    const afterById = new Map(after.map((r) => [r.id, r.stored]));
    let verifyingAfter = 0;
    if (first.key === "ok") {
      for (const r of live) {
        const legacy = legacyById.get(r.id);
        if (legacy && afterById.get(r.id) === macFromLegacy(REPORT_LINK_FAMILY, legacy)) verifyingAfter += 1;
      }
    }
    const refused = after.filter((r) => isLegacyStored(r.stored)).length;
    const revokedN = rows.filter((r) => r.revoked).length;
    const expiredN = rows.filter((r) => !r.revoked && r.expires != null && r.expires <= now).length;

    console.log(`  ${label}  rows: ${rows.length} (non-revoked ${rows.length - revokedN}, revoked ${revokedN}, expired ${expiredN})`);
    console.log(`  ${label}  ${first.converted} row(s) would be converted, ${refused} old-style value(s) refused, ${first.alarms} alarm(s)`);
    console.log(`  ${label}  live links verifying: before ${verifyingBefore}, after ${verifyingAfter}`);
    console.log(`  ${label}  second boot: converted ${second.converted}, alarms ${second.alarms}${before === null ? " (no report_link_tokens table)" : ""}`);

    if (first.key !== "ok") problems.push(`${label}: no usable token-hmac key (${first.key})`);
    if (!first.family) problems.push(`${label}: the conversion reported no result`);
    if (first.family?.state === "failed") problems.push(`${label}: the conversion FAILED`);
    if (first.family?.state === "skipped") problems.push(`${label}: the conversion was skipped (${first.family.reason})`);
    if (refused) problems.push(`${label}: ${refused} old-style value(s) would be REFUSED`);
    if (first.alarms) problems.push(`${label}: ${first.alarms} old-style value(s) were reported after the conversion`);
    if (verifyingAfter < verifyingBefore) {
      problems.push(`${label}: live links verifying drops from ${verifyingBefore} to ${verifyingAfter}`);
    }
    if (second.converted !== 0) problems.push(`${label}: a second pass converted ${second.converted} row(s) — the era did not stick`);
    if (second.alarms !== 0) problems.push(`${label}: a second pass still reports ${second.alarms} old-style row(s)`);
    if (!readState().families[REPORT_LINK_FAMILY]?.converted_at) {
      problems.push(`${label}: ${REPORT_LINK_FAMILY} is not marked converted in the era state`);
    }
  } finally {
    db.close();
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const filesFrom = args.filesFrom || resolveCrowHome();
  const root = args.home || mkdtempSync(join(tmpdir(), `crow-report-token-dryrun-${stamp()}-`));
  mkdirSync(root, { recursive: true, mode: 0o700 });

  console.log("");
  console.log(`Rehearsing the ${REPORT_LINK_FAMILY} conversion on ${args.dbs.length} copied database(s).`);
  console.log(`  scratch CROW_HOME: ${root}`);
  console.log("");
  try {
    for (const spec of args.dbs) {
      console.log(`${spec.label}:`);
      // eslint-disable-next-line no-await-in-loop -- one instance at a time, by design
      await rehearse(spec, { filesFrom, root });
      console.log("");
    }
  } finally {
    if (!args.home) {
      try { rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  }

  if (problems.length) {
    for (const problem of problems) console.log(`  - ${problem}`);
    console.log(`STOP: the ${REPORT_LINK_FAMILY} conversion above is not a clean rehearsal (nothing was changed).`);
    return 1;
  }
  console.log(`PASS: every ${REPORT_LINK_FAMILY} row converts, nothing is refused, no live link stops verifying,`);
  console.log("and a second boot changes nothing.");
  return 0;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.log(`STOP: the rehearsal failed (${err?.message || err}); nothing was changed.`);
    process.exit(1);
  },
);
