#!/usr/bin/env node
/**
 * DRY RUN of the §1a settings-token conversion (§8 PR 3a of the keyed-token-hashes design),
 * for an operator who wants to see what the next gateway boot will do to a real store BEFORE
 * it does it.
 *
 * WHAT IT DOES — and does not — TOUCH. Nothing outside its own scratch directory. Every
 * `--db` is COPIED (with its instance id and the raw token files the conversion proves against)
 * into a scratch CROW_HOME, and the real converter (`runSettingsTokenHmacBoot`) runs against the
 * copy, exactly as the pre-listen boot will run against the real one — including the STEP THAT
 * ROTATES the six boot-rotated families (the cloud door and the path-scoped loopback families):
 * that rotation mints its fresh token into the scratch home's own `llm-cloud-token` and
 * `secrets/*-token` files and stores the keyed verifier there, so the rehearsal reaches PASS on
 * a healthy box and a failure shows up here instead of on the next real boot. The source DB
 * files are opened read-only, once, to copy them; the source home is only read, and the source
 * instance's token files are never written, rotated or re-minted. No key is created there, no
 * row is written there, no token file is moved.
 *
 * WHY A COPY OF EACH DB NEEDS ITS INSTANCE ID. The settings are read override-first: a value in
 * `dashboard_settings_overrides` belongs to ONE instance id, so a copy that minted a fresh id
 * would silently read only the global rows and report a conversion the boot would not perform.
 * The id is therefore taken from `<db dir>/instance-id` beside each `--db` (or `--instance-id`),
 * and a DB it cannot attribute STOPS the run.
 *
 * WHAT IT PRINTS. Per family: the action the boot would take, and whether a stored value had to
 * be refused — split by REASON, because the two mean different things: `proof file` (a
 * file-backed family whose token file is missing, is not a regular file of ours, or is
 * group/world-writable, so it proves nothing — the boot refuses that value and re-mints the
 * family) and `global row` (a value in the GLOBAL `dashboard_settings` row, which a per-instance
 * token key is never read from: the boot moves a legacy one into the override once, and treats a
 * global row that coexists with an override as anomalous). It also reports, per file-backed
 * family, whether the SOURCE home's real token file — the one on this box, not the copy — passes
 * the same trust check (`trustedProofFile`, read-only), so a PASS covers the files themselves and
 * not just the rehearsal's copies. Then one verdict line — `PASS` or `STOP: <reason>` — and
 * counts. Never a token, never a hash, never a key id.
 *
 * STOP (exit 1) when: a DB or token file cannot be read; the instance id cannot be told; the
 * token-hmac key is lost or unusable; any family FAILS or is SKIPPED; any stored value is
 * refused (by proof file, as an anomalous global row, or after a snapshot); a SOURCE token file
 * that backs a stored old-style value is not a trustworthy proof file; any boot-rotated family
 * still holds an old-style value after the boot's own rotation; a second pass over the converted
 * copy is not a no-op; or a family is not marked converted in the era state afterwards.
 * PASS (exit 0) means: every family the boot would visit converts (or is minted fresh by the
 * boot's rotation), nothing is refused, and a second boot changes nothing.
 *
 *   node scripts/ops/settings-token-hmac-dryrun.mjs \
 *     --db crow=/path/copied/crow.db \
 *     --db r4=/path/copied/r4.db \
 *     --files-from ~/.crow          # optional: where the raw token files live (default $CROW_HOME)
 *
 * Run with the gateway STOPPED (a live gateway would be converting the same rows underneath the
 * copy). This is a read-only rehearsal, never the migration itself.
 */
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { tmpdir } from "node:os";
import { createDbClient } from "../../servers/db.js";
import { resolveCrowHome } from "../../servers/shared/crow-home.js";
import { forgetTokenMacKey, readState } from "../../servers/shared/token-mac.js";
import {
  ROTATED_AT_BOOT, SETTINGS_TOKEN_FAMILIES, forgetForcedSettingsLegacyRefusal, forgetSettingsTokenEvidence,
  isLegacyStored, settingsTokenRawFile, storedForms,
} from "../../servers/gateway/token-settings.js";
import { runSettingsTokenHmacBoot, trustedProofFile } from "../../servers/gateway/boot/token-hmac-settings.js";

/** The families whose conversion proves the stored value against a raw token file. */
const FILE_BACKED = SETTINGS_TOKEN_FAMILIES.filter((f) => settingsTokenRawFile(f, "/x") !== null);

function usage(code = 2) {
  console.error("usage: node scripts/ops/settings-token-hmac-dryrun.mjs --db <label>=<path> [--db ...]");
  console.error("         [--files-from <CROW_HOME>] [--home <scratch dir>]");
  console.error("  --db <label>=<path>   a COPY of one instance's crow.db to rehearse the conversion on");
  console.error("  --files-from <home>   where that instance's raw token files live (default: this $CROW_HOME)");
  console.error("  --home <dir>          scratch CROW_HOME for the rehearsal (default: a fresh temp dir)");
  console.error("");
  console.error("Prints per-family actions and one PASS/STOP verdict. Changes nothing outside the scratch dir.");
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

/** `2026-11-23T16:41:02.123Z` → a file-name-safe stamp. */
const stamp = () => new Date().toISOString().replace(/[:.]/g, "-");

/** One refusal/verdict collector; the LAST line the operator reads is PASS or STOP. */
const problems = [];

/** A DB copy is not attributable without its instance id: overrides are keyed by it. */
function instanceIdFor(dbPath, filesFrom) {
  for (const candidate of [join(dirname(dbPath), "instance-id"), join(filesFrom, "data", "instance-id")]) {
    try {
      const id = readFileSync(candidate, "utf8").trim();
      if (id) return { id, path: candidate };
    } catch { /* try the next */ }
  }
  return null;
}

/**
 * Rehearse one instance: copy the DB, its instance id and the raw token files into its own
 * scratch home, convert the copy twice, and report.
 */
async function rehearse({ label, path }, { filesFrom, root }) {
  const home = join(root, label);
  const dataDir = join(home, "data");
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const dbPath = join(dataDir, "crow.db");
  const sourceDb = resolve(path);
  if (!existsSync(sourceDb)) {
    problems.push(`${label}: ${sourceDb} does not exist`);
    return null;
  }
  copyFileSync(sourceDb, dbPath);
  // WAL sidecars, when present: a copy without them can miss the most recent writes.
  for (const suffix of ["-wal", "-shm"]) {
    const sidecar = `${sourceDb}${suffix}`;
    if (existsSync(sidecar)) {
      try { copyFileSync(sidecar, `${dbPath}${suffix}`); } catch { /* best effort */ }
    }
  }
  const instance = instanceIdFor(sourceDb, filesFrom);
  if (!instance) {
    problems.push(`${label}: no instance-id beside the DB, so its override rows cannot be attributed`);
    return null;
  }
  writeFileSync(join(dataDir, "instance-id"), `${instance.id}\n`, { mode: 0o600 });

  // The raw token files the conversion PROVES against, copied (never linked: a link would let
  // the rehearsal's scratch home be the operator's real one by accident).
  const missingFiles = [];
  for (const family of FILE_BACKED) {
    const source = settingsTokenRawFile(family, filesFrom);
    const target = settingsTokenRawFile(family, home);
    if (!source || !existsSync(source)) { missingFiles.push(family); continue; }
    mkdirSync(dirname(target), { recursive: true, mode: 0o700 });
    try { copyFileSync(source, target); } catch (err) {
      problems.push(`${label}: ${family}: its token file could not be copied (${err.code || err.message})`);
    }
  }

  // Point every resolver at this instance, and forget every per-process cache of the last one.
  process.env.CROW_HOME = home;
  process.env.CROW_DATA_DIR = dataDir;
  process.env.CROW_DB_PATH = dbPath;
  forgetTokenMacKey();
  forgetSettingsTokenEvidence();
  forgetForcedSettingsLegacyRefusal();

  const db = createDbClient(dbPath);
  try {
    const forms = new Map();
    for (const family of SETTINGS_TOKEN_FAMILIES) {
      // eslint-disable-next-line no-await-in-loop -- thirteen settings reads, one operator run
      forms.set(family, await storedForms(db, family));
    }
    // THE REAL FILES. The rehearsal proves a stored legacy value against a COPY of each token
    // file, so a PASS must also mean the SOURCE files would be trusted on the real box: a file
    // that is a symlink, another owner's, or group/world-writable proves nothing there either —
    // and the copy would happily copy its TARGET's bytes, which is exactly the false PASS this
    // check removes. read-only: `trustedProofFile` opens, judges and closes, and no value is
    // printed.
    const proofs = new Map();
    for (const family of FILE_BACKED) {
      const source = settingsTokenRawFile(family, filesFrom);
      const trusted = Boolean(source) && trustedProofFile(source);
      const backsOldStyle = (forms.get(family) || []).some((form) => isLegacyStored(form.value));
      proofs.set(family, { source, trusted, backsOldStyle });
    }
    // eslint-disable-next-line no-await-in-loop -- one conversion, then one re-check
    const first = await runSettingsTokenHmacBoot({ db });
    // eslint-disable-next-line no-await-in-loop -- the re-check is the zero-window proof
    const second = await runSettingsTokenHmacBoot({ db });

    const rows = [];
    for (const entry of first.families) {
      const before = forms.get(entry.family) || [];
      const forms_ = before.length === 0 ? "none" : before.map((f) => f.store).join("+");
      const action = entry.state === "failed" ? "FAILED"
        : entry.state === "skipped" ? "SKIPPED"
          : entry.rotated ? "rotated (the boot mints a fresh keyed value)"
            : entry.count ? `converted ${entry.count}` : "marked (nothing old-style)";
      const refused = entry.refused || 0;
      const why = [
        entry.refusedProofFile ? `${entry.refusedProofFile} proof file` : null,
        entry.refusedGlobal ? `${entry.refusedGlobal} global row` : null,
      ].filter(Boolean).join(" + ");
      rows.push({ family: entry.family, stored: forms_, action, refused, why });
    }
    for (const row of rows) {
      console.log(`  ${label}  ${row.family.padEnd(30)} ${row.stored.padEnd(12)} ${row.action}`
        + (row.refused ? `  ${row.refused} REFUSED${row.why ? ` (${row.why})` : ""}` : ""));
    }
    for (const [family, proof] of proofs) {
      console.log(`  ${label}  proof file ${family.padEnd(22)} ${proof.trusted ? "trusted" : "NOT trusted"}`
        + `${proof.backsOldStyle ? " (backs a stored old-style value)" : " (no stored old-style value)"}`);
      if (proof.backsOldStyle && !proof.trusted) {
        problems.push(
          `${label}: ${family}: the SOURCE token file ${proof.source} is not a trustworthy proof file `
          + "(missing, a symlink, another owner's, or group/world-writable), so the real boot would refuse "
          + "the stored value it stands for",
        );
      }
    }

    if (first.key !== "ok") problems.push(`${label}: no usable token-hmac key (${first.key})`);
    for (const entry of first.families) {
      if (entry.state === "failed") problems.push(`${label}: ${entry.family} conversion FAILED`);
      if (entry.state === "skipped") problems.push(`${label}: ${entry.family} was skipped (${entry.reason})`);
      if (entry.refusedProofFile) {
        problems.push(
          `${label}: ${entry.family}: ${entry.refusedProofFile} stored value(s) no TRUSTWORTHY token file proves — `
          + "the value would be refused (log + audit) after conversion and the family re-minted from a fresh token file",
        );
      }
      if (entry.refusedGlobal) {
        problems.push(
          `${label}: ${entry.family}: ${entry.refusedGlobal} value(s) sit in the GLOBAL dashboard_settings row, which a `
          + "per-instance token key is never read from — that row would be refused (log + audit), not converted",
        );
      }
      if (entry.refused && !entry.refusedProofFile && !entry.refusedGlobal) {
        problems.push(
          `${label}: ${entry.family}: ${entry.refused} stored value(s) nothing proves — they would be `
          + "refused (log + audit) after conversion",
        );
      }
    }
    if (second.converted !== 0) {
      problems.push(`${label}: a second pass converted ${second.converted} value(s) — the era did not stick`);
    }
    if (second.alarms !== 0) problems.push(`${label}: a second pass still reports ${second.alarms} old-style value(s)`);
    // That second pass is what a later boot does, so it would have reported (and refused) any
    // old-style value the rotation left behind. Check the stores directly too: a boot-rotated
    // family marked converted while still holding an old-style value is exactly the false alarm
    // six families raised on the first upgraded boot before the rotation moved into the converter.
    for (const family of ROTATED_AT_BOOT) {
      // eslint-disable-next-line no-await-in-loop -- six reads, one operator run
      const left = (await storedForms(db, family)).filter((f) => isLegacyStored(f.value));
      if (left.length) {
        problems.push(`${label}: ${family} is still old-style after the boot's rotation (${left.map((f) => f.store).join(",")})`);
      }
    }

    const state = readState();
    for (const family of SETTINGS_TOKEN_FAMILIES) {
      if (!state.families[family]?.converted_at) problems.push(`${label}: ${family} is not marked converted in the era state`);
    }

    console.log(`  ${label}: ${first.converted} stored value(s) would be converted, `
      + `${first.families.filter((f) => f.rotated).length} family(ies) rotated to a fresh keyed value, `
      + `${first.refused} refused (${first.refusedProofFile} by proof file, ${first.refusedGlobal} as an anomalous global row), `
      + `${first.alarms} old-style value(s) reported`);
    if (missingFiles.length) {
      console.log(`  ${label}: no raw token file for ${missingFiles.join(", ")} — those families are the boot-rotated ones, minted fresh by this boot`);
    }
    return { first, second };
  } finally {
    db.close();
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const filesFrom = args.filesFrom || resolveCrowHome();
  const root = args.home || mkdtempSync(join(tmpdir(), `crow-token-dryrun-${stamp()}-`));
  mkdirSync(root, { recursive: true, mode: 0o700 });

  console.log("");
  console.log(`Rehearsing the settings-token conversion on ${args.dbs.length} copied database(s).`);
  console.log(`  raw token files from: ${filesFrom}`);
  console.log(`  scratch CROW_HOME:    ${root}`);
  console.log("");

  try {
    for (const spec of args.dbs) {
      console.log(`${spec.label}:`);
      // eslint-disable-next-line no-await-in-loop -- one instance at a time, by design
      await rehearse(spec, { filesFrom, root });
      console.log("");
    }
  } finally {
    // The scratch home holds a key and this run's snapshots; it is a rehearsal, not a box.
    if (!args.home) {
      try { rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  }

  if (problems.length) {
    for (const problem of problems) console.log(`  - ${problem}`);
    console.log("STOP: the conversion above is not a clean rehearsal (nothing was changed).");
    return 1;
  }
  console.log("PASS: every family converts, nothing is refused, and a second boot changes nothing.");
  return 0;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    console.log(`STOP: the rehearsal failed (${err?.message || err}); nothing was changed.`);
    process.exit(1);
  },
);