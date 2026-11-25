#!/usr/bin/env node
/**
 * DRY RUN of the `peer:inbound` conversion (§1b/§8 PR 4 of the keyed-token-hashes design), for an
 * operator who wants to see what the next gateway boot will do to a real store BEFORE it does it.
 *
 * WHAT IT DOES — and does not — TOUCH. Nothing outside its own scratch directory. Every `--db`
 * is COPIED (with its instance id and a copy of `secrets/peer-tokens.json`) into a scratch
 * CROW_HOME, and the real converter (`runPeerTokenHmacBoot`) runs against the copy, twice, exactly
 * as the pre-listen boot will run against the real one. The source DB files are opened read-only,
 * once, to copy them; the source home is only read. No key is created there, no row is written
 * there, and the source credential store is never rewritten.
 *
 * WHY A COPY OF EACH DB NEEDS ITS INSTANCE ID. Nothing in this family is instance-scoped, but the
 * era mirror (`token_hmac_era:peer:inbound`) IS written as this instance's local override, and a
 * copy that minted a fresh id would report an era the boot would not record. The id is therefore
 * taken from `<db dir>/instance-id` beside each `--db`, and a DB it cannot attribute STOPS the run.
 *
 * WHY THE CREDENTIAL STORE IS COPIED TOO. The conversion records the pre-conversion value the
 * re-pair proof is keyed by (design D4) in `secrets/peer-tokens.json`, so the rehearsal must be
 * able to write that record — and it must prove the record is USEFUL: for every converted peer
 * that has a signing key on this home, `repairProofKey` computed from the recorded value must
 * equal the key computed from the pre-conversion legacy hash. That equality is the whole point of
 * D4: if it fails, every re-pair proof on that box would fail once the conversion happened.
 *
 * WHAT IT PRINTS. Per label: the number of rows holding a stored verifier, how many would be
 * converted, how many old-style values are refused (they were written after the snapshot, or the
 * family was already converted), the alarms, how many credential records gained
 * `inbound_bearer_sha256`, HOW MANY ROWS HAVE NO CREDENTIAL RECORD AT ALL (reported, never
 * refused: such a row still converts, it just cannot have a re-pair proof keyed for it), and the
 * re-pair proof check. Then one verdict line — `PASS` or `STOP: <reason>`. Counts only: never a
 * token, never a hash, never a peer id, never a key id.
 *
 * STOP (exit 1) when: a DB or the credential store cannot be read; the instance id cannot be
 * told; the token-hmac key is lost or unusable; the conversion FAILS or is SKIPPED; any old-style
 * value is refused; a converted peer's re-pair proof key would change; a credential record the
 * conversion should have written did not land; the family is not marked converted afterwards; or
 * a second pass is not a no-op. PASS (exit 0) means: every row converts, nothing is refused, every
 * converted peer's re-pair proof key is unchanged, and a second boot changes nothing.
 *
 *   node scripts/ops/peer-token-hmac-dryrun.mjs \
 *     --db crow=/path/copied/crow.db \
 *     --db r4=/path/copied/r4.db \
 *     --files-from ~/.crow          # optional: where secrets/peer-tokens.json lives (default $CROW_HOME)
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
import { repairProofKey } from "../../servers/shared/enroll-guard.js";
import { getPeerCreds } from "../../servers/shared/peer-credentials.js";
import { PEER_INBOUND_FAMILY, forgetPeerInboundEvidence, forgetForcedPeerLegacyRefusal, isLegacyStored } from "../../servers/gateway/peer-inbound-token.js";
import { runPeerTokenHmacBoot } from "../../servers/gateway/boot/token-hmac-peers.js";

const LEGACY = /^[0-9a-f]{64}$/;

function usage(code = 2) {
  console.error("usage: node scripts/ops/peer-token-hmac-dryrun.mjs --db <label>=<path> [--db ...]");
  console.error("         [--files-from <CROW_HOME>] [--home <scratch dir>]");
  console.error("  --db <label>=<path>   a COPY of one instance's crow.db to rehearse the conversion on");
  console.error("  --files-from <home>   where that instance's secrets/peer-tokens.json lives (default: this $CROW_HOME)");
  console.error("  --home <dir>          scratch CROW_HOME for the rehearsal (default: a fresh temp dir)");
  console.error("");
  console.error("Prints per-label counts, the re-pair proof check and one PASS/STOP verdict.");
  console.error("Changes nothing outside the scratch dir. Never prints a value, a hash or an id.");
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

/** A DB copy is not attributable without its instance id: the era mirror is scoped by it. */
function instanceIdFor(dbPath, filesFrom) {
  for (const candidate of [join(dirname(dbPath), "instance-id"), join(filesFrom, "data", "instance-id")]) {
    try {
      const id = readFileSync(candidate, "utf8").trim();
      if (id) return { id, path: candidate };
    } catch { /* try the next */ }
  }
  return null;
}

/** Every row that holds a stored verifier, as `{id, stored}`. */
async function storedRows(db) {
  const { rows } = await db.execute({
    sql: "SELECT id AS id, auth_token_hash AS stored FROM crow_instances WHERE auth_token_hash IS NOT NULL",
    args: [],
  });
  return rows.map((r) => ({ id: String(r.id ?? ""), stored: String(r.stored ?? "") }));
}

/**
 * Does this peer have a usable credential record? A recorded `inbound_bearer_sha256` needs the
 * entry (it lives in one) and a re-pair PROOF needs its `signing_key`, so "usable" means both a
 * real entry and a non-empty signing key. Never prints anything: callers report counts only.
 */
function hasCredentialRecord(creds) {
  if (!creds || typeof creds !== "object" || Array.isArray(creds)) return false;
  return typeof creds.signing_key === "string" && creds.signing_key !== "";
}

/**
 * Rehearse one instance: copy the DB, its instance id and the credential store into its own
 * scratch home, convert the copy twice, and report.
 */
async function rehearse({ label, path }, { filesFrom, root }) {
  const home = join(root, label);
  const dataDir = join(home, "data");
  mkdirSync(dataDir, { recursive: true, mode: 0o700 });
  const dbPath = join(dataDir, "crow.db");
  const sourceDb = resolve(path);
  if (!existsSync(sourceDb)) {
    problems.push(`${label}: the database does not exist`);
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
    problems.push(`${label}: no instance-id beside the DB, so the era mirror could not be attributed`);
    return null;
  }
  writeFileSync(join(dataDir, "instance-id"), `${instance.id}\n`, { mode: 0o600 });

  // The credential record the conversion WRITES lives here. Copied (never linked), and only when
  // the source home has one — a home with no paired peer has nothing to copy and nothing to
  // record, which the per-label line says out loud.
  mkdirSync(join(home, "secrets"), { recursive: true, mode: 0o700 });
  const sourceStore = join(filesFrom, "secrets", "peer-tokens.json");
  const storeCopied = existsSync(sourceStore);
  if (storeCopied) {
    try { copyFileSync(sourceStore, join(home, "secrets", "peer-tokens.json")); } catch (err) {
      problems.push(`${label}: the credential store could not be copied (${err.code || err.message})`);
      return null;
    }
  }

  // Point every resolver at this instance, and forget every per-process cache of the last one.
  process.env.CROW_HOME = home;
  process.env.CROW_DATA_DIR = dataDir;
  process.env.CROW_DB_PATH = dbPath;
  delete process.env.CROW_PEER_TOKENS_PATH;
  forgetTokenMacKey();
  forgetPeerInboundEvidence();
  forgetForcedPeerLegacyRefusal();

  const db = createDbClient(dbPath);
  try {
    // BEFORE: which rows hold what. The legacy values are what the re-pair proof is checked
    // against, and they never leave this function (a count is all that is printed).
    const before = await storedRows(db);
    const legacyBefore = before.filter((r) => isLegacyStored(r.stored));
    const recordsBefore = new Map();
    let noCredential = 0;
    for (const row of legacyBefore) {
      // eslint-disable-next-line no-await-in-loop -- one read per legacy row, one operator run
      const creds = storeCopied ? getPeerCreds(row.id) : null;
      recordsBefore.set(row.id, typeof creds?.inbound_bearer_sha256 === "string" ? creds.inbound_bearer_sha256 : null);
      // REPORTED, NEVER REFUSED (L2): the conversion of a row with no credential record is fine
      // — the `h1.` verifier is minted from the stored hash, no credential needed — but its
      // re-pair proof cannot be keyed (no signing key beside it), so it needs the peer
      // operator's `--allow-re-pair` allowance instead of the proof. A count, never an id.
      if (!hasCredentialRecord(creds)) noCredential += 1;
    }

    // eslint-disable-next-line no-await-in-loop -- one conversion, then one re-check
    const first = await runPeerTokenHmacBoot({ db });
    // eslint-disable-next-line no-await-in-loop -- the re-check is the zero-window proof
    const second = await runPeerTokenHmacBoot({ db });

    const after = await storedRows(db);
    const legacyAfter = after.filter((r) => isLegacyStored(r.stored));

    // The credential records the conversion wrote, and the D4 proof check.
    let gained = 0;
    let proofEqual = 0;
    let proofMismatch = 0;
    let proofSkipped = 0;
    let missingRecord = 0;
    for (const row of legacyBefore) {
      // eslint-disable-next-line no-await-in-loop -- one read per converted row
      const creds = storeCopied ? getPeerCreds(row.id) : null;
      const recorded = typeof creds?.inbound_bearer_sha256 === "string" ? creds.inbound_bearer_sha256 : null;
      if (recorded && recordsBefore.get(row.id) !== recorded) gained += 1;
      // Only a row that HAS a credential record may gain one: a row with none is the reported
      // count above, not a missing D4 record.
      if (!recorded && hasCredentialRecord(creds)) missingRecord += 1;
      const signingKey = typeof creds?.signing_key === "string" ? creds.signing_key : null;
      if (!recorded || !signingKey || !LEGACY.test(recorded)) {
        // No credential entry, no signing key, or no usable record: the proof cannot be computed
        // here. It is not a failure of the conversion — the pair's proof falls back to the
        // operator's `--allow-re-pair` — but it is reported, never silently counted as a pass.
        proofSkipped += 1;
        continue;
      }
      const fromRecord = repairProofKey(recorded, signingKey);
      const fromLegacy = repairProofKey(row.stored, signingKey);
      if (fromRecord && fromLegacy && fromRecord === fromLegacy) proofEqual += 1;
      else proofMismatch += 1;
    }

    const converted = first.converted;
    const refused = legacyAfter.length;
    console.log(`  ${label}  rows with a stored verifier: ${before.length}`);
    console.log(`  ${label}  ${converted} row(s) would be converted, ${refused} old-style value(s) refused, `
      + `${first.alarms} alarm(s)`);
    console.log(`  ${label}  credential records: ${storeCopied ? `${gained} gained inbound_bearer_sha256` : "no secrets/peer-tokens.json on this home"}`);
    console.log(`  ${label}  rows with no credential record: ${noCredential}`);
    console.log(`  ${label}  re-pair proof: ${proofEqual} key(s) unchanged, ${proofMismatch} WOULD CHANGE, `
      + `${proofSkipped} not checkable (no stored signing key)`);

    if (first.key !== "ok") problems.push(`${label}: no usable token-hmac key (${first.key})`);
    if (!first.family) problems.push(`${label}: the conversion reported no result`);
    if (first.family?.state === "failed") problems.push(`${label}: the conversion FAILED`);
    if (first.family?.state === "skipped") problems.push(`${label}: the conversion was skipped (${first.family.reason})`);
    if (refused) {
      problems.push(
        `${label}: ${refused} old-style value(s) would be REFUSED (written after the snapshot, or the family is `
        + "already converted) — every peer holding one has to re-pair",
      );
    }
    if (first.alarms) problems.push(`${label}: ${first.alarms} old-style value(s) were reported after the conversion`);
    if (proofMismatch) {
      problems.push(
        `${label}: ${proofMismatch} converted peer(s) would get a DIFFERENT re-pair proof key — design D4 is broken `
        + "on this box, so every re-pair proof from those peers would fail after the conversion",
      );
    }
    if (storeCopied && missingRecord) {
      problems.push(
        `${label}: ${missingRecord} legacy row(s) would be converted WITHOUT an inbound_bearer_sha256 record — their `
        + "re-pair proof would need the operator's --allow-re-pair",
      );
    }
    if (second.converted !== 0) {
      problems.push(`${label}: a second pass converted ${second.converted} row(s) — the era did not stick`);
    }
    if (second.alarms !== 0) problems.push(`${label}: a second pass still reports ${second.alarms} old-style row(s)`);
    if (!readState().families[PEER_INBOUND_FAMILY]?.converted_at) {
      problems.push(`${label}: ${PEER_INBOUND_FAMILY} is not marked converted in the era state`);
    }
    return { first, second };
  } finally {
    db.close();
  }
}

async function main() {
  const args = parseArgs(process.argv.slice(2));
  const filesFrom = args.filesFrom || resolveCrowHome();
  const root = args.home || mkdtempSync(join(tmpdir(), `crow-peer-token-dryrun-${stamp()}-`));
  mkdirSync(root, { recursive: true, mode: 0o700 });

  console.log("");
  console.log(`Rehearsing the ${PEER_INBOUND_FAMILY} conversion on ${args.dbs.length} copied database(s).`);
  console.log(`  credential store from: ${join(filesFrom, "secrets", "peer-tokens.json")}`);
  console.log(`  scratch CROW_HOME:     ${root}`);
  console.log("");

  try {
    for (const spec of args.dbs) {
      console.log(`${spec.label}:`);
      // eslint-disable-next-line no-await-in-loop -- one instance at a time, by design
      await rehearse(spec, { filesFrom, root });
      console.log("");
    }
  } finally {
    // The scratch home holds a key, a copy of the credential store and this run's snapshot; it is
    // a rehearsal, not a box.
    if (!args.home) {
      try { rmSync(root, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  }

  if (problems.length) {
    for (const problem of problems) console.log(`  - ${problem}`);
    console.log(`STOP: the ${PEER_INBOUND_FAMILY} conversion above is not a clean rehearsal (nothing was changed).`);
    return 1;
  }
  console.log(`PASS: every ${PEER_INBOUND_FAMILY} row converts, nothing is refused, every re-pair proof key is unchanged,`);
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