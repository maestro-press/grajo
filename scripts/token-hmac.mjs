#!/usr/bin/env node
/**
 * Operator recovery for the keyed token verifiers (§2.6 / §8 PR 2 of the keyed-token-hashes
 * design).
 *
 * WHY THIS EXISTS. Stored verifiers are HMACed under `<CROW_HOME>/secrets/token-hmac.key`.
 * That key is never re-created automatically: if it is lost (a restore of crow.db without
 * `secrets/`) or unreadable, every OAuth token and every dashboard session is refused, by
 * design. This tool is the deliberate way out.
 *
 * WHAT IT DOES
 *   1. Moves the key file aside — never deletes it (`token-hmac.key.lost-<stamp>`).
 *   2. Deletes EVERY `oauth_tokens` row: every OAuth grant (access and refresh) and every
 *      dashboard session is revoked. The dashboard password is NOT touched, so the owner
 *      signs in again with the password (or the first-run / 2FA flow) and gets a new session.
 *   3. Creates a new key and reports its id.
 *   4. Re-marks the three families CONVERTED (no rows behind them) — in the state file AND the
 *      `token_hmac_era:*` mirror. NO step of this tool clears or deletes a family marker: they
 *      stay CONVERTED throughout, because a converted family means "a bare sha256 is not a
 *      credential here", so a legacy row written between this reset and the next gateway boot
 *      is refused and alarmed instead of being laundered into a valid `h1.` row by that boot.
 *      Every sibling family's era and `password_set_at` stay in the state file, which is never
 *      moved aside.
 *
 * Net effect: a new key, an empty table, and the three families converted.
 *
 * Run it with the gateway STOPPED (it opens crow.db directly and replaces the key underneath
 * it). The tool probes `/health` first, on the gateway's OWN two expressions —
 * `gatewayListenPort()` (`PORT`, then `CROW_GATEWAY_PORT`, then 3001) and
 * `gatewayListenHost()` when that is a specific address, 127.0.0.1 for a wildcard, loopback or
 * unset bind — with a 1.5 s budget, and exits 2 without changing anything if a gateway answers. `--force-while-running` skips that probe — for an
 * operator who knows the answering process is not the gateway this run belongs to.
 *
 *   node scripts/token-hmac.mjs --reset          # asks for confirmation
 *   node scripts/token-hmac.mjs --reset --yes    # no prompt (scripts, runbooks)
 *
 * ─── --rollback: the deploy-day undo of the oauth_tokens conversion ─────────
 *
 * Rolling the RELEASE back does not roll the ROWS back: once the pre-listen boot has converted
 * `oauth_tokens`, every row holds an `h1.` verifier, and the previous release's
 * `sha256hex(token)` lookup cannot find any of them. `--rollback` puts the rows back into the
 * form that release reads, using the snapshots the converter wrote (`secrets/token-hmac-rollback-*.json`,
 * `{v, family, key_id, created_at, rows:[{rowid, token}]}` — the pre-conversion sha256 values,
 * never a raw token).
 *
 *   1. Same `/health` refusal as `--reset` (exit 2, nothing changed; `--force-while-running`
 *      overrides) and the same confirmation prompt (`--yes` skips it).
 *   2. The CURRENT key must be usable: only the key that converted the rows can compute their
 *      `h1.` values back to the snapshot entries. A lost or invalid key, a snapshot that does not
 *      parse, or one naming a family a rollback does not restore refuses the WHOLE run (exit 3,
 *      nothing changed). A snapshot written under a DIFFERENT key is IGNORED and REPORTED: its
 *      rows belong to an era this box no longer holds the key for (a `--reset`, a rotation), so it
 *      can neither be restored nor block what the current key can still do. A box with NOTHING
 *      usable to restore — no usable snapshot, and no `rollback_file` the era state still promises
 *      (a `--reset` box, which re-marked the families converted with no rollback file) — proceeds:
 *      every keyed row in the three families is revoked and the era is retired as usual. What it
 *      never does is proceed SILENTLY past a snapshot the state still promises: a promised file
 *      that is neither usable nor present-but-foreign is GONE, so the run stops and names it (the
 *      rows it would silently revoke are exactly the ones nobody could prove).
 *   3. In ONE DB transaction, in this order:
 *      a. POST-CONVERSION LEGACY WRITES. In EVERY converted family, a bare (non-`h1.`) row was
 *         written AFTER the conversion, so it is a forgery the alarm refused: it is DELETEd and
 *         counted as "removed (written after conversion, never valid)". Every value a snapshot
 *         itself names is SPARED — on a re-run of a rollback that already committed, those rows ARE
 *         the restored genuine ones. This is also what clears a forged row sitting on a snapshot's
 *         own value, which would otherwise collide with the restore below (the stored value IS the
 *         primary key). A family with NO usable snapshot spares NOTHING: it has no genuine bare row
 *         to protect (a `--reset` box, a snapshot written under another key), and a converted
 *         family whose promised snapshot is gone already refused the whole run above, so a bare row
 *         there can only be a post-conversion forgery. A family that is NOT converted (a §2.6
 *         skip, an era-less failure) keeps its legacy rows: they are still what that release reads.
 *      b. THE RESTORES. Each snapshot row is restored (`UPDATE … SET token = <legacy>
 *         WHERE token = <macFromLegacy(family, legacy)> AND <family predicate>`); a row that
 *         expired or was revoked since is skipped and counted as "gone", and a row already
 *         sitting at its snapshot value counts as restored (that is the re-run case).
 *      c. Everything left holding an `h1.` value — one minted AFTER the conversion, so no
 *         snapshot holds its raw token — is DELETEd and counted as "revoked (minted after
 *         conversion)": that release could never read it anyway. The restored rows are bare hex,
 *         so this only ever takes rows no snapshot can prove.
 *      d. The three `token_hmac_era:<family>` mirror rows are DELETEd — this instance's overrides
 *         and the global rows — INSIDE THE SAME TRANSACTION, so they commit with the restored
 *         rows (there is no moment at which the rows are restored while the mirror still calls
 *         them forgeries, and no failure after the commit can leave that mismatch behind). WHY
 *         THE MIRROR MUST GO: the era marker is the one-way "this family is converted" record.
 *         Left in place, a later re-deploy would read it, take the restored bare sha256 rows as
 *         forgeries written by something without the key, and refuse every restored credential
 *         with an alarm. With the markers gone the next boot converts the restored rows again —
 *         under a fresh key, since the old one was moved aside. A settings store this DB does not
 *         have is skipped on its own (a missing `dashboard_settings_overrides` never skips the
 *         global delete).
 *   4. AFTER the commit the era evidence is moved aside (`<name>.rolledback-<UTC stamp>`, never
 *      deleted, 0600 kept) in THIS order — the era state file, THEN the key, THEN the snapshots:
 *        - the state file first, because the key must never be absent while the state still
 *          claims an era (that is the "key lost" shape, and it strands the box: every credential
 *          refused, nothing left to restore from);
 *        - the snapshots last, because a snapshot that outlives the key is ignored on sight (it
 *          names a key this box no longer holds), while a key that outlives its snapshots is
 *          exactly the normal state.
 *   5. Prints per-family counts (restored / gone / revoked / removed), the ignored and missing
 *      snapshots, and the moved-aside paths. Never a token and never a hash.
 *
 * INTERRUPTION POINTS — every one of them is recoverable, because the DB changes are ONE
 * transaction and the file moves are renames of files that are never overwritten:
 *   - BEFORE the commit: nothing changed. Re-run from the start.
 *   - AFTER the commit, BEFORE the first move: the rows are restored and the mirror is gone, while
 *     every file is still in place. A RE-RUN completes cleanly and is a no-op restore (the rows
 *     already sit at their snapshot values, so nothing is rewritten and the legacy sweep spares
 *     every value a snapshot names) followed by the moves; booting the previous release instead
 *     also works, because its value lookup finds the bare rows.
 *   - AFTER the state file moved, BEFORE the key: the key file is still on disk, so a boot is
 *     NORMAL, not "key lost" — a key file answers for itself. No era is recorded for the three
 *     families (the state file is gone, the mirror committed away), so that boot converts the
 *     restored rows again, under the SAME key: nobody is locked out. Re-running the rollback just
 *     finishes the moves.
 *   - AFTER the key moved: the box is ALREADY the previous release's shape and consistent — bare
 *     rows, no key, no era state, no mirror — so nothing is left to finish. A re-run exits 3 (it
 *     refuses to run without the key, which is gone even though the box is fine); it is NOT needed.
 *     A re-deploy converts those restored rows afresh, under a fresh key.
 *
 * RE-RUN AN INTERRUPTED ROLLBACK BEFORE STARTING THE OLD RELEASE. The sweep above (step 3a) signs
 * out a post-conversion forgery by DELETING a bare row no snapshot names — and once the old release
 * is serving again it MINTS bare rows again, so a re-run after that point would delete the genuine
 * sessions that release issued. Order, not a check, is what keeps the two apart: finish the moves
 * first, then start the old release.
 *
 * ONE RESIDUAL, on a re-run of an ALREADY-COMMITTED rollback: a bot that recorded a keyed (`h1.`)
 * value before the first run can plant it as a row of its own, and the per-item collision check
 * (step 3b) then takes the bare row it collides with instead of keeping it — a genuine restored row
 * is dropped and counted as "removed". It is not a new capability: the value is one the bot can
 * already copy out of crow.db and writing rows there is what it already does. It cannot start a run
 * (no shell, and the CLI refuses while a gateway answers), and a single run with the gateway stopped
 * cannot be raced at all; the dropped row lands in the reported `removed` count.
 *
 * TEST SEAM — `CROW_TEST_ONLY_TOKEN_HMAC_ROLLBACK_INTERRUPT=<point>` (`commit`, `state`, `key`,
 * `snapshots`) stops the run right after that step with exit 7, which is how the tests model a crash
 * at each point above. It is TEST-ONLY: production never sets it, and nothing in `servers/` reads it.
 *
 * THE ACCEPTED WINDOW. Between a rollback and the next deploy the PREVIOUS release is on duty
 * again, and it reads a bare sha256 by value — so it is exposed to the forged-row issue this
 * release fixes. The next deploy converts every legacy row it finds, including one written in that
 * window (accepted). A rollback is a deploy-day undo, never a resting state.
 */
import { existsSync, readdirSync, readFileSync, renameSync } from "node:fs";
import { dirname, join } from "node:path";
import { request } from "node:http";
import { createInterface } from "node:readline";
import { createDbClient } from "../servers/db.js";
import {
  TokenMacKeyError, adoptOperatorKey, ensureKey, eraSettingKey, macFromLegacy, markConverted, readState,
  tokenMacKeyPath, tokenMacStatePath,
} from "../servers/shared/token-mac.js";
import { gatewayListenHost } from "../servers/gateway/listen-host.js";
import { gatewayListenPort } from "../servers/gateway/listen-port.js";
import { writeSetting } from "../servers/gateway/dashboard/settings/registry.js";
import { getOrCreateLocalInstanceId } from "../servers/gateway/instance-registry.js";
import { FAMILY_PREDICATE, TOKEN_STORE_FAMILIES, tokenFamilyConverted } from "../servers/gateway/token-store.js";
import { ROLLBACK_PREFIX } from "../servers/gateway/boot/token-hmac.js";

/** The health probe's budget: a live gateway answers long before this. */
const HEALTH_PROBE_TIMEOUT_MS = 1500;

/** `2026-11-23T16:41:02.123Z` → a file-name-safe stamp. */
function stamp(at = new Date()) {
  return at.toISOString().replace(/[:.]/g, "-");
}

/** Move `path` aside (never delete); returns the new path, or null when there was no file. */
function moveAside(path, suffix, at = new Date()) {
  if (!existsSync(path)) return null;
  const aside = `${path}.${suffix}-${stamp(at)}`;
  renameSync(path, aside);
  return aside;
}

/** A pre-conversion stored verifier: the old code's `sha256hex(token)`. */
const LEGACY_STORED = /^[0-9a-f]{64}$/;

/** The three families a rollback may restore — exactly the ones the boot converter visits. */
const RESTORABLE = new Set(TOKEN_STORE_FAMILIES);

/** Loopback or the unspecified address, in any spelling a bind may carry. */
function isLoopbackOrWildcard(host) {
  const h = String(host ?? "").trim().toLowerCase().replace(/^\[|\]$/g, "").replace(/%.*$/, "");
  if (!h || h === "::" || h === "0.0.0.0") return true;
  if (h === "localhost" || h === "ip6-localhost" || h === "ip6-loopback") return true;
  return /^127\./.test(h) || h === "::1";
}

/**
 * Where a gateway on this box answers `/health`: built from the gateway's OWN two expressions,
 * so this probe and the listener cannot drift apart. The port is `gatewayListenPort()` (the
 * same `PORT`, then `CROW_GATEWAY_PORT`, then 3001 precedence the gateway binds with) or null
 * when the env does not name one it could bind. The host is `gatewayListenHost()` when that is a
 * specific address; for a wildcard bind (0.0.0.0, ::), a loopback bind or an unset
 * `CROW_GATEWAY_BIND`, the gateway answers on loopback, so the probe asks 127.0.0.1.
 */
function gatewayProbeTarget(env = process.env) {
  const raw = gatewayListenPort(env);
  const port = Number.isInteger(raw) && raw > 0 && raw < 65536 ? raw : null;
  const bind = String(gatewayListenHost(env) || "");
  const host = isLoopbackOrWildcard(bind) ? "127.0.0.1" : bind.replace(/^\[|\]$/g, "");
  const shown = host.includes(":") ? `[${host}]` : host;
  return { host, port, url: `http://${shown}:${port}/health` };
}

/**
 * Is something answering `/health` at this target? True for ANY HTTP answer: what must not
 * happen is this reset running beside a live gateway, and a listener that replies is enough to
 * say stop it first. A refused connection, a timeout or a malformed request is false.
 */
function gatewayAnswers({ host, port }) {
  return new Promise((done) => {
    let settled = false;
    const finish = (value) => {
      if (settled) return;
      settled = true;
      done(value);
    };
    let req;
    try {
      req = request({
        host, port, path: "/health", method: "GET", agent: false, timeout: HEALTH_PROBE_TIMEOUT_MS,
      }, (res) => {
        res.resume();
        finish(true);
      });
    } catch {
      finish(false);
      return;
    }
    req.on("timeout", () => { req.destroy(); finish(false); });
    req.on("error", () => finish(false));
    req.end();
  });
}

function confirm(question) {
  return new Promise((done) => {
    const rl = createInterface({ input: process.stdin, output: process.stdout });
    rl.question(question, (answer) => {
      rl.close();
      done(/^y(es)?$/i.test(String(answer).trim()));
    });
  });
}

async function reset({ yes, force }) {
  const keyPath = tokenMacKeyPath();

  // Before ANY change: a live gateway must not be underfoot (it may be validating rows and
  // minting sessions while this run empties the table and swaps the key).
  if (!force) {
    const target = gatewayProbeTarget();
    if (target.port && await gatewayAnswers(target)) {
      console.error(
        `A Crow gateway is answering on ${target.url} — it is running and must be stopped `
        + "before this reset. Nothing was changed.",
      );
      return 2;
    }
  }

  if (!yes) {
    console.log("This will:");
    console.log("  - revoke EVERY OAuth grant and dashboard session (all oauth_tokens rows)");
    console.log("  - move the token HMAC key aside and create a new one");
    console.log("  - keep the dashboard password (you sign in again afterwards)");
    const ok = await confirm("Continue? [y/N] ");
    if (!ok) {
      console.log("Nothing was changed.");
      return 1;
    }
  }

  // 1. The key goes aside first: nothing may mint under it after this line. The era state is NOT
  //    touched here — the three families stay CONVERTED throughout (step 4 re-marks them), so
  //    the reset has no window in which a family is unconverted.
  const movedKey = moveAside(keyPath, "lost");

  const db = createDbClient();
  let revoked = 0;
  let key;
  let mirrored = 0;
  try {
    // 2. Revoke every token row: grants and sessions alike.
    const res = await db.execute({ sql: "DELETE FROM oauth_tokens", args: [] });
    revoked = Number(res?.rowsAffected ?? 0) || 0;

    // 3. A fresh key, so the box is immediately coherent (no login has to mint it). This is
    //    the one place a key may be created over an existing state file: the operator retired
    //    the old key on purpose, and every other field of the state stays as it is.
    key = adoptOperatorKey({ at: new Date().toISOString() });

    // 4. Re-mark the three families CONVERTED, never cleared: from here on a legacy sha256 row in
    //    one of them is refused and alarmed by every validator AND by the next boot's scan,
    //    instead of being converted into a valid `h1.` row. A family that was already converted
    //    keeps its first `converted_at` (markConverted is add-only); the DB mirror is written by
    //    markConverted itself (`token_hmac_era:<family>`, local scope).
    for (const family of TOKEN_STORE_FAMILIES) {
      // eslint-disable-next-line no-await-in-loop -- three families, one operator run
      const mark = await markConverted(family, {
        count: 0,
        rollbackFile: null,
        at: new Date().toISOString(),
        writeSetting: (k, v, o) => writeSetting(db, k, v, o),
      });
      if (mark.changed) mirrored += 1;
    }
  } finally {
    db.close();
  }

  console.log("");
  console.log("Token key reset.");
  console.log(`  key file:      ${movedKey ? `moved aside → ${movedKey}` : "none (already absent)"}`);
  console.log(`  new key id:    ${key.id} (${keyPath})`);
  console.log(`  era state:     re-marked converted, never cleared: ${TOKEN_STORE_FAMILIES.join(", ")}`);
  console.log(`  oauth_tokens:  ${revoked} row(s) deleted — every OAuth grant and dashboard session is revoked`);
  console.log(`  era mirror:    ${mirrored} family marker(s) written to the DB as converted (no rows behind them)`);
  console.log("");
  console.log("Start the gateway again. Existing MCP clients must re-authorize, and every browser");
  console.log("must sign in again with the dashboard password.");
  return 0;
}

/**
 * Every conversion snapshot in `secrets/`, validated together.
 *
 * A rollback restores only what a snapshot can PROVE, so one file that cannot be read at all — it
 * does not parse, it is not the snapshot shape, or it names a family a rollback does not restore —
 * refuses the whole run before anything moves. But a file written under a DIFFERENT key is IGNORED
 * (and reported): its values belong to an era this box no longer holds the key for (a `--reset`, a
 * key rotation), so it can neither be restored nor be allowed to block what the current key can
 * still do. The key check comes first on purpose: a foreign file is unusable as a whole, whatever
 * family it names.
 *
 * A file moved aside by an earlier rollback ends in `.rolledback-<stamp>`, not `.json`, so a
 * second rollback never picks one up. A row whose `token` is not a bare sha256 hex cannot be
 * restored and is ignored (the converter only ever writes those).
 *
 * @returns {{ok: true, names: string[], snapshots: {name: string, family: string, rows: string[]}[],
 *            ignored: {name: string, family: string}[]}
 *          | {ok: false, reason: string}} `names` are the USABLE files, the only ones moved aside.
 */
function readSnapshots(dir, keyId) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch (err) {
    if (err.code === "ENOENT") return { ok: true, names: [], snapshots: [], ignored: [] };
    throw err;
  }
  const names = [];
  const snapshots = [];
  const ignored = [];
  for (const name of entries.slice().sort()) {
    if (!name.startsWith(ROLLBACK_PREFIX) || !name.endsWith(".json")) continue;
    let body;
    try {
      body = JSON.parse(readFileSync(join(dir, name), "utf8"));
    } catch (err) {
      return {
        ok: false,
        reason: `secrets/${name} does not parse as a conversion snapshot (${err.code || err.message}).`,
      };
    }
    if (!body || typeof body !== "object" || Array.isArray(body) || !Array.isArray(body.rows)) {
      return { ok: false, reason: `secrets/${name} is not a conversion snapshot.` };
    }
    if (body.key_id !== keyId) {
      // Ignored, not a refusal: this file's rows cannot be computed back under the key on this
      // box, and a stale file left behind by an earlier era must not veto a rollback that the
      // CURRENT key can still do. Nothing is restored from it, so nothing is invented either.
      ignored.push({ name, family: String(body.family ?? "") });
      continue;
    }
    if (!RESTORABLE.has(body.family)) {
      return {
        ok: false,
        reason: `secrets/${name} names the family ${JSON.stringify(String(body.family))}, `
          + "which a rollback does not restore.",
      };
    }
    names.push(name);
    snapshots.push({
      name,
      family: body.family,
      rows: body.rows
        .map((row) => (typeof row?.token === "string" ? row.token.toLowerCase() : ""))
        .filter((token) => LEGACY_STORED.test(token)),
    });
  }
  return { ok: true, names, snapshots, ignored };
}

/**
 * The rollback snapshots the ERA STATE still promises: the `rollback_file` each converted family
 * records in `secrets/token-hmac-state.json`.
 *
 * This is what tells "there is nothing to restore" (a `--reset` box: it re-marks the three
 * families CONVERTED with no rollback file and writes no snapshot, so no row can be brought back)
 * from "a snapshot this box was relying on is MISSING". A corrupt or unreadable state file cannot
 * answer, and a rollback that cannot tell must not proceed.
 */
function promisedSnapshots() {
  let st;
  try {
    st = readState();
  } catch (err) {
    return { ok: false, reason: `the era state file could not be read (${err.message})` };
  }
  if (st.corrupt) return { ok: false, reason: `the era state file ${st.path} is corrupt` };
  const families = [];
  for (const family of TOKEN_STORE_FAMILIES) {
    const entry = st.families?.[family];
    if (!entry || typeof entry !== "object" || !entry.converted_at) continue;
    if (typeof entry.rollback_file === "string" && entry.rollback_file) {
      families.push({ family, file: entry.rollback_file });
    }
  }
  return { ok: true, families };
}

/**
 * Delete the three `token_hmac_era:<family>` mirror rows — this instance's overrides AND the
 * global rows — through the transaction's own synchronous `run`, so they commit with the restored
 * rows.
 *
 * R5: each store is asked about SEPARATELY. A DB without `dashboard_settings_overrides` (an older
 * store, a unit-test DB) still loses its global era rows, instead of one missing table aborting the
 * statement series and leaving a marker behind for the next deploy to trip over.
 *
 * @param {Function} run the transaction's synchronous statement runner
 * @param {string} localId this instance's id (overrides are keyed by (key, instance_id))
 * @returns {number} rows deleted
 */
function deleteEraMirrorRows(run, localId) {
  const hasTable = (table) => run({
    sql: "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?",
    args: [table],
  }).rows.length > 0;
  const overrides = hasTable("dashboard_settings_overrides");
  const globals = hasTable("dashboard_settings");
  let deleted = 0;
  for (const family of TOKEN_STORE_FAMILIES) {
    const setting = eraSettingKey(family);
    if (overrides) {
      const res = run({
        sql: "DELETE FROM dashboard_settings_overrides WHERE key = ? AND instance_id = ?",
        args: [setting, localId],
      });
      deleted += Number(res?.rowsAffected ?? 0) || 0;
    }
    if (globals) {
      const res = run({ sql: "DELETE FROM dashboard_settings WHERE key = ?", args: [setting] });
      deleted += Number(res?.rowsAffected ?? 0) || 0;
    }
  }
  return deleted;
}

/**
 * `--rollback`: put the converted `oauth_tokens` rows back into the old `sha256hex` form.
 *
 * Steps and their rationale are in this file's header. Every check runs BEFORE the first change
 * (the DB transaction is atomic, and the file moves happen only after it committed), so the two
 * refusals — a running gateway (2) and an unusable key or snapshot (3) — leave the box exactly as
 * it was.
 *
 * TEST SEAM: `CROW_TEST_ONLY_TOKEN_HMAC_ROLLBACK_INTERRUPT=<point>` (`commit`, `state`, `key`,
 * `snapshots`) reports and exits 7 right after that step, which is how the interruption tests model a
 * crash at each of the header's interruption points. TEST-ONLY: production never sets it.
 */
async function rollback({ yes, force }) {
  const keyPath = tokenMacKeyPath();
  const statePath = tokenMacStatePath();
  const dir = dirname(keyPath);
  const interruptAfter = String(process.env.CROW_TEST_ONLY_TOKEN_HMAC_ROLLBACK_INTERRUPT || "").trim() || null;

  // 1. Before ANY change: a live gateway must not be underfoot (it may be validating rows and
  //    minting sessions while this run rewrites them and retires the key they were minted under).
  if (!force) {
    const target = gatewayProbeTarget();
    if (target.port && await gatewayAnswers(target)) {
      console.error(
        `A Crow gateway is answering on ${target.url} — it is running and must be stopped `
        + "before this rollback. Nothing was changed.",
      );
      return 2;
    }
  }

  if (!yes) {
    console.log("This will:");
    console.log("  - restore the oauth_tokens rows listed in the conversion snapshots to the form the");
    console.log("    previous release reads (rows that expired or were revoked since stay gone)");
    console.log("  - delete old-style rows written after the conversion, and revoke every token minted");
    console.log("    after it (neither one has a pre-conversion form)");
    console.log("  - delete the three token_hmac_era:* mirror rows, so the next deploy converts again");
    console.log("  - move the era state, the token HMAC key and the snapshots aside (never delete them)");
    const ok = await confirm("Continue? [y/N] ");
    if (!ok) {
      console.log("Nothing was changed.");
      return 1;
    }
  }

  // 2. The key that CONVERTED the rows is the only thing that can compute them back.
  let key;
  try {
    key = ensureKey({ allowCreate: false });
  } catch (err) {
    if (!(err instanceof TokenMacKeyError)) throw err;
    console.error(
      `This rollback needs the token-hmac key that converted these rows, and the one on this box `
      + `is ${err.state === "invalid" ? "unusable" : "not there"}: ${keyPath}. Nothing was changed.`,
    );
    return 3;
  }

  // 2b. Every snapshot is validated before the transaction: a file that cannot be read at all
  //     refuses the whole run; one written under another key is ignored and reported (R3).
  const scan = readSnapshots(dir, key.id);
  if (!scan.ok) {
    console.error(`${scan.reason} Nothing was changed.`);
    return 3;
  }

  // A usable snapshot's values are the rows that may legitimately hold a bare value after this
  // run. They are keyed by family: the legacy sweep below spares exactly these, and the restore
  // plan is one entry per (family, legacy) pair.
  const usableByFamily = new Map();
  const plan = [];
  for (const snap of scan.snapshots) {
    if (!usableByFamily.has(snap.family)) usableByFamily.set(snap.family, new Map());
    const values = usableByFamily.get(snap.family);
    for (const legacy of snap.rows) {
      if (values.has(legacy)) continue;
      values.set(legacy, snap.name);
      plan.push({ family: snap.family, legacy, h1: macFromLegacy(snap.family, legacy) });
    }
  }

  // 2c. Nothing usable to restore: only a box the era state does not promise a snapshot for may
  //     proceed (a `--reset` box re-marks the three families converted with NO rollback file, so no
  //     row can be brought back and the whole point of the run is to retire the era). A snapshot the
  //     state still names and that is neither usable nor merely foreign on disk is GONE — proceeding
  //     there would silently revoke rows this run could never prove, so it stops and says which
  //     file to put back.
  const promised = promisedSnapshots();
  if (!promised.ok) {
    console.error(`${promised.reason}, so this run cannot tell which converted family still expects its snapshot. Nothing was changed.`);
    return 3;
  }
  const ignoredNames = new Set(scan.ignored.map((entry) => entry.name));
  const goneSnapshots = promised.families
    .filter((entry) => !usableByFamily.has(entry.family) && !ignoredNames.has(entry.file));
  if (goneSnapshots.length) {
    const names = goneSnapshots.map((entry) => `secrets/${entry.file} (${entry.family})`).join(", ");
    console.error(
      `The era state still records ${names}, but that file is not in ${dir} — so this rollback would revoke `
      + "every credential it cannot prove. Put it back and run this again (or, if those rows are meant to be "
      + "revoked, drop that family's rollback_file from the era state in secrets/token-hmac-state.json first). "
      + "Nothing was changed.",
    );
    return 3;
  }

  // 2d. The instance id the era-mirror override rows are scoped by, read BEFORE the transaction so a
  //     failure here changes nothing (an unreadable instance-id is not a mirror we may guess at).
  let localId;
  try {
    localId = getOrCreateLocalInstanceId();
  } catch (err) {
    console.error(
      `This instance's id could not be read (${err.message}), so the token_hmac_era:* override rows could not `
      + "be targeted. Nothing was changed.",
    );
    return 1;
  }

  const counts = new Map(TOKEN_STORE_FAMILIES.map((family) => [
    family, { restored: 0, gone: 0, revoked: 0, removed: 0 },
  ]));
  let mirrored = 0;
  const db = createDbClient();  try {
    // Does the ERA say this family is converted? (state file OR the DB mirror, failing closed).
    // Computed outside the transaction because a transaction callback must not await.
    const converted = new Map();
    for (const family of TOKEN_STORE_FAMILIES) {
      // eslint-disable-next-line no-await-in-loop -- three families, one operator run
      converted.set(family, await tokenFamilyConverted(family, db));
    }

    // 3. ONE transaction, in the order the header documents. The mirror rows go INSIDE it, so the
    //    commit is the single point of no return: the restored rows and the deletion of the reason
    //    they would be called forgeries arrive together, or not at all.
    await db.runTransaction((run) => {
      const changes = (res) => Number(res?.rowsAffected ?? 0) || 0;

      // 3a. POST-CONVERSION LEGACY WRITES (R2). A bare (non-`h1.`) row in a CONVERTED family was
      //     written after the conversion, so it is a forgery the alarm refused. It is deleted
      //     FIRST, because a forged row sitting on a snapshot's own value would collide with the
      //     restore below (the stored value is the primary key). Values a snapshot names are
      //     SPARED: on a re-run of a rollback that already committed, those rows ARE the restored
      //     genuine ones, so a sweep that took them would destroy the recovery it is repeating.
      //     EVERY converted family is swept — a family with no usable snapshot simply spares
      //     nothing (it has no genuine bare row to protect, and a promised-but-missing snapshot
      //     already refused this run).
      //     A family that is not converted keeps its legacy rows — they are still what the
      //     previous release reads (§2.6 skip, an era-less failure).
      for (const family of TOKEN_STORE_FAMILIES) {
        if (!converted.get(family)) continue;
        // No usable snapshot for this family (a `--reset` box, a snapshot written under another
        // key): it spares nothing, because a converted family's PROMISED snapshot being gone
        // already refused this run above. An empty set is exactly "every bare row is a forgery".
        const keep = usableByFamily.get(family) ?? new Set();
        const { rows } = run({
          sql: `SELECT rowid AS rowid, token FROM oauth_tokens WHERE token NOT LIKE 'h1.%' AND (${FAMILY_PREDICATE[family]})`,
          args: [],
        });
        for (const row of rows) {
          const value = String(row?.token ?? "");
          if (keep.has(value)) continue;
          const res = run({ sql: "DELETE FROM oauth_tokens WHERE token = ?", args: [value] });
          counts.get(family).removed += changes(res);
        }
      }

      // 3b. THE RESTORES.
      for (const item of plan) {
        const count = counts.get(item.family);
        const present = (value) => run({
          sql: "SELECT 1 AS present FROM oauth_tokens WHERE token = ?", args: [value],
        }).rows.length > 0;
        // The same primary-key collision as above, one row at a time: if the keyed row is still
        // there, a row claiming its snapshot value cannot be the restored genuine one, so the
        // claim is removed and the restore proceeds.
        if (present(item.legacy) && present(item.h1)) {
          const res = run({ sql: "DELETE FROM oauth_tokens WHERE token = ?", args: [item.legacy] });
          count.removed += changes(res);
        }
        const res = run({
          sql: `UPDATE oauth_tokens SET token = ? WHERE token = ? AND (${FAMILY_PREDICATE[item.family]})`,
          args: [item.legacy, item.h1],
        });
        if (changes(res) > 0) count.restored += 1;
        else if (run({
          sql: `SELECT 1 AS present FROM oauth_tokens WHERE token = ? AND (${FAMILY_PREDICATE[item.family]})`,
          args: [item.legacy],
        }).rows.length > 0) {
          count.restored += 1; // already in place: this is a re-run of a committed rollback
        } else {
          count.gone += 1; // expired, logged out or revoked since the conversion
        }
      }

      // 3c. Whatever still holds an `h1.` value is minted AFTER the conversion, so no snapshot
      //     knows its raw token and that release could never read it (R4). The restored rows are
      //     bare hex, so this only ever takes unrestorable rows — no value list needed.
      for (const family of TOKEN_STORE_FAMILIES) {
        const res = run({
          sql: `DELETE FROM oauth_tokens WHERE token LIKE 'h1.%' AND (${FAMILY_PREDICATE[family]})`,
          args: [],
        });
        counts.get(family).revoked += changes(res);
      }

      // 3d. The one-way era mirror, in the SAME transaction (R1) — see the header for why it must
      //     go, and R5 for why a missing settings table skips only itself.
      mirrored = deleteEraMirrorRows(run, localId);
    });
  } catch (err) {
    console.error(`The rollback transaction failed (${err.message}); nothing was changed.`);
    return 1;
  } finally {
    db.close();
  }

  // 4. COMMITTED. Move the era evidence aside — the era STATE first, then the KEY, then the
  //    SNAPSHOTS (the header says why that is the one order with no unrecoverable crash point).
  //    Never deleted, 0600 kept.
  const interrupted = (point) => {
    console.error(
      `token-hmac: interrupted after the ${point} step (CROW_TEST_ONLY_TOKEN_HMAC_ROLLBACK_INTERRUPT). The rows are `
      + "restored and the era mirror is gone; re-running --rollback finishes the moves (see this file's header).",
    );
    return 7;
  };
  if (interruptAfter === "commit") return interrupted("commit");
  const at = new Date();
  const moved = [];
  const steps = [
    { step: "state", path: statePath },
    { step: "key", path: keyPath },
    ...scan.names.map((name) => ({ step: "snapshots", path: join(dir, name) })),
  ];
  for (const { step, path } of steps) {
    const aside = moveAside(path, "rolledback", at);
    if (aside) moved.push(aside);
    if (interruptAfter === step) return interrupted(step);
  }

  // 5. Counts and the moved-aside paths. Never a token, never a hash.
  console.log("");
  console.log("Token conversion rolled back.");
  for (const family of TOKEN_STORE_FAMILIES) {
    const count = counts.get(family);
    console.log(
      `  ${family.padEnd(18)} ${count.restored} restored, ${count.gone} gone (expired or revoked since), `
      + `${count.revoked} revoked (minted after conversion), `
      + `${count.removed} removed (written after conversion, never valid)`,
    );
  }
  if (scan.snapshots.length === 0) {
    console.log("  conversion:        no usable snapshot, so no row was restored; every keyed row was revoked");
  }
  for (const entry of scan.ignored) {
    console.log(
      `  ignored:           secrets/${entry.name} (${entry.family || "unknown family"} was converted under a `
      + "different token-hmac key, so its rows cannot be computed back)",
    );
  }
  console.log(`  era mirror:        ${mirrored} marker row(s) deleted, so the next deploy converts again`);
  console.log(`  moved aside:       ${moved.length ? "" : "nothing (already absent)"}`);
  for (const path of moved) console.log(`    ${path}`);
  console.log("");
  console.log("The rows are in the form the previous release reads. Start that release again; the next");
  console.log("deploy converts them once more, under a fresh key.");
  console.log("Until it does, that release reads a bare sha256 by value, so the forged-row issue is back");
  console.log("for the duration (accepted); the next deploy converts any legacy row written in between.");
  return 0;
}

async function main(argv) {
  const args = new Set(argv);
  const modes = ["--reset", "--rollback"].filter((flag) => args.has(flag));
  if (modes.length !== 1) {
    console.error("usage: node scripts/token-hmac.mjs (--reset | --rollback) [--yes] [--force-while-running]");
    console.error("  --reset   move the token HMAC key aside, revoke every OAuth grant and dashboard");
    console.error("            session, re-mark the three families converted and create a new key (operator");
    console.error("            shell; run it with the gateway stopped)");
    console.error("  --rollback  undo the oauth_tokens conversion: restore the rows listed in the");
    console.error("            conversion snapshots to their pre-conversion form, delete the old-style rows");
    console.error("            written after it and revoke the tokens minted after it, then move the era state,");
    console.error("            the key and the snapshots aside and delete the era mirror (operator shell; run it");
    console.error("            with the gateway stopped)");
    console.error("  --yes     do not ask for confirmation");
    console.error("  --force-while-running  skip the /health probe (it says a gateway is running)");
    return 2;
  }
  if (args.has("--reset")) {
    return reset({ yes: args.has("--yes"), force: args.has("--force-while-running") });
  }
  return rollback({ yes: args.has("--yes"), force: args.has("--force-while-running") });
}

main(process.argv.slice(2)).then(
  (code) => process.exit(code),
  (err) => {
    console.error(`token-hmac failed: ${err.message}`);
    process.exit(1);
  },
);