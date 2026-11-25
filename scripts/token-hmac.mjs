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
 *   2b. Deletes the stored verifiers of the SETTINGS-BACKED static tokens (§1a: local MCP,
 *      board, phone, artifacts, models, peer relay, cloud door, the path-scoped loopback
 *      families and kiosk announce) from BOTH settings stores. They are keyed under the key
 *      this run retires, so leaving them would strand every one of those doors on a FOREIGN
 *      keyId. Deleting the verifier lets each family's own mint write a fresh one — the next
 *      boot re-ensures or rotates all of them except the local MCP token, which the owner
 *      generates again in Settings → Connect. Those rows are keyed by `(key, instance_id)`, so
 *      the delete targets THIS instance's id from `<data dir>/instance-id` — the file the
 *      gateway itself uses — and the run REFUSES before changing anything (exit 1) when this
 *      home has no such file: an id this process invented would match no row, and the reset
 *      would delete nothing while reporting success.
 *   2c. Clears every paired instance's inbound bearer verifier
 *      (`crow_instances.auth_token_hash`). It is keyed under the key this run retires, so each
 *      one would read as a FOREIGN keyId and refuse; and unlike a static token there is no
 *      re-mint on this side — the BEARER lives on the peer. Each peer therefore has to re-pair,
 *      which its own install can prove (design D4): `secrets/peer-tokens.json` still carries the
 *      `inbound_bearer_sha256` the re-pair proof is keyed by, so `crow instance pair` on the
 *      peer re-establishes the pair without the operator's `--allow-re-pair`. A revoked row
 *      already holds NULL and is untouched.
 *   3. Creates a new key and reports its id.
 *   4. Re-marks EVERY family CONVERTED (no rows behind them) — the three `oauth_tokens`
 *      families, the thirteen settings-backed ones AND the paired-instance family
 *      (`peer:inbound`) — in the state file AND the `token_hmac_era:*` mirror. Every family is
 *      marked even on a box whose key was lost BEFORE its conversion ever ran, and that is the
 *      point: with no marker of its own, a bare sha256 something without the key plants while
 *      the gateway is stopped (its units keep running) would be laundered into a valid `h1.`
 *      credential by the next boot — owner (or peer) authority from a row something without the
 *      key wrote. Marked converted, that value is refused and alarmed instead, and each family's
 *      own mint writes its fresh verifier.
 *      NO step of this tool clears or deletes a family marker: they stay CONVERTED throughout,
 *      because a converted family means "a bare sha256 is not a credential here", so a legacy
 *      row written between this reset and the next gateway boot is refused and alarmed instead
 *      of being laundered by that boot. Every sibling family's era and `password_set_at` stay in
 *      the state file, which is never moved aside.
 *
 * Net effect: a new key, an empty `oauth_tokens`, no static-token verifiers, and every family
 * converted.
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
 * ─── --rollback: the deploy-day undo of EVERY keyed family ─────────────────
 * One run restores all four conversions the previous release cannot read: the three `oauth_tokens`
 * families, the sixteen settings-backed static-token families, the paired-instance bearer verifiers
 * (`crow_instances.auth_token_hash`) and the report-link verifiers (`report_link_tokens.token_hash`).
 * The `oauth_tokens` mechanics are described first (steps 1-5), because the other families follow the
 * same shape; "FAMILIES BEYOND oauth_tokens" below says what each of them does differently.
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
 *         counted as "removed (written after conversion, never valid)". A snapshot value is NOT
 *         thereby genuine: a bare row equal to one may be a REPLANT of a credential the operator
 *         logged out, rotated or deleted after the conversion, so on a first run nothing is spared.
 *         Only the values the ROLLBACK JOURNAL names are SPARED (see below). This is also what clears a forged row sitting on a snapshot's
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
 * FAMILIES BEYOND oauth_tokens (all in the SAME transaction as step 3; per-family counts are printed):
 *   - SETTINGS families (`dashboard_settings_overrides` for THIS instance id, read from
 *     `<data dir>/instance-id` like `--reset`'s step 2b, which this run also refuses without — exit 1,
 *     nothing changed — plus the global `dashboard_settings` rows; snapshots
 *     `secrets/settings-token-hmac-rollback-*.json`).
 *       Non-file-backed (local MCP token, the rotated-at-boot families): a snapshot's legacy value is
 *       restored with CAS (only where the override still holds `macFromLegacy(family, legacy)`); an
 *       `h1.` value no snapshot names was minted after the conversion and is DELETED (the previous
 *       release re-mints a rotated-at-boot family on its next start; the local MCP token has to be
 *       generated again in Settings → Connect, its raw value is kept nowhere).
 *       File-backed (board, phone, artifacts, models, peer relay, kiosk announce): the verifier is
 *       rewritten as `sha256(raw token file)`, the file read the way the converter reads its proof
 *       (`readTrustedProofFile`: O_NOFOLLOW|O_NONBLOCK, regular, ours, not group/world-writable,
 *       <= 4 KiB, parent directory ours) AND only when the file proves the stored keyed value
 *       (`macFromLegacy(family, sha256(file)) === stored`). A missing, untrusted or non-matching file
 *       deletes the verifier instead; the previous release's boot re-ensures the token and the file.
 *       A global settings row of a converted family is never a credential and is deleted.
 *   - PEERS (`crow_instances.auth_token_hash`, family `peer:inbound`): an `h1.` row is restored to the
 *     peer's `inbound_bearer_sha256` record in `secrets/peer-tokens.json` (design D4 — the enroll route
 *     and the pairing CLI write it for pairings made AFTER the conversion too), with CAS on the current
 *     value AND only when `macFromLegacy("peer:inbound", record)` IS that current value: a record that
 *     does not match the row is never restored. A row with no record falls back to its snapshot entry
 *     under the same check; any other row (no record and no entry, a mismatch, a revoked peer) is set
 *     to NULL, so that peer re-pairs. The record in peer-tokens.json stays in place.
 *   - REPORT LINKS (`report_link_tokens.token_hash`, family `report:link`; snapshot
 *     `secrets/report-token-hmac-rollback-*.json`, `{id, legacy}`): snapshot values are restored with
 *     CAS on (id, keyed value); a link minted after the conversion keeps its `h1.` value (the
 *     previous release can never match it) and gets `revoked_at`; tombstoned `revoked:` rows are
 *     untouched. A bare row nothing in a snapshot names is a forgery: it is revoked and its value
 *     replaced by a tombstone (the column is NOT NULL UNIQUE, and the tombstone frees a value a
 *     restore needs).
 *   - Step 3a's sweep applies to every family (a bare legacy value in a converted family that no
 *     snapshot — and, for peers, no D4 record — names is a forgery: deleted / NULLed / revoked per
 *     family and counted as "removed"; uppercase 64-hex counts as legacy). A family whose era state
 *     records `rollback_file: null` (an adopted era, a `--reset` box) has nothing to restore, so its
 *     `h1.` rows are all "minted after" and are handled per family as above.
 *   - Every `token_hmac_era:<family>` mirror row, all 21 families, both stores.
 *   - bot:def is NOT a token family and is not rolled back. Its MACs are keyed under the key this run
 *     moves aside, and `secrets/bot-def-era.json` (not touched here) still says "converted", so after
 *     a re-upgrade mints a new key every bot definition reads as foreign and is refused until it is
 *     re-approved; the run prints that, naming `scripts/cli/bot-def-reapprove.mjs`.
 *   - A snapshot a converted family's era state still promises but that is not on disk refuses the
 *     whole run, for EVERY family (not only oauth_tokens), as does a snapshot that does not parse or
 *     names a family outside its prefix's set.
 *
 * INTERRUPTION POINTS — every one of them is recoverable, because the DB changes are ONE
 * transaction and the file moves are renames of files that are never overwritten:
 *   - BEFORE the commit: nothing changed. Re-run from the start.
 *   - AFTER the commit, BEFORE the first move: the rows are restored and the mirror is gone, while
 *     every file is still in place. A RE-RUN completes cleanly and is a no-op restore (the rows
 *     already sit at their snapshot values, so nothing is rewritten and the legacy sweep spares
 *     every value the journal names) followed by the moves; booting the previous release instead
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
 * THE JOURNAL. A snapshot entry is genuine only if THIS rollback restored it: its `h1.` row was present
 * and the CAS UPDATE put the legacy value back. The restores are collected INSIDE the one real
 * transaction, and only AFTER it committed — before the first move-aside — they are written to
 * `secrets/token-hmac-rbjournal-<stamp>.json` (0600, atomic) per family: identifiers plus legacy values,
 * hashes the snapshots beside it already hold. A first run (no journal) spares NOTHING, so a bare row
 * that merely equals a snapshot value — the replant of a session the operator logged out, of a rotated
 * local-token verifier, of a pairing or a deleted report link, which a crow.db writer holding the
 * pre-conversion hashes can do — is swept and counted as "removed". A RE-RUN after an interruption finds
 * the journal and spares exactly its entries (file-backed settings and peers included; a revoked peer
 * never); with NO journal it sweeps every bare row in a converted family. Because the journal exists
 * only once the transaction has committed, a crash BEFORE the commit leaves no journal at all (a later
 * rollback can never be told to spare something by a run that restored nothing), and a death between
 * the commit and the journal write simply means the re-run has no journal and sweeps. That fails closed:
 * the only cost is that the genuine restored rows are swept too, so those people sign in again and those
 * peers re-pair; nothing is laundered. The journal is moved aside with the snapshots, last, together with
 * any journal written under another key (ignored on read) and any leftover `.tmp-*` journal file. A
 * journal that does not parse, or carries an unknown `v`, refuses the run (exit 3).
 *
 * TEST SEAM — `CROW_TEST_ONLY_TOKEN_HMAC_ROLLBACK_INTERRUPT=<point>` (`precommit`, `commit`, `state`,
 * `key`, `snapshots`) stops the run right after that step with exit 7 (`precommit` throws inside the
 * transaction, so it rolls back and leaves no journal), which is how the tests model a crash
 * at each point above. It is TEST-ONLY: production never sets it, and nothing in `servers/` reads it.
 *
 * THE ACCEPTED WINDOW. Between a rollback and the next deploy the PREVIOUS release is on duty
 * again, and it reads a bare sha256 by value — so it is exposed to the forged-row issue this
 * release fixes. The next deploy converts every legacy row it finds, including one written in that
 * window (accepted). A rollback is a deploy-day undo, never a resting state.
 */
import {
  closeSync, existsSync, fsyncSync, openSync, readdirSync, readFileSync, renameSync, writeSync,
} from "node:fs";
import { createHash, randomBytes } from "node:crypto";
import { basename, dirname, join } from "node:path";
import { request } from "node:http";
import { createInterface } from "node:readline";
import { createDbClient } from "../servers/db.js";
import {
  TokenMacKeyError, adoptOperatorKey, ensureKey, eraSettingKey, familyConverted, macFromLegacy, markConverted,
  readState, tokenMacKeyPath, tokenMacStatePath,
} from "../servers/shared/token-mac.js";
import { gatewayListenHost } from "../servers/gateway/listen-host.js";
import { gatewayListenPort } from "../servers/gateway/listen-port.js";
import { readLocalInstanceIdOrNull } from "../servers/shared/crow-home.js";
import { readSetting, writeSetting } from "../servers/gateway/dashboard/settings/registry.js";
import { FAMILY_PREDICATE, TOKEN_STORE_FAMILIES, tokenFamilyConverted } from "../servers/gateway/token-store.js";
import {
  RAW_TOKEN_FILES, ROTATED_AT_BOOT, SETTINGS_TOKEN_FAMILIES, settingsTokenRawFile,
} from "../servers/gateway/token-settings.js";
import { PEER_INBOUND_FAMILY } from "../servers/gateway/peer-inbound-token.js";
import { ROLLBACK_PREFIX } from "../servers/gateway/boot/token-hmac.js";
import { SETTINGS_ROLLBACK_PREFIX, readTrustedProofFile } from "../servers/gateway/boot/token-hmac-settings.js";
import { PEER_ROLLBACK_PREFIX } from "../servers/gateway/boot/token-hmac-peers.js";
import { getInboundBearerSha256 } from "../servers/shared/peer-credentials.js";
import { REPORT_LINK_FAMILY } from "../servers/gateway/reports/link-token.js";
import { REPORT_LINK_ROLLBACK_PREFIX } from "../servers/gateway/boot/token-hmac-reports.js";

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

/** The `oauth_tokens` families a rollback restores — exactly the ones the boot converter visits. */
const RESTORABLE = new Set(TOKEN_STORE_FAMILIES);

/**
 * Every family `--reset` marks CONVERTED (step 4): the three `oauth_tokens` families, whose rows
 * this run just deleted; the thirteen settings-backed ones, whose stored verifiers it just
 * deleted; and the paired-instance family, whose row values it just cleared. Marking a family
 * that had no era yet is deliberate — see the header's step 4: without the marker, the next boot
 * would CONVERT a bare sha256 something without the key planted while the gateway was stopped.
 */
const CONVERTED_FAMILIES = Object.freeze([
  ...TOKEN_STORE_FAMILIES, ...SETTINGS_TOKEN_FAMILIES, PEER_INBOUND_FAMILY, REPORT_LINK_FAMILY,
]);

/** Every family a rollback visits: the same twenty-one `--reset` re-marks converted. */
const ROLLBACK_FAMILIES = CONVERTED_FAMILIES;

/**
 * `--reset`'s refusal when this home carries no `<data dir>/instance-id` (step 2b). Fixed text:
 * the reset cannot name the instance whose settings rows it must delete, so it changes nothing.
 */
const NO_INSTANCE_ID_REFUSAL =
  "No instance id at <data dir>/instance-id, so this home's stored token verifiers cannot be "
  + "targeted. Nothing was changed. Start the gateway once (it writes that file), then run this again.";

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

/**
 * Delete the SETTINGS-BACKED static tokens' stored verifiers (`--reset` step 2b).
 *
 * The rows are keyed by `(key, instance_id)`, so the delete means something only with THIS
 * instance's own id — the one `readLocalInstanceIdOrNull()` reads from `<data dir>/instance-id`,
 * the same file the gateway uses. Never `getOrCreateLocalInstanceId()` here: on a home that
 * carries no such file it mints a random per-process id, which matches no row, so the reset would
 * delete nothing and still report success. `reset()` refuses (exit 1, nothing changed) before
 * this is called when the file is missing.
 *
 * A settings store this DB does not have is skipped on its own, exactly as
 * `deleteEraMirrorRows` does for the era mirror, so a unit-test database loses only what it has.
 *
 * @param {object} db the gateway's crow.db client
 * @param {string} localId this instance's id (overrides are keyed by it)
 * @returns {Promise<number>} rows deleted
 */
async function dropSettingTokens(db, localId) {
  const hasTable = async (table) => {
    try {
      const { rows } = await db.execute({
        sql: "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", args: [table],
      });
      return (rows?.length ?? 0) > 0;
    } catch { return false; }
  };
  const overrides = await hasTable("dashboard_settings_overrides");
  const globals = await hasTable("dashboard_settings");
  let deleted = 0;
  for (const family of SETTINGS_TOKEN_FAMILIES) {
    if (overrides) {
      try {
        const res = await db.execute({
          sql: "DELETE FROM dashboard_settings_overrides WHERE key = ? AND instance_id = ?",
          args: [family, localId],
        });
        deleted += Number(res?.rowsAffected ?? 0) || 0;
      } catch { /* this store could not be written: nothing was deleted from it */ }
    }
    if (globals) {
      try {
        const res = await db.execute({ sql: "DELETE FROM dashboard_settings WHERE key = ?", args: [family] });
        deleted += Number(res?.rowsAffected ?? 0) || 0;
      } catch { /* same */ }
    }
  }
  return deleted;
}

/**
 * Clear every paired instance's inbound bearer verifier (`--reset` step 2c).
 *
 * Those values were minted under the key this run retires, so each would read as a FOREIGN keyId
 * and be refused anyway; clearing makes the required state explicit (every peer must re-pair)
 * and keeps the refusal from being mistaken for a keyId mismatch. The BEARER lives on the peer,
 * so nothing is re-minted here; the re-pair proof still works because
 * `secrets/peer-tokens.json` keeps the `inbound_bearer_sha256` this run does not touch (design
 * D4). A revoked row already holds NULL and is untouched, and an absent table (a unit-test
 * database) is skipped on its own.
 *
 * @param {object} db the gateway's crow.db client
 * @returns {Promise<number>} rows cleared
 */
async function clearPeerBearers(db) {
  try {
    const res = await db.execute({
      sql: "UPDATE crow_instances SET auth_token_hash = NULL WHERE auth_token_hash IS NOT NULL AND status != 'revoked'",
      args: [],
    });
    return Number(res?.rowsAffected ?? 0) || 0;
  } catch (err) {
    if (/no such table/i.test(String(err?.message || ""))) return 0;
    throw err;
  }
}

/**
 * Revoke every report link (`--reset` step 2d).
 *
 * Link verifiers keyed under the retired key would read as FOREIGN and be refused anyway. The column
 * is NOT NULL UNIQUE, so the rows are not cleared: `revoked_at` is stamped on every row that is not
 * already revoked (an already-revoked row keeps its own stamp). This SENDS NOTHING: recipients get
 * new links on the next normal scheduled run, the way they always do. An absent table is skipped.
 *
 * @returns {Promise<number>} rows revoked
 */
async function revokeReportLinks(db) {
  try {
    const res = await db.execute({
      sql: "UPDATE report_link_tokens SET revoked_at = ? WHERE revoked_at IS NULL",
      args: [Date.now()],
    });
    return Number(res?.rowsAffected ?? 0) || 0;
  } catch (err) {
    if (/no such table/i.test(String(err?.message || ""))) return 0;
    throw err;
  }
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

  // 2b needs this home's OWN instance id: the settings verifiers live in
  // `dashboard_settings_overrides`, keyed by `(key, instance_id)`. It is read from the file the
  // gateway itself uses, and a home without one is refused here — before anything moves — because
  // an id this process invented would target no row and delete nothing.
  const localId = readLocalInstanceIdOrNull();
  if (!localId) {
    console.error(NO_INSTANCE_ID_REFUSAL);
    return 1;
  }

  if (!yes) {
    console.log("This will:");
    console.log("  - revoke EVERY OAuth grant and dashboard session (all oauth_tokens rows)");
    console.log("  - delete the stored verifiers of every static token, and clear every paired instance's");
    console.log("    inbound bearer verifier (each peer then has to re-pair)");
    console.log("  - revoke every report link (nothing is sent; recipients get new links on the next scheduled run)");
    console.log("  - move the token HMAC key aside and create a new one");
    console.log("  - keep the dashboard password (you sign in again afterwards)");
    const ok = await confirm("Continue? [y/N] ");
    if (!ok) {
      console.log("Nothing was changed.");
      return 1;
    }
  }

  // 0. THE BOT DEFINITIONS, VERIFIED UNDER THE KEY THAT IS ABOUT TO RETIRE. A definition's verifier
  //    is an `h1.` MAC under that key, and after the swap nothing can tell a definition a key holder
  //    wrote from one a contained bot wrote. So the last moment to decide is NOW: every row is
  //    verified here (with the replay floor ON, round C item E5), and only the rows that verified are
  //    re-sealed in step 3b — re-sealed from the TUPLES collected here, never from a fresh read. A
  //    row that does not verify is LEFT AS IT IS (still refused, so its bot still does not spawn) and
  //    is printed for the operator, who re-approves that bot with
  //    `scripts/cli/bot-def-reapprove.mjs <bot_id>`. A RESET NEVER BLESSES AN UNVERIFIED ROW:
  //    with the old key gone there is nothing to verify with, so nothing would be re-sealed at all.
  const db = createDbClient();
  let botDefCheck = { verified: [], unverified: [], rows: [] };
  try {
    const { verifyAllBotDefs } = await import("../servers/shared/bot-def-store.js");
    botDefCheck = await verifyAllBotDefs(db);
  } catch (err) {
    console.warn(`bot defs:      could not be verified (${err?.message || err}); none will be re-sealed`);
  }

  // 1. The key goes aside first: nothing may mint under it after this line. The era state is NOT
  //    touched here — every family stays CONVERTED throughout (step 4 re-marks them, including
  //    the settings-backed ones), so the reset has no window in which a family is unconverted.
  const movedKey = moveAside(keyPath, "lost");

  let revoked = 0;
  let droppedStatic = 0;
  let resealed = { resealed: 0, failed: 0, refused: [] };
  let droppedPeers = 0;
  let revokedLinks = 0;
  let key;
  let mirrored = 0;
  try {
    // 2. Revoke every token row: grants and sessions alike.
    const res = await db.execute({ sql: "DELETE FROM oauth_tokens", args: [] });
    revoked = Number(res?.rowsAffected ?? 0) || 0;

    // 2b. The SETTINGS-BACKED static tokens (§1a: local MCP, board, phone, artifacts, models,
    //     peer relay, cloud door, the path-scoped loopback families, kiosk announce) are keyed
    //     under the key this run is retiring, so after it every stored one reads as a FOREIGN
    //     keyId and refuses. Their verifiers are deleted here so each family's own mint writes a
    //     fresh one: the boot re-ensures board/phone/artifacts/models/peer relay/kiosk, rotates
    //     the cloud door and the path-scoped families, and the owner re-generates the local MCP
    //     token in the Connect panel. This deletes VERIFIERS, not eras — every family is marked
    //     converted in step 4 (which is what makes a bare sha256 written in the meantime refused
    //     and alarmed rather than laundered by the next boot).
    droppedStatic = await dropSettingTokens(db, localId);

    // 2c. Every paired instance's inbound bearer verifier goes too: it is keyed under the key this
    //     run retires, it cannot be re-minted on this side (the bearer lives on the peer), and the
    //     peer's own re-pair proof still works from the `inbound_bearer_sha256` the credential
    //     store keeps. Revoked rows hold NULL already and are left alone.
    droppedPeers = await clearPeerBearers(db);

    // 2d. Every report link is revoked (stamped, never deleted): its verifier is keyed under the key
    //     this run retires. Nothing is sent from here; the next scheduled run mails new links.
    revokedLinks = await revokeReportLinks(db);

    // 3. A fresh key, so the box is immediately coherent (no login has to mint it). This is
    //    the one place a key may be created over an existing state file: the operator retired
    //    the old key on purpose, and every other field of the state stays as it is.
    key = adoptOperatorKey({ at: new Date().toISOString() });

    // 3b. Every BOT DEFINITION THAT VERIFIED under the retired key is re-sealed under the NEW key
    //     (servers/shared/bot-def-store.js). Each row gets a fresh generation too, which is also what
    //     retires any older (definition, MAC) pair a bot may have copied. `verifiedRows` is the TUPLE
    //     list step 0 verified while the OLD key was still loadable, and the re-seal writes exactly
    //     that content: it never re-reads a row, so a row a bot rewrote in between is skipped (its
    //     UPDATE's WHERE pins the step-0 tuple) instead of being stamped with content no key holder
    //     ever vouched for. A row that did not verify is not touched (a reset is a key change, never
    //     an amnesty). A store with no `pi_bot_defs` (or no seal columns) reports zero.
    {
      const { resealAllBotDefs } = await import("../servers/shared/bot-def-store.js");
      resealed = await resealAllBotDefs(db, { at: new Date(), verifiedRows: botDefCheck.verified });
    }

    // 4. Re-mark EVERY family CONVERTED, never cleared: the three `oauth_tokens` families and all
    //    thirteen settings-backed ones. From here on a legacy sha256 value in one of them — a row
    //    in oauth_tokens, a settings verifier a bot plants while the gateway is stopped — is
    //    refused and alarmed by every validator AND by the next boot's scan, instead of being
    //    converted into a valid `h1.` credential. A family that was already converted keeps its
    //    first `converted_at` (markConverted is add-only); the DB mirror is written by
    //    markConverted itself (`token_hmac_era:<family>`, local scope).
    for (const family of CONVERTED_FAMILIES) {
      // eslint-disable-next-line no-await-in-loop -- sixteen families, one operator run
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
  console.log(`  era state:     re-marked converted, never cleared: the ${TOKEN_STORE_FAMILIES.length} oauth_tokens`);
  console.log(`                 families, the ${SETTINGS_TOKEN_FAMILIES.length} settings-backed ones and the paired-instance`);
  console.log("                 family (no rows behind them)");
  console.log(`  oauth_tokens:  ${revoked} row(s) deleted — every OAuth grant and dashboard session is revoked`);
  console.log(`  static tokens: ${droppedStatic} stored verifier(s) deleted — board, phone, artifacts, models,`);
  console.log("                 peer relay, cloud door, services, satellite tools, secrets, sharing bot, reports");
  console.log("                 and kiosk announce are re-minted at the next start; the local MCP token has to");
  console.log("                 be generated again in Settings → Connect (its raw value is not kept anywhere)");
  console.log(`  peers:         ${droppedPeers} paired-instance verifier(s) cleared — every peer has to re-pair;`);
  console.log("                 its own `crow instance pair` can prove the old pairing (secrets/peer-tokens.json");
  console.log("                 keeps the record the re-pair proof is keyed by), so no --allow-re-pair is needed");
  console.log(`  report links:  ${revokedLinks} report link(s) revoked; recipients get new links on the next scheduled run`);
  console.log(`  era mirror:    ${mirrored} family marker(s) written to the DB as converted (no rows behind them)`);
  console.log(
    `  bot defs:      ${resealed.resealed} definition(s) re-sealed under the new key`
    + (resealed.failed ? `, ${resealed.failed} could not be` : ""),
  );
  // Rows that changed WHILE the reset ran: verified at step 0, not the row step 3b found. The re-seal
  // writes STEP 0's content and its UPDATE lands only on the row that still matches it, so they are
  // left exactly as they are and named (round C, item E5) — a reset re-seals what a key holder could
  // vouch for, never whatever a running bot wrote in between.
  const racedDefs = resealed.skipped || [];
  if (racedDefs.length) {
    console.log(
      "  bot defs changed during the reset (NOT re-sealed; re-run the reset or re-approve each): "
      + racedDefs.join(", "),
    );
  }
  // The rows nothing can vouch for. Listed by id, with the two ways out: the re-approve command (for
  // any bot, no Bot Builder page needed) or a full-form save in Bot Builder.
  const unverifiedDefs = botDefCheck.unverified || [];
  if (unverifiedDefs.length) {
    console.log(
      `  bot defs NOT re-sealed (changed outside Crow or captured before the seal). Until each one is\n`
      + "  re-approved it is refused and its bot does not start. For each id, review the stored\n"
      + "  definition and re-approve exactly that content:\n"
      + unverifiedDefs.map((id) => `    node scripts/cli/bot-def-reapprove.mjs ${id} --show`).join("\n"),
    );
  }
  console.log("");
  console.log("Start the gateway again. Existing MCP clients must re-authorize, and every browser");
  console.log("must sign in again with the dashboard password.");
  console.log("Restart the separate bot bridge process(es) too (pibot-bridge, the gateway's own bot");
  console.log("runtime, or both): each one holds the retired key in memory until it restarts.");
  return 0;
}

/**
 * The snapshot files a rollback reads, one entry per converter that writes them: its file prefix, the
 * families a file under that prefix may name, and the shape of its rows.
 *   - "token": `{…, token: <64 hex>}` (oauth_tokens: `{rowid, token}`; settings: `{store, key, token}`);
 *   - "id":    `{id, <field>: <64 hex>}` (peers: `token`; report links: `legacy`).
 * The prefixes do not start with one another, so a file belongs to at most one entry.
 */
const SNAPSHOT_KINDS = Object.freeze([
  { prefix: ROLLBACK_PREFIX, families: new Set(TOKEN_STORE_FAMILIES), shape: "token", field: "token" },
  { prefix: SETTINGS_ROLLBACK_PREFIX, families: new Set(SETTINGS_TOKEN_FAMILIES), shape: "token", field: "token" },
  { prefix: PEER_ROLLBACK_PREFIX, families: new Set([PEER_INBOUND_FAMILY]), shape: "id", field: "token" },
  { prefix: REPORT_LINK_ROLLBACK_PREFIX, families: new Set([REPORT_LINK_FAMILY]), shape: "id", field: "legacy" },
]);

/** Either hex case: the peer and report-link converters count an uppercase 64-hex as legacy too. */
const LEGACY_ANY_CASE = /^[0-9a-f]{64}$/i;

/** The `h1.` keyed form every converter writes. */
const isKeyed = (value) => typeof value === "string" && value.startsWith("h1.");

/** The key a snapshot row is deduplicated and spared by: the bare value, or `<id>\0<value>`. */
const rowKey = (row) => (typeof row === "string" ? row : `${row.id}\u0000${row.legacy}`);

/**
 * The ROLLBACK JOURNAL (`secrets/token-hmac-rbjournal-<stamp>.json`, 0600, atomic): what THIS
 * run's transaction restored, per family — identifiers plus legacy values, which the snapshots beside it
 * already hold. Its prefix deliberately does not start with a snapshot prefix.
 * A snapshot entry is genuine only if a rollback RESTORED it (its `h1.` row was present and the CAS
 * UPDATE ran); a bare row that merely equals a snapshot value is a replant of a credential the operator
 * had revoked or rotated, and is swept. The journal is what lets an interrupted run's RE-RUN tell the two
 * apart: it spares exactly the journal's entries. With no journal a re-run sweeps every bare row.
 */
const JOURNAL_PREFIX = "token-hmac-rbjournal-";
const JOURNAL_VERSION = 1;

/** A journal entry's spare key: the bare value (oauth_tokens, settings) or `<id>\0<value>`. */
const spareKey = (entry) => (typeof entry === "string" ? entry.toLowerCase() : `${entry.id}\u0000${entry.legacy}`);

const emptySpare = () => new Map();
const spareHas = (ctx, family, key) => ctx.spare.get(family)?.has(key) === true;

/** Record that THIS pass restored `entry` (a legacy string, or `{id, legacy}`) for `family`. */
function noteRestored(ctx, family, entry) {
  if (!ctx.restored.has(family)) ctx.restored.set(family, new Map());
  ctx.restored.get(family).set(spareKey(entry), entry);
}

/**
 * Journals left by an earlier, interrupted run under THIS key. A journal that does not parse refuses the
 * run (exit 3); one written under another key is ignored.
 *
 * @returns {{ok: true, names: string[], aside: string[], spare: Map<string, Set<string>>} | {ok: false, reason: string}}
 *          `names` are the journals this run spares from; `aside` additionally holds journals under another
 *          key and leftover `.tmp-*` files, which are only moved aside.
 */
function readJournals(dir, keyId) {
  let entries;
  try {
    entries = readdirSync(dir);
  } catch (err) {
    if (err.code === "ENOENT") return { ok: true, names: [], aside: [], spare: emptySpare() };
    throw err;
  }
  const names = [];
  const aside = [];
  const spare = emptySpare();
  for (const name of entries.slice().sort()) {
    if (!name.startsWith(JOURNAL_PREFIX)) continue;
    if (name.includes(".tmp-")) { aside.push(name); continue; }
    if (!name.endsWith(".json")) continue;
    let body;
    try {
      body = JSON.parse(readFileSync(join(dir, name), "utf8"));
    } catch (err) {
      return { ok: false, reason: `secrets/${name} does not parse as a rollback journal (${err.code || err.message}).` };
    }
    if (!body || typeof body !== "object" || Array.isArray(body) || !body.families || typeof body.families !== "object") {
      return { ok: false, reason: `secrets/${name} is not a rollback journal.` };
    }
    if (body.v !== JOURNAL_VERSION) {
      return { ok: false, reason: `secrets/${name} is a rollback journal of an unknown version.` };
    }
    if (body.key_id !== keyId) { aside.push(name); continue; }
    for (const [family, list] of Object.entries(body.families)) {
      if (!ROLLBACK_FAMILIES.includes(family) || !Array.isArray(list)) {
        return { ok: false, reason: `secrets/${name} is not a rollback journal.` };
      }
      if (!spare.has(family)) spare.set(family, new Set());
      for (const item of list) {
        const ok = typeof item === "string"
          ? LEGACY_ANY_CASE.test(item)
          : typeof item?.id === "string" && typeof item?.legacy === "string" && LEGACY_ANY_CASE.test(item.legacy);
        if (!ok) return { ok: false, reason: `secrets/${name} is not a rollback journal.` };
        spare.get(family).add(spareKey(item));
      }
    }
    names.push(name);
  }
  return { ok: true, names, aside, spare };
}

/** Write the journal atomically and owner-only (temp 0600 + fsync + rename), AFTER the commit. */
function writeJournal(dir, keyId, restored) {
  const families = {};
  let any = false;
  for (const [family, map] of restored) {
    if (map.size === 0) continue;
    families[family] = [...map.values()];
    any = true;
  }
  if (!any) return null;
  const final = join(dir, `${JOURNAL_PREFIX}${stamp()}.json`);
  const tmp = `${final}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, `${JSON.stringify({
      v: JOURNAL_VERSION, key_id: keyId, created_at: new Date().toISOString(), families,
    }, null, 2)}\n`);
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  renameSync(tmp, final);
  return final;
}

/**
 * Every conversion snapshot in `secrets/`, validated together.
 *
 * A rollback restores only what a snapshot can PROVE, so one file that cannot be read at all — it
 * does not parse, it is not the snapshot shape, or it names a family its prefix does not belong to —
 * refuses the whole run before anything moves. But a file written under a DIFFERENT key is IGNORED
 * (and reported): its values belong to an era this box no longer holds the key for (a `--reset`, a
 * key rotation), so it can neither be restored nor be allowed to block what the current key can
 * still do. The key check comes first on purpose: a foreign file is unusable as a whole, whatever
 * family it names.
 *
 * A file moved aside by an earlier rollback ends in `.rolledback-<stamp>`, not `.json`, so a
 * second rollback never picks one up. A row whose value is not a bare sha256 hex cannot be
 * restored and is ignored (the converters only ever write those).
 *
 * @returns {{ok: true, names: string[], snapshots: {name: string, family: string, rows: Array<string|{id: string, legacy: string}>}[],
 *            ignored: {name: string, family: string}[]}
 *          | {ok: false, reason: string}} `names` are the USABLE files, the only ones moved aside.
 *          A row is the lowercase legacy string (oauth_tokens, settings) or `{id, legacy}` (peers,
 *          report links; `legacy` exactly as the converter stored it).
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
    const kind = SNAPSHOT_KINDS.find((k) => name.startsWith(k.prefix));
    if (!kind || !name.endsWith(".json")) continue;
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
    if (!kind.families.has(body.family)) {
      return {
        ok: false,
        reason: `secrets/${name} names the family ${JSON.stringify(String(body.family))}, `
          + "which a rollback does not restore.",
      };
    }
    const rows = [];
    for (const row of body.rows) {
      const value = typeof row?.[kind.field] === "string" ? row[kind.field] : "";
      if (kind.shape === "token") {
        if (LEGACY_STORED.test(value.toLowerCase())) rows.push(value.toLowerCase());
      } else if (typeof row?.id === "string" && row.id && LEGACY_ANY_CASE.test(value)) {
        rows.push({ id: row.id, legacy: value });
      }
    }
    names.push(name);
    snapshots.push({ name, family: body.family, rows });
  }
  return { ok: true, names, snapshots, ignored };
}

/**
 * The rollback snapshots the ERA STATE still promises: the `rollback_file` each converted family
 * records in `secrets/token-hmac-state.json`, for EVERY keyed family (oauth_tokens, settings, peers,
 * report links).
 *
 * This is what tells "there is nothing to restore" (a `--reset` box, or an adopted era: they record
 * no rollback file, so no row can be brought back) from "a snapshot this box was relying on is
 * MISSING". A corrupt or unreadable state file cannot answer, and a rollback that cannot tell must
 * not proceed.
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
  for (const family of ROLLBACK_FAMILIES) {
    const entry = st.families?.[family];
    if (!entry || typeof entry !== "object" || !entry.converted_at) continue;
    if (typeof entry.rollback_file === "string" && entry.rollback_file) {
      families.push({ family, file: entry.rollback_file });
    }
  }
  return { ok: true, families };
}

/**
 * Delete every `token_hmac_era:<family>` mirror row (all keyed families) — this instance's overrides
 * AND the global rows — through the transaction's own synchronous `run`, so they commit with the
 * restored rows.
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
  const overrides = txHasTable(run, "dashboard_settings_overrides");
  const globals = txHasTable(run, "dashboard_settings");
  let deleted = 0;
  for (const family of ROLLBACK_FAMILIES) {
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

const txHasTable = (run, table) => run({
  sql: "SELECT name FROM sqlite_master WHERE type = 'table' AND name = ?", args: [table],
}).rows.length > 0;

const changesOf = (res) => Number(res?.rowsAffected ?? 0) || 0;

const newCounts = () => ({
  restored: 0, gone: 0, revoked: 0, removed: 0,
});

/**
 * `readSetting` for the era mirror, with "this DB has no settings store" answering null (a unit-test
 * DB). Any other failure is rethrown, so `familyConverted` fails CLOSED on it.
 */
async function mirrorReader(db, key) {
  try {
    return await readSetting(db, key);
  } catch (err) {
    if (/no such table/i.test(String(err?.message || ""))) return null;
    throw err;
  }
}

/**
 * What the proof file of a FILE-BACKED settings family says, judged exactly as the converter judges
 * it (`readTrustedProofFile`). `{ok: true, sha}` is `sha256(raw file content)`, the previous
 * release's stored form; `{ok: false}` is "missing or untrustworthy".
 */
function fileVerdict(family) {
  const path = settingsTokenRawFile(family);
  if (!path) return null;
  const read = readTrustedProofFile(path);
  if (!read.ok) return { ok: false };
  return { ok: true, sha: createHash("sha256").update(read.token).digest("hex") };
}

/** What the previous release does for a settings family whose verifier a rollback deleted. */
function settingsNote(family) {
  if (RAW_TOKEN_FILES[family]) return "a deleted verifier is re-ensured by the previous release's own boot";
  if (ROTATED_AT_BOOT.includes(family)) return "a deleted verifier is re-minted at the previous release's next start";
  return "a deleted verifier means the token is generated again in Settings -> Connect";
}

/**
 * The SETTINGS families, inside the rollback transaction (`run` is synchronous).
 *
 * @param {{localId: string, converted: Map<string, boolean>, snapshotRows: Map<string, string[]>,
 *          files: Map<string, {ok: boolean, sha?: string}>}} ctx
 * @returns {Map<string, ReturnType<typeof newCounts> & {fromFile: number, fileGone: number}>}
 */
function restoreSettingsFamilies(run, ctx) {
  const out = new Map();
  const overrides = txHasTable(run, "dashboard_settings_overrides");
  const globals = txHasTable(run, "dashboard_settings");
  for (const family of SETTINGS_TOKEN_FAMILIES) {
    const count = { ...newCounts(), fromFile: 0, fileGone: 0 };
    out.set(family, count);
    const isConverted = Boolean(ctx.converted.get(family));
    const legacies = ctx.snapshotRows.get(family) ?? [];
    const file = RAW_TOKEN_FILES[family] ? ctx.files.get(family) : null;
    let accounted = 0; // snapshot values found restored or already in place

    if (overrides) {
      const row = run({
        sql: "SELECT value AS value FROM dashboard_settings_overrides WHERE key = ? AND instance_id = ?",
        args: [family, ctx.localId],
      }).rows[0];
      const value = row?.value === undefined || row?.value === null ? null : String(row.value);
      const write = (to) => changesOf(run({
        sql: "UPDATE dashboard_settings_overrides SET value = ?, updated_at = datetime('now') "
          + "WHERE key = ? AND instance_id = ? AND value = ?",
        args: [to, family, ctx.localId, value],
      }));
      const drop = () => changesOf(run({
        sql: "DELETE FROM dashboard_settings_overrides WHERE key = ? AND instance_id = ? AND value = ?",
        args: [family, ctx.localId, value],
      }));
      if (value !== null && isKeyed(value)) {
        if (file) {
          // FILE-BACKED: the previous release stores sha256(raw file). The file must PROVE the keyed
          // value (it is the token's only raw copy); anything else is deleted and re-ensured.
          if (file.ok && macFromLegacy(family, file.sha) === value) {
            if (write(file.sha) > 0) {
              count.restored += 1; count.fromFile += 1; noteRestored(ctx, family, file.sha);
            }
          } else if (drop() > 0) {
            count.revoked += 1;
            count.fileGone += 1;
          }
        } else {
          const match = legacies.find((legacy) => macFromLegacy(family, legacy) === value);
          if (match) {
            if (write(match) > 0) {
              count.restored += 1; accounted += 1; noteRestored(ctx, family, match);
            }
          } else if (drop() > 0) {
            count.revoked += 1; // minted after the conversion: no snapshot knows its raw token
          }
        }
      } else if (value !== null && LEGACY_ANY_CASE.test(value)) {
        const lower = value.toLowerCase();
        if (file) {
          // Spared ONLY when an earlier run of this rollback restored it (its journal says so): a bare
          // value that merely equals sha256(file) is a replant of a credential the operator rotated.
          if (file.ok && lower === file.sha && spareHas(ctx, family, lower)) {
            count.restored += 1; count.fromFile += 1; // a re-run of a committed rollback
          } else if (isConverted && drop() > 0) count.removed += 1;
        } else if (spareHas(ctx, family, lower)) {
          count.restored += 1; // already in place: THIS rollback's own earlier run put it there
          accounted += 1;
        } else if (isConverted && drop() > 0) {
          count.removed += 1; // written after the conversion: a forgery the alarm refused
        }
      }
    }
    count.gone = file ? 0 : legacies.length - accounted;

    // A GLOBAL row of a converted family is never read and never legitimate (design OQ-8): whatever
    // form it holds, the previous release would read a bare value there, so it goes.
    if (globals && isConverted) {
      count.removed += changesOf(run({ sql: "DELETE FROM dashboard_settings WHERE key = ?", args: [family] }));
    }
  }
  return out;
}

/**
 * The PAIRED-INSTANCE verifiers, inside the rollback transaction.
 *
 * @returns {{restoredRecord: number, restoredSnapshot: number, nulled: number, removed: number} | null}
 *          null when this DB has no `crow_instances`.
 */
function restorePeers(run, ctx) {
  if (!txHasTable(run, "crow_instances")) return null;
  const result = {
    restoredRecord: 0, restoredSnapshot: 0, nulled: 0, removed: 0,
  };
  const isConverted = Boolean(ctx.converted.get(PEER_INBOUND_FAMILY));
  const fromSnapshot = new Map();
  for (const row of ctx.snapshotRows.get(PEER_INBOUND_FAMILY) ?? []) fromSnapshot.set(row.id, row.legacy);
  const { rows } = run({
    sql: "SELECT id AS id, auth_token_hash AS stored, status AS status FROM crow_instances WHERE auth_token_hash IS NOT NULL",
    args: [],
  });
  const cas = (id, stored, to) => changesOf(run({
    sql: "UPDATE crow_instances SET auth_token_hash = ? WHERE id = ? AND auth_token_hash = ?",
    args: [to, id, stored],
  }));
  for (const row of rows) {
    const id = String(row.id ?? "");
    const stored = String(row.stored ?? "");
    const revoked = String(row.status ?? "") === "revoked";
    const record = getInboundBearerSha256(id);
    const snap = fromSnapshot.get(id) ?? null;
    if (isKeyed(stored)) {
      // The D4 record decides (it also covers a pairing made AFTER the conversion); a snapshot entry
      // is the fallback ONLY for a peer with no record. Either must reproduce the row's CURRENT keyed
      // value, so a recorded hash that is not this row's verifier is never restored.
      let target = null;
      let via = null;
      if (record) {
        if (macFromLegacy(PEER_INBOUND_FAMILY, record) === stored) { target = record; via = "record"; }
      } else if (snap && macFromLegacy(PEER_INBOUND_FAMILY, snap) === stored) {
        target = snap;
        via = "snapshot";
      }
      if (target && !revoked && cas(id, stored, target) > 0) {
        if (via === "record") result.restoredRecord += 1; else result.restoredSnapshot += 1;
        noteRestored(ctx, PEER_INBOUND_FAMILY, { id, legacy: target });
      } else if (cas(id, stored, null) > 0) {
        result.nulled += 1; // that peer re-pairs
      }
    } else if (LEGACY_ANY_CASE.test(stored) && isConverted) {
      // A bare value is genuine only when an earlier run of THIS rollback restored it (its journal
      // names this peer and this value) and the peer is not revoked. Equal to the record or a snapshot
      // is not enough: that is exactly what a replant of a rotated or revoked pairing looks like.
      const genuine = !revoked && spareHas(ctx, PEER_INBOUND_FAMILY, spareKey({ id, legacy: stored }));
      if (genuine) {
        if (record && stored.toLowerCase() === record) result.restoredRecord += 1; else result.restoredSnapshot += 1;
      } else if (cas(id, stored, null) > 0) {
        result.removed += 1;
      }
    }
  }
  return result;
}

/**
 * The REPORT-LINK verifiers, inside the rollback transaction.
 *
 * @returns {{restored: number, gone: number, revoked: number, removed: number} | null}
 *          null when this DB has no `report_link_tokens`.
 */
function restoreReportLinks(run, ctx) {
  if (!txHasTable(run, "report_link_tokens")) return null;
  const count = newCounts();
  const isConverted = Boolean(ctx.converted.get(REPORT_LINK_FAMILY));
  const entries = ctx.snapshotRows.get(REPORT_LINK_FAMILY) ?? [];
  const nowMs = Date.now();
  // A tombstone is never a credential (neither 64-hex nor `h1.`); its random suffix means a bot cannot
  // pre-insert the value an UPDATE will write.
  const tombstone = (id) => run({
    sql: "UPDATE report_link_tokens SET revoked_at = COALESCE(revoked_at, ?), token_hash = ? WHERE id = ?",
    args: [nowMs, `revoked:${id}:${randomBytes(8).toString("hex")}`, id],
  });

  // 3a. A bare row in a converted family that no earlier run of THIS rollback restored (same id AND
  //     same value in its journal) is a forgery the alarm refused — or a replant of a link the operator
  //     deleted or revoked. It is revoked and its value freed (UNIQUE) before the restores.
  if (isConverted) {
    const { rows } = run({ sql: "SELECT id AS id, token_hash AS stored FROM report_link_tokens", args: [] });
    for (const row of rows) {
      const stored = String(row.stored ?? "");
      if (!LEGACY_ANY_CASE.test(stored) || spareHas(ctx, REPORT_LINK_FAMILY, spareKey({ id: String(row.id), legacy: stored }))) continue;
      tombstone(String(row.id));
      count.removed += 1;
    }
  }

  // 3b. The restores: CAS on (id, keyed value).
  for (const entry of entries) {
    const h1 = macFromLegacy(REPORT_LINK_FAMILY, entry.legacy);
    // The same primary-key collision, one row at a time: another row holding this value cannot be
    // the genuine one (only reachable on a family the era does not call converted).
    const clash = run({
      sql: "SELECT id AS id FROM report_link_tokens WHERE token_hash = ? AND id != ?", args: [entry.legacy, entry.id],
    }).rows[0];
    if (clash) {
      tombstone(String(clash.id));
      count.removed += 1;
    }
    const res = run({
      sql: "UPDATE report_link_tokens SET token_hash = ? WHERE id = ? AND token_hash = ?",
      args: [entry.legacy, entry.id, h1],
    });
    if (changesOf(res) > 0) {
      count.restored += 1;
      noteRestored(ctx, REPORT_LINK_FAMILY, entry);
    } else if (spareHas(ctx, REPORT_LINK_FAMILY, spareKey(entry)) && run({
      sql: "SELECT 1 AS present FROM report_link_tokens WHERE id = ? AND token_hash = ?",
      args: [entry.id, entry.legacy],
    }).rows.length > 0) count.restored += 1; // already in place: this rollback's own earlier run
    else count.gone += 1; // tombstoned as a twin/copy, or its row is gone
  }

  // 3c. Whatever still holds an `h1.` value was minted AFTER the conversion: the previous release can
  //     never match it, and it is stamped revoked (the value stays; `revoked:` tombstones are untouched).
  //     NOTE (re-upgrade): such a link keeps its OLD-key `h1.` value. That does not make the re-upgrade
  //     read as "key lost" (an `h1.` value on a key-less box), but ONLY because the oauth_tokens boot
  //     runs first, creates the new key, and scans oauth_tokens alone; every later boot finds a key.
  //     If a re-upgrade reports an adopted era or a lost key, `--reset` is the way out.
  count.revoked += changesOf(run({
    sql: "UPDATE report_link_tokens SET revoked_at = ? WHERE token_hash LIKE 'h1.%' AND revoked_at IS NULL",
    args: [nowMs],
  }));
  return count;
}

/** Settings, peer and report-link family names are longer than the oauth_tokens ones. */
const padFamily = (family) => family.padEnd(32);

/**
 * `--rollback`: put every converted keyed verifier back into the form the previous release reads.
 *
 * Steps and their rationale are in this file's header. Every check runs BEFORE the first change
 * (the DB transaction is atomic, and the file moves happen only after it committed), so the
 * refusals — a running gateway (2), an unusable key or snapshot (3), a home with no instance id (1)
 * — leave the box exactly as it was.
 *
 * TEST SEAM: `CROW_TEST_ONLY_TOKEN_HMAC_ROLLBACK_INTERRUPT=<point>` (`commit`, `state`, `key`,
 * `snapshots`) reports and exits 7 right after that step, which is how the interruption tests model a
 * crash at each of the header's interruption points. TEST-ONLY: production never sets it.
 */
class PrecommitInterrupt extends Error {}

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
    console.log("  - restore every converted verifier to the form the previous release reads: the oauth_tokens");
    console.log("    rows and the report links from their conversion snapshots, the static-token verifiers");
    console.log("    (file-backed ones as sha256 of their token file), and every paired instance's bearer");
    console.log("    verifier from its recorded hash (rows that expired or were revoked since stay gone)");
    console.log("  - delete, NULL or revoke old-style values written after the conversion, and every verifier");
    console.log("    minted after it (neither one has a pre-conversion form); a peer with nothing to restore");
    console.log("    from has to re-pair");
    console.log("  - delete every token_hmac_era:* mirror row, so the next deploy converts again");
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

  // 2b'. A journal an interrupted earlier run of THIS rollback left behind: its entries are the only bare
  //     rows a sweep may spare. Validated before anything changes, like the snapshots.
  const journals = readJournals(dir, key.id);
  if (!journals.ok) {
    console.error(`${journals.reason} Nothing was changed.`);
    return 3;
  }

  // A usable snapshot's values are the rows that may legitimately hold a bare value after this
  // run. They are keyed by family: the legacy sweeps below spare exactly these, and the oauth
  // restore plan is one entry per (family, legacy) pair.
  const usableByFamily = new Map();
  const snapshotRows = new Map();
  const plan = [];
  for (const snap of scan.snapshots) {
    if (!usableByFamily.has(snap.family)) {
      usableByFamily.set(snap.family, new Map());
      snapshotRows.set(snap.family, []);
    }
    const values = usableByFamily.get(snap.family);
    for (const row of snap.rows) {
      const k = rowKey(row);
      if (values.has(k)) continue;
      values.set(k, snap.name);
      snapshotRows.get(snap.family).push(row);
      if (RESTORABLE.has(snap.family)) plan.push({ family: snap.family, legacy: row, h1: macFromLegacy(snap.family, row) });
    }
  }

  // 2c. Nothing usable to restore: only a box the era state does not promise a snapshot for may
  //     proceed (a `--reset` box re-marks every family converted with NO rollback file, so no
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

  // 2d. The instance id the settings rows and the era-mirror override rows are scoped by, read BEFORE
  //     the transaction from the file the gateway itself uses (`--reset` does the same): an id this
  //     process invented would match no row, and the run would report success having restored none.
  const localId = readLocalInstanceIdOrNull();
  if (!localId) {
    console.error(NO_INSTANCE_ID_REFUSAL);
    return 1;
  }

  const counts = new Map(TOKEN_STORE_FAMILIES.map((family) => [family, newCounts()]));
  let mirrored = 0;
  let settings = new Map();
  let peers = null;
  let links = null;
  let journalPath = null;
  let realCtx = null;
  const db = createDbClient();
  try {
    // Does the ERA say this family is converted? (state file OR the DB mirror, failing closed).
    // Computed outside the transaction because a transaction callback must not await.
    const converted = new Map();
    for (const family of TOKEN_STORE_FAMILIES) {
      // eslint-disable-next-line no-await-in-loop -- three families, one operator run
      converted.set(family, await tokenFamilyConverted(family, db));
    }
    for (const family of [...SETTINGS_TOKEN_FAMILIES, PEER_INBOUND_FAMILY, REPORT_LINK_FAMILY]) {
      // eslint-disable-next-line no-await-in-loop -- one operator run
      converted.set(family, await familyConverted(family, { readSetting: (k) => mirrorReader(db, k) }));
    }
    // The raw token files of the file-backed families, judged before anything is written.
    const files = new Map();
    for (const family of Object.keys(RAW_TOKEN_FILES)) files.set(family, fileVerdict(family));
    // The pass body, in the order the header documents. It runs ONCE FOR REAL, and first (on a first run
    // only) as a DRY pass that is rolled back, to learn exactly which snapshot entries the CAS restores:
    // those, and only those, go into the journal before the real transaction.
    const pass = (run, ctx) => {
      // 3a. POST-CONVERSION LEGACY WRITES (R2). A bare (non-`h1.`) row in a CONVERTED family was
      //     written after the conversion, so it is a forgery the alarm refused. It is deleted
      //     FIRST, because a forged row sitting on a snapshot's own value would collide with the
      //     restore below (the stored value is the primary key). A snapshot value is NOT thereby
      //     genuine: a bare row equal to one is a replant of a credential the operator logged out or
      //     rotated since the conversion. Only the values a JOURNAL names — restored by an earlier,
      //     interrupted run of this very rollback — are SPARED, because on that re-run those rows ARE
      //     the restored genuine ones. With no journal (a first run) nothing is spared.
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
        const keep = ctx.spare.get(family) ?? new Set();
        const { rows } = run({
          sql: `SELECT rowid AS rowid, token FROM oauth_tokens WHERE token NOT LIKE 'h1.%' AND (${FAMILY_PREDICATE[family]})`,
          args: [],
        });
        for (const row of rows) {
          const value = String(row?.token ?? "");
          if (keep.has(value)) continue;
          const res = run({ sql: "DELETE FROM oauth_tokens WHERE token = ?", args: [value] });
          counts.get(family).removed += changesOf(res);
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
          count.removed += changesOf(res);
        }
        const res = run({
          sql: `UPDATE oauth_tokens SET token = ? WHERE token = ? AND (${FAMILY_PREDICATE[item.family]})`,
          args: [item.legacy, item.h1],
        });
        if (changesOf(res) > 0) {
          count.restored += 1;
          noteRestored(ctx, item.family, item.legacy);
        } else if (run({
          sql: `SELECT 1 AS present FROM oauth_tokens WHERE token = ? AND (${FAMILY_PREDICATE[item.family]})`,
          args: [item.legacy],
        }).rows.length > 0 && ctx.spare.get(item.family)?.has(item.legacy)) {
          count.restored += 1; // already in place: this rollback's own earlier run put it there
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
        counts.get(family).revoked += changesOf(res);
      }

      // 3c'. The other three kinds of family, same rules in their own stores (see the header).
      settings = restoreSettingsFamilies(run, ctx);
      peers = restorePeers(run, ctx);
      links = restoreReportLinks(run, ctx);

      // 3d. The one-way era mirror, in the SAME transaction (R1) — see the header for why it must
      //     go, and R5 for why a missing settings table skips only itself.
      mirrored = deleteEraMirrorRows(run, localId);
    };
    const freshCtx = (spare) => ({
      localId, converted, snapshotRows, files, spare, restored: new Map(),
    });

    realCtx = freshCtx(journals.spare);
    await db.runTransaction((run) => {
      pass(run, realCtx);
      // TEST SEAM: a crash BEFORE the commit. Throwing here rolls the transaction back; no journal exists.
      if (interruptAfter === "precommit") throw new PrecommitInterrupt();
    });
  } catch (err) {
    if (err instanceof PrecommitInterrupt) {
      console.error(
        "token-hmac: interrupted before the commit (CROW_TEST_ONLY_TOKEN_HMAC_ROLLBACK_INTERRUPT). Nothing was "
        + "changed and no journal was written.",
      );
      return 7;
    }
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
  // The journal is written only now, after the commit and before the first move-aside. A death between
  // the commit and this write leaves no journal, so the re-run sweeps (people sign in again, peers
  // re-pair): that fails closed. A re-run with a journal keeps it; it describes the first run.
  if (journals.names.length === 0) {
    try {
      journalPath = writeJournal(dir, key.id, realCtx.restored);
    } catch (err) {
      console.error(`token-hmac: the rollback journal could not be written (${err.code || err.message}); a re-run would sweep.`);
    }
  }
  if (interruptAfter === "commit") return interrupted("commit");
  const at = new Date();
  const moved = [];
  const steps = [
    { step: "state", path: statePath },
    { step: "key", path: keyPath },
    ...scan.names.map((name) => ({ step: "snapshots", path: join(dir, name) })),
    // The journal goes last: until the snapshots have moved, a re-run may still need it.
    ...[...journals.names, ...journals.aside, ...(journalPath ? [basename(journalPath)] : [])]
      .map((name) => ({ step: "snapshots", path: join(dir, name) })),
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
  for (const family of SETTINGS_TOKEN_FAMILIES) {
    const count = settings.get(family);
    if (!count) continue;
    const fileBacked = RAW_TOKEN_FILES[family];
    const detail = fileBacked
      ? `${count.fromFile} restored as sha256 of the token file, ${count.fileGone} deleted (token file missing, `
        + "untrusted or not matching), "
      : `${count.restored} restored, ${count.gone} gone, ${count.revoked} deleted (minted after conversion), `;
    console.log(`  ${padFamily(family)} ${detail}${count.removed} removed (written after conversion, never valid)`
      + `${count.revoked || count.fileGone ? `; ${settingsNote(family)}` : ""}`);
  }
  if (peers) {
    console.log(
      `  ${padFamily(PEER_INBOUND_FAMILY)} ${peers.restoredRecord} restored from the recorded bearer hash, `
      + `${peers.restoredSnapshot} restored from the snapshot (no record), ${peers.nulled} set to NULL `
      + `(no matching record: that peer re-pairs), ${peers.removed} removed (written after conversion, never valid)`,
    );
  }
  if (links) {
    console.log(
      `  ${padFamily(REPORT_LINK_FAMILY)} ${links.restored} restored, ${links.gone} gone, `
      + `${links.revoked} revoked (minted after conversion), `
      + `${links.removed} removed (written after conversion, never valid)`,
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
  console.log("  bot defs:          NOT rolled back (not a token family). Their MACs are keyed under the key just moved");
  console.log("                     aside, so after the next deploy mints a new key every bot definition is refused until");
  console.log("                     re-approved: node scripts/cli/bot-def-reapprove.mjs <bot_id> --show, then");
  console.log("                     node scripts/cli/bot-def-reapprove.mjs <bot_id> --approve <digest>");
  console.log("");
  console.log("If the re-upgrade reports an adopted era or a lost key, run `node scripts/token-hmac.mjs --reset`.");
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
    console.error("  --rollback  undo every keyed-verifier conversion: restore the oauth_tokens rows, the static-token");
    console.error("            verifiers, the paired-instance bearer verifiers and the report links to their");
    console.error("            pre-conversion form, delete/NULL/revoke what was written or minted after it, then");
    console.error("            move the era state, the key and the snapshots aside and delete the era mirror");
    console.error("            (operator shell; run it with the gateway stopped)");
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