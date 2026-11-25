/**
 * Pre-listen boot for the SETTINGS-BACKED token families (§1a / §3.2 / §3.3 / §8 PR 3a of the
 * keyed-token-hashes design): create or load the HMAC key, convert every legacy (bare sha256)
 * value of the thirteen `*_token_hash` settings to its `h1.` form, and alarm on old-style
 * values that appear afterwards.
 *
 * ORDER. `servers/gateway/index.js` calls this right after the `oauth_tokens` boot
 * (`boot/token-hmac.js`) and long before listen, so no middleware, door, model route or kiosk
 * route can validate a stored value the converter has not seen — the accepted-legacy window is
 * zero, not "until the next restart".
 *
 * CONVERSION (§3.2), per family, ONE shot and never a second one:
 *   1. What does each store hold? The local override (`dashboard_settings_overrides`) and the
 *      GLOBAL `dashboard_settings` row are BOTH read — a bot can plant in either.
 *   1b. THE OVERRIDE IS THE ONLY ANSWER (design OQ-8, decided 2026-11-23). Every reader of
 *      these keys is override-only (`readStoredSettingsToken`), and the product only ever writes
 *      them local-scope, so a global row is the bot's second write target. On this one boot:
 *        - global + override → ANOMALOUS: not converted, deleted by value (CAS), alarmed and
 *          counted as refused (`refusedGlobal`);
 *        - rotated-at-boot family → retired (the boot mints a fresh keyed value into the
 *          override a moment later, so it can launder nothing and is not accused);
 *        - otherwise (no override) → MOVED into this instance's override, so no working token
 *          is lost and no client breaks.
 *      From the next boot on, ANY global row alarms (§3.3, log + audit only) and is never read.
 *   2. A value that is already an `h1.` MAC needs nothing (a crash between steps 3 and 4
 *      re-runs to here and stops) — the keyed form verifies without any era marker.
 *   3. A family this boot ROTATES (`mcp_llm_cloud_token_hash`, the path-scoped loopback
 *      families) is NOT converted — converting a stored value would launder whatever wrote it.
 *      The ROTATION itself runs HERE, before the era marker (`BOOT_ROTATORS`), so the value that
 *      is in the store when the marker appears is already `h1.`; `boot/mcp-mounts.js` rotates the
 *      same families again a moment later (h1 -> h1), which changes nothing.
 *   4. A FILE-BACKED family (`board-token`, `phone-token`, `artifacts-token`, `models-token`,
 *      `secrets/peer-relay-token`, `kiosk-announce-token`) is converted only after
 *      `sha256(file) === stored` proves the value IS that file's token — and the FILE itself is
 *      trusted only when it is a regular file, owned by this process's uid, not
 *      group/world-writable, in a parent directory that is likewise ours and not
 *      group/world-writable. It is OPENED with `O_NOFOLLOW` and judged from its own fd, and the
 *      token is read from that same fd (`readTrustedProofFile`), so a symlink is never proof and
 *      there is no check-then-read gap to race. A value no trustworthy file backs — a
 *      missing file, a symlink, a foreign or group-writable file, a mismatch — is REFUSED,
 *      alarmed, and CLEARED, so this boot's own `ensure*` (boot/mcp-mounts.js, which mints only
 *      when the store holds nothing) re-mints a fresh token AND file; consumers read that file
 *      per spawn / per turn, so nothing needs a restart.
 *   5. The local MCP token has no raw copy anywhere (its only record is the stored verifier),
 *      so it converts from the stored sha256 itself, which is the MAC's input (design D1) — from
 *      the override only, per 1b.
 *   6. A CRASH RE-RUN is confined to the values a snapshot lists: a family with a snapshot but
 *      no `converted_at` converts ONLY those, and alarms anything else. That holds for an EMPTY
 *      snapshot too (`rows: []` — the family held nothing when it was taken): it still refuses
 *      and alarms anything written since, instead of converting that value fresh. Without that
 *      rule, a value a bot planted between the crash and the restart would be laundered into a
 *      credential the bot knows the raw token for.
 *   7. `markConverted` last: converted_at in the secrets-side state file plus the
 *      `token_hmac_era:<family>` DB mirror. Writing the era BEFORE the rewrite would lock every
 *      credential out on a crash mid-family; this order only ever re-runs.
 *
 * NOTHING IS REWRITTEN WHEN THE SNAPSHOT CANNOT BE WRITTEN (§2.6 last row): that family is
 * skipped, logged, and NO era is recorded, so its legacy value stays accepted (and unprotected)
 * instead of everyone being locked out. ANY OTHER FAILURE REFUSES LEGACY for that family in
 * this process (`forceRefuseSettingsLegacy`) and writes no era, so the next boot resumes.
 *
 * THE KEY IS NEVER REPLACED HERE. A lost or invalid key logs one loud line naming the file and
 * the recovery command, and the boot CARRIES ON: the gateway still starts, while every one of
 * these validators refuses through `token-mac`'s own key-lost refusal.
 *
 * NO NEW USER-VISIBLE TEXT: this file writes console lines and audit rows only, exactly as
 * `servers/shared/token-mac.js` already does.
 */
import {
  closeSync, fsyncSync, lstatSync, openSync, readFileSync, readdirSync, renameSync, unlinkSync, writeSync,
} from "node:fs";
import { createHash } from "node:crypto";
import { dirname, join } from "node:path";
import { readHardenedTokenFile } from "../token-file-read.js";
import {
  TokenMacKeyError, ensureKey, legacyAlarm, macFromLegacy, markConverted, noteEraEvidence, tokenMacKeyPath,
} from "../../shared/token-mac.js";
import {
  MAIL_HOOK_TOKEN, MEMORY_BOT_TOKEN, PROJECTS_BOT_TOKEN, REPORTS_TOKEN, SATELLITE_TOOLS_TOKEN, SECRETS_TOKEN, SERVICES_TOKEN, SHARING_BOT_TOKEN, rotateLlmCloudToken,
} from "../local-token.js";
import { ensureSecretsDir } from "../../shared/peer-credentials.js";
import { writeSetting } from "../dashboard/settings/registry.js";
import { auditLog } from "../../db.js";
import {
  ROTATED_AT_BOOT, SETTINGS_TOKEN_FAMILIES, deleteStoredForm, forceRefuseSettingsLegacy, h1ValuesExist,
  isLegacyStored, settingsFamilyConverted, settingsTokenRawFile, storedForms, writeStoredForm,
} from "../token-settings.js";

/**
 * Snapshot file prefix inside `secrets/`. DELIBERATELY NOT `token-hmac-rollback-`, which is the
 * `oauth_tokens` converter's prefix: that converter's operator rollback (`scripts/token-hmac.mjs
 * --rollback`) refuses any snapshot naming a family it does not restore, so a settings snapshot
 * under its prefix would block every rollback. The two eras roll back separately.
 */
export const SETTINGS_ROLLBACK_PREFIX = "settings-token-hmac-rollback-";
const SNAPSHOT_VERSION = 1;

/**
 * How this boot MINTS each `ROTATED_AT_BOOT` family (§3.2), one entry per family.
 *
 * The converter calls these itself, BEFORE it marks the family converted (see
 * `rotateAtBootFamily`). `boot/mcp-mounts.js` rotates the same six families again a moment later;
 * a second rotation of a keyed family is a no-op in form (h1 -> h1), so the duplication is
 * harmless and neither module has to know the other ran. The keys MUST be exactly
 * `ROTATED_AT_BOOT` — `tests/token-mac-settings.test.js` pins that, so a family added to one list
 * and not the other cannot be silently marked converted while it still holds an old-style value.
 */
export const BOOT_ROTATORS = Object.freeze({
  mcp_llm_cloud_token_hash: (db) => rotateLlmCloudToken(db),
  mcp_services_token_hash: (db) => SERVICES_TOKEN.rotate(db),
  mcp_satellite_tools_token_hash: (db) => SATELLITE_TOOLS_TOKEN.rotate(db),
  mcp_secrets_token_hash: (db) => SECRETS_TOKEN.rotate(db),
  mcp_sharing_bot_token_hash: (db) => SHARING_BOT_TOKEN.rotate(db),
  mcp_reports_token_hash: (db) => REPORTS_TOKEN.rotate(db),
  mcp_memory_bot_token_hash: (db) => MEMORY_BOT_TOKEN.rotate(db),
  mcp_projects_bot_token_hash: (db) => PROJECTS_BOT_TOKEN.rotate(db),
  mcp_mail_hook_token_hash: (db) => MAIL_HOOK_TOKEN.rotate(db),
});

function secretsDir() {
  return dirname(tokenMacKeyPath());
}

/** This process's uid, or null on a platform that has none. */
function ourUid() {
  return typeof process.getuid === "function" ? process.getuid() : null;
}

/**
 * Read the token file `path` AS a proof file this instance can TRUST — one open, one fd, no
 * window between "is it trustworthy?" and "what does it say?". (Token-settings hardening; the
 * same owner/mode rule `token-mac` applies to the key file, plus the parent directory.)
 *
 * A file-backed family converts a stored legacy value only when `sha256(file)` equals it — but
 * that proves nothing if the file is something a bot shell can plant or rewrite, nor if the path
 * is swapped between the check and the read. So:
 *   - the OPEN is `readHardenedTokenFile` (`servers/gateway/token-file-read.js`):
 *     `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`, never `lstat`ed and then re-read. A SYMLINK (ELOOP) or
 *     a FIFO with no writer (ENXIO) fails the open instead of being followed or BLOCKED ON (a
 *     planted FIFO used to park this boot before it could listen), a non-regular fd is refused
 *     before any read, and the token is read from the same fd, capped at 4 KiB;
 *   - the fd itself is what is judged (`fstat`): a regular file owned by this process's uid,
 *     which is not group- or world-writable (mode & 0o022 === 0);
 *   - the token is read FROM THAT FD, so the bytes judged are the bytes used;
 *   - the parent directory is likewise ours and not group/world-writable (lstat, never stat: a
 *     symlinked directory is not the directory this instance owns).
 * A refusal here never touches the file: the value is cleared and re-minted instead.
 *
 * @param {string} path the family's raw token file
 * @returns {{ok: true, token: string} | {ok: false}} `token` is the file's trimmed contents
 */
function readTrustedProofFile(path) {
  const uid = ourUid();
  const read = readHardenedTokenFile(path);
  if (!read.ok) return { ok: false };
  const file = read.stat;
  if ((file.mode & 0o022) !== 0) return { ok: false };
  if (uid !== null && file.uid !== uid) return { ok: false };
  let parent;
  try {
    parent = lstatSync(dirname(path));
  } catch {
    return { ok: false };
  }
  if (!parent.isDirectory()) return { ok: false };
  if ((parent.mode & 0o022) !== 0) return { ok: false };
  if (uid !== null && parent.uid !== uid) return { ok: false };
  return { ok: true, token: read.token };
}

/**
 * Is `path` a proof file this instance can TRUST? The boolean form of `readTrustedProofFile`,
 * exported for the operator dry run (`scripts/ops/settings-token-hmac-dryrun.mjs`), which asks the
 * question of the SOURCE home's real files so its verdict covers them too. Read-only: it opens,
 * judges and closes; it never writes, creates or replaces anything.
 *
 * @param {string} path the family's raw token file
 * @returns {boolean}
 */
export function trustedProofFile(path) {
  return readTrustedProofFile(path).ok;
}

/** `2026-11-23T16:41:02.123Z` → a file-name-safe stamp. */
function stamp(at = new Date()) {
  return at.toISOString().replace(/[:.]/g, "-");
}

/** Write the snapshot atomically and owner-only (temp 0600 + fsync + rename + fsync dir). */
function writeSnapshot(name, body) {
  const dir = secretsDir();
  ensureSecretsDir(dir);
  const final = join(dir, name);
  const tmp = `${final}.tmp-${process.pid}-${Math.random().toString(16).slice(2)}`;
  const fd = openSync(tmp, "wx", 0o600);
  try {
    writeSync(fd, JSON.stringify(body, null, 2) + "\n");
    fsyncSync(fd);
  } finally {
    closeSync(fd);
  }
  try {
    renameSync(tmp, final);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* already gone */ }
    throw err;
  }
  try {
    const dfd = openSync(dir, "r");
    fsyncSync(dfd);
    closeSync(dfd);
  } catch { /* best effort */ }
  return final;
}

/**
 * The newest settings snapshot for a family that has no `converted_at` yet — a conversion a
 * crash interrupted — or null. Only its own prefix is scanned, so the `oauth_tokens` era's
 * files are never read as ours (and vice versa). A snapshot written under another key is
 * ignored: its values belong to a key this box no longer holds.
 *
 * AN EMPTY SNAPSHOT IS STILL A PENDING ONE (design §3.2 / §3.3). `rows: []` means the snapshot
 * was taken when this family held no old-style value — the conversion committed (nothing) and
 * the process died before `markConverted`. Skipping such a file would let this boot convert
 * FRESH, laundering a value something wrote after the crash into a credential its writer knows
 * the token of. Any snapshot naming this family and this key therefore counts as pending: the
 * rerun converts only its (zero) rows, refuses-and-alarms every other old-style value, and
 * marks the family.
 */
function pendingSnapshot(family, keyId) {
  const dir = secretsDir();
  let names;
  try {
    names = readdirSync(dir);
  } catch {
    return null;
  }
  let best = null;
  for (const name of names) {
    if (!name.startsWith(SETTINGS_ROLLBACK_PREFIX) || !name.endsWith(".json")) continue;
    let body;
    let mtimeMs;
    try {
      mtimeMs = lstatSync(join(dir, name)).mtimeMs;
      body = JSON.parse(readFileSync(join(dir, name), "utf8"));
    } catch {
      continue;
    }
    if (!body || body.v !== SNAPSHOT_VERSION || body.family !== family || !Array.isArray(body.rows)) continue;
    if (keyId && body.key_id !== keyId) continue;
    const rows = body.rows
      .map((r) => ({
        store: r?.store === "global" ? "global" : "local",
        value: typeof r?.token === "string" ? r.token.toLowerCase() : "",
      }))
      .filter((r) => isLegacyStored(r.value));
    if (!best || mtimeMs > best.mtimeMs) best = { name, rows, mtimeMs };
  }
  return best;
}

/**
 * The alarm scan of §3.3, plus the OQ-8 rule: in a CONVERTED family nobody converts anything, a
 * legacy OVERRIDE is refused and alarmed, and ANY global row is alarmed too — it is never read
 * (`readStoredSettingsToken`), because a global row for a per-instance token key is the second
 * write target a bot has, whatever form it holds. The global row is left in place: the alarm
 * names the row, and a scan does not delete what a bot wrote.
 */
async function scanConvertedFamily(db, family, { audit }) {
  let alarms = 0;
  let refusedGlobal = 0;
  for (const form of await storedForms(db, family)) {
    if (form.store === "global") {
      legacyAlarm(family, `${family}@global`, { audit });
      alarms += 1;
      refusedGlobal += 1;
      continue;
    }
    if (!isLegacyStored(form.value)) continue;
    legacyAlarm(family, `${family}@${form.store}`, { audit });
    alarms += 1;
  }
  return { family, state: "converted", scan: true, alarms, refusedGlobal, refused: refusedGlobal };
}

/**
 * Mint one `ROTATED_AT_BOOT` family and mark its era, IN THAT ORDER (§3.2).
 *
 * Why the rotation belongs here and not only in `boot/mcp-mounts.js`: marking the era first leaves
 * a window in which the family is "converted" while the store still holds the previous
 * release's bare sha256, so any boot that ENDS inside that window (a crash, a rotation that
 * failed, an operator rehearsal's second pass) reports those six legitimate values as "something
 * without the key wrote this row" — six false alarms on the first upgraded boot of every
 * instance. With the minting done here there is no such window: the era appears only over an
 * `h1.` value or over no value at all.
 *
 * A family is marked only when nothing old-style is left. The rotation's own failure paths decide
 * what the store holds: the loopback families fail CLOSED (the stored value is deleted), while
 * the cloud door RESTORES the previous value — which on a never-rotated box is the old-style
 * form. That case is thrown to the per-family failure path instead: no era is recorded, this
 * process refuses the family's old-style values (§M2), and the next boot tries again. It is
 * deliberately NOT alarmed: the value is this box's own previous token restored by its own
 * rotation, not a write from something without the key.
 */
async function rotateAtBootFamily(db, family, { rotate, markConvertedHere, refusedGlobal = 0, globalAlarms = 0 }) {
  const run = typeof rotate === "function" ? rotate : BOOT_ROTATORS[family];
  if (typeof run !== "function") {
    throw new TypeError(`no boot rotation is wired for ${family}: add it to BOOT_ROTATORS`);
  }
  let failure = null;
  try {
    await run(db, family);
  } catch (err) {
    failure = err?.message || String(err);
  }
  const stillOldStyle = (await storedForms(db, family)).filter((f) => isLegacyStored(f.value));
  if (stillOldStyle.length) {
    throw new Error(failure
      ? `the boot rotation failed (${failure}) and the stored value is still old-style`
      : "the boot rotation left an old-style value behind");
  }
  return {
    family,
    state: "converted",
    rotated: true,
    refused: refusedGlobal,
    refusedGlobal,
    refusedProofFile: 0,
    alarms: globalAlarms,
    ...(await markConvertedHere({ count: 0 })),
  };
}

/**
 * Convert one family (fresh, or resumed from a pending snapshot).
 *
 * `snapshot`, `rotate` and `audit` are seams for the failure paths; production passes none.
 *
 * @returns {Promise<{family: string, state: string, count?: number, refused?: number,
 *          refusedProofFile?: number, refusedGlobal?: number, alarms?: number,
 *          rollbackFile?: string, reason?: string, changed?: boolean}>}
 *          `refused` is the total of stored values this boot would not convert;
 *          `refusedProofFile` (no trustworthy token file proves it) and `refusedGlobal` (it sat in
 *          the global settings row, which no reader consults) are its two reasons.
 */
async function convertFamily(db, family, {
  key, audit, now, rotate, writeSnapshot: writeSnapshotFor,
}) {
  const snapshot = typeof writeSnapshotFor === "function" ? writeSnapshotFor : writeSnapshot;
  const markConvertedHere = async (extra) => {
    const mark = await markConverted(family, {
      count: extra.count ?? 0,
      rollbackFile: extra.rollbackFile ?? null,
      at: (now || new Date()).toISOString(),
      writeSetting: (k, v, o) => writeSetting(db, k, v, o),
    });
    return { ...extra, changed: mark.changed };
  };

  // ─── 1b. The GLOBAL row is never a second answer (design OQ-8, decided) ──────────────
  // Every reader of these keys is override-only, and the product only ever writes them
  // local-scope, so a global row is the second write target a contained bot has (delete the
  // override, insert a global row). On this ONE boot it is either MOVED into this instance's
  // override — the only value the box has, so no working token is lost — or, when an override
  // exists too, ANOMALOUS: not converted, deleted by value (CAS), alarmed and refused.
  let refusedGlobal = 0;
  let globalAlarms = 0;
  {
    const forms = await storedForms(db, family);
    const localForm = forms.find((f) => f.store === "local") || null;
    const globalForm = forms.find((f) => f.store === "global") || null;
    if (globalForm && localForm) {
      await deleteStoredForm(db, family, globalForm);
      legacyAlarm(family, `${family}@global`, { audit });
      refusedGlobal += 1;
      globalAlarms += 1;
    } else if (globalForm && ROTATED_AT_BOOT.includes(family)) {
      // Rotated by this boot anyway (see `rotateAtBootFamily`): the fresh keyed value is minted
      // into the override a moment later, so this row is retired rather than converted or
      // accused — it cannot launder anything the rotation is about to replace.
      await deleteStoredForm(db, family, globalForm);
    } else if (globalForm) {
      // THE MOVE. Written before the global row is removed, so a crash in between can only leave
      // the value in both stores (the next boot then treats the global one as anomalous), never
      // lose the only value the box has.
      await writeStoredForm(db, family, { store: "local", value: globalForm.value });
      await deleteStoredForm(db, family, globalForm);
    }
  }

  const forms = await storedForms(db, family);
  const legacy = forms.filter((f) => isLegacyStored(f.value));

  // Nothing old-style left: an interrupted conversion already rewrote (or rotated away) every
  // value, so this boot only has to record the era.
  if (legacy.length === 0) {
    return {
      family,
      state: "converted",
      refused: refusedGlobal,
      refusedGlobal,
      refusedProofFile: 0,
      alarms: globalAlarms,
      ...(await markConvertedHere({ count: 0 })),
    };
  }

  // Rotated at boot: this boot mints the `h1.` form from a FRESH random token (nothing to
  // convert, and converting would launder whatever wrote the stored value) — and it does so
  // BEFORE the era marker, so no boot can ever find this family converted over an old-style
  // value (see `rotateAtBootFamily`).
  if (ROTATED_AT_BOOT.includes(family)) {
    return rotateAtBootFamily(db, family, { rotate, markConvertedHere, refusedGlobal, globalAlarms });
  }

  const pending = pendingSnapshot(family, key.id);
  const inSnapshot = pending
    ? new Set(pending.rows.map((r) => `${r.store}:${r.value}`))
    : null;

  // Which values may be converted? A crashed family: only what its snapshot lists. A fresh
  // one: the override's legacy value, and — for a file-backed family — only once a TRUSTWORTHY
  // token file proves it (`readTrustedProofFile`: a regular file of ours, in a directory of ours,
  // neither group/world-writable, opened O_NOFOLLOW and read from the fd that was judged; a
  // symlink is never proof).
  const rawFile = settingsTokenRawFile(family);
  // ONE open: the fd that was judged trustworthy is the fd the token is read from, so a path
  // swapped after the check cannot supply the value (`readTrustedProofFile`).
  const fileToken = rawFile ? readTrustedProofFile(rawFile) : { ok: false };
  const fileHash = fileToken.ok ? createHash("sha256").update(fileToken.token).digest("hex") : null;
  const rewrites = [];
  const cleared = [];
  let refused = refusedGlobal;
  let refusedProofFile = 0;
  let refusedSnapshot = 0;
  for (const form of legacy) {
    if (inSnapshot && !inSnapshot.has(`${form.store}:${form.value}`)) { refused += 1; refusedSnapshot += 1; continue; }
    if (rawFile && fileHash !== form.value.toLowerCase()) {
      refused += 1;
      refusedProofFile += 1;
      cleared.push(form);
      continue;
    }
    rewrites.push({ ...form, to: macFromLegacy(family, form.value) });
  }

  let rollbackFile = pending ? pending.name : null;
  if (rewrites.length && !pending) {
    rollbackFile = `${SETTINGS_ROLLBACK_PREFIX}${stamp(now)}-${family.replace(/[^a-z0-9]+/gi, "-")}.json`;
    try {
      snapshot(rollbackFile, {
        v: SNAPSHOT_VERSION,
        family,
        key_id: key.id,
        created_at: (now || new Date()).toISOString(),
        // The PRE-conversion values, in the store each one came from: hashes, never a token.
        // (A value moved out of the global row is listed in the override it now lives in.)
        rows: rewrites.map((r) => ({ store: r.store, key: family, token: r.value })),
      });
    } catch (err) {
      return {
        family,
        state: "skipped",
        reason: `secrets/ is not writable (${err.code || err.message})`,
        refused: refusedGlobal,
        refusedGlobal,
      };
    }
  }

  // A refused file-backed value is left to be RE-MINTED: `ensure*` mints only when the override
  // holds nothing, so it is cleared here and the pre-listen boot's own `ensure*` call writes a
  // fresh token + file a moment later (consumers read that file per spawn / per turn, so no
  // restart is needed). Cleared BEFORE the era is marked: nothing old-style survives the boot.
  for (const form of cleared) {
    // eslint-disable-next-line no-await-in-loop -- at most one override row per family
    await deleteStoredForm(db, family, form);
  }

  // Rewrite FIRST, mark second (see the header): a crash in between leaves keyed values behind,
  // which verify on their own, and the next boot only records the era.
  let count = 0;
  for (const r of rewrites) {
    // eslint-disable-next-line no-await-in-loop -- at most two stores per family
    await writeStoredForm(db, family, { store: r.store, value: r.to, instanceId: r.instanceId });
    count += 1;
  }
  // A value we could not convert is a value nothing with the key wrote: alarm it, and the era
  // marked below is what refuses it from now on. (A global row was already alarmed above.)
  let alarms = globalAlarms;
  if (refusedProofFile || refusedSnapshot) {
    legacyAlarm(family, `${family}@legacy`, { audit });
    alarms += 1;
  }
  return {
    family,
    state: "converted",
    count,
    refused,
    refusedProofFile,
    refusedGlobal,
    alarms,
    ...(await markConvertedHere({ count, rollbackFile })),
  };
}

/**
 * Run the boot: evidence → key → per-family convert or scan.
 *
 * Each family is independent: its own try/catch, and — if it still fails — a process-local
 * refusal of its legacy values. One broken family never skips its siblings and never fails
 * open.
 *
 * @param {{ db: object, now?: Date, audit?: Function,
 *           writeSnapshot?: (name: string, body: object) => string,
 *           rotateAtBoot?: (db: object, family: string) => Promise<unknown> }} opts
 *        `db` is the gateway's crow.db client; `audit` defaults to `auditLog` on that client.
 *        `writeSnapshot` and `rotateAtBoot` are TEST seams (the §2.6 skip and the §3.2 rotation);
 *        production passes neither, so the real minting functions in `BOOT_ROTATORS` run.
 * @returns {Promise<{key: "ok"|"lost"|"invalid", keyPath: string, families: object[],
 *          converted: number, refused: number, refusedProofFile: number, refusedGlobal: number,
 *          alarms: number}>}
 *          Never throws for a key problem: the gateway must still start. `refusedProofFile` and
 *          `refusedGlobal` are the two reasons a stored value is not converted (both are also
 *          included in `refused`): no trustworthy token file proves it, or it sat in the global
 *          settings row a per-instance token key is never read from.
 */
export async function runSettingsTokenHmacBoot({
  db, now = new Date(), audit, writeSnapshot: writeSnapshotSeam, rotateAtBoot,
} = {}) {
  if (!db) throw new TypeError("runSettingsTokenHmacBoot needs a crow.db client");
  const auditFn = typeof audit === "function" ? audit : (eventType, details) => auditLog(db, eventType, { details });
  const keyPath = tokenMacKeyPath();

  // The evidence flags are REQUIRED by ensureKey({allowCreate:true}) — an explicit scan.
  let mirrorConverted = false;
  for (const family of SETTINGS_TOKEN_FAMILIES) {
    // eslint-disable-next-line no-await-in-loop -- thirteen families, once at boot
    if (await settingsFamilyConverted(family, db)) {
      mirrorConverted = true;
      break;
    }
  }
  let h1 = false;
  try {
    h1 = await h1ValuesExist(db);
  } catch {
    h1 = true; // cannot tell → never "this box is new"
  }
  noteEraEvidence({ mirrorConverted, h1ValuesExist: h1 });

  let key;
  try {
    key = ensureKey({ allowCreate: true, mirrorConverted, h1ValuesExist: h1 });
  } catch (err) {
    if (err instanceof TokenMacKeyError) {
      console.error(
        `[token-hmac] the settings-token key is ${err.state === "lost" ? "lost" : "unusable"}: ${keyPath}. `
        + "Every static token (local MCP, board, phone, artifacts, models, peer relay, kiosk announce, "
        + "cloud door and the loopback family tokens) is being refused; the gateway is still running. "
        + "Recreate it deliberately with `node scripts/token-hmac.mjs --reset` (operator shell).",
      );
      return {
        key: err.state === "lost" ? "lost" : "invalid",
        keyPath,
        families: [],
        converted: 0,
        refused: 0,
        refusedProofFile: 0,
        refusedGlobal: 0,
        alarms: 0,
      };
    }
    throw err;
  }

  const families = [];
  let converted = 0;
  let refused = 0;
  let refusedProofFile = 0;
  let refusedGlobal = 0;
  let alarms = 0;
  for (const family of SETTINGS_TOKEN_FAMILIES) {
    let result;
    try {
      // eslint-disable-next-line no-await-in-loop -- one family at a time, by design
      const isConverted = await settingsFamilyConverted(family, db);
      // eslint-disable-next-line no-await-in-loop
      result = isConverted
        ? await scanConvertedFamily(db, family, { audit: auditFn })
        : await convertFamily(db, family, {
          key, audit: auditFn, now, rotate: rotateAtBoot, writeSnapshot: writeSnapshotSeam,
        });
    } catch (err) {
      forceRefuseSettingsLegacy(family);
      console.error(
        `[token-hmac] the ${family} conversion failed (${err?.message || err}); old-style values for that `
        + "family are REFUSED for the rest of this process and nothing was recorded, so the next boot "
        + "resumes the conversion.",
      );
      families.push({ family, state: "failed", reason: String(err?.message || err) });
      continue;
    }
    if (result.state === "converted" && result.count) {
      console.log(
        `[token-hmac] converted ${family}: ${result.count} stored value(s), snapshot secrets/${result.rollbackFile}`,
      );
    } else if (result.state === "skipped") {
      console.warn(
        `[token-hmac] skipped the ${family} conversion: ${result.reason}; its old-style value stays `
        + "accepted (unprotected) until this is fixed.",
      );
    }
    if (result.refused) {
      const why = [
        result.refusedProofFile ? `${result.refusedProofFile} with no trustworthy token file behind them` : null,
        result.refusedGlobal ? `${result.refusedGlobal} in the global settings row (never read)` : null,
      ].filter(Boolean).join(", ");
      console.warn(
        `[token-hmac] ${family}: ${result.refused} stored value(s) were NOT converted`
        + `${why ? ` (${why})` : " (written after the snapshot)"}`
        + " and they are refused and reported, not laundered; a file-backed family whose token file did "
        + "not prove its value is re-minted by its own ensure* helper on this boot.",
      );
    }
    if (result.alarms) {
      console.warn(`[token-hmac] ${family}: ${result.alarms} old-style value(s) found after conversion — they were refused, not converted.`);
    }
    converted += result.count || 0;
    refused += result.refused || 0;
    refusedProofFile += result.refusedProofFile || 0;
    refusedGlobal += result.refusedGlobal || 0;
    alarms += result.alarms || 0;
    families.push(result);
  }

  return {
    key: "ok", keyPath, families, converted, refused, refusedProofFile, refusedGlobal, alarms,
  };
}