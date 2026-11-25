/**
 * The one shared rule for "the era is recorded only in the database" (review finding H1), used by
 * all four boot converters (oauth_tokens, settings tokens, paired-instance bearers, report links)
 * so they cannot drift apart.
 *
 * THE PROBLEM. The DB mirror `token_hmac_era:<family>` sits in crow.db, which a contained bot can
 * write. A converter that chooses scan-vs-convert from "state file OR mirror" and whose scan branch
 * never records anything lets a mirror planted BEFORE the first boot stand in for the era: the
 * host-side state file then never learns it, the bot deletes the mirror, inserts a sha256 row (the
 * runtime now sees an unconverted family and accepts it) and the next boot converts that row into a
 * valid `h1.` credential.
 *
 * THE RULE.
 *   - the host STATE FILE says converted        -> nothing to do (the caller scans as always);
 *   - neither says converted                    -> nothing to do (a real first conversion);
 *   - ONLY the mirror says converted            -> ADOPT it: write the state-file marker
 *     (`markConverted`, count 0, no rollback file), raise the legacy alarm (audit
 *     `token_legacy_form` `{family, mirror: true}`, never a value) and log one line. The caller then
 *     SCANS, never converts: genuine legacy rows on such a box stay refused, which is the intent of
 *     §2.5 (the mirror is a one-way refusal trigger), and a bot can never downgrade the era by
 *     deleting the mirror afterwards.
 *   - the state file is corrupt/unreadable, or the mirror cannot be read -> nothing is adopted (we
 *     could not tell; the validators already fail closed on both).
 *   - a snapshot for this family under the CURRENT key is pending (a conversion a crash interrupted)
 *     -> nothing is adopted: the converter resumes from that snapshot and marks the family with its
 *     real count and rollback file.
 *
 * THE BOOT DECIDES CONVERT-vs-SCAN ONLY FROM THE HOST STATE FILE (`hostEraRecorded`), never from the
 * mirror and never from a fail-closed read error: a bot that can make the mirror unreadable (or make
 * the adoption's own write fail) must not be able to postpone the era. A box whose state file has no
 * marker takes the normal conversion path, which snapshots, converts and calls `markConverted` itself
 * (an unwritable `secrets/` is the converter's own "skipped (unprotected)" path, unchanged). The
 * VALIDATORS keep the fail-closed check (state OR mirror); only this decision is host-only.
 *
 * ACCEPTED (L-E): a mirror planted on a KEY-LESS box makes the key creation refuse (evidence of an
 * era with no key), so the key stays "lost" until the operator runs `token-hmac.mjs --reset`.
 *
 * KNOWN RESIDUALS (both need the HOST state file to have lost a marker it should hold, which a bot
 * cannot cause; both are named here because no crow.db evidence can close them):
 *   - A family that really was converted, on a box whose state file lacks its marker (`secrets/`
 *     restored from a backup older than crow.db): the DB mirror is then the only guard, a bot can
 *     delete it, and the next boot converts whatever legacy rows it planted. Restore `secrets/`
 *     together with crow.db, or run `token-hmac.mjs --reset` after a partial restore.
 *   - On the same kind of box, an old snapshot under the current key counts as pending, so the
 *     boot resumes from it instead of adopting: for `oauth_tokens` (CAS on the value) a legacy row a
 *     bot planted with a value it read before the conversion is converted and the genuine `h1.` row
 *     is dropped as a copy. The bot never learns the raw token, so it gains no credential; it
 *     controls that grant's client, scope and expiry, which it can already edit directly.
 */
import { ensureKey, eraSettingKey, eraValueIsConverted, markConverted, readState } from "../../shared/token-mac.js";
import { readSetting, writeSetting } from "../dashboard/settings/registry.js";

/** The mirror's raw value, with a store that has no settings table reading as "no mirror". */
async function readMirror(db, family) {
  try {
    return await readSetting(db, eraSettingKey(family));
  } catch (err) {
    if (/no such table/i.test(String(err?.message || ""))) return null;
    throw err;
  }
}

/**
 * True when the host state file records `family` as converted. A corrupt or unreadable state file
 * answers true too (we cannot tell, and no marker can be written to it either), which is the
 * fail-closed direction: scan, never convert.
 */
export function hostEraRecorded(family) {
  try {
    const state = readState();
    return Boolean(state.corrupt || state.families?.[family]?.converted_at);
  } catch {
    return true;
  }
}

/** The id of the key this box holds right now, or null when there is none (never creates one). */
function currentKeyId() {
  try {
    return ensureKey({ allowCreate: false }).id ?? null;
  } catch {
    return null;
  }
}

/**
 * @param {string} family
 * @param {{ db: object, audit: Function, now?: Date,
 *           hasPendingSnapshot?: (keyId: string) => boolean,
 *           mark?: Function }} opts `hasPendingSnapshot` is the converter's own pending-snapshot
 *        rule; `mark` is a TEST seam for `markConverted`.
 * @returns {Promise<boolean>} true when the era was adopted by this call
 */
export async function adoptMirrorOnlyEra(family, {
  db, audit, now = new Date(), hasPendingSnapshot, mark: markEra = markConverted,
}) {
  let state;
  try {
    state = readState();
  } catch {
    return false;
  }
  if (state.corrupt || state.families?.[family]?.converted_at) return false;
  let mirror;
  try {
    mirror = await readMirror(db, family);
  } catch {
    return false;
  }
  if (!eraValueIsConverted(mirror)) return false;
  // A pending snapshot under the current key wins: resume it instead of adopting (L-B).
  const keyId = currentKeyId();
  if (keyId && typeof hasPendingSnapshot === "function") {
    try {
      if (hasPendingSnapshot(keyId)) return false;
    } catch { /* cannot tell: fall through to adopt (fail closed) */ }
  }

  let mark;
  try {
    mark = await markEra(family, {
      count: 0,
      rollbackFile: null,
      at: now.toISOString(),
      writeSetting: (k, v, o) => writeSetting(db, k, v, o),
    });
  } catch (err) {
    // The state file could not be written: nothing is adopted, and the validators still refuse on
    // the mirror (fail closed). The next boot tries again.
    console.warn(`[token-hmac] ${family}: the era recorded in the database could not be adopted (${err?.message || err})`);
    return false;
  }
  console.warn(
    `[token-hmac] ${family}: the era was recorded only in the database; adopted (old-style rows stay refused)`,
  );
  try {
    const pending = audit("token_legacy_form", { family, mirror: true });
    if (pending && typeof pending.catch === "function") pending.catch(() => {});
  } catch { /* the audit log is best effort; the refusal already holds */ }
  return mark.changed;
}
