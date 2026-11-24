/**
 * "A dashboard password has been set" — recorded where crow.db cannot reach.
 *
 * auth.js answers "is the dashboard set up?" from the `password_hash` row in
 * dashboard_settings. Anything that can write crow.db — a contained bot has it
 * read-write — can DELETE that row, and a crow.db that says "no password" makes
 * the login page offer first-run setup: on a single-user box a direct-loopback
 * request is then allowed to set a new password WITHOUT the setup token
 * (allowFirstRun, setup-token.js), so deleting the row would hand the dashboard
 * over. The row is therefore not the only evidence: this file is.
 *
 * <CROW_HOME>/secrets/dashboard-password-set — the secrets directory the pi
 * sandbox never binds: `contain` binds none of the secrets dirs, and the
 * lighter bwrap tiers mask it (hideDirs, scripts/pi-bots/bridge.mjs). Contents
 * are an ISO timestamp and nothing else, so the file itself is not a secret;
 * what it proves is that something outside the bot's reach once set a password.
 *
 * The marker is written and never removed: an install whose password record is
 * deleted stays "a password was set" (the login form, a failed login, and the
 * owner's `npm run reset-password` recovery) instead of reopening setup.
 * A marker present and no row is LOCKED, never a first run.
 *
 * Node built-ins only.
 */
import { chmodSync, lstatSync, renameSync, unlinkSync, writeFileSync } from "node:fs";
import { randomBytes } from "node:crypto";
import { join } from "node:path";
import { resolveCrowHome } from "../../shared/crow-home.js";
import { ensureSecretsDir } from "../../shared/peer-credentials.js";

export const PASSWORD_SET_MARKER_FILENAME = "dashboard-password-set";

/** <CROW_HOME>/secrets/dashboard-password-set for the given (or this process's) home. */
export function passwordSetMarkerPath(crowHome = resolveCrowHome()) {
  return join(crowHome, "secrets", PASSWORD_SET_MARKER_FILENAME);
}

/**
 * Record that a dashboard password is set. Atomic (temp + rename), mode 0600,
 * inside a 0700 secrets dir (the same ensureSecretsDir the local tokens use).
 * Never throws: a marker that cannot be written is a degraded state, not a
 * boot failure, and the file holds no secret whose loss would matter.
 *
 * @param {{ crowHome?: string, log?: Function, now?: () => Date }} [opts]
 * @returns {boolean} true when the marker is on disk after the call.
 */
export function writePasswordSetMarker({ crowHome = resolveCrowHome(), log = console.warn, now = () => new Date() } = {}) {
  const path = passwordSetMarkerPath(crowHome);
  const tmp = `${path}.tmp-${process.pid}-${randomBytes(4).toString("hex")}`;
  try {
    ensureSecretsDir(join(crowHome, "secrets"));
    // "wx": never reuse a temp file (a pre-existing path fails instead of being
    // written through — this name is unique, but fail closed if it is not).
    writeFileSync(tmp, `${now().toISOString()}\n`, { flag: "wx", mode: 0o600 });
    // writeFileSync's mode is filtered by the umask; pin it.
    chmodSync(tmp, 0o600);
    renameSync(tmp, path);
    return true;
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* nothing to clean up */ }
    try { log(`[auth] could not record that a dashboard password is set (${path}): ${err.message}`); } catch { /* a broken logger is not fatal here */ }
    return false;
  }
}

/**
 * True when a dashboard password was ever set on this instance.
 *
 * Existence is the fact, whatever the shape: a symlink, a directory or a
 * socket at the path counts as PRESENT. Anything else that stops us from
 * telling (EACCES, EIO, ENOTDIR on a parent) also counts as present — fail
 * closed (locked, not "<no password>"), because "unknown" must never re-open
 * the first-run setup. Only a clean ENOENT is "no marker".
 *
 * @param {{ crowHome?: string }} [opts]
 * @returns {boolean}
 */
export function hasPasswordSetMarker({ crowHome = resolveCrowHome() } = {}) {
  try {
    lstatSync(passwordSetMarkerPath(crowHome));
    return true;
  } catch (err) {
    if (err && err.code === "ENOENT") return false;
    return true;
  }
}

/**
 * Gateway boot catch-up for installs that set a password before the marker
 * existed: when the `password_hash` ROW is there and the marker is not, write
 * the marker. A marker that is already there is left untouched (no rewrite, so
 * nothing churns on every boot).
 *
 * The row is read directly (auth.js hasPasswordRow), never through
 * isPasswordSet(), which now answers "yes" from the marker alone and so could
 * not tell the two apart. A row we cannot read writes nothing: on a genuinely
 * fresh install a marker written by mistake would lock first-run setup for
 * good, and the next boot simply tries again.
 *
 * RESIDUAL, accepted: this heals only a row that is still there at the first
 * boot of a version that has the marker. An install whose password row was
 * deleted BEFORE that first boot has nothing to learn from — no row, no marker
 * — so it is indistinguishable from a real first run and still offers setup.
 * Every install is caught up on its first boot of this version, so after the
 * deploy the operator can confirm one file per host:
 *   <CROW_HOME>/secrets/dashboard-password-set
 * If it is missing on a host that has a password, that host kept the pre-marker
 * behaviour (setup still offered if the row is later deleted); `npm run
 * reset-password` writes the marker.
 *
 * @param {{ crowHome?: string, hasPasswordRow?: () => (boolean|Promise<boolean>), log?: Function }} [opts]
 * @returns {Promise<string|null>} the logged line, or null when nothing was written.
 */
export async function bootPasswordSetMarker({ crowHome = resolveCrowHome(), hasPasswordRow, log = console.log } = {}) {
  let rowExists = false;
  try {
    rowExists = hasPasswordRow
      ? !!(await hasPasswordRow())
      : !!(await (await import("./auth.js")).hasPasswordRow());
  } catch {
    return null;
  }
  if (!rowExists) return null;
  if (hasPasswordSetMarker({ crowHome })) return null;
  if (!writePasswordSetMarker({ crowHome })) return null;
  const line = "[auth] recorded that a dashboard password is set";
  try { log(line); } catch { /* logging is best effort */ }
  return line;
}