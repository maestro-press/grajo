/**
 * The dashboard's step-up gate: one instance per process.
 *
 * Fresh re-authentication is the keychain's rule (`../keychain/reauth.js`): a grant per dashboard
 * session, five wrong tries locking that session for fifteen minutes, and an instance-wide ceiling
 * of twenty failures an hour. This module carries the dashboard's own dependencies for that gate,
 * so every caller that needs the owner to prove it is them right now asks the same object:
 *
 * - with dashboard 2FA on, only a code counts — never the password;
 * - a code that was already accepted is never accepted a second time, on any session, because the
 *   matched time step is remembered here and a step at or below it is refused (a replayed code
 *   from a request log, or the same code typed into a second form, cannot grant two accesses);
 *   the sign-in form's own 2FA check reads the same number through `verifyLoginTotp`, so one code
 *   cannot sign in and then step up a write;
 * - without 2FA the dashboard password is the method, as it always was.
 *
 * A gateway restart forgets the grants and the remembered step, which only means "ask again".
 */
import { createDbClient } from "../../db.js";
import { createReauthGate } from "../keychain/reauth.js";
import { verifyPassword } from "./auth.js";
import { getTotpSecret, is2faEnabled, verifyTotpStep } from "./totp.js";

/** The dashboard's password hash, or null when no password is set. */
async function readPasswordHash() {
  const db = createDbClient();
  try {
    const result = await db.execute("SELECT value FROM dashboard_settings WHERE key = 'password_hash'");
    return result.rows[0]?.value || null;
  } finally {
    db.close();
  }
}

async function dashboardPasswordMatches(password) {
  if (typeof password !== "string" || password === "") return false;
  let stored = null;
  try {
    stored = await readPasswordHash();
  } catch {
    return false;
  }
  if (!stored) return false;
  try {
    return (await verifyPassword(password, stored)) === true;
  } catch {
    return false;
  }
}

/**
 * One step-up gate.
 *
 * `overrides` replaces any dependency the underlying re-auth gate takes (`now`, `maxFailures`,
 * `globalMaxFailures`, `ttlMs`, `lockMs`, `globalWindowMs`, `is2faEnabled`, `hasDashboardPassword`,
 * `verifyDashboardPassword`), and the two this module adds: `getTotpSecret` and `verifyTotpStep`.
 * The replay guard itself is never replaced: a caller can choose how a code is read, not whether
 * an already-used one counts again.  The gate also carries `acceptLoginCode(code, secret)` for the
 * sign-in form, which shares that one remembered step but grants nothing.
 */
export function createStepUpGate(overrides = {}) {
  const given = overrides && typeof overrides === "object" ? overrides : {};
  const readSecret = typeof given.getTotpSecret === "function" ? given.getTotpSecret : getTotpSecret;
  const matchStep = typeof given.verifyTotpStep === "function" ? given.verifyTotpStep : verifyTotpStep;

  // The last time step this gate accepted, whatever session it came from. One number, in memory.
  let lastAcceptedStep = null;

  const verifyTotpCode = async (code) => {
    let step;
    try {
      step = await matchStep(code, await readSecret());
    } catch {
      return false;
    }
    if (!Number.isInteger(step)) return false;
    if (lastAcceptedStep !== null && step <= lastAcceptedStep) return false;
    lastAcceptedStep = step;
    return true;
  };

  /**
   * A code the sign-in form read, judged against the SAME remembered step this gate uses.
   *
   * The time step is the guard, not the code: a step this process already accepted — by the gate
   * or by the login form — is refused, so one code cannot open a session and then step up a
   * write. A code matching no step records nothing. Answers a boolean, and never a step.
   */
  const acceptLoginCode = async (code, secret) => {
    const text = typeof code === "string" ? code.trim() : "";
    if (text === "") return false;
    if (typeof secret !== "string" || secret.trim() === "") return false;
    let step;
    try {
      step = await matchStep(text, secret);
    } catch {
      return false;
    }
    if (!Number.isInteger(step)) return false;
    if (lastAcceptedStep !== null && step <= lastAcceptedStep) return false;
    lastAcceptedStep = step;
    return true;
  };

  const gate = createReauthGate({
    now: () => Date.now(),
    is2faEnabled: async () => (await is2faEnabled()) === true,
    hasDashboardPassword: async () => Boolean(await readPasswordHash()),
    verifyDashboardPassword: (password) => dashboardPasswordMatches(password),
    ...given,
    verifyTotpCode,
  });

  return { ...gate, acceptLoginCode };
}

let shared = null;

/** The one gate this process uses: the keychain and the Trading panel's Connect flow share it. */
export function sharedStepUpGate() {
  if (!shared) shared = createStepUpGate();
  return shared;
}

/**
 * The sign-in form's 2FA check, sharing the step-up gate's one remembered time step.
 *
 * A code accepted to sign in is spent for a step-up too, and a step the gate accepted is not the
 * sign-in form's to use again: the number is the same, in the same process-wide gate.
 *
 * @param {string} code - the 6-digit code the form was given
 * @param {string} secret - the dashboard's base32 secret
 * @returns {Promise<boolean>}
 */
export async function verifyLoginTotp(code, secret) {
  return sharedStepUpGate().acceptLoginCode(code, secret);
}