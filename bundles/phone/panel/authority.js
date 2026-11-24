/**
 * Phone — approval authority checks (PANEL side).
 *
 * WHY IT LIVES IN panel/ AND NOT server/ (2026, token-HMAC key move): every file
 * under a bundle's server/ tree is BOT-REACHABLE — a bot MCP child loads it —
 * while panel/ code runs only inside the gateway (panel/routes.js imports this
 * module on init). These checks read the gateway's own owner rule
 * (servers/gateway/dashboard/local-session.js -> servers/gateway/token-store.js,
 * which mints and checks a session verifier under servers/shared/token-mac.js's
 * host-only HMAC key) and the gateway's 2FA module; no bot-reachable file may
 * reach either. Nothing under server/ ever imported this module; only
 * panel/routes.js did, and it resolves it from here now.
 * tests/bundle-server-no-gateway-auth.test.js keeps it that way.
 *
 * The app root is resolved inline (not through server/app-root.js): this file is
 * loaded through the bundle's real on-disk location under CROW_APP_ROOT, so a
 * relative `../server/app-root.js` would be location-dependent.
 */
import { fileURLToPath, pathToFileURL } from "node:url";
import { existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";
import { homedir } from "node:os";

// The same three-step resolution server/app-root.js uses (CROW_APP_ROOT -> the checkout around
// this file -> the conventional ~/crow lab checkout), inlined: this module is loaded through
// the bundle's real on-disk location, so it cannot import a sibling server/ file.
function looksLikeAppRoot(p) { return !!p && existsSync(join(p, "servers", "db.js")); }
const __dirname = dirname(fileURLToPath(import.meta.url));
const __appRootGuess = resolve(__dirname, "..", "..", "..");
const __conventional = join(homedir(), "crow");
const APP_ROOT = looksLikeAppRoot(process.env.CROW_APP_ROOT) ? process.env.CROW_APP_ROOT
  : looksLikeAppRoot(__appRootGuess) ? __appRootGuess
  : looksLikeAppRoot(__conventional) ? __conventional
  : (process.env.CROW_APP_ROOT || __appRootGuess);
const appImport = (rel) => import(pathToFileURL(join(APP_ROOT, rel)).href);

/** Only the owner's own turn may approve calls: the gateway's isLocalPasswordSessionOn
 *  (servers/gateway/dashboard/local-session.js). A peer-instance SSO session
 *  ('dashboard sso'), a session minted by a login from this machine ('dashboard onhost'),
 *  a signed peer call, and any request from this machine itself are all refused.
 *  Takes the request (not the raw session) so the origin rule applies; anything else -> false. */
export async function isLocalDashboardSession(db, req) {
  if (!req || typeof req !== "object") return false;
  try {
    const { isLocalPasswordSessionOn } = await appImport("servers/gateway/dashboard/local-session.js");
    return await isLocalPasswordSessionOn(db, req);
  } catch {
    return false;
  }
}

async function defaultDeps() {
  const t = await appImport("servers/gateway/dashboard/totp.js");
  return { is2faEnabled: t.is2faEnabled, getTotpSecret: t.getTotpSecret, verifyTotp: t.verifyTotp };
}

export async function stepUpOk(code, deps) {
  const d = deps || (await defaultDeps());
  if (!(await d.is2faEnabled())) return true;
  if (!code || !/^\d{6}$/.test(String(code))) return false;
  const secret = await d.getTotpSecret();
  return !!secret && d.verifyTotp(String(code), secret);
}

/** Whether an approval needs a 2FA code right now (drives the card's 2FA field). */
export async function totpRequired(deps) {
  const d = deps || (await defaultDeps());
  return !!(await d.is2faEnabled());
}