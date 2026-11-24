/**
 * Maker Lab — solo-mode device binding helpers (PANEL side).
 *
 * Solo mode lets a single learner auto-redeem without a QR handoff. That
 * posture is SAFE only in two situations:
 *   (A) the kiosk and the Crow host are the same machine (loopback), or
 *   (B) the LAN kiosk has been explicitly bound after an admin Nest login.
 *
 * This module handles the server-side checks for both.
 *
 * WHY IT LIVES IN panel/ AND NOT server/ (2026, token-HMAC key move): every
 * file under a bundle's server/ tree is BOT-REACHABLE — a bot MCP child loads
 * it — while panel/ code runs only inside the gateway (the gateway imports the
 * panel and its routes, and this module with them). `hasAdminSession` reads the
 * dashboard's own session rule (servers/gateway/dashboard/auth.js ->
 * servers/gateway/token-store.js, the store that mints and checks a session
 * verifier under servers/shared/token-mac.js's host-only HMAC key), which no
 * bot-reachable file may reach. Nothing under server/ ever imported this
 * module; only panel/routes.js and panel/maker-lab.js did, and both resolve it
 * from here now. tests/bundle-server-no-gateway-auth.test.js keeps it that way.
 */

import { fileURLToPath, pathToFileURL } from "node:url";
import { existsSync } from "node:fs";
import { join, resolve, dirname } from "node:path";

// Inlined app-root resolver, same shape as panel/maker-lab.js's: this file is
// loaded through the bundle's real on-disk location under CROW_APP_ROOT (the
// gateway exports it), so a relative `../server/app-root.js` would be
// location-dependent and is deliberately not used.
function looksLikeAppRoot(p) { return !!p && existsSync(join(p, "servers", "db.js")); }
const __dirname = dirname(fileURLToPath(import.meta.url));
const __appRootGuess = resolve(__dirname, "..", "..", "..");
const APP_ROOT = looksLikeAppRoot(process.env.CROW_APP_ROOT) ? process.env.CROW_APP_ROOT
  : looksLikeAppRoot(__appRootGuess) ? __appRootGuess
  : (process.env.CROW_APP_ROOT || __appRootGuess);
const appImport = (rel) => import(pathToFileURL(join(APP_ROOT, rel)).href);

const { sessionFromRequest } = await appImport("servers/gateway/dashboard/auth.js");
const { createProjectSpace } = await appImport("servers/shared/project-spaces.js");
const { classifyPeer } = await appImport("servers/shared/peer-class.js");

/**
 * Is the request coming from this machine itself (same-host kiosk)?
 * Peer class "local": a loopback socket carrying no forwarding or tailscale-*
 * headers. Traffic proxied in through Tailscale Serve or any other same-box
 * proxy also arrives on loopback, but it is not the local kiosk.
 */
export function isLoopback(req) {
  return (req.crowPeer || classifyPeer(req)).via === "local";
}

/**
 * Read the maker_lab.solo_lan_exposure setting. Default "off".
 */
export async function getSoloLanExposure(db) {
  try {
    const r = await db.execute({
      sql: "SELECT value FROM dashboard_settings WHERE key = 'maker_lab.solo_lan_exposure'",
      args: [],
    });
    return r.rows[0]?.value === "on" ? "on" : "off";
  } catch {
    return "off";
  }
}

export async function setSoloLanExposure(db, value) {
  const v = value === "on" ? "on" : "off";
  await db.execute({
    sql: `INSERT INTO dashboard_settings (key, value) VALUES ('maker_lab.solo_lan_exposure', ?)
          ON CONFLICT(key) DO UPDATE SET value = excluded.value`,
    args: [v],
  });
  return v;
}

/**
 * Check whether a fingerprint is recorded in maker_bound_devices.
 * Returns the row (with learner_id) or null.
 */
export async function getBoundDevice(db, fingerprint) {
  if (!fingerprint) return null;
  try {
    const r = await db.execute({
      sql: `SELECT * FROM maker_bound_devices WHERE fingerprint = ?`,
      args: [fingerprint],
    });
    return r.rows[0] || null;
  } catch {
    return null;
  }
}

export async function touchBoundDevice(db, fingerprint) {
  try {
    await db.execute({
      sql: `UPDATE maker_bound_devices SET last_seen_at = datetime('now') WHERE fingerprint = ?`,
      args: [fingerprint],
    });
  } catch {}
}

/**
 * Bind a device fingerprint to a learner. Idempotent (INSERT ON CONFLICT DO UPDATE).
 */
export async function bindDevice(db, { fingerprint, learnerId, label }) {
  await db.execute({
    sql: `INSERT INTO maker_bound_devices (fingerprint, learner_id, label, bound_at, last_seen_at)
          VALUES (?, ?, ?, datetime('now'), datetime('now'))
          ON CONFLICT(fingerprint) DO UPDATE SET
            learner_id = excluded.learner_id,
            label = COALESCE(excluded.label, maker_bound_devices.label),
            last_seen_at = datetime('now')`,
    args: [fingerprint, learnerId, label || null],
  });
}

export async function unbindDevice(db, fingerprint) {
  await db.execute({
    sql: `DELETE FROM maker_bound_devices WHERE fingerprint = ?`,
    args: [fingerprint],
  });
}

export async function listBoundDevices(db) {
  try {
    const r = await db.execute({
      sql: `SELECT bd.fingerprint, bd.learner_id, bd.label, bd.bound_at, bd.last_seen_at,
                   rp.name AS learner_name
            FROM maker_bound_devices bd
            LEFT JOIN project_spaces rp ON rp.id = bd.learner_id AND rp.archived_at IS NULL
            ORDER BY bd.last_seen_at DESC NULLS LAST`,
      args: [],
    });
    return r.rows;
  } catch {
    return [];
  }
}

/**
 * Check the request for a valid Crow's Nest session cookie.
 * Used to auto-bind on first visit when the admin is already logged in.
 *
 * sessionFromRequest, not sessionTokenFromRequest + verifySession: it reads only
 * the session name the request's channel may carry over HTTPS
 * (`__Host-crow_session`, host-only, so a sibling host on the tailnet cannot toss
 * a plain one) AND it applies the dashboard's plain-cookie migration rule — a
 * plain `crow_session` over HTTPS is a session here only when its row was
 * created before PLAIN_SESSION_MIGRATION_CUTOFF. A tossed plain cookie naming a
 * session made after the cutoff is therefore not an admin session here either.
 */
export async function hasAdminSession(req) {
  try {
    return (await sessionFromRequest(req)) !== null;
  } catch {
    return false;
  }
}

/**
 * Ensure a default learner exists for solo mode. If none, create one with
 * consent captured (by the admin initiating the binding). Returns the id.
 */
export async function ensureDefaultLearner(db) {
  const r = await db.execute({
    sql: `SELECT id FROM project_spaces WHERE type = 'learner_profile' AND archived_at IS NULL ORDER BY id LIMIT 1`,
    args: [],
  });
  if (r.rows.length) return Number(r.rows[0].id);
  // Create with age null — admin can edit in the settings panel.
  const { id: lid } = await createProjectSpace(db, {
    name: "Default learner",
    type: "learner_profile",
    ownerMember: false,
  });
  await db.execute({
    sql: `INSERT INTO maker_learner_settings (learner_id, age, consent_captured_at)
          VALUES (?, NULL, datetime('now'))`,
    args: [lid],
  });
  return lid;
}