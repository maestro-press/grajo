/**
 * The extension proxy's WebSocket session gate.
 *
 * The rejection paths here need no DB:
 *  - funnel header → rejected before any cookie parsing
 *  - no/irrelevant cookies → rejected before sessionFromRequest opens the DB
 *    (it short-circuits on a missing token).
 *
 * The HTTPS half (the plain → `__Host-` migration rule) drives the same export
 * against real oauth_tokens rows in a scratch CROW_DATA_DIR: over HTTPS a plain
 * `crow_session` is a session only when its row predates
 * PLAIN_SESSION_MIGRATION_CUTOFF, exactly as dashboardAuth decides it. Before
 * the fix the gate used `sessionTokenFromRequest` + `verifySession`, which never
 * looked at the row's created_at — so a sibling host's tossed plain cookie
 * authorized an upgrade the dashboard's own pages refused.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";
import { authorizeExtensionUpgrade } from "../servers/gateway/routes/extension-proxy.js";
import { _setNowFn } from "../servers/gateway/dashboard/auth.js";

// Rejection paths only — none of these touch the DB:
//  - funnel header → rejected before any cookie parsing
//  - no/irrelevant cookies → rejected before verifySession opens the DB
//    (verifySession itself short-circuits on a falsy token).

test("ws auth: funneled upgrade is rejected even with a session cookie", async () => {
  const ok = await authorizeExtensionUpgrade({
    headers: {
      "tailscale-funnel-request": "?1",
      cookie: "crow_session=abc123",
    },
  });
  assert.equal(ok, false);
});

// For the cookie-path tests, give the request an allowed-network identity
// (tailnet CGNAT ip) so isAllowedNetwork passes and the cookie branch is
// actually exercised.
function tailnetReq(headers = {}) {
  return { headers, ip: "100.64.0.5", connection: { remoteAddress: "100.64.0.5" } };
}

test("ws auth: allowed network but no cookies is rejected", async () => {
  assert.equal(await authorizeExtensionUpgrade(tailnetReq()), false);
});

test("ws auth: allowed network with unrelated cookies (no crow_session) is rejected", async () => {
  const ok = await authorizeExtensionUpgrade(tailnetReq({ cookie: "theme=dark; csrf=xyz" }));
  assert.equal(ok, false);
});

test("ws auth: disallowed network is rejected even WITH a session cookie", async () => {
  const ok = await authorizeExtensionUpgrade({
    headers: { cookie: "crow_session=abc123" },
    ip: "8.8.8.8",
    connection: { remoteAddress: "8.8.8.8" },
  });
  assert.equal(ok, false);
});

// ---- the plain → `__Host-` migration rule (real session rows) --------------
// A raw upgrade request never passes through Express, so `secure` is the test's
// stand-in for the TLS Serve/Caddy terminated in front of the gateway
// (requestIsSecure takes a boolean `req.secure` first). The peer is a tailnet
// address, so the network half of sessionFromRequest passes and only the
// cookie/row half can decide.

const REPO = new URL("..", import.meta.url).pathname;
const MIGRATION_NOW = Date.parse("2026-11-25T12:00:00Z"); // inside the grace period
const PRE_CUTOFF = "2026-11-18 09:00:00";
const POST_CUTOFF = "2026-11-21 09:00:00"; // the tossing case: newer than the cutoff

/** Run `fn` against a scratch CROW_DATA_DIR with the real schema. */
async function withScratchDb(fn) {
  const dir = mkdtempSync(join(tmpdir(), "extension-ws-auth-"));
  const prev = {
    dataDir: process.env.CROW_DATA_DIR,
    dbPath: process.env.CROW_DB_PATH,
    tasksDbPath: process.env.CROW_TASKS_DB_PATH,
    home: process.env.CROW_HOME,
  };
  mkdirSync(join(dir, "home"), { recursive: true });
  process.env.CROW_DATA_DIR = dir;
  process.env.CROW_HOME = join(dir, "home");
  process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");
  delete process.env.CROW_DB_PATH;
  try {
    execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env }, stdio: "pipe", cwd: REPO });
    await fn(dir);
  } finally {
    if (prev.dataDir === undefined) delete process.env.CROW_DATA_DIR;
    else process.env.CROW_DATA_DIR = prev.dataDir;
    if (prev.dbPath === undefined) delete process.env.CROW_DB_PATH;
    else process.env.CROW_DB_PATH = prev.dbPath;
    if (prev.tasksDbPath === undefined) delete process.env.CROW_TASKS_DB_PATH;
    else process.env.CROW_TASKS_DB_PATH = prev.tasksDbPath;
    if (prev.home === undefined) delete process.env.CROW_HOME;
    else process.env.CROW_HOME = prev.home;
    rmSync(dir, { recursive: true, force: true });
  }
}

/** A dashboard session row created at `createdAt`, expiring from the real clock. */
function seedDatedSession(dir, token, createdAt) {
  const c = new Database(join(dir, "crow.db"));
  try {
    c.prepare(
      "INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at, created_at) " +
      "VALUES (?, 'access', 'dashboard', 'dashboard', ?, ?)",
    ).run(createHash("sha256").update(token).digest("hex"), new Date(Date.now() + 600_000).toISOString(), createdAt);
  } finally {
    c.close();
  }
}

/** A tailnet peer's HTTPS upgrade request carrying exactly `cookie`. */
function httpsUpgradeReq(cookie) {
  const socket = { remoteAddress: "100.64.0.5" };
  return { secure: true, headers: { cookie, host: "crow.example.ts.net" }, socket, connection: socket };
}

test("ws auth: a plain crow_session over HTTPS minted AFTER the cutoff is refused; a __Host- one is accepted", async () => {
  await withScratchDb(async (dir) => {
    _setNowFn(() => MIGRATION_NOW);
    try {
      seedDatedSession(dir, "tossed-upgrade-session", POST_CUTOFF);
      assert.equal(
        await authorizeExtensionUpgrade(httpsUpgradeReq("crow_session=tossed-upgrade-session")),
        false,
        "a plain cookie naming a session newer than the cutoff never authorizes an upgrade",
      );
      assert.equal(
        await authorizeExtensionUpgrade(httpsUpgradeReq("__Host-crow_session=tossed-upgrade-session")),
        true,
        "the same session under the __Host- name is the owner's: no sibling can set that cookie",
      );
    } finally {
      _setNowFn();
    }
  });
});

test("ws auth: a plain crow_session over HTTPS minted BEFORE the cutoff still authorizes (it is a migration, not a tossing)", async () => {
  await withScratchDb(async (dir) => {
    _setNowFn(() => MIGRATION_NOW);
    try {
      seedDatedSession(dir, "legacy-upgrade-session", PRE_CUTOFF);
      assert.equal(await authorizeExtensionUpgrade(httpsUpgradeReq("crow_session=legacy-upgrade-session")), true);
    } finally {
      _setNowFn();
    }
  });
});

test("ws auth: the same plain post-cutoff cookie over PLAIN HTTP is still the session (no __Host- cookie exists there)", async () => {
  await withScratchDb(async (dir) => {
    _setNowFn(() => MIGRATION_NOW);
    try {
      seedDatedSession(dir, "lan-upgrade-session", POST_CUTOFF);
      const socket = { remoteAddress: "192.168.1.20" };
      const req = { headers: { cookie: "crow_session=lan-upgrade-session", host: "192.168.1.20:3001" }, socket, connection: socket };
      assert.equal(await authorizeExtensionUpgrade(req), true, "bare HTTP has no migration rail to enforce");
    } finally {
      _setNowFn();
    }
  });
});
