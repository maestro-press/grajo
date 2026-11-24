/**
 * Maker Lab's `hasAdminSession` — the "is the admin already signed in?" check the
 * solo-mode kiosk uses to auto-bind a device on its first visit.
 *
 * It must read the session the same way the dashboard does. Before the fix it
 * used `sessionTokenFromRequest` + `verifySession`, which never looked at the
 * session row's `created_at`: over HTTPS a plain `crow_session` (a sibling host
 * on the tailnet can set that — `ts.net` is a public suffix, so every
 * `<x>.<tailnet>.ts.net` is the same SITE) naming a session the sibling had just
 * created was accepted as the admin. It now goes through `sessionFromRequest`, so
 * the plain → `__Host-` migration rule applies: a plain cookie over HTTPS is a
 * session only when its row was created before
 * PLAIN_SESSION_MIGRATION_CUTOFF, and never after PLAIN_SESSION_GRACE_END.
 *
 * Same harness shape as tests/session-cookie-migration.test.js: a scratch
 * CROW_DATA_DIR with the real schema, real oauth_tokens rows (created_at chosen
 * by the test), the migration window clock injected with `_setNowFn`, and the
 * network gate opened with CROW_DASHBOARD_PUBLIC (isAllowedNetwork is
 * auth-network.test.js's subject, not this one's).
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";

const dir = mkdtempSync(join(tmpdir(), "maker-lab-admin-session-"));
process.env.CROW_DATA_DIR = dir;
process.env.CROW_HOME = join(dir, "home");
mkdirSync(process.env.CROW_HOME, { recursive: true });
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");
process.env.CROW_DASHBOARD_PUBLIC = "true"; // the network gate is another test's subject

const REPO = new URL("..", import.meta.url).pathname;
const MIGRATION_NOW = Date.parse("2026-11-25T12:00:00Z"); // inside the grace period
const PRE_CUTOFF = "2026-11-18 09:00:00";  // a sign-in from before the release
const POST_CUTOFF = "2026-11-21 09:00:00"; // the cookie-tossing case

let hasAdminSession, _setNowFn;

/** A dashboard session row created at `createdAt`, expiring from the real clock. */
function seedSession(token, createdAt) {
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

/** An HTTPS request carrying exactly `cookie` (a tailnet-shaped install). */
const httpsReq = (cookie) => ({ secure: true, headers: { cookie, host: "crow.example.ts.net" } });

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env }, stdio: "pipe", cwd: REPO });
  // Imported AFTER the scratch env is in place: the bundle resolves the app root
  // and the dashboard modules when this module loads (its own appImport contract).
  ({ hasAdminSession } = await import("../bundles/maker-lab/panel/device-binding.js"));
  ({ _setNowFn } = await import("../servers/gateway/dashboard/auth.js"));
});

after(() => {
  try { _setNowFn?.(); } catch { /* never imported */ }
  rmSync(dir, { recursive: true, force: true });
});

test("hasAdminSession: a __Host- cookie naming a live session is the admin", async () => {
  _setNowFn(() => MIGRATION_NOW);
  try {
    seedSession("host-session", POST_CUTOFF);
    assert.equal(await hasAdminSession(httpsReq("__Host-crow_session=host-session")), true);
  } finally {
    _setNowFn();
  }
});

test("hasAdminSession: a plain crow_session over HTTPS minted AFTER the cutoff is NOT the admin (session fixation)", async () => {
  _setNowFn(() => MIGRATION_NOW);
  try {
    seedSession("tossed-session", POST_CUTOFF);
    assert.equal(
      await hasAdminSession(httpsReq("crow_session=tossed-session")),
      false,
      "a sibling host's plain cookie holding a session it just created must not auto-bind a device",
    );
    // The same session under the __Host- name is fine: that cookie is host-only,
    // so nothing off this origin can plant it.
    assert.equal(await hasAdminSession(httpsReq("__Host-crow_session=tossed-session")), true);
  } finally {
    _setNowFn();
  }
});

test("hasAdminSession: a plain crow_session minted BEFORE the cutoff is still migrated into", async () => {
  _setNowFn(() => MIGRATION_NOW);
  try {
    seedSession("legacy-session", PRE_CUTOFF);
    assert.equal(await hasAdminSession(httpsReq("crow_session=legacy-session")), true);
  } finally {
    _setNowFn();
  }
});

test("hasAdminSession: no cookie, a made-up token, or a dead plain cookie never counts", async () => {
  _setNowFn(() => MIGRATION_NOW);
  try {
    assert.equal(await hasAdminSession(httpsReq("")), false, "no cookie");
    assert.equal(await hasAdminSession(httpsReq("crow_session=made-up")), false, "no such row");
    assert.equal(await hasAdminSession({ headers: {} }), false, "no cookie header at all");

    // After the grace end the plain rail is closed for good, even for a genuinely
    // old session: __Host-crow_session is the only session cookie over HTTPS.
    const { PLAIN_SESSION_GRACE_END } = await import("../servers/gateway/dashboard/auth.js");
    _setNowFn(() => Date.parse(PLAIN_SESSION_GRACE_END) + 1000);
    seedSession("legacy-after-grace", PRE_CUTOFF);
    assert.equal(await hasAdminSession(httpsReq("crow_session=legacy-after-grace")), false);
    assert.equal(await hasAdminSession(httpsReq("__Host-crow_session=legacy-after-grace")), true);
  } finally {
    _setNowFn();
  }
});