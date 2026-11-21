/**
 * The plain → `__Host-` migration is a BOUNDED rail: it keeps the pre-`__Host-`
 * session it migrates, it never extends it, and it refuses a session it was not
 * built for.
 *
 * Over HTTPS the dashboard reads `__Host-crow_session`. A browser that still
 * holds only the OLD plain `crow_session` from an earlier release is migrated:
 * the response re-issues the cookie under the `__Host-` name for the session's
 * OWN remaining lifetime (never a fresh week — replaying the migration cannot
 * keep a credential alive) and expires the plain one, host-only AND at the
 * request host's parent domain where a sibling could have tossed it.
 *
 * The rail is only for sessions minted BEFORE the release that introduced
 * `__Host-` (PLAIN_SESSION_MIGRATION_CUTOFF), and only until the grace period
 * ends (PLAIN_SESSION_GRACE_END). The case it must refuse is session fixation by
 * cookie tossing: a sibling host on the tailnet (`ts.net` is a public suffix, so
 * `<x>.<tailnet>.ts.net` is the same SITE) tosses a plain `crow_session` holding
 * a session it just created, and those rows are newer than the cutoff.
 *
 * The real dashboardAuth middleware is driven directly over a scratch
 * CROW_DATA_DIR (same harness shape as dashboard-logout.test.js), with the
 * network gate opened by CROW_DASHBOARD_PUBLIC because isAllowedNetwork is
 * auth-network.test.js's subject, not this one's.
 *
 * Two clocks, on purpose: the migration WINDOW is measured against a clock
 * injected with `_setNowFn` (so "inside the grace period" and "after it" mean
 * the same thing on any day CI runs), while a session's EXPIRY is a real
 * timestamp in the row — `expires_at` is seeded from the machine's clock so the
 * session store's own `julianday(expires_at) > julianday('now')` check and the
 * re-issued Max-Age are the real ones.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "better-sqlite3";

const dir = mkdtempSync(join(tmpdir(), "session-cookie-migration-"));
process.env.CROW_DATA_DIR = dir;
process.env.CROW_HOME = join(dir, "home");
mkdirSync(process.env.CROW_HOME, { recursive: true });
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");
process.env.CROW_DASHBOARD_PUBLIC = "true";
writeFileSync(join(dir, "instance-id"), "instance-session-migration");

const REPO = new URL("..", import.meta.url).pathname;
const DAY_MS = 24 * 60 * 60 * 1000;
const SESSION_MAX_AGE_MS = 7 * DAY_MS;

// The migration-window clock every test stands at by default: INSIDE the grace
// period, so the rail is open and "post-cutoff" can only mean the session row's
// own created_at.
const NOW = Date.parse("2026-11-25T12:00:00Z");
const PRE_CUTOFF = "2026-11-18 09:00:00";  // datetime('now') text, before the release
const POST_CUTOFF = "2026-11-21 09:00:00"; // after it: the cookie-tossing case
const AT_CUTOFF = "2026-11-20 16:41:00";   // exactly PLAIN_SESSION_MIGRATION_CUTOFF

let dashboardAuth, hashToken, _setNowFn, PLAIN_SESSION_GRACE_END;

/** A dashboard session row created at `createdAt`, expiring `days` from the WALL clock. */
function seedSession(token, { createdAt = PRE_CUTOFF, days = 2 } = {}) {
  const c = new Database(join(dir, "crow.db"));
  try {
    c.prepare(
      "INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at, created_at) " +
      "VALUES (?, 'access', 'dashboard', 'dashboard', ?, ?)",
    ).run(hashToken(token), new Date(Date.now() + days * DAY_MS).toISOString(), createdAt);
  } finally {
    c.close();
  }
}

/** An HTTPS request carrying exactly `cookie` (Host: a tailnet-shaped install). */
function httpsReq(cookie, host = "crow.example.ts.net") {
  return { secure: true, method: "GET", headers: { cookie, host } };
}

/** Drive the real middleware; resolves what it chose to do. */
function auth(req) {
  return new Promise((resolve) => {
    const headers = {};
    const res = {
      headers,
      location: null,
      setHeader(name, value) { headers[String(name).toLowerCase()] = value; },
      redirect(url) { res.location = url; resolve({ next: false, res }); },
      redirectAfterPost(url) { res.location = url; resolve({ next: false, res }); },
    };
    dashboardAuth(req, res, () => resolve({ next: true, res }));
  });
}

const cookiesOf = (res) => [].concat(res.headers["set-cookie"] || []);
const maxAgeOf = (cookie) => Number(/Max-Age=(\d+)/.exec(cookie)?.[1] ?? NaN);
const plainExpiries = (res) => cookiesOf(res).filter((c) => c.startsWith("crow_session=;"));

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env }, stdio: "pipe", cwd: REPO });
  ({ dashboardAuth, hashToken, _setNowFn, PLAIN_SESSION_GRACE_END } =
    await import("../servers/gateway/dashboard/auth.js"));
  _setNowFn(() => NOW);
});
after(() => {
  _setNowFn();
  rmSync(dir, { recursive: true, force: true });
});

// ---- the migration itself (inside the grace period) -----------------------

test("the migration re-issues __Host- for the session's OWN remaining lifetime", async () => {
  const token = "migrate-keeps-lifetime";
  seedSession(token, { days: 2 });

  const { next, res } = await auth(httpsReq(`crow_session=${token}`));
  assert.equal(next, true, "a lone plain cookie over HTTPS is migrated");
  assert.equal(res.location, null);

  const cookies = cookiesOf(res);
  const host = cookies.find((c) => c.startsWith("__Host-crow_session="));
  assert.ok(host, cookies.join(" | "));
  const maxAge = maxAgeOf(host);
  assert.ok(
    Math.abs(maxAge - 2 * 24 * 60 * 60) <= 60,
    `keeps ~2 days, not a fresh week (got ${maxAge}s)`,
  );
  assert.ok(maxAge * 1000 < SESSION_MAX_AGE_MS, "and never longer than the session had left");
  assert.match(host, /; Secure/);
  // The plain cookie is expired — host-only AND at the parent domain a sibling
  // would have used.
  const plain = plainExpiries(res);
  assert.equal(plain.length, 2, cookies.join(" | "));
  assert.ok(plain.some((c) => /; Domain=example\.ts\.net/.test(c)), "the tossed Domain= copy goes too");
});

test("a request already carrying __Host- gets no re-issue at all", async () => {
  const token = "already-host";
  seedSession(token, { days: 1 });

  const { next, res } = await auth(httpsReq(`__Host-crow_session=${token}`));
  assert.equal(next, true);
  assert.deepEqual(cookiesOf(res), [], "no re-issue: the browser already has the __Host- cookie");
});

test("a session created before the release is still migrated", async () => {
  const token = "legacy-row";
  seedSession(token, { createdAt: "2026-06-01 00:00:00", days: 3 }); // exactly what an upgraded crow.db holds
  const { next, res } = await auth(httpsReq(`crow_session=${token}`));
  assert.equal(next, true);
  assert.ok(cookiesOf(res).some((c) => c.startsWith("__Host-crow_session=")));
});

// ---- the tossing case: a session minted at/after the cutoff ----------------

test("a plain cookie naming a POST-cutoff session is refused and cleared (session fixation)", async () => {
  const token = "tossed-session";
  seedSession(token, { createdAt: POST_CUTOFF, days: 2 });

  const { next, res } = await auth(httpsReq(`crow_session=${token}`));
  assert.equal(next, false, "not a session: the row is newer than the cutoff");
  assert.equal(res.location, "/dashboard/login", "signed out, never migrated into the attacker's session");

  const cookies = cookiesOf(res);
  assert.equal(
    cookies.filter((c) => c.startsWith("__Host-crow_session=")).length, 0,
    `no __Host- cookie is ever minted for it: ${cookies.join(" | ")}`,
  );
  const plain = plainExpiries(res);
  assert.equal(plain.length, 2, `the tossed cookie is expired (host-only + parent): ${cookies.join(" | ")}`);
  assert.ok(plain.every((c) => /Max-Age=0/.test(c) && /; Secure/.test(c)), plain.join(" | "));
  assert.ok(plain.some((c) => /; Domain=example\.ts\.net/.test(c)), "including the sibling's Domain= copy");
});

test("a session minted AT the cutoff is not migrated either (the cutoff is exclusive)", async () => {
  const token = "at-the-cutoff";
  seedSession(token, { createdAt: AT_CUTOFF, days: 2 });
  const { next, res } = await auth(httpsReq(`crow_session=${token}`));
  assert.equal(next, false);
  assert.equal(res.location, "/dashboard/login");
  assert.equal(cookiesOf(res).filter((c) => c.startsWith("__Host-crow_session=")).length, 0);
});

test("a refused plain cookie does not disturb a valid __Host- session", async () => {
  const host = "owner-host";
  const tossed = "tossed-with-owner";
  seedSession(host, { days: 1 });
  seedSession(tossed, { createdAt: POST_CUTOFF, days: 1 });

  const { next, res } = await auth(httpsReq(`__Host-crow_session=${host}; crow_session=${tossed}`));
  assert.equal(next, true, "__Host- wins, as before");
  assert.deepEqual(cookiesOf(res), [], "and nothing is re-issued or expired: the plain copy is just noise");
});

// ---- after the grace end: the plain rail is closed ------------------------

test("after the grace end even a PRE-cutoff plain cookie is refused over HTTPS, and cleared", async () => {
  const after = Date.parse(PLAIN_SESSION_GRACE_END) + 1000;
  _setNowFn(() => after);
  try {
    const token = "legacy-after-grace";
    seedSession(token, { createdAt: "2026-06-01 00:00:00", days: 30 });

    const { next, res } = await auth(httpsReq(`crow_session=${token}`));
    assert.equal(next, false, "the __Host- cookie is the only session cookie over HTTPS by then");
    assert.equal(res.location, "/dashboard/login");
    assert.equal(cookiesOf(res).filter((c) => c.startsWith("__Host-crow_session=")).length, 0);
    assert.equal(plainExpiries(res).length, 2, "and the dead plain cookie is expired");
  } finally {
    _setNowFn(() => NOW);
  }
});

test("after the grace end the __Host- cookie still decides", async () => {
  const after = Date.parse(PLAIN_SESSION_GRACE_END) + 1000;
  _setNowFn(() => after);
  try {
    const token = "host-after-grace";
    seedSession(token, { createdAt: "2026-06-01 00:00:00", days: 30 });

    const { next, res } = await auth(httpsReq(`__Host-crow_session=${token}`));
    assert.equal(next, true);
    assert.deepEqual(cookiesOf(res), []);
  } finally {
    _setNowFn(() => NOW);
  }
});

// ---- plain HTTP stays exactly as it was ----------------------------------

test("a plain HTTP request is untouched: no __Host- cookie", async () => {
  const token = "lan";
  seedSession(token, { days: 1 });
  const req = { secure: false, method: "GET", headers: { cookie: `crow_session=${token}`, host: "192.168.1.20:3001" } };
  const { next, res } = await auth(req);
  assert.equal(next, true);
  assert.deepEqual(cookiesOf(res), [], "nothing is re-issued over plain HTTP");
});

test("plain HTTP is unchanged even after the grace end, and for a POST-cutoff session", async () => {
  const after = Date.parse(PLAIN_SESSION_GRACE_END) + 1000;
  _setNowFn(() => after);
  try {
    const token = "lan-after-grace";
    seedSession(token, { createdAt: POST_CUTOFF, days: 30 });
    const req = { secure: false, method: "GET", headers: { cookie: `crow_session=${token}`, host: "192.168.1.20:3001" } };
    const { next, res } = await auth(req);
    assert.equal(next, true, "bare HTTP has no __Host- cookie to prefer: the plain one is the session");
    assert.deepEqual(cookiesOf(res), [], "and never a re-issue or an expiry");
  } finally {
    _setNowFn(() => NOW);
  }
});