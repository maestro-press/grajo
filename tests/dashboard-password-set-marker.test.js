// tests/dashboard-password-set-marker.test.js — a deleted password record must
// never re-open first-run setup.
//
// auth.js answers "is the dashboard set up?" from the `password_hash` row in
// crow.db's dashboard_settings. A contained bot has crow.db read-write, so it can
// DELETE that row — and a row-less crow.db makes the login page offer first-run
// setup, where allowFirstRun (setup-token.js) lets a direct-loopback request set
// a password WITHOUT the setup token on a single-user box. The fix is the
// out-of-database marker <CROW_HOME>/secrets/dashboard-password-set
// (password-set-marker.js): present means "a password was set", whatever the
// database now says, so the instance is LOCKED (login form, failed login,
// `npm run reset-password` to recover) instead of handed over.
//
// Harness: a scratch crow.db (init-db) and a scratch CROW_HOME, the REAL
// dashboard router and the REAL /setup handler, the way
// tests/first-run-setup-token.test.js does it.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import { mkdtempSync, mkdirSync, existsSync, readFileSync, statSync, symlinkSync } from "node:fs";
import { syncBuiltinESMExports } from "node:module";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmScratch } from "./helpers/safe-rm.js";

const REPO = join(import.meta.dirname, "..");
const dir = mkdtempSync(join(tmpdir(), "pw-set-marker-"));

const HOME = join(dir, "home");
process.env.CROW_HOME = HOME;
process.env.CROW_DATA_DIR = join(dir, "data");
delete process.env.CROW_DB_PATH;
delete process.env.CROW_SETUP_TOKEN;
// The self-hosted recovery hint is only rendered outside hosted mode; pin that
// so the hint assertions below do not depend on the suite's environment.
delete process.env.CROW_HOSTED;
execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env }, stdio: "pipe", cwd: REPO });

// dashboard/index.js and setup-page.js call allowFirstRun(req, { from }) with no
// opts, and the loopback exemption needs a machine with ONE login account. The
// host running this suite may have a second one, which would refuse every
// loopback request below for a reason these tests are not about. Redirect just
// the /etc/passwd read to a single-account fixture for this file.
const GATEWAY_UID = process.getuid?.();
const PASSWD_FIXTURE = join(dir, "passwd-single-account");
fs.writeFileSync(PASSWD_FIXTURE, [
  "root:x:0:0:root:/root:/bin/bash",
  "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
  "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
  `owner:x:${GATEWAY_UID}:${GATEWAY_UID}:owner:/home/owner:/bin/bash`,
].join("\n") + "\n");
const realReadFileSync = fs.readFileSync;
fs.readFileSync = function readFileSyncWithPasswdFixture(path, ...rest) {
  return realReadFileSync.call(fs, path === "/etc/passwd" ? PASSWD_FIXTURE : path, ...rest);
};
syncBuiltinESMExports();

const express = (await import("express")).default;
const { createDbClient } = await import("../servers/db.js");
const { default: dashboardRouter } = await import("../servers/gateway/dashboard/index.js");
const { setupPageHandler } = await import("../servers/gateway/setup-page.js");
const { isPasswordSet, setPassword, hasPasswordRow, attemptLogin } = await import("../servers/gateway/dashboard/auth.js");
const {
  passwordSetMarkerPath,
  writePasswordSetMarker,
  hasPasswordSetMarker,
  bootPasswordSetMarker,
} = await import("../servers/gateway/dashboard/password-set-marker.js");
const { createStepUpGate } = await import("../servers/gateway/dashboard/step-up.js");
const passwordSection = (await import("../servers/gateway/dashboard/settings/sections/password.js")).default;

const db = createDbClient();
const PW = "correct horse battery staple";
const MARKER = passwordSetMarkerPath(HOME);
const SECRETS_DIR = join(HOME, "secrets");
const DB_FILE = join(process.env.CROW_DATA_DIR, "crow.db");

// The first-run gate's refusal / the ordinary login page's wording — EXISTING
// strings only (this change adds no user-visible text).
const GATED_TEXT = "The setup link is printed by the installer";
const NO_PASSWORD_TEXT = "No password set.";
// login.lockoutSelfHosted (i18n): the existing line above `npm run reset-password`.
const RESET_HINT_TEXT = "You can reset your password from the command line:";
const hasPasswordForm = (html) => /name="password"/.test(html);
// renderLogin({isSetup:true}) is the ONLY form with a confirm field (the
// ordinary login form has just the password). A loopback first run gets the
// setup form without a setup_token field, so the confirm field is what tells
// "first-run setup" apart from "login" for the peer that needs no token.
const offersSetup = (html) => /name="confirm"/.test(html) && hasPasswordForm(html);

let server;
let base;
{
  const app = express();
  app.use((req, res, next) => { res.redirectAfterPost = (url) => res.redirect(303, url); next(); });
  app.use(dashboardRouter((req, res, next) => next()));
  app.get("/setup", setupPageHandler);
  server = await new Promise((r) => { const s = app.listen(0, "127.0.0.1", () => r(s)); });
  base = `http://127.0.0.1:${server.address().port}`;
}

after(async () => {
  try { db.close(); } catch {}
  if (server) await new Promise((r) => { server.close(r); server.closeAllConnections(); });
  rmScratch(dir);
});

/** A request straight off this machine's loopback socket (peer:null) or as a LAN peer. */
const get = (path, { peer = null } = {}) =>
  fetch(base + path, { redirect: "manual", headers: peer ? { "x-test-peer": peer } : {} });
const post = (path, fields, { peer = null } = {}) =>
  fetch(base + path, {
    method: "POST",
    redirect: "manual",
    headers: { "content-type": "application/x-www-form-urlencoded", ...(peer ? { "x-test-peer": peer } : {}) },
    body: new URLSearchParams(fields).toString(),
  });

async function deletePasswordRow() {
  await db.execute("DELETE FROM dashboard_settings WHERE key = 'password_hash'");
  assert.equal(await hasPasswordRow(), false, "the row really is gone (the attack's precondition)");
}

function removeMarker(path = MARKER) {
  try { fs.rmSync(path, { force: true }); } catch {}
}

// --- the marker is written wherever a password is set -----------------------

test("setPassword writes the marker: 0600 inside a 0700 secrets dir, an ISO timestamp and nothing else", async () => {
  await setPassword(PW);
  assert.equal(await hasPasswordRow(), true);
  assert.equal(existsSync(MARKER), true, "the marker exists after a password is set");
  assert.equal(MARKER, join(HOME, "secrets", "dashboard-password-set"), "inside <CROW_HOME>/secrets");
  assert.equal(statSync(MARKER).mode & 0o777, 0o600, "mode 0600");
  assert.equal(statSync(SECRETS_DIR).mode & 0o777, 0o700, "the secrets dir is 0700 (ensureSecretsDir)");
  assert.match(readFileSync(MARKER, "utf8"), /^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z\n$/, "an ISO timestamp + newline");
  assert.equal(await isPasswordSet(), true);
});

test("hasPasswordSetMarker: ENOENT is the ONLY false; a symlink, a directory and any other error fail closed", () => {
  const freshHome = join(dir, "marker-shapes");
  mkdirSync(freshHome, { recursive: true });
  assert.equal(hasPasswordSetMarker({ crowHome: freshHome }), false, "no file, no marker");

  // A symlink counts as present, even a dangling one.
  const linkHome = join(dir, "marker-symlink");
  const linkPath = passwordSetMarkerPath(linkHome);
  mkdirSync(join(linkHome, "secrets"), { recursive: true });
  symlinkSync(join(linkHome, "secrets", "not-there"), linkPath);
  assert.equal(hasPasswordSetMarker({ crowHome: linkHome }), true, "a symlink is PRESENT (fail closed)");

  // A directory at the path is not a regular file, but it is present.
  const dirHome = join(dir, "marker-directory");
  mkdirSync(passwordSetMarkerPath(dirHome), { recursive: true });
  assert.equal(hasPasswordSetMarker({ crowHome: dirHome }), true, "a directory is PRESENT (fail closed)");

  // A regular file, of course.
  assert.equal(writePasswordSetMarker({ crowHome: freshHome }), true);
  assert.equal(hasPasswordSetMarker({ crowHome: freshHome }), true);

  // Any error other than ENOENT fails closed: here the parent is a FILE, so the
  // lstat fails with ENOTDIR, not ENOENT.
  const blockedHome = join(dir, "marker-blocked");
  mkdirSync(blockedHome, { recursive: true });
  fs.writeFileSync(join(blockedHome, "secrets"), "not a directory\n");
  assert.equal(hasPasswordSetMarker({ crowHome: blockedHome }), true, "ENOTDIR is not 'no marker'");
});

test("writePasswordSetMarker never throws: an unwritable home returns false and warns once", () => {
  const lines = [];
  const blockedHome = join(dir, "marker-unwritable");
  mkdirSync(blockedHome, { recursive: true });
  fs.writeFileSync(join(blockedHome, "secrets"), "not a directory\n");
  assert.equal(writePasswordSetMarker({ crowHome: blockedHome, log: (l) => lines.push(l) }), false);
  assert.equal(lines.length, 1, "exactly one warning");
  assert.equal(hasPasswordSetMarker({ crowHome: blockedHome }), true, "and the reader still fails closed");
});

// --- THE ATTACK ------------------------------------------------------------

test("THE ATTACK: delete the password_hash row and the dashboard is LOCKED, never re-offered as setup", async () => {
  // A fully set-up instance: row + marker.
  await setPassword(PW);
  await deletePasswordRow();

  // 1. "Is a password set?" still answers yes — from the marker.
  assert.equal(await isPasswordSet(), true, "the marker remembers the password the row no longer does");

  // 2. GET /dashboard/login shows the ordinary LOGIN form, never first-run setup.
  const login = await get("/dashboard/login");
  assert.equal(login.status, 200);
  const html = await login.text();
  assert.equal(hasPasswordForm(html), true, "the password form");
  assert.equal(offersSetup(html), false, "NO setup form: no confirm field (and no setup_token field)");
  assert.equal(html.includes(GATED_TEXT), false, "and no gated-setup message either");

  // 3. GET /setup is done: it redirects to the login page (setup-page.js gate).
  const setup = await get("/setup");
  assert.equal(setup.status, 302);
  assert.equal(setup.headers.get("location"), "/dashboard/login?next=/dashboard/settings");

  // 4. First-run setup posted from direct loopback without a token is REFUSED:
  //    the request is not a setup at all any more, it is a login attempt — which
  //    fails with the existing "No password set." branch and writes no password.
  const attack = await post("/dashboard/login", { password: "attacker picked this", confirm: "attacker picked this" });
  assert.equal(attack.status, 200, "not signed in, not a setup");
  assert.equal(attack.headers.get("set-cookie"), null, "no session was minted");
  const attackHtml = await attack.text();
  assert.ok(attackHtml.includes(NO_PASSWORD_TEXT), "the ordinary failed-login branch");
  // …and the existing self-hosted recovery hint (the one a lockout shows) is
  // shown for this case too: "No password set." must not be a dead end.
  assert.ok(attackHtml.includes(RESET_HINT_TEXT), "the lockout page's recovery hint");
  assert.ok(attackHtml.includes("npm run reset-password"), "naming the reset command");
  assert.equal(await hasPasswordRow(), false, "no password was written: the row is still gone");
  assert.equal(await hasPasswordSetMarker(), true, "and nothing removed the marker");

  // 5. The ordinary login attempt fails too (there is nothing to verify against),
  //    and the marker keeps the instance locked rather than setup-able.
  const attempt = await attemptLogin(PW, "127.0.0.1");
  assert.equal(attempt.error, NO_PASSWORD_TEXT);
  assert.equal(await isPasswordSet(), true);

  // 6. Positive control: an ordinary wrong password (row present) shows the
  //    ordinary error and NOT the recovery hint — the hint is for a locked
  //    instance, not for every failed login.
  await setPassword(PW);
  const wrong = await post("/dashboard/login", { password: "not the password" });
  assert.equal(wrong.status, 200);
  const wrongHtml = await wrong.text();
  assert.ok(wrongHtml.includes("Invalid password."), "the ordinary failed login");
  assert.equal(wrongHtml.includes(RESET_HINT_TEXT), false, "no recovery hint for a plain wrong password");
});

// --- a DB that cannot be read is LOCKED, never setup ----------------------

/**
 * A path that cannot be a database (a directory), for NEW clients only: the
 * already-open test client keeps the real file. Any read through it throws.
 */
function withUnreadableDb(fn) {
  const saved = process.env.CROW_DB_PATH;
  const unopenable = mkdtempSync(join(dir, "unreadable-db-"));
  process.env.CROW_DB_PATH = unopenable;
  return Promise.resolve()
    .then(fn)
    .finally(() => {
      if (saved === undefined) delete process.env.CROW_DB_PATH;
      else process.env.CROW_DB_PATH = saved;
    });
}

test("a DB error with the marker present is LOCKED (login form, never setup), and isPasswordSet never touches the DB", async () => {
  await setPassword(PW);
  assert.equal(hasPasswordSetMarker(), true, "the marker is there");

  await withUnreadableDb(async () => {
    await assert.rejects(() => hasPasswordRow(), "the DB really cannot be read by a new client");
    // The fallback is the row read; it is never reached. If it were, this would
    // throw instead of answering.
    assert.equal(await isPasswordSet(), true, "answered from the marker, with no DB read");

    const login = await get("/dashboard/login");
    assert.equal(login.status, 200);
    const html = await login.text();
    assert.equal(hasPasswordForm(html), true, "the ordinary login form");
    assert.equal(offersSetup(html), false, "never first-run setup on a DB error");
    assert.equal(html.includes(GATED_TEXT), false);

    const setup = await get("/setup");
    assert.equal(setup.status, 302, "no setup page either");
    assert.equal(setup.headers.get("location"), "/dashboard/login?next=/dashboard/settings");
    assert.equal(offersSetup(await setup.text()), false);
  });
});

test("setup page: an unreadable password state and NO marker still does not render the setup form (catch → true)", async () => {
  removeMarker();
  assert.equal(hasPasswordSetMarker(), false, "no marker: isPasswordSet must ask the DB");

  await withUnreadableDb(async () => {
    await assert.rejects(() => isPasswordSet(), "the password state cannot be read at all");
    const setup = await get("/setup");
    assert.equal(setup.status, 302, "redirected to login, not the password form");
    assert.equal(setup.headers.get("location"), "/dashboard/login?next=/dashboard/settings");
    assert.equal(offersSetup(await setup.text()), false);
  });
});

test("the owner's recovery path still works: `npm run reset-password` rewrites the row AND the marker", async () => {
  // The recovery the lockout page names. The prompts are interactive, so the
  // write path the script runs after them is exercised directly (the same
  // INSERT + writePasswordSetMarker the CLI path calls).
  removeMarker();
  assert.equal(hasPasswordSetMarker(), false, "a lockout with no marker, as after a wiped secrets dir");
  await deletePasswordRow();

  const { writePasswordRecord } = await import("../scripts/reset-password.js");
  await writePasswordRecord(DB_FILE, `deadbeef:${"0".repeat(128)}`);

  assert.equal(await hasPasswordRow(), true, "the row is back");
  assert.equal(existsSync(MARKER), true, "the reset recorded the marker");
  assert.equal(statSync(MARKER).mode & 0o777, 0o600, "mode 0600");
  assert.match(readFileSync(MARKER, "utf8"), /^\d{4}-\d\d-\d\dT/);

  // The CLI path calls that seam, and importing the script does not run it.
  const source = readFileSync(join(REPO, "scripts", "reset-password.js"), "utf8");
  assert.match(source, /from "\.\.\/servers\/gateway\/dashboard\/password-set-marker\.js"/, "imports the marker module");
  assert.match(source, /writePasswordSetMarker\(/, "calls it after the INSERT");
  assert.match(source, /await writePasswordRecord\(dbPath, hash\)/, "main() writes through the seam");
  assert.match(source, /if \(invokedDirectly\)/, "and the prompts only run when the script is the program");
});

// --- the CLI itself, run the way an operator runs it ----------------------

test("`node <symlink to reset-password.js>` reaches the prompts: a symlinked path is still the program", () => {
  // Regression: import.meta.url is the REAL path, so comparing it with
  // resolve(argv[1]) made a symlinked invocation do nothing at all and exit 0.
  const binDir = join(dir, "bin");
  mkdirSync(binDir, { recursive: true });
  const link = join(binDir, "reset-password.js");
  symlinkSync(join(REPO, "scripts", "reset-password.js"), link);
  // CROW_DB_PATH satisfies resolveDbPath() without a database: the prompts are
  // reached before any DB write, which is exactly what this test observes.
  const env = { ...process.env, CROW_HOME: HOME, CROW_DB_PATH: join(dir, "cli-crow.db") };

  // stdin closed: main() has already printed its banner and reached the first
  // prompt (the question is written before an answer is required).
  const closed = spawnSync(process.execPath, [link], { env, input: "", encoding: "utf8" });
  assert.equal(closed.status, 0, closed.stderr);
  assert.match(closed.stdout, /Crow's Nest — Password Reset/, "main() ran");
  assert.match(closed.stdout, /New password \(12\+ characters\): /, "and reached the password prompt");

  // A too-short answer takes main() to its own validation exit (non-zero) —
  // a script that never ran exits 0 and prints nothing.
  const short = spawnSync(process.execPath, [link], { env, input: "short\n", encoding: "utf8" });
  assert.equal(short.status, 1, short.stdout + short.stderr);
  assert.match(short.stderr, /Password must be at least 12 characters\./, "the real validation branch ran");

  // The same script through its real path behaves identically (no regression
  // for `npm run reset-password`).
  const direct = spawnSync(process.execPath, [join(REPO, "scripts", "reset-password.js")], { env, input: "short\n", encoding: "utf8" });
  assert.equal(direct.status, 1, direct.stdout + direct.stderr);
  assert.match(direct.stdout, /New password \(12\+ characters\): /);
});

// --- no regression: a real first run still offers setup ---------------------

test("a true first run (no row, no marker) still offers setup, loopback sets the password, and the marker appears", async () => {
  await deletePasswordRow();
  removeMarker();
  assert.equal(await isPasswordSet(), false, "a genuine first run");
  assert.equal(hasPasswordSetMarker(), false);

  const login = await (await get("/dashboard/login")).text();
  assert.ok(offersSetup(login), "the setup form is offered (unchanged)");

  const set = await post("/dashboard/login", { password: PW, confirm: PW });
  assert.equal(set.status, 303, (await set.text()).slice(0, 200));
  assert.equal(await hasPasswordRow(), true, "the first password was written");
  assert.equal(existsSync(MARKER), true, "and the first password records the marker");

  const signedIn = await post("/dashboard/login", { password: PW });
  assert.equal(signedIn.status, 303, "the ordinary login still works");
});

// --- boot catch-up for installs that predate the marker --------------------

test("boot catch-up: row present and no marker → the marker is written once; a second boot leaves it alone", async () => {
  const bootHome = join(dir, "boot-home");
  mkdirSync(bootHome, { recursive: true });
  const marker = passwordSetMarkerPath(bootHome);
  assert.equal(existsSync(marker), false);
  // The DB has a password row and (in this home) no marker: an install that set
  // its password before the marker existed.
  await db.execute("INSERT INTO dashboard_settings (key, value, updated_at) VALUES ('password_hash', 'not-a-real-hash', datetime('now')) ON CONFLICT(key) DO UPDATE SET value = excluded.value");
  assert.equal(await hasPasswordRow(), true, "the scratch DB has a password row");

  const lines = [];
  const line = await bootPasswordSetMarker({ crowHome: bootHome, log: (l) => lines.push(l) });
  assert.equal(line, "[auth] recorded that a dashboard password is set", "one log line");
  assert.deepEqual(lines, [line]);
  assert.equal(existsSync(marker), true, "the marker now exists");
  assert.equal(statSync(marker).mode & 0o777, 0o600);

  const first = readFileSync(marker, "utf8");
  const before = statSync(marker).mtimeMs;
  const again = [];
  assert.equal(await bootPasswordSetMarker({ crowHome: bootHome, log: (l) => again.push(l) }), null, "silent the second time");
  assert.equal(again.length, 0);
  assert.equal(readFileSync(marker, "utf8"), first, "not rewritten");
  assert.equal(statSync(marker).mtimeMs, before, "mtime unchanged");

  // No row, no marker: nothing to record (a real first run keeps its setup page).
  const freshHome = join(dir, "boot-home-first-run");
  mkdirSync(freshHome, { recursive: true });
  assert.equal(await bootPasswordSetMarker({ crowHome: freshHome, hasPasswordRow: async () => false }), null);
  assert.equal(existsSync(passwordSetMarkerPath(freshHome)), false);

  // A row that cannot be read writes nothing (a marker written by mistake on a
  // fresh install would lock first-run setup for good).
  const brokenHome = join(dir, "boot-home-broken");
  mkdirSync(brokenHome, { recursive: true });
  assert.equal(await bootPasswordSetMarker({ crowHome: brokenHome, hasPasswordRow: async () => { throw new Error("db is gone"); } }), null);
  assert.equal(existsSync(passwordSetMarkerPath(brokenHome)), false);
});

test("bootSetupToken does not mint a setup token when the row is gone but the marker is there", async () => {
  const { bootSetupToken, setupTokenPath, clearSetupToken } = await import("../servers/gateway/dashboard/setup-token.js");
  const home = join(dir, "boot-setup-token-home");
  mkdirSync(home, { recursive: true });
  writePasswordSetMarker({ crowHome: home });
  clearSetupToken({ crowHome: home });
  await deletePasswordRow();

  const lines = [];
  const line = await bootSetupToken({ crowHome: home, isPasswordSet, log: (l) => lines.push(l) });
  assert.equal(line, null, "nothing announced");
  assert.equal(lines.length, 0);
  assert.equal(existsSync(setupTokenPath({ crowHome: home })), false, "no token file was minted");

  // And isPasswordSet (which bootSetupToken reads) is the reason.
  assert.equal(await isPasswordSet(), true);
});

// --- the other password_hash readers fail closed on a missing row ----------

test("step-up refuses when the row is gone: nothing can be granted without a password", async () => {
  await deletePasswordRow();
  const gate = createStepUpGate();
  const result = await gate.verify("a-dashboard-session-token", { password: PW });
  assert.equal(result.ok, false, "no grant");
  assert.equal(result.unavailable, true, "the gate says its method is unavailable, not that the password matched");
  assert.equal(result.method, "none");

  // Positive control: with the row back, the same gate grants on the password.
  await setPassword(PW);
  const good = await createStepUpGate().verify("a-dashboard-session-token", { password: PW });
  assert.equal(good.ok, true);
  assert.equal(good.method, "password");
});

test("Settings → Change Password refuses when the row is gone instead of skipping the current-password check", async () => {
  await setPassword(PW);
  await deletePasswordRow();

  const redirects = [];
  const res = { redirectAfterPost: (url) => redirects.push(url) };
  const handled = await passwordSection.handleAction({
    req: { body: { current_password: "", password: "attacker picked this", confirm: "attacker picked this" } },
    res,
    db,
    action: "change_password",
  });
  assert.equal(handled, true);
  assert.deepEqual(redirects, ["/dashboard/settings?section=password&error=wrong_current"], "the existing wrong-current-password message");
  assert.equal(await hasPasswordRow(), false, "no new password row was written");

  // Positive control: with the row there and the right current password, the
  // change goes through exactly as before.
  await setPassword(PW);
  const okRedirects = [];
  const okRes = { redirectAfterPost: (url) => okRedirects.push(url) };
  await passwordSection.handleAction({
    req: { body: { current_password: PW, password: "a different password entirely", confirm: "a different password entirely" } },
    res: okRes,
    db,
    action: "change_password",
  });
  assert.deepEqual(okRedirects, ["/dashboard/settings?section=password&success=password"]);
  assert.equal(await isPasswordSet(), true);
  assert.equal(hasPasswordSetMarker(), true);

  // Wrong current password, row present: still refused, as before.
  const wrongRedirects = [];
  await passwordSection.handleAction({
    req: { body: { current_password: "not the password", password: "another password value", confirm: "another password value" } },
    res: { redirectAfterPost: (url) => wrongRedirects.push(url) },
    db,
    action: "change_password",
  });
  assert.deepEqual(wrongRedirects, ["/dashboard/settings?section=password&error=wrong_current"]);
});