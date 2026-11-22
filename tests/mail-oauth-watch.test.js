/**
 * Crow Mail's reconnect watch (plan 5, Task 6): the weekly "Reconnect" before a Testing-mode Google
 * grant's refresh token lapses, and the words it carries.
 *
 * Three kinds of check, none of them a screenshot:
 *
 *   - the PREDICATE: `dueForReconnect` is true only for a Google grant whose app is in Testing (or was
 *     not told) and older than five days — never for a published app, never for Microsoft, never for a
 *     grant that was just renewed.
 *   - the BELL: the scheduler tick rings once per grant, with the approved title (C27) and `source:
 *     "mail"`, and neither a repeated tick nor a restart rings it again; a new `grantedAt` re-arms it;
 *     a `createNotification` answering null is tolerated; the text carries no address.
 *   - the COPY: every sentence this task adds is the operator-approved row (C27, C28, C29) verbatim,
 *     in both languages, taken from the central i18n table.
 *
 * The harness is a scratch crow.db built by `scripts/init-db.js` and copied per test (CROW_DATA_DIR /
 * CROW_HOME in a temp dir, so nothing can touch a real `~/.crow`), the real account store, the real
 * oauth meta store (a local-scope dashboard setting), the real scheduler-hook registry and the real
 * `createNotification` over the real `notifications` table. A clock the test moves by hand decides
 * every "day". No address at a personal mail domain appears: the mailboxes here are example.test.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "mail-oauth-watch-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
process.env.CROW_DISABLE_INSTANCE_SYNC = "1";
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");

const { createDbClient } = await import("../servers/db.js");
const { createAccount, getAccount, updateAccount } = await import("../servers/gateway/mail/store/accounts.js");
const { setOauthMeta } = await import("../servers/gateway/mail/oauth/meta.js");
const { createNotification } = await import("../servers/shared/notifications.js");
const { getSchedulerHook, runSchedulerHooks, unregisterSchedulerHook } =
  await import("../servers/gateway/scheduler-hooks.js");
const {
  MAIL_OAUTH_WATCH_HOOK_ID,
  MAIL_OAUTH_WATCH_SETTING,
  MAIL_SETTINGS_VIEW_HREF,
  OAUTH_SIGN_IN_STOPPED_TEXT,
  REAUTH_BELL_TITLE,
  REAUTH_WARN_AFTER_MS,
  TESTING_TOKEN_LIFE_MS,
  dueForReconnect,
  oauthProviderOf,
  registerOauthWatchHook,
  sweepReconnects,
} = await import("../servers/gateway/mail/oauth/watch.js");
const { translations } = await import("../servers/gateway/dashboard/shared/i18n.js");

const DAY = 24 * 3600 * 1000;
const T0 = Date.UTC(2026, 0, 5, 12, 0, 0);
const ADDRESS = "alex@example.test";
const IMAP = { host: "mail.example.test", port: 993, security: "ssl" };
const SMTP = { host: "mail.example.test", port: 465, security: "ssl" };

/** The operator-approved rows this task shows (C27, C28, C29 of the approved copy file). */
const APPROVED = {
  bellTitle: "Reconnect Gmail to keep mail syncing", // C27 (en)
  reconnectSoon: [
    "Google will end this sign-in soon.",
    "Google cerrará pronto este inicio de sesión.",
  ],
  reconnect: ["Reconnect", "Volver a conectar"],
  signInStopped: "The sign-in for this account stopped working. Reconnect to keep mail syncing.", // C29 (en)
  signInStoppedEs: "El inicio de sesión de esta cuenta dejó de funcionar. Vuelve a conectar para seguir sincronizando el correo.",
};

const open = [];
after(() => {
  unregisterSchedulerHook(MAIL_OAUTH_WATCH_HOOK_ID);
  for (const client of open) { try { client.close(); } catch { /* closed */ } }
  rmSync(root, { recursive: true, force: true });
});

before(() => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
});

let n = 0;

/** One scratch crow.db (a copy of the schema) and one hand-moved clock. */
function scratch() {
  const dir = join(root, "t" + (++n));
  mkdirSync(dir);
  const file = join(dir, "crow.db");
  copyFileSync(MASTER, file);
  process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");
  const db = createDbClient(file);
  open.push(db);
  const clock = { at: T0, now() { return clock.at; } };
  return { db, clock };
}

/** An XOAUTH2 Google account with a grant recorded at `grantedAt`. */
async function googleAccount(db, { grantedAt = T0, publishing = "testing", provider = "google", address = ADDRESS } = {}) {
  const account = await createAccount(db, {
    label: "Personal", address, username: address, authKind: "xoauth2",
    provider: provider === "google" ? "gmail" : "outlook", imap: IMAP, smtp: SMTP,
  });
  await setOauthMeta(db, account.id, { grantedAt, publishing, provider });
  return account;
}

/** Every bell row, newest last: the title, the body and the source it was written with. */
async function bellRows(db) {
  const { rows } = await db.execute({
    sql: "SELECT title, body, source, type, action_url FROM notifications ORDER BY id ASC",
    args: [],
  });
  return rows.map((row) => ({
    title: row.title,
    body: row.body ?? null,
    source: row.source,
    type: row.type,
    actionUrl: row.action_url ?? null,
  }));
}

/* ------------------------------------------------------------------ constants */

test("the watch's two clocks are the plan's, and today's bell/hook names are the fixed ones", () => {
  assert.equal(REAUTH_WARN_AFTER_MS, 5 * DAY);
  assert.equal(TESTING_TOKEN_LIFE_MS, 7 * DAY);
  assert.equal(REAUTH_WARN_AFTER_MS < TESTING_TOKEN_LIFE_MS, true, "the reminder comes before the lapse");
  assert.equal(MAIL_OAUTH_WATCH_HOOK_ID, "mail-oauth-watch");
  assert.equal(MAIL_OAUTH_WATCH_SETTING, "mail_oauth_reconnect_rung");
  assert.equal(MAIL_SETTINGS_VIEW_HREF, "/dashboard/mail?view=settings");
  // C27 and C29, the approved file's own English rows.
  assert.equal(REAUTH_BELL_TITLE, APPROVED.bellTitle);
  assert.equal(OAUTH_SIGN_IN_STOPPED_TEXT, APPROVED.signInStopped);
});

/* ---------------------------------------------------------------- the predicate */

test("dueForReconnect: day 4 is quiet, day 5 is due, and a renewed grant re-arms it", () => {
  const meta = { grantedAt: T0, publishing: "testing", provider: "google" };

  assert.equal(dueForReconnect(meta, T0 + 4 * DAY), false, "day 4: two days are left, nothing to say yet");
  assert.equal(dueForReconnect(meta, T0 + 5 * DAY - 1), false, "one millisecond short of five days");
  assert.equal(dueForReconnect(meta, T0 + 5 * DAY), true, "day 5: the reminder is due");
  assert.equal(dueForReconnect(meta, T0 + 8 * DAY), true, "past the lapse it is still true until reconnected");

  // A reconnect records a fresh grant, which is not due again for another five days.
  const renewed = { grantedAt: T0 + 8 * DAY, publishing: "testing", provider: "google" };
  assert.equal(dueForReconnect(renewed, T0 + 8 * DAY), false, "a new grantedAt re-arms the clock");
  assert.equal(dueForReconnect(renewed, T0 + 13 * DAY), true, "and rings again five days later");

  // The clock may be a function (the hook's own seam).
  assert.equal(dueForReconnect(meta, () => T0 + 5 * DAY), true);

  // `unknown` publishing is due: Crow was not told, so it must not assume the app is published.
  assert.equal(dueForReconnect({ grantedAt: T0, publishing: "unknown", provider: "google" }, T0 + 5 * DAY), true);
  assert.equal(dueForReconnect({ grantedAt: T0, provider: "google" }, T0 + 5 * DAY), true, "no publishing reads as unknown");
});

test("dueForReconnect: production, Microsoft, no grant and a bad label are all quiet", () => {
  const at = T0 + 30 * DAY;
  assert.equal(dueForReconnect({ grantedAt: T0, publishing: "production", provider: "google" }, at), false, "a published app never expires the grant");
  assert.equal(dueForReconnect({ grantedAt: T0, publishing: "testing", provider: "microsoft" }, at), false, "Microsoft has no such expiry");
  assert.equal(dueForReconnect(null, at), false, "no grant recorded");
  assert.equal(dueForReconnect(undefined, at), false);
  assert.equal(dueForReconnect({}, at), false, "nothing known");
  assert.equal(dueForReconnect({ grantedAt: null, publishing: "testing", provider: "google" }, at), false);
  assert.equal(dueForReconnect({ grantedAt: "yesterday", publishing: "testing", provider: "google" }, at), false);
  assert.equal(dueForReconnect({ grantedAt: T0, publishing: "testing", provider: "google" }, "now"), false, "a nonsense clock is not a prompt");
  assert.deepEqual([oauthProviderOf("gmail"), oauthProviderOf("outlook"), oauthProviderOf(null), oauthProviderOf("other")],
    ["google", "microsoft", null, null]);
});

/* -------------------------------------------------------------------- the bell */

test("day 4 rings nothing; day 5 rings one bell with C27 and no address in it", async () => {
  const { db, clock } = scratch();
  const account = await googleAccount(db, { grantedAt: T0 });

  clock.at = T0 + 4 * DAY;
  assert.deepEqual(await sweepReconnects(db, { now: clock.now }), { reminders: 0 });
  assert.deepEqual(await bellRows(db), [], "day 4: no bell at all");

  clock.at = T0 + 5 * DAY;
  assert.deepEqual(await sweepReconnects(db, { now: clock.now }), { reminders: 1 });
  const rows = await bellRows(db);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].title, APPROVED.bellTitle, "C27 exactly");
  assert.equal(rows[0].body, null, "no body: the approved row is the title alone");
  assert.equal(rows[0].source, "mail");
  assert.equal(rows[0].type, "system");
  assert.equal(rows[0].actionUrl, MAIL_SETTINGS_VIEW_HREF, "the bell lands on the page with the button");
  for (const text of [rows[0].title, rows[0].body ?? ""]) {
    assert.equal(text.includes(ADDRESS), false, "the bell carries no address");
    assert.equal(text.includes("example.test"), false, "no host or domain either");
  }
  assert.equal((await getAccount(db, account.id)).status, "active", "the account is not marked by the reminder");
});

test("a repeated tick, a fresh registration and a simulated restart do not ring the same grant twice", async () => {
  const { db, clock } = scratch();
  const account = await googleAccount(db, { grantedAt: T0 });
  clock.at = T0 + 5 * DAY;

  assert.deepEqual(await sweepReconnects(db, { now: clock.now }), { reminders: 1 });
  for (let i = 0; i < 3; i += 1) {
    assert.deepEqual(await sweepReconnects(db, { now: clock.now }), { reminders: 0 }, "a tick every minute says it once");
  }
  assert.equal((await bellRows(db)).length, 1);

  // A restart: the scheduler registry is emptied and the hook is registered again over the same db.
  unregisterSchedulerHook(MAIL_OAUTH_WATCH_HOOK_ID);
  registerOauthWatchHook(db, { now: clock.now });
  await runSchedulerHooks("tick", db);
  assert.equal((await bellRows(db)).length, 1, "the fact lives in the database, not in the process");

  // The record is this instance's local-scope setting, keyed by the account's grant.
  const stored = await db.execute({
    sql: "SELECT value FROM dashboard_settings_overrides WHERE key = ?",
    args: [MAIL_OAUTH_WATCH_SETTING],
  });
  assert.equal(stored.rows.length, 1, "one local row, so it never travels to a paired Crow");
  assert.deepEqual(JSON.parse(stored.rows[0].value), { [account.id]: T0 });
  unregisterSchedulerHook(MAIL_OAUTH_WATCH_HOOK_ID);
});

test("a reconnect (a new grantedAt) re-arms the reminder for the next grant", async () => {
  const { db, clock } = scratch();
  const account = await googleAccount(db, { grantedAt: T0 });
  clock.at = T0 + 5 * DAY;
  assert.deepEqual(await sweepReconnects(db, { now: clock.now }), { reminders: 1 });

  // The person pressed Reconnect: the callback records the new grant's grantedAt.
  await setOauthMeta(db, account.id, { grantedAt: clock.at, publishing: "testing", provider: "google" });
  assert.deepEqual(await sweepReconnects(db, { now: clock.now }), { reminders: 0 }, "a fresh grant is quiet");
  assert.equal((await bellRows(db)).length, 1);

  clock.at = T0 + 10 * DAY + 1;
  assert.deepEqual(await sweepReconnects(db, { now: clock.now }), { reminders: 1 }, "five days after the new grant, once more");
  assert.equal((await bellRows(db)).length, 2);
});

test("production-published, Microsoft and password accounts are never prompted", async () => {
  const { db, clock } = scratch();
  const published = await createAccount(db, {
    label: "Work", address: "sam@example.test", username: "sam@example.test", authKind: "xoauth2",
    provider: "gmail", imap: IMAP, smtp: SMTP,
  });
  await setOauthMeta(db, published.id, { grantedAt: T0, publishing: "production", provider: "google" });

  const microsoft = await createAccount(db, {
    label: "Outlook", address: "jo@example.test", username: "jo@example.test", authKind: "xoauth2",
    provider: "outlook", imap: IMAP, smtp: SMTP,
  });
  await setOauthMeta(db, microsoft.id, { grantedAt: T0, publishing: "testing", provider: "microsoft" });

  await createAccount(db, {
    label: "Password", address: "kim@example.test", username: "kim@example.test", authKind: "password",
    imap: IMAP, smtp: SMTP,
  });

  clock.at = T0 + 30 * DAY;
  assert.deepEqual(await sweepReconnects(db, { now: clock.now }), { reminders: 0 });
  assert.deepEqual(await bellRows(db), []);
});

test("an account another instance holds is not this box's reminder", async () => {
  const { db, clock } = scratch();
  const account = await googleAccount(db, { grantedAt: T0 });
  await updateAccount(db, account.id, { status: "claimed_elsewhere" });
  clock.at = T0 + 5 * DAY;
  assert.deepEqual(await sweepReconnects(db, { now: clock.now }), { reminders: 0 });
  assert.deepEqual(await bellRows(db), []);
});

test("a createNotification that answers null is tolerated, and still rung only once", async () => {
  const { db, clock } = scratch();
  await googleAccount(db, { grantedAt: T0 });
  clock.at = T0 + 5 * DAY;

  const calls = [];
  const ring = async (client, options) => {
    calls.push(options);
    return null;
  };
  assert.deepEqual(await sweepReconnects(db, { now: clock.now, createNotification: ring }), { reminders: 1 });
  assert.equal(calls.length, 1);
  assert.deepEqual(await sweepReconnects(db, { now: clock.now, createNotification: ring }), { reminders: 0 });
  assert.equal(calls.length, 1, "the switched-off type is not asked again");
  assert.deepEqual(await bellRows(db), [], "and no row was written");
});

test("the real createNotification, over the real table, writes the one bell", async () => {
  const { db, clock } = scratch();
  await googleAccount(db, { grantedAt: T0 });
  clock.at = T0 + 5 * DAY;
  assert.deepEqual(await sweepReconnects(db, { now: clock.now, createNotification }), { reminders: 1 });
  const rows = await bellRows(db);
  assert.equal(rows.length, 1);
  assert.equal(rows[0].title, APPROVED.bellTitle);
});

/* -------------------------------------------------------------------- the hook */

test("the hook registers under its own id, does the work on a tick, and unregisters", async () => {
  const { db, clock } = scratch();
  await googleAccount(db, { grantedAt: T0 });
  clock.at = T0 + 5 * DAY;

  const hook = registerOauthWatchHook(db, { now: clock.now });
  assert.equal(typeof getSchedulerHook(MAIL_OAUTH_WATCH_HOOK_ID)?.tick, "function");
  await runSchedulerHooks("tick", db);
  assert.equal((await bellRows(db)).length, 1);

  hook.unregister();
  assert.equal(getSchedulerHook(MAIL_OAUTH_WATCH_HOOK_ID), undefined);
});

test("a failing sweep is one coded line and never error text", async () => {
  const lines = [];
  const original = console.warn;
  console.warn = (...args) => { lines.push(args.map((a) => String(a)).join(" ")); };
  try {
    const hook = registerOauthWatchHook({
      async execute() { throw new Error(`SQLITE_BUSY: ${ADDRESS}`); },
    }, { now: () => T0 + 5 * DAY });
    const answer = await getSchedulerHook(MAIL_OAUTH_WATCH_HOOK_ID).tick();
    assert.equal(answer, null, "a failed sweep answers null");
    assert.equal(lines.length, 1);
    assert.match(lines[0], /\[mail-oauth-watch\] sweep_failed /);
    assert.equal(lines[0].includes(ADDRESS), false, "a database's message is not logged");
    hook.unregister();
  } finally {
    console.warn = original;
  }
});

/* -------------------------------------------------------------------- the copy */

test("the reconnect copy is the approved C28/C29, in both languages, from the i18n table", () => {
  assert.deepEqual(translations["mail.wizard.reconnectSoon"], {
    en: APPROVED.reconnectSoon[0],
    es: APPROVED.reconnectSoon[1],
  });
  assert.deepEqual(translations["mail.wizard.reconnect"], {
    en: APPROVED.reconnect[0],
    es: APPROVED.reconnect[1],
  });
  assert.deepEqual(translations["mail.statusAuthFailedOauth"], {
    en: APPROVED.signInStopped,
    es: APPROVED.signInStoppedEs,
  });
  for (const key of ["mail.wizard.reconnectSoon", "mail.wizard.reconnect", "mail.statusAuthFailedOauth"]) {
    assert.notEqual(translations[key].en, translations[key].es, `${key}: the Spanish is its own sentence`);
  }
});