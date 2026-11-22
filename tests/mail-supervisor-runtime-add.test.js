// A mail account added at RUNTIME — after `start()` — is first touched by `syncNow(id)`, which is the
// path `POST /dashboard/mail/api/accounts` takes (`startBackgroundSync` in routes/mail-api.js). That
// path reaches a worker through `prepare()`/`workerFor()`, never through `startAccount()`/`startWorker()`,
// so this file pins the one thing an account start() found and an account added later must share: it
// ends up in the same "watching" state — its IDLE watch armed and its poll timer scheduled — with no
// gateway restart.
//
// The observables are the ones tests/mail-supervisor.test.js already uses for a start()-time account:
// `supervisor.status(id).watching` (the worker holds a watcher), a delivered message reaching the store
// with no restart and no clock advance (only the IDLE watch can bring it in), and a non-idle folder
// being listed once the fake clock passes POLL_MS (only the poll timer can ask for it).
//
// Everything runs on a scratch DB built from MAIL_DDL, an in-memory fake mailbox and a fake clock whose
// timers the test fires by hand, so nothing here waits on real time.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDbClient } from "../servers/db.js";
import { MAIL_DDL, MAIL_ACCOUNT_SEND_COLUMNS } from "../servers/shared/mail-schema.js";
import { createAccount, listAccounts } from "../servers/gateway/mail/store/accounts.js";
import { MailError } from "../servers/gateway/mail/errors.js";
import { createFakeMailAdapter } from "./fixtures/fake-mail-adapter.mjs";
import { makeRaw } from "./fixtures/fake-mail-server.mjs";
import { POLL_MS, createMailSupervisor } from "../servers/gateway/mail/sync/supervisor.js";

const T0 = Date.UTC(2026, 1, 9, 12, 0, 0);

const dirs = [];
after(() => {
  for (const dir of dirs) rmSync(dir, { recursive: true, force: true });
});

/** Let every pending promise, db call and timer callback settle. */
async function flush(rounds = 200) {
  for (let i = 0; i < rounds; i += 1) await new Promise((resolve) => setImmediate(resolve));
}

/** A clock whose timers only fire when the test advances it. */
function makeClock(start = T0) {
  const timers = new Map();
  let current = start;
  let seq = 0;
  return {
    now: () => current,
    setTimer(fn, ms) {
      seq += 1;
      timers.set(seq, { fn, at: current + Math.max(0, Number(ms) || 0) });
      return seq;
    },
    clearTimer(handle) {
      timers.delete(handle);
    },
    /** Fire every timer due within `ms`, earliest first, and settle everything it starts. */
    async advance(ms) {
      const target = current + ms;
      for (;;) {
        await flush();
        let due = null;
        for (const entry of timers) {
          if (entry[1].at > target) continue;
          if (due == null || entry[1].at < due[1].at || (entry[1].at === due[1].at && entry[0] < due[0])) {
            due = entry;
          }
        }
        if (due == null) break;
        timers.delete(due[0]);
        if (due[1].at > current) current = due[1].at;
        due[1].fn();
      }
      current = target;
      await flush();
    },
  };
}

/**
 * One connection over the shared fake mailbox: a fresh view per `adapterFactory` call, so a reconnect
 * is a new object over the same mail. `close()` ends the view, never the mailbox beneath it.
 */
function adapterView(fake) {
  let closed = false;
  const open = () => {
    if (closed) throw new MailError("PROTOCOL", "closed");
  };
  return {
    async connect() {
      open();
      await fake.connect();
    },
    async close() {
      closed = true;
    },
    async listFolders() {
      open();
      return fake.listFolders();
    },
    async list(folderPath, options) {
      open();
      return fake.list(folderPath, options);
    },
    async get(folderPath, uids) {
      open();
      return fake.get(folderPath, uids);
    },
    async search(query, options) {
      open();
      return fake.search(query, options);
    },
    async watch(folderPaths, handlers) {
      open();
      return fake.watch(folderPaths, handlers);
    },
  };
}

const listCount = (fake, path) => fake.calls.filter((call) => call.method === "list" && call.args[0] === path).length;

async function messageCount(db, accountId) {
  const { rows } = await db.execute({
    sql: "SELECT COUNT(*) AS n FROM mail_messages WHERE account_id = ?",
    args: [accountId],
  });
  return Number(rows[0].n);
}

/** One scratch DB, one fake mailbox, one clock and one supervisor started with NO accounts. */
async function setup() {
  const dir = mkdtempSync(join(tmpdir(), "crow-mail-runtime-add-"));
  dirs.push(dir);
  const db = createDbClient(join(dir, "crow.db"));
  await db.executeMultiple(MAIL_DDL);
  for (const spec of MAIL_ACCOUNT_SEND_COLUMNS) {
    await db.execute({ sql: `ALTER TABLE ${spec.table} ADD COLUMN ${spec.column} ${spec.definition}`, args: [] });
  }

  const clock = makeClock(T0);
  const fake = createFakeMailAdapter({ now: clock.now });
  const supervisor = createMailSupervisor({
    db,
    credentials: { async getSecrets() { return { password: "runtime-add-secret" }; } },
    adapterFactory: async () => adapterView(fake),
    now: clock.now,
    setTimer: clock.setTimer,
    clearTimer: clock.clearTimer,
    random: () => 0.5,
    notify: async () => {},
    log: () => {},
    isClaimedElsewhere: async () => false,
    refreshClaim: async () => {},
  });

  // The boot shape this test is about: a running supervisor that found no accounts to start.
  await supervisor.start();
  assert.equal((await listAccounts(db)).length, 0, "start() ran before any account existed");

  return { db, clock, fake, supervisor };
}

const deliver = (fake, mailbox, subject) => fake.deliver(mailbox, makeRaw({ subject }), { internalDate: T0 });

const NEW_ACCOUNT = {
  address: "alex@example.com",
  label: "Alex",
  imap: { host: "mail.example.test", port: 993, security: "ssl" },
  smtp: { host: "mail.example.test", port: 587, security: "starttls" },
};

test("an account added after start() keeps syncing on its own: IDLE watch and poll, no restart", async () => {
  const h = await setup();

  const account = await createAccount(h.db, NEW_ACCOUNT);
  deliver(h.fake, "INBOX", "first");
  // What `startBackgroundSync` does on POST /accounts: one manual sync, not a start for this worker.
  await h.supervisor.syncNow(account.id);
  await flush();

  assert.equal(await messageCount(h.db, account.id), 1, "the first sync stored the message that was waiting");

  const status = await h.supervisor.status(account.id);
  assert.equal(
    status.watching,
    true,
    "an account added at runtime is watched over IDLE after its first sync, exactly like one start() found",
  );

  // Nothing but the IDLE watch can bring this one in: no restart, no clock advance, no manual sync.
  deliver(h.fake, "INBOX", "second");
  await flush();
  assert.equal(
    await messageCount(h.db, account.id),
    2,
    "a message delivered after the first sync is fetched by the IDLE watch, with no restart",
  );

  // And the poll is scheduled: one interval later the non-idle folders are refreshed (tick 1 syncs only
  // those), which nothing but that worker's own poll timer does.
  const draftsBefore = listCount(h.fake, "Drafts");
  await h.clock.advance(POLL_MS);
  assert.ok(
    listCount(h.fake, "Drafts") > draftsBefore,
    "the poll timer is scheduled for an account added at runtime, so its other folders are refreshed",
  );

  await h.supervisor.stop();
});

test("restartAccount keeps a runtime-added account watching and polling", async () => {
  const h = await setup();

  const account = await createAccount(h.db, NEW_ACCOUNT);
  deliver(h.fake, "INBOX", "first");
  await h.supervisor.syncNow(account.id);
  await flush();

  // The owner re-entered the app password: the same preparation a manual sync does, on a fresh secret.
  await h.supervisor.restartAccount(account.id);
  await flush();

  assert.equal(
    (await h.supervisor.status(account.id)).watching,
    true,
    "restartAccount leaves the worker watching, as the syncNow path it shares must",
  );

  deliver(h.fake, "INBOX", "after restart");
  await flush();
  assert.equal(
    await messageCount(h.db, account.id),
    2,
    "a message delivered after a restart is fetched by the IDLE watch, with no further restart",
  );

  const draftsBefore = listCount(h.fake, "Drafts");
  await h.clock.advance(POLL_MS);
  assert.ok(
    listCount(h.fake, "Drafts") > draftsBefore,
    "the poll timer is scheduled after a restartAccount",
  );

  await h.supervisor.stop();
});