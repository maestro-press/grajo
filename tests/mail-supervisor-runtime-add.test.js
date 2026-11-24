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

/** The `listAccounts` SELECT `start()` begins with: the one statement `listingFails` makes throw. */
const FROM_ACCOUNT_LISTING = /\bFROM\s+mail_accounts\s+ORDER\s+BY\b/;

/** One scratch DB, one fake mailbox, one clock and one supervisor, NOT started yet.
 *
 * `pollArms` collects the source of every timer armed for exactly POLL_MS. The global claim tick
 * shares that interval, so the callback tells them apart: only a worker's own poll arms one that runs
 * `pollTick`. `isClaimedElsewhere` is a seam for the test that needs start()'s claim read to fail,
 * and `listingFails` one for the test that needs the account listing start() begins with to fail (as
 * a busy database answers it): every other statement, the sync's own reads and writes included, is
 * left alone. */
async function createHarness({ pollArms = null, isClaimedElsewhere = async () => false, listingFails = false } = {}) {
  const dir = mkdtempSync(join(tmpdir(), "crow-mail-runtime-add-"));
  dirs.push(dir);
  const db = createDbClient(join(dir, "crow.db"));
  await db.executeMultiple(MAIL_DDL);
  for (const spec of MAIL_ACCOUNT_SEND_COLUMNS) {
    await db.execute({ sql: `ALTER TABLE ${spec.table} ADD COLUMN ${spec.column} ${spec.definition}`, args: [] });
  }

  // What the supervisor itself reads through: the seam fails ONLY the account listing, so a test can
  // see what a start whose `startAccount` pass covered nothing still arms.
  const supervisorDb = listingFails
    ? {
        ...db,
        async execute(arg) {
          if (FROM_ACCOUNT_LISTING.test(String(arg?.sql ?? arg))) throw new Error("database is locked");
          return db.execute(arg);
        },
      }
    : db;

  const clock = makeClock(T0);
  const fake = createFakeMailAdapter({ now: clock.now });
  const setTimer = (fn, ms) => {
    if (pollArms && ms === POLL_MS) pollArms.push(String(fn));
    return clock.setTimer(fn, ms);
  };
  const supervisor = createMailSupervisor({
    db: supervisorDb,
    credentials: { async getSecrets() { return { password: "runtime-add-secret" }; } },
    adapterFactory: async () => adapterView(fake),
    now: clock.now,
    setTimer,
    clearTimer: clock.clearTimer,
    random: () => 0.5,
    notify: async () => {},
    log: () => {},
    isClaimedElsewhere,
    refreshClaim: async () => {},
  });

  return { db, clock, fake, supervisor };
}

/** The boot shape most tests are about: a running supervisor that found no accounts to start. */
async function setup() {
  const h = await createHarness();
  await h.supervisor.start();
  assert.equal((await listAccounts(h.db)).length, 0, "start() ran before any account existed");
  return h;
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
// The residual this file's fix closes: `armPoll` arms only when the supervisor is `running()`
// (started && !stopped), while a run's watch and the run itself only need `live()`. A `syncNow` that
// lands BEFORE `start()` — a gateway whose boot has not reached the supervisor, the CLI hook's
// `syncNow` racing that boot — therefore arms the IDLE watch but silently drops the poll. `start()`
// remembers such a worker and arms its poll AFTER its own startAccount pass settled.
const isPollTickArm = (fn) => fn.includes("pollTick");

test("a poll asked for before start() is not armed while the claim stays unreadable", async () => {
  const pollArms = [];
  let claimReads = 0;
  const h = await createHarness({
    pollArms,
    // Unreadable for every read: start()'s startAccount cannot start the worker, and its short
    // re-check keeps saying so. `claimCheck` (the poll's own read) reads an unreadable claim as
    // "not claimed", so an armed poll WOULD sync here — which is exactly what must not happen.
    isClaimedElsewhere: async () => {
      claimReads += 1;
      throw new Error("claim store unreadable");
    },
  });

  const account = await createAccount(h.db, NEW_ACCOUNT);
  await h.supervisor.syncNow(account.id);
  await flush();

  assert.equal(
    (await h.supervisor.status(account.id)).watching,
    true,
    "syncNow before start() arms the IDLE watch (it only needs live())",
  );
  assert.equal(pollArms.some(isPollTickArm), false, "and it arms no poll yet: a supervisor that was never started may not poll");

  await h.supervisor.start();
  await flush();

  assert.ok(claimReads >= 1, "start() read the claim (and left the worker pending)");
  assert.equal(
    pollArms.some(isPollTickArm),
    false,
    "start() armed no poll for the worker it left pending on an unreadable claim",
  );

  const listsBefore = h.fake.calls.filter((call) => call.method === "list").length;
  await h.clock.advance(POLL_MS);
  assert.equal(
    h.fake.calls.filter((call) => call.method === "list").length,
    listsBefore,
    "one POLL_MS later, no sync ran for that worker: only the claim re-checks fired",
  );
  assert.equal(pollArms.some(isPollTickArm), false, "and the poll was never armed by a tick either");
  assert.ok(claimReads > 1, "the short claim re-check kept reading (and still could not answer)");

  await h.supervisor.stop();
});

// The same seam the other way round: the claim reads ours, so nothing holds the worker back and the
// poll the pre-start `syncNow` asked for must actually run. `start()`'s own `startAccount` pass would
// arm that poll itself, so this start's account listing is made to fail (a busy database): the pass
// then covers no worker at all, and the arm in start()'s `finally` — the part a `return` on a failed
// listing must not skip — is the ONLY thing that can arm the timer.
test("a poll asked for before start() is armed, and runs a pass, once the claim reads ours", async () => {
  const pollArms = [];
  const h = await createHarness({ pollArms, listingFails: true });

  const account = await createAccount(h.db, NEW_ACCOUNT);
  await h.supervisor.syncNow(account.id);
  await flush();

  assert.equal(
    (await h.supervisor.status(account.id)).watching,
    true,
    "syncNow before start() arms the IDLE watch (it only needs live())",
  );
  assert.equal(pollArms.some(isPollTickArm), false, "and arms no poll yet: a supervisor that was never started may not poll");

  await h.supervisor.start();
  await flush();

  assert.ok(
    pollArms.some(isPollTickArm),
    "start() armed the remembered poll, with no startAccount pass to arm one for this worker",
  );

  const draftsBefore = listCount(h.fake, "Drafts");
  await h.clock.advance(POLL_MS);
  assert.ok(
    listCount(h.fake, "Drafts") > draftsBefore,
    "one POLL_MS later that poll ran a pass for the account: its non-idle folders were listed",
  );

  await h.supervisor.stop();
});

// `stop()` must forget a remembered poll (the ARMING time is not the only gap: a gateway can stop and
// restart the supervisor). The account row is deleted first so start() has no startAccount pass that
// could arm a poll on its own — the remembered set is then the ONLY thing that could arm one.
test("stop() forgets a poll asked for before start(), so the next start() arms none", async () => {
  const pollArms = [];
  const h = await createHarness({ pollArms });

  const account = await createAccount(h.db, NEW_ACCOUNT);
  await h.supervisor.syncNow(account.id);
  await flush();
  assert.equal(pollArms.some(isPollTickArm), false, "a syncNow before start() remembers the poll, it does not arm it");

  await h.db.execute({ sql: "DELETE FROM mail_accounts WHERE id = ?", args: [account.id] });

  await h.supervisor.stop();
  await h.supervisor.start();
  await flush();

  assert.equal(pollArms.some(isPollTickArm), false, "stop() emptied the remembered set: no poll survives it");
  await h.clock.advance(POLL_MS);
  assert.equal(pollArms.some(isPollTickArm), false, "and nothing arms one later");

  await h.supervisor.stop();
});
