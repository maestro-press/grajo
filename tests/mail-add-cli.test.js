// tests/mail-add-cli.test.js
//
// `crow mail add` — scripts/cli/mail-add.js. Two halves, matching the two seams the script has:
//
//   - the exported core, `addMailAccount({db, input, password, adapterFactory, credentials,
//     localInstance, recordSecrets, dryRun})`, driven here the way tests/mail-api-accounts.test.js
//     drives POST /dashboard/mail/api/accounts: a real init-db'd scratch crow.db copied per test
//     (CROW_DATA_DIR / CROW_HOME in a temp dir — nothing can touch ~/.crow), the real account store,
//     the real keychain credentials and claim code, and a fake mail adapter;
//   - the script itself, spawned as a child process, to hold the promise the core cannot make: the
//     password never reaches argv, and never reaches stdout or stderr.
//
// No pi, no host config. The one socket the spawned run opens is a TCP connect to 127.0.0.1:1, which
// never answers — that is the point of it.

import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, statSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "mail-add-cli-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
// The script's first import is the gateway's .env + instance-path gate, so THIS process runs it too:
// point it at a scratch file that does not exist, so no checkout .env is ever applied here (or in a
// spawned run — spawnWorld sets the same for the children).
process.env.CROW_APP_ENV_PATH = join(root, "gateway.env");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");
const CLI = join(REPO, "scripts", "cli", "mail-add.js");

const { addMailAccount, readEnvFile, parseEnvValue, readLineFromStdin, MailCliError, EXIT, _reportForTest } = await import("../scripts/cli/mail-add.js");
const { createDbClient } = await import("../servers/db.js");
const { createKeychainKey, keychainKeyPath } = await import("../servers/gateway/keychain/key.js");
const { MailError } = await import("../servers/gateway/mail/errors.js");
const { createMailCredentials } = await import("../servers/gateway/mail/credentials.js");
const { checkClaim, claimKey, listClaims, releaseClaim, writeClaim } = await import("../servers/gateway/mail/claims.js");
const { createAccount, getAccount } = await import("../servers/gateway/mail/store/accounts.js");
const { createFakeMailAdapter } = await import("./fixtures/fake-mail-adapter.mjs");

const ADDRESS = "alex@example.com";
const PASSWORD = "hunter2-app-password";
const USERNAME = "alexuser";
const LOCAL = { instanceId: "instA", instanceName: "Delta" };
const PEER = "instB";

const ENDPOINT = { host: "imap.example.com", port: 993, security: "ssl" };
const SMTP_ENDPOINT = { host: "smtp.example.com", port: 465, security: "ssl" };
const INPUT = { label: "Personal", address: ADDRESS, username: USERNAME, imap: ENDPOINT, smtp: SMTP_ENDPOINT };

const open = [];
after(() => {
  for (const client of open) {
    try { client.close(); } catch { /* closed */ }
  }
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

/* ----------------------------------------------------------------- setup */

let n = 0;

/** One test's world: a fresh copy of the init-db'd crow.db, its own client and its own CROW_HOME. */
async function freshWorld() {
  const dir = join(root, "t" + (++n));
  mkdirSync(dir);
  const home = join(dir, "home");
  mkdirSync(home);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  open.push(db);
  return { db, crow, home, dir };
}

async function count(db, table) {
  const { rows } = await db.execute({ sql: `SELECT COUNT(*) AS n FROM ${table}`, args: [] });
  return Number(rows[0].n);
}

async function keychainRows(db, accountId) {
  const { rows } = await db.execute({
    sql: "SELECT id, kind, bundle_id, env_key, connection_uuid, secret_sealed FROM crow_keychain WHERE connection_uuid = ?",
    args: [accountId],
  });
  return rows;
}

/** Capture console.warn (the script's own log line) while `fn` runs. */
async function warnings(fn) {
  const lines = [];
  const original = console.warn;
  console.warn = (...args) => { lines.push(args.map((a) => String(a)).join(" ")); };
  try {
    return { lines, result: await fn() };
  } finally {
    console.warn = original;
  }
}

/** A working in-memory adapter, plus the factory calls, so a test can see whether anything dialled. */
function workingFactory() {
  const factoryCalls = [];
  const adapter = createFakeMailAdapter();
  const adapterFactory = (args) => {
    factoryCalls.push(args);
    return adapter;
  };
  return { adapterFactory, factoryCalls, adapter };
}

/** Credentials that record what was written and answer with what was saved. */
function fakeCredentials(saved = new Map()) {
  return {
    async saveSecret(accountId, envKey, secret) { saved.set(accountId, { envKey, secret }); return { id: 1, created: true }; },
    async getSecrets(accountId) {
      const row = saved.get(accountId);
      return row ? { [row.envKey]: row.secret } : {};
    },
    async deleteSecrets(accountId) { saved.delete(accountId); return { deleted: 1 }; },
    saved,
  };
}

/* -------------------------------------------------------------- the core */

test("the happy path: the account row, the sealed secret and the claim, in the route's order", async () => {
  const world = await freshWorld();
  const credentials = createMailCredentials({ db: world.db, crowHome: world.home });
  const recorded = [];
  const { adapterFactory, factoryCalls, adapter } = workingFactory();

  const result = await addMailAccount({
    db: world.db,
    input: INPUT,
    password: PASSWORD,
    adapterFactory,
    credentials,
    localInstance: LOCAL,
    recordSecrets: (values) => { recorded.push(values); },
  });

  assert.equal(result.outcome, "added", JSON.stringify(result));
  const id = result.account.id;
  assert.match(id, /^ma-[0-9a-f]{16}$/);
  assert.equal(JSON.stringify(result).includes(PASSWORD), false, "the outcome carries no password");

  // The row is the store's own, with the route's authKind and the endpooints as typed.
  const row = await getAccount(world.db, id);
  assert.equal(row.address, ADDRESS);
  assert.equal(row.username, USERNAME);
  assert.equal(row.authKind, "password");
  assert.equal(row.label, "Personal");
  assert.deepEqual(row.imap, ENDPOINT);
  assert.deepEqual(row.smtp, SMTP_ENDPOINT);

  // The secret is sealed under the mail bundle and reads back — and is in no column.
  const secrets = await keychainRows(world.db, id);
  assert.equal(secrets.length, 1);
  assert.equal(secrets[0].kind, "service");
  assert.equal(secrets[0].bundle_id, "crow-mail");
  assert.equal(secrets[0].env_key, "MAIL_PASSWORD");
  assert.equal(JSON.stringify(secrets).includes(PASSWORD), false, "the password is sealed, never a column");
  assert.deepEqual(await credentials.getSecrets(id), { MAIL_PASSWORD: PASSWORD });

  // The password joined the masking set before it was stored.
  assert.deepEqual(recorded, [[PASSWORD]]);

  // The probe ran against a row that had no id yet, and it connected and listed.
  assert.equal(factoryCalls.length, 1);
  assert.equal(factoryCalls[0].account.id, "probe", "the probe ran before the account row existed");
  assert.deepEqual(adapter.calls.map((call) => call.method), ["connect", "listFolders", "close"]);

  // The claim is this instance's, and the re-check passed.
  const claims = await listClaims(world.db, ADDRESS);
  assert.equal(claims.length, 1);
  assert.equal(claims[0].key, claimKey(ADDRESS, LOCAL.instanceId));
  assert.equal(claims[0].instanceName, LOCAL.instanceName);
  assert.equal(claims[0].released, false);
  assert.deepEqual(await checkClaim(world.db, ADDRESS, { localInstanceId: LOCAL.instanceId }), { ok: true });
  assert.equal(JSON.stringify(claims).includes(ADDRESS), false, "the claim carries no address");
});

test("a duplicate address is refused before the probe, and stores nothing at all", async () => {
  const world = await freshWorld();
  await createAccount(world.db, {
    label: "Personal", address: ADDRESS, username: USERNAME, authKind: "password",
    imap: ENDPOINT, smtp: SMTP_ENDPOINT,
  });
  const recorded = [];
  const { adapterFactory, factoryCalls } = workingFactory();

  const result = await addMailAccount({
    db: world.db,
    // A different spelling of the same mailbox: the store's identity is case-insensitive, and so is this.
    input: { ...INPUT, address: "Alex@Example.COM", label: "Second" },
    password: PASSWORD,
    adapterFactory,
    credentials: fakeCredentials(),
    localInstance: LOCAL,
    recordSecrets: (values) => { recorded.push(values); },
  });

  assert.equal(result.outcome, "duplicate");
  assert.deepEqual(factoryCalls, [], "the duplicate never dialled the server");
  assert.deepEqual(recorded, [], "the duplicate's password was never masked");
  assert.equal(await count(world.db, "mail_accounts"), 1, "no second account");
  assert.equal(await count(world.db, "crow_keychain"), 0, "no secret");
  assert.deepEqual(await listClaims(world.db, ADDRESS), [], "no claim");
});

test("a refused sign-in stores nothing: no account, no secret, no claim", async () => {
  const world = await freshWorld();
  const credentials = fakeCredentials();
  const result = await addMailAccount({
    db: world.db,
    input: INPUT,
    password: PASSWORD,
    adapterFactory: () => {
      const fake = createFakeMailAdapter();
      fake.failNext("connect", new MailError("AUTH_FAILED"));
      return fake;
    },
    credentials,
    localInstance: LOCAL,
  });

  assert.equal(result.outcome, "probe_failed");
  assert.equal(result.code, "AUTH_FAILED");
  assert.equal(JSON.stringify(result).includes(PASSWORD), false, "no password anywhere in the outcome");
  assert.equal(await count(world.db, "mail_accounts"), 0, "no account");
  assert.equal(await count(world.db, "crow_keychain"), 0, "no secret");
  assert.equal(credentials.saved.size, 0, "saveSecret was never called");
  assert.deepEqual(await listClaims(world.db, ADDRESS), [], "no claim");
});

test("a keychain that cannot save undoes the account it just made", async () => {
  const world = await freshWorld();
  const deleted = [];
  const credentials = {
    async saveSecret() { throw new Error("SQLITE_FULL: database or disk is full (crow_keychain)"); },
    async getSecrets() { return {}; },
    async deleteSecrets(id) { deleted.push(id); return { deleted: 0 }; },
  };
  const { adapterFactory } = workingFactory();

  const { lines, result } = await warnings(() => addMailAccount({
    db: world.db,
    input: INPUT,
    password: PASSWORD,
    adapterFactory,
    credentials,
    localInstance: LOCAL,
  }));

  assert.equal(result.outcome, "failed");
  assert.equal(result.undone, true);
  // A store failure is not a mail error, so it reports the fixed code rather than the store's text.
  assert.equal(result.code, "PROTOCOL");
  assert.equal(deleted.length, 1, "the secret of the half-made account was removed");
  assert.match(deleted[0], /^ma-[0-9a-f]{16}$/);
  assert.equal(await count(world.db, "mail_accounts"), 0, "the account was undone");
  assert.equal(await count(world.db, "crow_keychain"), 0);
  assert.deepEqual(await listClaims(world.db, ADDRESS), [], "no claim was written");
  for (const text of [JSON.stringify(result), lines.join("\n")]) {
    assert.equal(text.includes(PASSWORD), false, "no password in the outcome or a log");
    assert.equal(text.includes("SQLITE_FULL"), false, "no store text in the outcome or a log");
  }
});

test("a claim lost on the re-check undoes the whole add and reports where it is connected", async () => {
  const world = await freshWorld();
  await world.db.execute({
    sql: "INSERT INTO crow_instances (id, name, crow_id, status) VALUES (?, 'Echo', 'crow:mail', 'active')",
    args: [PEER],
  });
  const credentials = fakeCredentials();
  const adapterFactory = () => {
    const fake = createFakeMailAdapter();
    const connect = fake.connect.bind(fake);
    fake.connect = async () => {
      await connect();
      // The other instance's claim lands between our pre-check and our own write, and it is older.
      await writeClaim(world.db, ADDRESS, { localInstanceId: PEER, instanceName: "Echo", now: 1_000 });
    };
    return fake;
  };

  const result = await addMailAccount({
    db: world.db, input: INPUT, password: PASSWORD, adapterFactory, credentials, localInstance: LOCAL,
  });

  assert.equal(result.outcome, "claimed");
  assert.equal(result.undone, true);
  assert.equal(result.sentence, "This account is already connected on Echo");
  assert.equal(await count(world.db, "mail_accounts"), 0, "the account was undone");
  assert.equal(credentials.saved.size, 0, "the secret was undone");
  const ours = (await listClaims(world.db, ADDRESS)).find((c) => c.key === claimKey(ADDRESS, LOCAL.instanceId));
  assert.ok(ours, "our claim row is still there");
  assert.equal(ours.released, true, "…as a tombstone, so the address is not held by a phantom");
});

test("--dry-run probes and stores nothing — no account, no secret, no claim, no masking hash", async () => {
  const world = await freshWorld();
  const credentials = fakeCredentials();
  const recorded = [];
  const { adapterFactory, factoryCalls } = workingFactory();

  const result = await addMailAccount({
    db: world.db,
    input: INPUT,
    password: PASSWORD,
    adapterFactory,
    credentials,
    localInstance: LOCAL,
    recordSecrets: (values) => { recorded.push(values); },
    dryRun: true,
  });

  assert.equal(result.outcome, "dry_run");
  assert.equal(factoryCalls.length, 1, "the dry run is a real sign-in");
  assert.deepEqual(recorded, [], "a dry run records no masking hash either");
  assert.equal(credentials.saved.size, 0, "no secret was saved");
  assert.equal(await count(world.db, "mail_accounts"), 0);
  assert.equal(await count(world.db, "crow_keychain"), 0);
  assert.deepEqual(await listClaims(world.db, ADDRESS), []);
});

test("a failure after the claim was written releases the claim as well as undoing the secret and the account", async () => {
  const world = await freshWorld();
  const credentials = fakeCredentials();
  const { adapterFactory } = workingFactory();
  // The claim functions as one injected dependency, so the re-check can throw the way a locked or
  // half-migrated crow.db does — after our own claim row is already there.
  const real = { checkClaim, writeClaim, releaseClaim };
  let checks = 0;
  const claims = {
    writeClaim: real.writeClaim,
    releaseClaim: real.releaseClaim,
    async checkClaim(...args) {
      checks += 1;
      if (checks === 2) throw new Error("SQLITE_BUSY: database is locked (crow_instances)");
      return real.checkClaim(...args);
    },
  };

  const { lines, result } = await warnings(() => addMailAccount({
    db: world.db, input: INPUT, password: PASSWORD, adapterFactory, credentials, localInstance: LOCAL, claims,
  }));

  assert.equal(result.outcome, "failed");
  assert.equal(result.undone, true);
  assert.equal(checks, 2, "the failure came from the re-check, after the claim write");
  assert.equal(result.code, "PROTOCOL");
  assert.equal(credentials.saved.size, 0, "the secret was undone");
  assert.equal(await count(world.db, "mail_accounts"), 0, "the account was undone");
  const ours = (await listClaims(world.db, ADDRESS)).find((c) => c.key === claimKey(ADDRESS, LOCAL.instanceId));
  assert.ok(ours, "our claim row is still there");
  assert.equal(ours.released, true, "…as a tombstone, so it holds nothing");
  assert.deepEqual(await checkClaim(world.db, ADDRESS, { localInstanceId: PEER }), { ok: true });
  for (const text of [JSON.stringify(result), lines.join("\n")]) {
    assert.equal(text.includes(PASSWORD), false, "no password in the outcome or a log");
    assert.equal(text.includes("SQLITE_BUSY"), false, "no store text in the outcome or a log");
  }
});

test("a claim write that THREW was still attempted, so it is released and holds nothing", async () => {
  const world = await freshWorld();
  const credentials = fakeCredentials();
  const { adapterFactory } = workingFactory();
  // The write itself fails (a locked database). The attempt still has to be released: the flag is set
  // BEFORE the await, because a release tombstone holds nothing and no claim may be left behind.
  const claims = {
    checkClaim,
    releaseClaim,
    async writeClaim() { throw new Error("SQLITE_BUSY: database is locked (dashboard_settings)"); },
  };

  const { lines, result } = await warnings(() => addMailAccount({
    db: world.db, input: INPUT, password: PASSWORD, adapterFactory, credentials, localInstance: LOCAL, claims,
  }));

  assert.equal(result.outcome, "failed");
  assert.equal(result.undone, true);
  assert.equal(result.code, "PROTOCOL");
  assert.equal(credentials.saved.size, 0, "the secret was undone");
  assert.equal(await count(world.db, "mail_accounts"), 0, "the account was undone");
  const ours = (await listClaims(world.db, ADDRESS)).find((c) => c.key === claimKey(ADDRESS, LOCAL.instanceId));
  assert.ok(ours, "the attempted claim has a tombstone");
  assert.equal(ours.released, true, "…and it holds nothing");
  assert.deepEqual(await checkClaim(world.db, ADDRESS, { localInstanceId: PEER }), { ok: true });
  for (const text of [JSON.stringify(result), lines.join("\n")]) {
    assert.equal(text.includes(PASSWORD), false, "no password in the outcome or a log");
    assert.equal(text.includes("SQLITE_BUSY"), false, "no store text in the outcome or a log");
  }
});

/* ------------------------------------------------------- the env file parser */

test("the env-file parser keeps quoted content exactly, accepts export<TAB>, CRLF and an inline #", async () => {
  const path = join(root, "parse-" + (++n) + ".env");
  const lines = [
    "LEAD=' lead '",              // quotes keep their spaces, exactly
    "export\tTABBED=tabbed",      // `export` plus a tab, not a space
    'PLAIN="pa ss" # a note',     // text after the closing quote: whitespace then # is a comment
    'NOSPACE="pa ss"#note',       // …and the same comment with NO space before the #
    "HASH=pa#ss",                 // unquoted: an inline # is part of the value
    "PADDED=padded   ",           // unquoted: trailing whitespace goes
    "LEADED=  leaded",            // unquoted: leading whitespace goes too
    "GAPPED = gapped",            // …whether it follows = directly or ` = `
    "QUOTED_HASH='a#b'",
    "ESC='a\\nb'",                 // no escape processing: a backslash and an n
    "# a comment line",
  ];
  writeFileSync(path, lines.join("\r\n") + "\r\n", { mode: 0o600 }); // CRLF endings too

  const { lines: warned, result: values } = await warnings(() => readEnvFile(path));
  assert.equal(values.get("LEAD"), " lead ");
  assert.equal(values.get("TABBED"), "tabbed");
  assert.equal(values.get("PLAIN"), "pa ss");
  assert.equal(values.get("NOSPACE"), "pa ss");
  assert.equal(values.get("HASH"), "pa#ss");
  assert.equal(values.get("PADDED"), "padded");
  assert.equal(values.get("LEADED"), "leaded");
  assert.equal(values.get("GAPPED"), "gapped");
  assert.equal(values.get("QUOTED_HASH"), "a#b");
  assert.equal(values.get("ESC"), "a\\nb");
  assert.equal(values.has("#"), false);
  assert.deepEqual(warned, [], "a 0600 file warns about nothing");

  // The value parser is exported on its own too (the file reader is a thin loop over it).
  assert.equal(parseEnvValue("' x '"), " x ");
  assert.equal(parseEnvValue('"pw"#c'), "pw", "a comment needs no space before its #");
  assert.equal(parseEnvValue(" pw"), "pw", "an unquoted value is trimmed on the left too");
  assert.equal(parseEnvValue("pw   "), "pw");
  assert.equal(parseEnvValue('"x" trailing'), '"x" trailing');
});

test("an env file readable by group or others warns once, naming the flag and never the path", async () => {
  const path = join(root, "loose-" + (++n) + ".env");
  writeFileSync(path, "K='v'\n", { mode: 0o644 });
  chmodSync(path, 0o644); // whatever the umask took off

  const { lines, result } = await warnings(() => readEnvFile(path));
  assert.equal(result.get("K"), "v");
  assert.equal(lines.length, 1);
  assert.match(lines[0], /--password-env-file/);
  assert.match(lines[0], /readable by/);
  assert.equal(lines[0].includes(path), false, "the warning carries no path");
  assert.equal(lines[0].includes("'v'"), false, "and no value");
});

test("--password-stdin refuses a terminal before it would echo, and points at the two ways that work", async () => {
  await assert.rejects(() => readLineFromStdin({ isTTY: true }), (err) => {
    assert.ok(err instanceof MailCliError, String(err));
    assert.equal(err.exitCode, EXIT.usage);
    assert.match(err.message, /pipe it in or use --password-env-file/);
    return true;
  });
});

/* ------------------------------------------------------------- the script */

/**
 * A crow.db of its own plus the env a spawned run needs: nothing of the real box is reachable. The
 * script refuses to run against an instance without a keychain key file, so this world has one (the
 * real key file, made by the keychain's own code, for its own CROW_HOME) unless `key: false` asks for
 * the refusing case.
 */
function spawnWorld({ key = true } = {}) {
  const dir = join(root, "s" + (++n));
  mkdirSync(dir);
  const home = join(dir, "home");
  mkdirSync(home);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  if (key) createKeychainKey({ crowHome: home });
  return {
    dir,
    crow,
    home,
    env: {
      PATH: process.env.PATH || "/usr/bin:/bin",
      // Hermetic home: nothing under the real user's ~ is resolved by an accident.
      HOME: dir,
      CROW_DATA_DIR: join(dir, "data"),
      CROW_HOME: home,
      CROW_DB_PATH: crow,
      CROW_TASKS_DB_PATH: join(dir, "tasks.db"),
      // Never read the checkout .env: the script applies it through the gateway's gate, and a real
      // one on the box would point the run at a live instance.
      CROW_APP_ENV_PATH: join(dir, "gateway.env"),
    },
  };
}

function runCli(world, args, env = {}) {
  const child = spawnSync(process.execPath, [CLI, ...args], {
    env: { ...world.env, ...env },
    encoding: "utf8",
    timeout: 120_000,
  });
  return {
    code: child.status,
    out: String(child.stdout || ""),
    err: String(child.stderr || ""),
    all: String(child.stdout || "") + String(child.stderr || ""),
  };
}

/** An env file holding the password, and the address, in the shape an operator writes. */
function writeEnvFile(world) {
  const path = join(world.dir, "mail.env");
  writeFileSync(path, [
    "# the app password for this mailbox",
    `IMAP_PASSWORD='${PASSWORD}'`,
    `MAIL_ADDRESS="  ${ADDRESS}  "`,
    "",
  ].join("\n"), { mode: 0o600 });
  return path;
}

const ENDPOINT_FLAGS = ["--imap", "imap.example.com:993:ssl", "--smtp", "smtp.example.com:465:ssl"];

test("--help prints the flags, the file rules and the instance rule, and does nothing else", () => {
  const world = spawnWorld();
  const r = runCli(world, ["--help"], { CROW_MAIL: "1" });

  assert.equal(r.code, 0, r.err);
  assert.match(r.out, /--password-env-file/);
  assert.match(r.out, /--password-stdin/);
  assert.match(r.out, /umask 077/);
  assert.match(r.out, /This command writes to the instance/);
  assert.equal(r.all.includes(PASSWORD), false, "no password in the help text");
});

test("the script refuses a password on argv, and never echoes it", () => {
  const world = spawnWorld();
  const r = runCli(world, [
    "--label", "Personal", "--address", ADDRESS, ...ENDPOINT_FLAGS, "--password", PASSWORD,
  ], { CROW_MAIL: "1" });

  assert.equal(r.code, 2, r.err);
  assert.match(r.err, /password is never accepted on the command line/);
  assert.equal(r.all.includes(PASSWORD), false, "the password is nowhere in the output");
  assert.equal(r.code === 0, false, "nothing ran");
});

test("the script refuses when CROW_MAIL is not 1 in this shell, and says where the flag normally lives", () => {
  const world = spawnWorld();
  const envFile = writeEnvFile(world);
  const r = runCli(world, [
    "--label", "Personal", "--address-key", "MAIL_ADDRESS",
    "--password-env-file", envFile, "--password-key", "IMAP_PASSWORD",
    ...ENDPOINT_FLAGS,
  ]);

  assert.equal(r.code, 2, r.err);
  assert.match(r.err, /CROW_MAIL=1 is not set in this shell/);
  assert.match(r.err, /systemd unit/);
  assert.equal(r.all.includes(PASSWORD), false, "no password in the output");
});

test("a sign-in the server refuses prints only the code, never the password or the server's text", async () => {
  const world = spawnWorld();
  const envFile = writeEnvFile(world);
  const child = spawnSync(process.execPath, [
    CLI,
    "--label", "Personal", "--address-key", "MAIL_ADDRESS",
    "--password-env-file", envFile, "--password-key", "IMAP_PASSWORD",
    // Nothing listens on port 1: the probe's connection is refused at the socket, so no TLS or IMAP
    // exchange happens and the sign-in is reported as a failure by code.
    "--imap", "127.0.0.1:1:starttls", "--smtp", "127.0.0.1:1:starttls",
    "--dry-run",
  ], { env: { ...world.env, CROW_MAIL: "1" }, encoding: "utf8", timeout: 120_000 });

  const all = String(child.stdout || "") + String(child.stderr || "");
  assert.equal(child.status, 5, all);
  assert.match(all, /sign-in failed: [A-Z_]+/);
  assert.equal(all.includes(PASSWORD), false, "the password never reaches stdout or stderr");
  assert.equal(all.includes("hunter2"), false);

  // The dry-run guarantee itself (nothing stored) is the core test's above; what this run adds is
  // that the failure is one code. Its world is still empty all the same.
  const db = createDbClient(world.crow);
  open.push(db);
  assert.equal(await count(db, "mail_accounts"), 0);
  assert.equal(await count(db, "crow_keychain"), 0);
  assert.deepEqual(await listClaims(db, ADDRESS), []);
});

test("--password-stdin reads the one line from stdin and never echoes it", () => {
  const world = spawnWorld();
  const child = spawnSync(process.execPath, [
    CLI,
    "--label", "Personal", "--address", ADDRESS,
    "--imap", "127.0.0.1:1:starttls", "--smtp", "127.0.0.1:1:starttls",
    "--password-stdin", "--dry-run",
  ], {
    env: { ...world.env, CROW_MAIL: "1" },
    encoding: "utf8",
    input: `${PASSWORD}\n`,
    timeout: 120_000,
  });

  const all = String(child.stdout || "") + String(child.stderr || "");
  // The password came off stdin, and the run got as far as the probe the dead port refuses.
  assert.equal(child.status, 5, all);
  assert.equal(all.includes(PASSWORD), false, "the password never reaches stdout or stderr");
});

/* ------------------------------------- the instance this run may write to */

test("no crow.db at the resolved path: refused (2), named first, and no database is created", () => {
  const world = spawnWorld();
  rmSync(world.crow);
  const envFile = writeEnvFile(world);

  const r = runCli(world, [
    "--label", "Personal", "--address-key", "MAIL_ADDRESS",
    "--password-env-file", envFile, "--password-key", "IMAP_PASSWORD",
    ...ENDPOINT_FLAGS, "--dry-run",
  ], { CROW_MAIL: "1" });

  assert.equal(r.code, 2, r.err);
  assert.match(r.err, /no crow\.db yet/);
  // The run says which instance it resolved before refusing, so the operator can see the mistake.
  assert.match(r.out, /writing to instance CROW_HOME=/);
  assert.equal(r.out.includes(world.crow), true, "the line names the db path");
  assert.equal(existsSync(world.crow), false, "createDbClient never created an empty database");
  assert.equal(r.all.includes(PASSWORD), false, "no password in the output");
});

test("no keychain key file: refused (2), and the command mints no key of its own", () => {
  const world = spawnWorld({ key: false });
  const envFile = writeEnvFile(world);

  const r = runCli(world, [
    "--label", "Personal", "--address-key", "MAIL_ADDRESS",
    "--password-env-file", envFile, "--password-key", "IMAP_PASSWORD",
    ...ENDPOINT_FLAGS,
  ], { CROW_MAIL: "1" });

  assert.equal(r.code, 2, r.err);
  assert.match(r.err, /the keychain key at this instance is missing or unreadable/);
  assert.equal(existsSync(keychainKeyPath(world.home)), false, "ensureWriteKey never ran here");
  assert.equal(r.all.includes(PASSWORD), false, "no password in the output");
});

test("a keychain key PATH that is a directory: refused (2) as unreadable, and nothing is written", async () => {
  // existsSync alone would pass this: the keychain's own state check is what refuses it.
  const world = spawnWorld({ key: false });
  const keyPath = keychainKeyPath(world.home);
  mkdirSync(keyPath, { recursive: true });
  const envFile = writeEnvFile(world);

  const r = runCli(world, [
    "--label", "Personal", "--address-key", "MAIL_ADDRESS",
    "--password-env-file", envFile, "--password-key", "IMAP_PASSWORD",
    ...ENDPOINT_FLAGS,
  ], { CROW_MAIL: "1" });

  assert.equal(r.code, 2, r.err);
  assert.match(r.err, /the keychain key at this instance is missing or unreadable/);
  assert.equal(statSync(keyPath).isDirectory(), true, "the command neither replaced nor removed it");
  assert.equal(r.all.includes(PASSWORD), false, "no password in the output");

  // Nothing was written: no account, no sealed secret, no claim.
  const db = createDbClient(world.crow);
  open.push(db);
  assert.equal(await count(db, "mail_accounts"), 0);
  assert.equal(await count(db, "crow_keychain"), 0);
  assert.deepEqual(await listClaims(db, ADDRESS), []);
});

/* ------------------------------------------- no operator value in a failure */

test("a stray positional argument is refused by its position, never echoed", () => {
  const world = spawnWorld();
  const stray = "S3cretPw";
  const r = runCli(world, [
    "--label", "Personal", "--address", ADDRESS, ...ENDPOINT_FLAGS, stray,
  ], { CROW_MAIL: "1" });

  assert.equal(r.code, 2, r.err);
  assert.match(r.err, /an unexpected positional argument/);
  assert.equal(r.all.includes(stray), false, "an operator value is never echoed by a failure");
});

test("a --password-key variable that is not in the env file is reported without its name", () => {
  const world = spawnWorld();
  const envFile = writeEnvFile(world);
  const missing = "NOT_IN_THE_FILE";
  const r = runCli(world, [
    "--label", "Personal", "--address", ADDRESS, ...ENDPOINT_FLAGS,
    "--password-env-file", envFile, "--password-key", missing,
  ], { CROW_MAIL: "1" });

  assert.equal(r.code, 2, r.err);
  assert.match(r.err, /--password-key variable is not set in the env file/);
  assert.equal(r.all.includes(missing), false, "the variable name is not echoed");
  assert.equal(r.all.includes(PASSWORD), false, "nor the password");
});

/* --------------------------------------------- the closing line, and the hook */

/** Run `report()` for one added outcome and return what it printed (stdout) plus its exit code. */
function reportAdded(hook) {
  const lines = [];
  const original = console.log;
  console.log = (...args) => { lines.push(args.join(" ")); };
  try {
    const code = _reportForTest({ outcome: "added", account: { id: "acc1", label: "Personal", address: ADDRESS } }, hook);
    return { lines, out: lines.join("\n"), code };
  } finally {
    console.log = original;
  }
}

const RESTART_LINE = "restart the gateway so the sync supervisor starts this account";
const SYNCING_LINE = "The running gateway started syncing this account.";

test("an added account whose hook notified the gateway says so, and does not ask for a restart", () => {
  const r = reportAdded({ notified: true });

  assert.equal(r.code, EXIT.ok);
  assert.equal(r.lines[0], `added account acc1 (Personal, ${ADDRESS})`);
  assert.equal(r.lines[1], SYNCING_LINE);
  assert.equal(r.lines.length, 2, "the added account is two lines");
  assert.equal(r.out.includes("restart the gateway"), false, "no restart sentence when the gateway is syncing");
});

test("an added account whose hook did not notify still asks for a restart, and never claims a sync", () => {
  for (const hook of [{ notified: false }, undefined, {}]) {
    const r = reportAdded(hook);

    assert.equal(r.code, EXIT.ok);
    assert.equal(r.lines[0], `added account acc1 (Personal, ${ADDRESS})`);
    assert.equal(r.lines[1], RESTART_LINE);
    assert.equal(r.lines.length, 2);
    assert.equal(r.out.includes(SYNCING_LINE), false, "nothing started syncing, so nothing says it did");
  }
});
