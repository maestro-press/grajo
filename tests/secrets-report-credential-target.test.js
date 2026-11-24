// The `report-credential` secret target: the label grammar, the refusals, and the one place a report
// credential's value ever exists.
//
// Harness: a real init-db'd scratch crow.db per test, a real keychain key file under a temp CROW_HOME (so
// a `service` keychain row is really sealed), real report and host rows, and the real request store
// (`createSecretRequest` / `deliverSecret` / `takeSecretNotes`), so the notes a bot is told are the ones
// here.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "secrets-report-credential-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");
const HOME = process.env.CROW_HOME;
const NO_KEY_HOME = join(root, "no-key-home");

const { createDbClient } = await import("../servers/db.js");
const { createKeychainKey } = await import("../servers/gateway/keychain/key.js");
const { getTarget, targetNames } = await import("../servers/gateway/secrets/targets.js");
const {
  KEYCHAIN_NOTES, REPORT_CREDENTIAL_MIN_BYTES, REPORT_CREDENTIAL_SAVED_NOTE,
} = await import("../servers/gateway/secrets/targets.js");
const { INJECT_SECRET_MIN_BYTES } = await import("../scripts/pi-bots/pi_egress.mjs");
const {
  SECRET_DELIVER_FAILED, REPORT_CREDENTIAL_LABEL_MAX, _resetSecretStoreForTest, addSecretNote,
  cleanLabel, createSecretRequest, deliverSecret, getSecretRequest, takeSecretNotes,
} = await import("../servers/gateway/secrets/request-store.js");
const { proposeHost, approveHost, parseCredentialSpec } = await import(
  "../servers/gateway/reports/steps.js"
);
const { createReport } = await import("../servers/gateway/reports/store.js");

const OWNER = Object.freeze({ kind: "owner" });
const BOT = "bot-1";
const OTHER_BOT = "bot-2";
const SECRET = "credential-value-0123456789abcdef";
const T0 = 1_700_000_000_000;

mkdirSync(NO_KEY_HOME, { recursive: true });
const key = createKeychainKey({ crowHome: HOME });

const open = [];

after(() => {
  for (const db of open) { try { db.close(); } catch { /* closed */ } }
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

async function freshDb() {
  const dir = join(root, "t" + (++n));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  const db = createDbClient(crow);
  open.push(db);
  return db;
}

function deps(over = {}) {
  return { loadSeed: () => ({ seed: key.seed }), now: () => T0, crowHome: HOME, ...over };
}

/** A report owned by BOT with one approved host, ready for a credential request. */
async function world() {
  const db = await freshDb();
  const { id } = await createReport(db, { projectId: 7, owner: "owner", botId: BOT, title: "Weekly listings" });
  await proposeHost(db, deps(), { reportId: id, host: "example.com" });
  await approveHost(db, deps(), { reportId: id, host: "example.com", actor: OWNER });
  return { db, reportId: id };
}

const labelFor = (reportId, rest = "header=X-Key;paths=/v1") => `report=${reportId};host=example.com;${rest};end`;

let session = 0;
const nextSession = () => `sess-${++n}-${++session}`;

/** One request through the real store, then its claimed object. */
function requestFor(label, { botId = BOT, sid = nextSession() } = {}) {
  const { id } = createSecretRequest({
    sessionId: sid, threadId: sid, botId, kind: "password", target: "report-credential", label,
  });
  return { request: { id, sessionId: sid, threadId: sid, botId, kind: "password", target: "report-credential", label }, sid };
}

/** Collect every console line a block writes, so a failed delivery can be checked for the value. */
async function withCapturedConsole(fn) {
  const lines = [];
  const saved = { log: console.log, warn: console.warn, error: console.error };
  for (const name of ["log", "warn", "error"]) console[name] = (...args) => { lines.push(args.join(" ")); };
  try {
    const out = await fn();
    return { out, lines };
  } finally {
    Object.assign(console, saved);
  }
}

/* ---------------------------------------------------------------------- the registry */

test("the target is registered and parses the spec it documents", () => {
  assert.ok(targetNames().includes("report-credential"));
  assert.ok(getTarget("report-credential"));

  const spec = parseCredentialSpec(
    "report=rpt-0011223344556677;host=example.com;header=Authorization;format=Bearer {};paths=/v1/issues,/v1/repos;methods=GET,HEAD;end",
  );
  assert.deepEqual(spec, {
    reportId: "rpt-0011223344556677",
    host: "example.com",
    inject: {
      header: "Authorization",
      format: "Bearer {}",
      pathPrefixes: ["/v1/issues", "/v1/repos"],
      methods: ["GET", "HEAD"],
    },
  });

  const query = parseCredentialSpec("report=rpt-0011223344556677;host=api.example.com;query=api_key;paths=/v1;end");
  assert.deepEqual(query.inject, { query: "api_key", pathPrefixes: ["/v1"], methods: ["GET", "HEAD"] });
});

/* ------------------------------------------------------------------ the label grammar */

test("a well-formed spec is accepted and the card opens", async () => {
  const { db, reportId } = await world();
  const label = labelFor(reportId);
  assert.ok(parseCredentialSpec(label));

  const { request, sid } = requestFor(label);
  assert.equal(getTarget("report-credential").validate(request), true);

  const { out, lines } = await withCapturedConsole(() => deliverSecret(request, SECRET, { db, crowHome: HOME }));
  assert.equal(out.ok, true, out.note);
  assert.equal(out.note, REPORT_CREDENTIAL_SAVED_NOTE);
  assert.deepEqual(takeSecretNotes(sid), [REPORT_CREDENTIAL_SAVED_NOTE]);
  assert.equal(lines.join(" ").includes(SECRET), false, "no log line carries the value");
});

/* -------------------------------------------------------------- the label cap
 * The request store caps a label at 80 characters, except for `report-credential`, whose label is a
 * binding spec rather than a name: that target gets the tool schema's own 400. The grammar needs the
 * trailing `;end` token so a label the cap cut can never read as a shorter but complete binding. */

test("a 150 character report-credential spec is kept whole and opens the card", async () => {
  const { reportId } = await world();
  const label = labelFor(reportId,
    "header=X-Key;format=Bearer {};paths=/v1/accounts,/v1/transactions,/v1/statements,/v1/balances;methods=GET,POST");
  assert.ok(label.length > 150, `the spec is well past the usual label cap (${label.length})`);
  assert.ok(label.length <= REPORT_CREDENTIAL_LABEL_MAX);
  assert.ok(parseCredentialSpec(label), "the whole spec parses");

  const sid = nextSession();
  const { id } = createSecretRequest({
    sessionId: sid, threadId: sid, botId: BOT, kind: "password", target: "report-credential", label,
  });
  const stored = getSecretRequest(id);
  assert.equal(stored.label, label, "the spec reaches the card whole");
  assert.equal(getTarget("report-credential").validate(stored), true);
});

test("a 150 character label for the keychain target is still cut to 80", () => {
  const long = "k".repeat(150);
  assert.equal(cleanLabel(long).length, 80);
  assert.equal(cleanLabel(long, REPORT_CREDENTIAL_LABEL_MAX), long);

  const sid = nextSession();
  const { id } = createSecretRequest({
    sessionId: sid, threadId: sid, botId: BOT, kind: "password", target: "keychain", label: long,
  });
  assert.equal(getSecretRequest(id).label.length, 80, "every other target keeps the 80 character cap");
});

test("an over-400 spec is cut, and the cut text is not a spec", async () => {
  const { reportId } = await world();
  const pad = (letter) => `/v1/${letter.repeat(150)}`;
  const paths = [pad("a"), pad("b"), pad("c")].join(",");
  const overLong = labelFor(reportId, `header=X-Key;paths=${paths}`);
  assert.ok(overLong.length > REPORT_CREDENTIAL_LABEL_MAX, `${overLong.length} characters`);
  assert.equal(parseCredentialSpec(overLong), null, "the whole spec is past the grammar's own bound");

  const cut = cleanLabel(overLong, REPORT_CREDENTIAL_LABEL_MAX);
  assert.equal(cut.length, REPORT_CREDENTIAL_LABEL_MAX, "the cap cut it");
  assert.notEqual(cut, overLong);
  assert.equal(parseCredentialSpec(cut), null, "a cut spec is never a different valid binding");

  const sid = nextSession();
  assert.throws(
    () => createSecretRequest({
      sessionId: sid, threadId: sid, botId: BOT, kind: "password", target: "report-credential",
      label: overLong,
    }),
    (err) => err.code === "bad_target",
  );
  assert.deepEqual(takeSecretNotes(sid), [], "no card, no note");
});

test("the grammar refuses smuggling, extra keys, case tricks and newlines", () => {
  const target = getTarget("report-credential");
  const good = "report=rpt-0011223344556677;host=example.com;header=X-Key;paths=/v1;end";
  const validate = (label) => target.validate({ botId: BOT, kind: "password", target: "report-credential", label });

  assert.equal(validate(good), true);
  const bad = [
    // a stray `;` inside a value splits into a part with no `=`
    "report=rpt-0011223344556677;host=example.com;header=X;Key;paths=/v1;end",
    // an extra key is never read
    `${good};extra=1`,
    `${good};report=rpt-0011223344556677`,
    // a duplicate key
    "report=rpt-0011223344556677;host=example.com;header=X-Key;header=Y-Key;paths=/v1;end",
    // an upper-case or trailing-dot host
    "report=rpt-0011223344556677;host=Example.com;header=X-Key;paths=/v1;end",
    "report=rpt-0011223344556677;host=example.com.;header=X-Key;paths=/v1;end",
    // an IP, a wildcard, a single-label host
    "report=rpt-0011223344556677;host=127.0.0.1;header=X-Key;paths=/v1;end",
    "report=rpt-0011223344556677;host=*.example.com;header=X-Key;paths=/v1;end",
    "report=rpt-0011223344556677;host=localhost;header=X-Key;paths=/v1;end",
    // no path prefixes, an empty one, one that is not a path, one with a query
    "report=rpt-0011223344556677;host=example.com;header=X-Key;end",
    "report=rpt-0011223344556677;host=example.com;header=X-Key;paths=;end",
    "report=rpt-0011223344556677;host=example.com;header=X-Key;paths=v1;end",
    "report=rpt-0011223344556677;host=example.com;header=X-Key;paths=/v1?x=1;end",
    "report=rpt-0011223344556677;host=example.com;header=X-Key;paths=/;end",
    "report=rpt-0011223344556677;host=example.com;header=X-Key;paths=//;end",
    "report=rpt-0011223344556677;host=example.com;header=X-Key;paths=/v1,/etc/../root;end",
    // a report id that is not the store's shape
    "report=rpt-zzzz;host=example.com;header=X-Key;paths=/v1;end",
    "report=$(id);host=example.com;header=X-Key;paths=/v1;end",
    // both targets, neither target, a format on a query, a format without {}
    "report=rpt-0011223344556677;host=example.com;header=X-Key;query=k;paths=/v1;end",
    "report=rpt-0011223344556677;host=example.com;paths=/v1;end",
    "report=rpt-0011223344556677;host=example.com;query=k;format={};paths=/v1;end",
    "report=rpt-0011223344556677;host=example.com;header=X-Key;format=Token;paths=/v1;end",
    "report=rpt-0011223344556677;host=example.com;header=X-Key;format=Bearer {} {};paths=/v1;end",
    // a framing header, a bad header token, an unknown method
    "report=rpt-0011223344556677;host=example.com;header=Host;paths=/v1;end",
    "report=rpt-0011223344556677;host=example.com;header=Proxy-Authorization;paths=/v1;end",
    "report=rpt-0011223344556677;host=example.com;header=Bad Header;paths=/v1;end",
    "report=rpt-0011223344556677;host=example.com;header=X-Key;paths=/v1;methods=TRACE;end",
    // whitespace and control characters
    `${good} `,
    ` ${good}`,
    "report=rpt-0011223344556677;host=example.com;header=X-Key;paths=/v1;end\n",
    "report=rpt-0011223344556677;host=example.com;header=X-Key;paths=/v1;end\r\n;methods=GET",
    // the `;end` token: absent, doubled, spelled with a value, or cased differently
    "report=rpt-0011223344556677;host=example.com;header=X-Key;paths=/v1",
    `${good};end`,
    "report=rpt-0011223344556677;host=example.com;header=X-Key;paths=/v1;end=1;end",
    "report=rpt-0011223344556677;host=example.com;header=X-Key;end;paths=/v1;end",
    "end",
    ";end",
    "report=rpt-0011223344556677;host=example.com;header=X-Key;paths=/v1;END",
    "",
    null,
    7,
    {},
  ];
  for (const label of bad) {
    assert.equal(validate(label), false, JSON.stringify(label));
    assert.equal(parseCredentialSpec(label), null, JSON.stringify(label));
  }
  assert.equal(target.validate({ botId: "", label: good }), false, "a request always names a bot");
});

test("the request store refuses a bad spec with its own fixed line, and opens nothing", async () => {
  const { reportId } = await world();
  const sid = nextSession();
  assert.throws(
    () => createSecretRequest({
      sessionId: sid, threadId: sid, botId: BOT, kind: "password", target: "report-credential",
      label: labelFor(reportId, "header=X-Key;paths=/v1;extra=1"),
    }),
    (err) => err.code === "bad_target" && err.message === "That kind of request isn't available yet.",
  );
  assert.deepEqual(takeSecretNotes(sid), [], "no card, no note");
});

/* ------------------------------------------------------------------------- delivery */

test("a bot that is not the report's bot is refused, and nothing is saved", async () => {
  const { db, reportId } = await world();
  const { request, sid } = requestFor(labelFor(reportId), { botId: OTHER_BOT });
  const { out, lines } = await withCapturedConsole(() => deliverSecret(request, SECRET, { db, crowHome: HOME }));
  assert.equal(out.ok, false);
  assert.equal(out.note, SECRET_DELIVER_FAILED);
  assert.equal(out.note.includes(SECRET), false);
  assert.equal(lines.join(" ").includes(SECRET), false);
  assert.deepEqual(takeSecretNotes(sid), [SECRET_DELIVER_FAILED]);
  assert.equal(await countRows(db, "report_credentials"), 0);
  assert.equal(await countRows(db, "crow_keychain"), 0);
});

test("a host the report has not approved is refused", async () => {
  const db = await freshDb();
  const { id: reportId } = await createReport(db, {
    projectId: 7, owner: "owner", botId: BOT, title: "Weekly listings",
  });
  const { request } = requestFor(labelFor(reportId));
  const out = await deliverSecret(request, SECRET, { db, crowHome: HOME });
  assert.equal(out.ok, false);
  assert.equal(out.note, SECRET_DELIVER_FAILED);
  assert.equal(await countRows(db, "report_credentials"), 0);
  assert.equal(await countRows(db, "crow_keychain"), 0, "no keychain row for a refused host");
});

test("the card's floor is the relay's floor", () => {
  assert.equal(REPORT_CREDENTIAL_MIN_BYTES, INJECT_SECRET_MIN_BYTES);
});

test("a value under the relay's floor is refused at the card, and nothing is saved", async () => {
  const ten = "0123456789";
  const fifteen = "012345678901234";
  assert.equal(Buffer.byteLength(ten), 10);
  assert.equal(Buffer.byteLength(fifteen), 15);

  for (const value of [ten, fifteen]) {
    const { db, reportId } = await world();
    const { request, sid } = requestFor(labelFor(reportId));
    const { out, lines } = await withCapturedConsole(() => deliverSecret(request, value, { db, crowHome: HOME }));
    assert.equal(out.ok, false, `${value.length} bytes`);
    assert.equal(out.note, SECRET_DELIVER_FAILED);
    assert.deepEqual(takeSecretNotes(sid), [SECRET_DELIVER_FAILED]);
    assert.equal(lines.join(" ").includes(value), false, "no log line carries the value");
    assert.equal(await countRows(db, "report_credentials"), 0, `${value.length} bytes: no credential row`);
    assert.equal(await countRows(db, "crow_keychain"), 0, `${value.length} bytes: no keychain row`);
  }

  const { db, reportId } = await world();
  const sixteen = "0123456789012345";
  assert.equal(Buffer.byteLength(sixteen), REPORT_CREDENTIAL_MIN_BYTES);
  const out = await deliverSecret(requestFor(labelFor(reportId)).request, sixteen, { db, crowHome: HOME });
  assert.equal(out.ok, true, out.note);
  assert.equal(await countRows(db, "report_credentials"), 1);
  assert.equal(await countRows(db, "crow_keychain"), 1);
});

test("no keychain key is a fixed refusal, not a save", async () => {
  const { db, reportId } = await world();
  assert.equal(existsSync(join(NO_KEY_HOME, "secrets", "keychain.key")), false);
  const { request } = requestFor(labelFor(reportId));
  const out = await deliverSecret(request, SECRET, { db, crowHome: NO_KEY_HOME });
  assert.equal(out.ok, false);
  assert.equal(out.note, KEYCHAIN_NOTES.notSetUp);
  assert.equal(await countRows(db, "report_credentials"), 0);
  assert.equal(await countRows(db, "crow_keychain"), 0);
});

test("a save writes a sealed keychain row and a proposed credential, and nothing else", async () => {
  const { db, reportId } = await world();
  const { request, sid } = requestFor(labelFor(reportId));
  const { out } = await withCapturedConsole(() => deliverSecret(request, SECRET, { db, crowHome: HOME }));
  assert.equal(out.ok, true, out.note);

  const keychain = (await db.execute({
    sql: "SELECT kind, label, bundle_id, env_key, status, key_id, secret_sealed, connection_uuid FROM crow_keychain",
    args: [],
  })).rows;
  assert.equal(keychain.length, 1);
  assert.equal(keychain[0].kind, "service");
  assert.equal(keychain[0].bundle_id, "crow-reports");
  assert.equal(keychain[0].env_key, "REPORT_CREDENTIAL");
  assert.equal(keychain[0].status, "active");
  assert.equal(keychain[0].key_id, key.id);
  assert.match(keychain[0].secret_sealed, /^enc:v2:/);
  assert.equal(keychain[0].secret_sealed.includes(SECRET), false, "the value is sealed, not stored");
  assert.match(keychain[0].connection_uuid, /^[0-9a-f-]{36}$/);

  const credentials = (await db.execute({ sql: "SELECT * FROM report_credentials", args: [] })).rows;
  assert.equal(credentials.length, 1);
  const row = credentials[0];
  assert.equal(row.report_id, reportId);
  assert.equal(row.host, "example.com");
  assert.equal(row.state, "proposed", "the owner's tap decides, not the bot");
  assert.equal(row.connection_uuid, keychain[0].connection_uuid);
  assert.equal(row.approval_seal, null);
  assert.equal(row.approval_nonce, null);
  assert.deepEqual(JSON.parse(row.inject_json), {
    header: "X-Key", format: "{}", pathPrefixes: ["/v1"], methods: ["GET", "HEAD"],
  });

  const notes = takeSecretNotes(sid);
  assert.deepEqual(notes, [REPORT_CREDENTIAL_SAVED_NOTE]);

  // The value is in the sealed blob and nowhere else in the database.
  const reportTables = [
    "reports", "report_recipe_revisions", "report_state", "report_usage", "report_approvals_audit",
    "report_recipients", "report_sends", "report_custom_steps", "report_assets", "report_hosts",
    "report_credentials", "report_runs", "report_run_requests", "report_versions",
  ];
  for (const table of reportTables) {
    const { rows } = await db.execute(`SELECT * FROM ${table}`);
    for (const stored of rows) {
      for (const [name, value] of Object.entries(stored)) {
        assert.equal(String(value ?? "").includes(SECRET), false, `${table}.${name} carries the value`);
        assert.equal(String(value ?? "").includes("0123456789abcdef"), false, `${table}.${name} carries a piece of it`);
      }
    }
  }
  const { rows: keychainRows } = await db.execute("SELECT * FROM crow_keychain");
  for (const [name, value] of Object.entries(keychainRows[0])) {
    assert.equal(String(value ?? "").includes(SECRET), false, `crow_keychain.${name} carries the value`);
  }
  for (const note of notes) assert.equal(note.includes(SECRET), false);
});

test("the saved credential waits for the owner, and the previous keychain row is retired on a replace", async () => {
  const { db, reportId } = await world();
  const first = requestFor(labelFor(reportId));
  assert.equal((await deliverSecret(first.request, "first-secret-value", { db, crowHome: HOME })).ok, true);
  const firstUuid = (await db.execute({ sql: "SELECT connection_uuid FROM report_credentials", args: [] }))
    .rows[0].connection_uuid;

  const second = requestFor(labelFor(reportId));
  assert.equal((await deliverSecret(second.request, "second-secret-value", { db, crowHome: HOME })).ok, true);

  const rows = (await db.execute({
    sql: "SELECT connection_uuid, state FROM report_credentials", args: [],
  })).rows;
  assert.equal(rows.length, 1, "one binding per report and host");
  assert.notEqual(rows[0].connection_uuid, firstUuid);
  assert.equal(rows[0].state, "proposed");

  const old = (await db.execute({
    sql: "SELECT status FROM crow_keychain WHERE connection_uuid = ?", args: [firstUuid],
  })).rows;
  assert.equal(old.length, 1);
  assert.equal(old[0].status, "disconnected", "the replaced keychain row is never served again");
  const live = (await db.execute({
    sql: "SELECT status FROM crow_keychain WHERE connection_uuid = ?", args: [rows[0].connection_uuid],
  })).rows;
  assert.equal(live[0].status, "active");
});

test("the credential the target proposes is the one an owner tap can approve", async () => {
  const { db, reportId } = await world();
  const { request } = requestFor(labelFor(reportId));
  assert.equal((await deliverSecret(request, SECRET, { db, crowHome: HOME })).ok, true);

  const listed = (await db.execute({
    sql: "SELECT host, connection_uuid, inject_json FROM report_credentials", args: [],
  })).rows[0];
  const { approveCredential, credentialSecretFor, injectHashOf } = await import(
    "../servers/gateway/reports/steps.js"
  );
  const approved = await approveCredential(db, deps(), {
    reportId,
    host: listed.host,
    connectionUuid: listed.connection_uuid,
    injectHash: injectHashOf(JSON.parse(listed.inject_json)),
    actor: OWNER,
  });
  assert.equal(approved.verified, true, "the seal the target's proposal can be approved over");

  const secret = await credentialSecretFor(db, deps(), { reportId, host: "example.com" });
  assert.equal(secret(), SECRET, "the value the operator typed is what the relay would be handed");
});

test("the value a save carries joins the masking set, so a log line cannot print it", async () => {
  const { db, reportId } = await world();
  const { request } = requestFor(labelFor(reportId));
  const value = "masked-credential-0123456789abcdef";
  assert.equal((await deliverSecret(request, value, { db, crowHome: HOME })).ok, true);
  const { getSecretValues } = await import("../servers/shared/secret-values.js");
  const { redactSecrets } = await import("../servers/shared/redact-secrets.js");
  assert.equal(redactSecrets(`before ${value} after`, getSecretValues()), "before [redacted] after",
    "the value is masked on every display path from this process on");
  const hashes = (await import("../servers/shared/secret-values.js")).readServiceHashes();
  assert.equal(hashes.size > 0, true, "and its hash is in the service list");
});

test("a proposal that fails after the save retires the keychain row it wrote", async () => {
  const { db, reportId } = await world();
  const { request, sid } = requestFor(labelFor(reportId));
  // The credential row cannot be written: everything before it (the host check, the sealed keychain
  // row) succeeded, which is exactly the state that used to leave an orphan.
  const failing = new Proxy(db, {
    get(target, prop) {
      if (prop === "execute") {
        return async (stmt) => {
          if (String(stmt && stmt.sql).startsWith("INSERT INTO report_credentials")) throw new Error("write refused");
          return target.execute(stmt);
        };
      }
      const value = target[prop];
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  const { out, lines } = await withCapturedConsole(() => deliverSecret(request, SECRET, { db: failing, crowHome: HOME }));
  assert.equal(out.ok, false);
  assert.equal(out.note, SECRET_DELIVER_FAILED);
  assert.deepEqual(takeSecretNotes(sid), [SECRET_DELIVER_FAILED]);
  assert.equal(lines.join(" ").includes(SECRET), false, "no log line carries the value");
  assert.equal(await countRows(db, "report_credentials"), 0, "no binding was written");
  const rows = (await db.execute({ sql: "SELECT status FROM crow_keychain", args: [] })).rows;
  assert.equal(rows.length, 1, "the sealed row was written, and is still there");
  assert.equal(rows[0].status, "disconnected", "and it is never served again");
});

/* ---------------------------------------------------------------------------- helpers */

async function countRows(db, table) {
  const { rows } = await db.execute(`SELECT COUNT(*) AS n FROM ${table}`);
  return Number(rows[0].n);
}

test("the request store's own helpers do not leak a value into a note", () => {
  _resetSecretStoreForTest();
  const sid = nextSession();
  addSecretNote(sid, "a fixed line");
  assert.deepEqual(takeSecretNotes(sid), ["a fixed line"]);
  assert.equal(REPORT_CREDENTIAL_SAVED_NOTE.includes(SECRET), false);
  assert.equal(KEYCHAIN_NOTES.notSetUp.includes(SECRET), false);
});