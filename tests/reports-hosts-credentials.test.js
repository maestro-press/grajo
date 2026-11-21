// Crow Recurring Reports' hosts and credential bindings: the host grammar, the approval sentence, the
// rule that a credential needs an approved host, the seal checks, and the ONLY way a secret is read
// (from the keychain, at call time, never from a reports table).
//
// Harness: a real init-db'd scratch crow.db per test, a real keychain key file under a temp CROW_HOME
// (so a `service` keychain row can be sealed and reopened), and a fixed approvals seed injected through
// `deps.loadSeed`.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "reports-hosts-credentials-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");
const HOME = process.env.CROW_HOME;

const { createDbClient } = await import("../servers/db.js");
const { createKeychainKey, loadKeychainKey } = await import("../servers/gateway/keychain/key.js");
const { REPORTS_BUNDLE, saveServiceSecret, serviceSecretsFor } = await import(
  "../servers/gateway/keychain/store.js"
);
const {
  HOST_APPROVAL_LINE, approveCredential, approveHost, canonicalInject, credentialSecretFor, hostApproved,
  injectHashOf, injectRulesFor, listCredentials, listHosts, proposeCredential, proposeHost,
  revokeCredential, revokeHost, verifyCredential, verifyHost,
} = await import("../servers/gateway/reports/steps.js");
const { createReport } = await import("../servers/gateway/reports/store.js");

const OWNER = Object.freeze({ kind: "owner" });
const BOT_ACTOR = Object.freeze({ kind: "bot" });
const T0 = 1_700_000_000_000;
const UUID_A = "11111111-1111-4111-8111-111111111111";
const UUID_B = "22222222-2222-4222-8222-222222222222";
const SECRET = "credential-value-0123456789abcdef";

/** The keychain key the instance really has once it has one (written under the temp home). */
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
  return {
    loadSeed: () => ({ seed: key.seed }),
    loadKeychainKey: () => loadKeychainKey({ crowHome: HOME }),
    now: () => T0,
    crowHome: HOME,
    ...over,
  };
}

async function makeReport(db, title = "Weekly listings") {
  const { id } = await createReport(db, { projectId: 7, owner: "owner", botId: "bot-1", title });
  return id;
}

/** One approved host of one report, through the real paths. */
async function approvedHost(db, reportId, host = "example.com") {
  await proposeHost(db, deps(), { reportId, host });
  const out = await approveHost(db, deps(), { reportId, host, actor: OWNER });
  return out.host;
}

const RULE = Object.freeze({
  header: "Authorization",
  format: "Bearer {}",
  pathPrefixes: ["/v1/issues"],
  methods: ["GET", "HEAD"],
});

/** One proposed credential for an approved host, and the keychain row it names. */
async function credentialWithSecret(db, reportId, {
  host = "example.com", connectionUuid = UUID_A, secret = SECRET, inject = RULE,
} = {}) {
  await saveServiceSecret(db, key, {
    connectionUuid,
    bundleId: REPORTS_BUNDLE,
    envKey: "REPORT_CREDENTIAL",
    label: "report credential",
    secret,
  });
  return proposeCredential(db, deps(), {
    reportId, host, connectionUuid, inject, proposedBy: "bot:bot-1",
  });
}

async function storedCredential(db, reportId, host) {
  const { rows } = await db.execute({
    sql: "SELECT * FROM report_credentials WHERE report_id = ? AND host = ?", args: [reportId, host],
  });
  return rows[0];
}

/** What the owner's view of one binding carries into the tap: the reference and the rule digest. */
async function shownFor(db, reportId, host = "example.com") {
  const row = await storedCredential(db, reportId, host);
  return { connectionUuid: row.connection_uuid, injectHash: injectHashOf(JSON.parse(row.inject_json)) };
}

/** The owner's tap on the binding as the view shows it now. */
async function tapApprove(db, reportId, host = "example.com") {
  const shown = await shownFor(db, reportId, host);
  return approveCredential(db, deps(), { reportId, host, ...shown, actor: OWNER });
}

/* ----------------------------------------------------------------------- host grammar */

test("a host is an exact lower-case name or a *.suffix with two labels", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);

  for (const accepted of ["example.com", "api.example.com", "*.example.com", "a.example.co.uk"]) {
    const row = await proposeHost(db, deps(), { reportId, host: accepted });
    assert.equal(row.host, accepted, accepted);
    assert.equal(row.state, "proposed");
  }

  for (const refused of [
    "", "example", "*.com", "*.example", "com", "*.com.", "Example.com", "EXAMPLE.COM",
    "127.0.0.1", "1.2.3.4", "::1", "example.com.", "exa mple.com", "-bad.example.com",
    "bad-.example.com", "exa_mple.com", "*.", "*", "*.example.com.", "example.com:443",
  ]) {
    await assert.rejects(
      () => proposeHost(db, deps(), { reportId, host: refused }),
      { code: "bad_input" },
      JSON.stringify(refused),
    );
  }
  const { rows } = await db.execute({ sql: "SELECT COUNT(*) AS n FROM report_hosts WHERE report_id = ?", args: [reportId] });
  assert.equal(Number(rows[0].n), 4, "only the four accepted hosts were stored");
});

/* -------------------------------------------------------------------- host approvals */

test("approving a host seals it, returns the sentence, and lists without the seal", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await proposeHost(db, deps(), { reportId, host: "example.com" });

  const approved = await approveHost(db, deps(), { reportId, host: "example.com", actor: OWNER });
  assert.equal(approved.notice, HOST_APPROVAL_LINE);
  assert.equal(approved.notice,
    "Check that this site allows automated access. This is your responsibility.");
  assert.equal(approved.host.state, "approved");
  assert.equal(approved.host.verified, true);
  assert.equal(approved.host.approvedAt, T0);

  const { rows } = await db.execute({
    sql: "SELECT * FROM report_hosts WHERE report_id = ? AND host = ?",
    args: [reportId, "example.com"],
  });
  assert.match(rows[0].approval_seal, /^[0-9a-f]{64}$/);
  assert.match(rows[0].approval_nonce, /^[0-9a-f]{32}$/);
  assert.equal(await verifyHost(db, deps(), rows[0]), true);

  const listed = await listHosts(db, reportId, deps());
  assert.equal(listed.length, 1);
  assert.equal(listed[0].verified, true);
  assert.equal(JSON.stringify(listed).includes("approval_seal"), false, "no seal in the list");
  assert.equal(JSON.stringify(listed).includes("approval_nonce"), false, "no nonce in the list");
  assert.equal(JSON.stringify(listed).includes("seal"), false);

  // A direct UPDATE of the host name breaks the seal.
  await db.execute({
    sql: "UPDATE report_hosts SET host = 'other.example.com' WHERE report_id = ? AND host = 'example.com'",
    args: [reportId],
  });
  const moved = (await db.execute({
    sql: "SELECT * FROM report_hosts WHERE report_id = ?", args: [reportId],
  })).rows[0];
  assert.equal(await verifyHost(db, deps(), moved), false);
  assert.equal(await hostApproved(db, deps(), reportId, "other.example.com"), false);
});

test("revoking a host NULLs the seal and the nonce", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedHost(db, reportId);

  const revoked = await revokeHost(db, deps(), { reportId, host: "example.com", actor: OWNER });
  assert.equal(revoked.state, "revoked");
  assert.equal(revoked.approvedAt, null);
  const raw = (await db.execute({
    sql: "SELECT * FROM report_hosts WHERE report_id = ?", args: [reportId],
  })).rows[0];
  assert.equal(raw.approval_seal, null);
  assert.equal(raw.approval_nonce, null);
  assert.equal(await verifyHost(db, deps(), raw), false);
  assert.equal(await hostApproved(db, deps(), reportId, "example.com"), false);

  const { rows } = await db.execute({
    sql: "SELECT kind, subject, decided FROM report_approvals_audit WHERE report_id = ? ORDER BY id",
    args: [reportId],
  });
  assert.deepEqual(rows, [
    { kind: "host", subject: "example.com", decided: "approved" },
    { kind: "host", subject: "example.com", decided: "revoked" },
  ]);
});

test("host approvals and revocations are owner only", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await proposeHost(db, deps(), { reportId, host: "example.com" });
  for (const actor of [BOT_ACTOR, undefined, null, { kind: "system" }]) {
    await assert.rejects(
      () => approveHost(db, deps(), { reportId, host: "example.com", actor }),
      { code: "owner_only" },
    );
    await assert.rejects(
      () => revokeHost(db, deps(), { reportId, host: "example.com", actor }),
      { code: "owner_only" },
    );
  }
  const raw = (await db.execute({
    sql: "SELECT * FROM report_hosts WHERE report_id = ?", args: [reportId],
  })).rows[0];
  assert.equal(raw.state, "proposed");
  assert.equal(raw.approval_seal, null);
});

/* ------------------------------------------------------------------ credential binding */

test("a credential needs an approved host, and its own host is exact", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await saveServiceSecret(db, key, {
    connectionUuid: UUID_A, bundleId: REPORTS_BUNDLE, envKey: "REPORT_CREDENTIAL", label: "x", secret: SECRET,
  });

  await proposeHost(db, deps(), { reportId, host: "example.com" });
  await assert.rejects(
    () => proposeCredential(db, deps(), {
      reportId, host: "example.com", connectionUuid: UUID_A, inject: RULE, proposedBy: "owner",
    }),
    { code: "host_not_approved" },
    "a proposed host is not an approved one",
  );

  await approveHost(db, deps(), { reportId, host: "example.com", actor: OWNER });
  const proposed = await proposeCredential(db, deps(), {
    reportId, host: "example.com", connectionUuid: UUID_A, inject: RULE, proposedBy: "bot:bot-1",
  });
  assert.equal(proposed.state, "proposed", "a credential is proposed, never approved by asking");
  assert.equal(proposed.connectionUuid, UUID_A);
  assert.deepEqual(proposed.inject, {
    header: "Authorization", format: "Bearer {}", pathPrefixes: ["/v1/issues"], methods: ["GET", "HEAD"],
  });
  assert.equal(proposed.verified, false);

  await assert.rejects(
    () => proposeCredential(db, deps(), {
      reportId, host: "*.example.com", connectionUuid: UUID_B, inject: RULE, proposedBy: "owner",
    }),
    { code: "bad_input" },
    "a credential binds one exact site",
  );
  await assert.rejects(
    () => proposeCredential(db, deps(), {
      reportId, host: "other.example.com", connectionUuid: UUID_B, inject: RULE, proposedBy: "owner",
    }),
    { code: "host_not_approved" },
  );
});

test("a wildcard host cover makes an exact credential host approvable", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedHost(db, reportId, "*.example.com");
  assert.equal(await hostApproved(db, deps(), reportId, "api.example.com"), true);
  assert.equal(await hostApproved(db, deps(), reportId, "example.com"), false,
    "a wildcard does not cover the bare suffix");

  const proposed = await credentialWithSecret(db, reportId, { host: "api.example.com" });
  assert.equal(proposed.host, "api.example.com");
  assert.equal(proposed.state, "proposed");
});

test("a rule the relay would refuse is refused here too (bad_inject)", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedHost(db, reportId);
  await saveServiceSecret(db, key, {
    connectionUuid: UUID_A, bundleId: REPORTS_BUNDLE, envKey: "REPORT_CREDENTIAL", label: "x", secret: SECRET,
  });
  const proposeRule = (inject) => proposeCredential(db, deps(), {
    reportId, host: "example.com", connectionUuid: UUID_A, inject, proposedBy: "owner",
  });

  const bad = [
    { header: "Authorization", format: "Bearer {}" },
    { header: "Authorization", pathPrefixes: [] },
    { header: "Authorization", pathPrefixes: "[/v1]" },
    { header: "Authorization", pathPrefixes: ["v1"] },
    { header: "Authorization", pathPrefixes: ["/"] },
    { header: "Authorization", pathPrefixes: ["//"] },
    { pathPrefixes: ["/v1"] },
    { header: "Authorization", query: "key", pathPrefixes: ["/v1"] },
    { header: "Authorization", format: "Bearer", pathPrefixes: ["/v1"] },
    { header: "Authorization", format: "Bearer {} {}", pathPrefixes: ["/v1"] },
    { header: "Host", pathPrefixes: ["/v1"] },
    { header: "Proxy-Authorization", pathPrefixes: ["/v1"] },
    { header: "Bad Header", pathPrefixes: ["/v1"] },
    { query: "bad name", pathPrefixes: ["/v1"] },
    { query: "api_key", format: "{}", pathPrefixes: ["/v1"] },
    { header: "Authorization", pathPrefixes: ["/v1?x"] },
    { header: "Authorization", pathPrefixes: ["/v1/../etc"] },
    { header: "Authorization", pathPrefixes: ["/v1"], methods: ["GET", "TRACE"] },
    { header: "Authorization", pathPrefixes: ["/v1"], methods: [] },
    [],
    "Authorization",
  ];
  for (const inject of bad) {
    await assert.rejects(() => proposeRule(inject), { code: "bad_inject" }, JSON.stringify(inject));
  }
  const { rows } = await db.execute({
    sql: "SELECT COUNT(*) AS n FROM report_credentials WHERE report_id = ?", args: [reportId],
  });
  assert.equal(Number(rows[0].n), 0, "no row was written by any refused rule");

  const ok = await proposeRule({ query: "api_key", pathPrefixes: ["/v1"] });
  assert.deepEqual(ok.inject, { query: "api_key", pathPrefixes: ["/v1"], methods: ["GET", "HEAD"] });
});

test("approving a credential seals it and the list never carries the secret", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedHost(db, reportId);
  await credentialWithSecret(db, reportId);

  const approved = await tapApprove(db, reportId);
  assert.equal(approved.state, "approved");
  assert.equal(approved.verified, true);
  assert.equal(approved.approvedAt, T0);
  assert.equal(approved.injectHash, injectHashOf(RULE), "the view carries the digest the tap hands back");

  const raw = await storedCredential(db, reportId, "example.com");
  assert.match(raw.approval_seal, /^[0-9a-f]{64}$/);
  assert.equal(await verifyCredential(db, deps(), raw), true);

  const listed = await listCredentials(db, reportId, deps());
  assert.equal(listed.length, 1);
  assert.equal(listed[0].verified, true);
  assert.equal(listed[0].connectionUuid, UUID_A);
  const json = JSON.stringify(listed);
  assert.equal(json.includes(SECRET), false, "the secret is never in the list");
  assert.equal(json.includes("approval_seal"), false);
  assert.equal(json.includes("approval_nonce"), false);
  assert.equal(json.includes("secret_sealed"), false);
  assert.equal("secret" in listed[0], false);

  // A direct UPDATE of the bound reference breaks the seal (the reference is a sealed field).
  await db.execute({
    sql: "UPDATE report_credentials SET connection_uuid = ? WHERE report_id = ? AND host = ?",
    args: [UUID_B, reportId, "example.com"],
  });
  assert.equal(await verifyCredential(db, deps(), await storedCredential(db, reportId, "example.com")), false);

  for (const actor of [BOT_ACTOR, undefined, { kind: "system" }]) {
    await assert.rejects(
      () => approveCredential(db, deps(), {
        reportId, host: "example.com", connectionUuid: UUID_B, injectHash: injectHashOf(RULE), actor,
      }),
      { code: "owner_only" },
    );
    await assert.rejects(
      () => revokeCredential(db, deps(), { reportId, host: "example.com", actor }),
      { code: "owner_only" },
    );
  }
});

test("the credential seal covers the shape of the inject rule", async () => {  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedHost(db, reportId);
  await credentialWithSecret(db, reportId);
  await tapApprove(db, reportId);
  const approvedJson = (await storedCredential(db, reportId, "example.com")).inject_json;
  assert.equal((await injectRulesFor(db, deps(), { reportId })).length, 1);

  const writeRule = async (rule) => {
    await db.execute({
      sql: "UPDATE report_credentials SET inject_json = ? WHERE report_id = ? AND host = ?",
      args: [JSON.stringify(rule), reportId, "example.com"],
    });
    const row = await storedCredential(db, reportId, "example.com");
    assert.equal(row.state, "approved", "the state word is never touched by the UPDATE");
    return row;
  };

  // A rule read back in another key order is the same rule: the seal digests canonical text.
  const reordered = JSON.parse(approvedJson);
  const rewritten = {
    methods: [...reordered.methods].reverse(),
    pathPrefixes: [...reordered.pathPrefixes],
    format: reordered.format,
    header: reordered.header,
  };
  assert.equal(await verifyCredential(db, deps(), await writeRule(rewritten)), true,
    "re-ordering the same rule is not a different approval");
  assert.equal((await injectRulesFor(db, deps(), { reportId })).length, 1);

  // A WIDER path prefix list is a different binding on the host.
  const widened = await writeRule({ ...reordered, pathPrefixes: ["/v1/issues", "/v2"] });
  assert.equal(await verifyCredential(db, deps(), widened), false);
  assert.deepEqual(await injectRulesFor(db, deps(), { reportId }), []);
  assert.equal((await listCredentials(db, reportId, deps()))[0].verified, false);
  assert.equal((await credentialSecretFor(db, deps(), { reportId, host: "example.com" }))(), "");

  // A POST the owner never approved would put the credential on a write request.
  const writing = await writeRule({ ...reordered, methods: [...reordered.methods, "POST"] });
  assert.equal(await verifyCredential(db, deps(), writing), false);
  assert.deepEqual(await injectRulesFor(db, deps(), { reportId }), []);

  // Another header moves the credential out of the one the owner approved.
  const movedHeader = await writeRule({ ...reordered, header: "X-Api-Key", format: "{}" });
  assert.equal(await verifyCredential(db, deps(), movedHeader), false);
  assert.deepEqual(await injectRulesFor(db, deps(), { reportId }), []);

  // Another format on the same header is a different header value.
  const movedFormat = await writeRule({ ...reordered, format: "Token {}" });
  assert.equal(await verifyCredential(db, deps(), movedFormat), false);
  assert.deepEqual(await injectRulesFor(db, deps(), { reportId }), []);

  // A query parameter instead of a header carries no format at all.
  const asQuery = await writeRule({ query: "api_key", pathPrefixes: reordered.pathPrefixes });
  assert.equal(await verifyCredential(db, deps(), asQuery), false);
  assert.deepEqual(await injectRulesFor(db, deps(), { reportId }), []);

  // A row that is not a rule any more does not verify, and approving it again is refused.
  const broken = await writeRule({ header: "Authorization", pathPrefixes: [] });
  assert.equal(await verifyCredential(db, deps(), broken), false);
  await assert.rejects(
    () => approveCredential(db, deps(), {
      reportId, host: "example.com", connectionUuid: UUID_A, injectHash: injectHashOf(RULE), actor: OWNER,
    }),
    { code: "bad_inject" },
    "a row that is not a rule is not an approval over nothing",
  );

  // Putting the approved rule back restores the owner's approval, because content is what it covers.
  await db.execute({
    sql: "UPDATE report_credentials SET inject_json = ? WHERE report_id = ? AND host = ?",
    args: [approvedJson, reportId, "example.com"],
  });
  assert.equal(await verifyCredential(db, deps(), await storedCredential(db, reportId, "example.com")), true);
  assert.equal((await injectRulesFor(db, deps(), { reportId })).length, 1);
});

/* ------------------------------------------------------------ the rule's own digest */

test("a rule's digest is canonical: one key order, sorted prefixes and methods", () => {
  const rule = {
    header: "Authorization",
    format: "Bearer {}",
    pathPrefixes: ["/v1/issues", "/v1/repos"],
    methods: ["HEAD", "GET"],
  };
  assert.equal(canonicalInject(rule),
    '{"header":"Authorization","query":"","format":"Bearer {}","pathPrefixes":["/v1/issues","/v1/repos"],"methods":["GET","HEAD"]}',
    "five keys, one order, sorted lists, nothing else");
  assert.equal(canonicalInject({ methods: ["GET", "HEAD"], pathPrefixes: ["/v1/repos", "/v1/issues"],
    format: "Bearer {}", header: "Authorization" }), canonicalInject(rule), "the typing order is not sealed");
  assert.match(injectHashOf(rule), /^[0-9a-f]{64}$/);
  assert.equal(injectHashOf(rule), injectHashOf({ ...rule, pathPrefixes: [...rule.pathPrefixes].reverse() }));

  const header = injectHashOf(rule);
  assert.notEqual(header, injectHashOf({ ...rule, pathPrefixes: ["/v1/issues", "/v1/repos", "/v2"] }));
  assert.notEqual(header, injectHashOf({ ...rule, methods: ["GET", "HEAD", "POST"] }));
  assert.notEqual(header, injectHashOf({ ...rule, header: "X-Api-Key" }));
  assert.notEqual(header, injectHashOf({ ...rule, format: "Token {}" }));
  assert.notEqual(header, injectHashOf({ query: "api_key", pathPrefixes: rule.pathPrefixes }));
  assert.throws(() => injectHashOf({ header: "Authorization", pathPrefixes: [] }), {
    code: "inject_bad_path_prefixes",
  });
});

/* --------------------------------------------------------------------- the secret read */

test("the secret is read from the keychain only while the binding verifies", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedHost(db, reportId);
  await credentialWithSecret(db, reportId);

  // Before the owner's tap there is no secret to hand out.
  const beforeApproval = await credentialSecretFor(db, deps(), { reportId, host: "example.com" });
  assert.equal(beforeApproval(), "");
  assert.equal(await beforeApproval.refresh(), "");

  await tapApprove(db, reportId);
  const secret = await credentialSecretFor(db, deps(), { reportId, host: "example.com" });
  assert.equal(secret(), SECRET, "the stored secret, from the keychain, at call time");
  assert.equal(await secret.refresh(), SECRET);

  // The sealed row really holds the value: read it back the way the gateway would.
  const found = await serviceSecretsFor(db, key, UUID_A, { allowedKeys: ["REPORT_CREDENTIAL"] });
  assert.equal(found.REPORT_CREDENTIAL, SECRET);

  // A revoked binding answers nothing, on a fresh closure and on the one already held.
  await revokeCredential(db, deps(), { reportId, host: "example.com", actor: OWNER });
  const afterRevoke = await credentialSecretFor(db, deps(), { reportId, host: "example.com" });
  assert.equal(afterRevoke(), "");
  assert.equal(await secret.refresh(), "", "the closure a run holds stops answering after a revoke");
});

test("a tampered binding and a revoked host both stop the secret", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  const host = await approvedHost(db, reportId);
  await credentialWithSecret(db, reportId);
  await tapApprove(db, reportId);
  assert.equal((await credentialSecretFor(db, deps(), { reportId, host: "example.com" }))(), SECRET);

  // The host approval is revoked: the credential row itself is untouched and still verifies.
  assert.equal(host.verified, true);
  await revokeHost(db, deps(), { reportId, host: "example.com", actor: OWNER });
  assert.equal((await credentialSecretFor(db, deps(), { reportId, host: "example.com" }))(), "");
  assert.deepEqual(await injectRulesFor(db, deps(), { reportId }), []);

  // Re-approve the host: the credential is usable again, because its own approval never moved.
  await approveHost(db, deps(), { reportId, host: "example.com", actor: OWNER });
  assert.equal((await credentialSecretFor(db, deps(), { reportId, host: "example.com" }))(), SECRET);

  // A broken seal on the credential row stops it, even with the state word left as approved.
  await db.execute({
    sql: "UPDATE report_credentials SET approval_seal = ? WHERE report_id = ? AND host = ?",
    args: ["0".repeat(64), reportId, "example.com"],
  });
  assert.equal((await credentialSecretFor(db, deps(), { reportId, host: "example.com" }))(), "");
  assert.deepEqual(await injectRulesFor(db, deps(), { reportId }), []);
});

test("a revoke does not disconnect a keychain row that is another bundle's connection", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedHost(db, reportId);
  await credentialWithSecret(db, reportId);
  await tapApprove(db, reportId);

  // Two rows that are NOT this bundle's report credential: one belongs to another bundle, and one is
  // this bundle's id under another env key. A direct UPDATE of the binding row points at the first.
  const OTHER_BUNDLE = "someone-elses-addon";
  await saveServiceSecret(db, key, {
    connectionUuid: UUID_B,
    bundleId: OTHER_BUNDLE,
    envKey: "REPORT_CREDENTIAL",
    label: "another bundle's row",
    secret: "another-secret-value",
  });
  await saveServiceSecret(db, key, {
    connectionUuid: UUID_B,
    bundleId: REPORTS_BUNDLE,
    envKey: "SOME_OTHER_KEY",
    label: "another env key",
    secret: "a-third-secret-value",
  });
  await db.execute({
    sql: "UPDATE report_credentials SET connection_uuid = ? WHERE report_id = ? AND host = ?",
    args: [UUID_B, reportId, "example.com"],
  });

  // The normal owner revoke route (no `skipDisconnect`) revokes the binding and leaves both of those
  // rows serving: only a `crow-reports` `REPORT_CREDENTIAL` row is this bundle's to disconnect.
  const revoked = await revokeCredential(db, deps(), { reportId, host: "example.com", actor: OWNER });
  assert.equal(revoked.state, "revoked");
  const { rows } = await db.execute({
    sql: `SELECT env_key, status FROM crow_keychain
           WHERE connection_uuid = ? ORDER BY env_key`,
    args: [UUID_B],
  });
  assert.deepEqual(rows.map((row) => [row.env_key, row.status]), [
    ["REPORT_CREDENTIAL", "active"],
    ["SOME_OTHER_KEY", "active"],
  ], "another bundle's connection is not disconnected by a reports revoke");
});

test("a missing keychain key answers nothing rather than throwing", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedHost(db, reportId);
  await credentialWithSecret(db, reportId);
  await tapApprove(db, reportId);

  const noKey = await credentialSecretFor(db, { ...deps(), loadKeychainKey: () => null }, {
    reportId, host: "example.com",
  });
  assert.equal(noKey(), "");

  const otherDb = await freshDb();
  const otherReport = await makeReport(otherDb, "Another report");
  const nothing = await credentialSecretFor(otherDb, deps(), { reportId: otherReport, host: "example.com" });
  assert.equal(nothing(), "");
});

/* ----------------------------------------------------------------- the relay's rules */

test("injectRulesFor hands the relay one rule per approved, verified binding", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedHost(db, reportId, "example.com");
  await approvedHost(db, reportId, "second.example.net");

  await credentialWithSecret(db, reportId, { host: "example.com", connectionUuid: UUID_A });
  await credentialWithSecret(db, reportId, {
    host: "second.example.net",
    connectionUuid: UUID_B,
    secret: "another-secret-value",
    inject: { query: "api_key", pathPrefixes: ["/v1"] },
  });
  // Neither is approved yet, so the relay is handed nothing.
  assert.deepEqual(await injectRulesFor(db, deps(), { reportId }), []);

  await tapApprove(db, reportId, "example.com");
  await tapApprove(db, reportId, "second.example.net");

  const rules = await injectRulesFor(db, deps(), { reportId });
  assert.equal(rules.length, 2);
  const byHost = Object.fromEntries(rules.map((rule) => [rule.host, rule]));
  assert.equal(byHost["example.com"].header, "Authorization");
  assert.equal(byHost["example.com"].format, "Bearer {}");
  assert.deepEqual(byHost["example.com"].pathPrefixes, ["/v1/issues"]);
  assert.deepEqual(byHost["example.com"].methods, ["GET", "HEAD"]);
  assert.equal(typeof byHost["example.com"].secret, "function");
  assert.equal(byHost["example.com"].secret(), SECRET);
  assert.equal(byHost["second.example.net"].query, "api_key");
  assert.equal("format" in byHost["second.example.net"], false, "a query rule carries no format");
  assert.equal(byHost["second.example.net"].secret(), "another-secret-value");
  assert.equal(JSON.stringify(rules).includes(SECRET), false, "no rule ever carries a value");

  // Another report sees none of them.
  const otherReport = await makeReport(db, "Another report");
  assert.deepEqual(await injectRulesFor(db, deps(), { reportId: otherReport }), []);
  await assert.rejects(() => injectRulesFor(db, deps(), {}), { code: "bad_input" });
});

test("replacing a credential proposes the new reference and hands the old one back", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedHost(db, reportId);
  await credentialWithSecret(db, reportId, { connectionUuid: UUID_A });
  await tapApprove(db, reportId);

  const replaced = await credentialWithSecret(db, reportId, { connectionUuid: UUID_B });
  assert.equal(replaced.connectionUuid, UUID_B);
  assert.equal(replaced.previousConnectionUuid, UUID_A);
  assert.equal(replaced.state, "proposed", "a replacement is not an approval");
  const raw = await storedCredential(db, reportId, "example.com");
  assert.equal(raw.approval_seal, null);
  assert.equal(raw.approval_nonce, null);
  assert.deepEqual(await injectRulesFor(db, deps(), { reportId }), [],
    "an unapproved replacement stops the rule");
});

/* ------------------------------------------------- the closure against a moved binding */

test("a revoked binding stops a closure that was built before the revoke", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedHost(db, reportId);
  await credentialWithSecret(db, reportId);
  await tapApprove(db, reportId);

  const held = await credentialSecretFor(db, deps(), { reportId, host: "example.com" });
  assert.equal(held(), SECRET, "the binding verifies, so the closure answers the secret");

  await revokeCredential(db, deps(), { reportId, host: "example.com", actor: OWNER });
  assert.equal(await held.refresh(), "", "a revoke reaches the closure a run already holds");
  assert.equal(held(), "", "and the next call reads the row, not a cached answer");

  // A row that is gone is the same answer as a row that moved.
  await db.execute({
    sql: "DELETE FROM report_credentials WHERE report_id = ? AND host = ?", args: [reportId, "example.com"],
  });
  assert.equal(await held.refresh(), "");
  assert.equal(await held.refresh(), "", "and it stays silent on every later read");
});

test("a replaced binding never serves the new keychain row through an old closure", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedHost(db, reportId);
  await credentialWithSecret(db, reportId, { connectionUuid: UUID_A, secret: SECRET });
  await tapApprove(db, reportId);

  const held = await credentialSecretFor(db, deps(), { reportId, host: "example.com" });
  assert.equal(held(), SECRET);

  const NEW_SECRET = "replacement-value-0123456789abcdef";
  await credentialWithSecret(db, reportId, { connectionUuid: UUID_B, secret: NEW_SECRET });
  assert.equal(await held.refresh(), "",
    "a proposal for another keychain row is not the binding this closure was built on");

  await tapApprove(db, reportId);
  assert.equal(await held.refresh(), "",
    "the old closure never serves the new row's secret either");
  assert.equal(held(), "");

  const fresh = await credentialSecretFor(db, deps(), { reportId, host: "example.com" });
  assert.equal(fresh(), NEW_SECRET, "a closure built now answers the row that is there now");
});

test("a direct UPDATE of the rule stops a closure that was built before it", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedHost(db, reportId);
  await credentialWithSecret(db, reportId);
  await tapApprove(db, reportId);

  const held = await credentialSecretFor(db, deps(), { reportId, host: "example.com" });
  assert.equal(held(), SECRET);

  await db.execute({
    sql: "UPDATE report_credentials SET inject_json = ? WHERE report_id = ? AND host = ?",
    args: [JSON.stringify({ ...RULE, pathPrefixes: ["/v1/issues", "/v2"] }), reportId, "example.com"],
  });
  assert.equal(await held.refresh(), "", "the rule under that seal is not the rule on the row");
  assert.equal(held(), "");
});

/* -------------------------------------------------------------- the owner's tap guards */

test("an approval whose expected reference or rule digest is stale is refused", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedHost(db, reportId);
  await credentialWithSecret(db, reportId);

  // The view said this rule; the row holds a wider one.
  await assert.rejects(
    () => approveCredential(db, deps(), {
      reportId,
      host: "example.com",
      connectionUuid: UUID_A,
      injectHash: injectHashOf({ ...RULE, pathPrefixes: ["/v1/issues", "/v2"] }),
      actor: OWNER,
    }),
    { code: "credential_changed" },
  );
  let raw = await storedCredential(db, reportId, "example.com");
  assert.equal(raw.state, "proposed", "a stale digest approves nothing");
  assert.equal(raw.approval_seal, null);
  assert.equal(raw.approval_nonce, null);

  // The view said UUID_A; the row holds another reference now.
  await assert.rejects(
    () => approveCredential(db, deps(), {
      reportId, host: "example.com", connectionUuid: UUID_B, injectHash: injectHashOf(RULE), actor: OWNER,
    }),
    { code: "credential_changed" },
  );
  raw = await storedCredential(db, reportId, "example.com");
  assert.equal(raw.state, "proposed", "a stale reference approves nothing");
  assert.equal(raw.approval_seal, null);

  // A tap that names no reference, or no digest, is not a tap over anything.
  for (const connectionUuid of [undefined, null, "", "short", "has space", 42]) {
    await assert.rejects(
      () => approveCredential(db, deps(), {
        reportId, host: "example.com", connectionUuid, injectHash: injectHashOf(RULE), actor: OWNER,
      }),
      { code: "bad_input" },
      String(connectionUuid),
    );
  }
  for (const injectHash of [undefined, null, "", "0".repeat(63), "z".repeat(64)]) {
    await assert.rejects(
      () => approveCredential(db, deps(), {
        reportId, host: "example.com", connectionUuid: UUID_A, injectHash, actor: OWNER,
      }),
      { code: "bad_input" },
      String(injectHash),
    );
  }
  raw = await storedCredential(db, reportId, "example.com");
  assert.equal(raw.state, "proposed");
  assert.equal(raw.approval_seal, null);

  // The row the view showed is approved by the tap that matches it.
  const approved = await tapApprove(db, reportId);
  assert.equal(approved.state, "approved");
  assert.equal(approved.verified, true);
});

test("a rule written between the read and the write is never approved", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  await approvedHost(db, reportId);
  await credentialWithSecret(db, reportId);
  const shown = await shownFor(db, reportId);

  // The seed reader is awaited after the row is read and before the guarded write, so it stands in
  // for another writer landing in that window.
  let moved = false;
  const racing = deps({
    loadSeed: async () => {
      if (!moved) {
        moved = true;
        await db.execute({
          sql: "UPDATE report_credentials SET inject_json = ? WHERE report_id = ? AND host = ?",
          args: [JSON.stringify({ ...RULE, pathPrefixes: ["/v1/issues", "/v2"] }), reportId, "example.com"],
        });
      }
      return { seed: key.seed };
    },
  });
  await assert.rejects(
    () => approveCredential(db, racing, { reportId, host: "example.com", ...shown, actor: OWNER }),
    { code: "credential_changed" },
  );
  assert.equal(moved, true, "the writer landed between the read and the write");

  const raw = await storedCredential(db, reportId, "example.com");
  assert.equal(raw.state, "proposed", "nothing was sealed over the rule that arrived mid-flight");
  assert.equal(raw.approval_seal, null);
  assert.equal(raw.approval_nonce, null);
  assert.deepEqual(await injectRulesFor(db, deps(), { reportId }), []);

  // With no move in the window, the same tap approves the row.
  const approved = await tapApprove(db, reportId);
  assert.equal(approved.state, "approved");
  assert.equal(approved.verified, true);
});