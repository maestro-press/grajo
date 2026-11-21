// The four source blocks of Crow Recurring Reports: http_json, rss, mail_alerts and workspace_file.
//
// Every source reads only what the owner approved, on the terms it declares:
//   - the URL sources check the report's host approvals before a socket is opened AND again on the
//     host the response really came from, and the request itself goes through the injected
//     guarded-request seam;
//   - a credential goes in exactly one place (the first hop's header, or the first hop's query) and
//     never into an answer: a body that echoes it in any spelling is `credential_echoed` with no items,
//     and an error that quotes the request URL is redacted;
//   - the mail source reads through the injected `adapterFor` seam and only the report's own sender
//     account;
//   - the workspace file stays inside the workspace directory, real symlinks, FIFOs and oversize files
//     included.
//
// Harness: a real init-db'd scratch crow.db per test, a real keychain key under a temp CROW_HOME (so an
// approved credential's secret is sealed and reopened), a real approved host and credential through the
// steps module, two local servers on 127.0.0.1 for the redirect rule, and injected fetch/mail seams
// everywhere a source reads.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import { execFileSync } from "node:child_process";
import {
  copyFileSync, mkdirSync, mkdtempSync, rmSync, symlinkSync, writeFileSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const root = mkdtempSync(join(tmpdir(), "reports-blocks-sources-"));
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
const { REPORTS_BUNDLE, saveServiceSecret } = await import("../servers/gateway/keychain/store.js");
const {
  approveCredential, approveHost, injectHashOf, proposeCredential, proposeHost,
} = await import("../servers/gateway/reports/steps.js");
const { createReport, updateReportColumns } = await import("../servers/gateway/reports/store.js");
const { createAccount } = await import("../servers/gateway/mail/store/accounts.js");
const { guardedRequest } = await import("../servers/shared/fetch-page.js");
const { runRecipe } = await import("../servers/gateway/reports/blocks/run-recipe.js");
const { httpJsonBlock, echoForms, secretForms, rawPathOf, credentialPathAllowed } = await import(
  "../servers/gateway/reports/blocks/sources/http-json.js"
);
const { rssBlock } = await import("../servers/gateway/reports/blocks/sources/rss.js");
const { MAIL_READ_SENTENCE, mailAlertsBlock } = await import(
  "../servers/gateway/reports/blocks/sources/mail-alerts.js"
);
const { parseCsv, workspaceFileBlock, MAX_FILE_BYTES } = await import(
  "../servers/gateway/reports/blocks/sources/workspace-file.js"
);

const OWNER = Object.freeze({ kind: "owner" });
const T0 = 1_700_000_000_000;
const DAY_MS = 24 * 60 * 60 * 1000;
const SECRET = "s3cr3t+value/with=list&more";
const SECRET_FORMS = Object.freeze([
  SECRET,
  encodeURIComponent(SECRET),
  Buffer.from(SECRET, "utf8").toString("base64"),
]);
const HEADER_RULE = Object.freeze({
  header: "Authorization", format: "Bearer {}", pathPrefixes: ["/v1/issues"], methods: ["GET"],
});
const QUERY_RULE = Object.freeze({
  query: "api_key", pathPrefixes: ["/v1/issues"], methods: ["GET"],
});

/** The keychain key this instance really has once it has one (written under the temp home). */
const key = createKeychainKey({ crowHome: HOME });

const open = [];
let serverA;
let serverB;
let portA;
let portB;
const seen = { a: [], b: [] };

after(() => {
  for (const db of open) { try { db.close(); } catch { /* closed */ } }
  for (const server of [serverA, serverB]) {
    if (!server) continue;
    server.closeAllConnections();
    server.close();
  }
  rmSync(root, { recursive: true, force: true });
});

before(async () => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
  serverA = http.createServer((req, res) => {
    seen.a.push({ url: req.url, headers: req.headers });
    if (req.url === "/same") {
      res.writeHead(302, { Location: "/final" });
      return res.end();
    }
    if (req.url.startsWith("/cross")) {
      res.writeHead(302, { Location: `http://b.example.com:${portB}/final` });
      return res.end();
    }
    res.writeHead(200, { "Content-Type": "text/plain" });
    return res.end("ok");
  });
  portA = await listen(serverA);
  serverB = http.createServer((req, res) => {
    seen.b.push({ url: req.url, headers: req.headers });
    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("ok");
  });
  portB = await listen(serverB);
});

function listen(server) {
  return new Promise((resolve) => server.listen(0, "127.0.0.1", () => resolve(server.address().port)));
}

/* ------------------------------------------------------------------- the harness */

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

/** The approvals seam: the seal seed, the clock, this instance's home and its keychain key. */
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

async function reportWithHost(db, host = "example.com") {
  const reportId = await makeReport(db);
  await proposeHost(db, deps(), { reportId, host });
  await approveHost(db, deps(), { reportId, host, actor: OWNER });
  return reportId;
}

/** One approved credential for an approved host, through the real keychain row and the owner's tap. */
async function reportWithCredential(db, { host = "example.com", inject = HEADER_RULE, secret = SECRET } = {}) {
  const reportId = await makeReport(db);
  await proposeHost(db, deps(), { reportId, host });
  await approveHost(db, deps(), { reportId, host, actor: OWNER });
  const connectionUuid = "11111111-1111-4111-8111-111111111111";
  await saveServiceSecret(db, key, {
    connectionUuid,
    bundleId: REPORTS_BUNDLE,
    envKey: "REPORT_CREDENTIAL",
    label: "report credential",
    secret,
  });
  await proposeCredential(db, deps(), { reportId, host, connectionUuid, inject });
  const { rows } = await db.execute({
    sql: "SELECT connection_uuid, inject_json FROM report_credentials WHERE report_id = ? AND host = ?",
    args: [reportId, host],
  });
  await approveCredential(db, deps(), {
    reportId,
    host,
    connectionUuid: rows[0].connection_uuid,
    injectHash: injectHashOf(JSON.parse(rows[0].inject_json)),
    actor: OWNER,
  });
  return reportId;
}

/** One block context, with every seam the source blocks read. */
function blockCtx(settings, over = {}) {
  return {
    db: null,
    deps: deps(),
    report: null,
    run: { trigger: "manual" },
    live: null,
    block: { id: "src", type: "source", settings },
    blockId: "src",
    getState: async () => null,
    setState: () => { throw new Error("a source block stores no state"); },
    fetch: null,
    mail: null,
    workspaceDir: null,
    log: () => {},
    ...over,
  };
}

/** A guarded-request result with a body of `body`. */
function response(body, { status = 200, contentType = "application/json", finalUrl } = {}) {
  const text = typeof body === "string" ? body : JSON.stringify(body);
  return {
    final_url: finalUrl === undefined ? "https://example.com/v1/issues" : finalUrl,
    http_status: status,
    content_type: contentType,
    charset: "utf-8",
    buffer: Buffer.from(text, "utf8"),
  };
}

/** A dns.lookup-shaped stub over a name to address table. */
function stubLookup(table) {
  const fn = (hostname, options, callback) => {
    if (typeof options === "function") { callback = options; options = {}; }
    const address = table[hostname];
    if (!address) {
      return process.nextTick(() => callback(Object.assign(new Error(`getaddrinfo ENOTFOUND ${hostname}`), { code: "ENOTFOUND" })));
    }
    if (options && options.all) return process.nextTick(() => callback(null, [{ address, family: 4 }]));
    return process.nextTick(() => callback(null, address, 4));
  };
  return fn;
}

const lookup = stubLookup({
  "a.example.com": "127.0.0.1",
  "b.example.com": "127.0.0.1",
  "private.example.com": "127.0.0.1",
});
const allowAll = () => true;

function assertNoSecret(text, where) {
  for (const form of SECRET_FORMS) {
    assert.equal(String(text).includes(form), false, `${where} carries no secret form`);
  }
}

/* -------------------------------------------------------------- http_json: the host rule */

test("http_json refuses an unapproved host", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  const calls = [];
  const ctx = blockCtx({ url: "https://example.com/v1/issues" }, {
    db,
    report: { id: reportId },
    fetch: async (url) => { calls.push(url); return response([]); },
  });
  const out = await httpJsonBlock.run(ctx, {});
  assert.deepEqual(out, { sourceError: { message: "host_unapproved" } });
  assert.deepEqual(calls, [], "no request reached the seam");
});

test("http_json refuses a private address", async () => {
  const db = await freshDb();
  const reportId = await reportWithHost(db, "private.example.com");
  let calls = 0;
  const ctx = blockCtx({ url: "http://private.example.com/v1/issues" }, {
    db,
    report: { id: reportId },
    fetch: (url, request) => {
      calls += 1;
      return guardedRequest(url, { ...request, lookup });
    },
  });
  const out = await httpJsonBlock.run(ctx, {});
  assert.deepEqual(out, { sourceError: { message: "blocked_address" } });
  assert.equal(calls, 1, "the guard refused it, not the host rule");
});

test("http_json reads the array at itemsPath and wraps a scalar item", async () => {
  const db = await freshDb();
  const reportId = await reportWithHost(db);
  const calls = [];
  const ctx = blockCtx({ url: "https://example.com/v1/issues", itemsPath: "data.items" }, {
    db,
    report: { id: reportId },
    fetch: async (url, request) => {
      calls.push({ url, request });
      return response({ data: { items: [{ id: 1 }, "plain", 3] } });
    },
  });
  const out = await httpJsonBlock.run(ctx, {});
  assert.deepEqual(out.items, [{ id: 1 }, { value: "plain" }, { value: 3 }]);
  assert.equal(calls[0].url, "https://example.com/v1/issues");
  assert.match(calls[0].request.accept, /application\/json/);
  assert.equal(calls[0].request.headers, undefined, "no credential, no headers");
  const hopRule = calls[0].request.onHop;
  assert.equal(typeof hopRule, "function", "the report's host rule rides every request, credential or not");
  assert.equal(hopRule(new URL("https://example.com/v1/issues")), true, "a hop on the approved host");
  assert.equal(hopRule(new URL("https://other.example.net/v1/issues")), false,
    "a hop to a host this report never approved");
});

test("http_json answers fetch_not_available when no seam was injected", async () => {
  const db = await freshDb();
  const reportId = await reportWithHost(db);
  const ctx = blockCtx({ url: "https://example.com/v1/issues" }, { db, report: { id: reportId } });
  const out = await httpJsonBlock.run(ctx, {});
  assert.deepEqual(out, { sourceError: { message: "fetch_not_available" } });
});

/* --------------------------------------------------------- http_json: the credential rule */

test("credential never appears in a source error", async () => {
  const db = await freshDb();
  const reportId = await reportWithCredential(db, { inject: HEADER_RULE });
  const settings = {
    url: "https://example.com/v1/issues", credential: { host: "example.com" },
  };

  // A server that echoes the secret into a body it sends as a 200: a credential echo, never items.
  const echoed = await httpJsonBlock.run(blockCtx(settings, {
    db,
    report: { id: reportId },
    fetch: async () => response({ note: "here it is", echo: SECRET }),
  }), {});
  assert.deepEqual(echoed, { sourceError: { message: "credential_echoed" } });
  assertNoSecret(echoed.sourceError.message, "a credential_echoed answer");

  // A thrown error whose message quotes the request URL (which holds the query secret).
  const queryReportId = await reportWithCredential(db, { inject: QUERY_RULE });
  let quoted = "";
  const thrown = await httpJsonBlock.run(blockCtx({
    url: "https://example.com/v1/issues", credential: { host: "example.com" },
  }, {
    db,
    report: { id: queryReportId },
    fetch: async (url) => {
      quoted = `request to ${url} failed`;
      throw Object.assign(new Error(quoted), { code: "ECONNREFUSED" });
    },
  }), {});
  assert.deepEqual(thrown, { sourceError: { message: "fetch_failed" } });
  assert.equal(quoted.includes(encodeURIComponent(SECRET)), true, "the thrown text really held the URL");
  assertNoSecret(thrown.sourceError.message, "a fetch_failed answer");

  // A non-2xx answer whose body carries the secret.
  const failed = await httpJsonBlock.run(blockCtx(settings, {
    db,
    report: { id: reportId },
    fetch: async () => response({ echo: SECRET }, { status: 500 }),
  }), {});
  assert.deepEqual(failed, { sourceError: { message: "http_error" } });
  assertNoSecret(failed.sourceError.message, "an http_error answer");
});

/** The secret written as JSON `\uXXXX` escapes, one per character. */
const ESCAPED_SECRET = Array.from(SECRET)
  .map((character) => "\\u" + character.charCodeAt(0).toString(16).padStart(4, "0"))
  .join("");

test("a body that echoes the credential is credential_echoed, in every spelling", async () => {
  const db = await freshDb();
  const reportId = await reportWithCredential(db, { inject: HEADER_RULE });
  const settings = { url: "https://example.com/v1/issues", credential: { host: "example.com" } };
  const run = (fetch) => httpJsonBlock.run(blockCtx(settings, { db, report: { id: reportId }, fetch }), {});

  const cases = [
    ["the secret as itself", () => response([{ id: "a", note: SECRET }])],
    ["percent-encoded", () => response([{ id: "a", note: encodeURIComponent(SECRET) }])],
    ["percent-encoded, lower-case escapes", () => response([
      { id: "a", note: encodeURIComponent(SECRET).replace(/%[0-9A-F]{2}/g, (escape) => escape.toLowerCase()) },
    ])],
    ["base64", () => response([{ id: "a", note: Buffer.from(SECRET, "utf8").toString("base64") }])],
    ["base64url", () => response([{ id: "a", note: Buffer.from(SECRET, "utf8").toString("base64url") }])],
    ["hex", () => response([{ id: "a", note: Buffer.from(SECRET, "utf8").toString("hex") }])],
    ["the header value", () => response([{ id: "a", note: `Bearer ${SECRET}` }])],
    ["the header value in base64", () => response([
      { id: "a", note: Buffer.from(`Bearer ${SECRET}`, "utf8").toString("base64") },
    ])],
    // Only the escapes are in the raw text; the secret is in what the body parses to.
    ["JSON-escaped", () => response(`[{"id":"a","note":"${ESCAPED_SECRET}"}]`)],
  ];
  for (const [where, fetch] of cases) {
    const out = await run(fetch);
    assert.deepEqual(out, { sourceError: { message: "credential_echoed" } }, where);
    assert.equal(out.items, undefined, `${where}: no items`);
  }

  // A body that carries nothing of the credential reads as items.
  const clean = await run(async () => response([{ id: "a", note: "nothing to see" }]));
  assert.deepEqual(clean.items, [{ id: "a", note: "nothing to see" }]);
});

test("a secret holding a quote and a backslash is caught in the parsed document", async () => {
  const db = await freshDb();
  const secret = 'p"a\\ss word';
  const reportId = await reportWithCredential(db, { inject: HEADER_RULE, secret });
  const settings = { url: "https://example.com/v1/issues", credential: { host: "example.com" } };
  const run = (fetch) => httpJsonBlock.run(blockCtx(settings, { db, report: { id: reportId }, fetch }), {});

  // The raw body escapes both characters, so only the parsed value carries the secret itself.
  const inValue = await run(async () => response(`[{"id":"a","note":${JSON.stringify(secret)}}]`));
  assert.deepEqual(inValue, { sourceError: { message: "credential_echoed" } });
  assert.equal(inValue.items, undefined);

  // A key carrying it is the same answer.
  const inKey = await run(async () => response(`[{"id":"a",${JSON.stringify(secret)}:1}]`));
  assert.deepEqual(inKey, { sourceError: { message: "credential_echoed" } });

  // The upper-case hex spelling is one of the forms too.
  const upperHex = Buffer.from(secret, "utf8").toString("hex").toUpperCase();
  const upper = await run(async () => response([{ id: "a", note: upperHex }]));
  assert.deepEqual(upper, { sourceError: { message: "credential_echoed" } });

  // A document that carries nothing of the credential reads as items.
  const clean = await run(async () => response([{ id: "a", note: "nothing here" }]));
  assert.deepEqual(clean.items, [{ id: "a", note: "nothing here" }]);
});

test("the echo spellings cover what a server could reflect", () => {
  // A secret with a space in it, so the `+` spelling is the one under test here.
  const secret = "a b+=/x";
  const forms = echoForms(secret, `Bearer ${secret}`);
  for (const form of [
    secret,
    encodeURIComponent(secret),
    encodeURIComponent(secret).replace(/%[0-9A-F]{2}/g, (escape) => escape.toLowerCase()),
    "a+b%2B%3D%2Fx",
    Buffer.from(secret, "utf8").toString("base64"),
    Buffer.from(secret, "utf8").toString("base64url"),
    Buffer.from(secret, "utf8").toString("hex"),
    `Bearer ${secret}`,
    Buffer.from(`Bearer ${secret}`, "utf8").toString("base64"),
  ]) {
    assert.equal(forms.includes(form), true, `echoForms holds ${form}`);
  }
  assert.deepEqual(echoForms(""), [], "no secret, no spellings");

  // The forms a run's error text is redacted with stay the three the block answers with.
  assert.deepEqual(secretForms(secret), [
    secret,
    encodeURIComponent(secret),
    Buffer.from(secret, "utf8").toString("base64"),
  ]);
});

test("cross-host redirect drops credential", async () => {
  const db = await freshDb();
  const headerReportId = await reportWithCredential(db, { inject: HEADER_RULE });
  const headerCalls = [];
  const headerOut = await httpJsonBlock.run(blockCtx({
    url: "https://example.com/v1/issues", credential: { host: "example.com" },
  }, {
    db,
    report: { id: headerReportId },
    fetch: async (url, request) => {
      headerCalls.push({ url, request });
      return response([{ id: "a" }]);
    },
  }), {});
  assert.deepEqual(headerOut.items, [{ id: "a" }]);
  assert.equal(headerCalls.length, 1, "one request, the guard follows the redirects itself");
  assert.equal(headerCalls[0].url, "https://example.com/v1/issues", "the header rule leaves the URL alone");
  assert.equal(headerCalls[0].request.headers.Authorization, `Bearer ${SECRET}`);
  assertNoSecret(JSON.stringify(headerOut), "the items");

  // A query credential goes into the first request URL and nowhere else.
  const queryReportId = await reportWithCredential(db, { inject: QUERY_RULE });
  const queryCalls = [];
  const queryOut = await httpJsonBlock.run(blockCtx({
    url: "https://example.com/v1/issues", credential: { host: "example.com" },
  }, {
    db,
    report: { id: queryReportId },
    fetch: async (url, request) => {
      queryCalls.push({ url, request });
      return response([]);
    },
  }), {});
  assert.deepEqual(queryOut.items, []);
  const first = new URL(queryCalls[0].url);
  assert.equal(first.searchParams.get("api_key"), SECRET);
  assert.equal(queryCalls[0].request.headers, undefined, "no header rides a query credential");
});

test("guardedRequest drops a caller header on a cross-origin redirect and keeps it on a same-origin one", async () => {
  const authorization = `Bearer ${SECRET}`;

  // Same origin: the header rides both hops.
  seen.a.length = 0;
  await guardedRequest(`http://a.example.com:${portA}/same`, {
    lookup, isAllowedAddress: allowAll, headers: { Authorization: authorization },
  });
  assert.equal(seen.a.length, 2);
  assert.equal(seen.a[0].headers.authorization, authorization);
  assert.equal(seen.a[1].headers.authorization, authorization, "a same-origin hop keeps the header");

  // Cross origin: the header and the query stop at the first origin.
  seen.a.length = 0;
  seen.b.length = 0;
  const started = `http://a.example.com:${portA}/cross?api_key=${encodeURIComponent(SECRET)}`;
  await guardedRequest(started, {
    lookup, isAllowedAddress: allowAll, headers: { Authorization: authorization },
  });
  assert.equal(seen.a.length, 1);
  assert.equal(seen.a[0].headers.authorization, authorization);
  assert.equal(seen.b.length, 1);
  assert.equal(seen.b[0].headers.authorization, undefined, "the cross-origin hop carries no header");
  assert.equal(seen.b[0].url, "/final");
  assert.equal(seen.b[0].url.includes("api_key"), false, "the cross-origin hop carries no secret query");
  assertNoSecret(seen.b[0].url, "the second hop's URL");

  // No caller headers: the request looks exactly as it did before the option existed.
  seen.a.length = 0;
  await guardedRequest(`http://a.example.com:${portA}/same`, { lookup, isAllowedAddress: allowAll });
  assert.equal(seen.a[1].headers.authorization, undefined);
  assert.match(seen.a[1].headers["user-agent"], /Crow-Research/);

  // The four framing names are ignored wherever they appear.
  seen.a.length = 0;
  await guardedRequest(`http://a.example.com:${portA}/final`, {
    lookup,
    isAllowedAddress: allowAll,
    headers: {
      host: "evil.example.com",
      "content-length": "1",
      "transfer-encoding": "chunked",
      connection: "close",
      "X-Trace": "abc",
    },
  });
  assert.equal(seen.a[0].headers.host, `a.example.com:${portA}`);
  assert.equal(seen.a[0].headers["transfer-encoding"], undefined);
  assert.equal(seen.a[0].headers["x-trace"], "abc");
});

/* ------------------------------------------------------------- the response's own host */

test("an approved host that redirects to an unapproved one gives host_unapproved", async () => {
  const db = await freshDb();
  const reportId = await reportWithHost(db);

  const json = await httpJsonBlock.run(blockCtx({ url: "https://example.com/v1/issues" }, {
    db,
    report: { id: reportId },
    fetch: async () => response([{ id: "a" }], { finalUrl: "https://other.example.net/v1/issues" }),
  }), {});
  assert.deepEqual(json, { sourceError: { message: "host_unapproved" } });
  assert.equal(json.items, undefined, "no items from the unapproved host");

  const feed = await rssBlock.run(blockCtx({ url: "https://example.com/feed.xml" }, {
    db,
    report: { id: reportId },
    fetch: async () => response(RSS_XML, {
      contentType: "application/rss+xml", finalUrl: "https://other.example.net/feed.xml",
    }),
  }), {});
  assert.deepEqual(feed, { sourceError: { message: "host_unapproved" } });
  assert.equal(feed.items, undefined, "no items from the unapproved host");

  // A response that answers no final URL at all cannot be shown to be the approved host either.
  const nowhere = await httpJsonBlock.run(blockCtx({ url: "https://example.com/v1/issues" }, {
    db,
    report: { id: reportId },
    fetch: async () => response([{ id: "a" }], { finalUrl: "" }),
  }), {});
  assert.deepEqual(nowhere, { sourceError: { message: "host_unapproved" } });
});

test("a redirect hop to a host this report has not approved is never requested, for http_json and rss", async () => {
  const db = await freshDb();
  const reportId = await reportWithHost(db, "a.example.com");
  const lookups = [];
  const recordingLookup = (hostname, options, callback) => {
    lookups.push(hostname);
    return lookup(hostname, options, callback);
  };
  const fetch = (url, request) => guardedRequest(url, {
    ...request, lookup: recordingLookup, isAllowedAddress: allowAll,
  });

  seen.a.length = 0;
  seen.b.length = 0;
  // The approved host redirects to `b.example.com`, which this report never approved.
  const json = await httpJsonBlock.run(blockCtx({ url: `http://a.example.com:${portA}/cross` }, {
    db, report: { id: reportId }, fetch,
  }), {});
  assert.deepEqual(json, { sourceError: { message: "redirect_refused" } });
  assert.equal(json.items, undefined);
  assert.equal(seen.a.length, 1, "the approved host was asked once");
  assert.equal(seen.b.length, 0, "the unapproved intermediate host was never requested");
  assert.equal(lookups.includes("b.example.com"), false, "nor was it resolved");

  seen.a.length = 0;
  seen.b.length = 0;
  lookups.length = 0;
  const feed = await rssBlock.run(blockCtx({ url: `http://a.example.com:${portA}/cross` }, {
    db, report: { id: reportId }, fetch,
  }), {});
  assert.deepEqual(feed, { sourceError: { message: "redirect_refused" } });
  assert.equal(feed.items, undefined);
  assert.equal(seen.a.length, 1);
  assert.equal(seen.b.length, 0, "the feed's unapproved hop was never requested");
  assert.equal(lookups.includes("b.example.com"), false);

  // A hop on the approved host itself still runs: `/same` redirects to `/final` on a.example.com.
  seen.a.length = 0;
  const same = await httpJsonBlock.run(blockCtx({ url: `http://a.example.com:${portA}/same` }, {
    db,
    report: { id: reportId },
    fetch: async (url, request) => {
      const answer = await fetch(url, request);
      return { ...answer, content_type: "application/json", buffer: Buffer.from("[]", "utf8") };
    },
  }), {});
  assert.deepEqual(same.items, [], "an approved host's own redirect is followed");
  assert.equal(seen.a.length, 2);
});

test("a credentialed request's redirect stays on its origin and inside its path prefixes", async () => {
  const db = await freshDb();
  const reportId = await reportWithCredential(db, { inject: HEADER_RULE });
  const calls = [];
  const out = await httpJsonBlock.run(blockCtx({
    url: "https://example.com/v1/issues", credential: { host: "example.com" },
  }, {
    db,
    report: { id: reportId },
    fetch: async (url, request) => { calls.push({ url, request }); return response([{ id: "a" }]); },
  }), {});
  assert.deepEqual(out.items, [{ id: "a" }]);

  const request = calls[0].request;
  assert.equal(typeof request.onHop, "function", "the guard is handed a hop rule");
  const hop = (href) => request.onHop(new URL(href));
  assert.equal(hop("https://example.com/v1/issues/2"), true, "a hop still inside the rule");
  assert.equal(hop("https://example.com/v2/issues"), false, "a same-origin hop out of the path prefixes");
  assert.equal(hop("https://other.example.net/v1/issues"), false, "a hop to another origin");
  assert.equal(hop("http://example.com/v1/issues"), false, "a hop to another scheme");

  // The guard's own refusal for such a hop is the block's `redirect_refused`, with no items.
  const refused = await httpJsonBlock.run(blockCtx({
    url: "https://example.com/v1/issues", credential: { host: "example.com" },
  }, {
    db,
    report: { id: reportId },
    fetch: async () => {
      throw Object.assign(new Error("redirect refused"), { code: "EREDIRECT_REFUSED" });
    },
  }), {});
  assert.deepEqual(refused, { sourceError: { message: "redirect_refused" } });
});

test("a credentialed request is bound to whole path segments and to the default port", async () => {
  const db = await freshDb();
  const reportId = await reportWithCredential(db, {
    inject: { header: "Authorization", format: "Bearer {}", pathPrefixes: ["/api"], methods: ["GET"] },
  });
  const attempt = async (url) => {
    const calls = [];
    const out = await httpJsonBlock.run(blockCtx({ url, credential: { host: "example.com" } }, {
      db,
      report: { id: reportId },
      fetch: async (target, request) => {
        calls.push({ target, request });
        return response([{ id: "a" }], { finalUrl: url });
      },
    }), {});
    return { out, calls };
  };

  // A rule for `/api` covers `/api` itself and everything under it, on whole segments.
  for (const url of [
    "https://example.com/api",
    "https://example.com/api/x",
    "https://example.com/api/x/y?page=1",
    "https://example.com:443/api/x",
  ]) {
    const { out, calls } = await attempt(url);
    assert.deepEqual(out.items, [{ id: "a" }], url);
    assert.equal(calls.length, 1, url);
    assert.equal(calls[0].request.headers.Authorization, `Bearer ${SECRET}`, url);
  }

  // `/apix` is not under `/api`, and neither is a path that could be read as one.
  for (const url of [
    "https://example.com/apix",
    "https://example.com/api../",
    "https://example.com/api/%2e%2e/x",
    "https://example.com/api/x%2f..%2fadmin",
    "https://example.com/api/x%5c..%5cadmin",
    "https://example.com/api/x%2E%2E/y",
    "https://example.com:8443/api/x",
  ]) {
    const { out, calls } = await attempt(url);
    assert.deepEqual(out, { sourceError: { message: "credential_not_allowed" } }, url);
    assert.deepEqual(calls, [], `${url}: no request reached the seam`);
  }

  // The redirect predicate applies the same two rules to every hop.
  const { calls } = await attempt("https://example.com/api");
  const hopRule = calls[0].request.onHop;
  assert.equal(hopRule(new URL("https://example.com/api/x")), true, "a hop inside the segment");
  assert.equal(hopRule(new URL("https://example.com/apix")), false, "a hop in a segment beside it");
  assert.equal(hopRule(new URL("https://example.com/api/x%2f..%2fadmin")), false,
    "a hop that could be read as another path");
  assert.equal(hopRule(new URL("https://example.com:8443/api/x")), false, "another port is another origin");

  // Without a credential the same host reads on any port: the port rule is the credentialed path's.
  const plainId = await reportWithHost(db);
  const plain = await httpJsonBlock.run(blockCtx({ url: "https://example.com:8443/api/x" }, {
    db,
    report: { id: plainId },
    fetch: async () => response([{ id: "b" }], { finalUrl: "https://example.com:8443/api/x" }),
  }), {});
  assert.deepEqual(plain.items, [{ id: "b" }]);
});

test("the credentialed path rule is deny by default on the raw pathname", async () => {
  const db = await freshDb();
  const reportId = await reportWithCredential(db, {
    inject: { header: "Authorization", format: "Bearer {}", pathPrefixes: ["/api"], methods: ["GET"] },
  });
  const attempt = async (url) => {
    const calls = [];
    const out = await httpJsonBlock.run(blockCtx({ url, credential: { host: "example.com" } }, {
      db,
      report: { id: reportId },
      fetch: async (target, request) => {
        calls.push({ target, request });
        return response([{ id: "a" }], { finalUrl: url });
      },
    }), {});
    return { out, calls };
  };

  // A conforming path inside the rule is the one the credential rides.
  const allowed = await attempt("https://example.com/api/v1/items");
  assert.deepEqual(allowed.out.items, [{ id: "a" }]);
  assert.equal(allowed.calls.length, 1);
  assert.equal(allowed.calls[0].request.headers.Authorization, `Bearer ${SECRET}`);

  // Everything a parser, a proxy or the server itself could read as another path is refused before
  // any request is made.
  for (const url of [
    "https://example.com/api/%2e%2e/x",             // an encoded dot segment, which `new URL` resolves to /x
    "https://example.com/api/x%252f..%252fadmin",   // a double-encoded slash
    "https://example.com/api/x;jsessionid=1",       // a matrix parameter a server may strip before routing
    "https://example.com/api/../x",                 // a dot segment written out
    "https://example.com/api/./x",                  // a single-dot segment
    "https://example.com/api/x\\..\\admin",          // a backslash the parser turns into a slash
    "https://example.com/apix",                     // beside the prefix, not under it
    "https://example.com/api/x%2f..%2fadmin",       // an encoded slash
  ]) {
    const { out, calls } = await attempt(url);
    assert.deepEqual(out, { sourceError: { message: "credential_not_allowed" } }, url);
    assert.deepEqual(calls, [], `${url}: no request reached the seam`);
  }

  // The rule reads the text the caller wrote, not what the parser made of it.
  assert.equal(rawPathOf("https://example.com/api/%2e%2e/x"), "/api/%2e%2e/x");
  assert.equal(new URL("https://example.com/api/%2e%2e/x").pathname, "/x", "the parsed path would hide it");
  assert.equal(rawPathOf("https://example.com"), "/", "an absent path is the root the request sends");
  assert.equal(rawPathOf("https://example.com/api/v1/items?page=2#top"), "/api/v1/items");
  assert.equal(rawPathOf("not a url"), null, "a string this cannot read is refused");
  assert.equal(credentialPathAllowed("/api/v1/items", ["/api"]), true);
  assert.equal(credentialPathAllowed("/api/./x", ["/api"]), false);
  assert.equal(credentialPathAllowed("/api/../x", ["/api"]), false);
  assert.equal(credentialPathAllowed("/api/x%252f", ["/api"]), false);

  // A redirect hop goes through the same helper: out of scope, or a non-conforming path, is refused.
  const { calls } = await attempt("https://example.com/api");
  const hopRule = calls[0].request.onHop;
  assert.equal(hopRule(new URL("https://example.com/api/v1/items")), true, "a hop the rule covers");
  assert.equal(hopRule(new URL("https://example.com/v1/items")), false, "a hop out of the path prefixes");
  assert.equal(hopRule(new URL("https://example.com/api/x%252f")), false, "a hop whose path carries a percent-escape");
  assert.equal(hopRule(new URL("https://example.com/api/x;jsessionid=1")), false,
    "a hop whose path carries a matrix parameter");
});

/* ------------------------------------------------------------------------------ rss */

const RSS_XML = `<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel><title>Listings</title>
  <item>
    <title>Flat one</title>
    <link>https://example.com/flat-1</link>
    <pubDate>Fri, 02 Jan 2026 07:00:00 +0000</pubDate>
    <description>&lt;p&gt;A &lt;b&gt;two bedroom&lt;/b&gt; flat&lt;/p&gt;</description>
  </item>
  <item>
    <title>Unsafe link</title>
    <link>javascript:alert(1)</link>
    <description>no tags here</description>
  </item>
</channel></rss>`;

const ATOM_XML = `<?xml version="1.0" encoding="utf-8"?>
<feed xmlns="http://www.w3.org/2005/Atom"><title>Listings</title>
  <entry>
    <title>Atom flat</title>
    <link rel="alternate" href="https://example.com/atom-1"/>
    <link rel="self" href="https://example.com/self"/>
    <published>2026-01-02T07:00:00Z</published>
    <summary>An &lt;em&gt;atom&lt;/em&gt; entry</summary>
  </entry>
  <entry>
    <title>Atom flat 2</title>
    <link href="https://example.com/atom-2"/>
    <updated>2026-01-03T07:00:00Z</updated>
    <content>A second entry</content>
  </entry>
</feed>`;

test("rss parses an RSS 2.0 feed", async () => {
  const db = await freshDb();
  const reportId = await reportWithHost(db);
  const ctx = blockCtx({ url: "https://example.com/feed.xml" }, {
    db,
    report: { id: reportId },
    fetch: async (url, request) => {
      assert.match(request.accept, /rss\+xml/);
      return response(RSS_XML, { contentType: "application/rss+xml" });
    },
  });
  const out = await rssBlock.run(ctx, {});
  assert.equal(out.items.length, 2);
  assert.deepEqual(out.items[0], {
    title: "Flat one",
    link: "https://example.com/flat-1",
    published: "Fri, 02 Jan 2026 07:00:00 +0000",
    summary: "A two bedroom flat",
  });
  assert.equal(out.items[1].link, "", "a non-http(s) link is dropped");
  assert.equal(out.items[1].summary, "no tags here");
});

test("rss parses an Atom feed", async () => {
  const db = await freshDb();
  const reportId = await reportWithHost(db);
  const ctx = blockCtx({ url: "https://example.com/atom.xml" }, {
    db,
    report: { id: reportId },
    fetch: async () => response(ATOM_XML, { contentType: "application/atom+xml" }),
  });
  const out = await rssBlock.run(ctx, {});
  assert.equal(out.items.length, 2);
  assert.deepEqual(out.items[0], {
    title: "Atom flat",
    link: "https://example.com/atom-1",
    published: "2026-01-02T07:00:00Z",
    summary: "An atom entry",
  });
  assert.equal(out.items[1].link, "https://example.com/atom-2");
  assert.equal(out.items[1].published, "2026-01-03T07:00:00Z", "updated stands in for a missing published");
});

test("rss refuses an unapproved host without a request", async () => {
  const db = await freshDb();
  const reportId = await makeReport(db);
  const calls = [];
  const out = await rssBlock.run(blockCtx({ url: "https://example.com/feed.xml" }, {
    db,
    report: { id: reportId },
    fetch: async (url) => { calls.push(url); return response(RSS_XML); },
  }), {});
  assert.deepEqual(out, { sourceError: { message: "host_unapproved" } });
  assert.deepEqual(calls, []);
});

test("rss decodes the feed's references once, so escaped markup stays text", async () => {
  const db = await freshDb();
  const reportId = await reportWithHost(db);
  const xml = `<?xml version="1.0" encoding="utf-8"?>
<rss version="2.0"><channel><title>Listings</title>
  <item>
    <title>Escaped markup</title>
    <description>&amp;lt;script&amp;gt;</description>
  </item>
  <item>
    <title>Real markup</title>
    <description>&lt;p&gt;A &lt;b&gt;two bedroom&lt;/b&gt; flat&lt;/p&gt;</description>
  </item>
</channel></rss>`;
  const out = await rssBlock.run(blockCtx({ url: "https://example.com/feed.xml" }, {
    db,
    report: { id: reportId },
    fetch: async () => response(xml, { contentType: "application/rss+xml" }),
  }), {});
  assert.equal(out.items[0].summary, "&lt;script&gt;", "a second decode would have made a tag");
  assert.equal(out.items[0].summary.includes("<script>"), false);
  assert.equal(out.items[1].summary, "A two bedroom flat", "the item's own markup is still stripped");
});

/* ------------------------------------------------------------------------ mail_alerts */

function rawMessage({ subject, html, date = "Fri, 02 Jan 2026 07:00:00 +0000" }) {
  return Buffer.from([
    "From: Alex <alex@example.com>",
    "To: reports@example.com",
    `Subject: ${subject}`,
    `Date: ${date}`,
    "MIME-Version: 1.0",
    "Content-Type: text/html; charset=utf-8",
    "",
    html,
    "",
  ].join("\r\n"), "utf8");
}

function fakeMail(messages, calls) {
  return {
    listFolders: async () => [
      { path: "INBOX", name: "Inbox", specialUse: "\\Inbox", delimiter: "/", selectable: true },
    ],
    list: async (folder, opts) => {
      calls.push({ method: "list", folder, opts });
      return {
        uidValidity: 1,
        uidNext: 100,
        items: messages.map((message) => ({
          uid: message.uid, flags: [], internalDate: message.internalDate, size: message.raw.length,
        })),
      };
    },
    get: async (folder, uids) => {
      calls.push({ method: "get", folder, uids });
      return messages
        .filter((message) => uids.includes(message.uid))
        .map((message) => ({
          uid: message.uid, flags: [], internalDate: message.internalDate, raw: message.raw,
        }));
    },
  };
}

/** A mail account plus a report that names it as its sender. */
async function mailWorld(db, { provider } = {}) {
  const account = await createAccount(db, {
    address: provider ? "alex@example.com" : "reports@example.com",
    label: "Reports",
    ...(provider ? { provider } : {}),
    imap: { host: "imap.example.com", port: 993, security: "ssl" },
    smtp: { host: "smtp.example.com", port: 465, security: "ssl" },
  });
  const reportId = await makeReport(db);
  await updateReportColumns(db, reportId, { sender_account_id: account.id });
  return { account, reportId, report: { id: reportId, sender_account_id: account.id } };
}

test("mail_alerts reads through the injected adapterFor", async () => {
  const db = await freshDb();
  const { account, report } = await mailWorld(db);
  const messages = [
    {
      uid: 1,
      internalDate: T0 - 2 * DAY_MS,
      raw: rawMessage({
        subject: "Build failed",
        html: "<p>Build failed. See <a href=\"https://example.com/builds/1\">the build</a>.</p>",
      }),
    },
    {
      uid: 2,
      internalDate: T0 - DAY_MS,
      raw: rawMessage({
        subject: "Build fixed",
        html: "<p>Fixed. <a href=\"https://example.com/builds/1\">same link</a></p>",
      }),
    },
  ];
  const adapterCalls = [];
  const seams = [];
  const ctx = blockCtx({ accountId: account.id, folder: "INBOX", sinceDays: 7 }, {
    db,
    report,
    deps: deps({ now: () => T0 }),
    mail: async (accountArg, fn) => {
      seams.push(accountArg.id);
      return fn(fakeMail(messages, adapterCalls));
    },
  });
  const out = await mailAlertsBlock.run(ctx, {});
  assert.deepEqual(seams, [account.id], "the seam got the report's own account");
  assert.equal(out.items.length, 2);
  assert.equal(out.items[0].subject, "Build fixed", "newest first");
  assert.equal(out.items[0].from, "Alex <alex@example.com>");
  assert.match(out.items[0].date, /^2026-01-02T/);
  assert.equal(typeof out.items[0].text, "string");
  assert.match(out.items[0].html, /builds\/1/);
  assert.deepEqual(out.items[0].links, ["https://example.com/builds/1"]);
  assert.equal(out.items[0]._untrusted, true);
  assert.equal(adapterCalls[0].method, "list");
  assert.equal(adapterCalls[0].folder, "INBOX");
  assert.equal(adapterCalls[0].opts.sinceDate, T0 - 7 * DAY_MS);
  assert.equal(adapterCalls[0].opts.limit, 100);
  assert.deepEqual(adapterCalls[1].uids, [1, 2]);

  // A label is resolved through the adapter's own folder list.
  const labelCalls = [];
  const labelOut = await mailAlertsBlock.run(blockCtx({
    accountId: account.id, label: "inbox", sinceDays: 1,
  }, {
    db,
    report,
    deps: deps({ now: () => T0 }),
    mail: async (_account, fn) => fn(fakeMail(messages, labelCalls)),
  }), {});
  assert.equal(labelOut.items.length, 2);
  assert.equal(labelCalls[0].folder, "INBOX");
});

test("mail_alerts never reads an unapproved account", async () => {
  const db = await freshDb();
  const { account, report } = await mailWorld(db);
  let seamCalls = 0;
  const out = await mailAlertsBlock.run(blockCtx({
    accountId: "ma-0000000000000000", folder: "INBOX", sinceDays: 7,
  }, {
    db,
    report,
    deps: deps({ now: () => T0 }),
    mail: async () => { seamCalls += 1; return []; },
  }), {});
  assert.deepEqual(out, { sourceError: { message: "account_not_approved" } });
  assert.equal(seamCalls, 0, "another mailbox never reaches the seam");

  // The report's own account with no seam at all is a named error too.
  const missing = await mailAlertsBlock.run(blockCtx({
    accountId: account.id, folder: "INBOX", sinceDays: 7,
  }, { db, report, deps: deps({ now: () => T0 }) }), {});
  assert.deepEqual(missing, { sourceError: { message: "mail_not_available" } });
});

test("mail_alerts without read scope is a named source error", async () => {
  const db = await freshDb();
  const { account, report } = await mailWorld(db);
  const settings = { accountId: account.id, folder: "INBOX", sinceDays: 7 };
  assert.equal(MAIL_READ_SENTENCE, "Mail alerts need read access. Reconnect Google with reading turned on.");

  // An adapter with no read half.
  const withoutRead = await mailAlertsBlock.run(blockCtx(settings, {
    db,
    report,
    deps: deps({ now: () => T0 }),
    mail: async (_account, fn) => fn({}),
  }), {});
  assert.deepEqual(withoutRead, { sourceError: { message: MAIL_READ_SENTENCE } });

  // A Google account whose connection refuses the read for want of scope.
  const google = await mailWorld(db, { provider: "google" });
  const refused = await mailAlertsBlock.run(blockCtx({
    accountId: google.account.id, folder: "INBOX", sinceDays: 7,
  }, {
    db,
    report: google.report,
    deps: deps({ now: () => T0 }),
    mail: async () => { throw Object.assign(new Error("AUTH_FAILED"), { code: "AUTH_FAILED" }); },
  }), {});
  assert.deepEqual(refused, { sourceError: { message: MAIL_READ_SENTENCE } });

  // The same refusal on an IMAP account is a code word, not that sentence.
  const imapRefused = await mailAlertsBlock.run(blockCtx(settings, {
    db,
    report,
    deps: deps({ now: () => T0 }),
    mail: async () => { throw Object.assign(new Error("AUTH_FAILED"), { code: "AUTH_FAILED" }); },
  }), {});
  assert.deepEqual(imapRefused, { sourceError: { message: "mail_failed" } });
});

/* --------------------------------------------------------------------- workspace_file */

function workspace() {
  return mkdtempSync(join(root, "ws-"));
}

/** Can this computer make a FIFO? The FIFO tests skip with a reason when it cannot. */
const MKFIFO_SKIP = (() => {
  try {
    const probe = join(root, "mkfifo-probe");
    execFileSync("mkfifo", [probe]);
    rmSync(probe, { force: true });
    return false;
  } catch {
    return "mkfifo is not on this computer";
  }
})();

/** Settle `promise` or report that it did not settle in `ms`. */
async function withinMs(promise, ms) {
  let timer = null;
  const guard = new Promise((resolve) => {
    timer = setTimeout(() => resolve({ hung: true }), ms);
  });
  try {
    return await Promise.race([promise, guard]);
  } finally {
    clearTimeout(timer);
  }
}

test("workspace_file refuses ../ and symlink escape", async () => {
  const db = await freshDb();
  const dir = workspace();
  writeFileSync(join(dir, "items.csv"), "name\none\n");
  writeFileSync(join(root, "outside.csv"), "name\nsecret\n");
  symlinkSync(join(root, "outside.csv"), join(dir, "escape.csv"));

  const run = async (path, workspaceDir = dir) => workspaceFileBlock.run(
    blockCtx({ path }, { db, workspaceDir }), {},
  );

  assert.deepEqual(await run("../outside.csv"), { sourceError: { message: "bad_settings" } });
  assert.deepEqual(await run("sub/../../outside.csv"), { sourceError: { message: "bad_settings" } });
  assert.deepEqual(await run(join(dir, "items.csv")), { sourceError: { message: "bad_settings" } });
  assert.deepEqual(await run("escape.csv"), { sourceError: { message: "path_refused" } });
  assert.deepEqual(await run("gone.csv"), { sourceError: { message: "file_not_found" } });
  assert.deepEqual(await run("notes.txt"), { sourceError: { message: "unsupported_file_type" } });
  assert.deepEqual(await run("items.csv", null), { sourceError: { message: "workspace_not_available" } });
});

test("workspace_file reads a csv with quoted fields", async () => {
  const db = await freshDb();
  const dir = workspace();
  writeFileSync(join(dir, "items.csv"), [
    "name,note",
    "\"One, Inc.\",hello",
    "\"Two \"\"quoted\"\"\",world",
    "",
  ].join("\r\n"));
  const out = await workspaceFileBlock.run(blockCtx({ path: "items.csv" }, { db, workspaceDir: dir }), {});
  assert.deepEqual(out.items, [
    { name: "One, Inc.", note: "hello" },
    { name: "Two \"quoted\"", note: "world" },
  ]);
});

test("workspace_file reads a json array and an object with items", async () => {
  const db = await freshDb();
  const dir = workspace();
  writeFileSync(join(dir, "array.json"), JSON.stringify([{ id: 1 }, { id: 2 }]));
  writeFileSync(join(dir, "wrapped.json"), JSON.stringify({ items: [{ id: 3 }, "scalar"] }));
  writeFileSync(join(dir, "broken.json"), "{not json");

  const run = (path) => workspaceFileBlock.run(blockCtx({ path }, { db, workspaceDir: dir }), {});
  assert.deepEqual((await run("array.json")).items, [{ id: 1 }, { id: 2 }]);
  assert.deepEqual((await run("wrapped.json")).items, [{ id: 3 }, { value: "scalar" }]);
  assert.deepEqual(await run("broken.json"), { sourceError: { message: "bad_json" } });
});

test("workspace_file refuses a FIFO promptly, without reading it", { skip: MKFIFO_SKIP }, async () => {
  const db = await freshDb();
  const dir = workspace();
  execFileSync("mkfifo", [join(dir, "pipe.csv")]);
  const out = await withinMs(
    workspaceFileBlock.run(blockCtx({ path: "pipe.csv" }, { db, workspaceDir: dir }), {}),
    5000,
  );
  assert.deepEqual(out, { sourceError: { message: "not_a_file" } }, "a FIFO is refused, and the call returned");

  // The same through a symlink inside the workspace: the real path is the FIFO, so it is refused too.
  symlinkSync(join(dir, "pipe.csv"), join(dir, "pipe-link.csv"));
  const linked = await withinMs(
    workspaceFileBlock.run(blockCtx({ path: "pipe-link.csv" }, { db, workspaceDir: dir }), {}),
    5000,
  );
  assert.deepEqual(linked, { sourceError: { message: "not_a_file" } });
});

test("workspace_file refuses an oversize file", async () => {
  const db = await freshDb();
  const dir = workspace();
  writeFileSync(join(dir, "big.csv"), Buffer.alloc(MAX_FILE_BYTES + 1, 97));
  const out = await workspaceFileBlock.run(blockCtx({ path: "big.csv" }, { db, workspaceDir: dir }), {});
  assert.deepEqual(out, { sourceError: { message: "too_large" } });
  assert.equal(out.items, undefined);
});

test("workspace_file reads a file that fits the cap", async () => {
  const db = await freshDb();
  const dir = workspace();
  writeFileSync(join(dir, "fits.csv"), "name\none\n");
  const out = await workspaceFileBlock.run(blockCtx({ path: "fits.csv" }, { db, workspaceDir: dir }), {});
  assert.deepEqual(out.items, [{ name: "one" }]);
});

test("the executor resolves the workspace directory from the report's own project", async () => {
  const db = await freshDb();
  const dir = workspace();
  writeFileSync(join(dir, "items.json"), JSON.stringify([{ id: "a" }]));
  await db.execute({
    sql: "INSERT INTO project_spaces (id, slug, name, workspace_dir) VALUES (?, ?, ?, ?)",
    args: [7, "listings", "Listings", dir],
  });
  const recipe = { blocks: [{ id: "file", type: "workspace_file", settings: { path: "items.json" } }] };

  // The report names project 7, which owns `dir`: the file is read with no seam injected at all.
  const out = await runRecipe(db, {}, {
    report: { id: "rpt-0000000000000000", project_id: 7 }, recipe, run: { trigger: "manual" },
  });
  assert.deepEqual(out.items, [{ id: "a" }]);
  assert.deepEqual(out.sourceErrors, []);

  // A report on a project this Crow has no workspace for answers the named source error...
  const withoutProject = await runRecipe(db, {}, {
    report: { id: "rpt-0000000000000001", project_id: 999 }, recipe, run: { trigger: "manual" },
  });
  assert.deepEqual(withoutProject.sourceErrors, [{ source: "file", message: "workspace_not_available" }]);

  // ...and a caller's own `workspaceDir` and `fetch` are not seams at all.
  const ignored = await runRecipe(db, { workspaceDir: dir, fetch: async () => response([{ id: "b" }]) }, {
    report: { id: "rpt-0000000000000002", project_id: 999 }, recipe, run: { trigger: "manual" },
  });
  assert.deepEqual(ignored.sourceErrors, [{ source: "file", message: "workspace_not_available" }]);

  // A test harness's seams are honoured only under `testSeams`.
  const other = workspace();
  writeFileSync(join(other, "items.json"), JSON.stringify([{ id: "c" }]));
  const harness = await runRecipe(db, {
    testSeams: true,
    workspaceDirFor: async () => other,
  }, {
    report: { id: "rpt-0000000000000003", project_id: 999 }, recipe, run: { trigger: "manual" },
  });
  assert.deepEqual(harness.items, [{ id: "c" }]);
  assert.deepEqual(harness.sourceErrors, []);

  const notAFlag = await runRecipe(db, {
    testSeams: false,
    workspaceDirFor: async () => other,
  }, {
    report: { id: "rpt-0000000000000004", project_id: 999 }, recipe, run: { trigger: "manual" },
  });
  assert.deepEqual(notAFlag.sourceErrors, [{ source: "file", message: "workspace_not_available" }]);

  // The executor's `fetch` is the guard: `deps.fetch` is ignored, and `testFetch` counts only under
  // the flag. The host is approved and never resolves (`.invalid` is reserved), so the guard's own
  // request fails without a connection, and a caller's fake would have answered `too_large`.
  const feedReportId = await reportWithHost(db, "nowhere.invalid");
  const feed = {
    blocks: [{ id: "feed", type: "rss", settings: { url: "https://nowhere.invalid/feed.xml" } }],
  };
  const fakeDeps = {
    fetch: async () => { throw Object.assign(new Error("x"), { code: "ETOOBIG" }); },
    testFetch: async () => response(RSS_XML, {
      contentType: "application/rss+xml", finalUrl: "https://nowhere.invalid/feed.xml",
    }),
  };
  const notUnderFlag = await runRecipe(db, fakeDeps, {
    report: { id: feedReportId, project_id: 7 }, recipe: feed, run: { trigger: "manual" },
  });
  assert.deepEqual(notUnderFlag.sourceErrors, [{ source: "feed", message: "fetch_failed" }],
    "the caller's fetch is not the seam; the guarded request is");

  const underFlag = await runRecipe(db, { ...fakeDeps, testSeams: true }, {
    report: { id: feedReportId, project_id: 7 }, recipe: feed, run: { trigger: "manual" },
  });
  assert.equal(underFlag.items.length, 2, "the harness's fake read the feed");
  assert.deepEqual(underFlag.sourceErrors, []);
});

/* -------------------------------------------------------------------------- validate */

test("each source validate rejects bad settings", () => {
  const cases = [
    [httpJsonBlock, { url: "not a url" }, "url"],
    [httpJsonBlock, { url: "https://example.com", method: "POST" }, "method"],
    [httpJsonBlock, { url: "https://example.com", surprise: true }, "surprise"],
    [httpJsonBlock, { url: "https://example.com", credential: { host: "Example.com" } }, "credential.host"],
    [httpJsonBlock, { url: "https://example.com", itemsPath: 5 }, "itemsPath"],
    [rssBlock, {}, "url"],
    [rssBlock, { url: "ftp://example.com/feed.xml" }, "url"],
    [rssBlock, { url: "https://example.com/feed.xml", credential: { host: "example.com" } }, "credential"],
    [mailAlertsBlock, { accountId: "ma-1", label: "Inbox", folder: "INBOX", sinceDays: 7 }, "label"],
    [mailAlertsBlock, { accountId: "ma-1", label: "Inbox", sinceDays: 0 }, "sinceDays"],
    [mailAlertsBlock, { accountId: "ma-1", label: "Inbox", sinceDays: 61 }, "sinceDays"],
    [mailAlertsBlock, { accountId: "ma-1", folder: "INBOX", sinceDays: 2.5 }, "sinceDays"],
    [mailAlertsBlock, { label: "Inbox", sinceDays: 7 }, "accountId"],
    [mailAlertsBlock, { accountId: "ma-1", label: "Inbox", sinceDays: 7, extra: true }, "extra"],
    [workspaceFileBlock, {}, "path"],
    [workspaceFileBlock, { path: "/etc/passwd" }, "path"],
    [workspaceFileBlock, { path: "../x.csv" }, "path"],
    [workspaceFileBlock, { path: "a/../b.csv" }, "path"],
    [workspaceFileBlock, { path: "ok.csv", mode: "r" }, "mode"],
  ];
  for (const [block, settings, token] of cases) {
    const errors = block.validate(settings);
    assert.equal(Array.isArray(errors), true, block.type);
    assert.equal(errors.includes(token), true, `${block.type} rejects ${token}: ${JSON.stringify(errors)}`);
    assert.equal(errors.every((entry) => typeof entry === "string"), true, block.type);
  }

  assert.deepEqual(rssBlock.validate({ url: "https://example.com/feed.xml" }), []);
  assert.deepEqual(workspaceFileBlock.validate({ path: "sub/items.csv" }), []);
  assert.deepEqual(
    httpJsonBlock.validate({ url: "https://example.com", credential: { host: "example.com" } }),
    [],
  );
  assert.deepEqual(
    mailAlertsBlock.validate({ accountId: "ma-1", folder: "INBOX", sinceDays: 7 }),
    [],
  );
});

/* ------------------------------------------------------------------------ parseCsv */

test("parseCsv keeps quoted commas and newlines together", () => {
  assert.deepEqual(parseCsv("a,b\r\n1,2\r\n"), [["a", "b"], ["1", "2"]]);
  assert.deepEqual(parseCsv("a,b\n\"x,y\",\"line\nbreak\"\n"), [["a", "b"], ["x,y", "line\nbreak"]]);
  assert.deepEqual(parseCsv("a,b\n\"say \"\"hi\"\"\",2"), [["a", "b"], ["say \"hi\"", "2"]]);
});