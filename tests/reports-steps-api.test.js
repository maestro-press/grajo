// The owner API's step, host, credential and asset routes:
// `/dashboard/api/reports/:id/steps`, `.../steps/:key/:rev[/approve|refuse|revoke]`, `.../hosts`,
// `.../hosts/:host/approve|revoke`, `.../credentials`, `.../credentials/:uuid/approve|revoke` and
// `.../assets[/:name]`.
//
// Harness: a real init-db'd scratch crow.db copied per test, an ephemeral express app wired the way
// servers/gateway/index.js + dashboard/index.js wire it (the real fetch-metadata gate, a session stub,
// the dashboard's real CSRF middleware, then the real reports API router), the real report store and
// step module with an injected keychain seed and clock, and the owner rule taken from the request's own
// classification (tests/helpers/off-box.js).
//
// Every request is shaped like the owner's own browser, because that is what the routes see in
// production: the SERVER-BOUND CSRF token for its own session (tests/helpers/csrf-token.mjs; the
// retired `crow_csrf` cookie is gone, and a made-up value is a 403) and same-origin fetch metadata
// (`Sec-Fetch-Site`, a matching `Origin`). Both gates pass, so the reports owner guard is what answers
// each request and the owner_only / no-data assertions below test it rather than a gate in front.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import http from "node:http";
import Database from "better-sqlite3";
import { markFromLaptop } from "./helpers/off-box.js";
import { csrfTokenFor } from "./helpers/csrf-token.mjs";

const root = mkdtempSync(join(tmpdir(), "reports-steps-api-"));
process.env.CROW_DATA_DIR = join(root, "master");
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "master", "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const MASTER = join(root, "master", "crow.db");
const HOME = process.env.CROW_HOME;

const { default: express } = await import("express");
const { createDbClient } = await import("../servers/db.js");
const { csrfMiddleware } = await import("../servers/gateway/dashboard/shared/csrf.js");
const { fetchMetadataGate } = await import("../servers/gateway/dashboard/fetch-metadata.js");
const { reportsApiRouter, REPORTS_API_PREFIX, OWNER_LABEL } = await import(
  "../servers/gateway/routes/reports-api.js"
);
const { createReport } = await import("../servers/gateway/reports/store.js");
const {
  HOST_APPROVAL_LINE, approveHost, proposeCredential, proposeHost,
} = await import("../servers/gateway/reports/steps.js");
const { createKeychainKey } = await import("../servers/gateway/keychain/key.js");
const { REPORTS_BUNDLE, saveServiceSecret } = await import("../servers/gateway/keychain/store.js");

const OWNER = "owner-local-password-session";
const SSO = "peer-sso-session";
const SEED = Buffer.alloc(32, 29);
const T0 = 1_700_000_000_000;
const PROJECT = 7;
const UUID_A = "11111111-1111-4111-8111-111111111111";
const CODE = "print('approved code')\n";

const hashToken = (t) => createHash("sha256").update(t).digest("hex");
const KEY = createKeychainKey({ crowHome: HOME });

const open = [];
const servers = [];
let server = null;

after(() => {
  for (const s of servers) s.close();
  for (const c of open) { try { c.close(); } catch { /* closed */ } }
  rmSync(root, { recursive: true, force: true });
});

before(() => {
  mkdirSync(join(root, "master"), { recursive: true });
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: join(root, "master") },
    stdio: "pipe",
    cwd: REPO,
  });
  const raw = new Database(MASTER);
  const insert = raw.prepare(
    "INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at) VALUES (?, 'access', 'dashboard', ?, datetime('now','+1 day'))",
  );
  insert.run(hashToken(OWNER), "dashboard");
  insert.run(hashToken(SSO), "dashboard sso src:peer-1");
  raw.pragma("wal_checkpoint(TRUNCATE)");
  raw.close();
});

/* -------------------------------------------------------------------------- HTTP */

function parseCookies(header) {
  const out = {};
  for (const part of String(header || "").split(";")) {
    const i = part.indexOf("=");
    if (i > 0) out[part.slice(0, i).trim()] = part.slice(i + 1).trim();
  }
  return out;
}

/** One request, shaped like a page of this origin making it. The cookie carries the session and
 *  nothing else (the CSRF token is server-bound: HMAC(secret, session), delivered to the page, never a
 *  cookie); `X-Crow-Csrf` echoes that token for THIS session; `csrf: true` (the default) computes it
 *  through the real module, a string sends that value instead, `null` sends none; and the fetch
 *  metadata names this origin (`Sec-Fetch-Site: same-origin`, `Origin` = the URL asked on), which is
 *  what a browser on the dashboard sends and what the fetch-metadata gate admits. `token: null` sends
 *  no session cookie; `laptop: false` leaves the request classified as coming from this machine.
 *  `raw` sends a Buffer as typed. */
function call(method, path, { body, headers = {}, token = OWNER, csrf = true, laptop = true, raw = null } = {}) {
  const origin = `http://127.0.0.1:${server.address().port}`;
  let payload = null;
  const h = {
    origin,
    "sec-fetch-site": "same-origin",
    "sec-fetch-mode": "cors",
    "sec-fetch-dest": "empty",
  };
  if (raw !== null) {
    payload = Buffer.isBuffer(raw) ? raw : Buffer.from(String(raw));
    h["content-type"] = headers["content-type"] || "application/octet-stream";
    h["content-length"] = String(payload.length);
  } else if (body !== undefined) {
    payload = typeof body === "string" ? body : JSON.stringify(body);
    h["content-type"] = "application/json";
    h["content-length"] = String(Buffer.byteLength(payload));
  }
  if (token) h.cookie = "crow_session=" + token;
  if (token && csrf) h["x-crow-csrf"] = csrf === true ? csrfTokenFor(token) : String(csrf);
  if (laptop) h["x-test-from"] = "laptop";
  Object.assign(h, headers);
  return new Promise((resolve, reject) => {
    const req = http.request({ host: "127.0.0.1", port: server.address().port, method, path, headers: h }, (res) => {
      let text = "";
      res.on("data", (c) => { text += c; });
      res.on("end", () => {
        let json = null;
        try { json = JSON.parse(text); } catch { /* not JSON */ }
        resolve({ status: res.statusCode, headers: res.headers, text, json });
      });
    });
    req.on("error", reject);
    req.end(payload === null ? undefined : payload);
  });
}

const get = (path, opts) => call("GET", path, opts);
const post = (path, body, opts) => call("POST", path, { body, ...opts });

const reportPath = (id) => `${REPORTS_API_PREFIX}/${encodeURIComponent(id)}`;
const stepPath = (id, key, rev) => `${reportPath(id)}/steps/${encodeURIComponent(key)}/${rev}`;
const hostPath = (id, host) => `${reportPath(id)}/hosts/${encodeURIComponent(host)}`;

/* ------------------------------------------------------------------------- setup */

let n = 0;

async function setup({ ownerCheck = undefined } = {}) {
  const dir = join(root, "t" + (++n));
  mkdirSync(dir);
  const crow = join(dir, "crow.db");
  copyFileSync(MASTER, crow);
  process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");
  const db = createDbClient(crow);
  open.push(db);

  const openDb = () => createDbClient(crow);
  const approvalsDeps = {
    loadSeed: () => ({ seed: SEED }),
    loadKeychainKey: () => KEY,
    now: () => T0,
    crowHome: HOME,
    registry: { columns: { sourceBearing: false } },
    getRun: async () => null,
    senderReady: async () => true,
  };

  const app = express();
  app.use(express.json({ limit: "1mb" }));
  const sessionGate = (req, res, next) => {
    const token = parseCookies(req.headers.cookie).crow_session;
    if (!token) return res.status(401).json({ error: "unauthorized" });
    req.dashboardSession = token;
    if (req.headers["x-test-from"] === "laptop") markFromLaptop(req);
    next();
  };
  const dash = express.Router();
  // index.js mounts the fetch-metadata gate app-wide, before the routers: a request a browser wrote on
  // another site is refused there and never reaches csrfMiddleware or the reports owner guard.
  dash.use(fetchMetadataGate({ log: () => {} }));
  dash.use("/dashboard", csrfMiddleware);
  dash.use(reportsApiRouter(sessionGate, {
    openDb,
    approvalsDeps,
    ...(ownerCheck === undefined ? {} : { ownerCheck }),
  }));
  app.use(dash);

  server = await new Promise((r) => { const s = app.listen(0, "127.0.0.1", () => r(s)); });
  servers.push(server);
  return { db, crow };
}

async function prepareReport(db) {
  const { id } = await createReport(db, {
    projectId: PROJECT, owner: OWNER_LABEL, botId: "bot-1", title: "Weekly listings",
  });
  return id;
}

const FILES = { "run.py": CODE, "templates/report.html": "<h1>{{ title }}</h1>\n" };

const stepBody = (over = {}) => ({
  stepKey: "fetch",
  language: "python",
  entry: "run.py",
  files: FILES,
  requirements: "jinja2==3.1.4\n",
  ...over,
});

/** No response of this router may carry a seal, a nonce or a secret. */
function assertNoSeal(r, label) {
  for (const needle of ["approval_seal", "approval_nonce", "approvalSeal", "approvalNonce", "secret_sealed"]) {
    assert.equal(r.text.includes(needle), false, `${label}: no ${needle}`);
  }
  const visit = (value) => {
    if (value == null || typeof value !== "object") return;
    for (const [key, inner] of Object.entries(value)) {
      for (const forbidden of ["approval_seal", "approval_nonce", "seal", "nonce", "secret", "secret_sealed"]) {
        assert.notEqual(key, forbidden, `${label}: no ${forbidden} key`);
      }
      visit(inner);
    }
  };
  visit(r.json);
}

/* ------------------------------------------------------------------------- wiring */

test("the new routes are registered, and the raw upload sits before the shared JSON guard", () => {
  const probe = reportsApiRouter((req, res, next) => next(), { openDb: () => null });
  const paths = probe.stack
    .filter((layer) => layer.route)
    .map((layer) => `${Object.keys(layer.route.methods).join(",").toUpperCase()} ${layer.route.path}`);
  for (const wanted of [
    `GET ${REPORTS_API_PREFIX}/:id/steps`,
    `GET ${REPORTS_API_PREFIX}/:id/steps/:key/:rev`,
    `POST ${REPORTS_API_PREFIX}/:id/steps/:key/:rev/approve`,
    `POST ${REPORTS_API_PREFIX}/:id/steps/:key/:rev/refuse`,
    `POST ${REPORTS_API_PREFIX}/:id/steps/:key/:rev/revoke`,
    `GET ${REPORTS_API_PREFIX}/:id/hosts`,
    `POST ${REPORTS_API_PREFIX}/:id/hosts`,
    `POST ${REPORTS_API_PREFIX}/:id/hosts/:host/approve`,
    `POST ${REPORTS_API_PREFIX}/:id/hosts/:host/revoke`,
    `GET ${REPORTS_API_PREFIX}/:id/credentials`,
    `POST ${REPORTS_API_PREFIX}/:id/credentials/:uuid/approve`,
    `POST ${REPORTS_API_PREFIX}/:id/credentials/:uuid/revoke`,
    `GET ${REPORTS_API_PREFIX}/:id/assets`,
    `PUT ${REPORTS_API_PREFIX}/:id/assets/:name`,
  ]) {
    assert.ok(paths.includes(wanted), `${wanted} is registered`);
  }
  const upload = probe.stack.findIndex(
    (layer) => layer.route && layer.route.path === `${REPORTS_API_PREFIX}/:id/assets/:name`,
  );
  const jsonGuard = probe.stack.findIndex((layer) => !layer.route && layer.name === "bodyParser");
  assert.ok(upload >= 0 && jsonGuard > upload,
    "the raw asset upload is reachable before this router's 256 KB JSON parser");
});

/* ------------------------------------------------------------------ the owner rail */

test("a non-owner session is 403 on every step, host, credential and asset route", async () => {
  const world = await setup();
  const id = await prepareReport(world.db);
  const routes = [
    ["GET", `${reportPath(id)}/steps`, undefined],
    ["GET", stepPath(id, "fetch", 1), undefined],
    ["POST", `${reportPath(id)}/steps`, stepBody()],
    ["POST", `${stepPath(id, "fetch", 1)}/approve`, {}],
    ["POST", `${stepPath(id, "fetch", 1)}/refuse`, {}],
    ["POST", `${stepPath(id, "fetch", 1)}/revoke`, {}],
    ["GET", `${reportPath(id)}/hosts`, undefined],
    ["POST", `${reportPath(id)}/hosts`, { host: "example.com" }],
    ["POST", `${hostPath(id, "example.com")}/approve`, {}],
    ["POST", `${hostPath(id, "example.com")}/revoke`, {}],
    ["GET", `${reportPath(id)}/credentials`, undefined],
    ["POST", `${reportPath(id)}/credentials/${UUID_A}/approve`, {}],
    ["POST", `${reportPath(id)}/credentials/${UUID_A}/revoke`, {}],
    ["GET", `${reportPath(id)}/assets`, undefined],
  ];
  for (const [label, opts] of [
    ["a peer's single-sign-on session", { token: SSO }],
    ["a request from this machine", { token: OWNER, laptop: false }],
  ]) {
    for (const [method, path, body] of routes) {
      const r = await call(method, path, { body, ...opts });
      assert.equal(r.status, 403, `${label} ${method} ${path}: ${r.status} ${r.text}`);
      assert.deepEqual(r.json, { error: "owner_only", message: "Only the owner can see this." });
      assert.equal(r.text.includes(id), false, `${label} ${method} ${path}: no id`);
    }
  }
  const upload = await call("PUT", `${reportPath(id)}/assets/data.json`, {
    raw: "payload", token: SSO,
  });
  assert.equal(upload.status, 403, upload.text);
  assert.deepEqual(upload.json, { error: "owner_only", message: "Only the owner can see this." });

  const { rows } = await world.db.execute("SELECT COUNT(*) AS n FROM report_custom_steps");
  assert.equal(Number(rows[0].n), 0, "nothing was proposed");
  const { rows: hosts } = await world.db.execute("SELECT COUNT(*) AS n FROM report_hosts");
  assert.equal(Number(hosts[0].n), 0, "no host was added");
});

test("an owner check that throws is a 403 on the new routes too", async () => {
  const world = await setup({ ownerCheck: async () => { throw new Error("database is locked (crow.db)"); } });
  const id = await prepareReport(world.db);
  const r = await get(`${reportPath(id)}/steps`);
  assert.equal(r.status, 403, r.text);
  assert.equal(r.text.includes("database is locked"), false);
});

/* ------------------------------------------------------------------------- steps */

test("a step is proposed, read with its diff, and approved in the owner's flow", async () => {
  const world = await setup();
  const id = await prepareReport(world.db);

  const created = await post(`${reportPath(id)}/steps`, stepBody());
  assert.equal(created.status, 201, created.text);
  const step = created.json.step;
  assert.equal(step.stepKey, "fetch");
  assert.equal(step.rev, 1);
  assert.equal(step.state, "proposed");
  assert.equal(step.verified, false);
  assert.deepEqual(step.files.map((f) => f.path), ["run.py", "templates/report.html"]);
  assert.equal(step.files[0].sha256.length, 64);
  assert.equal(created.text.includes("print("), false, "the list view carries no file text");
  assertNoSeal(created, "propose");

  const listed = await get(`${reportPath(id)}/steps`);
  assert.equal(listed.status, 200, listed.text);
  assert.equal(listed.json.steps.length, 1);
  assert.equal(listed.json.steps[0].verified, false);
  assert.equal(listed.text.includes("print("), false, "the list carries no file text");
  assertNoSeal(listed, "the list");

  const detail = await get(stepPath(id, "fetch", 1));
  assert.equal(detail.status, 200, detail.text);
  assert.equal(detail.json.step.contents.find((f) => f.path === "run.py").text, CODE);
  assert.equal(detail.json.diff.previousRev, null, "nothing was approved before this revision");
  assert.deepEqual(detail.json.diff.files.map((f) => f.status), ["added", "added"]);
  assertNoSeal(detail, "the detail");

  const approved = await post(`${stepPath(id, "fetch", 1)}/approve`, { bundleHash: detail.json.step.bundleHash });
  assert.equal(approved.status, 200, approved.text);
  assert.equal(approved.json.step.state, "approved");
  assert.equal(approved.json.step.verified, true);
  assert.equal(approved.json.step.bundleHash, detail.json.step.bundleHash, "the answer carries the hash that was sealed");
  assertNoSeal(approved, "approve");

  const raw = (await world.db.execute({
    sql: "SELECT approval_seal, approval_nonce FROM report_custom_steps WHERE report_id = ?", args: [id],
  })).rows[0];
  assert.match(raw.approval_seal, /^[0-9a-f]{64}$/, "the row really carries a seal");
  assert.match(raw.approval_nonce, /^[0-9a-f]{32}$/);

  // A second revision reads against the approved one, and the newest unapproved revision is not run.
  const second = await post(`${reportPath(id)}/steps`, stepBody({ files: { "run.py": `${CODE}print('v2')\n` } }));
  assert.equal(second.status, 201, second.text);
  assert.equal(second.json.step.rev, 2);
  const secondDetail = await get(stepPath(id, "fetch", 2));  assert.equal(secondDetail.json.diff.previousRev, 1);
  assert.equal(secondDetail.json.diff.files.find((f) => f.path === "run.py").status, "changed");
  const listAfter = await get(`${reportPath(id)}/steps`);
  assert.deepEqual(listAfter.json.steps.map((s) => [s.rev, s.state, s.verified]), [[2, "proposed", false]],
    "the list shows each key at its newest revision");
});

test("a malformed step request is a stable code and writes nothing", async () => {
  const world = await setup();
  const id = await prepareReport(world.db);

  const badPath = await post(`${reportPath(id)}/steps`, stepBody({ files: { "../escape.py": "x" }, entry: "../escape.py" }));
  assert.equal(badPath.status, 400, badPath.text);
  assert.equal(badPath.json.error, "bad_input");

  const badEntry = await post(`${reportPath(id)}/steps`, stepBody({ entry: "missing.py" }));
  assert.equal(badEntry.status, 400, badEntry.text);
  assert.equal(badEntry.json.error, "bad_input");

  const tooBig = await post(`${reportPath(id)}/steps`, stepBody({ files: { "run.py": "a".repeat(2 * 1024 * 1024 + 1) } }));
  assert.equal(tooBig.status, 413, tooBig.text);

  const missing = [
    ["GET", `${reportPath(id)}/steps/FETCH/1`],
    ["GET", `${reportPath(id)}/steps/fetch/abc`],
    ["POST", `${reportPath(id)}/steps/fetch/1/approve`],
    ["GET", stepPath(id, "fetch", 1)],
    ["POST", `${stepPath(id, "fetch", 1)}/approve`],
    ["POST", `${stepPath("rpt-ffffffffffffffff", "fetch", 1)}/approve`],
  ];
  for (const [method, path] of missing) {
    const r = await call(method, path, { body: method === "POST" ? { bundleHash: "a".repeat(64) } : undefined });
    assert.equal(r.status, 404, `${method} ${path}: ${r.status} ${r.text}`);
    assert.equal(r.json.error, "not_found");
  }
  const { rows } = await world.db.execute("SELECT COUNT(*) AS n FROM report_custom_steps");
  assert.equal(Number(rows[0].n), 0, "no step row was written");
});

test("a step approval needs the bundle hash the view showed", async () => {
  const world = await setup();
  const id = await prepareReport(world.db);
  const created = await post(`${reportPath(id)}/steps`, stepBody());
  const shown = created.json.step.bundleHash;
  assert.match(shown, /^[0-9a-f]{64}$/, "the view carries the hash the tap hands back");

  for (const body of [{}, { bundleHash: "" }, { bundleHash: 42 }, { bundleHash: "0".repeat(63) }, { bundleHash: "nope" }]) {
    const refused = await post(`${stepPath(id, "fetch", 1)}/approve`, body);
    assert.equal(refused.status, 400, `${JSON.stringify(body)}: ${refused.status} ${refused.text}`);
    assert.equal(refused.json.error, "bad_input");
  }
  const stillProposed = (await world.db.execute({
    sql: "SELECT state, approval_seal FROM report_custom_steps WHERE report_id = ?", args: [id],
  })).rows[0];
  assert.equal(stillProposed.state, "proposed", "a refused body approves nothing");
  assert.equal(stillProposed.approval_seal, null);

  // An asset re-uploaded between the view and the tap is a step_changed: the hash the owner saw
  // is not the bundle that is here now.
  await call("PUT", `${reportPath(id)}/assets/ways.json`, {
    raw: "first", headers: { "content-type": "application/octet-stream" },
  });
  const withAsset = await post(`${reportPath(id)}/steps`, stepBody({ assets: ["ways.json"] }));
  const detail = await get(stepPath(id, "fetch", withAsset.json.step.rev));
  await call("PUT", `${reportPath(id)}/assets/ways.json`, {
    raw: "second", headers: { "content-type": "application/octet-stream" },
  });
  const stale = await post(`${stepPath(id, "fetch", withAsset.json.step.rev)}/approve`, {
    bundleHash: detail.json.step.bundleHash,
  });
  assert.equal(stale.status, 409, stale.text);
  assert.deepEqual(stale.json, {
    error: "step_changed",
    message: "That step changed while this request was in flight. Try again.",
  });

  // A fresh view shows the bundle that would run, and that tap is the approval.
  const fresh = await get(stepPath(id, "fetch", withAsset.json.step.rev));
  assert.notEqual(fresh.json.step.bundleHash, detail.json.step.bundleHash);
  const approved = await post(`${stepPath(id, "fetch", withAsset.json.step.rev)}/approve`, {
    bundleHash: fresh.json.step.bundleHash,
  });
  assert.equal(approved.status, 200, approved.text);
  assert.equal(approved.json.step.verified, true);
  assertNoSeal(approved, "the re-viewed approve");
});

test("refuse and revoke move the state and null the seal", async () => {
  const world = await setup();
  const id = await prepareReport(world.db);
  const created = await post(`${reportPath(id)}/steps`, stepBody());
  const bundleHash = created.json.step.bundleHash;
  await post(`${stepPath(id, "fetch", 1)}/approve`, { bundleHash });

  const refused = await post(`${stepPath(id, "fetch", 1)}/refuse`, {});
  assert.equal(refused.status, 200, refused.text);
  assert.equal(refused.json.step.state, "refused");
  assert.equal(refused.json.step.verified, false);
  let raw = (await world.db.execute({
    sql: "SELECT approval_seal, approval_nonce FROM report_custom_steps WHERE report_id = ?", args: [id],
  })).rows[0];
  assert.equal(raw.approval_seal, null);
  assert.equal(raw.approval_nonce, null);
  assertNoSeal(refused, "refuse");

  await post(`${stepPath(id, "fetch", 1)}/approve`, { bundleHash });
  const revoked = await post(`${stepPath(id, "fetch", 1)}/revoke`, {});
  assert.equal(revoked.status, 200, revoked.text);
  assert.equal(revoked.json.step.state, "revoked");
  raw = (await world.db.execute({
    sql: "SELECT approval_seal FROM report_custom_steps WHERE report_id = ?", args: [id],
  })).rows[0];
  assert.equal(raw.approval_seal, null);
});

/* ------------------------------------------------------------------------- hosts */

test("one host tap adds and approves, and answers with the sentence", async () => {
  const world = await setup();
  const id = await prepareReport(world.db);

  const added = await post(`${reportPath(id)}/hosts`, { host: "example.com" });
  assert.equal(added.status, 201, added.text);
  assert.equal(added.json.notice, HOST_APPROVAL_LINE);
  assert.equal(added.json.host.host, "example.com");
  assert.equal(added.json.host.state, "approved");
  assert.equal(added.json.host.verified, true);
  assertNoSeal(added, "the add");

  const listed = await get(`${reportPath(id)}/hosts`);
  assert.equal(listed.status, 200, listed.text);
  assert.equal(listed.json.hosts.length, 1);
  assert.equal(listed.json.hosts[0].verified, true);
  assertNoSeal(listed, "the list");

  // A wildcard is added the same way, and its path form survives encoding.
  const wildcard = await post(`${reportPath(id)}/hosts`, { host: "*.example.org" });
  assert.equal(wildcard.status, 201, wildcard.text);
  assert.equal(wildcard.json.host.host, "*.example.org");
  assert.equal(wildcard.json.notice, HOST_APPROVAL_LINE);

  const revoked = await post(`${hostPath(id, "*.example.org")}/revoke`, {});
  assert.equal(revoked.status, 200, revoked.text);
  assert.equal(revoked.json.host.state, "revoked");
  assert.equal(revoked.json.host.verified, false);

  const reapproved = await post(`${hostPath(id, "*.example.org")}/approve`, {});
  assert.equal(reapproved.status, 200, reapproved.text);
  assert.equal(reapproved.json.notice, HOST_APPROVAL_LINE);
  assert.equal(reapproved.json.host.verified, true);

  for (const host of ["", "com", "*.com", "127.0.0.1", "Example.com"]) {
    const r = await post(`${reportPath(id)}/hosts`, { host });
    assert.equal(r.status, 400, `${JSON.stringify(host)}: ${r.status} ${r.text}`);
    assert.equal(r.json.error, "bad_input");
  }
  const notThere = await post(`${hostPath(id, "absent.example.com")}/approve`, {});
  assert.equal(notThere.status, 404, notThere.text);
  const badPathHost = await post(`${reportPath(id)}/hosts/NOT%20A%20HOST/approve`, {});
  assert.equal(badPathHost.status, 404, badPathHost.text);
});

/* ------------------------------------------------------------------- credentials */

test("a credential is listed without its secret and approved by its reference", async () => {
  const world = await setup();
  const id = await prepareReport(world.db);
  await proposeHost(world.db, { loadSeed: () => ({ seed: SEED }), now: () => T0, crowHome: HOME }, {
    reportId: id, host: "example.com",
  });
  await approveHost(world.db, { loadSeed: () => ({ seed: SEED }), now: () => T0, crowHome: HOME }, {
    reportId: id, host: "example.com", actor: { kind: "owner" },
  });
  await saveServiceSecret(world.db, KEY, {
    connectionUuid: UUID_A,
    bundleId: REPORTS_BUNDLE,
    envKey: "REPORT_CREDENTIAL",
    label: "report credential",
    secret: "credential-value-0123456789abcdef",
  });
  await proposeCredential(world.db, { loadSeed: () => ({ seed: SEED }), now: () => T0, crowHome: HOME }, {
    reportId: id,
    host: "example.com",
    connectionUuid: UUID_A,
    inject: { header: "Authorization", format: "Bearer {}", pathPrefixes: ["/v1/issues"] },
    proposedBy: "bot:bot-1",
  });

  const listed = await get(`${reportPath(id)}/credentials`);
  assert.equal(listed.status, 200, listed.text);
  assert.equal(listed.json.credentials.length, 1);
  assert.equal(listed.json.credentials[0].connectionUuid, UUID_A);
  assert.equal(listed.json.credentials[0].state, "proposed");
  assert.match(listed.json.credentials[0].injectHash, /^[0-9a-f]{64}$/,
    "the view carries the digest an approval hands back");
  assert.deepEqual(listed.json.credentials[0].inject, {
    header: "Authorization", format: "Bearer {}", pathPrefixes: ["/v1/issues"], methods: ["GET", "HEAD"],
  });
  assert.equal(listed.text.includes("credential-value"), false, "the secret is never in a list view");
  assertNoSeal(listed, "the credential list");

  const injectHash = listed.json.credentials[0].injectHash;

  // A tap that names no expected rule is not a tap over anything.
  for (const body of [{}, { injectHash: "" }, { injectHash: 42 }, { injectHash: "0".repeat(63) }]) {
    const refused = await post(`${reportPath(id)}/credentials/${UUID_A}/approve`, body);
    assert.equal(refused.status, 400, `${JSON.stringify(body)}: ${refused.status} ${refused.text}`);
    assert.equal(refused.json.error, "bad_input");
  }
  const stillProposed = (await world.db.execute({
    sql: "SELECT state, approval_seal FROM report_credentials WHERE report_id = ?", args: [id],
  })).rows[0];
  assert.equal(stillProposed.state, "proposed", "a refused body approves nothing");
  assert.equal(stillProposed.approval_seal, null);

  const approved = await post(`${reportPath(id)}/credentials/${UUID_A}/approve`, { injectHash });
  assert.equal(approved.status, 200, approved.text);
  assert.equal(approved.json.credential.state, "approved");
  assert.equal(approved.json.credential.verified, true);
  assert.equal(approved.json.credential.injectHash, injectHash);
  assert.equal(approved.text.includes("credential-value"), false);
  assertNoSeal(approved, "the credential approval");

  const revoked = await post(`${reportPath(id)}/credentials/${UUID_A}/revoke`, {});
  assert.equal(revoked.status, 200, revoked.text);
  assert.equal(revoked.json.credential.state, "revoked");
  assert.equal(revoked.json.credential.verified, false);

  for (const ref of ["not-a-uuid", UUID_A.replace(/1/g, "9"), "e".repeat(40)]) {
    const r = await post(`${reportPath(id)}/credentials/${ref}/approve`, { injectHash });
    assert.equal(r.status, 404, `${ref}: ${r.status} ${r.text}`);
  }
});

test("a credential approval whose rule moved under it is a 409 and approves nothing", async () => {
  const world = await setup();
  const id = await prepareReport(world.db);
  const seedDeps = { loadSeed: () => ({ seed: SEED }), now: () => T0, crowHome: HOME };
  await proposeHost(world.db, seedDeps, { reportId: id, host: "example.com" });
  await approveHost(world.db, seedDeps, { reportId: id, host: "example.com", actor: { kind: "owner" } });
  await saveServiceSecret(world.db, KEY, {
    connectionUuid: UUID_A,
    bundleId: REPORTS_BUNDLE,
    envKey: "REPORT_CREDENTIAL",
    label: "report credential",
    secret: "credential-value-0123456789abcdef",
  });
  await proposeCredential(world.db, seedDeps, {
    reportId: id,
    host: "example.com",
    connectionUuid: UUID_A,
    inject: { header: "Authorization", format: "Bearer {}", pathPrefixes: ["/v1/issues"] },
    proposedBy: "bot:bot-1",
  });

  const listed = await get(`${reportPath(id)}/credentials`);
  const shownHash = listed.json.credentials[0].injectHash;

  // Another path prefix reaches the row after the owner's view was read.
  await world.db.execute({
    sql: "UPDATE report_credentials SET inject_json = ? WHERE report_id = ? AND host = ?",
    args: [
      JSON.stringify({ header: "Authorization", format: "Bearer {}", pathPrefixes: ["/v1/issues", "/v2"], methods: ["GET", "HEAD"] }),
      id,
      "example.com",
    ],
  });
  const stale = await post(`${reportPath(id)}/credentials/${UUID_A}/approve`, { injectHash: shownHash });
  assert.equal(stale.status, 409, stale.text);
  assert.deepEqual(stale.json, {
    error: "credential_changed",
    message: "That credential changed while this request was in flight. Try again.",
  });
  const raw = (await world.db.execute({
    sql: "SELECT state, approval_seal, approval_nonce FROM report_credentials WHERE report_id = ?",
    args: [id],
  })).rows[0];
  assert.equal(raw.state, "proposed", "the row stays proposed and is not sealed over the new rule");
  assert.equal(raw.approval_seal, null);
  assert.equal(raw.approval_nonce, null);

  // The digest of the rule the row holds NOW is what that row's approval needs.
  const fresh = await get(`${reportPath(id)}/credentials`);
  assert.notEqual(fresh.json.credentials[0].injectHash, shownHash);
  const approved = await post(`${reportPath(id)}/credentials/${UUID_A}/approve`, {
    injectHash: fresh.json.credentials[0].injectHash,
  });
  assert.equal(approved.status, 200, approved.text);
  assert.equal(approved.json.credential.state, "approved");
  assert.equal(approved.json.credential.verified, true);
});

/* ------------------------------------------------------------------------ assets */

test("an asset is uploaded as raw bytes, listed by hash, and never returned", async () => {
  const world = await setup();
  const id = await prepareReport(world.db);

  const upload = await call("PUT", `${reportPath(id)}/assets/ways.json`, {
    raw: '[{"id":1}]', headers: { "content-type": "application/octet-stream" },
  });
  assert.equal(upload.status, 201, upload.text);
  assert.equal(upload.json.asset.name, "ways.json");
  assert.equal(upload.json.asset.bytes, 10);
  assert.match(upload.json.asset.sha256, /^[0-9a-f]{64}$/);

  const listed = await get(`${reportPath(id)}/assets`);
  assert.equal(listed.status, 200, listed.text);
  assert.equal(listed.json.assets.length, 1);
  assert.equal(listed.json.assets[0].name, "ways.json");
  assert.equal(listed.json.assets[0].verified, true);
  assert.equal(listed.text.includes('"id":1'), false, "the bytes are never in the answer");

  const empty = await call("PUT", `${reportPath(id)}/assets/ways.json`, {
    raw: "", headers: { "content-type": "application/octet-stream" },
  });
  assert.equal(empty.status, 400, empty.text);
  assert.equal(empty.json.error, "bad_input");

  for (const name of ["a%2Fb", "a%20b"]) {
    const r = await call("PUT", `${reportPath(id)}/assets/${name}`, {
      raw: "x", headers: { "content-type": "application/octet-stream" },
    });
    assert.equal(r.status, 404, `${name}: ${r.status} ${r.text}`);
  }
  const dotDot = await call("PUT", `${reportPath(id)}/assets/..`, {
    raw: "x", headers: { "content-type": "application/octet-stream" },
  });
  assert.equal(dotDot.status, 400, dotDot.text);
  assert.equal(dotDot.json.error, "bad_input");
  const missingReport = await call("PUT", `${reportPath("rpt-ffffffffffffffff")}/assets/a.json`, {
    raw: "x", headers: { "content-type": "application/octet-stream" },
  });
  assert.equal(missingReport.status, 404, missingReport.text);
  const missingList = await get(`${reportPath("rpt-ffffffffffffffff")}/assets`);
  assert.equal(missingList.status, 404, missingList.text);

  // The raw upload route is owner-only even though it sits before the shared guards.
  const anonymous = await call("PUT", `${reportPath(id)}/assets/a.json`, {
    raw: "x", token: null, headers: { "content-type": "application/octet-stream" },
  });
  assert.equal(anonymous.status, 401, anonymous.text);
});

test("the JSON body guard still applies to the routes behind it", async () => {
  const world = await setup();
  const id = await prepareReport(world.db);
  const big = JSON.stringify({ stepKey: "fetch", language: "python", entry: "run.py", files: { "run.py": "a".repeat(300 * 1024) } });
  const r = await call("POST", `${reportPath(id)}/steps`, { body: big });
  assert.equal(r.status, 413, r.text);
  assert.equal(r.json.error, "too_large");
});