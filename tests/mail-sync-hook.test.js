// Crow Mail's loopback sync hook (`POST /mail/local/sync-now`, servers/gateway/routes/mail-sync-hook.js).
//
// The hook exists so a terminal `crow mail add` — which writes crow.db itself — can have the ALREADY
// RUNNING gateway's supervisor start the new account, exactly as the dashboard's connect does with
// `supervisor.syncNow(id)`. It is a SECURITY-SENSITIVE auth surface, so this file pins, against a
// scratch crow.db and the real token module:
//
//   - the one accepted request (loopback, this boot's MAIL_HOOK_TOKEN, a known active account, a live
//     mail runtime) answering 202 and calling syncNow once;
//   - every refusal, with its status and code, and that syncNow was NOT called;
//   - that the mail-hook token authenticates no MCP mount through the REAL localTokenAuthMiddleware,
//     and that `MAIL_HOOK_TOKEN.validate` is called from exactly one place in servers/;
//   - Funnel: the real middleware refuses the path, and it is not in PUBLIC_FUNNEL_PREFIXES;
//   - the boot rotation list includes the token, and its file is minted where the CLI reads it.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, readFileSync, readdirSync, statSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, relative } from "node:path";
import express from "express";
import { rmScratch } from "./helpers/safe-rm.js";
import { createDbClient } from "../servers/db.js";
import {
  MAIL_HOOK_TOKEN,
  generateBoardToken,
  generateLocalToken,
  localTokenAuthMiddleware,
} from "../servers/gateway/local-token.js";
import { createAccount, updateAccount } from "../servers/gateway/mail/store/accounts.js";
import { clearMailApiRuntime, getMailSupervisor, setMailApiRuntime } from "../servers/gateway/routes/mail-api.js";
import { MAIL_SYNC_HOOK_PATH, mailSyncHookRouter } from "../servers/gateway/routes/mail-sync-hook.js";
import { PUBLIC_FUNNEL_PREFIXES, isFunnelPublicPath, rejectFunneledMiddleware } from "../servers/gateway/funnel.js";

const REPO = join(import.meta.dirname, "..");
const root = mkdtempSync(join(tmpdir(), "mail-sync-hook-"));
const home = join(root, "home");
const dataDir = join(root, "data");
mkdirSync(home, { recursive: true });
execFileSync(process.execPath, ["scripts/init-db.js"], {
  env: { ...process.env, CROW_DATA_DIR: dataDir, CROW_HOME: home },
  stdio: "pipe",
  cwd: REPO,
});
const prev = { home: process.env.CROW_HOME, data: process.env.CROW_DATA_DIR };
process.env.CROW_HOME = home;
process.env.CROW_DATA_DIR = dataDir;
const DB = join(dataDir, "crow.db");
const db = createDbClient(DB);

const open = [db];
after(() => {
  clearMailApiRuntime();
  for (const client of open) {
    try { client.close(); } catch { /* closed */ }
  }
  if (prev.home === undefined) delete process.env.CROW_HOME; else process.env.CROW_HOME = prev.home;
  if (prev.data === undefined) delete process.env.CROW_DATA_DIR; else process.env.CROW_DATA_DIR = prev.data;
  rmScratch(root);
});

/* --------------------------------------------------------------------- fixtures */

/** A supervisor that records what it was asked and answers at once. */
function fakeSupervisor() {
  const calls = [];
  return {
    calls,
    syncNow(accountId) {
      calls.push(accountId);
      return Promise.resolve();
    },
  };
}

let supervisor;
let hookToken;
let account;
let server;
let base;

const flush = async (rounds = 20) => {
  for (let i = 0; i < rounds; i += 1) await new Promise((resolve) => setImmediate(resolve));
};

before(async () => {
  // The real boot rotation: the raw token lands in <CROW_HOME>/secrets/mail-hook-token at 0600, and
  // only its hash is stored (local scope). This is the exact value the CLI reads after a boot.
  hookToken = await MAIL_HOOK_TOKEN.rotate(db);
  assert.match(hookToken, /^[0-9a-f]{64}$/);

  account = await createAccount(db, {
    address: "alex@example.com",
    label: "Alex",
    imap: { host: "mail.example.test", port: 993, security: "ssl" },
    smtp: { host: "mail.example.test", port: 587, security: "starttls" },
  });

  supervisor = fakeSupervisor();
  setMailApiRuntime({ supervisor });

  const app = express();
  // TEST SCAFFOLDING only: the loopback refusal is driven through the same socket field the gate
  // reads (a real server always connects from 127.0.0.1 here), and the two auth flags the gateway's
  // earlier middleware can set are simulated with headers.
  app.use((req, _res, next) => {
    const remote = req.headers["x-test-remote-addr"];
    // Always define it: undici's keep-alive reuses sockets across requests, and a one-way override
    // would leave a later test's request on the previous test's fake address.
    Object.defineProperty(req.socket, "remoteAddress", {
      value: typeof remote === "string" && remote !== "" ? remote : "127.0.0.1",
      configurable: true,
    });
    if (req.headers["x-test-instance-auth"]) req.instanceAuth = { instanceId: "inst-test" };
    if (req.headers["x-test-cross-host-auth"]) req.crossHostAuth = { host: "peer.example" };
    next();
  });
  app.use(mailSyncHookRouter({ createDbClient: () => createDbClient(DB), log: { warn() {} } }));
  // A body-parser refusal (the route's own 8kb limit) goes through express's default error handler,
  // which logs an HTML page to stderr. Answer it quietly here; the 413 status is what the test reads.
  app.use((err, _req, res, _next) => {
    if (res.headersSent) return;
    res.status(Number(err?.status) || 500).json({ error: "parser" });
  });
  server = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  base = `http://127.0.0.1:${server.address().port}`;
});

after(() => {
  if (server) {
    try { server.close(); } catch { /* already closed */ }
  }
});

beforeEach(() => {
  supervisor.calls.length = 0;
  setMailApiRuntime({ supervisor });
});

/** One POST to the hook. */
async function post(body = { accountId: account.id }, { token = hookToken, headers = {}, path = MAIL_SYNC_HOOK_PATH } = {}) {
  const res = await fetch(`${base}${path}`, {
    method: "POST",
    headers: {
      "content-type": "application/json",
      ...(token ? { authorization: `Bearer ${token}` } : {}),
      ...headers,
    },
    body: JSON.stringify(body),
  });
  const text = await res.text();
  return { status: res.status, body: text ? JSON.parse(text) : null };
}

/* ------------------------------------------------------------------ happy path */

test("202: loopback, this boot's mail-hook token, a known active account -> syncNow(id) once", async () => {
  const r = await post();
  assert.equal(r.status, 202);
  assert.deepEqual(r.body, { ok: true }, "the answer carries the flag and no account data");
  await flush();
  assert.deepEqual(supervisor.calls, [account.id], "syncNow was called exactly once with the id");
  assert.ok(!JSON.stringify(r.body).includes(hookToken), "never echoes the token");
});

test("the response does not wait for the sync to settle", async () => {
  let release;
  const slow = {
    calls: [],
    syncNow(accountId) {
      this.calls.push(accountId);
      return new Promise((resolve) => { release = resolve; });
    },
  };
  setMailApiRuntime({ supervisor: slow });
  const r = await post();
  assert.equal(r.status, 202, "the 202 does not await the whole sync");
  await flush();
  assert.deepEqual(slow.calls, [account.id]);
  release();
  await flush();
});

/* ------------------------------------------------------------------ refusals: step a */

test("step a: not provably the same box -> 404 not_found, no sync", async () => {
  const cases = [
    ["non-loopback socket", { "x-test-remote-addr": "100.64.0.5" }],
    ["X-Forwarded-For", { "x-forwarded-for": "100.64.0.5" }],
    ["tailscale identity", { "tailscale-user-login": "alex@example.com" }],
    ["Funnel", { "tailscale-funnel-request": "?1" }],
    ["instance auth", { "x-test-instance-auth": "1" }],
    ["cross-host auth", { "x-test-cross-host-auth": "1" }],
    ["the bot egress relay mark", { "x-test-remote-addr": "127.0.77.1" }],
    ["the bot egress relay mark, v4-mapped", { "x-test-remote-addr": "::ffff:127.0.77.1" }],
    ["the add-on relay mark", { "x-test-remote-addr": "127.0.78.1" }],
  ];
  for (const [label, headers] of cases) {
    const r = await post(undefined, { headers });
    assert.equal(r.status, 404, label);
    assert.deepEqual(r.body, { error: "not_found" }, label);
    assert.deepEqual(supervisor.calls, [], `${label}: syncNow was not called`);
  }
});

// The loopback spellings the kernel actually reports are all accepted: an IPv6 loopback, and the
// v4-mapped form a dual-stack listener reports for 127.0.0.1.
test("step a: both loopback spellings are still the same box -> 202", async () => {
  for (const addr of ["::1", "::ffff:127.0.0.1"]) {
    supervisor.calls.length = 0;
    const r = await post(undefined, { headers: { "x-test-remote-addr": addr } });
    assert.equal(r.status, 202, addr);
    assert.deepEqual(r.body, { ok: true }, addr);
    await flush();
    assert.deepEqual(supervisor.calls, [account.id], `${addr}: syncNow was called`);
  }
});

/* ------------------------------------------------------- the path is not a secret */

// Express routes case-insensitively and non-strictly, so this spelling reaches the SAME route. Every
// check must still run for it: it is not a bypass, and it is not a second entry point.
test("the hook path matches case-insensitively and with a trailing slash, checks and all", async () => {
  const odd = "/MAIL/local/sync-now/";
  const refused = await post(undefined, { path: odd, headers: { "x-test-remote-addr": "100.64.0.5" } });
  assert.equal(refused.status, 404, "step a still refuses a non-loopback caller on this spelling");
  assert.deepEqual(refused.body, { error: "not_found" });
  assert.deepEqual(supervisor.calls, [], "no sync from the refused spelling");

  const badToken = await post(undefined, { path: odd, token: "a".repeat(64) });
  assert.equal(badToken.status, 401, "step b still runs on this spelling");
  assert.deepEqual(badToken.body, { error: "bad_token" });

  const ok = await post(undefined, { path: odd });
  assert.equal(ok.status, 202, "and the valid request is served");
  assert.deepEqual(ok.body, { ok: true });
  await flush();
  assert.deepEqual(supervisor.calls, [account.id]);
});

/* ------------------------------------------------- the owner's own body limit */

// The route parses its own 8kb body. index.js's global 1mb parser must not reach the path first, or a
// 20kb body would be parsed there and the hook's own limit would never apply (a static read of the
// predicate, as the other route tests do — the test app here mounts only the router).
test("the hook's own 8kb limit applies: index.js leaves the path to it, and 20kb is refused", async () => {
  const indexSrc = readFileSync(join(REPO, "servers", "gateway", "index.js"), "utf8");
  const predicate = /const _hasOwnParser = \(p\) => ([^\n]*\n[^\n]*);/.exec(indexSrc);
  assert.ok(predicate, "index.js's _hasOwnParser is where it was");
  const hasOwnParser = new Function("p", `return ${predicate[1]};`);
  assert.equal(hasOwnParser(MAIL_SYNC_HOOK_PATH), true, "the global parser skips the hook path");
  assert.equal(hasOwnParser("/MAIL/local/sync-now/"), true, "the spelling Express also routes is skipped too");

  // Raw fetch: express's default error handler answers a parser error with HTML, not JSON.
  const res = await fetch(`${base}${MAIL_SYNC_HOOK_PATH}`, {
    method: "POST",
    headers: { "content-type": "application/json", authorization: `Bearer ${hookToken}` },
    body: JSON.stringify({ accountId: account.id, pad: "x".repeat(20 * 1024) }),
  });
  assert.equal(res.status, 413, "the route's own 8kb parser refuses a 20kb body");
  await res.text();
  await flush();
  assert.deepEqual(supervisor.calls, [], "and an oversized body never reaches the supervisor");
});

/* --------------------------------------------------------- a sync that rejects */

test("a rejecting syncNow is still a 202, with no unhandled rejection", async () => {
  const unhandled = [];
  const onUnhandled = (err) => unhandled.push(err);
  process.on("unhandledRejection", onUnhandled);
  const rejecting = {
    calls: [],
    syncNow(accountId) {
      this.calls.push(accountId);
      return Promise.reject(new Error("sync failed after the answer"));
    },
  };
  try {
    setMailApiRuntime({ supervisor: rejecting });
    const r = await post();
    assert.equal(r.status, 202, "the answer does not depend on the sync succeeding");
    assert.deepEqual(r.body, { ok: true });
    await flush();
    assert.deepEqual(rejecting.calls, [account.id], "syncNow was asked once");
  } finally {
    await flush();
    process.removeListener("unhandledRejection", onUnhandled);
    setMailApiRuntime({ supervisor });
  }
  assert.deepEqual(unhandled, [], "the rejection was caught, not left unhandled");
});

/* ------------------------------------------------------------------ refusals: step b */

test("step b: the bearer must be the mail-hook token -> 401 bad_token", async () => {
  const board = await generateBoardToken(db);
  const local = await generateLocalToken(db);
  const cases = [
    ["no Authorization", null],
    ["a wrong token", "a".repeat(64)],
    ["the full local MCP token", local],
    ["the board token", board],
  ];
  for (const [label, token] of cases) {
    const r = await post(undefined, { token });
    assert.equal(r.status, 401, label);
    assert.deepEqual(r.body, { error: "bad_token" }, label);
    assert.deepEqual(supervisor.calls, [], `${label}: syncNow was not called`);
  }
});

// The stored hash is the ONLY thing that validates a token: with the setting row gone, a token that
// was valid a moment ago (the file still holds it) is refused. The family re-rotates for later tests.
test("step b: the stored hash deleted -> the previously valid token is 401", async () => {
  try {
    await db.execute({ sql: "DELETE FROM dashboard_settings_overrides WHERE key = ?", args: ["mcp_mail_hook_token_hash"] });
    await db.execute({ sql: "DELETE FROM dashboard_settings WHERE key = ?", args: ["mcp_mail_hook_token_hash"] });
    const r = await post();
    assert.equal(r.status, 401);
    assert.deepEqual(r.body, { error: "bad_token" });
    assert.deepEqual(supervisor.calls, [], "syncNow was not called");
  } finally {
    hookToken = await MAIL_HOOK_TOKEN.rotate(db);
  }
});

/* ------------------------------------------------------------------ refusals: step c */
test("step c: a malformed id is 400, an unknown or non-active account 404, none synced", async () => {
  for (const body of [{ accountId: "nope" }, { accountId: 42 }, {}, { accountId: "ma-zzzzzzzzzzzzzzzz" }]) {
    const r = await post(body);
    assert.equal(r.status, 400, JSON.stringify(body));
    assert.deepEqual(r.body, { error: "bad_request" });
  }
  // A well-formed id the store never minted.
  const unknown = await post({ accountId: "ma-0000000000000000" });
  assert.equal(unknown.status, 404);
  assert.deepEqual(unknown.body, { error: "unknown_account" });

  // An account the supervisor would not sync (signed out): the dashboard's own add never asks for
  // one of these either, so the CLI hook must not start it.
  const disabled = await createAccount(db, {
    address: "second@example.com",
    label: "Second",
    imap: { host: "mail.example.test", port: 993, security: "ssl" },
    smtp: { host: "mail.example.test", port: 587, security: "starttls" },
  });
  await updateAccount(db, disabled.id, { status: "auth_failed" });
  const refused = await post({ accountId: disabled.id });
  assert.equal(refused.status, 404);
  assert.deepEqual(refused.body, { error: "unknown_account" });
  assert.deepEqual(supervisor.calls, [], "syncNow was not called for any refused id");
});

/* ------------------------------------------------------------------ refusals: step d */

test("step d: no mail runtime -> 503 mail_off, no sync", async () => {
  clearMailApiRuntime();
  assert.equal(getMailSupervisor(), null);
  try {
    const r = await post();
    assert.equal(r.status, 503);
    assert.deepEqual(r.body, { error: "mail_off" });
    assert.deepEqual(supervisor.calls, [], "syncNow was not called");
  } finally {
    setMailApiRuntime({ supervisor });
  }
});

/* --------------------------------------------------- the token opens nothing else */

test("the mail-hook token authenticates no MCP mount through the real middleware", async () => {
  const app = express();
  app.use(localTokenAuthMiddleware(db));
  app.use((req, res) => res.json({ localTokenAuth: req.localTokenAuth ?? null }));
  const mcpServer = await new Promise((resolve) => {
    const s = app.listen(0, "127.0.0.1", () => resolve(s));
  });
  try {
    const port = mcpServer.address().port;
    for (const path of [
      "/memory/mcp",
      "/board/mcp",
      "/reports/mcp",
      "/secrets/mcp",
      "/phone/mcp",
      "/artifacts/mcp",
      "/sharing-bot/mcp",
      "/mail-draft/mcp",
    ]) {
      const res = await fetch(`http://127.0.0.1:${port}${path}`, {
        method: "POST",
        headers: { "content-type": "application/json", authorization: `Bearer ${hookToken}` },
        body: "{}",
      });
      assert.equal(res.status, 200, path);
      const body = await res.json();
      assert.equal(body.localTokenAuth, null, `${path}: the mail-hook token sets no localTokenAuth`);
    }
    // Sanity on the same app: the operator's full local token DOES authenticate an MCP path, so the
    // negative above is about the hook token, not about a mis-wired probe.
    const local = await generateLocalToken(db);
    const res = await fetch(`http://127.0.0.1:${port}/memory/mcp`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${local}` },
      body: "{}",
    });
    assert.deepEqual((await res.json()).localTokenAuth, { token: "local-mcp" });
  } finally {
    await new Promise((resolve) => mcpServer.close(resolve));
  }
});

/** Every file under servers/, relative to the repo. */
function serverFiles(dir = join(REPO, "servers")) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    const full = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...serverFiles(full));
    else if (entry.isFile() && entry.name.endsWith(".js")) out.push(full);
  }
  return out;
}

test("source: MAIL_HOOK_TOKEN.validate is called only by the hook, and its hash key lives only in local-token.js", () => {
  const files = serverFiles();
  const rel = (f) => relative(REPO, f).split("\\").join("/");

  // The keyed-hash family tables list every token-hash key NAME and never read or write the row
  // themselves, so they are not second owners: servers/shared/token-mac.js (#101) and the
  // settings-family list in servers/gateway/token-settings.js (#113), plus the boot converter's
  // BOOT_ROTATORS key, which reaches the row only through MAIL_HOOK_TOKEN.rotate (local-token.js).
  const FAMILY_TABLES = new Set([
    "servers/shared/token-mac.js", "servers/gateway/token-settings.js", "servers/gateway/boot/token-hmac-settings.js",
  ]);
  const hashKeyFiles = files.filter((f) => readFileSync(f, "utf8").includes("mcp_mail_hook_token_hash"))
    .filter((f) => !FAMILY_TABLES.has(rel(f)));
  assert.deepEqual(hashKeyFiles.map(rel), ["servers/gateway/local-token.js"], "one owner for the hash key");

  const validated = files.filter((f) => /MAIL_HOOK_TOKEN\s*\.\s*validate\s*\(/.test(readFileSync(f, "utf8")));
  assert.deepEqual(validated.map(rel), ["servers/gateway/routes/mail-sync-hook.js"], "one validator, on the hook only");
});

/* ------------------------------------------------------------------------- Funnel */

test("Funnel: the real middleware refuses the hook path, and it is not public", async () => {
  const prevPublic = process.env.CROW_DASHBOARD_PUBLIC;
  const prevExtra = process.env.GATEWAY_FUNNEL_PUBLIC_PREFIXES;
  delete process.env.CROW_DASHBOARD_PUBLIC;
  delete process.env.GATEWAY_FUNNEL_PUBLIC_PREFIXES;
  try {
    assert.equal(isFunnelPublicPath(MAIL_SYNC_HOOK_PATH), false);
    assert.ok(!PUBLIC_FUNNEL_PREFIXES.some((p) => MAIL_SYNC_HOOK_PATH.startsWith(p)), "not under a public prefix");

    const app = express();
    app.use(rejectFunneledMiddleware());
    app.post(MAIL_SYNC_HOOK_PATH, (req, res) => res.json({ ok: true }));
    const funnelServer = await new Promise((resolve) => {
      const s = app.listen(0, "127.0.0.1", () => resolve(s));
    });
    try {
      const url = `http://127.0.0.1:${funnelServer.address().port}${MAIL_SYNC_HOOK_PATH}`;
      const refused = await fetch(url, {
        method: "POST",
        headers: { "content-type": "application/json", "tailscale-funnel-request": "?1" },
        body: "{}",
      });
      assert.equal(refused.status, 403, "a Funnel-marked request never reaches the hook");
      const allowed = await fetch(url, { method: "POST", headers: { "content-type": "application/json" }, body: "{}" });
      assert.equal(allowed.status, 200, "and the path itself is served normally off-Funnel");
    } finally {
      await new Promise((resolve) => funnelServer.close(resolve));
    }
  } finally {
    if (prevPublic === undefined) delete process.env.CROW_DASHBOARD_PUBLIC; else process.env.CROW_DASHBOARD_PUBLIC = prevPublic;
    if (prevExtra === undefined) delete process.env.GATEWAY_FUNNEL_PUBLIC_PREFIXES; else process.env.GATEWAY_FUNNEL_PUBLIC_PREFIXES = prevExtra;
  }
});

/* --------------------------------------------------------------------------- boot */

test("boot: the family rotation list includes [MAIL_HOOK_TOKEN, \"mail-hook\"]", () => {
  const src = readFileSync(join(REPO, "servers", "gateway", "boot", "mcp-mounts.js"), "utf8");
  assert.match(src, /MAIL_HOOK_TOKEN[^\n]*local-token\.js/, "imported from local-token.js");
  assert.match(src, /\[MAIL_HOOK_TOKEN,\s*"mail-hook"\]/, "rotated every boot with the other families");
});

test("the raw token is minted where the CLI reads it: secrets/mail-hook-token, 0600", () => {
  assert.equal(MAIL_HOOK_TOKEN.path(), join(home, "secrets", "mail-hook-token"));
  assert.equal(statSync(MAIL_HOOK_TOKEN.path()).mode & 0o777, 0o600);
  assert.equal(readFileSync(MAIL_HOOK_TOKEN.path(), "utf8").trim(), hookToken);
});
