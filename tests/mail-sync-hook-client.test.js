// The CLI half of Crow Mail's sync hook: scripts/cli/lib/mail-sync-hook-client.js.
//
// `crow mail add` writes crow.db itself, so after a successful add it asks the running gateway (via
// POST /mail/local/sync-now) to start the new account now instead of at the next restart. This helper
// must never be able to fail the add or its exit code, and it must never widen the target beyond this
// box: no token file means no request, a refusal/timeout/failure resolves quietly, and the one
// request it does make carries the Bearer and the account id to 127.0.0.1 only.
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmScratch } from "./helpers/safe-rm.js";
import {
  MAIL_SYNC_HOOK_HOST,
  MAIL_SYNC_HOOK_PATH,
  notifyMailSyncHook,
} from "../scripts/cli/lib/mail-sync-hook-client.js";

const root = mkdtempSync(join(tmpdir(), "mail-sync-hook-client-"));
after(() => rmScratch(root));

const TOKEN = "b".repeat(64);
const ACCOUNT = "ma-0123456789abcdef";
let tokenFile;

before(() => {
  tokenFile = join(root, "mail-hook-token");
  writeFileSync(tokenFile, TOKEN, { mode: 0o600 });
});

/** A fetch spy that records the one request; `impl` decides its outcome. */
function fetchSpy(impl = async () => new Response("{}", { status: 202 })) {
  const calls = [];
  const fetchImpl = async (url, options) => {
    calls.push({ url, options });
    return impl(url, options);
  };
  return { calls, fetchImpl };
}

test("no token file -> no request at all", async () => {
  const spy = fetchSpy();
  const result = await notifyMailSyncHook({
    accountId: ACCOUNT,
    tokenPath: join(root, "no-such-token"),
    port: 3001,
    fetchImpl: spy.fetchImpl,
  });
  assert.deepEqual(result, { notified: false });
  assert.equal(spy.calls.length, 0);
});

test("an unreadable token file is the same skip", async () => {
  const spy = fetchSpy();
  const result = await notifyMailSyncHook({
    accountId: ACCOUNT,
    tokenPath: tokenFile,
    port: 3001,
    fetchImpl: spy.fetchImpl,
    readFile: () => { const err = new Error("EACCES"); err.code = "EACCES"; throw err; },
  });
  assert.deepEqual(result, { notified: false });
  assert.equal(spy.calls.length, 0);
});

test("an empty token file is the same skip", async () => {
  const empty = join(root, "empty-token");
  writeFileSync(empty, "  \n", { mode: 0o600 });
  const spy = fetchSpy();
  const result = await notifyMailSyncHook({ accountId: ACCOUNT, tokenPath: empty, port: 3001, fetchImpl: spy.fetchImpl });
  assert.deepEqual(result, { notified: false });
  assert.equal(spy.calls.length, 0);
});

test("the Bearer and the account id go to 127.0.0.1 only", async () => {
  const spy = fetchSpy();
  const result = await notifyMailSyncHook({ accountId: ACCOUNT, tokenPath: tokenFile, port: 4321, fetchImpl: spy.fetchImpl });
  assert.deepEqual(result, { notified: true });
  assert.equal(spy.calls.length, 1);
  const [{ url, options }] = spy.calls;
  assert.equal(url, `http://${MAIL_SYNC_HOOK_HOST}:4321${MAIL_SYNC_HOOK_PATH}`);
  assert.equal(new URL(url).hostname, "127.0.0.1", "loopback only; never a hostname or a peer address");
  assert.equal(options.method, "POST");
  assert.equal(options.headers.authorization, `Bearer ${TOKEN}`);
  assert.equal(options.headers["content-type"], "application/json");
  assert.deepEqual(JSON.parse(options.body), { accountId: ACCOUNT });
});

test("a thrown fetch, a non-2xx reply and a hang all resolve without throwing", async () => {
  const thrown = await notifyMailSyncHook({
    accountId: ACCOUNT,
    tokenPath: tokenFile,
    port: 3001,
    fetchImpl: async () => { throw new Error("ECONNREFUSED"); },
  });
  assert.deepEqual(thrown, { notified: false });

  const refused = await notifyMailSyncHook({
    accountId: ACCOUNT,
    tokenPath: tokenFile,
    port: 3001,
    fetchImpl: async () => new Response(JSON.stringify({ error: "bad_token" }), { status: 401 }),
  });
  assert.deepEqual(refused, { notified: false }, "a refused request is never an error for the CLI");

  const started = Date.now();
  const hung = await notifyMailSyncHook({
    accountId: ACCOUNT,
    tokenPath: tokenFile,
    port: 3001,
    fetchImpl: () => new Promise(() => {}),
    timeoutMs: 25,
  });
  assert.deepEqual(hung, { notified: false });
  assert.ok(Date.now() - started < 2000, "the short timeout returns promptly");
});

test("an unusable account id, token path or port makes no request", async () => {
  const spy = fetchSpy();
  for (const options of [
    { accountId: "", tokenPath: tokenFile, port: 3001 },
    { accountId: null, tokenPath: tokenFile, port: 3001 },
    { accountId: ACCOUNT, tokenPath: "", port: 3001 },
    { accountId: ACCOUNT, tokenPath: tokenFile, port: 0 },
    { accountId: ACCOUNT, tokenPath: tokenFile, port: "not-a-port" },
  ]) {
    const result = await notifyMailSyncHook({ ...options, fetchImpl: spy.fetchImpl });
    assert.deepEqual(result, { notified: false }, JSON.stringify(options));
  }
  assert.equal(spy.calls.length, 0);
});