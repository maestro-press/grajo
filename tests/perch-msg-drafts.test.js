// The Perch chat's own view of Crow Messages' drafts (bot-door plan, PR B):
//   - GET /interactive/:sid/msg-drafts answers the OPEN drafts this chat made — ids only, owner-checked,
//     no-store (the mail-drafts route's shape and rails);
//   - the chat's event stream carries a `{type:"msg_draft", id}` frame for every draft write whose
//     `chat_thread_id` is that session, and nothing for another chat's.
//
// Harness: a real init-db'd scratch crow.db, an ephemeral express app, the REAL router with the owner
// rule and the engine injected (the seams the router already takes), and the real draft store. No pi
// is spawned.
import { test, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { copyFileSync, mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmScratch } from "./helpers/safe-rm.js";

const root = mkdtempSync(join(tmpdir(), "perch-msg-drafts-"));
process.env.CROW_DATA_DIR = root;
process.env.CROW_HOME = join(root, "home");
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(root, "tasks.db");
mkdirSync(process.env.CROW_HOME, { recursive: true });
const REPO = new URL("..", import.meta.url).pathname;
const DB_FILE = join(root, "crow.db");

const { default: express } = await import("express");
const { createDbClient } = await import("../servers/db.js");
const store = await import("../servers/gateway/messages/drafts-store.js");
const bus = (await import("../servers/shared/event-bus.js")).default;

const SEED = Buffer.from("a fixed keychain seed for the perch draft list");
const NOW = 1_767_225_600_000;
const SID = "perchlive-0000abcd";
const PUBKEY = "02" + "a".repeat(64);
const P = "/dashboard/perch-api";

let server, base;
let ownerVerdict = true;
const open = [];

const engine = {
  async get(sid) { return { sessionId: sid, botId: "chatty", threadId: sid, rowId: 1, state: "awake", pendingUi: null, lastError: null, model: "local/qwen" }; },
  async subscribe(sid, fn) {
    fn({ type: "state", sessionId: sid, botId: "chatty", threadId: sid, state: "awake", lastError: null, pendingUi: null });
    return () => {};
  },
};

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: root },
    stdio: "pipe",
    cwd: REPO,
  });
  const { default: perchInteractiveApiRouter } = await import("../servers/gateway/routes/perch-interactive-api.js");
  const fakeAuth = (req, res, next) => { req.dashboardSession = "test-token"; next(); };
  const app = express();
  const json = express.json();
  app.use((req, res, next) => (/^\/dashboard\/perch-api\/interactive\/[^/]+\/(files|message)$/.test(req.path) ? next() : json(req, res, next)));
  app.use(perchInteractiveApiRouter(fakeAuth, {
    engine: () => engine,
    ownerCheck: async () => ownerVerdict,
    annotate: async (models) => models,
    providerModels: () => [],
    piProviders: () => null,
  }));
  await new Promise((r) => { server = app.listen(0, "127.0.0.1", r); });
  base = "http://127.0.0.1:" + server.address().port + P;
});

after(() => {
  if (server) server.close();
  for (const db of open) { try { db.close(); } catch { /* already closed */ } }
  rmScratch(root);
});

beforeEach(() => {
  ownerVerdict = true;
  bus.removeAllListeners(store.DRAFT_CHANGED_EVENT);
});

let n = 0;
let draftSeq = 0;

/** One contact per test (the router reads the same file this client writes through CROW_DATA_DIR). */
async function fixture() {
  const db = createDbClient();
  open.push(db);
  const id = ++n;
  const contact = await db.execute({
    sql: `INSERT INTO contacts (crow_id, display_name, secp256k1_pubkey, ed25519_pubkey, contact_type)
          VALUES (?, ?, ?, ?, 'crow')`,
    args: [`crow:peer-${id}`, `Peer ${id}`, PUBKEY, "e".repeat(64)],
  });
  const contactId = Number(contact.lastInsertRowid);
  const recipients = [{ contactId, crowId: `crow:peer-${id}`, pubkey: PUBKEY }];
  const opts = { now: () => NOW, loadSeed: async () => SEED };
  const thread = `perchlive-fixed${String(id).padStart(4, "0")}`;
  /** Each draft gets its OWN conversation (the store keeps one open draft per conversation). */
  const draft = async ({ inThread = thread, origin = "bot", body = "Hello from the bot" } = {}) => {
    const who = `crow:peer-${id}-${++draftSeq}`;
    const row = await db.execute({
      sql: `INSERT INTO contacts (crow_id, display_name, secp256k1_pubkey, ed25519_pubkey, contact_type)
            VALUES (?, ?, ?, ?, 'crow')`,
      args: [who, `Peer ${draftSeq}`, PUBKEY, "e".repeat(64)],
    });
    const contactId = Number(row.lastInsertRowid);
    const out = await store.createDraft(db, {
      conversationKind: "contact",
      conversationId: contactId,
      body,
      recipients: [{ contactId, crowId: who, pubkey: PUBKEY }],
      origin,
      botId: origin === "bot" ? "hank" : null,
      botName: origin === "bot" ? "Hank" : null,
      chatThreadId: origin === "bot" ? inThread : null,
    }, opts);
    assert.equal(out.ok, true);
    return out.draft;
  };
  return { db, contactId: null, recipients: null, opts, thread, draft };
}

/* ------------------------------------------------------------------- the list */

test("the chat's draft list is ids only, and only this chat's open bot drafts", async () => {
  const f = await fixture();
  const mine = await f.draft();
  await f.draft({ inThread: "another-chat", body: "Someone else's chat" });
  const discarded = await f.draft({ body: "Never mind" });
  await store.discardDraft(f.db, discarded.id, {}, f.opts);
  const owners = await f.draft({ origin: "owner", body: "The operator's own" });

  const res = await fetch(base + `/interactive/${f.thread}/msg-drafts`);
  assert.equal(res.status, 200);
  assert.equal(res.headers.get("cache-control"), "no-store");
  const body = await res.json();
  assert.deepEqual(body, { drafts: [{ id: mine.id }] });
  assert.equal(JSON.stringify(body).includes("Hello from the bot"), false, "ids only — no body");
  assert.equal(JSON.stringify(body).includes(owners.id), false, "an owner's draft has no chat thread");
});

test("a non-owner session is refused with no data at all", async () => {
  await fixture();
  ownerVerdict = false;
  const res = await fetch(base + `/interactive/${SID}/msg-drafts`);
  assert.equal(res.status, 403);
  const body = await res.json();
  assert.equal(body.error, "owner_only");
  assert.equal(body.drafts, undefined);
});

/* ------------------------------------------------------------------ the frame */

/** Read SSE frames from `path` until `predicate(buffer)` holds (or the stream ends). */
async function readSse(path, predicate) {
  const res = await fetch(base + path);
  const reader = res.body.getReader();
  const dec = new TextDecoder();
  let buf = "";
  const read = async () => {
    const { value, done } = await reader.read();
    if (!done) buf += dec.decode(value, { stream: true });
    return !done;
  };
  while (!predicate(buf)) { if (!(await read())) break; }
  return { status: res.status, buf, reader };
}

const frames = (buf) => buf.split("\n").filter((l) => l.startsWith("event: ")).map((l) => l.slice(7).trim());
const dataFor = (buf, name) => {
  const blocks = buf.split("\n\n");
  for (const block of blocks) {
    const lines = block.split("\n");
    if (lines.some((l) => l === `event: ${name}`)) {
      const data = lines.find((l) => l.startsWith("data: "));
      if (data) { try { return JSON.parse(data.slice(6)); } catch { return null; } }
    }
  }
  return null;
};

test("every write to this chat's draft is pushed as a {type:\"msg_draft\", id} frame; another chat's is not", async () => {
  const f = await fixture();
  const mine = await f.draft();
  const { status, buf, reader } = await readSse(`/interactive/${f.thread}/events`, (b) => frames(b).includes("state"));
  let live = buf;
  try {
    assert.equal(status, 200);
    // Another chat's draft write: nothing may arrive for it.
    bus.emit(store.DRAFT_CHANGED_EVENT, { draftId: "msgd-" + "1".repeat(32), chatThreadId: "another-chat", action: "create" });
    // This chat's: one frame, and it names the draft, nothing else.
    bus.emit(store.DRAFT_CHANGED_EVENT, { draftId: mine.id, chatThreadId: f.thread, action: "create" });
    while (!frames(live).includes("msg_draft")) {
      const { value, done } = await reader.read();
      if (done) break;
      live += new TextDecoder().decode(value, { stream: true });
    }
    assert.equal(frames(live).filter((n) => n === "msg_draft").length, 1, "one frame, from the matching write");
    assert.deepEqual(dataFor(live, "msg_draft"), { type: "msg_draft", id: mine.id });
  } finally {
    try { await reader.cancel(); } catch { /* already closed */ }
  }
});