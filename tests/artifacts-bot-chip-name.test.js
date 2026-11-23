/**
 * The viewer's bot chip shows the bot's display name ("Hank · bot"), not its id.
 * listThreads (the viewer payload and artifact_comments) adds author_name to bot
 * comments from pi_bot_defs.display_name, sanitized, falling back to the id.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, rmSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { createDbClient } from "../servers/db.js";
import { initArtifactsTables } from "../bundles/artifacts/server/init-tables.js";

const REPO = new URL("..", import.meta.url).pathname;
const { listThreads } = await import("../bundles/artifacts/server/comments.js");
const line = readFileSync(REPO + "bundles/artifacts/panel/static/viewer-client.js", "utf8").split("\n").find((l) => l.includes("function authorName"));
const authorName = new Function("T", line + "\nreturn authorName;")({ you: "you", bot: "bot" });

let dir, db;
async function seed(rows) {
  await db.execute({ sql: "INSERT INTO artifacts (id, owner_kind, title, type) VALUES ('a1','owner','t','html')", args: [] }).catch(() => {});
  let n = 0;
  for (const [kind, id] of rows) {
    const r = await db.execute({ sql: "INSERT INTO artifact_threads (artifact_id,version_n,anchor_json,author_kind,author_id,anchor_from_version) VALUES ('a1',1,'{\"kind\":\"whole\"}',?,?,1)", args: [kind, id] });
    await db.execute({ sql: "INSERT INTO artifact_comments (thread_id,author_kind,author_id,text,ts) VALUES (?,?,?,?,?)", args: [Number(r.lastInsertRowid), kind, id, "c" + ++n, Date.now()] });
  }
}
before(async () => {
  dir = mkdtempSync(join(tmpdir(), "chip-name-"));
  db = createDbClient(join(dir, "crow.db"));
  await db.executeMultiple(`CREATE TABLE IF NOT EXISTS pi_bot_defs (bot_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, definition TEXT, enabled INTEGER NOT NULL DEFAULT 1);`);
  await initArtifactsTables(db);
});
after(() => { try { rmSync(dir, { recursive: true, force: true }); } catch {} });

const ins = (id, name) => db.execute({ sql: "INSERT INTO pi_bot_defs (bot_id, display_name) VALUES (?,?)", args: [id, name] });
const cmts = async () => (await listThreads(db, "a1")).flatMap((t) => t.comments);

test("bot comments carry author_name from display_name; fallbacks and sanitizing", async () => {
  await ins("hank", "Hank");
  await ins("blank", "   ");
  await ins("evil", "Ev\nil‮gnp  " + "x".repeat(60));
  await seed([["bot", "hank"], ["bot", "ghost"], ["bot", "blank"], ["bot", "evil"], ["owner", null], ["contact", "alex"]]);
  const c = await cmts();
  const by = (id) => c.find((x) => x.author_id === id);
  assert.equal(by("hank").author_name, "Hank");
  assert.equal(authorName(by("hank")), "Hank · bot");
  assert.equal(by("ghost").author_name, "ghost");
  assert.equal(authorName(by("ghost")), "ghost · bot");
  assert.equal(by("blank").author_name, "blank");
  const evil = by("evil").author_name;
  assert.ok(!/[\n‮]/.test(evil) && evil.length <= 40 && evil.startsWith("Evilgnp"), evil);
  assert.equal(by("alex").author_name, undefined, "contact comments are untouched");
  assert.equal(c.find((x) => x.author_kind === "owner").author_name, undefined);
});

test("authorName falls back to the id without author_name", () => {
  assert.equal(authorName({ author_kind: "bot", author_id: "hank" }), "hank · bot");
});

test("a report recipient's thread carries the display name its recipient row holds", async () => {
  // The same reader (listThreads) names a bot by pi_bot_defs and a report recipient by
  // report_recipients: the table it reads is the real one, from the reports schema.
  const { REPORTS_SEND_DDL } = await import("../servers/shared/reports-schema.js");
  await db.executeMultiple(REPORTS_SEND_DDL);
  const recipient = (id, displayName) => db.execute({
    sql: `INSERT INTO report_recipients (id, report_id, address, display_name, state, proposed_by, created_at)
          VALUES (?, 'rpt-0000000000000001', ?, ?, 'approved', 'owner', 1)`,
    args: [id, `${id}@example.com`, displayName],
  });
  await recipient("rrc-0000000000000001", "Alex Rivera");
  await recipient("rrc-0000000000000002", null);
  await recipient("rrc-0000000000000003", `Ev\nil\u202egnp ${"x".repeat(70)}`);
  for (const [index, id] of ["rrc-0000000000000001", "rrc-0000000000000002", "rrc-0000000000000003"].entries()) {
    const r = await db.execute({
      sql: `INSERT INTO artifact_threads (artifact_id,version_n,anchor_json,author_kind,author_id,anchor_from_version)
            VALUES ('a2',1,'{"kind":"whole"}','contact',?,1)`,
      args: [id],
    });
    await db.execute({
      sql: "INSERT INTO artifact_comments (thread_id,author_kind,author_id,text,ts) VALUES (?,?,?,?,?)",
      args: [Number(r.lastInsertRowid), "contact", id, `c${index}`, Date.now()],
    });
  }
  const threads = await listThreads(db, "a2");
  const by = (id) => threads.find((row) => row.author_id === id);
  assert.equal(by("rrc-0000000000000001").author_name, "Alex Rivera");
  assert.equal(by("rrc-0000000000000002").author_name, undefined, "no name on the row, no name on the thread");
  const cleaned = by("rrc-0000000000000003").author_name;
  assert.ok(!/[\n\u202e]/.test(cleaned), "control characters are stripped");
  assert.ok(cleaned.length <= 60, "and the name is capped");
  assert.ok(cleaned.startsWith("Evilgnp"), cleaned);
});
