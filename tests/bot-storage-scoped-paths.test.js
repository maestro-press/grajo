/**
 * A hydrated bot child's REAL paths, against a fake MinIO that enforces the operator's scoped
 * policy — the shape round A was reviewed against, where the key could not even ask whether the
 * bucket existed.
 *
 * The three callers whose quota check is a whole-bucket listing today:
 *   - `crow_upload_file` (servers/storage/server.js, the MCP tool a bot's storage child serves);
 *   - sunvox-studio's `saveToStorage` (bundles/sunvox-studio/server/outputs.js);
 *   - Studio's take storage adapter (bundles/studio/server/take-storage.js, the upload service's
 *     `putObjectStream` + `getBucketStats`).
 * Each of them must succeed with a key that may list ONLY `projects/`, `bots/`, `studio/` and
 * `sunvox-studio/` of `<prefix>-files`, and may neither HeadBucket nor create anything.
 *
 * No network: the S3 seam is the s3-client module with a fake MinIO client installed
 * (`_setClientForTest`), and the DB is a real crow.db in a scratch CROW_HOME.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { Readable } from "node:stream";

const REPO = resolve(new URL("..", import.meta.url).pathname);
const T = mkdtempSync(join(tmpdir(), "bot-storage-scoped-"));
const DATA = join(T, "data");
mkdirSync(DATA, { recursive: true });
const DB_FILE = join(DATA, "crow.db");
// The scratch instance, set before any module that pins a data dir is imported (the project-space
// helper derives its workspace paths from CROW_DATA_DIR at import time).
process.env.CROW_HOME = T;
process.env.CROW_DATA_DIR = DATA;
process.env.CROW_DB_PATH = DB_FILE;
process.env.CROW_TASKS_DB_PATH = join(DATA, "tasks.db");
process.env.CROW_DISABLE_INSTANCE_SYNC = "1";

after(() => { try { rmSync(T, { recursive: true, force: true }); } catch { /* best effort */ } });

// ── the fake MinIO, enforcing the scoped policy ───────────────────────────

/** The four prefixes the operator's policy grants a bot's key. */
const GRANTED_PREFIXES = ["projects/", "bots/", "studio/", "sunvox-studio/"];

/**
 * A fake MinIO that refuses what a real one refuses under the bot policy:
 *   - `bucketExists` (HeadBucket) — refused, because MinIO reads it as s3:ListBucket with NO
 *     prefix, so the policy's s3:prefix condition fails on a healthy backend;
 *   - `listBuckets`, `makeBucket` — never granted;
 *   - any listing or object operation whose prefix is not one of the four granted prefixes —
 *     refused, so an empty-prefix listing of the bucket root cannot pass.
 * Every refusal is AccessDenied-shaped (`code: "AccessDenied"`, `statusCode: 403`).
 */
function fakeMinio({ objects = [] } = {}) {
  const store = new Map(objects.map(([k, v]) => [k, Buffer.from(String(v))]));
  const calls = [];
  const denied = (what) => Object.assign(new Error(`Access Denied (${what})`), { code: "AccessDenied", statusCode: 403 });
  const grantedPrefix = (prefix) => GRANTED_PREFIXES.some((a) => String(prefix ?? "").startsWith(a)) ? String(prefix ?? "") : null;
  const grantedKey = (key) => GRANTED_PREFIXES.some((a) => String(key).startsWith(a));
  const items = (prefix, max = Infinity) => [...store.keys()]
    .filter((k) => k.startsWith(prefix)).sort().slice(0, max)
    .map((name) => ({ name, size: store.get(name).length, lastModified: new Date(0) }));
  return {
    calls,
    store,
    async bucketExists(bucket) { calls.push(["bucketExists", bucket]); throw denied("HeadBucket"); },
    async makeBucket(bucket) { calls.push(["makeBucket", bucket]); throw denied("MakeBucket"); },
    async listBuckets() { calls.push(["listBuckets"]); throw denied("ListBuckets"); },
    async listObjectsV2Query(bucket, prefix, _token, _delimiter, maxKeys) {
      calls.push(["listObjectsV2Query", bucket, prefix, maxKeys]);
      const p = grantedPrefix(prefix);
      if (p === null) throw denied(`ListBucket prefix ${JSON.stringify(prefix)}`);
      const limit = Number(maxKeys) > 0 ? Number(maxKeys) : Infinity;
      return { objects: items(p, limit), isTruncated: false, nextContinuationToken: "" };
    },
    listObjectsV2(bucket, prefix) {
      calls.push(["listObjectsV2", bucket, prefix]);
      const p = grantedPrefix(prefix);
      if (p === null) throw denied(`ListBucket prefix ${JSON.stringify(prefix)}`);
      return Readable.from(items(p));
    },
    async putObject(bucket, key, data, size) {
      calls.push(["putObject", bucket, key, size]);
      if (!grantedKey(key)) throw denied(`PutObject ${key}`);
      const pieces = [];
      if (data && typeof data[Symbol.asyncIterator] === "function") {
        for await (const piece of data) pieces.push(Buffer.from(piece));
      } else if (Buffer.isBuffer(data)) pieces.push(data);
      else pieces.push(Buffer.from(String(data ?? "")));
      store.set(key, Buffer.concat(pieces));
      return { etag: "etag", versionId: null };
    },
    async removeObject(bucket, key) {
      calls.push(["removeObject", bucket, key]);
      if (!grantedKey(key)) throw denied(`DeleteObject ${key}`);
      store.delete(key);
    },
    async presignedGetObject(bucket, key, expiry) {
      calls.push(["presignedGetObject", bucket, key, expiry]);
      return `http://minio.invalid/${bucket}/${key}?sig=get&expires=${expiry}`;
    },
    async presignedPutObject(bucket, key, expiry) {
      calls.push(["presignedPutObject", bucket, key, expiry]);
      return `http://minio.invalid/${bucket}/${key}?sig=put&expires=${expiry}`;
    },
    async statObject(bucket, key) {
      calls.push(["statObject", bucket, key]);
      if (!grantedKey(key)) throw denied(`Head ${key}`);
      if (!store.has(key)) throw Object.assign(new Error("Not Found"), { code: "NotFound", statusCode: 404 });
      return { size: store.get(key).length };
    },
    async getObject(bucket, key) {
      calls.push(["getObject", bucket, key]);
      if (!grantedKey(key)) throw denied(`GetObject ${key}`);
      return Readable.from([store.get(key) || Buffer.alloc(0)]);
    },
  };
}

/** The env a hydrated bot block carries (servers/shared/bot-storage-key.js botStorageEnv). */
const HYDRATED_ENV = {
  CROW_STORAGE_FROM_HOST: "1",
  S3_ENDPOINT: "127.0.0.1:19999",
  S3_USE_SSL: "false",
  S3_REGION: "us-east-1",
  S3_BUCKET_PREFIX: "fx",
  S3_ACCESS_KEY: "bot-access",
  S3_SECRET_KEY: "bot-secret",
};

const BUCKET = "fx-files";

let s3 = null;
let OWNER = null;
let createStorageServer = null;
let Client = null;
let InMemoryTransport = null;
let createProjectSpace = null;
let db = null;
/** The fake MinIO the whole file runs against. */
const fake = fakeMinio({
  objects: [
    ["projects/p-seed/1-old.txt", "abcd"],
    ["bots/b-seed/2-old.txt", "abcde"],
    ["studio/s-seed/takes/3-old.wav", "abcdef"],
    ["sunvox-studio/renders/4-old.mp3", "abcdefg"],
    // Not granted to a bot's key: never counted, and never listed.
    ["elsewhere/5-other.txt", "abcdefgh"],
  ],
});

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], { cwd: REPO, stdio: "pipe", env: { ...process.env } });
  s3 = await import("../servers/storage/s3-client.js");
  ({ OWNER } = await import("../servers/research/actor.js"));
  ({ createStorageServer } = await import("../servers/storage/server.js"));
  ({ Client } = await import("@modelcontextprotocol/sdk/client/index.js"));
  ({ InMemoryTransport } = await import("@modelcontextprotocol/sdk/inMemory.js"));
  ({ createProjectSpace } = await import("../servers/shared/project-spaces.js"));
  const { createDbClient } = await import("../servers/db.js");
  db = createDbClient(DB_FILE);
  assert.equal(s3.adoptHostStorage(HYDRATED_ENV), "hydrated", "every caller below runs as a hydrated bot child");
  s3._setClientForTest(fake);
});

after(async () => {
  try { s3 && s3._setClientForTest(null); } catch { /* best effort */ }
  try { db && db.close && db.close(); } catch { /* best effort */ }
});

/** A storage server wired to an in-process MCP client; the S3 seam is the hydrated s3-client. */
async function openStorageServer() {
  const server = createStorageServer(DB_FILE, { baseActor: OWNER });
  const [clientTransport, serverTransport] = InMemoryTransport.createLinkedPair();
  await Promise.all([server.connect(serverTransport)]);
  const client = new Client({ name: "bot-storage-scoped", version: "0" });
  await client.connect(clientTransport);
  return {
    async call(name, args) {
      const r = await client.callTool({ name, arguments: args });
      const text = (r.content || []).filter((c) => c.type === "text").map((c) => c.text).join("\n");
      return { text, isError: !!r.isError };
    },
    async close() {
      try { await client.close(); } catch { /* best effort */ }
      try { await server.close(); } catch { /* best effort */ }
    },
  };
}

// ── crow_upload_file ───────────────────────────────────────────────────────

test("crow_upload_file: a project upload lands under projects/ and its quota check sums the granted prefixes", async () => {
  const project = await createProjectSpace(db, { name: "Scoped storage uploads" });
  const prefix = (await db.execute({ sql: "SELECT storage_prefix FROM project_spaces WHERE id = ?", args: [Number(project.id)] })).rows[0].storage_prefix;
  assert.ok(String(prefix).startsWith("projects/"), "the fixture project's prefix is a granted one: " + prefix);

  const srv = await openStorageServer();
  try {
    const r = await srv.call("crow_upload_file", {
      file_name: "notes.txt",
      mime_type: "text/plain",
      data_base64: Buffer.from("hello scoped storage").toString("base64"),
      project_id: Number(project.id),
    });
    assert.equal(r.isError, false, r.text);
    const key = /Key: (\S+)/.exec(r.text)[1];
    assert.ok(key.startsWith(prefix), `${key} sits under ${prefix}`);
    assert.equal(fake.store.get(key).toString(), "hello scoped storage");
    assert.match(r.text, /Download URL/, "a presigned URL came back");

    // The presigned-upload branch (a file too large for base64) uses the same allowed calls.
    const big = await srv.call("crow_upload_file", { file_name: "big.bin", mime_type: "text/plain", project_id: Number(project.id) });
    assert.equal(big.isError, false, big.text);
    assert.match(big.text, /Upload URL generated for "big\.bin"/);
    const putUrl = /PUT (\S+)/.exec(big.text)[1];
    assert.match(putUrl, new RegExp(`^http://minio\\.invalid/${BUCKET}/${prefix}`), "the presigned PUT is for a granted key");
    const putKey = (await db.execute({
      sql: "SELECT s3_key FROM storage_files WHERE original_name = 'big.bin' AND project_id = ? ORDER BY id DESC LIMIT 1",
      args: [Number(project.id)],
    })).rows[0].s3_key;
    assert.ok(putKey.startsWith(prefix), putKey);

    // The row records the bucket actually used, and nothing above the granted prefixes was
    // consulted: no HeadBucket, no listBuckets, no makeBucket.
    const row = (await db.execute({ sql: "SELECT bucket FROM storage_files WHERE s3_key = ?", args: [key] })).rows[0];
    assert.equal(row.bucket, BUCKET);
    for (const c of fake.calls) {
      assert.equal(["bucketExists", "listBuckets", "makeBucket"].includes(c[0]), false, "never " + c[0]);
    }
    for (const c of fake.calls.filter((x) => x[0] === "listObjectsV2" || x[0] === "listObjectsV2Query")) {
      assert.equal(GRANTED_PREFIXES.some((p) => String(c[2]).startsWith(p)), true, "list prefix " + JSON.stringify(c[2]));
    }
  } finally {
    await srv.close();
  }
});

// ── sunvox-studio's saveToStorage ──────────────────────────────────────────

test("sunvox-studio saveToStorage: the quota read and the upload both work under the scoped key", async () => {
  const outputs = await import("../bundles/sunvox-studio/server/outputs.js");
  const rows = [];
  const fakeDb = {
    execute: async ({ sql, args }) => {
      if (/INSERT INTO storage_files/.test(sql)) rows.push(args);
      return { rows: [], rowsAffected: 1 };
    },
  };
  const r = await outputs.saveToStorage({
    s3, db: fakeDb, buf: Buffer.from("wav-bytes"), fileName: "my song!.wav", mimeType: "audio/wav",
    kind: "renders", now: 1700000000000, rand: () => "ab12cd34", botBound: false,
  });
  assert.equal(r.storage_key, "sunvox-studio/renders/1700000000000-ab12cd34-my_song_.wav");
  assert.equal(r.bucket, BUCKET);
  assert.equal(fake.store.get(r.storage_key).toString(), "wav-bytes");
  assert.match(r.url, /^http:\/\/minio\.invalid\//);
  assert.equal(rows.length, 1, "the storage_files row was written");
  assert.equal(rows[0][4], BUCKET);
});

// ── Studio's take storage ──────────────────────────────────────────────────

test("studio take storage: a streamed take uploads under studio/ and its stat sums the granted prefixes", async () => {
  const { createTakeStorage } = await import("../bundles/studio/server/take-storage.js");
  const projectPrefix = "projects/studio-fixture/";
  const takeStorage = createTakeStorage({
    client: s3,
    db: { execute: async () => ({ rows: [{ storage_prefix: projectPrefix }] }) },
  });
  const bytes = Buffer.from("RIFF....WAVE");
  // Whatever earlier tests have already stored: the stat must equal the objects under the FOUR
  // granted prefixes, and nothing else (the ungranted `elsewhere/` object is never counted).
  const grantedNow = [...fake.store.keys()].filter((k) => GRANTED_PREFIXES.some((p) => k.startsWith(p)));
  const before = await takeStorage.getBucketStats();
  assert.deepEqual(before, {
    fileCount: grantedNow.length,
    totalSizeBytes: grantedNow.reduce((n, k) => n + fake.store.get(k).length, 0),
  }, "the four granted prefixes, summed — the ungranted object is not counted");

  const key = `${projectPrefix}studio/song-1/takes/take-1.wav`;
  await takeStorage.putObjectStream(key, Readable.from([bytes]), bytes.length, { contentType: "audio/wav" });
  assert.equal(fake.store.get(key).toString(), "RIFF....WAVE");

  const after = await takeStorage.getBucketStats();
  assert.deepEqual(after, { fileCount: before.fileCount + 1, totalSizeBytes: before.totalSizeBytes + bytes.length });
  assert.equal(takeStorage.defaultBucket(), BUCKET);
  for (const c of fake.calls) {
    assert.equal(["bucketExists", "listBuckets", "makeBucket"].includes(c[0]), false, "never " + c[0]);
  }
});