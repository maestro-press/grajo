/**
 * The BOT storage key — the one storage credential a contained bot's MCP child may hold.
 *
 * WHY: the instance's `storage.shared.*` settings are the instance-wide (on a MinIO install,
 * root-level) credential, and a sibling process in a bot's sandbox can read the child's
 * `/proc/<pid>/environ`. So the bot engine hydrates a storage-using block from a SEPARATE,
 * operator-provisioned, path-scoped key at `<CROW_HOME>/secrets/bot-storage.json` — outside
 * crow.db, which is bot-writable, and in the directory a bot sandbox is never bound — or it
 * gives the block no storage at all (fail closed: never the shared settings, never the env).
 *
 * What this suite pins:
 *   1. the reader: absent is its own reason; a group/world-readable file, a symlink, an oversized
 *      file, non-JSON and a missing endpoint/access_key/secret_key are each refused with a reason
 *      (and never a value); a valid file yields the six S3_* values plus the marker, and nothing
 *      else (the names match s3-client's, so the two cannot drift);
 *   2. the writer: a valid file hydrates every storage-using block from the FILE even when crow.db
 *      holds different shared settings, and a subprocess with an identity loader that THROWS if
 *      `servers/sharing/identity.js` is ever loaded still builds the config (so no bot block opens
 *      the shared settings or the identity);
 *   3. no key file -> storage off, marker 0, no S3_* name, the exact boot line;
 *   4. an unusable file -> storage off with the "could not be read: <reason>" boot line;
 *   5. a HYDRATED child (s3-client), against a fake MinIO that enforces the REAL scoped policy:
 *      availability is a non-recursive one-key list under `bots/` (never bucketExists/HeadBucket,
 *      never listBuckets, never makeBucket — MinIO refuses all three), every granted call works
 *      (upload, presigned upload URL, a listing under projects/, and getBucketStats, which sums
 *      only the four granted prefixes), an AccessDenied reads "storage refused this location",
 *      and the OWNER path is unchanged (listBuckets, makeBucket, the client's own error);
 *   6. the reader's directory check: a secrets dir that is not exactly 0700, or that is a symlink,
 *      is refused before the file is ever opened;
 *   7. the ops script: `set -euo pipefail`, the exact policy (multipart actions included),
 *      per-instance user/policy names, a second apply refused, an undo that never claims to have
 *      removed something absent, no secret ever printed, and a syntactically valid bash file.
 *
 * Scratch only: every path here is inside this test's temp dir.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, renameSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import { Readable } from "node:stream";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { randomUUID } from "node:crypto";

const REPO = resolve(new URL("..", import.meta.url).pathname);
const T = mkdtempSync(join(tmpdir(), "bot-storage-key-"));
after(() => { try { rmSync(T, { recursive: true, force: true }); } catch { /* best effort */ } });

const { readBotStorageKey, botStorageEnv, botStorageKeyPath, BOT_STORAGE_KEY_MISSING, BOT_STORAGE_ENV_NAMES, BOT_STORAGE_KEY_MAX_BYTES, BOT_STORAGE_FROM_HOST_ENV } =
  await import("../servers/shared/bot-storage-key.js");

const mk = (p) => { mkdirSync(p, { recursive: true }); return p; };
/**
 * The instance's secrets dir, at the mode the reader demands. mkdirSync's mode is masked by the
 * umask, so it is set explicitly: every fixture here must be a directory this user alone owns and
 * can alone write.
 */
function mkSecrets(home, mode = 0o700) {
  const dir = mk(join(home, "secrets"));
  chmodSync(dir, mode);
  return dir;
}
/** A crow home whose secrets dir holds `body` (or nothing), mode 0600 unless `mode` says other. */
function homeWith(body, { mode = 0o600, secretsMode = 0o700 } = {}) {
  const home = mk(join(T, "home-" + randomUUID()));
  mkSecrets(home, secretsMode);
  const path = botStorageKeyPath(home);
  writeFileSync(path, typeof body === "string" ? body : `${JSON.stringify(body, null, 2)}\n`);
  chmodSync(path, mode);
  return { home, path };
}
const KEY = Object.freeze({
  endpoint: "127.0.0.1:19999",
  use_ssl: false,
  region: "us-east-1",
  bucket_prefix: "fixture",
  access_key: "GKbotaccess00000000000",
  secret_key: "bot-secret-" + randomUUID(),
});

// ─── 1. the reader ─────────────────────────────────────────────────────────

test("no file: its own reason, and no config", () => {
  const home = mk(join(T, "empty-home"));
  mkSecrets(home);
  const r = readBotStorageKey({ crowHome: home });
  assert.deepEqual(r, { config: null, reason: BOT_STORAGE_KEY_MISSING });
  // No resolved home is a refusal too — never a guess at this box's real home.
  assert.equal(readBotStorageKey({}).reason, "no Crow home was resolved");
  assert.equal(readBotStorageKey({ crowHome: "" }).config, null);
  // A home with no secrets dir at all is the same normal state, not a fault.
  const bare = mk(join(T, "home-without-secrets-" + randomUUID()));
  assert.deepEqual(readBotStorageKey({ crowHome: bare }), { config: null, reason: BOT_STORAGE_KEY_MISSING });
});

/**
 * The DIRECTORY is judged before the file, and a directory someone loosened (or replaced with a
 * symlink) is a refusal — never repaired here. Two lookups, not a check-then-use gap: the dir is
 * lstat'ed, the file opened with O_NOFOLLOW, and every file check runs on that descriptor.
 */
test("the secrets dir is checked first: not 0700, a symlink, or a plain file is refused", () => {
  const loose = homeWith(KEY);
  chmodSync(join(loose.home, "secrets"), 0o755);
  const l = readBotStorageKey({ crowHome: loose.home });
  assert.equal(l.config, null);
  assert.match(l.reason, /secrets directory is not owner-only \(mode 755\)/);

  const linked = homeWith(KEY);
  const real = join(linked.home, "secrets-real");
  renameSync(join(linked.home, "secrets"), real);
  symlinkSync(real, join(linked.home, "secrets"));
  const s = readBotStorageKey({ crowHome: linked.home });
  assert.equal(s.config, null);
  assert.match(s.reason, /secrets directory is a symbolic link/);
  assert.equal(s.reason.includes(KEY.secret_key), false, "nothing from the file it points at is reported");

  const notADir = mk(join(T, "home-secrets-is-a-file-" + randomUUID()));
  writeFileSync(join(notADir, "secrets"), "not a directory\n");
  const n = readBotStorageKey({ crowHome: notADir });
  assert.equal(n.config, null);
  assert.match(n.reason, /secrets directory is not a directory/);
});

test("a valid file: the six values, the defaults, and no secret in the reason field", () => {
  const { home } = homeWith(KEY);
  const { config, reason } = readBotStorageKey({ crowHome: home });
  assert.equal(reason, null);
  assert.deepEqual(config, {
    endpoint: KEY.endpoint,
    useSSL: false,
    region: "us-east-1",
    bucketPrefix: "fixture",
    accessKey: KEY.access_key,
    secretKey: KEY.secret_key,
  });
  // The defaults the file is allowed to omit.
  const minimal = homeWith({ endpoint: "s3.internal:9000", access_key: "a", secret_key: "b" }).home;
  const m = readBotStorageKey({ crowHome: minimal }).config;
  assert.deepEqual([m.useSSL, m.region, m.bucketPrefix], [false, "us-east-1", "crow"]);
  // An endpoint written as a URL is reduced to host:port, the shape S3_ENDPOINT has always had.
  const url = homeWith({ ...KEY, endpoint: "https://s3.internal:9000/", use_ssl: true }).home;
  const u = readBotStorageKey({ crowHome: url }).config;
  assert.deepEqual([u.endpoint, u.useSSL], ["s3.internal:9000", true]);
});

test("an unsafe or broken file is refused with a reason, never a value", () => {
  const cases = [
    ["group/world readable", () => homeWith(KEY, { mode: 0o644 }), /readable by other users \(mode 644\)/],
    ["mode 0660", () => homeWith(KEY, { mode: 0o660 }), /readable by other users \(mode 660\)/],
    ["a symlink", () => {
      const { home, path } = homeWith(KEY);
      const target = join(home, "secrets", "elsewhere.json");
      writeFileSync(target, `${JSON.stringify(KEY)}\n`, { mode: 0o600 });
      chmodSync(target, 0o600);
      rmSync(path);
      symlinkSync(target, path);
      return { home, path };
    }, /symbolic link/],
    ["not JSON", () => homeWith("{not json"), /not valid JSON/],
    ["a JSON array", () => homeWith([]), /not a JSON object/],
    ["an oversized file", () => homeWith(`${JSON.stringify({ ...KEY, pad: "x".repeat(BOT_STORAGE_KEY_MAX_BYTES) })}\n`), /too large/],
    ["an empty file", () => homeWith(""), /empty/],
    ["no endpoint", () => homeWith({ ...KEY, endpoint: "" }), /no endpoint/],
    ["no access_key", () => homeWith({ ...KEY, access_key: "" }), /no access_key/],
    ["no secret_key", () => homeWith({ ...KEY, secret_key: undefined }), /no secret_key/],
    ["a non-boolean use_ssl", () => homeWith({ ...KEY, use_ssl: "yes" }), /use_ssl is not a boolean/],
    ["a bucket_prefix that is not a bucket name", () => homeWith({ ...KEY, bucket_prefix: "../files" }), /bucket_prefix/],
  ];
  for (const [why, build, pattern] of cases) {
    const { home } = build();
    const r = readBotStorageKey({ crowHome: home });
    assert.equal(r.config, null, why + ": no config");
    assert.match(r.reason, pattern, why + ": " + r.reason);
    assert.equal(r.reason.includes(KEY.secret_key), false, why + ": the reason never carries the secret");
  }
});

test("botStorageEnv: exactly the six S3_* names plus the marker — the same names s3-client uses", async () => {
  const env = botStorageEnv(readBotStorageKey({ crowHome: homeWith(KEY).home }).config);
  assert.deepEqual(Object.keys(env).sort(), [
    BOT_STORAGE_FROM_HOST_ENV, ...BOT_STORAGE_ENV_NAMES,
  ].sort());
  assert.deepEqual(env, {
    S3_ENDPOINT: KEY.endpoint,
    S3_USE_SSL: "false",
    S3_REGION: "us-east-1",
    S3_BUCKET_PREFIX: "fixture",
    S3_ACCESS_KEY: KEY.access_key,
    S3_SECRET_KEY: KEY.secret_key,
    CROW_STORAGE_FROM_HOST: "1",
  });
  // No drift with the storage client's own list: a name added on one side must fail here.
  const s3 = await import("../servers/storage/s3-client.js");
  assert.deepEqual([...BOT_STORAGE_ENV_NAMES].sort(), [...s3.STORAGE_SETTING_ENV_NAMES].sort());
  assert.equal(BOT_STORAGE_FROM_HOST_ENV, s3.STORAGE_FROM_HOST_ENV);
});

// ─── 2-4. the writer: the file decides, and nothing else is opened ──────────

/** A scratch bot world the writer can build a config in (no DB is opened by the writer). */
function botWorld({ withKey = true } = {}) {
  const root = mk(join(T, "world-" + randomUUID()));
  const home = join(root, "home", "alex");
  const crowHome = join(home, ".crow");
  mk(join(home, ".pi", "agent"));
  mk(join(crowHome, "data"));
  writeFileSync(join(home, ".pi", "agent", "mcp.json"), JSON.stringify({ mcpServers: {} }));
  const canonicalPath = join(root, "canonical.json");
  writeFileSync(canonicalPath, JSON.stringify({ mcpServers: {} }));
  const sessionDir = mk(join(root, "session"));
  if (withKey) {
    mkSecrets(crowHome);
    const path = botStorageKeyPath(crowHome);
    writeFileSync(path, `${JSON.stringify(KEY, null, 2)}\n`);
    chmodSync(path, 0o600);
  }
  return { root, home, crowHome, canonicalPath, sessionDir };
}

const DEF = { tools: { crow_mcp: ["crow-storage/tool"] } };
const isStorageShaped = (name) => /^(?:MINIO_|S3_)/.test(name);

const WRITER_DRIVER = `
import { writeFileSync } from "node:fs";
const [report, crowHome, canonicalPath, sessionDir] = process.argv.slice(2);
const W = await import(new URL("scripts/pi-bots/mcp_writer.mjs", "file://" + process.env.CROW_TEST_APP_ROOT + "/").href);
const res = W.writeBotMcp({ tools: { crow_mcp: ["crow-storage/tool"] } }, {
  sessionDir, canonicalPath, crowHome, write: false, addonKeys: "hydrate",
});
writeFileSync(report, JSON.stringify({ env: res.json.mcpServers["crow-storage"].env, note: res.sharedStorage && res.sharedStorage.note }));
process.exit(0);
`;

/**
 * A loader hook that THROWS when `servers/sharing/identity.js` is loaded — the strictest form of
 * "a bot block never reads the identity": if anything on the writer's path reached it, the build
 * would fail instead of quietly succeeding.
 */
const THROWING_HOOK = `
export async function load(url, context, next) {
  if (/\\/servers\\/sharing\\/identity\\.js$/.test(url)) throw new Error("BOT_STORAGE_TEST: the identity was loaded");
  return next(url, context);
}
`;
const THROWING_LOADER = `
import { register } from "node:module";
register(new URL("./hook.mjs", import.meta.url));
`;

/** Build a bot config in a subprocess whose identity module throws if it is ever loaded. */
function buildViaThrowingLoader(world) {
  const dir = mk(join(world.root, "spy"));
  writeFileSync(join(dir, "hook.mjs"), THROWING_HOOK);
  writeFileSync(join(dir, "load.mjs"), THROWING_LOADER);
  writeFileSync(join(dir, "driver.mjs"), WRITER_DRIVER);
  const report = join(dir, "report.json");
  const r = spawnSync(process.execPath, [
    "--import", join(dir, "load.mjs"), join(dir, "driver.mjs"),
    report, world.crowHome, world.canonicalPath, world.sessionDir,
  ], {
    cwd: REPO, encoding: "utf8", timeout: 120_000,
    env: {
      ...process.env,
      CROW_TEST_APP_ROOT: REPO,
      HOME: world.home,
      CROW_HOME: world.crowHome,
      CROW_DATA_DIR: join(world.crowHome, "data"),
      CROW_DB_PATH: join(world.crowHome, "data", "crow.db"),
    },
  });
  const out = existsSync(report) ? JSON.parse(readFileSync(report, "utf8")) : null;
  return { status: r.status, stderr: r.stderr || "", stdout: r.stdout || "", report: out };
}

test("the writer hydrates the six names from the FILE, with an identity loader that throws if called", () => {
  const world = botWorld();
  const r = buildViaThrowingLoader(world);
  assert.equal(r.status, 0, "the build never loaded the identity: " + r.stderr.slice(0, 1200));
  assert.ok(r.report, "the driver reported");
  for (const [name, value] of Object.entries(botStorageEnv(readBotStorageKey({ crowHome: world.crowHome }).config))) {
    assert.equal(r.report.env[name], value, name);
  }
  assert.deepEqual(Object.keys(r.report.env).filter(isStorageShaped).sort(), [...BOT_STORAGE_ENV_NAMES].sort(),
    "exactly the six S3_* names, from the key file");
  assert.equal(r.report.note, "shared storage: over fd");
  assert.equal(r.stderr.includes(KEY.secret_key), false, "the secret never reaches stderr");
});

test("the writer's shared settings are never opened: crow.db holds DIFFERENT values and they never board", async () => {
  const world = botWorld();
  // A crow.db with the instance's shared settings. Nothing on a bot's path may open it, so the
  // values are written plainly and are expected to stay in the file.
  const dbPath = join(world.crowHome, "data", "crow.db");
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    cwd: REPO, stdio: "pipe",
    env: { ...process.env, CROW_HOME: world.crowHome, CROW_DATA_DIR: join(world.crowHome, "data"), CROW_DB_PATH: dbPath },
  });
  const Database = (await import("better-sqlite3")).default;
  const sharedAccess = "shared-access-" + randomUUID();
  const sharedSecret = "shared-secret-" + randomUUID();
  const raw = new Database(dbPath);
  try {
    const put = raw.prepare("INSERT OR REPLACE INTO dashboard_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))");
    put.run("storage.shared.endpoint", "127.0.0.1:19998");
    put.run("storage.shared.bucket_prefix", "instancewide");
    put.run("storage.shared.access_key", sharedAccess);
    put.run("storage.shared.secret_key", sharedSecret);
  } finally { raw.close(); }
  const r = buildViaThrowingLoader(world);
  assert.equal(r.status, 0, r.stderr.slice(0, 1200));
  assert.equal(r.report.env.S3_ACCESS_KEY, KEY.access_key, "the bot's own key");
  assert.equal(r.report.env.S3_SECRET_KEY, KEY.secret_key);
  assert.equal(r.report.env.S3_BUCKET_PREFIX, "fixture");
  assert.equal(JSON.stringify(r.report).includes(sharedSecret), false, "the shared credential is nowhere");
  assert.equal(JSON.stringify(r.report).includes(sharedAccess), false);
});

test("no key file: storage off, marker 0, no S3_* name, and the exact boot line", () => {
  const world = botWorld({ withKey: false });
  const r = buildViaThrowingLoader(world);
  assert.equal(r.status, 0, r.stderr.slice(0, 1200));
  assert.equal(r.report.env.CROW_STORAGE_FROM_HOST, "0");
  for (const name of Object.keys(r.report.env)) assert.equal(isStorageShaped(name), false, "not " + name);
  assert.equal(r.report.note, "shared storage: off (no bot storage key on this instance)");
});

test("an unusable key file: storage off with the 'could not be read' boot line and its reason", () => {
  for (const [why, breakIt, pattern] of [
    ["mode 0644", (path) => chmodSync(path, 0o644), /could not be read: it is readable by other users \(mode 644\)/],
    ["a missing secret_key", (path) => {
      writeFileSync(path, `${JSON.stringify({ ...KEY, secret_key: undefined })}\n`);
      chmodSync(path, 0o600);
    }, /could not be read: it has no secret_key/],
  ]) {
    const world = botWorld();
    const path = botStorageKeyPath(world.crowHome);
    breakIt(path);
    const r = buildViaThrowingLoader(world);
    assert.equal(r.status, 0, why + ": " + r.stderr.slice(0, 1200));
    assert.equal(r.report.env.CROW_STORAGE_FROM_HOST, "0", why);
    for (const name of Object.keys(r.report.env)) assert.equal(isStorageShaped(name), false, why + ": not " + name);
    assert.match(r.report.note, /^shared storage: off \(the bot storage key file could not be read: /, why + ": " + r.report.note);
    assert.match(r.report.note, pattern, why + ": " + r.report.note);
  }
});

// ─── 5. the hydrated child: only the calls its scoped key is granted ───────

/** The four prefixes the operator's policy grants a bot's key (scripts/ops/minio-bot-storage.sh). */
const GRANTED_PREFIXES = ["projects/", "bots/", "studio/", "sunvox-studio/"];

/**
 * A fake MinIO that ENFORCES the scoped policy the way a real MinIO does, because that is how the
 * round-A behaviour was found to be unusable:
 *   - `bucketExists` (HeadBucket) is REFUSED: MinIO evaluates it as s3:ListBucket with NO prefix,
 *     so the policy's s3:prefix condition fails on a perfectly healthy backend;
 *   - `listBuckets` and `makeBucket` are not granted at all;
 *   - any listing (and any object operation) whose prefix does not start with one of the four
 *     granted prefixes is refused, so an empty-prefix listing of the bucket root cannot pass.
 * Every refusal is AccessDenied-shaped (`code: "AccessDenied"`, `statusCode: 403`).
 */
function fakeMinio({ objects = [], denyAll = false } = {}) {
  const store = new Map(objects.map(([k, v]) => [k, Buffer.from(String(v))]));
  const calls = [];
  const denied = (what) => Object.assign(new Error(`Access Denied (${what})`), { code: "AccessDenied", statusCode: 403 });
  const grantedPrefix = (prefix) => {
    if (denyAll) return null;
    const p = String(prefix ?? "");
    return GRANTED_PREFIXES.some((a) => p.startsWith(a)) ? p : null;
  };
  const grantedKey = (key) => !denyAll && GRANTED_PREFIXES.some((a) => String(key).startsWith(a));
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
    async putObject(bucket, key, data) {
      calls.push(["putObject", bucket, key]);
      if (!grantedKey(key)) throw denied(`PutObject ${key}`);
      store.set(key, Buffer.isBuffer(data) ? data : Buffer.from(String(data)));
      return { etag: "etag", versionId: null };
    },
    async removeObject(bucket, key) {
      calls.push(["removeObject", bucket, key]);
      if (!grantedKey(key)) throw denied(`DeleteObject ${key}`);
    },
    async presignedPutObject(bucket, key, expiry) {
      calls.push(["presignedPutObject", bucket, key, expiry]);
      return `http://minio.invalid/${bucket}/${key}?sig=put`;
    },
    async presignedGetObject(bucket, key, expiry) {
      calls.push(["presignedGetObject", bucket, key, expiry]);
      return `http://minio.invalid/${bucket}/${key}?sig=get`;
    },
    async statObject(bucket, key) {
      calls.push(["statObject", bucket, key]);
      if (!grantedKey(key)) throw denied(`Head ${key}`);
      return { size: (store.get(key) || Buffer.alloc(0)).length };
    },
    async getObject(bucket, key) {
      calls.push(["getObject", bucket, key]);
      if (!grantedKey(key)) throw denied(`GetObject ${key}`);
      return Readable.from([store.get(key) || Buffer.alloc(0)]);
    },
  };
}

const HYDRATED_ENV = {
  CROW_STORAGE_FROM_HOST: "1",
  S3_ENDPOINT: "127.0.0.1:19999",
  S3_USE_SSL: "false",
  S3_REGION: "us-east-1",
  S3_BUCKET_PREFIX: "fx",
  S3_ACCESS_KEY: "bot-access",
  S3_SECRET_KEY: "bot-secret",
};

test("hydrated: availability is ONE key under bots/ — never HeadBucket, listBuckets or makeBucket", async () => {
  const s3 = await import("../servers/storage/s3-client.js");
  assert.equal(s3.adoptHostStorage(HYDRATED_ENV), "hydrated");
  assert.equal(s3.isHydratedBotStorage(), true);
  assert.deepEqual([...s3.BOT_STORAGE_PREFIXES], GRANTED_PREFIXES, "the four prefixes the policy grants");

  // Nothing uploaded yet: an empty listing is a HEALTHY backend (a fresh instance must not read as
  // "storage unavailable" just because nobody has uploaded anything).
  const empty = fakeMinio();
  s3._setClientForTest(empty);
  assert.equal(await s3.isAvailable(), true);
  assert.deepEqual(empty.calls, [["listObjectsV2Query", "fx-files", "bots/", 1]],
    "one non-recursive list of one key under an allowed prefix, and nothing else");

  const full = fakeMinio({ objects: [["bots/b1/1-a.txt", "x"]] });
  s3._setClientForTest(full);
  assert.equal(await s3.isAvailable(), true);
  for (const c of [...empty.calls, ...full.calls]) {
    assert.equal(["bucketExists", "listBuckets", "makeBucket"].includes(c[0]), false, "never " + c[0]);
  }
});

test("hydrated: an AccessDenied on the probe reads 'storage refused this location'", async () => {
  const s3 = await import("../servers/storage/s3-client.js");
  s3.adoptHostStorage(HYDRATED_ENV);
  s3._setClientForTest(fakeMinio({ denyAll: true }));
  await assert.rejects(() => s3.isAvailable(), (err) => {
    assert.equal(err.message, "storage refused this location");
    assert.equal(err.code, "STORAGE_REFUSED_LOCATION");
    return true;
  });
});

test("hydrated: upload, presigned upload URL, a projects/ listing and getBucketStats all work", async () => {
  const s3 = await import("../servers/storage/s3-client.js");
  s3.adoptHostStorage(HYDRATED_ENV);
  const fake = fakeMinio({
    objects: [
      ["projects/p-1/a.txt", "abc"],
      ["bots/b1/c.txt", "abcde"],
      ["studio/s1/takes/t.wav", "abcdefg"],
      ["sunvox-studio/renders/r.mp3", "abcdefghijk"],
      // NOT granted to a bot's key: counted by no hydrated stat, and never listed by the sum.
      ["elsewhere/y.txt", "abcdefghijklm"],
    ],
  });
  s3._setClientForTest(fake);

  await s3.uploadObject("projects/p-1/new.txt", Buffer.from("12345"), { contentType: "text/plain" });
  assert.ok(fake.calls.some((c) => c[0] === "putObject" && c[2] === "projects/p-1/new.txt"));

  const putUrl = await s3.getPresignedUploadUrl("projects/p-1/direct.txt");
  assert.match(putUrl, /^http:\/\/minio\.invalid\/fx-files\/projects\/p-1\/direct\.txt/);

  const listed = await s3.listObjects({ prefix: "projects/" });
  assert.deepEqual(listed.map((o) => o.name), ["projects/p-1/a.txt", "projects/p-1/new.txt"]);

  // The quota check: the four granted prefixes, summed — never the bucket root, which the policy
  // refuses (and which used to make every upload's quota check fail).
  const stats = await s3.getBucketStats();
  assert.deepEqual(stats, { fileCount: 5, totalSizeBytes: 3 + 5 + 7 + 11 + 5 });
  const listPrefixes = fake.calls.filter((c) => c[0] === "listObjectsV2" || c[0] === "listObjectsV2Query")
    .map((c) => c[2]);
  for (const p of listPrefixes) {
    assert.equal(GRANTED_PREFIXES.some((a) => p.startsWith(a)), true, "only granted prefixes are listed: " + JSON.stringify(p));
  }
});

test("hydrated: an AccessDenied on a granted call still reads 'storage refused this location'", async () => {
  const s3 = await import("../servers/storage/s3-client.js");
  s3.adoptHostStorage(HYDRATED_ENV);
  s3._setClientForTest(fakeMinio({ denyAll: true }));
  await assert.rejects(() => s3.uploadObject("studio/takes/1-a.wav", Buffer.from("x")), (err) => {
    assert.equal(err.message, "storage refused this location");
    assert.equal(err.code, "STORAGE_REFUSED_LOCATION");
    return true;
  });
  assert.equal(s3.STORAGE_REFUSED_LOCATION, "storage refused this location");
});

test("the OWNER path is unchanged: listBuckets, a bucket it may create, the whole-bucket stat, its own error", async () => {
  const s3 = await import("../servers/storage/s3-client.js");
  // No marker: the owner's own spawn (the gateway, ~/.pi/agent config).
  s3.useStorageConfig({ endpoint: "127.0.0.1:19999", host: "127.0.0.1", port: 19999, useSSL: false, region: "us-east-1", bucketPrefix: "fx", accessKey: "a", secretKey: "b" });
  assert.equal(s3.isHydratedBotStorage(), false);
  const stub = {
    calls: [],
    async listBuckets() { this.calls.push(["listBuckets"]); return []; },
    async bucketExists(bucket) { this.calls.push(["bucketExists", bucket]); return false; },
    async makeBucket(bucket) { this.calls.push(["makeBucket", bucket]); return true; },
    listObjectsV2(bucket, prefix) { this.calls.push(["listObjectsV2", bucket, prefix]); return Readable.from([{ name: "root.txt", size: 4 }]); },
    async putObject(bucket, key) { this.calls.push(["putObject", bucket, key]); throw Object.assign(new Error("Access Denied"), { code: "AccessDenied", statusCode: 403 }); },
  };
  s3._setClientForTest(stub);
  assert.equal(await s3.isAvailable(), true, "the owner probe is still the bucket listing");
  assert.ok(stub.calls.some((c) => c[0] === "listBuckets"));
  await s3.ensureBucket();
  assert.ok(stub.calls.some((c) => c[0] === "makeBucket" && c[1] === "fx-files"), "the owner may create the bucket");
  // The owner's stat is still ONE whole-bucket listing (the empty prefix), unchanged.
  assert.deepEqual(await s3.getBucketStats(), { fileCount: 1, totalSizeBytes: 4 });
  assert.ok(stub.calls.some((c) => c[0] === "listObjectsV2" && c[2] === ""), "one listing of the whole bucket");
  // A refusal keeps the client's error on the owner's path (no rewriting).
  await assert.rejects(() => s3.uploadObject("1-a.txt", Buffer.from("x")), /Access Denied/);
  s3._setClientForTest(null);
  s3.useStorageConfig(null);
});

// ─── 6. the ops script ─────────────────────────────────────────────────────

const SCRIPT = join(REPO, "scripts", "ops", "minio-bot-storage.sh");

test("minio-bot-storage.sh: valid bash, set -euo pipefail, the exact policy, and no secret ever printed", () => {
  // An ops script an operator cannot run is a broken ops script (git records the mode).
  assert.equal(statSync(SCRIPT).mode & 0o111, 0o111, "the script is executable");
  execFileSync("bash", ["-n", SCRIPT], { stdio: "pipe" });
  const src = readFileSync(SCRIPT, "utf8");
  assert.match(src, /^set -euo pipefail$/m);
  for (const verb of ["apply", "undo", "show"]) assert.match(src, new RegExp(`\\b${verb}\\)`), verb + " is a subcommand");
  // The policy: exactly the four statements, the four writable prefixes, the conditioned ListBucket
  // and GetBucketLocation. Nothing else is allowed.
  for (const needle of [
    "arn:aws:s3:::${prefix}-files/projects/*",
    "arn:aws:s3:::${prefix}-files/bots/*",
    "arn:aws:s3:::${prefix}-files/studio/*",
    "arn:aws:s3:::${prefix}-files/sunvox-studio/*",
    '"s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"',
    '"s3:ListBucket"',
    '"s3:ListBucketMultipartUploads"',
    '"s3:GetBucketLocation"',
    "StringLike",
  ]) assert.ok(src.includes(needle), "the policy names " + needle);
  assert.equal((src.match(/"Effect": "Allow"/g) || []).length, 4, "four statements, nothing else");
  assert.equal((src.match(/"Action"/g) || []).length, 4);
  // The multipart listing is UNCONDITIONED: MinIO refuses this policy when s3:prefix is attached to
  // ListBucketMultipartUploads, and minio-js needs the action for an upload over 64 MiB. ListBucket
  // itself stays conditioned on the four prefixes, so the bucket root remains unlistable.
  const heredoc = /cat <<JSON\n([\s\S]*?)\nJSON\n/.exec(src);
  assert.ok(heredoc, "policy_json writes the policy as a JSON heredoc");
  const policy = JSON.parse(heredoc[1].replace(/\$\{prefix\}/g, "crow"));
  assert.equal(policy.Statement.length, 4, "four statements");
  const actionsOf = (s) => (Array.isArray(s.Action) ? s.Action : [s.Action]);
  const multipartList = policy.Statement.filter((s) => actionsOf(s).includes("s3:ListBucketMultipartUploads"));
  assert.equal(multipartList.length, 1, "exactly one statement carries the multipart listing");
  assert.deepEqual(multipartList[0], {
    Effect: "Allow",
    Action: ["s3:ListBucketMultipartUploads"],
    Resource: ["arn:aws:s3:::crow-files"],
  }, "that statement is Allow + the bucket resource, with NO Condition");
  assert.equal("Condition" in multipartList[0], false, "no Condition: MinIO rejects s3:prefix on ListBucketMultipartUploads");
  const listBucket = policy.Statement.filter((s) => actionsOf(s).includes("s3:ListBucket"));
  assert.equal(listBucket.length, 1, "exactly one statement carries ListBucket");
  assert.deepEqual(actionsOf(listBucket[0]), ["s3:ListBucket"], "ListBucket is not paired with the multipart listing");
  assert.deepEqual(listBucket[0].Condition.StringLike["s3:prefix"].slice(0, 4),
    ["projects/*", "bots/*", "studio/*", "sunvox-studio/*"], "the object prefixes stay prefix-limited");
  // PER-INSTANCE names: the tag hashes the host name and the crow home's REAL path (a directory
  // basename is not unique — every default install is ~/.crow), and the policy name carries the
  // user name.
  assert.match(src, /sha256sum|shasum|openssl dgst -sha256/);
  assert.match(src, /realpath/);
  assert.equal(src.includes("short_tag"), false, "the basename-derived tag is gone");
  assert.match(src, /-bot-%s/, "the user name is <prefix>-bot-<tag>");
  assert.match(src, /policy_name\(\)/);
  // A second apply refuses — the existing user/policy, and the key file.
  assert.match(src, /admin user info/);
  assert.match(src, /admin policy info/);
  assert.match(src, /MinIO user \$user already exists/);
  assert.match(src, /MinIO policy \$policy already exists/);
  assert.match(src, /run 'undo' first/, "a second apply refuses and names undo");
  // undo reports what it did, and never claims to have removed something absent.
  assert.match(src, /absent — nothing to remove/);
  assert.match(src, /if "\$MC" admin user remove "\$alias" "\$user"/, "the 'removed' line follows mc's own success");
  // The secret is generated locally, never printed, and the file is written 0600 + renamed.
  assert.match(src, /openssl rand -hex 20/);
  assert.match(src, /\/dev\/urandom/);
  assert.equal(/say[^\n]*\$\{?secret/.test(src), false, "the secret is never printed");
  assert.equal(/echo[^\n]*\$\{?secret/.test(src), false, "the secret is never echoed");
  assert.match(src, /umask 077/);
  assert.match(src, /chmod 600 "\$tmp"/);
  assert.match(src, /mv -f "\$tmp" "\$key_file"/);
  assert.match(src, /mc admin policy create|"\$MC" admin policy create/);
  assert.match(src, /"\$MC" admin policy attach/);
  assert.match(src, /"\$MC" admin user add/);
});

/** A stand-in `mc` on PATH: absent answers every query "not there"; present claims user + policy. */
function fakeMc(name, { present = false } = {}) {
  const bin = mk(join(T, "bin-" + name));
  const path = join(bin, "mc");
  writeFileSync(path, present
    ? "#!/bin/sh\ncase \"$*\" in *'user info'*) echo '{\"accessKey\":\"x\"}'; exit 0;; *'policy info'*) echo '{}'; exit 0;; esac\nexit 1\n"
    : "#!/bin/sh\nexit 1\n");
  chmodSync(path, 0o755);
  return path;
}

test("minio-bot-storage.sh: two crow homes on one host never share a MinIO user or policy", () => {
  const mc = fakeMc("absent");
  const a = mk(join(T, "instance-a", ".crow"));
  const b = mk(join(T, "instance-b", ".crow"));
  const show = (home) => execFileSync(SCRIPT, ["show", "minio", home], {
    encoding: "utf8", env: { ...process.env, MC: mc },
  });
  const outA = show(a);
  const outB = show(b);
  const userOf = (out) => /^user:\s+(\S+)$/m.exec(out)[1];
  const policyOf = (out) => /^policy:\s+(\S+)$/m.exec(out)[1];
  assert.match(userOf(outA), /^crow-bot-[0-9a-f]{12}$/, "a 12-hex tag from <host name>:<real crow home>");
  assert.notEqual(userOf(outA), userOf(outB), "two crow homes, two MinIO users (the old basename tag collided)");
  assert.equal(policyOf(outA), `${userOf(outA)}-policy`, "the policy is the user's own");
  assert.match(outA, /exists: no/, "an mc that knows nothing reports both as absent");
  assert.match(outA, /bucket: crow-files/, "the bucket is still reported");
  // The report names this instance only: no other home's path is printed.
  assert.equal(outA.includes(join(T, "instance-b")), false);
  assert.equal(outA.includes(".crow"), true, "the derivation's input is shown as a basename");
});

test("minio-bot-storage.sh: apply refuses when this instance's user already exists, and writes nothing", () => {
  const mc = fakeMc("present", { present: true });
  const home = mk(join(T, "instance-existing", ".crow"));
  const r = spawnSync(SCRIPT, ["apply", "minio", home], { encoding: "utf8", env: { ...process.env, MC: mc } });
  assert.notEqual(r.status, 0, "apply refuses");
  assert.match(r.stderr, /already exists — run 'undo' first/);
  assert.equal(existsSync(join(home, "secrets", "bot-storage.json")), false, "no key file was written");
  assert.equal(existsSync(join(home, "secrets")), false, "nothing was created in the crow home at all");
});

test("minio-bot-storage.sh: undo is idempotent and never claims to remove what was absent", () => {
  const mc = fakeMc("absent2");
  const home = mk(join(T, "instance-absent", ".crow"));
  const run = () => execFileSync(SCRIPT, ["undo", "minio", home], { encoding: "utf8", env: { ...process.env, MC: mc } });
  for (const out of [run(), run()]) {
    assert.equal(/removed/.test(out), false, "nothing was there, so nothing was removed: " + out);
    assert.equal((out.match(/\(absent — nothing to remove\)/g) || []).length, 3, out);
  }
});