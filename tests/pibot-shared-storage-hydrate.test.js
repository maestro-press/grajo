/**
 * Shared Storage over the fd pipe — from the BOT's own key, never the instance's.
 *
 * A bot's MCP children cannot read this instance's identity, and they must not hold this
 * instance's storage credential either: `storage.shared.*` is the instance-wide (on a MinIO
 * install, root-level) key and a sibling process in the sandbox can read a child's
 * `/proc/<pid>/environ`. So the bot engine (host side) reads the instance's BOT storage key
 * (`<CROW_HOME>/secrets/bot-storage.json`, provisioned by scripts/ops/minio-bot-storage.sh,
 * outside crow.db, scoped to projects/*, bots/*, studio/*, sunvox-studio/*) and pipes ONLY the
 * opened values into the block's env — endpoint, region, prefix, access key, secret key, plus
 * CROW_STORAGE_FROM_HOST=1. Never the shared settings, never the seed, never the
 * "crow-secret-box-v1" seal key. With no key the block is storage-OFF, never the env fallback.
 *
 * What this suite pins:
 *   1. the writer hydrates exactly the six S3_* names + the marker (nothing else), and never
 *      writes that config to disk;
 *   1b. NO bot block carries a storage credential from this instance's environment — not the
 *      values, not even the names. A repo-style .env (CROW_APP_ENV_PATH) with MINIO_* and S3_*
 *      is planted for that check, in BOTH delivery modes, for the storage users AND for an
 *      add-on whose own entry lists MINIO_*;
 *   2. a file-delivery turn carries NO credentials: the block gets the marker with no settings
 *      and one warning per storage-using server, so the child runs with no shared storage at
 *      all instead of silently falling back to a localhost MinIO where nothing listens;
 *   3. a validate-only turn opens nothing and reports the names it owes (like needsKeys);
 *   3b. there is NO env fallback and NO shared-settings fallback for a bot: no key file gets
 *      storage OFF with one warning, a key file that cannot be used gets storage OFF with a
 *      DIFFERENT warning and its reason, and crow.db holding different shared settings
 *      changes nothing;
 *   4. the per-bot boot line's states;
 *   5. every storage-using child (crow-storage, studio, sunvox-studio, data-dashboard, and the
 *      artifacts bundle's blob backend) adopts the piped values with CROW_STORAGE_FROM_HOST=1
 *      and never loads identity.js at all (an ESM loader spy, plus a positive control so the spy
 *      cannot pass by doing nothing);
 *   6. the same children with the marker off have NO storage (getClient() null), even with a
 *      localhost S3_ENDPOINT in their env;
 *   7. a block that declares no `needs` still carries the marker off (an undeclared consumer must
 *      never take the owner path inside a bot), and the writer's module reaches neither the
 *      shared settings nor the identity at all;
 *   8. the OWNER path of sunvox-studio and data-dashboard retries a failed settings read on a
 *      later call (short backoff) and caches a success;
 *   9. a manifest `needs: ["shared-storage"]` is a REQUEST, not a grant: the bundle id must also
 *      be on the reviewed, code-held allow-list (STORAGE_ENV_CONSUMERS), so an add-on from the
 *      store that declares the need gets NO credentials (fd and file alike), the marker 0 and
 *      one warning naming it — while the allow-listed four keep hydrating exactly as before.
 *
 * The bot key file's own checks and the hydrated child's scoped behaviour (bucketExists, never
 * listBuckets/makeBucket, an AccessDenied sentence) are tests/bot-storage-key.test.js.
 *
 * Scratch only: $HOME, CROW_HOME, CROW_DATA_DIR and CROW_DB_PATH all point into one temp dir,
 * set before the bot engine's modules are imported (identity.js pins its data dir at load).
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync, spawnSync } from "node:child_process";
import { chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, rmSync, symlinkSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { randomUUID } from "node:crypto";
import Database from "better-sqlite3";

const REPO = resolve(new URL("..", import.meta.url).pathname);

// ── the scratch instance (before any engine import) ────────────────────────
const T = mkdtempSync(join(tmpdir(), "pibot-storage-hydrate-"));
function mkdir(p) { mkdirSync(p, { recursive: true }); return p; }

const HOMEDIR = join(T, "home", "alice");
const CROW_HOME = join(HOMEDIR, ".crow");
const DATA = join(CROW_HOME, "data");
const DB_PATH = join(DATA, "crow.db");
mkdir(DATA);
mkdir(join(HOMEDIR, ".pi", "agent"));
writeFileSync(join(HOMEDIR, ".pi", "agent", "mcp.json"), JSON.stringify({ mcpServers: {} }));

process.env.HOME = HOMEDIR;
process.env.CROW_HOME = CROW_HOME;
process.env.CROW_DATA_DIR = DATA;
process.env.CROW_DB_PATH = DB_PATH;
process.env.CROW_APP_ROOT = REPO;
delete process.env.S3_ENDPOINT;
delete process.env.MINIO_ENDPOINT;

// A plaintext-seed fixture identity (the shape loadIdentityIfPresent accepts), and the
// real schema, because the crow-storage child's own entry verifies the DB before it runs.
const SEED_HEX = "5a".repeat(32);
writeFileSync(join(DATA, "identity.json"), JSON.stringify({ version: 1, seed: SEED_HEX, crowId: "crow:fixture" }));
execFileSync(process.execPath, ["scripts/init-db.js"], {
  cwd: REPO, stdio: "pipe",
  env: { ...process.env, CROW_HOME, CROW_DATA_DIR: DATA, CROW_DB_PATH: DB_PATH },
});

const { loadIdentityIfPresent } = await import("../servers/sharing/identity.js");
const { sealSecret } = await import("../servers/sharing/secret-box.js");
const identity = loadIdentityIfPresent();
const ENGINE_PLAINTEXT = {
  endpoint: "127.0.0.1:19999",
  access: "GK" + randomUUID().replace(/-/g, ""),
  secret: "sec-" + randomUUID(),
  prefix: "fixture",
};
const ENGINE_SEED_HEX = Buffer.from(identity.seed).toString("hex");

/** Write the six storage.shared.* rows into the fixture instance's dashboard_settings. */
function seedStorageSettings({ clear = false, seed = true } = {}) {
  const raw = new Database(DB_PATH);
  try {
    const cols = raw.prepare("PRAGMA table_info(dashboard_settings)").all().map((c) => c.name);
    if (clear) raw.prepare("DELETE FROM dashboard_settings WHERE key LIKE 'storage.shared.%'").run();
    if (!seed) return;
    if (!cols.includes("key") || !cols.includes("value")) return; // nothing to seed into
    const names = ["key", "value", ...(cols.includes("updated_at") ? ["updated_at"] : [])];
    const values = ["?", "?", ...(cols.includes("updated_at") ? ["datetime('now')"] : [])];
    const put = raw.prepare(`INSERT OR REPLACE INTO dashboard_settings (${names.join(", ")}) VALUES (${values.join(", ")})`);
    const rows = [
      ["storage.shared.endpoint", ENGINE_PLAINTEXT.endpoint],
      ["storage.shared.use_ssl", "false"],
      ["storage.shared.region", "us-east-1"],
      ["storage.shared.bucket_prefix", ENGINE_PLAINTEXT.prefix],
      ["storage.shared.access_key", sealSecret(ENGINE_PLAINTEXT.access, identity)],
      ["storage.shared.secret_key", sealSecret(ENGINE_PLAINTEXT.secret, identity)],
    ];
    for (const row of rows) put.run(...row);
  } finally { raw.close(); }
}
seedStorageSettings();

/**
 * The BOT storage key the bridge reads: `<CROW_HOME>/secrets/bot-storage.json`, written 0600.
 *
 * This is the ONLY storage credential a bot block may hold, and it is its own key — not the six
 * `storage.shared.*` rows above (those are the instance-wide credential). The fixture deliberately
 * starts from the SAME values, so the assertions about "exactly the six S3_* names" stay
 * meaningful while the SOURCE is unmistakably the file: the tests that matter plant DIFFERENT
 * shared settings and check that the file's values are what boards the block.
 */
function writeBotKey(overrides = {}) {
  const dir = join(CROW_HOME, "secrets");
  mkdir(dir);
  // The reader demands a REAL directory this user alone owns at mode 0700 exactly (never repaired
  // for us), so the fixture sets it explicitly: mkdir's mode is masked by the umask.
  chmodSync(dir, 0o700);
  const path = join(dir, "bot-storage.json");
  rmSync(path, { force: true }); // never write THROUGH a leftover symlink
  const body = {
    endpoint: ENGINE_PLAINTEXT.endpoint,
    use_ssl: false,
    region: "us-east-1",
    bucket_prefix: ENGINE_PLAINTEXT.prefix,
    access_key: ENGINE_PLAINTEXT.access,
    secret_key: ENGINE_PLAINTEXT.secret,
    ...overrides,
  };
  writeFileSync(path, `${JSON.stringify(body, null, 2)}\n`);
  chmodSync(path, 0o600);
  return path;
}
const BOT_KEY_PATH = () => join(CROW_HOME, "secrets", "bot-storage.json");
const removeBotKey = () => rmSync(BOT_KEY_PATH(), { force: true });
writeBotKey();

// The storage-using servers a bot may select: the core one (registry `needs`) and the three
// bundles whose manifests declare `needs: ["shared-storage"]`.
/** The core storage server is absent (not erroring) for a bot with no usable storage. */
function assertCoreStorageAbsent(res) {
  assert.deepEqual(res.json.mcpServers["crow-storage"], { disabled: true }, "crow-storage block is dropped");
  assert.equal(res.servers.includes("crow-storage"), false);
  assert.ok(res.disabled.includes("crow-storage"));
}
const STORAGE_SERVERS = ["crow-storage", "studio", "sunvox-studio", "data-dashboard"];
const ADDON_ENTRY = { command: "node", args: ["server/index.js"] };
mkdir(join(CROW_HOME, "bundles"));
for (const id of ["studio", "sunvox-studio", "data-dashboard"]) {
  const src = JSON.parse(readFileSync(join(REPO, "bundles", id, "manifest.json"), "utf8"));
  mkdir(join(CROW_HOME, "bundles", id, "server"));
  writeFileSync(join(CROW_HOME, "bundles", id, "manifest.json"), JSON.stringify(src));
  writeFileSync(join(CROW_HOME, "bundles", id, "server", "index.js"), "// fixture\n");
}
// A fourth add-on that declares nothing: the hydration must not touch it.
mkdir(join(CROW_HOME, "bundles", "plain-addon", "server"));
writeFileSync(join(CROW_HOME, "bundles", "plain-addon", "manifest.json"), JSON.stringify({ id: "plain-addon", name: "Plain", version: "1.0.0", type: "mcp-server", category: "misc", description: "d", server: ADDON_ENTRY }));
writeFileSync(join(CROW_HOME, "bundles", "plain-addon", "server", "index.js"), "// fixture\n");
// A sixth whose OWN entry lists MINIO_* credentials: a bot block must never board those either.
mkdir(join(CROW_HOME, "bundles", "env-addon", "server"));
writeFileSync(join(CROW_HOME, "bundles", "env-addon", "manifest.json"), JSON.stringify({ id: "env-addon", name: "Env", version: "1.0.0", type: "mcp-server", category: "misc", description: "d", server: ADDON_ENTRY }));
writeFileSync(join(CROW_HOME, "bundles", "env-addon", "server", "index.js"), "// fixture\n");
const ADDON_MINIO_USER = "addon-root-user" + randomUUID();
const ADDON_MINIO_PASSWORD = "addon-root-password" + randomUUID();
// A sixth: a THIRD-PARTY add-on whose installed manifest asks for shared storage, but whose id
// is not on the reviewed allow-list (STORAGE_ENV_CONSUMERS in servers/gateway/addon-env.js). The
// declaration must buy it nothing: no credentials, marker 0, one warning naming it.
const UNREVIEWED_STORAGE_ADDON = "thirdparty-storage";
mkdir(join(CROW_HOME, "bundles", UNREVIEWED_STORAGE_ADDON, "server"));
writeFileSync(join(CROW_HOME, "bundles", UNREVIEWED_STORAGE_ADDON, "manifest.json"), JSON.stringify({
  id: UNREVIEWED_STORAGE_ADDON, name: "Third Party", version: "1.0.0", type: "mcp-server", category: "misc",
  description: "d", server: ADDON_ENTRY, needs: ["shared-storage"],
}));
writeFileSync(join(CROW_HOME, "bundles", UNREVIEWED_STORAGE_ADDON, "server", "index.js"), "// fixture\n");
writeFileSync(join(CROW_HOME, "mcp-addons.json"), JSON.stringify({
  studio: { ...ADDON_ENTRY, env: { STUDIO_MAX_TAKE_SECONDS: "120" } },
  "sunvox-studio": { ...ADDON_ENTRY },
  "data-dashboard": { ...ADDON_ENTRY, cwd: join(CROW_HOME, "bundles", "data-dashboard") },
  "plain-addon": { ...ADDON_ENTRY, env: { PLAIN_SETTING: "on" } },
  "env-addon": { ...ADDON_ENTRY, env: { MINIO_ROOT_USER: ADDON_MINIO_USER, MINIO_ROOT_PASSWORD: ADDON_MINIO_PASSWORD, MINIO_ENDPOINT: "127.0.0.1:9000", PLAIN_SETTING: "on" } },
  [UNREVIEWED_STORAGE_ADDON]: { ...ADDON_ENTRY },
}));

/**
 * A repo-style .env (the file scripts/server-registry.js's loadEnv reads, at CROW_APP_ENV_PATH)
 * that sets the MINIO_* and S3_* names the core block's `mcpEnv` template resolves. On a MinIO
 * install these ARE the instance's root credential, and they must never board a bot config —
 * not the values, not even the names.
 */
const ENV_ROOT_USER = "env-root-user" + randomUUID();
const ENV_ROOT_PASSWORD = "env-root-password" + randomUUID();
const ENV_S3_ACCESS = "env-access" + randomUUID();
const ENV_S3_SECRET = "env-secret" + randomUUID();
const REPO_ENV_PATH = join(T, "repo.env");
writeFileSync(REPO_ENV_PATH, [
  "MINIO_ENDPOINT=127.0.0.1:19000",
  "MINIO_PORT=9000",
  "MINIO_USE_SSL=false",
  `MINIO_ROOT_USER=${ENV_ROOT_USER}`,
  `MINIO_ROOT_PASSWORD=${ENV_ROOT_PASSWORD}`,
  "S3_ENDPOINT=127.0.0.1:19000",
  "S3_USE_SSL=false",
  "S3_REGION=garage",
  "S3_BUCKET_PREFIX=envprefix",
  `S3_ACCESS_KEY=${ENV_S3_ACCESS}`,
  `S3_SECRET_KEY=${ENV_S3_SECRET}`,
  "",
].join("\n"));

/** Run `fn` with the repo .env source pointing at the credential-bearing fixture. */
function withRepoEnv(fn) {
  const prev = process.env.CROW_APP_ENV_PATH;
  process.env.CROW_APP_ENV_PATH = REPO_ENV_PATH;
  try { return fn(); } finally {
    if (prev === undefined) delete process.env.CROW_APP_ENV_PATH;
    else process.env.CROW_APP_ENV_PATH = prev;
  }
}

/** True for an env name that is a storage credential (the shape the guard refuses). */
const isStorageShaped = (name) => /^(?:MINIO_|S3_)/.test(name);

const SESSION = mkdir(join(T, "session"));
const CANONICAL = join(T, "canonical.json");
writeFileSync(CANONICAL, JSON.stringify({ mcpServers: { "third-party": { command: "node", args: ["server.js"] } } }));

const W = await import("../scripts/pi-bots/mcp_writer.mjs");

after(() => { try { rmSync(T, { recursive: true, force: true }); } catch { /* best effort */ } });

const ALL_IDS = [...STORAGE_SERVERS, "plain-addon"];
const def = (ids = ALL_IDS) => ({ tools: { crow_mcp: ids.map((id) => id + "/tool") } });
const mcpFile = () => join(SESSION, ".mcp.json");
const written = () => (existsSync(mcpFile()) ? readFileSync(mcpFile(), "utf8") : null);

function build(opts = {}) {
  return W.writeBotMcp(def(opts.ids || ALL_IDS), {
    sessionDir: SESSION, canonicalPath: CANONICAL, crowHome: CROW_HOME, ...opts,
  });
}

/** The hydration names a block gained (the ONLY names a hydrated block may ever carry). */
const HYDRATION_ENV = {
  CROW_STORAGE_FROM_HOST: "1",
  S3_ENDPOINT: ENGINE_PLAINTEXT.endpoint,
  S3_USE_SSL: "false",
  S3_REGION: "us-east-1",
  S3_BUCKET_PREFIX: ENGINE_PLAINTEXT.prefix,
  S3_ACCESS_KEY: ENGINE_PLAINTEXT.access,
  S3_SECRET_KEY: ENGINE_PLAINTEXT.secret,
};

// ─── 1. the fd turn: only the opened settings, never on disk ───────────────

test("fd + hydrate: every storage-using block gets ONLY the six S3_* names plus the marker", () => {
  const res = build({ write: false, addonKeys: "hydrate" });

  for (const id of STORAGE_SERVERS) {
    const block = res.json.mcpServers[id];
    assert.ok(block, id + " is in the config");
    assert.equal(block.disabled, undefined);
    for (const [name, value] of Object.entries(HYDRATION_ENV)) {
      assert.equal(block.env[name], value, id + ": " + name);
    }
    // Nothing else storage-shaped came along: no MINIO_*, no seed, no seal key, no home.
    for (const name of ["MINIO_ENDPOINT", "MINIO_ROOT_USER", "MINIO_ROOT_PASSWORD", "S3_BUCKET", "CROW_BOT_SEED"]) {
      assert.equal(block.env[name], undefined, id + " must not carry " + name);
    }
    assert.equal(JSON.stringify(block.env).includes(ENGINE_SEED_HEX), false, id + ": the seed is nowhere in the block");
  }
  // An add-on that declares nothing is storage-OFF: it never gets the settings, and the marker
  // says so (no marker IS the owner path — see the marker-0 rule).
  assert.deepEqual(res.json.mcpServers["plain-addon"].env, { PLAIN_SETTING: "on", CROW_HOME, CROW_STORAGE_FROM_HOST: "0" });
  // The boot line and the owed names.
  assert.deepEqual(res.sharedStorage, { servers: STORAGE_SERVERS, note: W.SHARED_STORAGE_NOTE_OVER_FD });
  assert.deepEqual(res.needsSharedStorage, []);
  // Nothing was written: the plaintext lives in the in-memory config only.
  assert.equal(res.path, null);
  assert.equal(written(), null);
  assert.deepEqual(readdirSync(SESSION), [], "not even a temp file");
});

test("the hydrated plaintext appears in NO file on disk (a file-mode turn of the same bot)", () => {
  const res = build(); // file mode
  assert.equal(res.path, mcpFile());
  const text = written();
  assert.ok(text);
  for (const secret of [ENGINE_PLAINTEXT.access, ENGINE_PLAINTEXT.secret, ENGINE_SEED_HEX]) {
    assert.equal(text.includes(secret), false, "the .mcp.json carries no credential and no seed");
  }
  assert.equal(text.includes("S3_SECRET_KEY"), false, "not even the name of a credential");
  // Every file in the session dir, not just .mcp.json.
  for (const name of readdirSync(SESSION)) {
    assert.equal(readFileSync(join(SESSION, name), "utf8").includes(ENGINE_PLAINTEXT.secret), false, name);
  }
});

// ─── 2. a file-delivery turn: no storage, one warning, never a localhost fallback ──

test("file mode: no credentials at all, the marker is off, and ONE warning per storage server", () => {
  const res = build();
  for (const id of STORAGE_SERVERS) {
    const block = res.json.mcpServers[id];
    if (id === "crow-storage") { assertCoreStorageAbsent(res); assert.ok(res.warnings.includes(W.WARN_SHARED_STORAGE_FILE_MODE(id))); continue; }
    assert.equal(block.env.CROW_STORAGE_FROM_HOST, "0", id + " runs with no shared storage");
    for (const name of Object.keys(HYDRATION_ENV).filter((n) => n !== "CROW_STORAGE_FROM_HOST")) {
      assert.equal(block.env[name], undefined, id + " must not carry " + name);
    }
    assert.ok(res.warnings.includes(W.WARN_SHARED_STORAGE_FILE_MODE(id)), id + ": one fixed sentence");
  }
  assert.equal(res.warnings.filter((w) => /shared storage needs fd delivery/.test(w)).length, STORAGE_SERVERS.length);
  assert.deepEqual(res.sharedStorage, { servers: STORAGE_SERVERS, note: W.SHARED_STORAGE_NOTE_OFF_FILE });
  assert.deepEqual(res.needsSharedStorage, [], "a file turn decided it: nothing is owed");
  assert.equal(JSON.stringify(res.json).includes(ENGINE_PLAINTEXT.secret), false);
});

// ─── 3. a validate-only turn opens nothing ──────────────────────────────────

test("fd + omit (the default): the block is untouched and the names it owes are reported", () => {
  const res = build({ write: false });
  for (const id of STORAGE_SERVERS) {
    const block = res.json.mcpServers[id];
    assert.equal(block.env.CROW_STORAGE_FROM_HOST, undefined, id + ": nothing was decided");
    assert.equal(block.env.S3_SECRET_KEY, undefined);
  }
  assert.deepEqual(res.needsSharedStorage, STORAGE_SERVERS, "names only, never a value");
  assert.deepEqual(res.sharedStorage, { servers: STORAGE_SERVERS, note: W.SHARED_STORAGE_NOTE_DEFERRED });
  assert.equal(JSON.stringify(res).includes(ENGINE_PLAINTEXT.secret), false);
});

// ─── 3c. an UNDECLARED consumer never reaches the owner path ────────────────

test("every active stdio block that declares no shared storage carries marker 0, in every mode", () => {
  // "plain-addon" is the shape that matters: a bundle whose code could import the storage client
  // while its manifest declares no `needs` — an installed copy from before the declaration, or a
  // bundle that never added one. It is never hydrated, so WITHOUT a marker the child would reach
  // adoptHostStorage with null = an OWNER's spawn and open the instance identity inside a bot.
  for (const mode of [{ write: false, addonKeys: "hydrate" }, { write: false }, {}]) {
    const res = build({ ids: ["plain-addon"], ...mode });
    const env = res.json.mcpServers["plain-addon"].env;
    assert.equal(env.CROW_STORAGE_FROM_HOST, "0", JSON.stringify(mode) + ": storage is off, never undecided");
    for (const name of Object.keys(env)) assert.equal(isStorageShaped(name), false, name + " must not board");
    // Still the add-on's own block: nothing else changed, and nobody owes it a hydration.
    assert.equal(env.PLAIN_SETTING, "on");
    assert.deepEqual(res.needsSharedStorage, []);
    assert.equal(res.warnings.some((w) => w.includes("shared storage")), false, "a non-consumer is not warned about");
  }
});

test("a {url, headers} block spawns no child, so it is left exactly as it was", () => {
  const urlCanonical = join(T, "canonical-url.json");
  const block = { url: "https://example.test/mcp", headers: { Authorization: "Bearer x" } };
  writeFileSync(urlCanonical, JSON.stringify({ mcpServers: { "remote-thing": block } }));
  const res = build({ ids: ["remote-thing"], write: false, addonKeys: "hydrate", canonicalPath: urlCanonical });
  assert.deepEqual(res.json.mcpServers["remote-thing"], block, "no marker and no env: there is no child to decide for");
});

// ─── 3d. a manifest `needs` is a REQUEST — the grant also needs the reviewed id ──

test("the catalog refuses the declaration alone: a non-allow-listed bundle is named unreviewed, not owed", async () => {
  const { crowServerCatalog } = await import("../scripts/pi-bots/crow-server-catalog.mjs");
  const { needsSharedStorage, sharedStorageUnreviewed } = crowServerCatalog(CROW_HOME);
  // Core crow-storage stays granted by its REGISTRY entry (code in this repo, reviewed).
  assert.ok(needsSharedStorage.includes("crow-storage"), "the registry `needs` is still a grant");
  // The reviewed bundles keep theirs (they are on STORAGE_ENV_CONSUMERS).
  for (const id of ["studio", "sunvox-studio", "data-dashboard"]) {
    assert.ok(needsSharedStorage.includes(id), id + " is a reviewed consumer and keeps its hydration");
  }
  // The third-party one declared the same need and is refused by ID, not by anything its
  // (operator-writable) installed manifest could say.
  assert.equal(needsSharedStorage.includes(UNREVIEWED_STORAGE_ADDON), false, "a declaration alone grants nothing");
  assert.ok(sharedStorageUnreviewed.includes(UNREVIEWED_STORAGE_ADDON), "and the refusal is reported, not silent");
});

test("fd + hydrate: a bundle that declares the need but is not reviewed gets NO credentials and ONE warning", () => {
  const res = build({ ids: [UNREVIEWED_STORAGE_ADDON, "studio"], write: false, addonKeys: "hydrate" });
  const block = res.json.mcpServers[UNREVIEWED_STORAGE_ADDON];
  assert.ok(block, "the add-on is still emitted — it is only storage-OFF");
  assert.equal(block.env.CROW_STORAGE_FROM_HOST, "0", "marker 0: storage off, never the owner path");
  for (const name of Object.keys(HYDRATION_ENV).filter((n) => n !== "CROW_STORAGE_FROM_HOST")) {
    assert.equal(block.env[name], undefined, UNREVIEWED_STORAGE_ADDON + " must not carry " + name);
  }
  for (const name of Object.keys(block.env)) assert.equal(isStorageShaped(name), false, name + " must not board");
  assert.ok(res.warnings.includes(W.WARN_SHARED_STORAGE_NOT_REVIEWED(UNREVIEWED_STORAGE_ADDON)),
    "one warning names it: not a reviewed storage consumer");
  assert.equal(res.warnings.filter((w) => w === W.WARN_SHARED_STORAGE_NOT_REVIEWED(UNREVIEWED_STORAGE_ADDON)).length, 1, "exactly one");
  assert.deepEqual(res.needsSharedStorage, [], "a refused declaration owes nothing");
  // The reviewed consumer in the SAME turn is hydrated exactly as before, and the boot line
  // names only it.
  for (const [name, value] of Object.entries(HYDRATION_ENV)) assert.equal(res.json.mcpServers.studio.env[name], value, "studio: " + name);
  assert.deepEqual(res.sharedStorage, { servers: ["studio"], note: W.SHARED_STORAGE_NOTE_OVER_FD });
  assert.equal(JSON.stringify(block.env).includes(ENGINE_PLAINTEXT.secret), false, "no credentials on the refused block");
});

test("file mode: the same bundle is storage-OFF with the same warning, and no credential reaches the file", () => {
  const res = build({ ids: [UNREVIEWED_STORAGE_ADDON, "studio"] });
  const block = res.json.mcpServers[UNREVIEWED_STORAGE_ADDON];
  assert.equal(block.env.CROW_STORAGE_FROM_HOST, "0");
  for (const name of Object.keys(HYDRATION_ENV).filter((n) => n !== "CROW_STORAGE_FROM_HOST")) {
    assert.equal(block.env[name], undefined, UNREVIEWED_STORAGE_ADDON + " must not carry " + name);
  }
  assert.ok(res.warnings.includes(W.WARN_SHARED_STORAGE_NOT_REVIEWED(UNREVIEWED_STORAGE_ADDON)));
  // File mode's own warning belongs to the reviewed consumer, not to the refused one.
  assert.equal(res.warnings.includes(W.WARN_SHARED_STORAGE_FILE_MODE(UNREVIEWED_STORAGE_ADDON)), false,
    "it was never a candidate for the pipe, so it gets the review sentence alone");
  assert.deepEqual(res.sharedStorage, { servers: ["studio"], note: W.SHARED_STORAGE_NOTE_OFF_FILE });
  const text = written();
  assert.ok(text);
  assert.equal(text.includes(ENGINE_PLAINTEXT.secret), false);
  assert.equal(text.includes("S3_SECRET_KEY"), false, "not even the name of a credential");
});

// ─── 3b. a repo .env with MINIO_*/S3_* never boards a bot ──────────────────

test("file mode + a repo .env with MINIO_*/S3_*: no credential and not even a credential NAME reaches .mcp.json", () => {
  const res = withRepoEnv(() => build());
  const text = written();
  assert.ok(text);
  for (const secret of [ENV_ROOT_USER, ENV_ROOT_PASSWORD, ENV_S3_ACCESS, ENV_S3_SECRET]) {
    assert.equal(text.includes(secret), false, "the operator's storage credential is nowhere in the file");
  }
  assert.equal(text.includes("MINIO_"), false, "not even the name of a MinIO credential");
  assert.deepEqual(JSON.parse(text).mcpServers["crow-storage"], { disabled: true }, "a file turn drops the core storage block");
  assert.ok(res.warnings.includes(W.WARN_STORAGE_CREDENTIALS_STRIPPED("crow-storage")));
  // An add-on whose OWN entry lists MINIO_* loses them too, and keeps its plain setting.
  const addon = withRepoEnv(() => build({ ids: ["env-addon"] }));
  assert.deepEqual(addon.json.mcpServers["env-addon"].env, { PLAIN_SETTING: "on", CROW_HOME, CROW_STORAGE_FROM_HOST: "0" });
  assert.ok(addon.warnings.includes(W.WARN_STORAGE_CREDENTIALS_STRIPPED("env-addon")));
  assert.equal(written().includes(ADDON_MINIO_PASSWORD), false);
});

test("fd + hydrate + a repo .env: exactly the six S3_* names and the marker, and the BOT KEY wins", () => {
  const res = withRepoEnv(() => build({ write: false, addonKeys: "hydrate" }));
  for (const id of STORAGE_SERVERS) {
    const block = res.json.mcpServers[id];
    assert.deepEqual(
      Object.keys(block.env).filter(isStorageShaped).sort(),
      ["S3_ACCESS_KEY", "S3_BUCKET_PREFIX", "S3_ENDPOINT", "S3_REGION", "S3_SECRET_KEY", "S3_USE_SSL"],
      id + ": exactly the six hydrated names, nothing else storage-shaped",
    );
    for (const [name, value] of Object.entries(HYDRATION_ENV)) assert.equal(block.env[name], value, id + ": " + name);
    assert.equal(JSON.stringify(block.env).includes(ENV_S3_SECRET), false, id + ": the env credential is nowhere");
  }
  // The core block is the one the repo .env reaches (its registry `mcpEnv`), so it is the one
  // that also carries the one-line note about the credentials left out.
  assert.ok(res.warnings.includes(W.WARN_STORAGE_CREDENTIALS_STRIPPED("crow-storage")), "one line says they were left out");
  // A block that is NOT a storage consumer keeps its own env, loses only the credentials, and is
  // decided OFF (it never receives the settings, so it must never take the owner path either).
  const addon = withRepoEnv(() => build({ ids: ["env-addon"], write: false, addonKeys: "hydrate" }));
  const addonEnv = addon.json.mcpServers["env-addon"].env;
  assert.equal(addonEnv.PLAIN_SETTING, "on");
  assert.equal(addonEnv.CROW_STORAGE_FROM_HOST, "0", "a non-consumer is storage-off, never marker-less");
  for (const name of Object.keys(addonEnv)) assert.equal(isStorageShaped(name), false, "env-addon lost " + name);
});

// ─── 4. no bot storage key: off, with one warning ──────────────────────────

test("fd + hydrate with no bot storage key: off with one warning, never the shared settings and never the ambient env", () => {
  removeBotKey();
  // The shared settings are the INSTANCE credential. They stay in crow.db (a normal install),
  // and they must not board a bot block now that no bot key is provisioned.
  seedStorageSettings();
  try {
    const res = build({ write: false, addonKeys: "hydrate" });
    for (const id of STORAGE_SERVERS) {
      if (id === "crow-storage") { assertCoreStorageAbsent(res); assert.ok(res.warnings.includes(W.WARN_SHARED_STORAGE_NO_BOT_KEY(id))); continue; }
      assert.equal(res.json.mcpServers[id].env.CROW_STORAGE_FROM_HOST, "0", id + " has no shared storage");
      for (const name of Object.keys(res.json.mcpServers[id].env)) {
        assert.equal(isStorageShaped(name), false, id + " must not carry " + name);
      }
      assert.ok(res.warnings.includes(W.WARN_SHARED_STORAGE_NO_BOT_KEY(id)));
    }
    assert.deepEqual(res.sharedStorage, { servers: STORAGE_SERVERS, note: W.SHARED_STORAGE_NOTE_OFF_NO_BOT_KEY });
    assert.equal(W.SHARED_STORAGE_NOTE_OFF_NO_BOT_KEY, "shared storage: off (no bot storage key on this instance)");
    assert.equal(JSON.stringify(res).includes(ENGINE_PLAINTEXT.secret), false,
      "the shared credential is nowhere in the turn");
  } finally {
    writeBotKey(); // put the instance back for the rest of the file
  }
});

test("the bot key file's VALUES are what boards the block, even when crow.db holds different shared settings", () => {
  // Both sources are present and disagree. The block must carry the FILE's values: a bot never
  // opens storage.shared.* at all. (The shared rows are plaintext here — nothing opens them, so
  // sealing them would only prove the test can seal.)
  const sharedAccess = "shared-access-" + randomUUID();
  const sharedSecret = "shared-secret-" + randomUUID();
  const raw = new Database(DB_PATH);
  try {
    const put = raw.prepare("INSERT OR REPLACE INTO dashboard_settings (key, value, updated_at) VALUES (?, ?, datetime('now'))");
    put.run("storage.shared.endpoint", "127.0.0.1:19901");
    put.run("storage.shared.use_ssl", "true");
    put.run("storage.shared.region", "other-region-1");
    put.run("storage.shared.bucket_prefix", "instanceprefix");
    put.run("storage.shared.access_key", sharedAccess);
    put.run("storage.shared.secret_key", sharedSecret);
  } finally { raw.close(); }
  try {
    const res = build({ write: false, addonKeys: "hydrate" });
    for (const id of STORAGE_SERVERS) {
      const block = res.json.mcpServers[id];
      assert.equal(block.env.S3_ENDPOINT, ENGINE_PLAINTEXT.endpoint, id + ": the key file's endpoint");
      assert.equal(block.env.S3_BUCKET_PREFIX, ENGINE_PLAINTEXT.prefix, id + ": the key file's prefix");
      assert.equal(block.env.S3_ACCESS_KEY, ENGINE_PLAINTEXT.access, id + ": the bot's OWN access key");
      assert.equal(block.env.S3_SECRET_KEY, ENGINE_PLAINTEXT.secret, id + ": the bot's OWN secret");
      assert.equal(block.env.S3_REGION, "us-east-1");
      assert.equal(JSON.stringify(block.env).includes(sharedSecret), false, id + ": the shared credential is nowhere");
      assert.equal(JSON.stringify(block.env).includes(sharedAccess), false, id + ": not the shared access key either");
    }
    assert.deepEqual(res.sharedStorage, { servers: STORAGE_SERVERS, note: W.SHARED_STORAGE_NOTE_OVER_FD });
  } finally {
    seedStorageSettings(); // put the fixture rows back
    writeBotKey();
  }
});

test("an instance with no bot storage key and no shared settings: a bot gets NO storage, never the operator's env credentials", () => {
  const other = join(T, "envonly");
  mkdir(other);
  const data = mkdir(join(other, ".crow", "data"));
  const dbPath = join(data, "crow.db");
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    cwd: REPO, stdio: "pipe",
    env: { ...process.env, CROW_HOME: join(other, ".crow"), CROW_DATA_DIR: data, CROW_DB_PATH: dbPath },
  });
  const saved = { CROW_HOME: process.env.CROW_HOME, CROW_DATA_DIR: process.env.CROW_DATA_DIR, CROW_DB_PATH: process.env.CROW_DB_PATH };
  try {
    // The writer resolves the instance from the env, so this leg moves the process with it.
    process.env.CROW_HOME = join(other, ".crow");
    process.env.CROW_DATA_DIR = data;
    process.env.CROW_DB_PATH = dbPath;
    // The operator's own storage environment — on a MinIO install, the ROOT credential.
    process.env.S3_ENDPOINT = "127.0.0.1:19000";
    process.env.S3_ACCESS_KEY = "env-access-not-for-bots";
    process.env.S3_SECRET_KEY = "env-secret-not-for-bots";
    process.env.S3_BUCKET_PREFIX = "envprefix";
    const res = W.writeBotMcp(def(["crow-storage"]), {
      sessionDir: SESSION, canonicalPath: CANONICAL, crowHome: join(other, ".crow"),
      write: false, addonKeys: "hydrate",
    });
    assertCoreStorageAbsent(res);
    assert.equal(JSON.stringify(res).includes("env-secret-not-for-bots"), false, "the operator's credential is never piped to a bot");
    assert.ok(res.warnings.includes(W.WARN_SHARED_STORAGE_NO_BOT_KEY("crow-storage")));
    assert.deepEqual(res.sharedStorage, { servers: ["crow-storage"], note: W.SHARED_STORAGE_NOTE_OFF_NO_BOT_KEY });
  } finally {
    for (const k of Object.keys(saved)) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    for (const k of ["S3_ENDPOINT", "S3_ACCESS_KEY", "S3_SECRET_KEY", "S3_BUCKET_PREFIX"]) delete process.env[k];
  }
});

test("a bot storage key file that cannot be used is a fault, not 'no key': its own warning and boot line", () => {
  // Every refusal reads the same way to the operator (OFF, one sentence with the reason) and is
  // never the "no key on this instance" line: the file is there, and it is broken. A half-written
  // key must not look like a fresh install.
  const cases = [
    ["group/world readable", () => chmodSync(BOT_KEY_PATH(), 0o644), /readable by other users/],
    ["a symlink", () => {
      const target = join(T, "planted-bot-storage.json");
      writeFileSync(target, readFileSync(BOT_KEY_PATH(), "utf8"), { mode: 0o600 });
      chmodSync(target, 0o600);
      rmSync(BOT_KEY_PATH(), { force: true });
      symlinkSync(target, BOT_KEY_PATH());
    }, /symbolic link/],
    ["a missing field", () => writeBotKey({ secret_key: "" }), /secret_key/],
    ["not JSON", () => { writeFileSync(BOT_KEY_PATH(), "{not json\n"); chmodSync(BOT_KEY_PATH(), 0o600); }, /not valid JSON/],
  ];
  try {
    for (const [why, breakIt, pattern] of cases) {
      writeBotKey();
      breakIt();
      const res = build({ write: false, addonKeys: "hydrate" });
      for (const id of STORAGE_SERVERS) {
        const block = res.json.mcpServers[id];
        if (id === "crow-storage") assertCoreStorageAbsent(res);
        else assert.equal(block.env.CROW_STORAGE_FROM_HOST, "0", why + ": storage is off either way");
        if (id === "crow-storage") { assert.ok(res.warnings.some((w) => w.startsWith(`${id}: the bot storage key file could not be read (`))); continue; }
        for (const name of Object.keys(block.env)) assert.equal(isStorageShaped(name), false, why + ": " + id + " must not carry " + name);
        const prefix = `${id}: the bot storage key file could not be read (`;
        const warned = res.warnings.find((w) => w.startsWith(prefix));
        assert.ok(warned, why + ": " + id + " reports the fault");
        assert.match(warned, pattern, why + ": the reason travels with it");
        assert.equal(res.warnings.includes(W.WARN_SHARED_STORAGE_NO_BOT_KEY(id)), false, why + ": not the 'no key' sentence");
      }
      const note = res.sharedStorage.note;
      assert.match(note, /^shared storage: off \(the bot storage key file could not be read: /, why + ": " + note);
      assert.match(note, pattern, why + ": the boot line carries the reason");
      assert.notEqual(note, W.SHARED_STORAGE_NOTE_OFF_NO_BOT_KEY, why);
    }
  } finally {
    rmSync(BOT_KEY_PATH(), { force: true });
    writeBotKey();
  }
});

test("the writer reads no shared settings and no identity for a bot: the module has no such reference", () => {
  // The structural half of the promise the tests above make behaviourally: nothing on the bot
  // config path can open the instance's sealed settings or the identity file any more.
  const src = readFileSync(join(REPO, "scripts", "pi-bots", "mcp_writer.mjs"), "utf8");
  for (const needle of [
    '"storage.shared."', "'storage.shared.'", "storage.shared.endpoint",
    "readSharedStorageSettingsSync", "loadSharedStorageFromDb", "loadIdentityIfPresent",
    "servers/sharing/identity.js",
  ]) {
    assert.equal(src.includes(needle), false, "mcp_writer.mjs must not reference " + needle);
  }
  assert.match(src, /readBotStorageKey/, "it reads the BOT storage key instead");
});

// ─── 5. the boot line ──────────────────────────────────────────────────────

test("the per-bot boot line has exactly five states, and the engine logs it beside the config warnings", () => {
  assert.equal(W.SHARED_STORAGE_NOTE_OVER_FD, "shared storage: over fd");
  assert.equal(W.SHARED_STORAGE_NOTE_OFF_FILE, "shared storage: off (file delivery)");
  assert.equal(W.SHARED_STORAGE_NOTE_OFF_NO_BOT_KEY, "shared storage: off (no bot storage key on this instance)");
  assert.equal(W.SHARED_STORAGE_NOTE_OFF_KEY_UNREADABLE("it is a symbolic link"),
    "shared storage: off (the bot storage key file could not be read: it is a symbolic link)");
  assert.equal(W.SHARED_STORAGE_NOTE_DEFERRED, "shared storage: not piped in this turn");
  const world = readFileSync(join(REPO, "scripts", "pi-bots", "bot-world.mjs"), "utf8");
  assert.match(world, /if \(w\.sharedStorage && w\.sharedStorage\.note\) a\.log\(w\.sharedStorage\.note\);/,
    "the world builder logs the note it was handed (the spawn log, next to the [containment] line)");
  // A bot with no storage-using server gets no line at all.
  const none = build({ ids: ["plain-addon"], write: false });
  assert.equal(none.sharedStorage, null);
});

// ─── 6. each child adopts the piped settings and never loads identity.js ───

const SPY_HOOK = `
import { appendFileSync } from "node:fs";
export async function resolve(specifier, context, next) {
  const r = await next(specifier, context);
  if (/\\/servers\\/sharing\\/identity\\.js$/.test(r.url)) appendFileSync(process.env.CROW_SPY_MARKER, r.url + "\\n");
  return r;
}
`;
const SPY_LOADER = `
import { register } from "node:module";
register(new URL("./hook.mjs", import.meta.url));
`;
const DRIVER = `
import { writeFileSync } from "node:fs";
const [entry, report, kind] = process.argv.slice(2);
const app = (rel) => import(new URL(rel, "file://" + process.env.CROW_TEST_APP_ROOT + "/").href);
const mod = await import(entry);
if (kind === "studio") await mod.openStorageModule({ db: null });
if (kind === "sunvox-studio") await mod.storage();
if (kind === "data-dashboard") await mod.useInstanceStorage(null);
if (kind === "artifacts") {
  // This bundle's storage path exactly as the gateway mount and the panel routes reach it: the
  // blob store is created by createBlobStore, which adopts the bot's marker before it looks at
  // anything else (bundles/artifacts/server/blob-store-minio.js resolveS3).
  const { createDbClient } = await app("servers/db.js");
  const db = createDbClient();
  await (await app("bundles/artifacts/server/init-tables.js")).initArtifactsTables(db);
  await mod.createBlobStore(db, process.env.CROW_DATA_DIR, { noCache: true });
}
const client = await import(new URL("servers/storage/s3-client.js", "file://" + process.env.CROW_TEST_APP_ROOT + "/").href);
writeFileSync(report, JSON.stringify({
  mode: client.storageFromHostMode(),
  configured: client.isConfigured(),
  origin: client.getStorageOrigin(),
  bucket: client.defaultBucket(),
  off: client.storageOffReason() || null,
}));
process.exit(0);
`;
/**
 * The children whose storage bootstrap this suite walks. The four hydrating servers, plus
 * artifacts: its blob backend is the storage consumer the core mount and the panel routes both
 * reach, and it declares `needs: ["shared-storage"]` — so it must adopt the marker first too.
 */
const CHILD_KINDS = [...STORAGE_SERVERS, "artifacts"];

const SPY_DIR = mkdir(join(T, "spy"));
writeFileSync(join(SPY_DIR, "hook.mjs"), SPY_HOOK);
writeFileSync(join(SPY_DIR, "load.mjs"), SPY_LOADER);

/**
 * Run one child's storage bootstrap in a subprocess, with (or without) the piped settings and
 * with the loader spy in place. Returns the child's report and the identity.js loads it made.
 */
function childStorage(kind, env) {
  // The module that holds the child's storage bootstrap: the stdio entry for crow-storage
  // (which runs it at load), studio's own storage-init module (yjs and the editor graph stay
  // out of this test), and the server module for sunvox-studio and data-dashboard (they decide
  // on their first storage call, so the driver calls it).
  const entry = {
    "crow-storage": join(REPO, "servers", "storage", "index.js"),
    studio: join(REPO, "bundles", "studio", "server", "storage-init.js"),
    "sunvox-studio": join(REPO, "bundles", "sunvox-studio", "server", "server.js"),
    "data-dashboard": join(REPO, "bundles", "data-dashboard", "server", "server.js"),
    artifacts: join(REPO, "bundles", "artifacts", "server", "blob-store-minio.js"),
  }[kind];
  const driver = join(SPY_DIR, kind + "-driver.mjs");
  writeFileSync(driver, DRIVER);
  const report = join(SPY_DIR, kind + "-" + randomUUID() + ".json");
  const marker = report + ".identity-loads";
  const r = spawnSync(process.execPath, ["--import", join(SPY_DIR, "load.mjs"), driver, "file://" + entry, report, kind], {
    cwd: REPO, encoding: "utf8", timeout: 120_000, input: "",
    env: {
      ...process.env,
      CROW_TEST_APP_ROOT: REPO,
      CROW_SPY_MARKER: marker,
      CROW_HOME, CROW_DATA_DIR: DATA, CROW_DB_PATH: DB_PATH,
      PIBOT_MCP_CONFIG_DELIVERY: "fd",
      ...env,
    },
  });
  const loads = existsSync(marker) ? readFileSync(marker, "utf8").trim().split("\n").filter(Boolean) : [];
  let out = null;
  if (existsSync(report)) out = JSON.parse(readFileSync(report, "utf8"));
  return { status: r.status, stderr: r.stderr || "", report: out, identityLoads: loads };
}

test("the spy really fires: a driver that imports identity.js is caught (positive control)", () => {
  const driver = join(SPY_DIR, "control.mjs");
  writeFileSync(driver, 'await import("file://' + join(REPO, "servers", "sharing", "identity.js") + '");\n');
  const marker = join(SPY_DIR, "control-" + randomUUID() + ".marker");
  const r = spawnSync(process.execPath, ["--import", join(SPY_DIR, "load.mjs"), driver], {
    cwd: REPO, encoding: "utf8", timeout: 60_000,
    env: { ...process.env, CROW_SPY_MARKER: marker, CROW_DATA_DIR: DATA, CROW_HOME, CROW_DB_PATH: DB_PATH },
  });
  assert.equal(r.status, 0, r.stderr);
  assert.ok(existsSync(marker), "the loader spy records the identity.js load");
  assert.match(readFileSync(marker, "utf8"), /servers\/sharing\/identity\.js/);
});

for (const kind of CHILD_KINDS) {
  test("child " + kind + ": hydrated from the piped env, and identity.js is never loaded", { timeout: 180_000 }, () => {
    const r = childStorage(kind, {
      CROW_STORAGE_FROM_HOST: "1",
      ...Object.fromEntries(Object.entries(HYDRATION_ENV).filter(([k]) => k !== "CROW_STORAGE_FROM_HOST")),
    });
    assert.ok(r.report, kind + " reached its storage bootstrap (stderr: " + r.stderr.slice(0, 1600) + ")");
    assert.equal(r.report.mode, "on", kind + " sees the hydration marker");
    assert.equal(r.report.configured, true, kind + " is configured from the piped settings");
    assert.equal(r.report.origin, "http://127.0.0.1:19999", kind + ": the piped endpoint, not localhost:9000");
    assert.equal(r.report.bucket, ENGINE_PLAINTEXT.prefix + "-files", kind + ": the piped bucket prefix");
    assert.deepEqual(r.identityLoads, [], kind + " never loads the identity file");
  });

  test("child " + kind + ": a file-delivery turn has NO storage, whatever its env says", { timeout: 180_000 }, () => {
    const r = childStorage(kind, {
      CROW_STORAGE_FROM_HOST: "0",
      // The silent fallback this replaces: a localhost endpoint inherited from the gateway env.
      S3_ENDPOINT: "localhost:9000",
      S3_ACCESS_KEY: "inherited",
      S3_SECRET_KEY: "inherited",
    });
    assert.ok(r.report, kind + " reached its storage bootstrap (stderr: " + r.stderr.slice(0, 1600) + ")");
    assert.equal(r.report.mode, "off");
    assert.equal(r.report.configured, false, kind + " has no storage at all");
    assert.equal(r.report.origin, null, kind + " does not point at the inherited endpoint");
    assert.equal(r.report.off, "no shared storage in this turn (a file-delivery MCP config cannot carry the credentials)");
    assert.deepEqual(r.identityLoads, [], kind + " does not fall back to the identity either");
  });
}

// ─── 7. the OWNER path retries a failed settings read (it is not a life sentence) ──

/**
 * Drives one bundle's OWNER path (no marker) four times with a controllable clock: a failing
 * crow.db, then a good one INSIDE the backoff (nothing may be retried), then a good one PAST it
 * (the settings are opened), then a failing one again (a success is cached, so nothing is
 * reopened). `state.good`/`state.fails` count the real DB calls, so a silent retry cannot pass.
 */
const RETRY_DRIVER = `
import { writeFileSync } from "node:fs";
const [entry, report, kind] = process.argv.slice(2);
const app = (rel) => import(new URL(rel, "file://" + process.env.CROW_TEST_APP_ROOT + "/").href);
const client = await app("servers/storage/s3-client.js");
const { createDbClient } = await app("servers/db.js");
const real = createDbClient();
const mod = await import(entry);
const retryMs = mod.STORAGE_RETRY_MS;
const state = { fails: 0, good: 0 };
const failing = { execute: async () => { state.fails += 1; throw new Error("database is locked"); } };
const good = { execute: (q) => { state.good += 1; return real.execute(q); } };
// The two shapes of the same decision: data-dashboard opens it from a db argument, sunvox from
// its own (here injected) client factory.
const call = (db, now) => (kind === "data-dashboard"
  ? mod.useInstanceStorage(db, { now })
  : mod.storage({ now, db: async () => db }));
const snap = (step) => ({ step, configured: client.isConfigured(), bucket: client.defaultBucket(), fails: state.fails, good: state.good });
const steps = [];
await call(failing, () => 0);
steps.push(snap("failing"));
await call(good, () => 1);
steps.push(snap("backoff"));
await call(good, () => retryMs + 1);
steps.push(snap("retried"));
await call(failing, () => retryMs * 10);
steps.push(snap("cached"));
writeFileSync(report, JSON.stringify({ retryMs, steps }));
process.exit(0);
`;

/** Run the retry driver for one bundle in its own process (the module state is per process). */
function childRetry(kind) {
  const entry = {
    "sunvox-studio": join(REPO, "bundles", "sunvox-studio", "server", "server.js"),
    "data-dashboard": join(REPO, "bundles", "data-dashboard", "server", "server.js"),
  }[kind];
  const driver = join(SPY_DIR, kind + "-retry.mjs");
  writeFileSync(driver, RETRY_DRIVER);
  const report = join(SPY_DIR, kind + "-retry-" + randomUUID() + ".json");
  const r = spawnSync(process.execPath, [driver, "file://" + entry, report, kind], {
    cwd: REPO, encoding: "utf8", timeout: 120_000,
    // No CROW_STORAGE_FROM_HOST: this is an OWNER's spawn, the path the retry belongs to.
    env: { ...process.env, CROW_TEST_APP_ROOT: REPO, CROW_HOME, CROW_DATA_DIR: DATA, CROW_DB_PATH: DB_PATH },
  });
  let out = null;
  if (existsSync(report)) out = JSON.parse(readFileSync(report, "utf8"));
  return { status: r.status, stderr: r.stderr || "", report: out };
}

for (const kind of ["sunvox-studio", "data-dashboard"]) {
  test(kind + ": the owner path retries a failed settings read on a later call, and caches a success", { timeout: 180_000 }, () => {
    const r = childRetry(kind);
    assert.ok(r.report, kind + " reached its retry driver (stderr: " + r.stderr.slice(0, 1600) + ")");
    const { retryMs, steps } = r.report;
    assert.ok(Number.isFinite(retryMs) && retryMs > 0 && retryMs <= 120_000, kind + ": a SHORT backoff, got " + retryMs);
    const [failing, backoff, retried, cached] = steps;
    assert.deepEqual([failing.configured, failing.fails], [false, 1], kind + ": a failing read leaves storage unset");
    assert.deepEqual([backoff.configured, backoff.good], [false, 0], kind + ": nothing is retried inside the backoff window");
    assert.ok(retried.good > 0, kind + ": past the backoff the settings ARE opened again");
    assert.equal(retried.configured, true, kind + ": and wired up");
    assert.equal(retried.bucket, ENGINE_PLAINTEXT.prefix + "-files", kind + ": the instance's own prefix, not crow-files");
    assert.deepEqual([cached.fails, cached.configured], [failing.fails, true], kind + ": a success is cached, so no later call reopens the DB");
  });
}