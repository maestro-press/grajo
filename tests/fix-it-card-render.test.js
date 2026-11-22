/**
 * Fix-it cards render per language at VIEW time — the red (round 1) tests.
 *
 * Every card in scope here is raised through its REAL detector code path into a
 * scratch crow.db (init-db + createDbClient + wireFixIt, exactly like
 * tests/fix-it-nest-unchanged.test.js), then read back through
 * `fixItCardModels(db, { lang })` — the ONE card model both renderers use.
 *
 * What this file pins:
 *
 *   1. EN BYTE-IDENTITY. For every raised kind the English model must equal
 *      tests/fixtures/fix-it-render-en-baseline.json, except for the entries in
 *      APPROVED_EN_FIXES (the operator-approved English bug fixes of
 *      2026-11-22, copied verbatim from APPROVED-COPY-fixit-english-fixes).
 *      Capture mode writes that baseline from what the code renders right now
 *      and asserts nothing about the copy:
 *
 *        CAPTURE_EN_BASELINE=1 node --test tests/fix-it-card-render.test.js
 *
 *      (equally fine through the scratch env: `CAPTURE_EN_BASELINE=1 npm test --
 *      tests/fix-it-card-render.test.js`).
 *
 *   2. ES. Every kind renders the operator-approved Spanish (title, why and
 *      button labels), hard-coded below character for character from the two
 *      approved copy files (the English-fixes file supersedes round 2). The
 *      Technical-details labels stay on the existing (already approved) keys.
 *
 *   3. LEGACY ROWS. A row with no `context.card` renders its stored English text
 *      unchanged in every language; an unknown code or malformed values fall back
 *      to the stored text; unknown value names are ignored; the renderers still
 *      escape everything.
 *
 *   4. A caddy card's {fixCommand} is recomputed from code, never read from the
 *      stored context.
 *
 *   5. A re-raise rewrites an old-style (no `context.card`) row, so it gains the
 *      code-held copy on the next boot check / event.
 *
 *   6. The add-on-wall reason codes: the documented `{code, values}` shapes, the
 *      English sentence each one renders, and the nested warmup detail.
 *
 *   7. i18n: the new key namespaces exist in BOTH languages with the same
 *      placeholders, and no ES card is the English sentence.
 *
 * Nothing under servers/, scripts/ or any existing test is edited by this file.
 * Docker, the Caddyfile, the boot-guard state, the wall's stderr and the browser
 * container are all injected fakes, so nothing here reads the real ~/.crow.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { basename, dirname, join } from "node:path";

const REPO = join(import.meta.dirname, "..");
const FIXTURE = join(REPO, "tests", "fixtures", "fix-it-render-en-baseline.json");
const CAPTURE = process.env.CAPTURE_EN_BASELINE === "1";

// ── the scratch instance, set BEFORE any gateway module is imported ──────────
const scratch = mkdtempSync(join(tmpdir(), "fixit-card-render-"));
const HOME = join(scratch, "home");
mkdirSync(HOME, { recursive: true });
process.env.CROW_DATA_DIR = scratch;
process.env.CROW_HOME = HOME;
delete process.env.CROW_DB_PATH;
process.env.CROW_TASKS_DB_PATH = join(scratch, "tasks.db");

const silent = { warn() {}, log() {} };
const put = (rel, content) => {
  const p = join(HOME, rel);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, content);
};
const sha256 = (text) => createHash("sha256").update(String(text), "utf8").digest("hex");

let db, idx, store, failures, addonWall, remote, bootGuard, caddyProxy, caddyAdmin, backends, drift, browserStale, seal, cardCopy;
let t, fill, translations, escapeHtml, sha256Compose;

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env }, stdio: "pipe", cwd: REPO,
  });
  const { createDbClient } = await import("../servers/db.js");
  db = createDbClient();
  idx = await import("../servers/gateway/fix-it/index.js");
  store = await import("../servers/shared/fix-it/store.js");
  failures = await import("../scripts/addon-sandbox/failures.mjs");
  addonWall = await import("../servers/gateway/fix-it/detectors/addon-wall.js");
  remote = await import("../servers/gateway/fix-it/detectors/remote-exposure.js");
  bootGuard = await import("../servers/gateway/fix-it/detectors/boot-guard.js");
  caddyProxy = await import("../servers/gateway/fix-it/detectors/caddy-proxy-socket.js");
  caddyAdmin = await import("../servers/gateway/fix-it/detectors/caddy-admin-socket.js");
  backends = await import("../servers/gateway/fix-it/detectors/data-backend-reapproval.js");
  drift = await import("../servers/gateway/fix-it/detectors/bundle-bind-drift.js");
  browserStale = await import("../servers/gateway/fix-it/detectors/browser-image-stale.js");
  seal = await import("../servers/gateway/addon-secrets-seal.js");
  cardCopy = await import("../servers/gateway/fix-it/card-copy.js");
  ({ t, fill, translations } = await import("../servers/gateway/dashboard/shared/i18n.js"));
  ({ escapeHtml } = await import("../servers/gateway/dashboard/shared/components.js"));
  ({ sha256: sha256Compose } = await import("../servers/gateway/bundle-compose-state.js"));
  assert.equal(typeof idx.fixItCardModels, "function", "fix-it/index.js must export fixItCardModels(db, { lang })");
  idx.wireFixIt();
});

after(() => {
  try { db?.close(); } catch { /* already closed */ }
  try { rmSync(scratch, { recursive: true, force: true }); } catch { /* best effort */ }
});

// ─────────────────────────────────────────────────────────────────────────────
// The db-bound store the detectors are handed (the same shape fix-it/index.js's
// own boundStore gives them, so every context round-trips through JSON).
// ─────────────────────────────────────────────────────────────────────────────
function boundStore() {
  return {
    db,
    upsertItem: (item) => store.upsertItem(db, item),
    resolveByKey: (source, key) => store.resolveByKey(db, source, key),
    listBySource: (source) => store.listBySource(db, source),
    recordDuplicate: (id) => store.recordDuplicate(db, id),
    recordSuppressed: () => {},
    markResolved: (id) => store.markResolved(db, id),
  };
}

async function clearCards() {
  await db.execute({ sql: "DELETE FROM fix_it_items", args: [] });
}

async function resetForCase() {
  await clearCards();
  failures._resetWallFailuresForTest();
  rmSync(join(HOME, "bundles"), { recursive: true, force: true });
  rmSync(join(HOME, "installed.json"), { force: true });
}

async function pendingRow(source, dedupKey) {
  const rows = await store.listPending(db);
  return rows.find((r) => r.source === source && r.dedupKey === dedupKey) || null;
}

/** The model a case's pending row renders as, in `lang`. */
async function readModel(source, dedupKey, lang = "en") {
  const row = await pendingRow(source, dedupKey);
  assert.ok(row, `no pending card for ${source} / ${dedupKey}`);
  const models = await idx.fixItCardModels(db, { lang });
  const model = models.find((m) => m.id === row.id);
  assert.ok(model, `fixItCardModels returned no model for ${source} / ${dedupKey} (item ${row.id})`);
  return model;
}

/** The part of a model a per-case baseline pins (ids and counts are order-dependent). */
function modelShape(model) {
  return {
    title: model.title,
    why: model.why,
    remedies: (model.remedies || []).map((r) => ({
      kind: r.kind,
      label: r.label,
      ...(typeof r.actionId === "string" ? { actionId: r.actionId } : {}),
      // A link's destination is held in code (LINK_REMEDIES), never in the row.
      ...(r.kind === "link" && typeof r.href === "string" ? { href: r.href } : {}),
    })),
    details: (model.details || []).map((d) => ({ label: d.label, code: d.code })),
  };
}

/**
 * The captured baseline must not depend on where this checkout lives: a caddy
 * reason sentence embeds `sudo bash <appRoot>/scripts/…`, which the detector
 * builds from the checkout it runs in. Capture AND comparison both pass through
 * this, so that one path is pinned to "<checkout>" and every other byte is still
 * compared exactly. (The ES expectations below are not normalized: they are only
 * ever compared in this checkout.)
 */
const portable = (value) => {
  if (Array.isArray(value)) return value.map(portable);
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).map((key) => [key, portable(value[key])]));
  }
  return typeof value === "string" ? value.split(REPO).join("<checkout>") : value;
};

/** Recursively key-sorted, so the fixture is byte-stable between captures. */
function stable(value) {
  if (Array.isArray(value)) return value.map(stable);
  if (value && typeof value === "object") {
    const out = {};
    for (const key of Object.keys(value).sort()) out[key] = stable(value[key]);
    return out;
  }
  return value;
}

// ─────────────────────────────────────────────────────────────────────────────
// Fakes: docker, the Caddyfile, the boot-guard state, the wall's stderr.
// ─────────────────────────────────────────────────────────────────────────────

/** A `docker` CLI stand-in whose answers come from `handler`; never a real daemon. */
function dockerStub(handler) {
  const calls = [];
  const runner = async (cmd, args, opts) => {
    calls.push({ cmd, args: [...args], opts });
    return handler(cmd, args, opts);
  };
  runner.calls = calls;
  return runner;
}

/** `docker ps` → one running container; `docker inspect` → one row of published ports. */
function driftRunner(ports) {
  return dockerStub(async (cmd, args) => {
    if (cmd !== "docker") throw new Error(`unexpected command ${cmd}`);
    if (args[0] === "ps") return { stdout: "container1\n", stderr: "" };
    if (args[0] === "inspect") {
      return { stdout: JSON.stringify([{ NetworkSettings: { Ports: ports } }]), stderr: "" };
    }
    return { stdout: "", stderr: "" };
  });
}

function writeBundle(id, { name, compose, version = "1.0.0", files = {} } = {}) {
  put(`bundles/${id}/manifest.json`, JSON.stringify({
    id, name, version, type: "bundle", docker: { composefile: "docker-compose.yml" },
  }));
  put(`bundles/${id}/docker-compose.yml`, compose);
  for (const [rel, content] of Object.entries(files)) put(`bundles/${id}/${rel}`, content);
}

function setInstalled(ids) {
  put("installed.json", JSON.stringify(ids.map((id) => ({ id }))));
}

const DRIFT_COMPOSE = 'services:\n  web:\n    image: x\n    ports:\n      - "127.0.0.1:13378:80"\n';
const WIDE_COMPOSE = 'services:\n  web:\n    image: x\n    ports:\n      - "0.0.0.0:13378:80"\n';
const IMAGE_COMPOSE = 'services:\n  web:\n    image: linkding:latest\n    ports:\n      - "127.0.0.1:13378:80"\n';

function writeRepoBundle(id, compose) {
  const root = join(scratch, "repo-bundles");
  mkdirSync(join(root, id), { recursive: true });
  writeFileSync(join(root, id, "manifest.json"), JSON.stringify({
    id, name: "Audiobookshelf", version: "1.0.0", type: "bundle", docker: { composefile: "docker-compose.yml" },
  }));
  writeFileSync(join(root, id, "docker-compose.yml"), compose);
  return root;
}

// ── boot guard ──────────────────────────────────────────────────────────────
const BG_NOW = Date.parse("2026-11-22T12:00:00.000Z");
const BG_UPTIME_MS = 5 * 60 * 1000;
const BG_SYSTEM_UPTIME_MS = 10 * 24 * 60 * 60 * 1000;
const iso = (ms) => new Date(ms).toISOString();

/**
 * The injected `bootGuardProblem` inputs for one reason. `launcher` = no fresh
 * launcher stamp; `recorder` = the previous start was in this boot but its stop
 * stamp never landed; `other` = the record cannot be read at all.
 */
function bootGuardOpts(reason) {
  const dir = join(scratch, `boot-guard-${reason}`);
  rmSync(dir, { recursive: true, force: true });
  mkdirSync(dir, { recursive: true });
  let state = null;
  if (reason === "launcher") state = { v: 1, state: "ok", launcher_finished_at: null };
  if (reason === "recorder") {
    state = {
      v: 1,
      state: "ok",
      launcher_finished_at: iso(BG_NOW - 60_000),
      stable_at: iso(BG_NOW - 40 * 24 * 60 * 60 * 1000),
      prev_launcher_ran_at: iso(BG_NOW - 120_000),
      recorder_ran_at: null,
    };
  }
  writeFileSync(join(dir, "state.json"), state ? JSON.stringify(state) : "{ this is not the state format");
  return {
    env: { CROW_BOOT_GUARD: "1" },
    stateDir: dir,
    now: BG_NOW,
    uptimeMs: BG_UPTIME_MS,
    systemUptimeMs: BG_SYSTEM_UPTIME_MS,
  };
}

// ── Caddy ───────────────────────────────────────────────────────────────────
// The detectors build the command from the checkout they run in (appRoot()), and
// so does the view-time render: nothing about it comes from crow.db.
const CADDY_APP = REPO;
const CADDYFILE = "/etc/caddy/Caddyfile";
const CADDY_PROXY_TEXT = "example.com {\n  reverse_proxy localhost:3001\n}\n";
const CADDY_ADMIN_TEXT = "example.com {\n  reverse_proxy unix//run/crow-proxy/gateway.sock\n}\n";

const caddyProxyOpts = () => ({ caddyfile: CADDYFILE, readFile: () => CADDY_PROXY_TEXT, exists: () => false });
const caddyAdminOpts = () => ({ caddyfile: CADDYFILE, readFile: () => CADDY_ADMIN_TEXT });
const CADDY_PROXY_FIX = `sudo bash ${join(CADDY_APP, "scripts", "fix-caddy-proxy-socket.sh")}`;
const CADDY_ADMIN_FIX = `sudo bash ${join(CADDY_APP, "scripts", "fix-caddy-admin-socket.sh")}`;

// ── browser image ───────────────────────────────────────────────────────────
const BROWSER_COMPOSE = [
  "name: ${CROW_BROWSER_CONTAINER_NAME:-browser}",
  "services:",
  "  crow-browser:",
  "    build:",
  "      context: .",
  "      dockerfile: Dockerfile",
  "    container_name: crow-browser",
  "",
].join("\n");
const BROWSER_DOCKERFILE = [
  "FROM ubuntu:22.04",
  "WORKDIR /app",
  "COPY cdp-relay.mjs ./",
  "COPY package.json ./",
  "",
].join("\n");
const BROWSER_PKG = '{"name":"crow-browser","version":"1.8.0"}\n';
const BROWSER_LOCK = `${JSON.stringify({
  name: "crow-browser",
  lockfileVersion: 3,
  packages: {
    "": { name: "crow-browser", version: "1.8.0" },
    "node_modules/playwright-core": { version: "1.58.2" },
  },
}, null, 2)}\n`;
const BROWSER_RELAY_INSTALLED = "// the relay Crow just installed\n";
const BROWSER_RELAY_OLD = "// the relay the container still runs\n";
const PROFILE_145 = "145.0.7632.6";
/** The running container holds no /app/manifest.json (an image from before the marker). */
const RUNNING_MANIFEST_MISSING = Symbol("running-manifest-missing");

/**
 * `docker` for the browser detector: one running container whose relay differs
 * from the installed one, a readable Chromium profile (so the downgrade guard
 * allows the restart), and the running container's own manifest version.
 */
function browserRunner({ runningVersion = "1.9.2" } = {}) {
  const files = {
    "/app/cdp-relay.mjs": BROWSER_RELAY_OLD,
    "/app/package.json": BROWSER_PKG,
  };
  return dockerStub(async (cmd, args) => {
    if (cmd !== "docker") throw new Error(`unexpected command ${cmd}`);
    if (args[0] === "ps") return { stdout: "container1\n", stderr: "" };
    if (args[0] === "exec") {
      if (args[2] === "sha256sum") {
        const lines = [];
        const missing = [];
        for (const dest of args.slice(3)) {
          if (dest in files) lines.push(`${sha256(files[dest])}  ${dest}`);
          else missing.push(dest);
        }
        const out = { stdout: lines.length ? `${lines.join("\n")}\n` : "", stderr: missing.map((d) => `sha256sum: ${d}: No such file or directory`).join("\n") };
        if (missing.length) throw Object.assign(new Error("docker exec exited 1"), { code: 1, ...out });
        return out;
      }
      if (args[2] === "cat") {
        const target = String(args[3] ?? "");
        if (basename(target) === "manifest.json") {
          if (runningVersion === RUNNING_MANIFEST_MISSING) {
            throw Object.assign(new Error("docker exec exited 1"), {
              code: 1, stdout: "", stderr: `cat: ${target}: No such file or directory`,
            });
          }
          return { stdout: `${JSON.stringify({ id: "browser", name: "Browser Automation", version: runningVersion })}\n`, stderr: "" };
        }
        return { stdout: `${PROFILE_145}\n`, stderr: "" };
      }
    }
    return { stdout: "", stderr: "" };
  });
}

// ── the add-on wall's evidence ──────────────────────────────────────────────
const WALL_ID = "browser";
const WALL_INSTALL_DIR = join(scratch, "wall-bundles", "browser");
const WALL_DATA_DIR = join(scratch, "wall-data", "browser");
const openFailureLine = (absPath, code = "ENOENT") => `Error: ${code}: no such file or directory, open '${absPath}'`;

/**
 * The wall reasons this file pins: the arguments the proxy hands
 * `wallFailureReason`, the documented code shape, the English sentence and the
 * approved Spanish. `args === null` is the event-with-no-reason default (W11),
 * which only the detector's own fallback produces.
 */
const WALL_REASONS = [
  {
    key: "addon-wall/refused",
    args: { refused: true },
    shape: { code: "refused", values: {} },
    en: "could not be set up inside its wall on this computer",
    es: "no pudo configurar su aislamiento en este equipo",
  },
  {
    key: "addon-wall/installed-changed",
    args: { refused: "installed-changed" },
    shape: { code: "installed-changed", values: {} },
    en: "has installed files that changed; reinstall it to wall it",
    es: "tiene archivos instalados que cambiaron; reinstálalo para aislarlo",
  },
  {
    key: "addon-wall/warmup-alone",
    args: { refused: "warmup" },
    shape: { code: "warmup", values: {} },
    en: "could not get its packages ready inside its wall",
    es: "no pudo preparar sus paquetes dentro de su aislamiento",
  },
  {
    key: "addon-wall/warmup-not-ready",
    args: { refused: "warmup" },
    shape: { code: "warmup", values: {} },
    en: "could not get its packages ready inside its wall",
    es: "no pudo preparar sus paquetes dentro de su aislamiento",
  },
  {
    key: "addon-wall/warmup-denied",
    args: { refused: "warmup", denials: ["192.0.2.9:80"] },
    shape: { code: "warmup", values: {} },
    detail: { codes: ["denied"], values: { target: "192.0.2.9:80" } },
    en: "could not get its packages ready inside its wall: tried to reach 192.0.2.9:80, which it is not set up for",
    es: "no pudo preparar sus paquetes dentro de su aislamiento: intentó conectarse a 192.0.2.9:80, para lo que no está configurado",
  },
  {
    key: "addon-wall/warmup-open-rel",
    args: { refused: "warmup", stderrLines: [openFailureLine(join(WALL_INSTALL_DIR, "data/secret.txt"))], installDir: WALL_INSTALL_DIR, dataDir: WALL_DATA_DIR },
    shape: { code: "warmup", values: {} },
    detail: { codes: ["open", "open-rel"], values: { rel: "data/secret.txt" } },
    en: "could not get its packages ready inside its wall: could not open data/secret.txt",
    es: "no pudo preparar sus paquetes dentro de su aislamiento: no pudo abrir data/secret.txt",
  },
  {
    key: "addon-wall/warmup-open-hidden-in-folder",
    args: { refused: "warmup", stderrLines: [openFailureLine(join(WALL_INSTALL_DIR, "my secret.txt"))], installDir: WALL_INSTALL_DIR, dataDir: WALL_DATA_DIR },
    shape: { code: "warmup", values: {} },
    detail: { codes: ["open-folder", "open-in-folder", "open-hidden-in-folder"], values: {} },
    en: "could not get its packages ready inside its wall: could not open a file in its folder",
    es: "no pudo preparar sus paquetes dentro de su aislamiento: no pudo abrir un archivo de su carpeta",
  },
  {
    key: "addon-wall/warmup-open-outside",
    args: { refused: "warmup", stderrLines: [openFailureLine("/etc/shadow", "EACCES")], installDir: WALL_INSTALL_DIR, dataDir: WALL_DATA_DIR },
    shape: { code: "warmup", values: {} },
    detail: { codes: ["open-outside", "open-outside-folder"], values: {} },
    en: "could not get its packages ready inside its wall: could not open a file outside its folder",
    es: "no pudo preparar sus paquetes dentro de su aislamiento: no pudo abrir un archivo fuera de su carpeta",
  },
  {
    key: "addon-wall/warmup-exit-code",
    args: { refused: "warmup", exitCode: 7 },
    shape: { code: "warmup", values: {} },
    detail: { codes: ["exit-code"], values: { exitCode: 7 } },
    en: "could not get its packages ready inside its wall: stopped with exit code 7",
    es: "no pudo preparar sus paquetes dentro de su aislamiento: se detuvo con el código de salida 7",
  },
  {
    key: "addon-wall/not-ready",
    args: {},
    shape: { code: "not-ready", values: {} },
    en: "stopped before it was ready",
    es: "se detuvo antes de estar listo",
  },
  {
    key: "addon-wall/denied-plain-target",
    args: { denials: ["192.0.2.9:80"] },
    shape: { code: "denied", values: { target: "192.0.2.9:80" } },
    en: "tried to reach 192.0.2.9:80, which it is not set up for",
    es: "intentó conectarse a 192.0.2.9:80, para lo que no está configurado",
  },
  {
    key: "addon-wall/denied-hidden-target",
    args: { denials: ["a secret name /etc/shadow"] },
    shape: { code: "denied", values: { target: "an address" } },
    en: "tried to reach an address, which it is not set up for",
    es: "intentó conectarse a una dirección, para lo que no está configurado",
  },
  {
    key: "addon-wall/open-rel",
    args: { stderrLines: [openFailureLine(join(WALL_INSTALL_DIR, "data/secret.txt"))], installDir: WALL_INSTALL_DIR, dataDir: WALL_DATA_DIR },
    shape: { code: "open", values: { rel: "data/secret.txt" } },
    en: "could not open data/secret.txt",
    es: "no pudo abrir data/secret.txt",
  },
  {
    key: "addon-wall/open-hidden-in-folder",
    args: { stderrLines: [openFailureLine(join(WALL_INSTALL_DIR, "my secret.txt"))], installDir: WALL_INSTALL_DIR, dataDir: WALL_DATA_DIR },
    shape: { code: "open-folder", values: {} },
    en: "could not open a file in its folder",
    es: "no pudo abrir un archivo de su carpeta",
  },
  {
    key: "addon-wall/open-outside",
    args: { stderrLines: [openFailureLine("/etc/shadow", "EACCES")], installDir: WALL_INSTALL_DIR, dataDir: WALL_DATA_DIR },
    shape: { code: "open-outside", values: {} },
    en: "could not open a file outside its folder",
    es: "no pudo abrir un archivo fuera de su carpeta",
  },
  {
    key: "addon-wall/exit-code",
    args: { exitCode: 7 },
    shape: { code: "exit-code", values: { exitCode: 7 } },
    en: "stopped with exit code 7",
    es: "se detuvo con el código de salida 7",
  },
  {
    key: "addon-wall/no-reason-default",
    args: null,
    shape: { code: "default", values: {} },
    en: "could not run inside its wall",
    es: "no pudo ejecutarse dentro de su aislamiento",
  },
];

// ─────────────────────────────────────────────────────────────────────────────
// Raising the cards
// ─────────────────────────────────────────────────────────────────────────────

async function raiseRemote({ capability, peerId, peerName }) {
  await remote.default.onEvent("peer-exposure:denied", {
    capability,
    requestingInstance: peerId,
    requestingInstanceName: peerName,
    toolName: "some_tool",
  }, boundStore());
  return { source: "remote-exposure", dedupKey: `expose|${capability}|${peerId}` };
}

async function raiseBootGuard(reason) {
  await bootGuard.default.check(boundStore(), { bootGuard: bootGuardOpts(reason) });
  return { source: "boot-guard", dedupKey: bootGuard.DEDUP_KEY };
}

async function raiseCaddyProxy() {
  await caddyProxy.default.check(boundStore(), caddyProxyOpts());
  return { source: "caddy-proxy-socket", dedupKey: caddyProxy.DEDUP_KEY };
}

async function raiseCaddyAdmin() {
  await caddyAdmin.default.check(boundStore(), caddyAdminOpts());
  return { source: "caddy-admin-socket", dedupKey: caddyAdmin.DEDUP_KEY };
}

async function raiseDataBackends(n) {
  await db.execute({ sql: "DELETE FROM data_backends", args: [] });
  let projectId = (await db.execute({ sql: "SELECT id FROM project_spaces LIMIT 1", args: [] })).rows[0]?.id;
  if (projectId == null) {
    projectId = (await db.execute({
      sql: "INSERT INTO project_spaces (name, slug, type) VALUES ('Fix-it render', 'fixit-render', 'data_connector') RETURNING id",
      args: [],
    })).rows[0].id;
  }
  for (let i = 0; i < n; i += 1) {
    await db.execute({
      sql: "INSERT INTO data_backends (project_id, name, backend_type, connection_ref, status, approved_ref_sha256) VALUES (?, ?, 'mcp_server', ?, 'pending_approval', ?)",
      args: [projectId, `backend-${i}`, JSON.stringify({ command: "node", args: ["server.js"] }), String(i + 1).repeat(64).slice(0, 64)],
    });
  }
  await backends.default.check(boundStore());
  return { source: "data-backend-reapproval", dedupKey: backends.DEDUP_KEY };
}

/** One bundle-bind-drift family card, through the detector's real check(). */
async function raiseDrift(kind) {
  const id = "audiobookshelf";
  const opts = { crowHome: HOME, installedPath: join(HOME, "installed.json"), only: [id], log: silent };

  if (kind === "wider") {
    writeBundle(id, { name: "Audiobookshelf", compose: DRIFT_COMPOSE });
    setInstalled([id]);
    await drift.default.check(boundStore(), {
      ...opts, runner: driftRunner({ "80/tcp": [{ HostIp: "0.0.0.0", HostPort: "13378" }] }),
    });
    return { source: drift.SOURCE, dedupKey: `bundle:${id}` };
  }
  if (kind === "extra") {
    writeBundle(id, { name: "Audiobookshelf", compose: DRIFT_COMPOSE });
    setInstalled([id]);
    await drift.default.check(boundStore(), {
      ...opts,
      // The extra port first: the detector cards the FIRST drift entry.
      runner: driftRunner({
        "9000/tcp": [{ HostIp: "0.0.0.0", HostPort: "9000" }],
        "80/tcp": [{ HostIp: "127.0.0.1", HostPort: "13378" }],
      }),
    });
    return { source: drift.SOURCE, dedupKey: `bundle:${id}` };
  }
  if (kind === "compose-edited") {
    const edited = "changedetection-io";
    writeBundle(edited, { name: "Changedetection.io", compose: DRIFT_COMPOSE });
    put(`bundles/${edited}/.crow-compose.edited`, `${JSON.stringify({ compose: "docker-compose.yml" })}\n`);
    setInstalled([edited]);
    await drift.default.check(boundStore(), {
      crowHome: HOME, installedPath: join(HOME, "installed.json"), only: [edited], log: silent,
      runner: driftRunner({ "80/tcp": [{ HostIp: "127.0.0.1", HostPort: "13378" }] }),
    });
    return { source: drift.COMPOSE_EDITED_SOURCE, dedupKey: `bundle:${edited}` };
  }
  if (kind === "repo-edited" || kind === "repo-unknown") {
    writeBundle(id, { name: "Audiobookshelf", compose: WIDE_COMPOSE });
    if (kind === "repo-edited") {
      put(`bundles/${id}/.crow-compose.edited`, `${JSON.stringify({ compose: "docker-compose.yml" })}\n`);
    } else {
      put(`bundles/${id}/.crow-compose.state.json`, `${JSON.stringify({
        installedSha: sha256Compose(Buffer.from(WIDE_COMPOSE, "utf8")),
        repoComposeSha: sha256Compose(Buffer.from(DRIFT_COMPOSE, "utf8")),
        verdict: "unknown",
      })}\n`);
    }
    setInstalled([id]);
    await drift.default.check(boundStore(), {
      ...opts,
      repoBundlesDir: writeRepoBundle(id, DRIFT_COMPOSE),
      runner: driftRunner({ "80/tcp": [{ HostIp: "0.0.0.0", HostPort: "13378" }] }),
    });
    return { source: drift.REPO_DRIFT_SOURCE, dedupKey: `bundle:${id}:repo` };
  }
  if (kind === "needs-config") {
    const vikunja = "vikunja";
    writeBundle(vikunja, { name: "Vikunja", compose: DRIFT_COMPOSE });
    put(`bundles/${vikunja}/.crow-compose.needs-config`, `${JSON.stringify({
      compose: "docker-compose.yml", missing: ["VIKUNJA_DB_PASSWORD"],
    })}\n`);
    setInstalled([vikunja]);
    await drift.default.check(boundStore(), {
      crowHome: HOME, installedPath: join(HOME, "installed.json"), only: [vikunja], log: silent,
      runner: driftRunner({ "80/tcp": [{ HostIp: "127.0.0.1", HostPort: "13378" }] }),
    });
    return { source: drift.COMPOSE_NEEDS_CONFIG_SOURCE, dedupKey: `bundle:${vikunja}` };
  }
  if (kind === "image-added" || kind === "image-removed" || kind === "image-swapped" || kind === "image-swapped-none") {
    const vikunja = "vikunja";
    const change = kind === "image-added"
      ? { service: "vikunja-volume-owner", from: null, to: "busybox:1.38.0@sha256:a46257e0" }
      : kind === "image-removed"
        ? { service: "web-legacy-helper", from: "busybox:1.36.0", to: null }
        : kind === "image-swapped"
          ? { service: "vikunja", from: "vikunja/vikunja:0.24.6", to: "vikunja/vikunja:0.25.1" }
          // Both ends empty: the one shape that reaches the "none" word.
          : { service: "helper" };
    writeBundle(vikunja, { name: "Vikunja", compose: IMAGE_COMPOSE });
    put(`bundles/${vikunja}/.crow-compose.image-change`, `${JSON.stringify([change])}\n`);
    setInstalled([vikunja]);
    await drift.default.check(boundStore(), {
      crowHome: HOME, installedPath: join(HOME, "installed.json"), only: [vikunja], log: silent,
      runner: driftRunner({ "80/tcp": [{ HostIp: "127.0.0.1", HostPort: "13378" }] }),
    });
    return { source: drift.COMPOSE_IMAGE_CHANGE_SOURCE, dedupKey: `bundle:${vikunja}` };
  }
  throw new Error(`unknown drift kind ${kind}`);
}

/** The browser add-on's stale-image card: known / unknown / no version at all. */
async function raiseBrowserImageStale(variant) {
  const manifestVersion = variant === "no-version" ? "1.9.4 beta" : "1.9.4";
  writeBundle("browser", {
    name: "Browser Automation",
    compose: BROWSER_COMPOSE,
    version: manifestVersion,
    files: {
      Dockerfile: BROWSER_DOCKERFILE,
      "cdp-relay.mjs": BROWSER_RELAY_INSTALLED,
      "package.json": BROWSER_PKG,
      "package-lock.json": BROWSER_LOCK,
    },
  });
  setInstalled(["browser"]);
  const runningVersion = variant === "version-unknown" ? RUNNING_MANIFEST_MISSING : "1.9.2";
  await browserStale.default.check(boundStore(), {
    crowHome: HOME,
    installedPath: join(HOME, "installed.json"),
    runner: browserRunner({ runningVersion }),
    log: silent,
  });
  return { source: browserStale.SOURCE, dedupKey: browserStale.DEDUP_KEY };
}

async function raiseAddonKeys() {
  await seal.raiseAddonKeysUnreadableCard(db, { bundleId: "joplin", names: ["JOPLIN_TOKEN"] });
  return { source: seal.ADDON_KEY_CARD_SOURCE, dedupKey: seal.ADDON_KEY_CARD_KEY };
}

/**
 * One wall failure: build the reason the proxy builds, keep the code beside it
 * when the module has one (it does not on the unchanged tree — this file must
 * capture its baseline there), record it, then emit the detector's event.
 */
async function raiseWall(args, { omitPayloadReason = false } = {}) {
  const reason = args === null
    ? addonWall.DEFAULT_REASON
    : failures.wallFailureReason(args);
  let ref;
  if (typeof failures.wallFailureReasonCode === "function") {
    const code = args === null ? { code: "default", values: {} } : failures.wallFailureReasonCode(args);
    ref = failures.recordWallFailure(WALL_ID, reason, code);
  } else {
    ref = failures.recordWallFailure(WALL_ID, reason);
  }
  assert.ok(ref, "the wall failure record must be created");
  const payload = { id: WALL_ID, ref };
  if (!omitPayloadReason) payload.reason = reason;
  await addonWall.default.onEvent("addon-wall-failed", payload, boundStore());
  return { source: addonWall.SOURCE, dedupKey: `${failures.CARD_DEDUP_PREFIX}${WALL_ID}` };
}

// ─────────────────────────────────────────────────────────────────────────────
// The cases (one per card the contract names), with their approved Spanish.
// ─────────────────────────────────────────────────────────────────────────────
const CASES = [
  {
    key: "remote-exposure/named-peer",
    source: "remote-exposure",
    dedupKey: "expose|funkwhale|peer-glasses",
    raise: () => raiseRemote({ capability: "funkwhale", peerId: "peer-glasses", peerName: "Glasses" }),
    es: {
      title: "Glasses intentó usar Música, pero todavía no se comparte con este dispositivo",
      why: "Permítelo solo para Glasses: tus otros Crows no cambian, y el permiso puede caducar o quitarse en Ajustes.",
      labels: ["Permitir durante 30 días", "Permitir durante 7 días", "Permitir hasta que yo lo quite"],
      details: [
        { label: "Capacidad:", code: "funkwhale" },
        { label: "Instancia que lo pide:", code: "peer-glasses" },
      ],
    },
  },
  {
    key: "remote-exposure/no-name",
    source: "remote-exposure",
    dedupKey: "expose|crow-memory|peer-nameless",
    raise: () => raiseRemote({ capability: "crow-memory", peerId: "peer-nameless", peerName: null }),
    es: {
      title: "Otro dispositivo intentó usar Memoria, pero todavía no se comparte con este dispositivo",
      why: "Permítelo solo para ese dispositivo: tus otros Crows no cambian, y el permiso puede caducar o quitarse en Ajustes.",
      labels: ["Permitir durante 30 días", "Permitir durante 7 días", "Permitir hasta que yo lo quite"],
      details: [
        { label: "Capacidad:", code: "crow-memory" },
        { label: "Instancia que lo pide:", code: "peer-nameless" },
      ],
    },
  },
  {
    key: "remote-exposure/crow-sharing",
    source: "remote-exposure",
    dedupKey: "expose|crow-sharing|peer-phone",
    raise: () => raiseRemote({ capability: "crow-sharing", peerId: "peer-phone", peerName: "Phone" }),
    es: {
      title: "Phone intentó usar Compartir y mensajes, pero todavía no se comparte con este dispositivo",
      why: "Permítelo solo para Phone: tus otros Crows no cambian, y el permiso puede caducar o quitarse en Ajustes.",
      labels: ["Permitir durante 30 días", "Permitir durante 7 días", "Permitir hasta que yo lo quite"],
      details: [
        { label: "Capacidad:", code: "crow-sharing" },
        { label: "Instancia que lo pide:", code: "peer-phone" },
      ],
    },
  },
  {
    key: "remote-exposure/unknown-addon",
    source: "remote-exposure",
    dedupKey: "expose|weather-station|peer-tablet",
    raise: () => raiseRemote({ capability: "weather-station", peerId: "peer-tablet", peerName: "Tablet" }),
    es: {
      title: "Tablet intentó usar weather-station, pero todavía no se comparte con este dispositivo",
      why: "Permítelo solo para Tablet: tus otros Crows no cambian, y el permiso puede caducar o quitarse en Ajustes.",
      labels: ["Permitir durante 30 días", "Permitir durante 7 días", "Permitir hasta que yo lo quite"],
      details: [
        { label: "Capacidad:", code: "weather-station" },
        { label: "Instancia que lo pide:", code: "peer-tablet" },
      ],
    },
  },
  {
    key: "boot-guard/recorder",
    source: "boot-guard",
    dedupKey: "boot-guard:did-not-run",
    raise: () => raiseBootGuard("recorder"),
    es: {
      title: "La protección de arranque no se ejecutó",
      why: "Este servicio está configurado para revertir una actualización de Crow que falla una y otra vez al arrancar (CROW_BOOT_GUARD=1), pero la parte que registra cómo terminó un arranque no se ejecutó. Nada más se ve afectado, pero una actualización defectuosa no se podría revertir automáticamente y seguiría reiniciándose. Vuelve a ejecutar el paso de instalación de la protección de arranque para este servicio (scripts/ops/install-boot-guard.sh) y luego reinícialo.",
      labels: [],
    },
  },
  {
    key: "boot-guard/launcher",
    source: "boot-guard",
    dedupKey: "boot-guard:did-not-run",
    raise: () => raiseBootGuard("launcher"),
    es: {
      title: "La protección de arranque no se ejecutó",
      why: "Este servicio está configurado para revertir una actualización de Crow que falla una y otra vez al arrancar (CROW_BOOT_GUARD=1), pero la parte que se ejecuta antes de cada arranque no se ejecutó. Nada más se ve afectado, pero una actualización defectuosa no se podría revertir automáticamente y seguiría reiniciándose. Vuelve a ejecutar el paso de instalación de la protección de arranque para este servicio (scripts/ops/install-boot-guard.sh) y luego reinícialo.",
      labels: [],
    },
  },
  {
    key: "boot-guard/other",
    source: "boot-guard",
    dedupKey: "boot-guard:did-not-run",
    raise: () => raiseBootGuard("other"),
    es: {
      title: "La protección de arranque no se ejecutó",
      why: "Este servicio está configurado para revertir una actualización de Crow que falla una y otra vez al arrancar (CROW_BOOT_GUARD=1), pero no se pudo leer su registro. Nada más se ve afectado, pero una actualización defectuosa no se podría revertir automáticamente y seguiría reiniciándose. Vuelve a ejecutar el paso de instalación de la protección de arranque para este servicio (scripts/ops/install-boot-guard.sh) y luego reinícialo.",
      labels: [],
    },
  },
  {
    key: "caddy-proxy-socket",
    source: "caddy-proxy-socket",
    dedupKey: "caddy:loopback-reverse-proxy",
    raise: () => raiseCaddyProxy(),
    es: {
      title: "Los visitantes que entran por el Caddy de este equipo están siendo rechazados",
      why: `Caddy sigue pasándolos a la puerta de enlace por una conexión loopback (bucle local) con su propio encabezado de reenvío, y Crow no puede distinguirla de cualquier otro programa de este equipo, así que Crow's Nest los rechaza. Se arregla apuntando Caddy al socket proxy propio de la puerta de enlace. Crow no se ejecuta como root, así que ejecuta esto una vez en el servidor: ${CADDY_PROXY_FIX}`,
      labels: [],
      details: [{ label: "Caddyfile:", code: "/etc/caddy/Caddyfile" }],
    },
  },
  {
    key: "caddy-admin-socket",
    source: "caddy-admin-socket",
    dedupKey: "caddy:admin-open",
    raise: () => raiseCaddyAdmin(),
    es: {
      title: "La API de administración de Caddy de este equipo está abierta a cualquier programa que se ejecute en él",
      why: `La API de administración de Caddy está en su dirección local predeterminada y sin autenticación, así que cualquier programa o bot de este equipo puede reescribir el Caddy que da acceso a Crow. Un solo comando la pasa a un socket unix que solo puede abrir el usuario de servicio del propio Caddy. Crow no se ejecuta como root, así que ejecuta esto una vez en el servidor: ${CADDY_ADMIN_FIX}`,
      labels: [],
      details: [{ label: "Caddyfile:", code: "/etc/caddy/Caddyfile" }],
    },
  },
  {
    key: "data-backend-reapproval",
    source: "data-backend-reapproval",
    dedupKey: "data-backend:legacy-approval",
    raise: () => raiseDataBackends(3),
    es: {
      title: "Hay orígenes de datos que hay que aprobar de nuevo",
      why: "3 origen(es) de datos se aprobaron antes de que Crow protegiera las aprobaciones con una clave guardada fuera de su base de datos. Siguen detenidos hasta que los apruebes de nuevo en la página de Proyectos.",
      labels: ["Abrir la página de Proyectos"],
    },
  },
  {
    key: "bundle-bind-drift/bind-wider",
    source: "bundle-bind-drift",
    dedupKey: "bundle:audiobookshelf",
    raise: () => raiseDrift("wider"),
    es: {
      title: "Reinicia Audiobookshelf para aplicar sus ajustes de red actualizados",
      why: "Audiobookshelf sigue siendo accesible en 0.0.0.0:13378 desde otros dispositivos, pero sus ajustes ahora lo limitan a este equipo. Reinícialo en la página de Extensiones para aplicarlos.",
      labels: ["Abrir Extensiones"],
    },
  },
  {
    key: "bundle-bind-drift/bind-extra",
    source: "bundle-bind-drift",
    dedupKey: "bundle:audiobookshelf",
    raise: () => raiseDrift("extra"),
    es: {
      title: "Reinicia Audiobookshelf para aplicar sus ajustes de red actualizados",
      why: "Audiobookshelf sigue siendo accesible en 0.0.0.0:9000 desde otros dispositivos, pero sus ajustes ya no publican ese puerto. Reinícialo en la página de Extensiones para aplicarlos.",
      labels: ["Abrir Extensiones"],
    },
  },
  {
    key: "bundle-compose-edited",
    source: "bundle-compose-edited",
    dedupKey: "bundle:changedetection-io",
    raise: () => raiseDrift("compose-edited"),
    es: {
      title: "El archivo de ajustes de Changedetection.io tiene cambios locales",
      why: "El archivo de ajustes de Changedetection.io (docker-compose.yml) tiene cambios locales, así que Crow no lo actualizó. Pasa tus cambios a docker-compose.override.yml y restaura el archivo de ajustes (cuando Crow lo restaura, guarda una copia del actual como docker-compose.yml.bak).",
      labels: ["Restaurar el compose de Crow", "Abrir Extensiones"],
    },
  },
  {
    key: "bundle-repo-bind-drift/edited",
    source: "bundle-repo-bind-drift",
    dedupKey: "bundle:audiobookshelf:repo",
    raise: () => raiseDrift("repo-edited"),
    es: {
      title: "Audiobookshelf sigue publicado en otros dispositivos",
      why: "Audiobookshelf está publicado en otros dispositivos; Crow ahora lo entrega solo en este equipo. Reiniciarlo no cambiará eso mientras su archivo de ajustes tenga cambios locales: mira la otra tarjeta.",
      labels: ["Abrir Extensiones"],
    },
  },
  {
    key: "bundle-repo-bind-drift/unknown",
    source: "bundle-repo-bind-drift",
    dedupKey: "bundle:audiobookshelf:repo",
    raise: () => raiseDrift("repo-unknown"),
    es: {
      title: "Audiobookshelf sigue publicado en otros dispositivos",
      why: "Audiobookshelf está publicado en otros dispositivos; Crow ahora lo entrega solo en este equipo. Reiniciarlo no cambiará eso mientras Crow no pueda saber si el archivo de ajustes instalado tiene cambios locales.",
      labels: ["Abrir Extensiones"],
    },
  },
  {
    key: "bundle-compose-needs-config",
    source: "bundle-compose-needs-config",
    dedupKey: "bundle:vikunja",
    raise: () => raiseDrift("needs-config"),
    es: {
      title: "No se actualizó el archivo de ajustes de Vikunja",
      why: "Crow no pudo actualizar el archivo de ajustes de Vikunja: primero hay que configurar VIKUNJA_DB_PASSWORD (Configurar, en su tarjeta de Extensiones).",
      labels: ["Abrir Extensiones"],
    },
  },
  {
    key: "bundle-compose-image-change/added",
    source: "bundle-compose-image-change",
    dedupKey: "bundle:vikunja",
    raise: () => raiseDrift("image-added"),
    es: {
      title: "El archivo de ajustes de Vikunja tiene una actualización que Crow no aplicó",
      why: "Crow mantiene Vikunja con sus ajustes actuales porque la actualización también añadiría un paso auxiliar \"vikunja-volume-owner\" que usa la imagen \"busybox:1.38.0@sha256:a46257e0\". Haz una copia de seguridad de sus datos y luego pulsa «Aplicar la actualización» para cambiar, o déjalo como está.",
      labels: ["Aplicar la actualización", "Abrir Extensiones"],
    },
  },
  {
    key: "bundle-compose-image-change/removed",
    source: "bundle-compose-image-change",
    dedupKey: "bundle:vikunja",
    raise: () => raiseDrift("image-removed"),
    es: {
      title: "El archivo de ajustes de Vikunja tiene una actualización que Crow no aplicó",
      why: "Crow mantiene Vikunja con sus ajustes actuales porque la actualización también quitaría el paso \"web-legacy-helper\". Haz una copia de seguridad de sus datos y luego pulsa «Aplicar la actualización» para cambiar, o déjalo como está.",
      labels: ["Aplicar la actualización", "Abrir Extensiones"],
    },
  },
  {
    key: "bundle-compose-image-change/swapped",
    source: "bundle-compose-image-change",
    dedupKey: "bundle:vikunja",
    raise: () => raiseDrift("image-swapped"),
    es: {
      title: "El archivo de ajustes de Vikunja tiene una actualización que Crow no aplicó",
      why: "Crow mantiene Vikunja con sus ajustes actuales porque la actualización también cambiaría su imagen (vikunja/vikunja:0.24.6 → vikunja/vikunja:0.25.1; puede ser más antigua que la que se está ejecutando). La actualización también restringe cómo se publica Vikunja. Haz una copia de seguridad de sus datos y luego pulsa «Aplicar la actualización» para cambiar, o déjalo como está.",
      labels: ["Aplicar la actualización", "Abrir Extensiones"],
    },
  },
  {
    key: "bundle-compose-image-change/swapped-none",
    source: "bundle-compose-image-change",
    dedupKey: "bundle:vikunja",
    raise: () => raiseDrift("image-swapped-none"),
    es: {
      title: "El archivo de ajustes de Vikunja tiene una actualización que Crow no aplicó",
      why: "Crow mantiene Vikunja con sus ajustes actuales porque la actualización también cambiaría su imagen (ninguna → ninguna; puede ser más antigua que la que se está ejecutando). La actualización también restringe cómo se publica Vikunja. Haz una copia de seguridad de sus datos y luego pulsa «Aplicar la actualización» para cambiar, o déjalo como está.",
      labels: ["Aplicar la actualización", "Abrir Extensiones"],
    },
  },
  {
    key: "browser-image-stale/version-known",
    source: "browser-image-stale",
    dedupKey: "bundle:browser:image-stale",
    raise: () => raiseBrowserImageStale("version-known"),
    es: {
      title: "El complemento del navegador sigue ejecutando la versión anterior",
      why: "Crow actualizó el complemento del navegador, pero la copia que está en marcha sigue siendo la anterior. Reinícialo para cargar la actualización. Un reinicio no se puede deshacer, y las páginas que están abiertas ahora en el navegador se cerrarán. Los inicios de sesión y las cookies guardados se conservan. En marcha ahora: versión 1.9.2. La actualización instalaría la versión 1.9.4.",
      labels: ["Reiniciar el complemento del navegador", "Abrir Extensiones"],
    },
  },
  {
    key: "browser-image-stale/version-unknown",
    source: "browser-image-stale",
    dedupKey: "bundle:browser:image-stale",
    raise: () => raiseBrowserImageStale("version-unknown"),
    es: {
      title: "El complemento del navegador sigue ejecutando la versión anterior",
      why: "Crow actualizó el complemento del navegador, pero la copia que está en marcha sigue siendo la anterior. Reinícialo para cargar la actualización. Un reinicio no se puede deshacer, y las páginas que están abiertas ahora en el navegador se cerrarán. Los inicios de sesión y las cookies guardados se conservan. En marcha ahora: una versión anterior que no indica su número. La actualización instalaría la versión 1.9.4.",
      labels: ["Reiniciar el complemento del navegador", "Abrir Extensiones"],
    },
  },
  {
    key: "browser-image-stale/no-version",
    source: "browser-image-stale",
    dedupKey: "bundle:browser:image-stale",
    raise: () => raiseBrowserImageStale("no-version"),
    es: {
      title: "El complemento del navegador sigue ejecutando la versión anterior",
      why: "Crow actualizó el complemento del navegador, pero la copia que está en marcha sigue siendo la anterior. Reinícialo para cargar la actualización. Un reinicio no se puede deshacer, y las páginas que están abiertas ahora en el navegador se cerrarán. Los inicios de sesión y las cookies guardados se conservan.",
      labels: ["Reiniciar el complemento del navegador", "Abrir Extensiones"],
    },
  },
  {
    key: "addon-keys",
    source: "addon-keys",
    dedupKey: "addon-keys-unreadable",
    raise: () => raiseAddonKeys(),
    es: {
      title: "No se pueden leer las claves guardadas de los complementos",
      why: "Falta la clave del llavero de Crow, así que no se guardó esta clave. Primero restaura la clave del llavero o importa una exportación del llavero.",
      labels: [],
    },
  },
  ...WALL_REASONS.map((reason) => ({
    key: reason.key,
    source: "addon-wall",
    dedupKey: `addon-wall:${WALL_ID}`,
    raise: () => raiseWall(reason.args, { omitPayloadReason: reason.args === null }),
    es: {
      title: "Un complemento no pudo ejecutarse dentro de su aislamiento",
      why: `${WALL_ID} ${reason.es}. Seguirá apagado hasta que decidas.`,
      labels: [`Ejecutar ${WALL_ID} sin aislamiento`, "Mantenerlo apagado"],
    },
  })),
];

/**
 * The ONLY differences an English card may show against the captured baseline:
 * the operator-approved English bug fixes of 2026-11-22 (BUG 1, BUG 2, BUG 3).
 * Everything else must stay byte-identical.
 */
function approvedEnFixes() {
  const wallWhy = (reason) => fill(t("fixit.addonWall.why", "en"), { id: WALL_ID, reason });
  return {
    // BUG 1 — the no-name device title (its why keeps "Allow it for another device
    // only — …", which is already grammatical).
    "remote-exposure/no-name": {
      title: "Another device tried to use Memory, but it isn't shared with this device yet",
    },
    // BUG 3 — "settings file" everywhere, and the edited card now names the file.
    "bundle-compose-edited": {
      title: "Changedetection.io's settings file has local changes",
      why: "Changedetection.io's settings file (docker-compose.yml) has local changes, so Crow did not update it. "
        + "Move your changes into docker-compose.override.yml and restore the settings file (a copy of the current one is kept as docker-compose.yml.bak when Crow restores it).",
    },
    "bundle-repo-bind-drift/edited": {
      why: "Audiobookshelf is published to other devices; Crow now ships it on this computer only. "
        + "Restart won't change that while its settings file has local changes — see the other card.",
    },
    "bundle-repo-bind-drift/unknown": {
      why: "Audiobookshelf is published to other devices; Crow now ships it on this computer only. "
        + "Restart won't change that while Crow cannot tell whether the installed settings file has local changes.",
    },
    // BUG 2 — the doubled subject in the two wall reasons.
    "addon-wall/refused": {
      why: wallWhy("could not be set up inside its wall on this computer"),
    },
    "addon-wall/installed-changed": {
      why: wallWhy("has installed files that changed; reinstall it to wall it"),
    },
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// The one pass: raise every case, read it back in both languages.
// ─────────────────────────────────────────────────────────────────────────────
async function raiseEverything() {
  const out = new Map();
  for (const c of CASES) {
    await resetForCase();
    const at = await c.raise();
    assert.equal(at.source, c.source, `${c.key}: the detector raised under another source`);
    assert.equal(at.dedupKey, c.dedupKey, `${c.key}: the detector raised under another dedup key`);
    const en = await readModel(c.source, c.dedupKey, "en");
    const es = await readModel(c.source, c.dedupKey, "es");
    out.set(c.key, { en: modelShape(en), es: modelShape(es) });
  }
  await resetForCase();
  return out;
}

// ─────────────────────────────────────────────────────────────────────────────
// 1. Capture / EN byte-identity
// ─────────────────────────────────────────────────────────────────────────────
test("capture mode writes the EN baseline from what the code renders now", async (t) => {
  if (!CAPTURE) {
    t.skip("CAPTURE_EN_BASELINE is not 1 (normal runs compare against the fixture)");
    return;
  }
  const raised = await raiseEverything();
  const baseline = {};
  for (const key of [...raised.keys()].sort()) baseline[key] = portable(raised.get(key).en);
  mkdirSync(dirname(FIXTURE), { recursive: true });
  writeFileSync(FIXTURE, `${JSON.stringify(stable(baseline), null, 2)}\n`);
});

test("EN byte-identity: every card renders the baseline, apart from the approved English fixes", async (t) => {
  if (CAPTURE) {
    t.skip("capture mode writes the fixture and compares nothing");
    return;
  }
  assert.ok(existsSync(FIXTURE),
    `the EN baseline ${FIXTURE} is missing — generate it once on the unchanged tree with `
    + "CAPTURE_EN_BASELINE=1 node --test tests/fix-it-card-render.test.js");
  const baseline = JSON.parse(readFileSync(FIXTURE, "utf8"));
  const raised = await raiseEverything();
  const fixes = approvedEnFixes();

  assert.deepEqual([...raised.keys()].sort(), Object.keys(baseline).sort(),
    "the captured baseline must cover exactly the cases this file raises");

  for (const [key, { en }] of raised) {
    const expected = baseline[key];
    const approved = fixes[key] || {};
    const actual = portable(en);
    const title = approved.title ?? expected.title;
    const why = approved.why ?? expected.why;
    assert.equal(actual.title, title, `${key}: English title`);
    assert.equal(actual.why, why, `${key}: English body`);
    // English button labels and the code-held link targets do NOT change.
    assert.deepEqual(actual.remedies, expected.remedies, `${key}: English remedies`);
    assert.deepEqual(actual.details, expected.details, `${key}: English details`);
  }

  for (const [key, fields] of Object.entries(fixes)) {
    assert.ok(baseline[key], `APPROVED_EN_FIXES names "${key}", which the baseline does not contain`);
    for (const [field, value] of Object.entries(fields)) {
      assert.notEqual(value, baseline[key][field],
        `${key}: APPROVED_EN_FIXES.${field} is identical to the baseline — it is not a fix, drop it`);
    }
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 2. Spanish, and the Technical-details labels
// ─────────────────────────────────────────────────────────────────────────────
test("ES: every card renders the approved Spanish, with the existing details labels", async () => {
  const raised = await raiseEverything();
  for (const c of CASES) {
    const { en, es } = raised.get(c.key);
    assert.equal(es.title, c.es.title, `${c.key}: ES title`);
    assert.equal(es.why, c.es.why, `${c.key}: ES body`);
    assert.deepEqual(es.remedies.map((r) => r.label), c.es.labels, `${c.key}: ES button labels`);
    // A button keeps its action (or its code-held link) across languages.
    assert.deepEqual(es.remedies.map((r) => [r.kind, r.actionId ?? r.href]),
      en.remedies.map((r) => [r.kind, r.actionId ?? r.href]),
      `${c.key}: the ES buttons post to the same actions as the EN ones`);
    if (c.es.details) {
      assert.deepEqual(es.details, c.es.details, `${c.key}: ES Technical details`);
    } else {
      assert.deepEqual(es.details, en.details, `${c.key}: Technical details without a translated label`);
    }
  }
});

test("ES: the unchanged dashboard labels the cards share stay exactly as they are", () => {
  const expected = {
    "fixit.notNow": ["Not now", "Ahora no"],
    "fixit.technicalDetails": ["Technical details", "Detalles técnicos"],
    "fixit.capability": ["Capability:", "Capacidad:"],
    "fixit.requestingInstance": ["Requesting instance:", "Instancia que lo pide:"],
    "fixit.caddyfile": ["Caddyfile:", "Caddyfile:"],
  };
  for (const [key, [en, es]] of Object.entries(expected)) {
    assert.equal(t(key, "en"), en, `${key} must keep its English`);
    assert.equal(t(key, "es"), es, `${key} must keep its approved Spanish`);
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// 3. Legacy rows, fallbacks, escaping
// ─────────────────────────────────────────────────────────────────────────────
/**
 * The baseline case that stands for one in-scope source in the legacy-row test.
 * The add-on wall is deliberately absent: that card is CODE-HELD (it renders the
 * live failure record, never the row), so it has no legacy text to fall back to —
 * the same reason retired-bundle and sharing-bot-acl are out of scope.
 */
const LEGACY_SAMPLES = [
  { source: "remote-exposure", caseKey: "remote-exposure/named-peer" },
  { source: "boot-guard", caseKey: "boot-guard/recorder" },
  { source: "caddy-proxy-socket", caseKey: "caddy-proxy-socket" },
  { source: "caddy-admin-socket", caseKey: "caddy-admin-socket" },
  { source: "data-backend-reapproval", caseKey: "data-backend-reapproval" },
  { source: "bundle-bind-drift", caseKey: "bundle-bind-drift/bind-wider" },
  { source: "bundle-compose-edited", caseKey: "bundle-compose-edited" },
  { source: "bundle-repo-bind-drift", caseKey: "bundle-repo-bind-drift/edited" },
  { source: "bundle-compose-needs-config", caseKey: "bundle-compose-needs-config" },
  { source: "bundle-compose-image-change", caseKey: "bundle-compose-image-change/swapped" },
  { source: "browser-image-stale", caseKey: "browser-image-stale/version-known" },
  { source: "addon-keys", caseKey: "addon-keys" },
];

function readBaseline() {
  assert.ok(existsSync(FIXTURE),
    `the EN baseline ${FIXTURE} is missing — generate it once with CAPTURE_EN_BASELINE=1 node --test tests/fix-it-card-render.test.js`);
  return JSON.parse(readFileSync(FIXTURE, "utf8"));
}

test("legacy rows (no context.card) render their stored English text in every language", async () => {
  const baseline = readBaseline();
  // A link remedy stores only its actionId; the href is code-held (LINK_REMEDIES).
  const hrefToAction = Object.fromEntries(Object.entries(idx.LINK_REMEDIES).map(([id, href]) => [href, id]));
  await resetForCase();
  const ids = new Map();
  for (const sample of LEGACY_SAMPLES) {
    const shape = baseline[sample.caseKey];
    assert.ok(shape, `the baseline has no entry "${sample.caseKey}"`);
    const { id } = await store.upsertItem(db, {
      source: sample.source,
      dedupKey: `legacy:${sample.source}`,
      title: shape.title,
      why: shape.why,
      severity: "warn",
      remedies: shape.remedies.map((r) => ({
        kind: r.kind,
        label: r.label,
        actionId: r.actionId ?? (r.href ? hrefToAction[r.href] : undefined),
      })),
      // No `card`: the shape every row written before this change has.
      context: null,
    });
    ids.set(sample.source, id);
  }

  for (const lang of ["en", "es"]) {
    const models = await idx.fixItCardModels(db, { lang });
    for (const sample of LEGACY_SAMPLES) {
      const shape = baseline[sample.caseKey];
      const model = models.find((m) => m.id === ids.get(sample.source));
      assert.ok(model, `${lang}: the legacy ${sample.source} row is not modelled`);
      assert.equal(model.title, shape.title, `${lang}: a legacy ${sample.source} row renders its stored title`);
      assert.equal(model.why, shape.why, `${lang}: a legacy ${sample.source} row renders its stored body`);
      assert.deepEqual(model.remedies.map((r) => r.label), shape.remedies.map((r) => r.label),
        `${lang}: a legacy ${sample.source} row keeps its stored button labels`);
    }
  }
  await resetForCase();
});

test("a malformed or unknown context.card falls back to the stored text", async () => {
  // A real card first: its stored context.card gives us the code the renderer knows.
  await resetForCase();
  await raiseRemote({ capability: "funkwhale", peerId: "peer-glasses", peerName: "Glasses" });
  const real = await pendingRow("remote-exposure", "expose|funkwhale|peer-glasses");
  assert.ok(real?.context?.card, "the detector must store context.card (the card's code + values)");
  const card = real.context.card;

  const variants = [
    ["an unknown code", { card: { code: "no-such-fixit-card", values: {} } }],
    ["values that are not an object", { card: { code: card.code, values: "not an object" } }],
    ["values of the wrong types", { card: { code: card.code, values: { ...card.values, peer: { nested: true }, capability: 42 } } }],
    ["no values at all", { card: { code: card.code } }],
  ];
  for (const [index, [what, context]] of variants.entries()) {
    const dedupKey = `fallback-${index}`;
    await store.upsertItem(db, {
      source: "remote-exposure",
      dedupKey,
      title: "Stored title",
      why: "Stored body",
      severity: "warn",
      remedies: [{ actionId: "expose-capability-30d", kind: "instant", label: "Stored button" }],
      context,
    });
    for (const lang of ["en", "es"]) {
      const models = await idx.fixItCardModels(db, { lang });
      const row = (await store.listPending(db)).find((r) => r.dedupKey === dedupKey);
      const model = models.find((m) => m.id === row.id);
      assert.equal(model.title, "Stored title", `${lang}: ${what} falls back to the stored title`);
      assert.equal(model.why, "Stored body", `${lang}: ${what} falls back to the stored body`);
      assert.deepEqual(model.remedies.map((r) => r.label), ["Stored button"],
        `${lang}: ${what} keeps the stored button label`);
    }
    await db.execute({ sql: "DELETE FROM fix_it_items WHERE dedup_key = ?", args: [dedupKey] });
  }
  await resetForCase();
});

test("a context.card's unknown extra value names are ignored", async () => {
  await resetForCase();
  await raiseRemote({ capability: "funkwhale", peerId: "peer-glasses", peerName: "Glasses" });
  const en = modelShape(await readModel("remote-exposure", "expose|funkwhale|peer-glasses", "en"));
  const real = await pendingRow("remote-exposure", "expose|funkwhale|peer-glasses");
  assert.ok(real?.context?.card, "the detector must store context.card (the card's code + values)");
  const card = real.context.card;

  await store.upsertItem(db, {
    source: "remote-exposure",
    dedupKey: "extra-values",
    title: "Stored title",
    why: "Stored body",
    severity: "warn",
    remedies: [],
    context: {
      capability: card.values.capability,
      requestingInstance: card.values.requestingInstance,
      card: { code: card.code, values: { ...card.values, bogus: "<script>alert(1)</script>", anotherIgnored: "x" } },
    },
  });
  const extraRow = await pendingRow("remote-exposure", "extra-values");
  assert.ok(extraRow, "the tampered row is pending");
  const model = (await idx.fixItCardModels(db, { lang: "en" })).find((m) => m.id === extraRow.id);
  assert.equal(model.title, en.title, "an unknown value name cannot change the title");
  assert.equal(model.why, en.why, "an unknown value name cannot change the body");
  assert.equal(JSON.stringify(model).includes("script"), false, "an unknown value never reaches the card");
  await resetForCase();
});

test("a stored capability id that names an Object member renders as the id itself", async () => {
  // "constructor" is an own property of Object.prototype, not of the friendly-name
  // map: the lookup must miss (Object.hasOwn) and fall through to the id, not
  // splice `function Object() { [native code] }` into the title.
  await resetForCase();
  await raiseRemote({ capability: "constructor", peerId: "peer-glasses", peerName: "Glasses" });
  const row = await pendingRow("remote-exposure", "expose|constructor|peer-glasses");
  assert.ok(row?.context?.card, "the detector stored the card's code + values");
  assert.equal(row.context.card.values.capability, "constructor", "the row carries the capability id as a value");

  for (const lang of ["en", "es"]) {
    const model = await readModel("remote-exposure", "expose|constructor|peer-glasses", lang);
    assert.ok(model.title.includes("constructor"), `${lang}: the title names the id itself: ${model.title}`);
    assert.equal(/function Object|native code/.test(model.title), false,
      `${lang}: a prototype member never reaches the title: ${model.title}`);
  }
  await resetForCase();
});

test("a peer name is escaped by the renderers, exactly like today", async () => {
  await resetForCase();
  await raiseRemote({ capability: "funkwhale", peerId: "peer-markup", peerName: "<b>x</b>" });
  assert.ok((await pendingRow("remote-exposure", "expose|funkwhale|peer-markup")), "the card was raised");

  const html = await idx.renderFixItCards(db, { lang: "es" });
  const escaped = escapeHtml("<b>x</b>");
  assert.ok(html.includes(escaped), `the peer name must land in the card escaped (${escaped})`);
  assert.equal(html.includes("<b>x</b>"), false, "no raw markup from a peer name reaches the page");
  await resetForCase();
});

// ─────────────────────────────────────────────────────────────────────────────
// 4. The caddy fix command is code, not crow.db
// ─────────────────────────────────────────────────────────────────────────────
test("the caddy card's fix command is recomputed from code, never read from context", async () => {
  assert.equal(caddyProxy.appRoot(), REPO, "the app root the renderer must build the command from");
  await resetForCase();
  await raiseCaddyProxy();
  const row = await pendingRow("caddy-proxy-socket", "caddy:loopback-reverse-proxy");
  assert.ok(row?.context?.card, "the caddy detector must store context.card");
  const tampered = {
    ...row.context,
    card: { ...row.context.card, values: { ...row.context.card.values, fixCommand: "rm -rf /" } },
  };
  await db.execute({
    sql: "UPDATE fix_it_items SET context = ? WHERE id = ?",
    args: [JSON.stringify(tampered), row.id],
  });

  for (const lang of ["en", "es"]) {
    const models = await idx.fixItCardModels(db, { lang });
    const model = models.find((m) => m.id === row.id);
    assert.equal(JSON.stringify(model).includes("rm -rf /"), false,
      `${lang}: a stored fixCommand is never rendered`);
    assert.ok(model.why.includes(CADDY_PROXY_FIX),
      `${lang}: the card carries the command the code builds (${CADDY_PROXY_FIX})`);
  }
  await resetForCase();
});

// ─────────────────────────────────────────────────────────────────────────────
// 5. A re-raise rewrites an old-style row
// ─────────────────────────────────────────────────────────────────────────────
test("re-raising a card rewritten by a detector stores context.card", async () => {
  await resetForCase();
  await store.upsertItem(db, {
    source: "boot-guard",
    dedupKey: "boot-guard:did-not-run",
    title: "The boot guard did not run",
    why: "stored body",
    severity: "warn",
    remedies: [],
    context: { reason: "launcher" },
  });
  await raiseBootGuard("launcher");
  const row = await pendingRow("boot-guard", "boot-guard:did-not-run");
  assert.ok(row, "the detector's upsert reopened the same card");
  assert.ok(row.context?.card, "the re-raise rewrote context and stored the card's code + values");
  assert.equal(row.count, 2, "the re-raise bumped the existing row, it did not insert a second one");
  await resetForCase();
});

// ─────────────────────────────────────────────────────────────────────────────
// 6. The add-on wall's reason codes
// ─────────────────────────────────────────────────────────────────────────────
/** Values compare by their text: the set is strings/numbers/null, never a shape. */
const valueText = (value) => {
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.keys(value).sort().map((key) => [key, valueText(value[key])]));
  }
  return value == null ? "" : String(value);
};

test("wallFailureReasonCode returns the documented {code, values} for every reason", () => {
  assert.equal(typeof failures.wallFailureReasonCode, "function",
    "scripts/addon-sandbox/failures.mjs must export wallFailureReasonCode(sameArgs)");
  for (const reason of WALL_REASONS) {
    if (reason.args === null) continue; // W11 is the event's no-reason fallback, not a function input
    const got = failures.wallFailureReasonCode(reason.args);
    assert.equal(typeof got?.code, "string", `${reason.key}: the code`);
    assert.equal(got.code, reason.shape.code, `${reason.key}: the reason code`);
    if (!reason.detail) {
      // No nested detail: "warmup alone" renders the one sentence (a warmup that
      // left no evidence collapses to W3, as wallFailureReason already does).
      assert.deepEqual(valueText(got.values ?? {}), {}, `${reason.key}: no values`);
      continue;
    }
    // The nested detail repeats the same evidence codes (the contract's prose
    // list is descriptive; accept its wordings for the open() variants).
    const detail = got.values?.detail;
    assert.ok(detail, `${reason.key}: the warmup detail is nested under values.detail`);
    assert.deepEqual(Object.keys(got.values).sort(), ["detail"], `${reason.key}: only values.detail`);
    assert.ok(reason.detail.codes.includes(detail.code),
      `${reason.key}: nested code "${detail.code}" is not one of ${reason.detail.codes.join(", ")}`);
    assert.deepEqual(valueText(detail.values ?? {}), valueText(reason.detail.values),
      `${reason.key}: the nested values`);
  }
});

test("wallFailureReason still returns the English sentence each code renders", () => {
  for (const reason of WALL_REASONS) {
    if (reason.args === null) continue;
    assert.equal(failures.wallFailureReason(reason.args), reason.en, `${reason.key}: the English sentence`);
  }
});

test("the stored English is the card's own English for the same {code, values}", () => {
  // The one-copy rule: wallFailureReason(args) must be exactly what the card
  // renders (renderWallReason) for wallFailureReasonCode(args) in English. A
  // wording change in either place (the constants in failures.mjs, the i18n
  // table, the card's renderer) breaks here instead of shipping two sentences.
  for (const reason of WALL_REASONS) {
    if (reason.args === null) continue;
    const code = failures.wallFailureReasonCode(reason.args);
    assert.equal(
      failures.wallFailureReason(reason.args),
      cardCopy.renderWallReason(code, "en"),
      `${reason.key}: wallFailureReason(args) must be the card's EN rendering of wallFailureReasonCode(args)`,
    );
  }

  // Every code, and both shapes of a nested warmup detail (`values.detail`, and
  // the evidence fields beside `code`), render the same sentence on both sides.
  const shapes = [
    { code: "refused", values: {} },
    { code: "installed-changed", values: {} },
    { code: "warmup", values: {} },
    { code: "warmup", values: { detail: { code: "denied", values: { target: "192.0.2.9:80" } } } },
    { code: "warmup", values: { detail: { code: "denied", target: "an address" } } },
    { code: "warmup", values: { detail: { code: "open", values: { rel: "data/secret.txt" } } } },
    { code: "warmup", values: { detail: { code: "open-folder", values: {} } } },
    { code: "warmup", values: { detail: { code: "open-outside", values: {} } } },
    { code: "warmup", values: { detail: { code: "exit-code", values: { exitCode: 7 } } } },
    { code: "not-ready", values: {} },
    { code: "denied", values: { target: "192.0.2.9:80" } },
    { code: "denied", values: { target: "an address" } },
    { code: "open", values: { rel: "data/secret.txt" } },
    { code: "open-folder", values: {} },
    { code: "open-outside", values: {} },
    { code: "exit-code", values: { exitCode: 7 } },
    { code: "default", values: {} },
  ];
  for (const shape of shapes) {
    const nested = shape.values?.detail ? ` / ${shape.values.detail.code}` : "";
    assert.equal(
      failures.renderWallReasonEnglish(shape),
      cardCopy.renderWallReason(shape, "en"),
      `${shape.code}${nested}: the two English renderings of one code`,
    );
  }
});

test("the keychain refusal is the add-on-keys card's English why, one copy", async () => {
  // KEY_SAVE_REFUSED stays the English message the thrown error carries, and the
  // card shows that same sentence (from fixit.card.addonKeys.why). Pinning the
  // pair here is what stops the two copies drifting apart.
  assert.equal(typeof seal.KEY_SAVE_REFUSED, "string", "the refusal stays a string error message");
  assert.equal(seal.KEY_SAVE_REFUSED, t("fixit.card.addonKeys.why", "en"),
    "the refusal message and the card's EN why come from one sentence");
  assert.equal(cardCopy.cardText("addon-keys-unreadable", {}, "en").why, seal.KEY_SAVE_REFUSED,
    "cardText renders the refusal sentence");

  await resetForCase();
  await raiseAddonKeys();
  const en = await readModel("addon-keys", seal.ADDON_KEY_CARD_KEY, "en");
  assert.equal(en.why, seal.KEY_SAVE_REFUSED, "the stored card's EN why is the refusal message");
  await resetForCase();
});

test("the no-reason default is the approved English and Spanish fallback (W11)", async () => {
  assert.equal(addonWall.DEFAULT_REASON, "could not run inside its wall",
    "the event's no-reason fallback is the approved W11 English");
  await resetForCase();
  await raiseWall(null, { omitPayloadReason: true });
  const en = await readModel("addon-wall", `addon-wall:${WALL_ID}`, "en");
  const es = await readModel("addon-wall", `addon-wall:${WALL_ID}`, "es");
  assert.equal(en.why, fill(t("fixit.addonWall.why", "en"), { id: WALL_ID, reason: "could not run inside its wall" }));
  assert.equal(es.why, fill(t("fixit.addonWall.why", "es"), { id: WALL_ID, reason: "no pudo ejecutarse dentro de su aislamiento" }));
  await resetForCase();
});

// ─────────────────────────────────────────────────────────────────────────────
// 7. i18n
// ─────────────────────────────────────────────────────────────────────────────
test("i18n: the card-copy namespaces exist in both languages with the same placeholders", () => {
  const keys = Object.keys(translations).filter((key) => (
    key.startsWith("fixit.card.") || key.startsWith("fixit.wall.reason.")
  ));
  const cardKeys = keys.filter((key) => key.startsWith("fixit.card."));
  const wallKeys = keys.filter((key) => key.startsWith("fixit.wall.reason."));
  assert.ok(cardKeys.length > 0, "card-copy must add its sentences under fixit.card.*");
  // W1-W5 and W7-W11 are whole sentences; W6 ("an address") may live as a
  // value rather than a key, so ten is the floor.
  assert.ok(wallKeys.length >= 10, "every wall reason (W1-W11) must live under fixit.wall.reason.*");

  const placeholders = (text) => [...new Set(String(text).match(/\{[a-zA-Z0-9_]+\}/g) || [])].sort();
  for (const key of keys) {
    assert.equal(typeof translations[key]?.en, "string", `${key} has no English`);
    assert.equal(typeof translations[key]?.es, "string", `${key} has no Spanish`);
    assert.deepEqual(placeholders(translations[key].en), placeholders(translations[key].es),
      `${key}: the placeholder sets differ between en and es`);
  }
});

test("i18n: no ES card is left showing the English sentence", async () => {
  const raised = await raiseEverything();
  const englishMarkers = [/ the /i, / is /i, / are /i, / will /i, / your /i, / could not /i, / is still /i, /does not/i];
  for (const c of CASES) {
    const { en, es } = raised.get(c.key);
    assert.notEqual(es.title, en.title, `${c.key}: the ES title is still the English one`);
    assert.notEqual(es.why, en.why, `${c.key}: the ES body is still the English one`);
    for (const [field, text] of [["title", es.title], ["why", es.why]]) {
      for (const marker of englishMarkers) {
        assert.equal(marker.test(text), false, `${c.key}: the ES ${field} carries English text (${marker}): ${text}`);
      }
    }
  }
});

// ─────────────────────────────────────────────────────────────────────────────
// Coverage guard: every in-scope source is raised by a case
// ─────────────────────────────────────────────────────────────────────────────
test("the cases cover every in-scope card source", () => {
  const expected = new Set([
    "remote-exposure",
    "boot-guard",
    "caddy-proxy-socket",
    "caddy-admin-socket",
    "data-backend-reapproval",
    "bundle-bind-drift",
    "bundle-compose-edited",
    "bundle-repo-bind-drift",
    "bundle-compose-needs-config",
    "bundle-compose-image-change",
    "browser-image-stale",
    "addon-keys",
    "addon-wall",
  ]);
  const covered = new Set(CASES.map((c) => c.source));
  for (const source of expected) {
    assert.ok(covered.has(source), `no case raises the "${source}" card`);
  }
  assert.deepEqual([...covered].filter((s) => !expected.has(s)), [], "a case raises a source that is not in scope");
});

test("a capability the gate could not match raises no card at all", async () => {
  await resetForCase();
  const suppressed = [];
  const s = { ...boundStore(), recordSuppressed: (info) => { suppressed.push(info); } };
  await remote.default.onEvent("peer-exposure:denied", {
    capability: "some-tool-name",
    capabilityKnown: false,
    requestingInstance: "peer-glasses",
    requestingInstanceName: "Glasses",
  }, s);
  assert.deepEqual(await store.listPending(db), [], "an unknown capability must never become a card");
  assert.equal(suppressed.length, 1, "it is counted instead (one bucket per peer)");
  await resetForCase();
});