// Project workspace pins: the real path of each project's workspace recorded outside crow.db, and the
// no-database spawn that refuses a row that disagrees with it. Scratch CROW_HOME only.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, symlinkSync, chmodSync, existsSync, statSync, readFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import Database from "../node_modules/better-sqlite3/lib/index.js";

const T = realpathSync(mkdtempSync(join(tmpdir(), "crow-wspin-")));
after(() => rmSync(T, { recursive: true, force: true }));
const mk = (...p) => { const d = join(...p); mkdirSync(d, { recursive: true }); return d; };
const newHome = (name) => { const h = mk(T, name, "home"); chmodSync(h, 0o700); return h; };

const {
  pinProjectWorkspace, readWorkspacePin, readWorkspacePins, workspacePinsPath,
} = await import("../servers/shared/project-workspace-pins.js");
const { runProjectWorkspacePinBackfill } = await import("../servers/gateway/boot/project-workspace-pin-backfill.js");

test("store: pin stores the REALPATH, compared through a symlinked data dir", () => {
  const home = newHome("a");
  const realData = mk(T, "a", "real-data");
  const linkData = join(T, "a", "link-data");
  symlinkSync(realData, linkData);
  const ws = mk(realData, "projects", "p-1", "workspace");
  const r = pinProjectWorkspace(1, join(linkData, "projects", "p-1", "workspace"), { crowHome: home, dataDir: linkData });
  assert.equal(r.ok, true);
  assert.equal(readWorkspacePin(1, { crowHome: home }), ws);
  assert.equal((statSync(workspacePinsPath(home)).mode & 0o777), 0o600);
  assert.equal(pinProjectWorkspace(1, ws, { crowHome: home, dataDir: realData }).ok, true, "same path again is a no-op");
});

test("store: never overwrites a different pin; refuses a workspace not strictly below projects/", () => {
  const home = newHome("b");
  const data = mk(T, "b", "data");
  const w1 = mk(data, "projects", "one", "workspace");
  const w2 = mk(data, "projects", "two", "workspace");
  assert.equal(pinProjectWorkspace(5, w1, { crowHome: home, dataDir: data }).ok, true);
  const r = pinProjectWorkspace(5, w2, { crowHome: home, dataDir: data });
  assert.deepEqual(r, { ok: false, reason: "pinned-elsewhere" });
  assert.equal(readWorkspacePin(5, { crowHome: home }), w1);
  for (const bad of [data, join(data, "projects"), mk(data, "secrets")]) {
    assert.equal(pinProjectWorkspace(6, bad, { crowHome: home, dataDir: data }).ok, false);
  }
  assert.equal(readWorkspacePin(6, { crowHome: home }), null);
});

test("store: unsafe files mean no pins plus a reason, and a faulty store is never overwritten", () => {
  const data = mk(T, "c", "data");
  const ws = mk(data, "projects", "p", "workspace");
  const cases = {
    group: (home, f) => { writeFileSync(f, '{"version":1,"pins":{"1":{"path":"/x"}}}'); chmodSync(f, 0o640); },
    symlink: (home, f) => { const t = join(home, "t.json"); writeFileSync(t, '{"version":1,"pins":{"1":{"path":"/x"}}}', { mode: 0o600 }); symlinkSync(t, f); },
    oversize: (home, f) => { writeFileSync(f, " ".repeat(5 * 1024 * 1024), { mode: 0o600 }); },
    garbage: (home, f) => { writeFileSync(f, "nope", { mode: 0o600 }); },
  };
  for (const [name, setup] of Object.entries(cases)) {
    const home = newHome("c-" + name);
    mk(home, "secrets"); chmodSync(join(home, "secrets"), 0o700);
    const f = workspacePinsPath(home);
    setup(home, f);
    const r = readWorkspacePins({ crowHome: home });
    assert.deepEqual(r.pins, {}, name);
    assert.ok(r.reason && r.reason !== "missing", name);
    assert.equal(readWorkspacePin(1, { crowHome: home }), null, name);
    assert.equal(pinProjectWorkspace(9, ws, { crowHome: home, dataDir: data }).ok, false, name + ": no write over a faulty store");
  }
  const home = newHome("c-dir");
  mk(home, "secrets"); chmodSync(join(home, "secrets"), 0o755);
  assert.match(readWorkspacePins({ crowHome: home }).reason, /owner-only/);
});

// ---- creation, both slug modes (real scratch DB, like project-spaces-helper.test.js) ----
const scratch = mk(T, "create");
const cHome = newHome("create");
const cData = mk(scratch, "data");
execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env, CROW_DATA_DIR: cData, CROW_HOME: cHome }, stdio: "pipe" });
const raw = new Database(join(cData, "crow.db"));
after(() => raw.close());
const wrap = {
  async execute(a) {
    const sql = typeof a === "string" ? a : a.sql; const args = typeof a === "string" ? [] : (a.args || []);
    const st = raw.prepare(sql);
    if (st.reader) { const rows = st.all(...args); return { rows, columns: [], rowsAffected: 0, lastInsertRowid: 0 }; }
    const i = st.run(...args); return { rows: [], columns: [], rowsAffected: i.changes, lastInsertRowid: i.lastInsertRowid };
  },
  async batch(ss) { return raw.transaction((xs) => xs.map((s) => { const st = raw.prepare(s.sql); const i = st.run(...(s.args || [])); return { rows: [], rowsAffected: i.changes, lastInsertRowid: i.lastInsertRowid }; }))(ss); },
};

test("creation pins the workspace in BOTH slug modes", async () => {
  const saved = { h: process.env.CROW_HOME, d: process.env.CROW_DATA_DIR };
  process.env.CROW_HOME = cHome; process.env.CROW_DATA_DIR = cData;
  try {
    const { createProjectSpace } = await import("../servers/shared/project-spaces.js");
    const a = await createProjectSpace(wrap, { name: "Default Mode" });
    const b = await createProjectSpace(wrap, { name: "Explicit Mode", explicitSlug: "explicit-mode" });
    assert.equal(readWorkspacePin(a.id, { crowHome: cHome }), realpathSync(a.workspaceDir));
    assert.equal(readWorkspacePin(b.id, { crowHome: cHome }), realpathSync(b.workspaceDir));
  } finally {
    if (saved.h === undefined) delete process.env.CROW_HOME; else process.env.CROW_HOME = saved.h;
    if (saved.d === undefined) delete process.env.CROW_DATA_DIR; else process.env.CROW_DATA_DIR = saved.d;
  }
});

// ---- backfill ----
test("backfill pins good rows, skips each bad category with a counts-only line, and runs once", async () => {
  const home = newHome("bf");
  const data = mk(T, "bf", "data");
  const rows = [];
  const add = (id, slug, ws) => rows.push({ id, slug, workspace_dir: ws });
  add(1, "alpha-1", mk(data, "projects", "alpha-1", "workspace"));            // good (id suffix)
  add(2, "beta", mk(data, "projects", "beta-2", "workspace"));                // good (slug-N)
  add(3, "gamma", null);                                                       // no-workspace
  add(4, "delta", join(data, "projects", "delta", "workspace"));              // missing
  add(5, "eps", mk(data, "elsewhere", "eps", "workspace"));                   // shape
  add(6, "zeta", mk(data, "projects", "someone-else", "workspace"));          // slug
  const sh = mk(data, "projects", "eta", "workspace");
  add(7, "eta", sh); add(8, "eta", sh);                                        // shared
  const db = { async execute() { return { rows }; }, close() {} };
  const logs = [];
  const res = await runProjectWorkspacePinBackfill({ createDbClient: () => db, crowHome: home, dataDir: data, log: (m) => logs.push(m), warn: () => {} });
  assert.equal(res.pinned, 2);
  assert.deepEqual(res.counts, { "no-workspace": 1, missing: 1, shape: 1, slug: 1, shared: 2 });
  assert.equal(logs.length, 1);
  assert.equal(logs[0], "[workspace-pin] backfill: 2 pinned, 6 skipped (no-workspace: 1, missing: 1, shape: 1, slug: 1, shared: 2)");
  assert.ok(!logs[0].includes(data));
  assert.equal(readWorkspacePin(1, { crowHome: home }), realpathSync(rows[0].workspace_dir));
  assert.equal(readWorkspacePin(8, { crowHome: home }), null);
  // once: a retargeted row is NOT pinned by the next run
  rows.push({ id: 9, slug: "theta", workspace_dir: mk(data, "projects", "theta-9", "workspace") });
  const again = await runProjectWorkspacePinBackfill({ createDbClient: () => db, crowHome: home, dataDir: data, log: () => {}, warn: () => {} });
  assert.equal(again.ran, false);
  assert.ok(again.alreadyDoneAt);
  assert.equal(readWorkspacePin(9, { crowHome: home }), null);
});

// ---- the consumer: the noDb plan ----
const { buildContainPlan, ContainRefused } = await import("../scripts/pi-bots/pi_contain.mjs");
const H = join(T, "plan", "home", "alice");
const node = mk(H, ".nvm", "versions", "node", "v24.0.0"); mk(node, "bin"); writeFileSync(join(node, "bin", "node"), "");
const cliRoot = mk(node, "lib", "node_modules", "@earendil-works", "pi-coding-agent"); mk(cliRoot, "dist"); writeFileSync(join(cliRoot, "dist", "cli.js"), "");
const appDir = mk(H, "crow"), piLab = mk(H, "pi-lab"), agent = mk(H, ".pi", "agent");
for (const d of ["pkg", "agents", "prompts", "bin", "sessions"]) mk(agent, d);
const shadow = mk(T, "plan", "shadow");
const crowHome = mk(H, ".crow"); const planData = mk(crowHome, "data"); mk(crowHome, "secrets");
writeFileSync(join(planData, "crow.db"), "");
const session = mk(T, "plan", "sess"); const cache = mk(crowHome, "bot-cache");
const mine = mk(planData, "projects", "mine", "workspace");
const theirs = mk(planData, "projects", "theirs", "workspace");
const base = (over = {}) => ({
  home: H, uid: 1000, nodeBin: join(node, "bin", "node"), cliPath: join(cliRoot, "dist", "cli.js"),
  appRoot: appDir, piLabDir: piLab, piAgentDir: agent, shadowAgentDir: shadow, crowHome, dataDir: planData, botCacheDir: cache,
  sessionDir: session, cwd: session, workspaceDir: null, writePaths: [], readPaths: [], mcpServers: [],
  exists: undefined, systemDirs: ["/usr", "/etc"], dbPaths: [join(planData, "crow.db")], ...over,
});

test("noDb plan: no pin refuses, a mismatched pin refuses (row retargeted), a matching pin passes", () => {
  const nodb = { noDb: true, workspaceDir: mine, cwd: mine };
  assert.throws(() => buildContainPlan(base({ ...nodb, workspacePin: null })),
    (e) => e instanceof ContainRefused && /no pin/.test(e.message) && !e.message.includes(planData));
  // the row says "theirs" but this project's pin is "mine"'s sibling: retargeting the row changes the workspace only
  assert.throws(() => buildContainPlan(base({ noDb: true, workspaceDir: theirs, cwd: theirs, workspacePin: mine })),
    (e) => e instanceof ContainRefused && /pinned workspace/.test(e.message) && !e.message.includes(planData));
  const ok = buildContainPlan(base({ ...nodb, workspacePin: mine }));
  assert.deepEqual(ok.refused, []);
});

test("a non-noDb plan is unchanged by a pin (it is not judged)", () => {
  const without = buildContainPlan(base({ workspaceDir: mine, cwd: mine }));
  const withPin = buildContainPlan(base({ workspaceDir: mine, cwd: mine, workspacePin: null }));
  assert.deepEqual(withPin.args, without.args);
});

// ---- fail closed: a noDb plan with no workspacePin key refuses ----
test("noDb plan with NO workspacePin key refuses like 'no pin'", () => {
  assert.throws(() => buildContainPlan(base({ noDb: true, workspaceDir: mine, cwd: mine })),
    (e) => e instanceof ContainRefused && /no pin/.test(e.message));
});

// ---- the bridge supplies the pin ----
test("bridge noDbWorkspacePinInput: pinned project -> its path, unpinned -> null, non-noDb -> nothing; containInputs uses it", async () => {
  const { noDbWorkspacePinInput } = await import("../scripts/pi-bots/bridge.mjs");
  const home = newHome("br");
  const data = mk(T, "br", "data");
  const ws = mk(data, "projects", "p-1", "workspace");
  pinProjectWorkspace(1, ws, { crowHome: home, dataDir: data });
  const o = (projectId, extra = {}) => ({ noDb: true, projectWorkspaceDir: ws, projectId, ...extra });
  assert.deepEqual(noDbWorkspacePinInput(o(1), home), { workspacePin: ws });
  assert.deepEqual(noDbWorkspacePinInput(o(2), home), { workspacePin: null });
  assert.deepEqual(noDbWorkspacePinInput(o(null), home), { workspacePin: null });
  assert.deepEqual(noDbWorkspacePinInput(o(1, { noDb: false }), home), {});
  assert.deepEqual(noDbWorkspacePinInput(o(1, { projectWorkspaceDir: null }), home), {});
  const src = readFileSync(new URL("../scripts/pi-bots/bridge.mjs", import.meta.url), "utf8");
  const body = src.slice(src.indexOf("function containInputs("));
  assert.ok(body.slice(0, body.indexOf("\n}\n")).includes("...noDbWorkspacePinInput(opts, crowHome)"), "containInputs spreads the helper");
});

test("backfill: a row rewritten to another project's folder (slug set to that folder name) is skipped, the owner is pinned", async () => {
  const home = newHome("tofu");
  const data = mk(T, "tofu", "data");
  const bWs = mk(data, "projects", "beta-2", "workspace");
  const rows = [
    { id: 1, slug: "beta-2", workspace_dir: bWs }, // A, rewritten
    { id: 2, slug: "beta", workspace_dir: bWs },   // B, the real owner
  ];
  const db = { async execute() { return { rows }; }, close() {} };
  const logs = [];
  const res = await runProjectWorkspacePinBackfill({ createDbClient: () => db, crowHome: home, dataDir: data, log: (m) => logs.push(m), warn: () => {} });
  assert.equal(res.pinned, 1);
  assert.equal(res.counts.slug, 1);
  assert.equal(readWorkspacePin(1, { crowHome: home }), null);
  assert.equal(readWorkspacePin(2, { crowHome: home }), bWs);
});

test("store: one real path is never pinned for two projects (pin and replace alike)", async () => {
  const { replaceWorkspacePin } = await import("../servers/shared/project-workspace-pins.js");
  const home = newHome("two");
  const data = mk(T, "two", "data");
  const w1 = mk(data, "projects", "one", "workspace");
  const w2 = mk(data, "projects", "two", "workspace");
  assert.equal(pinProjectWorkspace(1, w1, { crowHome: home, dataDir: data }).ok, true);
  assert.deepEqual(pinProjectWorkspace(2, w1, { crowHome: home, dataDir: data }), { ok: false, reason: "path-pinned-to-another-project" });
  assert.equal(pinProjectWorkspace(2, w2, { crowHome: home, dataDir: data }).ok, true);
  assert.deepEqual(replaceWorkspacePin(2, w1, { crowHome: home, dataDir: data }), { ok: false, reason: "path-pinned-to-another-project" });
  assert.equal(readWorkspacePin(2, { crowHome: home }), w2);
});
