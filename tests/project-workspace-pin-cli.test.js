import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, rmSync, realpathSync, chmodSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const T = realpathSync(mkdtempSync(join(tmpdir(), "crow-wspin-cli-")));
after(() => rmSync(T, { recursive: true, force: true }));
const mk = (...p) => { const d = join(...p); mkdirSync(d, { recursive: true }); return d; };
const home = mk(T, "home"); chmodSync(home, 0o700);
const data = mk(T, "data");
const saved = { h: process.env.CROW_HOME, d: process.env.CROW_DATA_DIR };
process.env.CROW_HOME = home; process.env.CROW_DATA_DIR = data;
after(() => { for (const [k, v] of [["CROW_HOME", saved.h], ["CROW_DATA_DIR", saved.d]]) { if (v === undefined) delete process.env[k]; else process.env[k] = v; } });

const { main } = await import("../scripts/cli/project-workspace-pin.js");
const { readWorkspacePin } = await import("../servers/shared/project-workspace-pins.js");

const wsA = mk(data, "projects", "alpha-1", "workspace");
const wsB = mk(data, "projects", "beta-2", "workspace");
const wsOdd = mk(data, "projects", "odd", "workspace");
const rows = [
  { id: 1, slug: "alpha-1", workspace_dir: wsA },
  { id: 2, slug: "beta-2", workspace_dir: wsB },
  { id: 3, slug: "zzz", workspace_dir: wsOdd },
];
const createDb = () => ({ async execute() { return { rows }; }, close() {} });
const run = async (...argv) => {
  let o = "", e = "";
  const code = await main({ argv, stdout: { write: (s) => { o += s; } }, stderr: { write: (s) => { e += s; } }, createDb });
  return { code, o, e };
};

test("--show lists pinned/none, paths only with --paths", async () => {
  let r = await run("--show");
  assert.equal(r.code, 0); assert.equal(r.o, "1 none\n2 none\n3 none\n");
  { const y = await run("1", "--yes"); assert.equal(y.code, 0, y.e + y.o); }
  r = await run("--show"); assert.equal(r.o, "1 pinned\n2 none\n3 none\n");
  r = await run("--show", "--paths"); assert.ok(r.o.includes(`1 pinned ${wsA}`));
});

test("<id> prints what it would pin and needs --yes; shape checks refuse a bad row", async () => {
  let r = await run("2");
  assert.equal(r.code, 0); assert.ok(r.o.includes("would pin") && r.o.includes(wsB));
  assert.equal(readWorkspacePin(2, { crowHome: home }), null);
  r = await run("2", "--yes"); assert.equal(r.code, 0);
  assert.equal(readWorkspacePin(2, { crowHome: home }), wsB);
  r = await run("3", "--yes"); assert.equal(r.code, 1); assert.match(r.e, /slug/);
  assert.equal(readWorkspacePin(3, { crowHome: home }), null);
});

test("--path pins an explicit folder (below projects/ only); no overwrite without --replace", async () => {
  let r = await run("3", "--path", wsOdd, "--yes"); assert.equal(r.code, 0);
  assert.equal(readWorkspacePin(3, { crowHome: home }), wsOdd);
  r = await run("3", "--path", data, "--yes"); assert.equal(r.code, 1);
  const wsNew = mk(data, "projects", "newer", "workspace");
  r = await run("3", "--path", wsNew, "--yes");
  assert.equal(r.code, 1); assert.match(r.e, /--replace/);
  assert.equal(readWorkspacePin(3, { crowHome: home }), wsOdd);
  r = await run("3", "--path", wsNew, "--yes", "--replace"); assert.equal(r.code, 0);
  assert.equal(readWorkspacePin(3, { crowHome: home }), wsNew);
});

test("--show flags a row that differs from its pin (no paths without --paths); a path pinned for another project is refused", async () => {
  // project 1 is pinned to wsA; retarget its row at wsB
  rows[0].workspace_dir = wsB;
  let r = await run("--show");
  assert.match(r.o, /^1 pinned \(row differs from pin\)$/m);
  assert.ok(!r.o.includes(data));
  assert.match(r.o, /^2 pinned$/m);
  r = await run("--show", "--paths"); assert.ok(r.o.includes(wsA));
  rows[0].workspace_dir = wsA;
  // wsA is pinned for project 1: project 3 may not take it, even with --replace
  r = await run("3", "--path", wsA, "--yes", "--replace");
  assert.equal(r.code, 1); assert.match(r.e, /path-pinned-to-another-project/);
});

test("pin-from-row: a row rewritten to another project's folder is refused", async () => {
  const wsC = mk(data, "projects", "gamma-9", "workspace");
  rows.push({ id: 9, slug: "gamma", workspace_dir: wsC }, { id: 10, slug: "gamma-9", workspace_dir: wsC });
  const r = await run("10", "--yes");
  assert.equal(r.code, 1); assert.match(r.e, /slug/);
  assert.equal((await run("9", "--yes")).code, 0, "the real owner pins");
});
