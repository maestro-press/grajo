// H1: a mask nested below a plain directory of a bot-writable bind can be sidestepped by a rename
// (`mv projects p2` moves the mounts along; a concurrent spawn's mask then lands on a decoy). The
// contain plan masks `projects` WHOLESALE (a direct child of the bind root, so a mount point that
// cannot be renamed) and binds the bot's own workspace back inside it from an fd. Real bubblewrap;
// skipped when it or --bind-fd is missing.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, readdirSync, existsSync, symlinkSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openBindFds, bwrapHasBindFd, probePiSandbox } from "../scripts/pi-bots/pi_sandbox.mjs";
import { judgeBindSources, assembleBindArgs, scanEnvMasks } from "../scripts/pi-bots/pi_contain.mjs";

const probe = probePiSandbox();
const skip = probe.ok && probe.pidns && probe.bwrap && bwrapHasBindFd(probe.bwrap) ? false : "bwrap missing, unusable here, or without --bind-fd";
const T = realpathSync(mkdtempSync(join(tmpdir(), "crow-structmask-")));
after(() => rmSync(T, { recursive: true, force: true }));
const mk = (...p) => { const d = join(T, ...p); mkdirSync(d, { recursive: true }); return d; };

const BASE = ["--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
  "--proc", "/proc", "--dev", "/dev", "--unshare-user", "--unshare-pid"];

/** Plan the way buildContainPlan lays a data dir: root rw, `projects` masked whole, the workspace rw inside it. */
function plan(data, ws) {
  const rw = new Map([[data, data], [ws, ws]]);
  return [...BASE, ...assembleBindArgs({ ro: new Map(), rw, masks: [[join(data, "projects"), "dir"]], readonlyDirMasks: true })];
}
function run(args, script) {
  const l = { cmd: probe.bwrap, wrapper: "bwrap", tier: "contain", args: [...args, "--", "/bin/sh", "-c", script], judged: judgeBindSources(args) };
  const r = openBindFds(l, { bwrapHelp: undefined });
  try {
    const stdio = ["ignore", "pipe", "pipe"];
    for (const b of r.fds) { while (stdio.length < b.childFd) stdio.push("ignore"); stdio[b.childFd] = b.fd; }
    return spawnSync(l.cmd, r.args, { stdio, encoding: "utf8" });
  } finally { r.close(); }
}

test("argv: projects is one tmpfs, remounted read-only after the workspace bind; no per-project mask", () => {
  const data = mk("a", "data"); const ws = mk("a", "data", "projects", "mine", "ws"); mk("a", "data", "projects", "theirs");
  const a = plan(data, ws);
  const iT = a.indexOf("--tmpfs"); const iB = a.findIndex((x, i) => x === "--bind" && a[i + 1] === ws);
  assert.equal(a[iT + 1], join(data, "projects"));
  assert.ok(iT < iB, "the tmpfs precedes the workspace bind");
  assert.ok(a.indexOf("--remount-ro") > iB, "the remount follows it");
  assert.ok(!a.includes(join(data, "projects", "theirs")));
});

test("integration: the projects mount cannot be renamed away, only the own workspace shows, and a second spawn lands the same", { skip }, () => {
  const data = mk("b", "data"); const ws = mk("b", "data", "projects", "mine", "ws");
  writeFileSync(join(ws, "hello"), "HELLO");
  mk("b", "data", "projects", "theirs"); writeFileSync(join(data, "projects", "theirs", "secret"), "TOPSECRET");
  writeFileSync(join(data, "crow.db"), "");
  const script = `cd ${data}
mv projects p2 2>/dev/null && echo RENAMED || echo MV-REFUSED
mv projects/mine projects/m2 2>/dev/null && echo MINE-RENAMED || echo MINE-FIXED
mkdir projects/x 2>/dev/null && echo CREATED || echo RO
echo -; ls projects; echo -; ls projects/mine; echo -; cat projects/mine/ws/hello; echo -; echo more > projects/mine/ws/w && echo WS-WRITABLE
echo -; ls`;
  for (let i = 0; i < 2; i++) {
    const res = run(plan(data, ws), script);
    assert.equal(res.status, 0, res.stderr);
    assert.match(res.stdout, /^MV-REFUSED\nMINE-FIXED\nRO\n/, res.stdout + res.stderr);
    const [, projects, mine, hello, writable, top] = res.stdout.split("-\n");
    assert.equal(projects, "mine\n", "no other project is visible");
    assert.equal(mine, "ws\n");
    assert.equal(hello, "HELLO");
    assert.match(writable, /WS-WRITABLE/);
    assert.ok(!/p2/.test(top), "nothing was renamed beside projects: " + top);
  }
  assert.equal(readdirSync(data).includes("p2"), false);
  assert.ok(existsSync(join(data, "projects", "theirs", "secret")), "the host files are untouched");
});

test("control: the OLD shape (projects exposed, the other project masked inside it) really is renameable", { skip }, () => {
  const data = mk("c", "data"); const ws = mk("c", "data", "projects", "mine", "ws"); const theirs = mk("c", "data", "projects", "theirs");
  const rw = new Map([[data, data], [ws, ws]]);
  const args = [...BASE, ...assembleBindArgs({ ro: new Map(), rw, masks: [[theirs, "dir"]], readonlyDirMasks: true })];
  const res = run(args, `cd ${data}; mv projects p2 && echo RENAMED`);
  assert.match(res.stdout, /RENAMED/, res.stderr + " the nested mask is no mount-point protection for its parent");
  assert.ok(existsSync(join(data, "p2", "theirs")));
});

test("integration: a nested .env's folders are chained bind roots, so renaming them (or the kept folder) fails and the mask holds", { skip }, () => {
  const data = mk("d", "data"); const k = mk("d", "data", "keep"); const sub = mk("d", "data", "keep", "sub");
  writeFileSync(join(sub, ".env"), "TOPSECRET"); writeFileSync(join(data, "crow.db"), "");
  const rw = new Map([[data, data], [k, k], [sub, sub]]);
  const args = [...BASE, ...assembleBindArgs({ ro: new Map(), rw, masks: [[join(sub, ".env"), "file"]], readonlyDirMasks: true })];
  const res = run(args, `cd ${data}; mv keep k2 2>/dev/null && echo R1 || echo OK1; mv keep/sub keep/s2 2>/dev/null && echo R2 || echo OK2; cat keep/sub/.env | wc -c`);
  assert.equal(res.stdout, "OK1\nOK2\n0\n", res.stderr);
});

test("integration: a symlinked .env under a writable bind: the link's folder is read-only, the target's folder cannot be renamed, the target stays masked", { skip }, () => {
  const data = mk("e", "data"); const w = mk("e", "data", "keep", "W"); const conf = mk("e", "data", "keep", "conf"); const keep = join(data, "keep");
  writeFileSync(join(conf, "real.env"), "TOPSECRET"); symlinkSync(join(conf, "real.env"), join(w, ".env"));
  const rw = new Map([[data, data], [keep, keep], [conf, conf]]); const ro = new Map([[w, w]]);
  const args = [...BASE, ...assembleBindArgs({ ro, rw, masks: [[join(conf, "real.env"), "file"]], readonlyDirMasks: true })];
  const res = run(args, `cd ${keep}; rm W/.env 2>/dev/null && echo RM || echo RM-FAIL; mv conf conf2 2>/dev/null && echo MV || echo MV-FAIL; mv W W2 2>/dev/null && echo MVW || echo MVW-FAIL; cat W/.env conf/real.env 2>&1 | wc -c`);
  assert.match(res.stdout, /^RM-FAIL\nMV-FAIL\nMVW-FAIL\n/, res.stdout + res.stderr);
  assert.ok(existsSync(join(w, ".env")) && existsSync(join(conf, "real.env")), "host files untouched");
});

/** A bot whose workspace is projects/mine/ws holding a read_write share of one entry in another
 *  project's workspace, with a .env it planted in that entry: the data dir's own shape. */
function shareLayout(tag) {
  const data = mk(tag, "data"); const ws = mk(tag, "data", "projects", "mine", "ws");
  const other = mk(tag, "data", "projects", "other"); writeFileSync(join(other, "private.txt"), "PRIV");
  const entry = mk(tag, "data", "projects", "other", "workspace", "entry");
  mk(tag, "data", "projects", "other", "workspace", "notshared"); writeFileSync(join(other, "workspace", "notshared", "s.txt"), "OTHERSECRET");
  writeFileSync(join(entry, ".env"), "PLANTED=1");
  writeFileSync(join(data, "crow.db"), "");
  const rw = new Map([[data, data], [ws, ws], [entry, entry]]);
  const masks = [[join(data, "projects"), "dir"]];
  scanEnvMasks({ ro: new Map(), rw, masks, chainParents: true });
  return { data, ws, other, entry, rw, masks };
}

test("a shared entry's .env never binds the folders under the projects mask (the other project stays hidden)", () => {
  const { data, other, entry, rw, masks } = shareLayout("s1");
  for (const f of [join(data, "projects"), other, join(other, "workspace")]) assert.ok(!rw.has(f), f + " is not bound over the mask");
  assert.ok(rw.has(entry), "the shared entry is still its own bind");
  assert.ok(masks.some(([p, k]) => p === join(entry, ".env") && k === "file"), "its .env is masked");
});

test("integration: with a planted .env in a shared entry, the other project is neither visible nor writable", { skip }, () => {
  const { data, other, rw, masks } = shareLayout("s2");
  const args = [...BASE, ...assembleBindArgs({ ro: new Map(), rw, masks, readonlyDirMasks: true })];
  const res = run(args, `cd ${data}/projects/other
ls; echo -; cat private.txt 2>/dev/null || echo NO-PRIV; cat workspace/notshared/s.txt 2>/dev/null || echo NO-SECRET
echo x > planted 2>/dev/null && echo PLANTED || echo RO; mv workspace/entry workspace/e2 2>/dev/null && echo MOVED || echo FIXED
cat workspace/entry/.env 2>/dev/null; echo "[env]"`);
  assert.equal(res.status, 0, res.stderr);
  assert.equal(res.stdout, "workspace\n-\nNO-PRIV\nNO-SECRET\nRO\nFIXED\n[env]\n", res.stdout + res.stderr);
  assert.ok(!existsSync(join(other, "planted")), "nothing landed on the host");
});
