// Contained spawns mount every bind source from an fd opened and verified just before exec
// (pi_sandbox.mjs openBindFds), so a path swapped for a symlink between the plan and the mount
// can never expose a masked file.
import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, renameSync, symlinkSync, rmSync, readFileSync, closeSync, realpathSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openBindFds, bwrapHasBindFd, BIND_FD_BASE, probePiSandbox } from "../scripts/pi-bots/pi_sandbox.mjs";
import { ContainRefused, judgeBindSources, assembleBindArgs, bindOpIndexes, buildContainPlan } from "../scripts/pi-bots/pi_contain.mjs";

const HELP_OK = "  --bind-fd FD DEST\n  --ro-bind-fd FD DEST\n";
const root = realpathSync(mkdtempSync(join(tmpdir(), "crow-bindfd-")));
const mk = (n) => { const d = join(root, n); mkdirSync(d, { recursive: true }); return d; };
const launchOf = (args) => ({ cmd: "/usr/bin/bwrap", wrapper: "bwrap", tier: "contain", args: [...args, "--", "/bin/true"], judged: judgeBindSources(args) });
const open = (l, o = {}) => openBindFds(l, { bwrapHelp: HELP_OK, ...o });
const quiet = (fn) => { const e = console.error; const lines = []; console.error = (m) => lines.push(String(m)); try { return fn(lines); } finally { console.error = e; } };

test("the unchanged path opens; argv swaps --bind/--ro-bind for the -fd forms, same dest and order", () => {
  const d = mk("ok"); const f = join(d, "file"); writeFileSync(f, "x"); const sub = mk("ok/sub");
  const args = ["--tmpfs", "/", "--ro-bind", f, "/f", "--bind", sub, "/sub", "--ro-bind", "/dev/null", "/masked", "--tmpfs", "/m"];
  const l = launchOf(args);
  const r = open(l);
  try {
    assert.deepEqual(r.args.slice(0, 2), ["--tmpfs", "/"]);
    assert.deepEqual(r.args.slice(2, 5), ["--ro-bind-fd", String(BIND_FD_BASE), "/f"]);
    assert.deepEqual(r.args.slice(5, 8), ["--bind-fd", String(BIND_FD_BASE + 1), "/sub"]);
    assert.deepEqual(r.args.slice(8), ["--ro-bind", "/dev/null", "/masked", "--tmpfs", "/m", "--", "/bin/true"]);
    assert.deepEqual(r.fds.map((x) => x.childFd), [BIND_FD_BASE, BIND_FD_BASE + 1]);
    assert.ok(!r.args.includes(f) && !r.args.includes(sub), "no source path is left for bwrap to resolve");
  } finally { r.close(); }
});

test("a path swapped for a symlink to another file between plan and open is refused", () => {
  const d = mk("swap"); const sub = mk("swap/own"); const secret = join(d, "secret"); writeFileSync(secret, "s");
  const l = launchOf(["--bind", sub, sub]);
  renameSync(sub, sub + ".away"); symlinkSync(secret, sub);
  quiet((lines) => {
    assert.throws(() => open(l), ContainRefused);
    assert.match(lines[0], /^\[contain\] spawn refused: a bind changed between the check and the mount \((type|path)\)$/);
    assert.ok(!lines.join("\n").includes(secret));
  });
});

test("an intermediate-directory symlink swap is refused", () => {
  const d = mk("mid"); const parent = mk("mid/p"); const child = mk("mid/p/c"); const other = mk("mid/other"); mkdirSync(join(other, "c"));
  const l = launchOf(["--bind", child, child]);
  renameSync(parent, parent + ".away"); symlinkSync(other, parent);
  quiet(() => assert.throws(() => open(l), ContainRefused));
});

test("a type change since the plan is refused", () => {
  const d = mk("type"); const p = join(d, "thing"); mkdirSync(p);
  const l = launchOf(["--ro-bind", p, p]);
  rmSync(p, { recursive: true }); writeFileSync(p, "now a file");
  quiet((lines) => { assert.throws(() => open(l), ContainRefused); assert.match(lines[0], /\((type|path)\)/); });
});

test("a missing source is refused and leaves no fd open", () => {
  const d = mk("gone"); const a = join(d, "a"); mkdirSync(a);
  const l = launchOf(["--bind", a, a, "--bind", join(d, "nope"), "/x"]);
  quiet(() => assert.throws(() => open(l), ContainRefused));
});

test("a bubblewrap without --bind-fd refuses the spawn with one clear line", () => {
  assert.equal(bwrapHasBindFd("x", HELP_OK), true);
  assert.equal(bwrapHasBindFd("x", "  --ro-bind-fd FD DEST\n"), false);
  const d = mk("nofd");
  quiet((lines) => {
    assert.throws(() => openBindFds(launchOf(["--bind", d, d]), { bwrapHelp: "  --bind SRC DEST\n" }), ContainRefused);
    assert.deepEqual(lines, ["[contain] spawn refused: a bind changed between the check and the mount (this bubblewrap has no --bind-fd)"]);
  });
});

test("a non-contain launch is returned untouched", () => {
  const l = { cmd: "bwrap", wrapper: "bwrap", tier: "pidns", args: ["--bind", "/a", "/a", "--", "x"] };
  assert.equal(openBindFds(l, { bwrapHelp: "" }).args, l.args);
});

test("assembleBindArgs output converts end to end (masks stay masks)", () => {
  const d = mk("asm"); const w = mk("asm/w"); const secret = join(w, "secret"); writeFileSync(secret, "s");
  const args = assembleBindArgs({ ro: new Map(), rw: new Map([[w, w]]), masks: [[secret, "file"]] });
  const r = open(launchOf(args));
  try {
    assert.deepEqual(r.args.slice(0, 3), ["--bind-fd", String(BIND_FD_BASE), w]);
    assert.deepEqual(r.args.slice(3, 6), ["--ro-bind", "/dev/null", secret]);
  } finally { r.close(); }
});

const probe = probePiSandbox();
const bwrapOk = probe.ok && probe.pidns && probe.bwrap && bwrapHasBindFd(probe.bwrap);
const skip = bwrapOk ? false : "bwrap missing, unusable here, or without --bind-fd";

test("integration: a masked file stays masked when a later bind's path is swapped to a symlink to it", { skip }, () => {
  const base = ["--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
    "--proc", "/proc", "--dev", "/dev", "--unshare-user", "--unshare-pid"];
  const fixture = (n) => {
    const d = mk(n); const own = mk(n + "/own"); const secret = join(d, "secret"); writeFileSync(secret, "TOPSECRET");
    // the mask, then the bind whose path gets swapped after the plan
    const args = [...base, "--bind", d, d, "--ro-bind", "/dev/null", secret, "--bind", own, own];
    return { d, own, secret, args };
  };
  // Control: with the OLD path-string mount the swap really does defeat the mask (bwrap is run).
  const c = fixture("int1c");
  renameSync(c.own, c.own + ".away"); symlinkSync("secret", c.own);
  const leak = spawnSync(probe.bwrap, [...c.args, "--", "/bin/cat", c.secret], { encoding: "utf8" });
  assert.match(leak.stdout, /TOPSECRET/, leak.stderr + " control: a path mount follows the swapped symlink past the mask");
  // The fix: the same swap after the plan refuses the spawn; bwrap is never started and the file is intact.
  const f = fixture("int1");
  const l = { ...launchOf(f.args), cmd: probe.bwrap, args: [...f.args, "--", "/bin/cat", f.secret] };
  renameSync(f.own, f.own + ".away"); symlinkSync("secret", f.own);
  quiet(() => assert.throws(() => openBindFds(l), ContainRefused));
  assert.equal(readFileSync(f.secret, "utf8"), "TOPSECRET", "the host file was not touched");
});

test("integration: a normal spawn mounts the right content, and a mask still wins", { skip }, async () => {
  const d = mk("int2"); const w = mk("int2/w"); writeFileSync(join(w, "hello"), "HELLO"); const secret = join(w, "secret"); writeFileSync(secret, "TOPSECRET");
  const base = ["--ro-bind", "/usr", "/usr", "--symlink", "usr/bin", "/bin", "--symlink", "usr/lib", "/lib", "--symlink", "usr/lib64", "/lib64",
    "--proc", "/proc", "--dev", "/dev", "--unshare-user", "--unshare-pid"];
  const args = [...base, "--bind", w, w, "--ro-bind", "/dev/null", secret];
  const l = { ...launchOf(args), cmd: probe.bwrap };
  l.args = [...args, "--", "/bin/sh", "-c", `cat ${w}/hello; echo -; cat ${secret}; ls /proc/self/fd | tr '\\n' ' '`];
  const r = openBindFds(l, { bwrapHelp: undefined });
  try {
    const stdio = ["ignore", "pipe", "pipe"];
    for (const b of r.fds) { while (stdio.length < b.childFd) stdio.push("ignore"); stdio[b.childFd] = b.fd; }
    const res = spawnSync(l.cmd, r.args, { stdio, encoding: "utf8" });
    assert.equal(res.status, 0, res.stderr);
    const [hello, rest] = res.stdout.split("-\n");
    assert.equal(hello, "HELLO");
    assert.ok(!rest.includes("TOPSECRET"), "the /dev/null mask still covers the secret");
    assert.ok(!/\b1[0-9]\b/.test(rest.split("\n").pop()), "bind fds are not handed on to the sandboxed process: " + rest);
  } finally { r.close(); }
});

test("L2: option arguments are skipped; `--setenv X --bind` is not a bind flag; parsing stops at `--`", () => {
  const args = ["--setenv", "X", "--bind", "--tmpfs", "/t", "--ro-bind", "/a", "/a", "--chdir", "--bind", "--", "--bind", "/b", "/b"];
  assert.deepEqual(bindOpIndexes(args), [5]);
  const d = mk("l2"); const a = mk("l2/a");
  const r = open(launchOf(["--setenv", "X", "--bind", "--bind", a, a, "--setenv", "--ro-bind", "--ro-bind", "/dev/null", "/m"]));
  try {
    assert.deepEqual(r.args.slice(0, 3), ["--setenv", "X", "--bind"], "the setenv value is left alone");
    assert.equal(r.args[3], "--bind-fd");
    assert.equal(r.args[7], "--ro-bind", "a /dev/null mask stays a plain ro-bind");
    assert.equal(r.fds.length, 1);
  } finally { r.close(); }
});

test("M1: a symlinked agent dir and a symlinked subdir give a plan whose sources are canonical and open fine", () => {
  const home = mk("m1/home"); const real = mk("m1/realagent"); const lab = mk("m1/lab-ext");
  mkdirSync(join(real, "pkg")); symlinkSync(lab, join(real, "extensions"));
  const link = join(home, "agent"); symlinkSync(real, link);
  const shadow = mk("m1/shadow"); const app = mk("m1/home/crow"); mkdirSync(join(home, "node/bin"), { recursive: true });
  const nodeBin = join(home, "node/bin/node"); writeFileSync(nodeBin, "");
  const plan = buildContainPlan({ home, crowHome: join(home, ".crow"), dataDir: join(home, ".crow/data"), appRoot: app,
    nodeBin, sessionDir: shadow, cwd: shadow, writePaths: [], readPaths: [], mcpServers: [], otherHomes: [],
    piAgentDir: link, shadowAgentDir: shadow, systemDirs: [] });
  assert.ok(plan.args.includes(realpathSync(lab)), "the symlinked subdir's source is its canonical target");
  assert.ok(!plan.args.some((a, i) => plan.args[i - 1] === "--ro-bind" && a.startsWith(link + "/")), "no lexical source is left");
  const r = open({ ...launchOf(plan.args), judged: plan.judged });
  try { assert.ok(r.fds.length >= 2); } finally { r.close(); }
});

test.after(() => rmSync(root, { recursive: true, force: true }));
