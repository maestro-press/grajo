// P2: a no-database (core doors) spawn gets a synthetic root: the data dir is not bound at all, so
// crow.db, identity.json, secrets and the other projects are ABSENT (ENOENT), and only the path down
// to the bot's own workspace exists. Real bubblewrap over a plan from buildContainPlan; skipped when
// bwrap or --bind-fd is missing.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, realpathSync, readdirSync, readFileSync, existsSync } from "node:fs";
import { spawnSync } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { openBindFds, bwrapHasBindFd, probePiSandbox } from "../scripts/pi-bots/pi_sandbox.mjs";
import { buildContainPlan } from "../scripts/pi-bots/pi_contain.mjs";

const probe = probePiSandbox();
const skip = probe.ok && probe.pidns && probe.bwrap && bwrapHasBindFd(probe.bwrap) ? false : "bwrap missing, unusable here, or without --bind-fd";
const T = realpathSync(mkdtempSync(join(tmpdir(), "crow-nodb-synth-")));
after(() => rmSync(T, { recursive: true, force: true }));
const mk = (...p) => { const d = join(T, ...p); mkdirSync(d, { recursive: true }); return d; };

function fixture(name) {
  const home = mk(name, "home", "alice");
  const crowHome = mk(name, "home", "alice", ".crow");
  const data = mk(name, "home", "alice", ".crow", "data");
  const ws = mk(name, "home", "alice", ".crow", "data", "projects", "mine", "ws");
  mk(name, "home", "alice", ".crow", "data", "projects", "other");
  mk(name, "home", "alice", ".crow", "data", "secrets");
  mk(name, "home", "alice", ".crow", "pi-bots", "bot-a");
  writeFileSync(join(data, "crow.db"), "DB");
  writeFileSync(join(data, "identity.json"), "{}");
  writeFileSync(join(data, "secrets", "x"), "S");
  writeFileSync(join(data, "projects", "other", "s.txt"), "TOPSECRET");
  writeFileSync(join(ws, "hello"), "HELLO");
  const state = join(crowHome, "pi-bots", "bot-a");
  const cache = mk(name, "home", "alice", ".crow", "bot-cache");
  const cli = join(mk(name, "cli"), "cli.js"); writeFileSync(cli, "");
  const input = { home, uid: process.getuid(), crowHome, dataDir: data, botCacheDir: cache, sessionDir: state, botStateDir: state, cwd: ws,
    workspaceDir: ws, workspacePin: ws, nodeBin: process.execPath, cliPath: cli, writePaths: [], readPaths: [], mcpServers: [],
    systemDirs: ["/usr"], noDb: true, dbPaths: [join(data, "crow.db"), join(data, "tasks.db")], dataKeep: ["secrets"] };
  return { data, ws, input, home };
}

function run(args, script) {
  const l = { cmd: probe.bwrap, wrapper: "bwrap", tier: "contain", args: [...args, "--", "/bin/sh", "-c", script], judged: undefined };
  const r = openBindFds(l, { bwrapHelp: undefined });
  try {
    const stdio = ["ignore", "pipe", "pipe"];
    for (const b of r.fds) { while (stdio.length < b.childFd) stdio.push("ignore"); stdio[b.childFd] = b.fd; }
    return spawnSync(l.cmd, r.args, { stdio, encoding: "utf8" });
  } finally { r.close(); }
}

const tree = (d) => readdirSync(d, { recursive: true }).sort().join("\n");

test("a noDb plan over a real bwrap: the databases and every other entry are absent, the workspace works, mv above it changes nothing, a second spawn is identical", { skip }, () => {
  const { data, ws, input } = fixture("a");
  const before = tree(data);
  const script = `cd ${data} 2>/dev/null || exit 9
for f in crow.db identity.json secrets/x projects/other/s.txt projects/other secrets; do
  if [ -e ${data}/$f ]; then echo "PRESENT $f"; else echo "ABSENT $f"; fi
done
cat ${data}/crow.db 2>&1 | grep -o 'No such file' | head -1
echo -; ls ${data}; echo -; ls ${data}/projects; echo -; ls ${data}/projects/mine
echo -; cat ${ws}/hello; echo; echo -; echo new > ${ws}/fresh && echo WS-WRITABLE
mv ${data}/projects ${data}/p2 2>/dev/null && echo MV-RENAMED || echo MV-REFUSED
echo -; ls ${data}`;
  let first;
  for (let i = 0; i < 2; i++) {
    const plan = buildContainPlan(input);
    assert.deepEqual(plan.refused, []);
    const res = run(plan.args, script);
    assert.equal(res.status, 0, res.stderr + res.stdout);
    for (const f of ["crow.db", "identity.json", "secrets/x", "projects/other/s.txt", "projects/other", "secrets"]) assert.match(res.stdout, new RegExp("ABSENT " + f.replace(/[./]/g, "\\$&") + "\\n"), res.stdout);
    assert.ok(!/PRESENT/.test(res.stdout), res.stdout);
    assert.match(res.stdout, /No such file/, "ENOENT, not EACCES");
    const [, top, projects, mine, hello, writable, after] = res.stdout.split("-\n");
    assert.equal(top, "projects\n", "only the path down to the workspace");
    assert.equal(projects, "mine\n");
    assert.equal(mine, "ws\n");
    assert.equal(hello, "HELLO\n");
    assert.match(writable, /WS-WRITABLE/);
    first ??= res.stdout;
    assert.equal(res.stdout, first, "a second spawn sees the same layout");
  }
  assert.equal(readFileSync(join(ws, "fresh"), "utf8"), "new\n", "the write landed on the host");
  rmSync(join(ws, "fresh"));
  assert.equal(tree(data), before, "the host tree is unchanged by the rename attempt and the probes");
  assert.equal(readFileSync(join(data, "crow.db"), "utf8"), "DB");
  assert.ok(existsSync(join(data, "projects", "other", "s.txt")));
});
