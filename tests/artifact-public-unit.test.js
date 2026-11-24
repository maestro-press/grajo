/**
 * The install-time half of the public report-link front end: the two systemd unit templates, the
 * gateway drop-in and install.sh.
 *
 * WHY THESE ARE STATIC CASES WITH ONE RUNTIME EXCEPTION: three of the four files are templates the
 * installer renders onto a machine this suite must never touch, so what is pinned here is their shape —
 * who the listener runs as, what it may read, which fd the gateway takes and by what NAME, and what the
 * installer does before it changes anything. The one thing exercised for real is the refusal path: an
 * unprivileged run with a missing or non-IPv4 bind must exit 2 having written nothing, which is exactly
 * what the validation-first order is for. Nothing here starts a unit, writes under /etc or runs as root.
 *
 * THE NEW UNDO SHAPE: one root-only backup under /run, one standalone restore.sh with the values baked
 * in, and ONE deadman timer armed before the first change. There is no lock, no marker, no run id, no
 * second timer and no restoring trap, and no in-process undo either: a failure STARTS that same script
 * through the deadman's own service and prints the restore command and the fire time, and keeping the
 * install is an operator action (`keep`) — while restore.sh stops its own timer once its decision is
 * final. A run also REFUSES to start while an earlier run's deadman is still armed, so no older timer
 * can undo a newer, kept install. The behavioural cases below render the real restore.sh out of
 * install.sh's generator block and run it against stub tools, so what is exercised is install.sh's own
 * text rather than a copy of it.
 *
 * The hyphenated door name that must never appear is assembled from fragments below, so this file does
 * not itself carry the string it scans for.
 *
 * HOW THE INSTALLER ASKS GIT is pinned too. install.sh runs as root, but the checkout it vets belongs to
 * another user, and root running git inside such a repository executes whatever that repository's own
 * config names (core.fsmonitor, a filter, a hook) with root's rights. So every git call goes through one
 * wrapper that drops to the checkout's owner with `runuser` and switches those off, a checkout owned by
 * root or by an owner that will not resolve to a numeric non-zero uid is refused, and the ownership
 * override that would instead tell root to trust the tree never appears at all.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

import { REPORTS_DOOR_SOCKET_UNIT } from "../servers/gateway/reports/public-door.js";
import { pickActivatedFd } from "../servers/gateway/proxy-socket.js";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const DIR = join(ROOT, "scripts", "artifact-public");
const LISTENER_UNIT = "crow-artifact-public.service.tmpl";
const SOCKET_UNIT = "crow-report-readers.socket.tmpl";
const DROP_IN = "gateway-door.conf.tmpl";
const INSTALL = "install.sh";
const DOOR_WORD = ["reports", "door"].join("-");

const read = (name) => readFileSync(join(DIR, name), "utf8");
const files = () => readdirSync(DIR, { withFileTypes: true })
  .filter((e) => e.isFile())
  .map((e) => e.name);

/** Every `Key=Value` of a unit file, per `[Section]`, in file order (a key may repeat, e.g. ExecStart). */
function unitDirectives(text) {
  const out = new Map();
  let section = "";
  for (const raw of text.split("\n")) {
    const line = raw.trim();
    if (!line || line.startsWith("#") || line.startsWith(";")) continue;
    const sec = /^\[([A-Za-z]+)\]$/.exec(line);
    if (sec) {
      section = sec[1];
      continue;
    }
    const at = line.indexOf("=");
    if (at < 1) continue;
    const key = `${section}/${line.slice(0, at).trim()}`;
    out.set(key, [...(out.get(key) ?? []), line.slice(at + 1).trim()]);
  }
  return out;
}

/** The one value of a directive that must appear exactly once. */
function one(directives, key) {
  const values = directives.get(key);
  assert.ok(values && values.length === 1, `${key}= appears exactly once (got ${values ? values.length : 0})`);
  return values[0];
}

/** install.sh with its comment lines blanked (line count kept), so a scan reads code and not prose. */
function stripShellComments(text) {
  return text.split("\n").map((line) => (/^\s*#/.test(line) ? "" : line)).join("\n");
}

/** The first non-comment line matching `re`, or -1. */
function codeLine(source, re) {
  const lines = source.split("\n");
  return lines.findIndex((line, i) => !/^\s*#/.test(line) && line.trim() !== "" && re.test(line));
}

/**
 * Where a shell function's source sits: from its `name() {` line to its closing `}`, as
 * `{ start, end, lines }`, or null when there is no such function.
 */
function functionLines(source, name) {
  const lines = source.split("\n");
  const start = lines.findIndex((line) => line.trim().startsWith(`${name}() {`));
  if (start < 0) return null;
  const end = lines.findIndex((line, i) => i > start && line.trim() === "}");
  if (end < 0) return null;
  return { start, end, lines: lines.slice(start, end + 1) };
}

/**
 * The body of the restore.sh this installer generates (between the quoted heredoc
 * markers), as text — the undo script's own source, which ships inside install.sh.
 */
function scriptBody(source) {
  const lines = source.split("\n");
  const start = lines.findIndex((line) => line.includes("cat <<'RESTORE_BODY'"));
  if (start < 0) return "";
  const end = lines.findIndex((line, i) => i > start && line.trim() === "RESTORE_BODY");
  if (end < 0) return "";
  return lines.slice(start + 1, end).join("\n");
}

/**
 * install.sh with the generated restore.sh body blanked (line numbering kept). What is
 * left is the installer's OWN steps: a scan for "the first change" must not see the undo
 * script's own `install -m`, `userdel` or `systemctl restart` inside the heredoc that
 * writes it, hundreds of lines before the installer itself does anything.
 */
function stripGeneratedScript(text) {
  const body = scriptBody(text);
  if (body === "") return text;
  return text.replace(body, () => body.split("\n").map(() => "").join("\n"));
}

const tmpDirs = [];
function tempDir(prefix) {
  const dir = mkdtempSync(join(tmpdir(), prefix));
  tmpDirs.push(dir);
  return dir;
}
after(() => {
  for (const dir of tmpDirs) {
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* already gone */ }
  }
});

/**
 * The restore.sh this installer generates, RENDERED: the generator block is lifted out of
 * install.sh verbatim (from its bare `{` to the `} > "$RESTORE_SCRIPT"` that closes it) and run
 * with the values install.sh would have set, so the script exercised below is install.sh's own
 * text rather than a copy of it. Nothing else of install.sh runs: no root, no systemctl, no /run.
 *
 * The three destination paths are among the values, which is why a temp directory can be restored
 * instead of /etc/systemd/system: install.sh sets those variables to the real paths.
 */
function renderRestoreScript(values) {
  const lines = read(INSTALL).split("\n");
  const open = lines.findIndex((line, i) => line.trim() === "{" && (lines[i + 1] ?? "").includes("#!/usr/bin/env bash"));
  assert.ok(open > 0, "the generator block opens with a bare { before its shebang print");
  const close = lines.findIndex((line, i) => i > open && /^\}\s*>\s*"\$RESTORE_SCRIPT"/.test(line.trim()));
  assert.ok(close > open, 'and closes with `} > "$RESTORE_SCRIPT"`');
  const quote = (value) => `'${String(value).replace(/'/g, "'\\''")}'`;
  const assignments = Object.entries(values).map(([key, value]) => `${key}=${quote(value)}`).join("\n");
  const run = spawnSync("bash", ["-c", `${assignments}\n${lines.slice(open + 1, close).join("\n")}`], { encoding: "utf8" });
  assert.equal(run.status, 0, `the generator ran: ${run.stderr}`);
  return run.stdout;
}

/** The deadman timer name the harness bakes in, so `stop_own_timer`'s calls can be asserted. */
const TEST_DEADMAN_TIMER = "crow-artifact-public-deadman-20260101000000-4242.timer";
/** The deadman service beside it, derived the way restore.sh derives it (`${DEADMAN_TIMER%.timer}`). */
const TEST_DEADMAN_SERVICE = TEST_DEADMAN_TIMER.replace(/\.timer$/, ".service");
/** The one rule the harness's ufw stub reports as added, word for word. */
const TEST_UFW_RULE = "ufw allow in on br-test from 192.0.2.2 to 192.0.2.1 port 3093 proto tcp";

/**
 * The rendered restore.sh, RUN FOR REAL as the current user in a temp directory, with every tool
 * that would change this machine's state replaced by a stub that only logs its argv. Nothing here
 * touches a unit: the question is which tools the script reaches for, not what systemd would do.
 *
 * The stubs answer like a healthy host, so no case waits on anything real: systemctl hands out a NEW
 * InvocationID on every read (and says `active`), curl says 200, and `sleep` is a no-op. The keeper
 * file, the state file and the backup copies all live under this test's own temp directory.
 *
 * `pending` made the undo check that the thing it may remove is really there, so two stubs carry
 * that answer: `id` says whether the public user exists (`userExists`) and `ufw show added` lists
 * the one rule or nothing (`ufwHasRule`). `deadmanStopRc` and `deadmanResetRc` are what the stub
 * returns for `systemctl stop <deadman>.timer` and `systemctl reset-failed …`, so a stop or a reset
 * that fails can be exercised too.
 */
function runRenderedRestore({ keep = false, state = "", snapshotFiles = {}, installed = {}, userExists = true, ufwHasRule = true, deadmanStopRc = 0, deadmanResetRc = 0 } = {}) {
  const work = tempDir("artifact-public-restore-run-");
  const bin = join(work, "bin");
  mkdirSync(bin, { recursive: true });
  const calls = join(work, "calls.log");
  const counter = join(work, "invocation.count");

  // systemctl: logs its argv, then answers the two things restore.sh reads back. A stop of the
  // deadman's own timer, and a reset-failed of anything, are the calls whose answer is configurable.
  writeFileSync(join(bin, "systemctl"),
    `#!/usr/bin/env bash\n`
    + `printf 'systemctl %s\\n' "$*" >> ${JSON.stringify(calls)}\n`
    + `case "$*" in\n`
    + `  "stop "*.timer) exit ${deadmanStopRc} ;;\n`
    + `  "reset-failed "*) exit ${deadmanResetRc} ;;\n`
    + `  *"show -p InvocationID"*) n=0; [ -f ${JSON.stringify(counter)} ] && n=$(cat ${JSON.stringify(counter)}); n=$((n + 1)); printf '%s' "$n" > ${JSON.stringify(counter)}; printf 'invocation-%s\\n' "$n" ;;\n`
    + `  *"is-active"*) printf 'active\\n' ;;\n`
    + `esac\n`
    + `exit 0\n`, { mode: 0o755 });
  // ufw: every call logged, and `show added` answers with exactly one rule or none.
  writeFileSync(join(bin, "ufw"),
    `#!/usr/bin/env bash\n`
    + `printf 'ufw %s\\n' "$*" >> ${JSON.stringify(calls)}\n`
    + `case "$*" in\n`
    + `  "show added") ${ufwHasRule ? `printf '%s\\n' ${JSON.stringify(TEST_UFW_RULE)}` : `:`} ;;\n`
    + `esac\n`
    + `exit 0\n`, { mode: 0o755 });
  // id: says whether the public user the undo checks for is really there.
  writeFileSync(join(bin, "id"),
    `#!/usr/bin/env bash\n`
    + `printf 'id %s\\n' "$*" >> ${JSON.stringify(calls)}\n`
    + `case "$1" in\n`
    + `  crow-artifact-public) exit ${userExists ? 0 : 1} ;;\n`
    + `esac\n`
    + `exit 1\n`, { mode: 0o755 });
  for (const stub of ["userdel", "logger"]) {
    writeFileSync(join(bin, stub),
      `#!/usr/bin/env bash\nprintf '%s %s\\n' ${JSON.stringify(stub)} "$*" >> ${JSON.stringify(calls)}\n`, { mode: 0o755 });
  }
  // The gateway always answers 200 here, so neither a check nor its retry loop waits on a real one.
  writeFileSync(join(bin, "curl"),
    `#!/usr/bin/env bash\nprintf 'curl %s\\n' "$*" >> ${JSON.stringify(calls)}\nprintf '200'\n`, { mode: 0o755 });
  // The undo's waits back off with `timeout 10 sleep 5`; a no-op keeps this suite fast.
  writeFileSync(join(bin, "sleep"), "#!/usr/bin/env bash\nexit 0\n", { mode: 0o755 });

  const restoreDir = join(work, "restore");
  const snapshot = join(restoreDir, "snapshot");
  const etc = join(work, "etc");
  const dropInDir = join(etc, "crow-gateway.service.d");
  mkdirSync(snapshot, { recursive: true });
  mkdirSync(dropInDir, { recursive: true });

  const dropIn = join(dropInDir, "report-readers.conf");
  const socketUnit = join(etc, "crow-report-readers.socket");
  const listenerUnit = join(etc, "crow-artifact-public.service");

  if (keep) writeFileSync(join(restoreDir, "keep"), "");
  if (state) writeFileSync(join(restoreDir, "state"), state);
  for (const [name, content] of Object.entries(snapshotFiles)) writeFileSync(join(snapshot, name), content);
  if (installed.dropIn !== undefined) writeFileSync(dropIn, installed.dropIn);
  if (installed.socketUnit !== undefined) writeFileSync(socketUnit, installed.socketUnit);
  if (installed.listenerUnit !== undefined) writeFileSync(listenerUnit, installed.listenerUnit);

  const script = renderRestoreScript({
    RESTORE_DIR: restoreDir,
    LISTENER_UNIT_NAME: "crow-artifact-public.service",
    SOCKET_UNIT_NAME: "crow-report-readers.socket",
    GATEWAY_UNIT_NAME: "crow-gateway.service",
    LISTENER_UNIT_DEST: listenerUnit,
    SOCKET_UNIT_DEST: socketUnit,
    DROP_IN_DIR: dropInDir,
    DROP_IN_DEST: dropIn,
    PUBLIC_USER: "crow-artifact-public",
    CROW_ARTIFACT_BRIDGE_IF: "br-test",
    CROW_ARTIFACT_SIDECAR_IP: "192.0.2.2",
    CROW_ARTIFACT_PUBLIC_BIND: "192.0.2.1",
    PUBLIC_PORT: "3093",
    GATEWAY_HEALTH_URL: "http://127.0.0.1:3001/health",
    DEADMAN_TIMER: TEST_DEADMAN_TIMER,
  });
  const scriptPath = join(restoreDir, "restore.sh");
  writeFileSync(scriptPath, script, { mode: 0o700 });
  const syntax = spawnSync("bash", ["-n", scriptPath], { encoding: "utf8" });
  assert.equal(syntax.status, 0, `the rendered restore.sh parses: ${syntax.stderr}`);

  const env = { PATH: `${bin}:/usr/bin:/bin`, HOME: work, TMPDIR: work };
  const rerun = () => spawnSync("bash", [scriptPath], { encoding: "utf8", timeout: 120_000, env });
  const run = rerun();
  const called = existsSync(calls) ? readFileSync(calls, "utf8").split("\n").filter(Boolean) : [];
  return { run, rerun, called, script, scriptPath, restoreDir, work, dropIn, dropInDir, socketUnit, listenerUnit };
}

/** Only these stubs change this machine's state; `logger` is how the undo reports, not a change. */
const STATE_CHANGING_CALL = /^(?:systemctl|ufw|userdel) /;
const stateChanging = (called) => called.filter((line) => STATE_CHANGING_CALL.test(line));

/** A state file as install.sh writes it when this run made everything it installs. */
const STATE_FIRST_INSTALL = [
  "LISTENER_UNIT_PRESENT=0",
  "SOCKET_UNIT_PRESENT=0",
  "DROP_IN_PRESENT=1",
  "DROP_IN_DIR_CREATED=0",
  "GATEWAY_TOUCHED=1",
  "USER_CREATED=0",
  "UFW_RULE_ADDED=0",
  "PREV_SOCKET_ENABLED=",
  "PREV_SOCKET_ACTIVE=",
  "PREV_LISTENER_ENABLED=",
  "PREV_LISTENER_ACTIVE=",
  "",
].join("\n");

/* --------------------------------------------------------------------- the listener unit */

test("the unit template runs as crow-artifact-public with ProtectHome=tmpfs and only the two read-only binds", () => {
  const d = unitDirectives(read(LISTENER_UNIT));

  assert.equal(one(d, "Service/User"), "crow-artifact-public", "its own system user, never the operator's");
  assert.equal(one(d, "Service/Group"), "crow-artifact-public");
  assert.equal(one(d, "Service/ProtectHome"), "tmpfs", "the instance home is a tmpfs, not a readable path");

  // Exactly two read-only binds: node's own install prefix and this listener's own directory.
  const binds = d.get("Service/BindReadOnlyPaths");
  assert.ok(binds && binds.length === 1, "one BindReadOnlyPaths= line");
  const paths = binds[0].split(/\s+/).filter(Boolean);
  assert.deepEqual(paths, ["@NODE_DIR@", "@APP_DIR@/scripts/artifact-public"],
    "the node install prefix and the listener's own directory, nothing else");
  // ... and no writable bind, no state or cache directory, no second bind of any kind.
  for (const key of ["BindPaths", "BindWritePaths", "ReadWritePaths", "StateDirectory", "CacheDirectory", "LogsDirectory"]) {
    assert.equal(d.has(`Service/${key}`), false, `no ${key}= on a process a stranger reaches`);
  }

  assert.match(one(d, "Service/InaccessiblePaths"), /^-@CROW_HOME@$/,
    "the instance home is named and made unreadable (the '-' is what makes a missing path no error)");

  // Hardening, in the unit rather than in a promise.
  assert.equal(one(d, "Service/NoNewPrivileges"), "yes");
  assert.equal(one(d, "Service/ProtectSystem"), "strict");
  assert.equal(one(d, "Service/PrivateTmp"), "yes");
  assert.equal(one(d, "Service/PrivateDevices"), "yes");
  assert.equal(one(d, "Service/CapabilityBoundingSet"), "", "no capability at all");
  assert.equal(one(d, "Service/RestrictAddressFamilies"), "AF_INET AF_INET6 AF_UNIX");
  assert.equal(one(d, "Service/RestrictNamespaces"), "yes");
  assert.equal(one(d, "Service/SystemCallFilter"), "@system-service");
  assert.equal(one(d, "Service/ProtectKernelTunables"), "yes");
  assert.equal(one(d, "Service/ProtectControlGroups"), "yes");
  assert.equal(one(d, "Service/LockPersonality"), "yes");

  // The two ceilings that exist because this is the one process a stranger reaches directly.
  assert.equal(one(d, "Service/MemoryMax"), "256M");
  assert.equal(one(d, "Service/TasksMax"), "64");

  // It runs its own file under the node the installer resolved, and reads only the two values below.
  const exec = one(d, "Service/ExecStart");
  assert.match(exec, /^@NODE_BIN@ @APP_DIR@\/scripts\/artifact-public\/server\.mjs$/);
  assert.doesNotMatch(exec, /npm/);
  assert.deepEqual(d.get("Service/Environment"), [
    "CROW_ARTIFACT_PUBLIC_BIND=@BIND@",
    "CROW_ARTIFACT_PUBLIC_PORT=3093",
  ], "the bind and the port, and no other host value");
  assert.equal(d.has("Service/EnvironmentFile"), false, "no environment file is read");

  // It is useful only once the gateway's door exists, so the door is ordered before it.
  const after_ = one(d, "Unit/After").split(/\s+/);
  assert.ok(after_.includes(REPORTS_DOOR_SOCKET_UNIT), "After= names the door socket");
  assert.ok(one(d, "Unit/Wants").split(/\s+/).includes(REPORTS_DOOR_SOCKET_UNIT), "Wants= names it too");
  assert.equal(one(d, "Install/WantedBy"), "multi-user.target");
});

test("the listener unit tolerates a missing CROW_HOME path", () => {
  const text = read(LISTENER_UNIT);

  // Exactly one InaccessiblePaths= line, and it carries the leading '-'.
  const lines = text.split("\n").map((line) => line.trim())
    .filter((line) => line.startsWith("InaccessiblePaths="));
  assert.deepEqual(lines, ["InaccessiblePaths=-@CROW_HOME@"],
    "one InaccessiblePaths= line, dash-prefixed so a path that is not there is not an error");
  assert.equal(one(unitDirectives(text), "Service/InaccessiblePaths"), "-@CROW_HOME@",
    "the instance home, prefixed with the '-' that makes it optional");

  // The un-dashed form must not exist anywhere. Under ProtectHome=tmpfs the path IS missing
  // (the home is an empty tmpfs for this process), and systemd refuses to set the namespace
  // up at all for an InaccessiblePaths= that is not there: the unit would fail 226/NAMESPACE
  // instead of starting without a home it is never meant to read.
  assert.doesNotMatch(text, /^\s*InaccessiblePaths=(?!-)/m,
    "no un-dashed InaccessiblePaths= line: that is the form that fails the unit with 226/NAMESPACE");
  assert.equal(one(unitDirectives(text), "Service/ProtectHome"), "tmpfs",
    "the home is a tmpfs, which is why the path is not there to be made inaccessible");

  // The header explains the dash, so the reason on the line cannot quietly drift from it.
  const header = text.split("\n").filter((line) => /^\s*#/.test(line)).join("\n");
  assert.match(header, /dash-prefixed InaccessiblePaths=/, "the header says the line is dash-prefixed");
  assert.match(header, /ProtectHome=tmpfs/, "and names the tmpfs that makes the path missing");
});

/* ---------------------------------------------------------------------- the gateway drop-in */

test("the drop-in's ExecStart runs node directly", () => {
  const text = read(DROP_IN);
  // The header explains why an `npm run gateway` unit needs this drop-in, so the scan for
  // npm in the COMMAND PATH reads code lines only.
  const codeOnly = text.split("\n").filter((line) => !/^\s*#/.test(line)).join("\n");
  assert.doesNotMatch(codeOnly, /npm/i,
    "npm is never in the command path: systemd would hand the fd to npm and node would be its child");

  const d = unitDirectives(text);
  const starts = d.get("Service/ExecStart") ?? [];
  assert.equal(starts.length, 2, "the empty reset line and the real ExecStart");
  assert.equal(starts[0], "", "an empty ExecStart= clears the inherited value first");
  assert.notEqual(starts[0], starts[1], "the reset is its own line, not a re-statement");

  const argv = starts[1].split(/\s+/).filter(Boolean);
  assert.equal(argv.length, 2, `node plus the script path only (got '${starts[1]}')`);
  assert.equal(argv[0], "@NODE_BIN@", "the absolute node binary is the command, so node is the MainPID");
  assert.notEqual(argv[0], "npm");
  assert.equal(argv[1], "servers/gateway/index.js",
    "the script stays relative, so it resolves inside the unit's OWN WorkingDirectory");
  assert.equal(d.has("Service/WorkingDirectory"), false,
    "the drop-in never sets WorkingDirectory=: the unit keeps its own");

  // Sockets= NAMES only the door: a second unit here would hand the same fd over twice.
  assert.equal(one(d, "Service/Sockets"), REPORTS_DOOR_SOCKET_UNIT);
  assert.equal(one(d, "Unit/After"), REPORTS_DOOR_SOCKET_UNIT);
  for (const other of ["crow-gateway-proxy.socket", "crow-gateway.service"]) {
    assert.doesNotMatch(codeOnly,
      new RegExp(`^(?:Sockets|Requires|Wants|After)=.*${other.replace(/\./g, "\\.")}`, "m"),
      `${other} is not repeated in the drop-in's unit lines`);
  }
});

/* ---------------------------------------------------------------------- the socket unit */

test("the socket unit is root:crow-artifact-public 0660 and named crow-report-readers.socket", () => {
  const d = unitDirectives(read(SOCKET_UNIT));

  assert.equal(REPORTS_DOOR_SOCKET_UNIT, "crow-report-readers.socket", "the name the gateway looks for");
  assert.equal(one(d, "Socket/ListenStream"), "/run/crow-report-readers/door.sock");
  assert.equal(one(d, "Socket/Service"), "crow-gateway.service", "the gateway is the service that receives it");
  // The name systemd passes must be the name the gateway looks for, whatever the file is called on disk.
  assert.equal(one(d, "Socket/FileDescriptorName"), REPORTS_DOOR_SOCKET_UNIT);
  assert.equal(one(d, "Socket/SocketUser"), "root");
  assert.equal(one(d, "Socket/SocketGroup"), "crow-artifact-public", "the listener's own group");
  assert.equal(one(d, "Socket/SocketMode"), "0660", "root and that one group, nobody else");
  assert.equal(one(d, "Socket/DirectoryMode"), "0750", "the directory is traversable by that group only");
  assert.equal(one(d, "Install/WantedBy"), "sockets.target");
  // The unit needs no installer value, so it carries no placeholder that could be left unfilled.
  assert.doesNotMatch(read(SOCKET_UNIT), /@[A-Za-z_][A-Za-z0-9_]*@/);
});

test("the door socket is part of the gateway so a stopped gateway stays stopped", () => {
  const d = unitDirectives(read(SOCKET_UNIT));

  // In [Unit], and naming the very service the socket activates: stopping or restarting
  // the gateway stops or restarts this socket too, so a gateway the operator stopped on
  // purpose is not woken by a public request arriving at a socket that would start it.
  assert.equal(one(d, "Unit/PartOf"), "crow-gateway.service",
    "PartOf= names the service the socket activates");
  assert.equal(one(d, "Socket/Service"), "crow-gateway.service",
    "the same unit: without PartOf= that Service= would start a stopped gateway again");

  // The comment says why, inside the socket: the hazard, and the page a listener answers
  // while the operator's gateway stays down.
  const header = read(SOCKET_UNIT).split("\n").filter((line) => /^\s*#/.test(line)).join("\n");
  assert.match(header, /PartOf=crow-gateway\.service/, "the header names the directive and its unit");
  assert.match(header, /stopped on purpose/, "and the case it exists for");
  assert.match(header, /503/, "and the 503 page the listener answers meanwhile");

  // install.sh's header says the same — as a comment only: its logic is unchanged.
  const install = read(INSTALL);
  const installComments = install.split("\n").filter((line) => /^\s*#/.test(line)).join("\n");
  assert.match(installComments, /PartOf=crow-gateway\.service/, "install.sh's header mentions PartOf=");
  assert.match(installComments, /503/, "with the same consequence spelled out");
  assert.equal(stripShellComments(install).includes("PartOf"), false,
    "and only in a comment: no installer step reads or writes PartOf=");
});

/* ------------------------------------------------- the fd the gateway takes, by name only */

test("the gateway takes the door fd by LISTEN_FDNAMES and never creates the socket path", () => {
  const pid = 4242;
  const env = { LISTEN_PID: String(pid), LISTEN_FDS: "1", LISTEN_FDNAMES: REPORTS_DOOR_SOCKET_UNIT };
  assert.equal(pickActivatedFd(REPORTS_DOOR_SOCKET_UNIT, env, pid), 3, "the one activated fd is fd 3");

  // By NAME, never by position: the same single fd under another unit's name is not ours.
  assert.equal(pickActivatedFd(REPORTS_DOOR_SOCKET_UNIT, { ...env, LISTEN_FDNAMES: "crow-gateway-proxy.socket" }, pid), null);
  assert.equal(pickActivatedFd(REPORTS_DOOR_SOCKET_UNIT, { ...env, LISTEN_FDNAMES: "" }, pid), null);
  // Two activated sockets: the index in LISTEN_FDNAMES decides the fd.
  assert.equal(pickActivatedFd(REPORTS_DOOR_SOCKET_UNIT, {
    ...env, LISTEN_FDS: "2", LISTEN_FDNAMES: `crow-gateway-proxy.socket:${REPORTS_DOOR_SOCKET_UNIT}`,
  }, pid), 4);
  // A stale or foreign LISTEN_PID is ignored: an inherited env must never open someone else's socket.
  assert.equal(pickActivatedFd(REPORTS_DOOR_SOCKET_UNIT, { ...env, LISTEN_PID: "1" }, pid), null);

  // The door module never touches a path: systemd owns the socket, so no process creates, chmods or
  // unlinks one and the unit's mode is the mode in force.
  const source = readFileSync(join(ROOT, "servers", "gateway", "reports", "public-door.js"), "utf8");
  for (const call of ["unlink", "unlinkSync", "chmod", "chmodSync", "mkdir", "mkdirSync", "rmSync", "openSync"]) {
    assert.doesNotMatch(source, new RegExp(`\\b${call}\\s*\\(`), `public-door.js never calls ${call}()`);
  }
  assert.doesNotMatch(source, /from\s*["'](?:node:)?fs["']|require\(\s*["'](?:node:)?fs["']\s*\)/,
    "public-door.js imports no filesystem module at all");
  assert.doesNotMatch(source, /\/run\/crow/, "and it names no socket path");
  // It takes the inherited fd by name, and listens on that fd only.
  assert.match(source, /pickActivatedFd\(\s*REPORTS_DOOR_SOCKET_UNIT/);
  assert.match(source, /server\.listen\(\s*\{\s*fd\s*\}\s*\)/);
});

/* ---------------------------------------------------------------- the forbidden hyphenated name */

test(`no template or script says ${DOOR_WORD}`, () => {
  const scanned = files();
  assert.ok(scanned.length >= 4, `the directory holds the two units, the drop-in and the installer (${scanned.join(", ")})`);
  for (const name of scanned) {
    const text = readFileSync(join(DIR, name), "utf8");
    assert.equal(text.includes(DOOR_WORD), false, `${name} never writes ${DOOR_WORD}`);
  }
});

/* -------------------------------------------------------------------------- install.sh */

test("install.sh refuses an unset or non-IPv4 bind", () => {
  const source = read(INSTALL);

  // The order in the source is the behavior: the bind is validated before the root check, so an
  // unprivileged run gets the real reason instead of a permission error, and before the first
  // systemctl call, so nothing privileged is even attempted with a bad value.
  const validateAt = codeLine(source, /\[ -n "\$\{CROW_ARTIFACT_PUBLIC_BIND:-\}" \]/);
  const rootAt = codeLine(source, /\bid -u\b/);
  const systemctlAt = codeLine(source, /\bsystemctl\b/);
  assert.ok(validateAt > 0, "the bind is validated at all");
  assert.ok(rootAt > 0, "there is a root check");
  assert.ok(systemctlAt > 0, "the script does call systemctl, later");
  assert.ok(validateAt < rootAt, "the bind validation comes BEFORE the root check");
  assert.ok(validateAt < systemctlAt, "and before the first systemctl call");

  const baseEnv = { PATH: process.env.PATH ?? "/usr/bin:/bin" };
  const workDir = tempDir("artifact-public-install-");
  const cases = [
    ["unset", null],
    ["a hostname", "localhost"],
    ["an out-of-range octet", "10.0.0.999"],
    ["a wildcard address", "0.0.0.0"],
    ["an IPv6 address", "::1"],
  ];
  for (const [label, bind] of cases) {
    const env = { ...baseEnv, TMPDIR: workDir };
    if (bind !== null) env.CROW_ARTIFACT_PUBLIC_BIND = bind;
    const run = spawnSync("bash", [join(DIR, INSTALL)], { env, encoding: "utf8", timeout: 30_000 });
    assert.equal(run.signal, null, `${label}: the script refused on its own (signal ${run.signal})`);
    assert.equal(run.status, 2, `${label}: exit 2, got ${run.status}: ${run.stdout}${run.stderr}`);
    assert.match(run.stderr, /refusing/, `${label}: it says it refused`);
    assert.match(run.stderr, /CROW_ARTIFACT_PUBLIC_BIND/, `${label}: and names the value that was wrong`);
    assert.doesNotMatch(run.stdout + run.stderr, /systemctl/, `${label}: nothing privileged was attempted`);
    assert.deepEqual(readdirSync(workDir), [], `${label}: nothing was created (not even a backup dir)`);
  }
});

test("install.sh takes no inline password and caps every step", () => {
  const code = stripShellComments(read(INSTALL));

  // No password is ever taken, in any of the shapes that would put one on a command line.
  assert.doesNotMatch(code, /echo\s+[^\n|]*\|\s*sudo\b/, "no literal is piped into sudo");
  assert.doesNotMatch(code, /\bsudo\b[^\n]*\s-[a-zA-Z]*S/, "no sudo -S");
  assert.doesNotMatch(code, /\bsshpass\b/, "no sshpass");
  assert.doesNotMatch(code, /(?:PASSWORD|PASSWD|SSHPASS)\s*=/, "no password variable");
  assert.doesNotMatch(code, /read\s+-s\b/, "no hidden password prompt");
  assert.doesNotMatch(code, /\bcurl\b[^\n]*\s(?:-u|--user)\b/, "no password on a curl command line");

  // Every step is capped, and so is the run as a whole: a wall clock derived from the step budget,
  // and a kill-after grace behind it. Both are named, and the exec line reads those names.
  assert.match(code, /^STEP_TIMEOUT=\d+$/m, "a per-step limit");
  assert.match(code, /\btimeout\s+"\$STEP_TIMEOUT"\s+\S/, "system steps go through timeout");
  assert.match(code, /^WALL_CLOCK_SECONDS=\$\(\(/m, "the wall clock is derived, not inlined");
  assert.match(code, /^WALL_CLOCK_KILL_AFTER=\d+$/m, "and so is a named kill-after");
  assert.match(code, /exec\s+timeout\s+-k\s+"\$WALL_CLOCK_KILL_AFTER"\s+"\$WALL_CLOCK_SECONDS"\s+bash\s+"\$SELF"/,
    "the run re-execs under that wall clock, with that kill-after behind it");

  // The undo is not this process's job: the failure path starts the deadman's own service (the one
  // restore.sh) and prints, and both proofs fail the run through `fail`, whose non-zero return is
  // what raises it.
  assert.match(code, /^fail\(\)\s*\{[\s\S]*?return 1\b/m, "fail returns non-zero");
  const healthAt = code.indexOf("if ! wait_for_gateway_health; then");
  assert.ok(healthAt > 0, "the health check is a gating check");
  assert.match(code.slice(healthAt, healthAt + 200), /fail\s+"/, "a failed /health check fails the run");
  const tripAt = code.indexOf("if ! round_trip_through_listener; then");
  assert.ok(tripAt > 0, "the round trip is a gating check");
  assert.match(code.slice(tripAt, tripAt + 200), /fail\s+"/, "and so does a failed round trip");

  // What is proved: the gateway's /health, and a mailed-report path through the listener answering the
  // sandboxed 404 page (the one check that says the whole chain is real).
  assert.match(code, /\/health/, "the health check asks /health");
  assert.match(code, /curl[^\n]*-w '%\{http_code\}'/, "and reads the status code");
  assert.match(code, /\/r\/\$ROUND_TRIP_TOKEN/, "the round trip goes through a report-link path");
  assert.match(code, /grep -qi '\^content-security-policy:\.\*sandbox'/, "and requires a sandboxed CSP");
});

test("install.sh creates the system user without a home and nologin", () => {
  const code = stripShellComments(read(INSTALL));
  assert.match(code, /^PUBLIC_USER="crow-artifact-public"$/m);
  assert.match(code, /timeout "\$STEP_TIMEOUT" useradd --system --no-create-home --shell \/usr\/sbin\/nologin "\$PUBLIC_USER"/,
    "a system user with no home and no login shell");
  assert.doesNotMatch(code, /useradd[^\n]*--create-home/, "never with a home directory");
  assert.doesNotMatch(code, /useradd[^\n]*(?:-m\b|--home\b)/, "and never pointed at one");
  // The socket's group is that same user's group, and the script refuses to go on without it.
  assert.match(code, /getent group "\$PUBLIC_USER"/, "the matching group is checked before anything is written");
});

test("scripts/artifact-public holds no real host, IP or user", () => {
  const scanned = files();
  assert.ok(scanned.length >= 4, "the directory is there to scan");
  for (const name of scanned) {
    const text = readFileSync(join(DIR, name), "utf8");
    assert.doesNotMatch(text, /\.ts\.net\b/i, `${name}: no tailnet host`);
    // The one address allowed: the loopback health check. Every other dotted quad is a stand-in.
    for (const m of text.matchAll(/(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])/g)) {
      assert.equal(m[0], "127.0.0.1", `${name}: ${m[0]} is not a literal address this repo may ship`);
    }
    assert.doesNotMatch(text, /\/(?:home|Users)\/[A-Za-z0-9._-]+/, `${name}: no real home directory`);
    assert.doesNotMatch(text, /\bssh\s+(?:[^\s@]+@)?[A-Za-z0-9-]+\b/, `${name}: no ssh target`);
    assert.doesNotMatch(text, /\b[A-Za-z0-9._-]+@[A-Za-z0-9-]+\.(?:lan|local|internal)\b/i, `${name}: no real login`);
  }
});

test("install.sh resolves node and the working directory from the existing gateway unit", () => {
  const code = stripShellComments(read(INSTALL));

  // The binary and the directory come from the unit that is running, read-only.
  assert.match(code, /systemctl show -p ExecStart --value "\$GATEWAY_UNIT_NAME"/,
    "ExecStart is read off crow-gateway.service");
  assert.match(code, /systemctl show -p WorkingDirectory --value "\$GATEWAY_UNIT_NAME"/,
    "and so is its WorkingDirectory");
  assert.match(code, /unit_exec_path\(\)/, "with a parser for the `{ path=... ; argv[]=... }` block");
  assert.match(code, /sed -n 's\/\^\.\*\[ \{\]path=/,
    "path= is taken up to the next ' ;'");

  // A unit whose ExecStart is node: that node. A unit whose ExecStart is npm: the node beside it.
  assert.match(code, /^\s*node\)\s*$/m, "node is a case of its own");
  assert.match(code, /^\s*npm\)\s*$/m, "npm is a case of its own");
  assert.match(code, /dirname -- "\$UNIT_EXEC_PATH"\)\/node/,
    "npm is a node program, so the node in the same directory is the one it runs under");
  assert.match(code, /refuse .*only when that is node itself/, "anything else is refused");

  // The version: the major package.json declares, compared with what the binary reports.
  assert.match(code, /package\.json/, "the declared major comes from package.json");
  assert.match(code, /engines/, "… out of its engines field");
  assert.match(code, /WANT_NODE_MAJOR=/, "as WANT_NODE_MAJOR");
  assert.match(code, /"\$NODE_BIN" -v/, "the resolved node is actually run");
  assert.match(code, /\[ "\$GOT_NODE_MAJOR" = "\$WANT_NODE_MAJOR" \]/,
    "and its major must equal the declared one");
  assert.match(code, /could not read a node major/, "an unparseable engines field is refused, not guessed");

  // The working directory must be this very checkout, so a worktree run cannot repoint prod.
  assert.match(code, /realpath -- "\$UNIT_WORKDIR"/, "the unit's directory is resolved");
  assert.match(code, /\[ "\$UNIT_WORKDIR_REAL" = "\$APP_DIR_REAL" \]/,
    "and compared for equality with this checkout");
  assert.match(code, /worktree can never repoint production/,
    "with the reason spelled out in the refusal");

  // ... and node never comes from PATH.
  assert.doesNotMatch(code, /command -v node/, "node is never taken from PATH");
  assert.doesNotMatch(code, /\bwhich node\b/, "nor from `which`");

  // The drop-in therefore cannot pin a working directory of its own: the unit keeps its.
  const dropInCode = read(DROP_IN).split("\n").filter((line) => !/^\s*#/.test(line)).join("\n");
  assert.equal(dropInCode.includes("WorkingDirectory"), false,
    "the drop-in template has no WorkingDirectory= at all");
});

test("the drop-in leaves the boot guard and environment alone", () => {
  // Comment lines are stripped first: the header explains what the drop-in deliberately does
  // NOT restate, and the check is about the unit lines.
  const codeOnly = read(DROP_IN).split("\n").filter((line) => !/^\s*[#;]/.test(line)).join("\n");
  for (const key of ["ExecStartPre", "ExecStopPost", "Environment", "EnvironmentFile", "TimeoutStartSec", "Restart"]) {
    assert.equal(codeOnly.includes(key), false,
      `the drop-in never mentions ${key}: that line belongs to the gateway's own unit`);
  }
  // What it does keep: the ExecStart reset and the one ExecStart line.
  const starts = unitDirectives(read(DROP_IN)).get("Service/ExecStart") ?? [];
  assert.deepEqual(starts, ["", "@NODE_BIN@ servers/gateway/index.js"]);
});

test("the drop-in wants the socket and does not require it", () => {
  const d = unitDirectives(read(DROP_IN));
  assert.equal(one(d, "Unit/Wants"), REPORTS_DOOR_SOCKET_UNIT,
    "Wants=: the gateway starts whether or not the door socket exists");
  assert.equal(one(d, "Unit/After"), REPORTS_DOOR_SOCKET_UNIT,
    "After=: the socket is still started first when it does exist");
  assert.equal(d.has("Unit/Requires"), false,
    "no Requires=: a missing door socket must never keep the gateway from starting");
  assert.equal(one(d, "Service/Sockets"), REPORTS_DOOR_SOCKET_UNIT,
    "the fd still arrives by socket activation");
  // The header says why, and says it about the 503 page, so the reason cannot quietly drift.
  const header = read(DROP_IN).split("\n").filter((line) => /^\s*#/.test(line)).join("\n");
  assert.match(header, /503/, "the comment names the page a listener answers without the socket");
});

/* ---------------------------------------------- the failure path: print, never restore, here */

test("a failure prints the restore command and the fire time and exits non-zero", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));

  const fn = functionLines(code, "on_fail");
  assert.ok(fn, "on_fail() is the single failure handler");
  const body = fn.lines.join("\n");

  // It names the failing step (recorded by fail), and prints the two things an operator needs.
  assert.match(body, /\$FAILED_STEP/, "the failing step is named");
  assert.match(body, /sudo \/bin\/bash \$RESTORE_SCRIPT/, "the exact restore command is printed");
  assert.match(body, /\$DEADMAN_FIRE_AT/, "the fire time is printed as an epoch");
  assert.match(body, /deadman_fire_time_human/, "and as a readable local time");
  assert.match(body, /exit "\$rc"/, "and it exits with the failing status");

  // IT STARTS THE UNDO AND NOTHING ELSE is left to it: the deadman's own service is asked for,
  // which runs the one restore.sh — so production is not left broken until the timer would have
  // fired — and no unit is stopped, no rule deleted and no user removed by this handler.
  assert.match(body, /timeout "\$STEP_TIMEOUT" systemctl start --no-block "\$DEADMAN_UNIT_NAME\.service"/,
    "the deadman's own service is started, under the step cap");
  assert.equal((body.match(/systemctl/g) ?? []).length > 0, true, "and systemctl is the only tool it runs");
  for (const cmd of ["ufw", "userdel", "useradd", "install -m", "rm ", "systemctl stop", "systemctl restart",
    "systemctl disable", "systemctl enable", "daemon-reload"]) {
    assert.equal(body.includes(cmd), false, `on_fail never runs ${cmd}`);
  }
  // The one systemctl EXECUTION is the start (the echo lines only quote the command's name).
  assert.equal((body.match(/timeout "\$STEP_TIMEOUT" systemctl/g) ?? []).length, 1,
    "exactly one capped systemctl call in the whole handler");
  // It is guarded by the armed flag, so a failure before the arm starts nothing at all.
  assert.match(body, /\[ "\$\{DEADMAN_ARMED:-0\}" = "1" \]/, "guarded by the deadman's armed flag");
  assert.match(body, /no deadman was armed yet/, "and the other branch says nothing was started");
  const armedZeroAt = codeLine(code, /^DEADMAN_ARMED=0$/);
  const armedOneAt = codeLine(code, /^DEADMAN_ARMED=1$/);
  assert.ok(armedZeroAt > 0, "the flag starts at 0");
  assert.ok(armedOneAt > codeLine(code, /systemd-run --on-active/),
    "and is only set after systemd accepted the arm");
  assert.equal((code.match(/^DEADMAN_ARMED=1$/gm) ?? []).length, 1, "one place sets it");
  // The undo it starts is the same script the timer runs: one implementation, not two.
  assert.match(body, /the undo is restore\.sh/, "the handler says restore.sh is the undo");
  // The only place the script's path appears is inside an announcement.
  for (const line of fn.lines) {
    if (!line.includes("$RESTORE_SCRIPT")) continue;
    assert.match(line.trim(), /^echo "/, `on_fail only prints the script's path: ${line.trim()}`);
  }

  // `fail` is what raises it: it records the step and returns non-zero, and -E is what makes the
  // failure inside a function fire the trap at all.
  const failFn = functionLines(code, "fail");
  assert.ok(failFn, "fail() is defined");
  assert.match(failFn.lines.join("\n"), /FAILED_STEP="\$\*"/, "fail records the failing step");
  assert.match(failFn.lines.join("\n"), /return 1/, "and returns non-zero");
  assert.match(code, /^set -Eeuo pipefail$/m, "errtrace is on");

  // The traps route all three signals into that one handler, and they are armed before the first
  // change — after the deadman exists, so the fire time it prints is already a fact.
  const errAt = codeLine(code, /^trap 'on_fail "\$\\?\?"' ERR$/);
  assert.ok(errAt > 0, "ERR is trapped into on_fail");
  assert.match(code, /^trap 'on_fail 143' TERM$/m, "TERM too, with the shell's 143");
  assert.match(code, /^trap 'on_fail 130' INT$/m, "and INT with 130");
  assert.ok(errAt > codeLine(code, /systemd-run --on-active/), "the trap is armed after the deadman");
  assert.ok(errAt < codeLine(code, /useradd --system/), "and before the first change on the host");
});

test("on_fail starts the deadman service and runs nothing else", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));
  const fn = functionLines(code, "on_fail");
  assert.ok(fn, "on_fail() is defined");
  const body = fn.lines.join("\n");

  // The undo it starts is the deadman's OWN service — the very restore.sh the timer would run —
  // so a failed install is put back at once instead of staying broken until the cap expires.
  assert.match(body, /timeout "\$STEP_TIMEOUT" systemctl start --no-block "\$DEADMAN_UNIT_NAME\.service"/,
    "the deadman's service is started, non-blocking and under the step cap");
  assert.equal((body.match(/timeout "\$STEP_TIMEOUT" systemctl/g) ?? []).length, 1,
    "and that start is the only systemctl call in the handler");
  for (const forbidden of [/\bufw\b/, /userdel/, /useradd/, /restart/, /disable/, /enable /, /daemon-reload/, /rm -/, /install -m/]) {
    assert.equal(forbidden.test(body), false, `on_fail runs no ${forbidden}`);
  }
  // It is guarded by the armed flag, so a failure before the arm starts nothing at all.
  assert.match(body, /if \[ "\$\{DEADMAN_ARMED:-0\}" = "1" \]; then/, "guarded by the armed flag");
  assert.match(code, /^DEADMAN_ARMED=0$/m, "the flag starts false");
  const armedAt = codeLine(code, /^DEADMAN_ARMED=1$/);
  assert.ok(armedAt > codeLine(code, /systemd-run --on-active/),
    "and it is only set after systemd accepted the arm");
  assert.equal((code.match(/^DEADMAN_ARMED=1$/gm) ?? []).length, 1, "one place sets it");
  assert.match(body, /no deadman was armed yet, so no undo was started/, "the unarmed branch says nothing was started");

  // The guidance is all still printed: the failing step, the manual command, the fire time, the exit.
  assert.match(body, /\$FAILED_STEP/, "the failing step is named");
  assert.match(body, /sudo \/bin\/bash \$RESTORE_SCRIPT/, "the exact manual command is still printed");
  assert.match(body, /\$DEADMAN_FIRE_AT/, "and the fire time");
  assert.match(body, /exit "\$rc"/, "then it exits with the failing status");
});

test("a failure inside render_template reaches the failure handler", () => {
  const code = stripShellComments(read(INSTALL));

  // Ordering is the behavior: the trap is armed before the first render call, so a failed render
  // is trapped rather than returned to a caller that carries on with an empty staged file.
  const trapAt = codeLine(code, /^trap 'on_fail "\$\\?\?"' ERR$/);
  const callAt = codeLine(code, /^render_template "\$SOCKET_UNIT_TEMPLATE" /);
  assert.ok(trapAt > 0 && callAt > 0, "both the trap and the first render call exist");
  assert.ok(callAt > trapAt, "render_template is first called after the ERR trap is armed");

  const fnAt = code.indexOf("render_template() {");
  assert.ok(fnAt > 0, "render_template is a function");
  const body = code.slice(fnAt, code.indexOf("\nSTAGE=", fnAt));
  assert.match(body, /\[ -f "\$tpl" \] \|\| fail /, "a missing template calls fail");
  assert.match(body, /\|\| fail "could not render \$tpl"/, "a failed sed calls fail");
  assert.match(body, /fail "\$tpl still carries the placeholder/, "an unfilled placeholder calls fail");

  // `fail` is what raises the trap: it returns non-zero, and -E is what makes that failure
  // inside a function fire the ERR trap instead of just returning 1.
  assert.match(code, /^fail\(\)\s*\{[\s\S]*?return 1\b/m, "fail returns non-zero");
  assert.match(code, /^set -Eeuo pipefail$/m, "with errtrace on for the function it is called from");
});

test("restart is non-blocking and waits for a new InvocationID before polling health", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));

  assert.match(code, /timeout "\$STEP_TIMEOUT" systemctl restart --no-block "\$GATEWAY_UNIT_NAME"/,
    "the restart is asked for under the step cap, without blocking");
  assert.equal(/timeout "\$STEP_TIMEOUT" systemctl restart "\$GATEWAY_UNIT_NAME" \|\| fail/.test(code), false,
    "a blocking restart would be killed inside its 60 s cap while the unit allows 15min to start");

  const idAt = code.indexOf("systemctl show -p InvocationID --value");
  const restartAt = code.indexOf("restart --no-block");
  assert.ok(idAt > 0, "the running gateway's InvocationID is read");
  assert.ok(restartAt > idAt, "BEFORE the restart is asked for, so /health cannot be the old process's");

  const waitAt = code.indexOf("wait_for_new_gateway_invocation()");
  assert.ok(waitAt > restartAt, "there is a wait for the new process");
  const waitBody = code.slice(waitAt, code.indexOf("\nif ! wait_for_new_gateway_invocation", waitAt));
  assert.match(waitBody, /systemctl is-active "\$GATEWAY_UNIT_NAME"/, "it requires the unit to be active");
  assert.match(waitBody, /\[ "\$now" != "\$GATEWAY_INVOCATION_ID" \]/, "and a DIFFERENT InvocationID");
  assert.match(waitBody, /deadline=\$\(\( SECONDS \+ GATEWAY_INVOCATION_WAIT \)\)/,
    "bounded to the named GATEWAY_INVOCATION_WAIT (whose value the deadman's cap is added up from)");
  assert.match(waitBody, /timeout 10 sleep 5/, "in 5 s steps");

  const gateAt = code.indexOf("if ! wait_for_new_gateway_invocation; then");
  const healthAt = code.indexOf("if ! wait_for_gateway_health; then");
  assert.ok(gateAt > 0, "a failed wait fails the run");
  assert.ok(healthAt > gateAt, "/health is polled only after the new process is confirmed");
  assert.match(code.slice(gateAt, gateAt + 250), /fail "/, "and that failure reaches the handler");
});

test("the ufw check compares the exact rule against ufw show added", () => {
  const code = stripShellComments(read(INSTALL));

  assert.match(code, /ufw show added/, "the added-rules list is what is read");
  assert.match(code, /UFW_RULE=\(allow in on "\$CROW_ARTIFACT_BRIDGE_IF" from "\$CROW_ARTIFACT_SIDECAR_IP"/,
    "the rule's words are written once");
  assert.match(code, /UFW_EXPECTED="ufw \$\{UFW_RULE\[\*\]\}"/, "as one exact line");
  assert.match(code, /if \[ "\$line" = "\$UFW_EXPECTED" \]/, "compared for exact line equality");
  assert.match(code, /timeout "\$STEP_TIMEOUT" ufw show added/, "under a timeout");
  assert.match(code, /ufw "\$\{UFW_RULE\[@\]\}"/, "and the rule added is those same words");

  // The old substring test on `ufw status` is gone: a rule for another source, interface or port
  // must never be mistaken for this one.
  assert.doesNotMatch(code, /done <<<"\$UFW_STATUS"/, "the status text is not scanned for a rule");
  assert.doesNotMatch(code, /\*"\$CROW_ARTIFACT_SIDECAR_IP"\*/, "no wildcard match on the address");
});

test("install.sh records the previous unit state and restore.sh puts it back", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));

  for (const name of ["PREV_SOCKET_ENABLED", "PREV_SOCKET_ACTIVE", "PREV_LISTENER_ENABLED", "PREV_LISTENER_ACTIVE"]) {
    assert.match(code, new RegExp(`^${name}=`, "m"), `${name} is recorded`);
    assert.match(code, new RegExp(`state_set ${name} `), `${name} reaches the restore state file`);
  }
  assert.match(code, /systemctl is-enabled "\$unit"/, "from systemctl is-enabled");
  assert.match(code, /systemctl is-active "\$unit"/, "and systemctl is-active");
  assert.match(code, /""\|not-found\|unknown\|error\)/, "with not-found and errors read as absent");

  // Recorded before anything on the host changes.
  const recordedAt = codeLine(code, /^PREV_SOCKET_ENABLED=/);
  const firstChangeAt = codeLine(code, /useradd --system/);
  assert.ok(recordedAt > 0, "the state is recorded");
  assert.ok(firstChangeAt > recordedAt, "before the first change (the system user)");

  // The restore reads those values back out of the state file, so a deadman run — with no installer
  // process alive — puts back the same state a hand-run undo would.
  const body = scriptBody(read(INSTALL));
  assert.match(body, /restore_unit_state "\$SOCKET_UNIT" SOCKET_UNIT_PRESENT PREV_SOCKET_ENABLED PREV_SOCKET_ACTIVE/,
    "the socket's state is put back");
  assert.match(body, /restore_unit_state "\$LISTENER_UNIT" LISTENER_UNIT_PRESENT PREV_LISTENER_ENABLED PREV_LISTENER_ACTIVE/,
    "and the listener's");

  const helperAt = body.indexOf("restore_unit_state() {");
  assert.ok(helperAt > 0, "through a helper");
  const helper = body.slice(helperAt, body.indexOf('\nrestore_unit_state "$SOCKET_UNIT"', helperAt));
  assert.match(helper, /\[ "\$\(state_get "\$flag"\)" != "1" \]/, "a unit this run created has no backup copy");
  assert.match(helper, /systemctl disable "\$unit"/, "so it stays disabled");
  assert.match(helper, /enabled\|enabled-runtime\)/, "an enabled unit is re-enabled");
  assert.match(helper, /active\|activating\|reloading\)/, "a running unit is started again");
});

/* ------------------------------------------------------------- the one deadman, armed first */

test("the deadman is armed before the first change", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));
  const deadmanAt = codeLine(code, /systemd-run --on-active/);
  assert.ok(deadmanAt > 0, "the undo is armed with systemd-run --on-active");
  const line = code.split("\n")[deadmanAt];
  assert.match(line, /--unit="\$DEADMAN_UNIT_NAME"/, "a named transient unit");
  assert.match(line, /--collect/, "collected, so a fired unit does not linger");
  assert.match(line, /\$\{DEADMAN_AFTER\}s/, "its cap is the named DEADMAN_AFTER");

  // The unit name is unique per run: a timestamp plus this shell's pid.
  assert.match(code, /^DEADMAN_DATE_STAMP="\$\(date \+%Y%m%d%H%M%S\)"$/m, "the name starts from a timestamp");
  assert.match(code, /^DEADMAN_STAMP="\$\{DEADMAN_DATE_STAMP\}-\$\$"$/m, "and is made unique per run with $$");

  // Everything that changes the host comes AFTER it, or an install killed in between would have no
  // out-of-process undo watching it — including every state file entry that records a change.
  for (const re of [
    /useradd --system/,
    /^install -m 0644/,
    /ufw "\$\{UFW_RULE\[@\]\}"/,
    /systemctl daemon-reload/,
    /systemctl enable/,
    /systemctl restart --no-block "\$GATEWAY_UNIT_NAME"/,
    /mkdir -p "\$DROP_IN_DIR"/,
    /state_set GATEWAY_TOUCHED 1/,
    /state_set DROP_IN_DIR_CREATED 1/,
    /state_set USER_CREATED 1/,
    /state_set UFW_RULE_ADDED 1/,
  ]) {
    const at = codeLine(code, re);
    assert.ok(at > 0, `${re} is in the source`);
    assert.ok(at > deadmanAt, `${re} must not run before the deadman is armed (line ${at} vs ${deadmanAt})`);
  }

  // The backup copies and the state file's initial values come first — the deadman has to run a
  // script that already exists and already knows what it would put back.
  for (const re of [/^restore_one|^snapshot_file "\$DROP_IN_DEST"/, /\} > "\$RESTORE_SCRIPT"/, /^state_set GATEWAY_TOUCHED 0/]) {
    const at = codeLine(code, re);
    assert.ok(at > 0, `${re} is in the source`);
    assert.ok(at < deadmanAt, `${re} happens before the deadman is armed (line ${at} vs ${deadmanAt})`);
  }

  // A deadman that cannot be armed is a refusal with nothing changed: before this point the host has
  // not been touched, so there is nothing to undo — and an install with no out-of-process undo must
  // not start at all. Exit 2, like every other refusal here.
  assert.match(code, /\|\| abort_unarmed "the 'systemd-run' command is missing/, "a host without systemd-run is refused");
  assert.match(code, /if ! timeout "\$STEP_TIMEOUT" systemd-run --on-active=[\s\S]{0,400}?abort_unarmed "/,
    "and so is an arm that fails");
  const unarmed = functionLines(code, "abort_unarmed");
  assert.ok(unarmed, "abort_unarmed() exists");
  assert.match(unarmed.lines.join("\n"), /exit 2/, "both exit 2, the refusal code");
  assert.match(unarmed.lines.join("\n"), /rm -rf -- "\$RESTORE_DIR"/,
    "and they take the half-written backup directory with them");
});

test("the deadman runs restore.sh through /bin/bash", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));
  const lines = code.split("\n");

  // /run is noexec on the target box, so exec'ing the script itself fails (203/EXEC) and the deadman
  // would never undo anything. The interpreter is absolute and comes first; the script is its ARGUMENT.
  const armAt = codeLine(code, /systemd-run --on-active/);
  assert.ok(armAt > 0, "the deadman is armed with systemd-run");
  assert.match(lines[armAt], /--collect \/bin\/bash "\$RESTORE_SCRIPT"/,
    '--collect /bin/bash "$RESTORE_SCRIPT": the interpreter is the program, the script its argument');

  const comments = read(INSTALL).split("\n").filter((l) => /^\s*#/.test(l)).join("\n");
  assert.match(comments, /noexec/, "the comment says why (a noexec /run cannot exec the script itself)");
});

test("restore.sh is run only through /bin/bash", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));

  // Every mention of the script in this installer's own code is one of: an absolute interpreter in
  // front of it, a redirect that writes it, a command that never executes its operand, or printed
  // text telling a human what to run. Nothing else may start it.
  const NON_EXEC = /^\s*(?:chmod|install|rm|cp|cat|ls|stat|\[)/;
  const offenders = [];
  code.split("\n").forEach((line, i) => {
    if (!line.includes("$RESTORE_SCRIPT")) return;
    const viaBash = /\/bin\/bash\s+"\$RESTORE_SCRIPT"/.test(line);
    const redirect = />{1,2}\s*"\$RESTORE_SCRIPT"/.test(line);
    const printed = /(?:echo|log)\b[^\n]*\$RESTORE_SCRIPT/.test(line) || /\|\|\s*(?:abort_clean|fail)\b/.test(line);
    if (!(viaBash || redirect || printed || NON_EXEC.test(line))) offenders.push(`${i + 1}: ${line.trim()}`);
  });
  assert.deepEqual(offenders, [], `no line starts the script without an interpreter: ${offenders.join(" | ")}`);

  // The one execution site is the deadman; the operator's own command is printed, not run.
  assert.equal((code.match(/\/bin\/bash "\$RESTORE_SCRIPT"/g) ?? []).length, 1,
    "exactly one line executes restore.sh, and it is the deadman arm");
  assert.match(code, /sudo \/bin\/bash \$RESTORE_SCRIPT/, "and the operator is told to run the same thing by hand");
});

/* ------------------------------------- the earlier run's deadman is refused, never adopted */

test("the preflight refuses while a deadman timer is active", () => {
  const source = read(INSTALL);
  const code = stripGeneratedScript(stripShellComments(source));

  // Ordering is the behaviour: the preflight is CALLED before the backup directory exists and
  // before anything is armed or changed, so a refusal cannot leave a second backup dir behind.
  const callAt = codeLine(code, /^refuse_on_active_deadman$/);
  const listAt = codeLine(code, /systemctl list-units --type=timer --state=active/);
  const backupAt = codeLine(code, /^RESTORE_DIR="\$\(mktemp -d \/run\/crow-artifact-public-restore/);
  const armAt = codeLine(code, /systemd-run --on-active/);
  const useraddAt = codeLine(code, /useradd --system/);
  assert.ok(listAt > 0, "the active timers are listed at all");
  assert.ok(callAt > 0, "and the preflight is called");
  assert.ok(callAt < backupAt, `the preflight runs before the backup dir is created (${callAt} vs ${backupAt})`);
  assert.ok(callAt < armAt, "and before the deadman is armed");
  assert.ok(callAt < useraddAt, "and before the first change on the host");
  assert.ok(listAt < callAt, "the list-units read is inside the function that call reaches");
  // Only the deadman's own timers can block this run: a stranger's timer is never named here.
  assert.match(code, /^DEADMAN_UNIT_PREFIX="crow-artifact-public-deadman-"$/m, "the prefix is named once");
  assert.match(code, /--no-legend --plain "\$\{DEADMAN_UNIT_PREFIX\}\*\.timer"/,
    "and only that prefix, with .timer, is listed");

  // Behaviour: the preflight function, lifted out with its helper, against a stub systemctl that
  // reports one active deadman timer whose service names a backup directory's restore.sh.
  const work = tempDir("artifact-public-preflight-");
  const bin = join(work, "bin");
  mkdirSync(bin, { recursive: true });
  const calls = join(work, "called.log");
  const timer = "crow-artifact-public-deadman-20260101000000-4242.timer";
  const backupDir = "/run/crow-artifact-public-restore.ABC123";
  writeFileSync(join(bin, "systemctl"),
    `#!/usr/bin/env bash\n`
    + `printf 'systemctl %s\\n' "$*" >> ${JSON.stringify(calls)}\n`
    + `case "$*" in\n`
    + `  *list-units*) printf '%s loaded active waiting %s\\n' ${JSON.stringify(timer)} "a deadman from an earlier run" ;;\n`
    + `  *"show -p ExecStart"*) printf '{ path=/bin/bash ; argv[]=/bin/bash ${backupDir}/restore.sh ; ignore_errors=no ; }\\n' ;;\n`
    + `esac\n`
    + `exit 0\n`, { mode: 0o755 });

  const helper = functionLines(code, "deadman_restore_script_of");
  const preflight = functionLines(code, "refuse_on_active_deadman");
  assert.ok(helper, "deadman_restore_script_of() is in install.sh");
  assert.ok(preflight, "refuse_on_active_deadman() is in install.sh");
  const script = [
    "STEP_TIMEOUT=60",
    'DEADMAN_UNIT_PREFIX="crow-artifact-public-deadman-"',
    helper.lines.join("\n"),
    preflight.lines.join("\n"),
    "refuse_on_active_deadman",
    "",
  ].join("\n");
  const run = spawnSync("bash", ["-c", script], { encoding: "utf8", env: { PATH: `${bin}:/usr/bin:/bin` } });
  assert.equal(run.status, 2, `an armed deadman is a refusal (exit 2): ${run.stdout}${run.stderr}`);
  assert.match(run.stderr, /refusing/, "it says it refused");
  assert.ok(run.stderr.includes(timer), "it names the active timer");
  assert.ok(run.stderr.includes(backupDir), "and the backup directory whose restore.sh that timer would run");
  assert.match(run.stderr, /holds restore\.sh/, "and says which kind of directory holds restore.sh");
  assert.ok(run.stderr.includes(`to keep that run: sudo touch ${backupDir}/keep`), "it says how to keep that run");
  assert.ok(run.stderr.includes(`to keep that run: sudo touch ${backupDir}/keep and then sudo /bin/bash ${backupDir}/restore.sh`),
    "and that keeping it means running its restore.sh too, to retire the timer");
  assert.ok(run.stderr.includes(`to undo it: sudo /bin/bash ${backupDir}/restore.sh`), "or how to undo it");
  assert.match(run.stderr, /changed nothing/, "and that this run changed nothing");
  const ran = existsSync(calls) ? readFileSync(calls, "utf8").split("\n").filter(Boolean) : [];
  assert.ok(ran.length > 0, "the stub was consulted");
  for (const line of ran) {
    assert.match(line, /^systemctl /, `only systemctl runs before the refusal: ${line}`);
  }
  assert.equal(ran.some((line) => /systemd-run|mktemp|useradd/.test(line)), false,
    "nothing is armed, no backup dir is made and no user is touched");
});

test("the active-deadman refusal offers keep-then-restore and undo, in that order, with real paths", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));
  const helper = functionLines(code, "deadman_restore_script_of");
  const preflight = functionLines(code, "refuse_on_active_deadman");
  assert.ok(helper, "deadman_restore_script_of() is in install.sh");
  assert.ok(preflight, "refuse_on_active_deadman() is in install.sh");
  const timer = "crow-artifact-public-deadman-20260101000000-4242.timer";
  const backupDir = "/run/crow-artifact-public-restore.TEST";

  // Behaviour, through the same harness the preflight test above uses: the refusal function is
  // lifted out with its helper and run against a stub systemctl whose one active timer's service
  // names <backupDir>/restore.sh after /bin/bash. `execStart` is what its `show -p ExecStart`
  // prints, so the readable-script and no-readable-script cases share one setup.
  const runPreflight = (execStart) => {
    const work = tempDir("artifact-public-preflight-keep-");
    const bin = join(work, "bin");
    mkdirSync(bin, { recursive: true });
    writeFileSync(join(bin, "systemctl"),
      `#!/usr/bin/env bash\n`
      + `case "$*" in\n`
      + `  *list-units*) printf '%s loaded active waiting %s\\n' ${JSON.stringify(timer)} "a deadman from an earlier run" ;;\n`
      + `  *"show -p ExecStart"*) ${execStart} ;;\n`
      + `esac\n`
      + `exit 0\n`, { mode: 0o755 });
    const script = [
      "STEP_TIMEOUT=60",
      'DEADMAN_UNIT_PREFIX="crow-artifact-public-deadman-"',
      helper.lines.join("\n"),
      preflight.lines.join("\n"),
      "refuse_on_active_deadman",
      "",
    ].join("\n");
    return spawnSync("bash", ["-c", script], { encoding: "utf8", env: { PATH: `${bin}:/usr/bin:/bin` } });
  };

  const run = runPreflight(`printf '{ path=/bin/bash ; argv[]=/bin/bash ${backupDir}/restore.sh ; ignore_errors=no ; }\\n'`);
  assert.equal(run.status, 2, `an armed deadman is still a refusal (exit 2): ${run.stdout}${run.stderr}`);
  const err = run.stderr;

  // The keep action comes first and carries BOTH commands: touching keep alone leaves the timer
  // armed, so the same message has to say to run the restore that retires it.
  const keepTouch = err.indexOf(`sudo touch ${backupDir}/keep`);
  const keepRestore = err.indexOf(`sudo /bin/bash ${backupDir}/restore.sh`);
  const undo = err.indexOf(`to undo it: sudo /bin/bash ${backupDir}/restore.sh`);
  assert.ok(keepTouch >= 0, `the keep option uses the real backup directory: ${err}`);
  assert.ok(keepRestore > keepTouch, "and its restore.sh comes after the touch, as one action");
  assert.ok(undo > keepRestore, `the undo option follows the keep option: ${err}`);
  assert.ok(err.indexOf("to keep that run:") < err.indexOf("to undo it:"), "the keep option is printed first");
  assert.equal((err.match(/to keep that run:/g) ?? []).length, 1, "one keep option for the one timer");
  assert.equal((err.match(/to undo it:/g) ?? []).length, 1, "and one undo option for it");
  assert.match(err, /with keep present, restore\.sh changes nothing and only retires the timer/,
    "it says what a keep really does: retire the timer, change nothing");
  assert.doesNotMatch(err, /accept that run instead/, "the old 'accept that run instead' wording is gone");
  assert.doesNotMatch(err, /<dir>/, "and no placeholder is used when the real directory is known");
  assert.match(err, /changed nothing/, "the refusal still says this run changed nothing");

  // No timer's script can be read: the same two commands, in the same order, name <dir>, and the
  // directories found on disk are listed under them for the operator to match.
  const blind = runPreflight("printf ''");
  assert.equal(blind.status, 2, "an active timer with no readable script is still a refusal");
  const keepFallback = blind.stderr.indexOf("to keep that run: sudo touch <dir>/keep");
  const undoFallback = blind.stderr.indexOf("to undo it: sudo /bin/bash <dir>/restore.sh");
  assert.ok(keepFallback >= 0, `the keep option falls back to <dir>: ${blind.stderr}`);
  assert.ok(undoFallback > keepFallback, "with the undo option second");
  assert.match(blind.stderr, /<dir> is the matching directory listed below/, "and says what <dir> stands for");
  assert.ok(blind.stderr.indexOf("the backup directories on this machine are:") > undoFallback,
    `the directories found on disk are listed below the two commands: ${blind.stderr}`);
});

test("install.sh has no restoring trap, lock, committed marker or second timer", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));

  // The machinery that was removed, all of it, in one place: nothing here may come back.
  assert.doesNotMatch(code, /\bflock\b/, "no flock lock");
  assert.doesNotMatch(code, /RESTORE_COMMITTED|\/committed\b/, "no committed marker");
  assert.doesNotMatch(code, /RESTORE_DONE|\/done\b/, "no done marker either");
  assert.doesNotMatch(code, /DEADMAN_GATEWAY|deadman-[^\n]*-g\b/, "no second, gateway-phase timer");
  assert.doesNotMatch(code, /\bretry\b/i, "no retry/hand-off logic");
  assert.doesNotMatch(code, /\brollback\b/i, "no rollback function");
  assert.doesNotMatch(code, /RUN_ID|run id/, "no run id stamped anywhere");

  // Exactly one systemd-run EXECUTION: the arm. (The `command -v systemd-run` presence check runs
  // nothing, and the two refusal messages only mention the command by name.)
  assert.equal((code.match(/systemd-run --on-active="\$\{DEADMAN_AFTER\}s"/g) ?? []).length, 1,
    "one systemd-run call, the arm");
  assert.equal((code.match(/--unit=/g) ?? []).length, 1, "one --unit=, so one timer");
  assert.equal((code.match(/--on-active="\$\{DEADMAN_AFTER\}s"/g) ?? []).length, 1,
    "and one deadline, the named cap");

  // The traps: ERR, TERM and INT, all three into on_fail, which is a printing function, plus the
  // one `trap -` that clears them INSIDE that handler so a second failure cannot re-enter it. A trap
  // that restored anything would be a second undo implementation.
  const trapLines = code.split("\n").map((line) => line.trim()).filter((line) => /^trap /.test(line));
  assert.deepEqual(trapLines, [
    "trap - ERR TERM INT",
    `trap 'on_fail "$?"' ERR`,
    "trap 'on_fail 143' TERM",
    "trap 'on_fail 130' INT",
  ], "the only traps are the three print-only handlers and their own clear");
  const onFail = functionLines(code, "on_fail");
  assert.ok(onFail, "on_fail exists");
  assert.ok(onFail.lines.some((line) => line.trim() === "trap - ERR TERM INT"),
    "the clear happens inside on_fail, so a second failure cannot re-enter it");
  // The one command it runs is starting the deadman's own service — the same restore.sh the timer
  // runs — and nothing else: no ufw, no userdel/useradd, no file install or removal.
  for (const forbidden of [/\bufw\b/, /userdel/, /useradd/, /rm -/, /install -m/]) {
    assert.equal(forbidden.test(onFail.lines.join("\n")), false,
      `on_fail runs no command (${forbidden})`);
  }
  assert.equal((code.split("\n").filter((line) => /^\s*on_fail\(\)/.test(line)).length), 1,
    "and there is exactly one such handler");

  // The success path does not stop, clear or disarm anything either, and it never removes the
  // backup the deadman and the operator's keep file live in: the only removals belong to the two
  // pre-deadman aborts, which run before anything on the host has changed.
  assert.doesNotMatch(code, /systemctl stop .*DEADMAN/, "nothing stops the deadman");
  const removals = code.split("\n").filter((line) => /rm -rf -- "\$RESTORE_DIR"/.test(line));
  assert.equal(removals.length, 2, `only the two aborts remove it (got ${removals.length})`);
  for (const helper of ["abort_clean", "abort_unarmed"]) {
    const fn = functionLines(code, helper);
    assert.ok(fn && fn.lines.some((line) => /rm -rf -- "\$RESTORE_DIR"/.test(line)),
      `${helper} is one of them`);
  }
  assert.ok(codeLine(code, /rm -rf -- "\$RESTORE_DIR"/) < codeLine(code, /systemd-run --on-active/),
    "and both run only before the deadman exists, so nothing depends on that directory yet");
});

test("install.sh never touches the keep file", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));

  // The keep file is the operator's decision. This script prints the command that creates it and
  // exits; it never creates, writes, reads or removes it. The only mentions allowed are the one
  // assignment, the printed guidance, and the generated script's own header text.
  const mentions = code.split("\n").filter((line) => /RESTORE_KEEP|\bkeep\b/.test(line));
  assert.ok(mentions.length > 0, "the keep file is named at all");
  for (const line of mentions) {
    const trimmed = line.trim();
    assert.ok(/^RESTORE_KEEP="\$RESTORE_DIR\/keep"$/.test(trimmed) || /^(?:log|echo|printf)\b/.test(trimmed),
      `the keep file is only assigned once and otherwise printed: ${trimmed}`);
  }
  // No file command ever takes it as its operand: the only `touch` in this file is inside the text
  // an operator is told to run.
  for (const line of mentions) {
    assert.doesNotMatch(line.trim(), /^(?:touch|rm|install|chmod|cat|cp|mv|ln|mkdir)\b/,
      `install.sh never runs a file command on the keep file: ${line.trim()}`);
  }
  assert.doesNotMatch(code, /\$RESTORE_KEEP\s*$|[<>]{1,2}\s*"?\$RESTORE_KEEP/m,
    "and nothing redirects into or out of it");
  assert.match(code, /log "KEEP THIS INSTALL, once you have read the checks above: sudo touch \$RESTORE_KEEP"/,
    "the exact keep command is what it prints");

  // The printed guidance also says when the deadman fires, so the operator knows the window.
  assert.match(code, /log "the deadman \$DEADMAN_TIMER fires at \$\(deadman_fire_time_human\) \(epoch \$DEADMAN_FIRE_AT\)/,
    "and the fire time it must beat");

  // It is printed on the SUCCESS path, after every check, and the run then exits 0.
  const printAt = codeLine(code, /log "KEEP THIS INSTALL/);
  const exitAt = code.split("\n").reduce((acc, line, i) => (/^exit 0$/.test(line) ? i : acc), -1);
  for (const re of [/if ! wait_for_new_gateway_invocation; then/, /if ! wait_for_gateway_health; then/, /if ! round_trip_through_listener; then/]) {
    assert.ok(codeLine(code, re) < printAt, `${re} comes before the keep command is printed`);
  }
  assert.ok(printAt < exitAt, "and the script exits after printing it");
  assert.equal((code.match(/^exit 0$/gm) ?? []).length, 1, "one success exit, and nothing after it but comments");
});

test("the deadman cap is derived from the step budgets and outlives the install wall clock", () => {
  const code = stripShellComments(read(INSTALL));
  const lines = code.split("\n");

  // The whole budget block, in the order install.sh writes it: the plain constants, then the derived
  // sums, then the wall clock and the deadman's cap. Evaluated the way the shell would, so the
  // relationships are recomputed here rather than trusted.
  const NAMES = [
    "STEP_TIMEOUT", "CAPPED_STEPS", "GATEWAY_INVOCATION_WAIT", "GATEWAY_INVOCATION_SLACK",
    "GATEWAY_HEALTH_TRIES", "GATEWAY_HEALTH_INTERVAL", "GATEWAY_ROUND_TRIP_TRIES",
    "GATEWAY_ROUND_TRIP_INTERVAL", "GATEWAY_REQUEST_CAP", "INSTALL_STEP_BUDGET",
    "INSTALL_WAIT_BUDGET", "INSTALL_WORST_CASE", "WALL_CLOCK_MARGIN", "WALL_CLOCK_SECONDS",
    "WALL_CLOCK_KILL_AFTER", "DEADMAN_MARGIN", "DEADMAN_AFTER",
  ];
  const assignmentBlock = (name) => {
    const at = lines.findIndex((line) => line.startsWith(`${name}=`));
    assert.ok(at > 0, `${name} is defined in install.sh`);
    const block = [lines[at]];
    if (lines[at].includes("$((") && !lines[at].trimEnd().endsWith("))")) {
      for (let i = at + 1; i < lines.length; i++) {
        block.push(lines[i]);
        if (lines[i].trimEnd().endsWith("))")) break;
      }
    }
    return block.join("\n");
  };
  const budgetScript = `${NAMES.map(assignmentBlock).join("\n")}\n`
    + NAMES.map((name) => `printf '%s=%s\\n' ${name} "$${name}"`).join("\n");
  const budgetRun = spawnSync("bash", ["-c", budgetScript], { encoding: "utf8" });
  assert.equal(budgetRun.status, 0, `the budget block evaluates: ${budgetRun.stderr}`);
  const values = new Map(budgetRun.stdout.split("\n").filter(Boolean)
    .map((line) => [line.slice(0, line.indexOf("=")), Number(line.slice(line.indexOf("=") + 1))]));
  const evaluate = (name) => {
    const n = values.get(name);
    assert.ok(Number.isFinite(n) && n > 0, `${name} is a number of seconds (got '${n}')`);
    return n;
  };

  const step = evaluate("STEP_TIMEOUT");
  const capped = evaluate("CAPPED_STEPS");
  const wait = evaluate("GATEWAY_INVOCATION_WAIT");
  const slack = evaluate("GATEWAY_INVOCATION_SLACK");
  const tries = evaluate("GATEWAY_HEALTH_TRIES");
  const interval = evaluate("GATEWAY_HEALTH_INTERVAL");
  const trips = evaluate("GATEWAY_ROUND_TRIP_TRIES");
  const tripInterval = evaluate("GATEWAY_ROUND_TRIP_INTERVAL");
  const requestCap = evaluate("GATEWAY_REQUEST_CAP");
  const killafter = evaluate("WALL_CLOCK_KILL_AFTER");
  const margin = evaluate("WALL_CLOCK_MARGIN");

  // THE INSTALL'S WORST CASE, recomputed here from those constants: every capped step at its cap,
  // plus the InvocationID wait (with its overshoot), the /health poll and the round trip.
  const worst = step * capped + wait + slack
    + tries * (requestCap + interval) + trips * (requestCap + tripInterval);
  const installWorst = evaluate("INSTALL_WORST_CASE");
  assert.equal(installWorst, worst, `INSTALL_WORST_CASE is exactly that sum (${installWorst} vs ${worst})`);

  const wall = evaluate("WALL_CLOCK_SECONDS");
  const deadman = evaluate("DEADMAN_AFTER");

  // THE RELATIONSHIPS: the wall clock is above the install's own worst case, and the deadman's cap is
  // above the wall clock PLUS its kill-after, so the timer can never fire while this process lives.
  assert.ok(wall > installWorst, `the wall clock ${wall}s must exceed the install worst case ${installWorst}s`);
  assert.equal(wall, installWorst + margin, "and be that sum plus its named margin");
  assert.ok(deadman > wall + killafter,
    `the deadman cap ${deadman}s must exceed the wall clock plus the kill-after (${wall + killafter}s)`);
  assert.ok(deadman > installWorst, "which also puts it above the install's whole worst case");

  // Nothing in that arithmetic is a magic number: every term there is a named budget.
  for (const name of ["INSTALL_STEP_BUDGET", "INSTALL_WAIT_BUDGET", "INSTALL_WORST_CASE", "WALL_CLOCK_SECONDS", "DEADMAN_AFTER"]) {
    const block = assignmentBlock(name);
    assert.equal(/\d/.test(block), false, `no bare number is added for ${name}: ${block}`);
  }
  const arithmetic = ["INSTALL_STEP_BUDGET", "INSTALL_WAIT_BUDGET", "INSTALL_WORST_CASE", "WALL_CLOCK_SECONDS", "DEADMAN_AFTER"]
    .map(assignmentBlock).join("\n");
  for (const name of ["STEP_TIMEOUT", "CAPPED_STEPS", "GATEWAY_INVOCATION_WAIT", "GATEWAY_HEALTH_TRIES",
    "GATEWAY_ROUND_TRIP_TRIES", "GATEWAY_REQUEST_CAP"]) {
    assert.ok(arithmetic.includes(name), `the arithmetic is derived from ${name}`);
  }

  // The header states the window those numbers add up to, so the prose cannot drift from the code.
  const comments = read(INSTALL).split("\n").filter((line) => /^\s*#/.test(line)).join("\n");
  assert.match(comments, /worst-case window in which production can be down/i, "the header states the window");
  assert.ok(comments.includes(String(deadman)), `the header quotes the deadman cap (${deadman}s)`);
  assert.match(comments, /restore\.sh's own bounded work/, "and counts the undo's own worst case");
});

test("the header states the keep window and the success line prints the remaining time", () => {
  const comments = read(INSTALL).split("\n").filter((line) => /^\s*#/.test(line)).join("\n");
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));

  // The window is stated as what it IS — the deadman's cap minus what this run spends — with the
  // typical numbers written out of the named constants, and both caveats in the header.
  assert.match(comments, /THE KEEP WINDOW IS THE DEADMAN'S CAP MINUS THE TIME THIS RUN ACTUALLY TAKES/,
    "the keep window is named and derived");
  assert.match(comments, /2255 \/ 60 = 37\.6 minutes/, "the typical arithmetic is written out");
  assert.match(comments, /ABOUT 37 MINUTES/, "with the number an operator can act on");
  assert.match(comments, /`keep` touched\s+# AFTER the deadman has started does nothing/,
    "the first caveat: a keep after the restore has begun does nothing");
  assert.match(comments, /at the operator's own risk/, "the second: a keep before the checks pass is their own risk");

  // The remaining time is computed, not guessed: the fire epoch minus `date +%s`, in whole minutes.
  const remaining = functionLines(code, "deadman_remaining_minutes");
  assert.ok(remaining, "deadman_remaining_minutes() is defined");
  const body = remaining.lines.join("\n");
  assert.match(body, /DEADMAN_FIRE_AT - now/, "from the fire epoch");
  assert.match(body, /date \+%s/, "and the current time");
  assert.match(body, /left \/ 60/, "in whole minutes");

  // The success line prints it, and says the same two caveats in one sentence.
  const successAt = codeLine(code, /deadman_remaining_minutes\) minutes from now/);
  assert.ok(successAt > 0, "the success output prints the remaining minutes");
  const line = code.split("\n")[successAt];
  assert.match(line, /^log "/, "on a log line");
  assert.match(line, /\$\(deadman_remaining_minutes\) minutes from now/, "with the computed number");
  assert.match(line, /a keep touched after the deadman has started does nothing/, "caveat one, in that sentence");
  assert.match(line, /a keep touched before the checks above passed was at your own risk/, "and caveat two");
});

/* ------------------------------------------------------------- the generated undo script */

test("restore.sh keeps no marker or lock and logs every step to the journal", () => {
  const body = scriptBody(read(INSTALL));
  assert.ok(body.length > 2000, `the generated script is a real script (${body.length} chars)`);

  // Journal, not stdout-only: a deadman run has nobody watching a terminal.
  assert.match(body, /logger -t crow-artifact-public-restore/, "every action goes to the journal under its own tag");
  assert.match(body, /ATTENTION/, "with a loud line when the gateway does not come back");
  assert.match(body, /\/health/, "the gateway's /health is what it polls");
  assert.match(body, /timeout 10 curl/, "each request under its own cap");

  // NOTHING marks progress: no done marker, no ran marker, no lock, no run id. Every step is
  // re-run on every run, which is what makes a second run safe.
  for (const gone of ["RESTORE_DONE", "RESTORE_COMMITTED", "/done\"", "flock", "RUN_ID", "committed"]) {
    assert.equal(body.includes(gone), false, `the undo keeps no '${gone}' of any kind`);
  }
  assert.match(body, /each is a no-op when it is already done/, "and says that re-running is the repair path");

  // Guarded by the state file: only what THIS run created is removed, and `pending` (written
  // before the command, confirmed after) is treated like `1` — with an existence check first.
  assert.match(body, /case "\$\(state_get USER_CREATED\)" in\n  1\|pending\)/, "userdel is guarded by the state file");
  assert.match(body, /if id "\$PUBLIC_USER" >\/dev\/null 2>&1; then/, "and by `id`: a user that is not there is not removed");
  assert.match(body, /userdel "\$PUBLIC_USER"/, "and is the only place the user is deleted");
  assert.match(body, /case "\$\(state_get UFW_RULE_ADDED\)" in\n  1\|pending\)/, "so is the ufw delete");
  assert.match(body, /ufw_rule_is_present\(\)/, "with the exact line in `ufw show added` as the existence check");
  assert.match(body, /LC_ALL=C timeout "\$STEP_TIMEOUT" ufw show added/, "read under the C locale");
  assert.match(body, /LC_ALL=C timeout "\$STEP_TIMEOUT" ufw delete allow in on "\$BRIDGE_IF" from "\$SIDECAR_IP"/,
    "one source, one interface, one port, and the C locale");

  // The file restores are guarded the same way: copy back when it existed, remove it when it did not.
  assert.match(body, /if \[ "\$\(state_get "\$flag"\)" = "1" \] && \[ -f "\$snap" \]/, "each file restore re-decides");
  assert.match(body, /rmdir -- "\$DROP_IN_DIR"/, "the drop-in directory is removed only when this run made it");
  assert.match(body, /if \[ "\$\(state_get DROP_IN_DIR_CREATED\)" = "1" \]/, "… under that state guard");

  // Every step goes through `timeout`, so even the deadman's run is bounded.
  assert.match(body, /^\s*timeout "\$STEP_TIMEOUT" install -m 0644 --/m, "the file restores are capped");
  assert.match(body, /for unit in "\$LISTENER_UNIT" "\$SOCKET_UNIT"; do/, "both units are handled in one capped loop");
  assert.match(body, /systemctl restart --no-block "\$GATEWAY_UNIT"/, "the restart is asked for non-blocking");
  assert.match(body, /systemctl daemon-reload/, "a daemon-reload follows the file restores");

  // Standalone: nothing from the checkout, and no password of any kind.
  assert.doesNotMatch(body, /APP_DIR|package\.json|artifact-public\/install\.sh/, "it reads nothing from the checkout");
  assert.doesNotMatch(body, /read -s|\bsudo\b|sshpass/, "and takes no password");
});

test("restore.sh waits for a new InvocationID before polling health", () => {
  const body = scriptBody(read(INSTALL));

  // The old process can answer /health 200 for a moment, so an InvocationID read first and a
  // DIFFERENT, active one is what the restart is waited on — the installer's own trick, reused.
  const idAt = body.indexOf('systemctl show -p InvocationID --value "$GATEWAY_UNIT"');
  const restartAt = body.indexOf('systemctl restart --no-block "$GATEWAY_UNIT"');
  assert.ok(idAt > 0, "the gateway's InvocationID is read");
  assert.ok(restartAt > idAt, "BEFORE the restart is asked for");

  const waitAt = body.indexOf("wait_for_new_invocation() {");
  assert.ok(waitAt > 0, "and there is a wait for the new process");
  const waitBody = body.slice(waitAt, body.indexOf("\n}", waitAt));
  assert.match(waitBody, /\[ "\$now" != "\$old" \]/, "which requires a DIFFERENT InvocationID");
  assert.match(waitBody, /\[ "\$state" = "active" \]/, "and the unit to be active");
  assert.match(waitBody, /deadline=\$\(\( SECONDS \+ INVOCATION_WAIT \)\)/, "bounded, not open-ended");
  assert.match(waitBody, /ATTENTION/, "and loud when it never comes");

  const callAt = body.indexOf('wait_for_new_invocation "$GATEWAY_INVOCATION_ID"');
  assert.ok(callAt > restartAt, "the wait is called after the restart");
  const healthAt = body.lastIndexOf("if check_gateway; then");
  assert.ok(healthAt > callAt, "/health is trusted only after the new process is confirmed");
  // And every ATTENTION line goes through say(), which is the journal tag the undo is read under.
  assert.match(body, /logger -t crow-artifact-public-restore "\$\*"/, "ATTENTION goes to the journal tag");
  assert.match(body, /say "ATTENTION: \$GATEWAY_UNIT did not come back as a new, active process/,
    "a failed wait says so, in so many words, through say()");
});

test("restore.sh restarts the gateway only when this run touched it", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));

  // The fact is recorded in the state file BEFORE the install of either file the gateway reads,
  // so a run killed in between still leaves an undo that restarts the gateway it half changed.
  const setAt = codeLine(code, /state_set GATEWAY_TOUCHED 1/);
  const socketAt = codeLine(code, /install -m 0644 "\$STAGE\/\$SOCKET_UNIT_NAME"/);
  const dropInAt = codeLine(code, /install -m 0644 "\$STAGE\/\$DROP_IN_NAME"/);
  assert.ok(setAt > 0, "GATEWAY_TOUCHED reaches the restore state file");
  assert.ok(socketAt > 0 && dropInAt > 0, "both gateway-affecting files are installed here");
  assert.ok(setAt < socketAt, `recorded before the socket unit is installed (${setAt} vs ${socketAt})`);
  assert.ok(setAt < dropInAt, `and before the drop-in is (${setAt} vs ${dropInAt})`);
  assert.match(code, /^state_set GATEWAY_TOUCHED 0/m, "it starts false, before the deadman exists");

  // restore.sh restarts the gateway only under that flag, and says so otherwise. One restart only:
  // a second one would bounce a gateway this undo never changed.
  const body = scriptBody(read(INSTALL));
  const guardAt = body.indexOf('[ "$(state_get GATEWAY_TOUCHED)" = "1" ]');
  const restartAt = body.indexOf('systemctl restart --no-block "$GATEWAY_UNIT"');
  assert.ok(guardAt > 0, "the restart is guarded by the state file");
  assert.ok(restartAt > guardAt, "and sits inside that guard");
  assert.equal((body.match(/systemctl restart --no-block "\$GATEWAY_UNIT"/g) ?? []).length, 1,
    "exactly one restart in the whole undo script");
  assert.match(body, /not restarting \$GATEWAY_UNIT/, "the other branch says the gateway is left alone");
});

test("the backup lives in a root-only directory under /run", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));
  assert.match(code, /mktemp -d \/run\/crow-artifact-public-restore\.XXXXXX/,
    "a root-only tmpfs directory, which needs no assumption about /var/lib or /root");
  assert.match(code, /chmod 0700 "\$RESTORE_DIR"/, "mode 0700 on it");
  assert.doesNotMatch(code, /mktemp -d \/var\/lib/, "no assumption about /var/lib");
  assert.doesNotMatch(code, /mktemp -d \/root/, "and none about /root");
  assert.match(code, /chmod 0700 "\$RESTORE_SCRIPT"/, "the script itself is 0700");

  // What goes in: a copy of each of the three files and a state file, all before the deadman.
  assert.match(code, /snapshot_file "\$LISTENER_UNIT_DEST" LISTENER_UNIT_PRESENT/, "the listener unit is recorded");
  assert.match(code, /snapshot_file "\$SOCKET_UNIT_DEST" SOCKET_UNIT_PRESENT/, "the socket unit is recorded");
  assert.match(code, /snapshot_file "\$DROP_IN_DEST" DROP_IN_PRESENT/, "the drop-in is recorded");
  assert.match(code, /cp -a -- "\$target" "\$RESTORE_SNAPSHOT\/\$\(basename -- "\$target"\)"/, "with a copy when it exists");

  // The values are baked in quoted, and the body is not expanded when it is written.
  assert.match(code, /printf 'RESTORE_DIR=%q\\n' "\$RESTORE_DIR"/, "the paths are baked in quoted");
  assert.match(code, /printf 'GATEWAY_HEALTH_URL=%q\\n' "\$GATEWAY_HEALTH_URL"/, "… all of them");
  assert.match(code, /printf 'LISTENER_UNIT_DEST=%q\\n' "\$LISTENER_UNIT_DEST"/, "including the file destinations");
  assert.match(code, /printf 'DROP_IN_DEST=%q\\n' "\$DROP_IN_DEST"/, "which is how a temp dir can be restored instead");
  assert.match(code, /cat <<'RESTORE_BODY'/, "and the body is a quoted heredoc");
});

test("the restore state file is written when the user and the ufw rule are created", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));

  // Both start false when the backup is taken, before the deadman can fire.
  const initAt = codeLine(code, /state_set USER_CREATED 0/);
  assert.ok(initAt > 0, "USER_CREATED starts false");
  assert.ok(codeLine(code, /state_set UFW_RULE_ADDED 0/) > 0, "UFW_RULE_ADDED starts false");
  assert.ok(initAt < codeLine(code, /systemd-run --on-active/), "initialised before the deadman is armed");

  // Flipped the moment the thing happens, not at the end of the run.
  const userAddAt = codeLine(code, /useradd --system/);
  const userSetAt = codeLine(code, /state_set USER_CREATED 1/);
  assert.ok(userAddAt > 0 && userSetAt > userAddAt, "USER_CREATED is recorded after the useradd");
  assert.ok(userSetAt - userAddAt <= 6, `within a few lines of it (${userSetAt - userAddAt})`);

  const ufwAt = codeLine(code, /timeout "\$STEP_TIMEOUT" ufw "\$\{UFW_RULE\[@\]\}"/);
  const ufwSetAt = codeLine(code, /state_set UFW_RULE_ADDED 1/);
  assert.ok(ufwAt > 0 && ufwSetAt > ufwAt, "UFW_RULE_ADDED is recorded after the rule is added");
  assert.ok(ufwSetAt - ufwAt <= 6, `within a few lines of it (${ufwSetAt - ufwAt})`);

  // What already existed is recorded too, so the undo can tell "this run made it" from "it was here".
  assert.match(code, /state_set USER_EXISTED/, "whether the system user was already there");
  assert.match(code, /state_set UFW_RULE_EXISTED/, "and whether the exact rule was");

  // A state file that cannot be written fails the run: an undo that does not know what
  // this run created must not go on guessing.
  assert.match(code, /state_set USER_CREATED 1 \\\n\s*\|\| fail /, "a failed write fails the run");
  assert.match(code, /state_set UFW_RULE_ADDED 1 \\\n\s*\|\| fail /, "for the rule too");
  assert.match(code, /state_set DROP_IN_DIR_CREATED 1/, "and for the drop-in directory");
});

test("the pending markers are written before useradd and ufw allow", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));

  // A kill between the command and its confirmation is the window this closes: the marker is on
  // disk BEFORE the command runs, so the undo knows the thing MIGHT be this run's.
  const userPendingAt = codeLine(code, /state_set USER_CREATED pending/);
  const userAddAt = codeLine(code, /timeout "\$STEP_TIMEOUT" useradd --system/);
  const userConfirmAt = codeLine(code, /state_set USER_CREATED 1/);
  assert.ok(userPendingAt > 0, "USER_CREATED=pending is written");
  assert.ok(userAddAt > 0 && userConfirmAt > 0, "and the command and its confirmation are both there");
  assert.ok(userPendingAt < userAddAt, `pending precedes useradd (${userPendingAt} vs ${userAddAt})`);
  assert.ok(userConfirmAt > userAddAt, "and the confirmation follows it");

  const rulePendingAt = codeLine(code, /state_set UFW_RULE_ADDED pending/);
  const allowAt = codeLine(code, /UFW_ALLOW_OUTPUT="\$\(LC_ALL=C timeout "\$STEP_TIMEOUT" ufw/);
  const ruleConfirmAt = codeLine(code, /state_set UFW_RULE_ADDED 1/);
  // The LAST `state_set UFW_RULE_ADDED 0` is the "ufw said it did not add it" branch (the first is
  // the initial value taken with the backup).
  const ruleResetAt = code.split("\n").reduce((acc, line, i) => (/^\s*state_set UFW_RULE_ADDED 0/.test(line) ? i : acc), -1);
  assert.ok(rulePendingAt > 0, "UFW_RULE_ADDED=pending is written");
  assert.ok(allowAt > 0, "the ufw allow is there");
  assert.ok(rulePendingAt < allowAt, `pending precedes the ufw allow (${rulePendingAt} vs ${allowAt})`);
  assert.ok(ruleConfirmAt > allowAt, "and the confirmation follows it");
  assert.ok(ruleResetAt > allowAt, "and the 'ufw did not add it' branch writes 0 back");

  assert.match(code, /state_set USER_CREATED pending \\\n\s*\|\| fail /, "a failed pending write fails the run");
  assert.match(code, /state_set UFW_RULE_ADDED pending \\\n\s*\|\| fail /, "for the rule too");

  // The undo treats `pending` like `1`, and checks the thing is really there before removing it.
  const body = scriptBody(read(INSTALL));
  assert.match(body, /case "\$\(state_get USER_CREATED\)" in\n  1\|pending\)/, "restore.sh treats pending like 1 for the user");
  assert.match(body, /case "\$\(state_get UFW_RULE_ADDED\)" in\n  1\|pending\)/, "and for the rule");
  assert.match(body, /if id "\$PUBLIC_USER" >\/dev\/null 2>&1; then/, "the user is checked with id first");
  assert.match(body, /ufw allow in on \$BRIDGE_IF from \$SIDECAR_IP to \$BIND_ADDR port \$PUBLIC_PORT proto tcp/,
    "and the rule against an exact line of ufw show added");
});

test("ufw is always run with LC_ALL=C", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));

  // Every place ufw is EXECUTED by the installer: the two reads and the one allow.
  const calls = code.split("\n").filter((line) => /timeout "\$STEP_TIMEOUT" ufw/.test(line));
  assert.equal(calls.length, 3, `the three installer ufw calls are there (got ${calls.length})`);
  for (const line of calls) {
    assert.match(line, /LC_ALL=C timeout "\$STEP_TIMEOUT" ufw/, `every ufw call sets the locale: ${line.trim()}`);
  }
  assert.ok(calls.some((line) => /ufw status/.test(line)), "ufw status is one of them");
  assert.ok(calls.some((line) => /ufw show added/.test(line)), "ufw show added is one of them");
  assert.ok(calls.some((line) => /ufw "\$\{UFW_RULE\[@\]\}"/.test(line)), "and the allow is the third");

  // The undo's delete is under the same locale, for the same reason.
  assert.match(scriptBody(read(INSTALL)), /LC_ALL=C timeout "\$STEP_TIMEOUT" ufw delete/,
    "restore.sh deletes the rule under LC_ALL=C too");

  // The reason is written down, and it names the line that depends on it.
  const comments = read(INSTALL).split("\n").filter((line) => /^\s*#/.test(line)).join("\n");
  assert.match(comments, /EVERY ufw CALL IN THIS FILE RUNS UNDER LC_ALL=C/, "the rule is stated where the calls are");
  assert.match(comments, /Rule added/, "and names the output whose match depends on it");
});

test("UFW_RULE_ADDED is set only when ufw reports Rule added", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));

  // The decision lives in one small pure function, so it can be exercised for real: the text
  // ufw printed is the only input, and only "Rule added" (or its "(v6)" copy) means THIS run
  // wrote a rule. "Skipping adding existing rule" — and an empty answer — mean it did not, and
  // a rule this run did not add is never deleted by its undo.
  const fn = functionLines(code, "ufw_output_added");
  assert.ok(fn, "ufw_output_added() is defined in install.sh");
  const fnText = fn.lines.join("\n");
  assert.match(fnText, /\*"Rule added"\*/, 'the one accepted shape is "Rule added"');
  const verdict = (text) => spawnSync("bash", ["-c", `${fnText}\nufw_output_added "$1"`, "bash", text], { encoding: "utf8" });
  assert.equal(verdict("Rule added").status, 0, '"Rule added" is a rule this run added');
  assert.equal(verdict("Rule added (v6)").status, 0, 'its IPv6 copy — "Rule added (v6)" — counts too');
  assert.equal(verdict("Skipping adding existing rule").status, 1, "a skipped rule is not this run's to delete");
  assert.equal(verdict("").status, 1, "and no output never is");
  assert.equal(verdict("ERROR: Could not load file '/etc/default/ufw'").status, 1, "an error is not an addition");

  // The installer decides from that output, never from ufw's exit status, and records it only
  // inside the branch that decided "added".
  assert.match(code, /UFW_ALLOW_OUTPUT="\$\(LC_ALL=C timeout "\$STEP_TIMEOUT" ufw "\$\{UFW_RULE\[@\]\}" 2>&1\)"/,
    "the ufw allow output is captured, under the C locale so its wording is the one matched");
  assert.match(code, /if ufw_output_added "\$UFW_ALLOW_OUTPUT"; then/, "and fed to the helper");
  const decideAt = codeLine(code, /if ufw_output_added "/);
  const addAt = codeLine(code, /^\s*UFW_RULE_ADDED=1$/);
  assert.ok(addAt > decideAt, `the flag is set inside the accepted branch only (${addAt} vs ${decideAt})`);
  assert.match(code, /state_set UFW_RULE_ADDED 1 \\\n\s*\|\| fail /, "and reaches the state file there");
  assert.equal((code.match(/^[ \t]*UFW_RULE_ADDED=1$/gm) ?? []).length, 1, "one assignment, in one branch");
});

/* ------------------------------------------- the undo script, RUN against stub tools */

test("restore.sh with keep present changes nothing and logs kept", () => {
  // Every fact in the state file says "this run changed this", so only the keep check stands
  // between the script and a full restore.
  const kept = runRenderedRestore({
    keep: true,
    state: STATE_FIRST_INSTALL.replace("USER_CREATED=0", "USER_CREATED=1").replace("UFW_RULE_ADDED=0", "UFW_RULE_ADDED=1"),
    snapshotFiles: { "report-readers.conf": "[Service]\n# the old drop-in\n" },
    installed: { dropIn: "[Service]\n# the new drop-in\n", socketUnit: "new socket", listenerUnit: "new listener" },
  });

  assert.equal(kept.run.status, 0, `a kept install exits 0: ${kept.run.stderr}`);
  assert.deepEqual(stateChanging(kept.called), [
    `systemctl stop ${TEST_DEADMAN_TIMER}`,
    `systemctl reset-failed ${TEST_DEADMAN_TIMER}`,
    `systemctl reset-failed ${TEST_DEADMAN_SERVICE}`,
  ], `the only things it changes are its own deadman units: ${kept.called.join(" | ")}`);
  assert.ok(kept.called.some((line) => /^logger /.test(line) && /kept:/.test(line)),
    "and it is logged under the undo's journal tag");
  assert.equal(kept.called.some((line) => /^curl /.test(line)), false, "not even a health check runs");

  // The files are exactly as the install left them.
  assert.equal(readFileSync(kept.dropIn, "utf8"), "[Service]\n# the new drop-in\n", "the new drop-in stays");
  assert.equal(readFileSync(kept.socketUnit, "utf8"), "new socket", "the new socket unit stays");
  assert.equal(readFileSync(kept.listenerUnit, "utf8"), "new listener", "the new listener unit stays");
});

test("restore.sh stops its own timer after a complete restore and when keep exists", () => {
  const stopCall = `systemctl stop ${TEST_DEADMAN_TIMER}`;

  // (a) a COMPLETE restore: the timer this run armed is stopped, so it can never fire over a host
  // that is already back the way it was.
  const restored = runRenderedRestore({
    state: STATE_FIRST_INSTALL,
    snapshotFiles: { "report-readers.conf": "[Service]\n# the old drop-in\n" },
    installed: { dropIn: "[Service]\n# the new drop-in\n" },
  });
  assert.equal(restored.run.status, 0, `the undo completed: ${restored.run.stderr}`);
  assert.ok(restored.called.includes(stopCall), `the deadman's own timer is stopped: ${restored.called.join(" | ")}`);
  assert.ok(restored.called.some((line) => /^logger /.test(line) && /stopped crow-artifact-public-deadman-/.test(line)),
    `and the stop is logged under the undo's journal tag: ${restored.called.join(" | ")}`);

  // (b) the KEEP path: nothing is undone, and the timer is stopped as well — that is the only
  // change the undo makes on a kept install.
  const kept = runRenderedRestore({ keep: true, state: STATE_FIRST_INSTALL });
  assert.equal(kept.run.status, 0, `a kept install exits 0: ${kept.run.stderr}`);
  assert.ok(kept.called.includes(stopCall), "a kept install stops its own timer too");
  assert.deepEqual(stateChanging(kept.called), [
    stopCall,
    `systemctl reset-failed ${TEST_DEADMAN_TIMER}`,
    `systemctl reset-failed ${TEST_DEADMAN_SERVICE}`,
  ], "and touches nothing else on this machine");

  // (c) a stop that FAILS is logged and does not fail the restore.
  const failedStop = runRenderedRestore({ keep: true, state: STATE_FIRST_INSTALL, deadmanStopRc: 1 });
  assert.equal(failedStop.run.status, 0, `a failing stop is not fatal: ${failedStop.run.stderr}`);
  assert.ok(failedStop.called.includes(stopCall), "the stop was attempted");
  assert.match(failedStop.run.stderr, /could not stop crow-artifact-public-deadman-20260101000000-4242\.timer/,
    "and the failure is reported");
});

test("restore.sh stops and resets its own timer on every exit path", () => {
  // A transient timer cannot be disabled: `stop` is the only thing that keeps it from firing, and
  // only `reset-failed` takes it — and the service it runs — out of the unit list. Both happen on
  // every path that reaches its end, in that order, and neither can fail the restore.
  const stopCall = `systemctl stop ${TEST_DEADMAN_TIMER}`;
  const resetTimerCall = `systemctl reset-failed ${TEST_DEADMAN_TIMER}`;
  const resetServiceCall = `systemctl reset-failed ${TEST_DEADMAN_SERVICE}`;

  const checkCleared = (called, label) => {
    const stoppedAt = called.indexOf(stopCall);
    const resetTimerAt = called.indexOf(resetTimerCall);
    assert.ok(stoppedAt >= 0, `${label}: the timer is stopped: ${called.join(" | ")}`);
    assert.ok(resetTimerAt >= 0, `${label}: and the timer is reset-failed: ${called.join(" | ")}`);
    assert.ok(stoppedAt < resetTimerAt, `${label}: the stop comes BEFORE the reset-failed`);
    assert.ok(called.includes(resetServiceCall), `${label}: the service it ran is reset-failed too`);
    // The service is never stopped: when the deadman fired, this very script runs inside it.
    assert.equal(called.some((line) => line === `systemctl stop ${TEST_DEADMAN_SERVICE}`), false,
      `${label}: the service is reset, never stopped`);
  };

  // (1) a COMPLETE restore.
  const restored = runRenderedRestore({
    state: STATE_FIRST_INSTALL,
    snapshotFiles: { "report-readers.conf": "[Service]\n# the old drop-in\n" },
    installed: { dropIn: "[Service]\n# the new drop-in\n" },
  });
  assert.equal(restored.run.status, 0, `the undo completed: ${restored.run.stderr}`);
  checkCleared(restored.called, "complete restore");

  // (2) the KEEP path: the decision is final there too, so the timer goes the same way.
  const kept = runRenderedRestore({ keep: true, state: STATE_FIRST_INSTALL });
  assert.equal(kept.run.status, 0, `a kept install exits 0: ${kept.run.stderr}`);
  checkCleared(kept.called, "keep path");

  // (3) EVERY one of those calls failing still leaves a successful restore: they are housekeeping,
  // not part of what the undo did to the host.
  const failing = runRenderedRestore({ keep: true, state: STATE_FIRST_INSTALL, deadmanStopRc: 1, deadmanResetRc: 1 });
  assert.equal(failing.run.status, 0, `failing stop/reset-failed calls are not fatal: ${failing.run.stderr}`);
  assert.ok(failing.called.includes(stopCall), "the stop was still attempted");
  assert.ok(failing.called.includes(resetTimerCall), "and both resets were, even after the stop failed");
  assert.ok(failing.called.includes(resetServiceCall), "including the service's");
  assert.match(failing.run.stderr, /could not stop crow-artifact-public-deadman-20260101000000-4242\.timer/,
    "the failed stop is reported");
  assert.match(failing.run.stderr, /could not reset-failed crow-artifact-public-deadman-20260101000000-4242\.timer/,
    "the timer's failed reset too");
  assert.match(failing.run.stderr, /could not reset-failed crow-artifact-public-deadman-20260101000000-4242\.service/,
    "and the service's");
});

test("restore.sh without keep restores the files and restarts the gateway", () => {
  const OLD_DROP_IN = "[Service]\n# the drop-in this host had before\n";
  const restored = runRenderedRestore({
    state: STATE_FIRST_INSTALL,
    snapshotFiles: { "report-readers.conf": OLD_DROP_IN },
    installed: {
      dropIn: "[Service]\n# the drop-in this install wrote\n",
      socketUnit: "[Socket]\n# installed by this run\n",
      listenerUnit: "[Service]\n# installed by this run\n",
    },
  });

  assert.equal(restored.run.status, 0, `the undo completed: ${restored.run.stderr}`);
  // The drop-in comes back from its copy; both units this run created are gone.
  assert.ok(existsSync(restored.dropIn), `the restored drop-in is there: ${restored.run.stderr}`);
  assert.equal(readFileSync(restored.dropIn, "utf8"), OLD_DROP_IN, "the existing drop-in is back, byte for byte");
  assert.equal(existsSync(restored.socketUnit), false, "the socket unit this run created is removed");
  assert.equal(existsSync(restored.listenerUnit), false, "and so is the listener unit");
  assert.equal(existsSync(restored.dropInDir), true, "the drop-in directory stays: this run did not create it");

  // Both units were stopped and disabled before their files went, and the state was re-applied.
  assert.ok(restored.called.some((line) => line === "systemctl stop crow-artifact-public.service"), "the listener is stopped");
  assert.ok(restored.called.some((line) => line === "systemctl disable crow-report-readers.socket"), "the socket is disabled");
  assert.ok(restored.called.some((line) => line === "systemctl daemon-reload"), "and a daemon-reload follows");

  // The gateway: a non-blocking restart, the InvocationID polled, and /health asked for 200.
  assert.ok(restored.called.some((line) => line === "systemctl restart --no-block crow-gateway.service"),
    `the gateway restart is asked for non-blocking: ${restored.called.join(" | ")}`);
  assert.ok(restored.called.some((line) => /^systemctl show -p InvocationID --value crow-gateway\.service$/.test(line)),
    "the InvocationID is polled");
  assert.ok(restored.called.some((line) => /^curl .*127\.0\.0\.1:3001\/health$/.test(line)), "and /health is asked");
  assert.ok(restored.called.some((line) => /^logger /.test(line) && /restore complete/.test(line)),
    "with the completion logged");
});

test("restore.sh run twice is idempotent", () => {
  const OLD_DROP_IN = "[Service]\n# the drop-in this host had before\n";
  const first = runRenderedRestore({
    state: STATE_FIRST_INSTALL,
    snapshotFiles: { "report-readers.conf": OLD_DROP_IN },
    installed: {
      dropIn: "[Service]\n# the drop-in this install wrote\n",
      socketUnit: "[Socket]\n# installed by this run\n",
      listenerUnit: "[Service]\n# installed by this run\n",
    },
  });
  assert.equal(first.run.status, 0, `the first run completes: ${first.run.stderr}`);

  const afterFirst = {
    dropIn: readFileSync(first.dropIn, "utf8"),
    socket: existsSync(first.socketUnit),
    listener: existsSync(first.listenerUnit),
    entries: readdirSync(first.dropInDir).sort(),
  };

  const second = first.rerun();
  assert.equal(second.status, 0, `a second run exits 0 rather than failing on what is already restored: ${second.stderr}`);
  assert.equal(readFileSync(first.dropIn, "utf8"), afterFirst.dropIn, "the drop-in is unchanged by the second run");
  assert.equal(existsSync(first.socketUnit), afterFirst.socket, "the socket unit is still absent");
  assert.equal(existsSync(first.listenerUnit), afterFirst.listener, "and so is the listener unit");
  assert.deepEqual(readdirSync(first.dropInDir).sort(), afterFirst.entries, "no file appears in the drop-in directory");
  assert.ok(second.stderr.includes("no-op"), "and it says it is re-running steps that are already done");
});

test("restore.sh skips the gateway restart when the gateway was never touched", () => {
  const untouched = runRenderedRestore({
    state: [
      "LISTENER_UNIT_PRESENT=0",
      "SOCKET_UNIT_PRESENT=0",
      "DROP_IN_PRESENT=0",
      "DROP_IN_DIR_CREATED=0",
      "GATEWAY_TOUCHED=0",
      "USER_CREATED=0",
      "UFW_RULE_ADDED=0",
      "",
    ].join("\n"),
  });

  assert.equal(untouched.run.status, 0, `it exits 0 with nothing to do: ${untouched.run.stderr}`);
  assert.equal(untouched.called.some((line) => /^systemctl restart/.test(line)), false,
    "no gateway restart is asked for");
  assert.equal(untouched.called.some((line) => /InvocationID/.test(line)), false,
    "the InvocationID is not even read");
  assert.equal(untouched.called.some((line) => /^curl /.test(line)), false, "and /health is not polled");
  assert.ok(untouched.called.some((line) => /^logger /.test(line) && /not restarting crow-gateway\.service/.test(line)),
    "it says the gateway was left alone");
  assert.match(untouched.called.find((line) => /^logger /.test(line) && /restore complete/.test(line)) ?? "",
    /restore complete/, "and still reports the restore complete");
});

test("restore.sh removes the user and the ufw rule only when this run created them", () => {
  // Case 1: this run created neither. Nothing may be deleted, and it must say so.
  const neither = runRenderedRestore({
    state: [
      "LISTENER_UNIT_PRESENT=0",
      "SOCKET_UNIT_PRESENT=0",
      "DROP_IN_PRESENT=0",
      "DROP_IN_DIR_CREATED=0",
      "GATEWAY_TOUCHED=0",
      "USER_CREATED=0",
      "UFW_RULE_ADDED=0",
      "",
    ].join("\n"),
  });
  assert.equal(neither.run.status, 0, `it exits 0: ${neither.run.stderr}`);
  assert.equal(neither.called.some((line) => /^userdel /.test(line)), false, "the system user is left alone");
  assert.equal(neither.called.some((line) => /^ufw delete/.test(line)), false, "and the firewall rule is untouched");
  assert.ok(neither.called.some((line) => /^logger .*left alone: this install did not create it/.test(line)),
    "the user decision is logged");
  assert.ok(neither.called.some((line) => /^logger .*no ufw rule is deleted/.test(line)), "and so is the rule's");

  // Case 2: this run created both, so both go — the rule by its exact words, under LC_ALL=C.
  const both = runRenderedRestore({
    state: [
      "LISTENER_UNIT_PRESENT=0",
      "SOCKET_UNIT_PRESENT=0",
      "DROP_IN_PRESENT=0",
      "DROP_IN_DIR_CREATED=1",
      "GATEWAY_TOUCHED=0",
      "USER_CREATED=1",
      "UFW_RULE_ADDED=1",
      "",
    ].join("\n"),
  });
  assert.equal(both.run.status, 0, `it exits 0: ${both.run.stderr}`);
  assert.ok(both.called.some((line) => line === "userdel crow-artifact-public"),
    `the user this run created is removed: ${both.called.join(" | ")}`);
  assert.ok(both.called.some((line) => line === "ufw delete allow in on br-test from 192.0.2.2 to 192.0.2.1 port 3093 proto tcp"),
    "and only the one exact rule this run added");
  assert.equal(existsSync(both.dropInDir), false, "the drop-in directory this run created is removed too");
});

test("restore.sh removes the user and rule only when they exist", () => {
  // `pending` is what the installer leaves behind when it is killed between the command and its
  // confirmation, so the undo has to treat it as "possibly mine" AND look at the thing itself.
  const pendingState = [
    "LISTENER_UNIT_PRESENT=0",
    "SOCKET_UNIT_PRESENT=0",
    "DROP_IN_PRESENT=0",
    "DROP_IN_DIR_CREATED=0",
    "GATEWAY_TOUCHED=0",
    "USER_CREATED=pending",
    "UFW_RULE_ADDED=pending",
    "",
  ].join("\n");

  // pending, and neither thing is actually there: nothing may be removed.
  const absent = runRenderedRestore({ state: pendingState, userExists: false, ufwHasRule: false });
  assert.equal(absent.run.status, 0, `it exits 0: ${absent.run.stderr}`);
  assert.equal(absent.called.some((line) => /^userdel /.test(line)), false,
    `no userdel for a user that is not there: ${absent.called.join(" | ")}`);
  assert.equal(absent.called.some((line) => /^ufw delete/.test(line)), false,
    "and no ufw delete for a rule ufw does not list");
  assert.ok(absent.called.includes("id crow-artifact-public"), "the user is checked with id first");
  assert.ok(absent.called.includes("ufw show added"), "and the rule against `ufw show added`");
  assert.ok(absent.called.some((line) => /^logger .*is not there, so there is nothing to delete/.test(line)),
    "the user decision is logged");
  assert.ok(absent.called.some((line) => /^logger .*is not in 'ufw show added', so there is nothing to delete/.test(line)),
    "and so is the rule's");

  // pending, and both are there: both go, the rule by its exact words.
  const present = runRenderedRestore({ state: pendingState, userExists: true, ufwHasRule: true });
  assert.equal(present.run.status, 0, `it exits 0: ${present.run.stderr}`);
  assert.ok(present.called.includes("userdel crow-artifact-public"),
    `the pending user is removed once it exists: ${present.called.join(" | ")}`);
  assert.ok(present.called.includes(`ufw delete ${TEST_UFW_RULE.replace(/^ufw /, "")}`),
    "and the pending rule, by exactly the words `ufw show added` lists");
});

/* ------------------------------------------------------------------ node and checkout */

test("install.sh refuses a node that is not absolute, executable and the declared major", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));
  const deadmanAt = codeLine(code, /systemd-run --on-active/);
  const firstChangeAt = codeLine(code, /useradd --system/);

  const absoluteAt = codeLine(code, /not an absolute path/);
  assert.ok(absoluteAt > 0, "a path that is not absolute is refused");
  assert.match(code.split("\n")[absoluteAt], /^\s*\*\).*refuse "/, "as a refusal, naming the condition");
  assert.match(code, /case "\$NODE_BIN" in\n\s*\/\*\) ;;/, "the shape of the resolved path is what is checked");

  const execAt = codeLine(code, /\[ -x "\$NODE_BIN" \]/);
  assert.ok(execAt > 0, "it must be executable");
  assert.match(code, /not an executable file/, "and that refusal names the condition");

  const majorAt = codeLine(code, /\[ "\$GOT_NODE_MAJOR" = "\$WANT_NODE_MAJOR" \]/);
  assert.ok(majorAt > 0, "and its major must be the one package.json declares");
  assert.match(code, /declares node \$WANT_NODE_MAJOR\.x/, "the refusal names the declared major");

  for (const [label, at] of [["absolute", absoluteAt], ["executable", execAt], ["major", majorAt]]) {
    assert.ok(at < deadmanAt, `the ${label} check happens before the deadman is armed`);
    assert.ok(at < firstChangeAt, `and before the first change on the host`);
  }
});

test("install.sh never falls back to PATH for node", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));

  assert.doesNotMatch(code, /command -v node/, "node is never taken from PATH");
  assert.doesNotMatch(code, /\bwhich\s+node\b/, "nor from `which`");
  assert.doesNotMatch(code, /\bPATH\b[^\n]*\bnode\b/, "PATH is not consulted for the node at all");
  assert.doesNotMatch(code, /\benv\s+node\b|\bnpx\b/, "and never through env or npx");

  // The binary is only ever executed as "$NODE_BIN" itself: there is no bare `node`.
  // (The word appears in refusal prose, so the scan is about a command POSITION: the
  // first word of a line, or the first word after a command separator.)
  for (const line of code.split("\n")) {
    assert.doesNotMatch(line, /^\s*node\s/, `no bare node is run: ${line.trim()}`);
    assert.doesNotMatch(line, /[&|(]\s*node\s/, `no bare node after a command separator: ${line.trim()}`);
  }
  assert.match(code, /"\$NODE_BIN" -v/, "the resolved absolute path is the thing that runs");
  // The only bare *name* is the unit's ExecStart basename, compared, not executed.
  assert.match(code, /^\s*node\)\s*$/m, "the ExecStart basename case");
});

test("install.sh refuses a checkout that is not the gateway's, not on main, or dirty", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));

  // 1: the unit's WorkingDirectory must be this checkout.
  assert.match(code, /\[ "\$UNIT_WORKDIR_REAL" = "\$APP_DIR_REAL" \]/,
    "the unit's directory and this checkout are compared");
  assert.match(code, /refuse "[^"\n]*worktree can never repoint production/, "and the refusal names that condition");

  // 2: on branch main, read through the ONE wrapper that runs git — as the checkout's
  // owner, never as root. A checkout owned by another user is exactly where a repo-held
  // config (core.fsmonitor, a filter, a hook) would otherwise run as root.
  assert.match(code, /git_as_owner rev-parse --abbrev-ref HEAD/,
    "the branch is read from this checkout, through the wrapper that drops to its owner");
  assert.match(code, /\[ "\$CHECKOUT_BRANCH" = "main" \]/, "and must be exactly main");
  assert.match(code, /refuse "[^"\n]*not on the main branch/, "the refusal names that condition");

  // 3: nothing uncommitted in the tracked tree (untracked files are deliberately fine).
  assert.match(code, /git_as_owner status --porcelain --untracked-files=no/,
    "uncommitted tracked changes are read through the same wrapper, untracked files are not");
  assert.match(code, /\[ -z "\$CHECKOUT_DIRTY" \]/, "which means it must print nothing");
  assert.match(code, /refuse "[^"\n]*uncommitted changes to tracked files/, "the refusal names that condition");

  // All of it read-only, before the undo scaffolding exists and before any change.
  const gitAt = codeLine(code, /rev-parse --abbrev-ref HEAD/);
  assert.ok(gitAt > 0, "git is consulted at all");
  assert.ok(codeLine(code, /systemd-run --on-active/) > gitAt, "the checkout is vetted before the deadman exists");
  assert.ok(codeLine(code, /useradd --system/) > gitAt, "and before the first change on the host");
});

/**
 * A `git` COMMAND on a line: git in command position (start of line, after a separator, or
 * inside a `$( ... )`), or git followed by one of the flags/subcommands this installer
 * would use. Prose inside a refusal message matches neither shape, and the `command -v git`
 * presence check runs nothing — so this is "runs git", not "says git".
 */
const GIT_IN_COMMAND_POSITION = /(?:^|[;|&(`]|\$\()\s*git\s/;
const GIT_WITH_SUBCOMMAND = /\bgit\s+(?:-[cC]\b|rev-parse\b|status\b|diff\b|log\b|show\b|fetch\b|worktree\b)/;

function gitInvocations(source, skip) {
  const found = [];
  source.split("\n").forEach((line, i) => {
    if (skip && i >= skip.start && i <= skip.end) return;
    const rest = line.replace(/command -v git\b/g, "");
    if (GIT_IN_COMMAND_POSITION.test(rest) || GIT_WITH_SUBCOMMAND.test(rest)) {
      found.push(`${i + 1}: ${line.trim()}`);
    }
  });
  return found;
}

test("install.sh never runs git as root", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));

  // Exactly one wrapper, and it is what drops the privilege before git is executed.
  const wrapper = functionLines(code, "git_as_owner");
  assert.ok(wrapper, "git_as_owner() is defined as a function");
  assert.equal(code.split("\n").filter((line) => /^\s*git_as_owner\(\)\s*\{/.test(line)).length, 1,
    "and defined exactly once");
  const body = wrapper.lines.join("\n");
  assert.match(body, /timeout "\$STEP_TIMEOUT" runuser -u "\$CHECKOUT_OWNER" -- env GIT_CONFIG_NOSYSTEM=1 git\b/,
    'the wrapper runs git under `runuser -u "$CHECKOUT_OWNER"`, so it is the checkout owner and never root');
  for (const off of ["core.fsmonitor=false", "core.hooksPath=/dev/null", "core.untrackedCache=false"]) {
    assert.ok(body.includes(off), `the wrapper turns off ${off}, so the checkout's own config cannot run a command`);
  }
  assert.match(body, /-C "\$APP_DIR" "\$@"/,
    "the checkout is named once, inside the wrapper, and every argument is passed through to git");

  // Nothing else runs git: everywhere the installer needs an answer from git, it is a call
  // to this wrapper (the one exception is `command -v git`, which executes nothing).
  const offenders = gitInvocations(code, wrapper);
  assert.deepEqual(offenders, [], `no line outside git_as_owner() runs git: ${offenders.join(" | ")}`);
  assert.match(code, /"\$\(git_as_owner rev-parse --abbrev-ref HEAD 2>\/dev\/null \|\| true\)"/,
    "the branch is read through the wrapper");
  assert.match(code, /"\$\(git_as_owner status --porcelain --untracked-files=no 2>\/dev\/null \|\| true\)"/,
    "and so is the tracked-tree check");

  // The wrapper is not merely prose: it is code, and no second path to git re-opens what it
  // switched off.
  assert.equal(stripShellComments(read(INSTALL)).includes("runuser"), true,
    "runuser is in the code, not only in the comments");
  assert.doesNotMatch(code, /GIT_TERMINAL_PROMPT|--no-optional-locks|core\.sshCommand/,
    "and nothing adds another git setting beside the wrapper's three");
});

test("install.sh does not use safe.directory", () => {
  // Assembled from fragments so this file does not carry the word it scans for.
  const override = ["safe", "directory"].join(".");
  const raw = read(INSTALL);

  // The WHOLE file — comments included. Overriding git's ownership check is what lets root
  // run commands a foreign checkout's config names; the fix is to run as the owner instead.
  assert.equal(raw.includes(override), false,
    `install.sh never names git's ownership override (${override}), not even in a comment`);
  assert.doesNotMatch(raw, /\bsafe\s*\.\s*directory/i,
    "and not split across whitespace or written in another case");
  assert.doesNotMatch(raw, /-c\s+safe\b/, "nor as any other -c safe* setting");
});

test("install.sh refuses a root-owned or unresolvable checkout owner", () => {
  const code = stripGeneratedScript(stripShellComments(read(INSTALL)));

  // The owner is read once, off the filesystem, before git is consulted.
  const ownerAt = codeLine(code, /^CHECKOUT_OWNER="\$\(stat -c %U "\$APP_DIR"\)"$/);
  assert.ok(ownerAt > 0, 'the owner comes from `stat -c %U "$APP_DIR"`');
  assert.match(code, /^\[ -n "\$CHECKOUT_OWNER" \]/m, "an owner that comes back empty is refused, not guessed at");
  assert.match(code, /^\[ "\$CHECKOUT_OWNER" != "root" \]/m, "an owner literally named root is refused by name");

  // A name that does not resolve to a numeric, non-zero uid is refused as well: a checkout
  // whose owner cannot be dropped to is a checkout whose git would run as root.
  assert.match(code, /CHECKOUT_OWNER_UID="\$\(id -u "\$CHECKOUT_OWNER" 2>\/dev\/null \|\| true\)"/,
    'the owner is resolved with `id -u "$CHECKOUT_OWNER"`');
  assert.match(code, /^\s*''\|\*\[!0-9\]\*\)$/m, "a uid that is not numeric is not accepted as one");
  assert.match(code, /^\[ "\$CHECKOUT_OWNER_UID" -ne 0 \]/m, "and uid 0 is refused as root, however it was reached");

  // Each of those refusals says why: git must never run as root on another user's checkout.
  const ownerRefusals = code.split("\n").filter((line) =>
    /refuse "[^"]*(?:owned by root|uid 0|does not resolve to a numeric uid)/.test(line));
  assert.equal(ownerRefusals.length, 3, `three owner refusals, one per condition (got ${ownerRefusals.length})`);
  for (const line of ownerRefusals) {
    assert.match(line, /git must never run as root on a checkout another user controls/,
      `each owner refusal names the reason: ${line.trim()}`);
  }

  // The tool that switches user is checked up front, with the other required tools.
  const runuserAt = codeLine(code, /^command -v runuser >\/dev\/null 2>&1/);
  assert.ok(runuserAt > 0, "runuser presence is checked");
  assert.match(code.split("\n")[runuserAt + 1], /refuse "[^"]*runuser/, "and a missing runuser refuses the run");
  assert.ok(runuserAt < ownerAt, "before the owner is read");
  assert.ok(runuserAt < codeLine(code, /^GATEWAY_EXEC_START=/),
    "and early in the file, before any value the run is built from is read");

  // All of it before git is consulted, before the deadman is armed and before any change.
  for (const re of [/git_as_owner rev-parse/, /systemd-run --on-active/, /useradd --system/]) {
    const at = codeLine(code, re);
    assert.ok(at > 0, `${re} is in the source`);
    assert.ok(ownerAt < at, `the owner is settled before ${re} (line ${ownerAt} vs ${at})`);
  }
});

test("install.sh hard-codes no home path or username", () => {
  const nonComment = stripGeneratedScript(stripShellComments(read(INSTALL)));
  const undoScript = scriptBody(read(INSTALL));

  for (const [label, text] of [["install.sh", nonComment], ["the generated restore script", undoScript]]) {
    assert.doesNotMatch(text, /\/(?:home|Users|root)\/[A-Za-z0-9._-]+/, `${label}: no home directory literal`);
    assert.doesNotMatch(text, /\bHOME=["']?\//, `${label}: HOME is never set to a literal path`);
  }

  // The instance home is derived, never assumed: CROW_HOME, or the invoking user's own
  // passwd entry, or the environment.
  assert.match(nonComment, /CROW_HOME="\$\(crow_home_of\)"/, "the home comes from a lookup");
  assert.match(nonComment, /getent passwd "\$SUDO_USER"/, "of the invoking user's passwd entry");
  // The only account it names is the product's own system account, through a variable.
  assert.match(nonComment, /useradd --system --no-create-home --shell \/usr\/sbin\/nologin "\$PUBLIC_USER"/,
    "the one user it creates is named by a variable");
});

/* ---------------------------------------------------------- the refusal, exercised */

test("install.sh refusals run before any change and before the deadman", (t) => {
  if (typeof process.getuid === "function" && process.getuid() === 0) {
    // As root the script gets PAST its root check, and from there it could reach the real
    // host. This case is only meaningful (and only safe) for a non-root run.
    t.skip("needs a non-root user: a root run would not be refused at the root check");
    return;
  }

  const work = tempDir("artifact-public-refusal-");
  const bin = join(work, "bin");
  mkdirSync(bin, { recursive: true });
  const calls = join(work, "called.log");
  // A stub for every privileged tool the installer would use. Each appends its own name,
  // so one line in the log is proof that the installer got further than it should have.
  for (const stub of ["systemd-run", "systemctl", "ufw", "useradd"]) {
    writeFileSync(join(bin, stub),
      `#!/usr/bin/env bash\nprintf '%s\\n' "${stub} $*" >> ${JSON.stringify(calls)}\n`, { mode: 0o755 });
  }

  const run = spawnSync("bash", [join(DIR, INSTALL)], {
    encoding: "utf8",
    timeout: 60_000,
    env: {
      PATH: `${bin}:/usr/bin:/bin`,
      TMPDIR: work,
      // Documentation placeholders only: RFC 5737 TEST-NET-1 and a bridge name that is
      // no real interface. Every one of them passes the installer's own validators, so
      // the only thing left that can refuse this run is the root check.
      CROW_ARTIFACT_PUBLIC_BIND: "192.0.2.1",
      CROW_ARTIFACT_BRIDGE_IF: "br-test",
      CROW_ARTIFACT_SIDECAR_IP: "192.0.2.2",
      CROW_GATEWAY_HEALTH_URL: "http://127.0.0.1:3001/health",
    },
  });

  assert.equal(run.signal, null, `the script refused on its own (signal ${run.signal})`);
  assert.notEqual(run.status, 0, `a non-root run is refused: ${run.stdout}${run.stderr}`);
  assert.equal(run.status, 2, "with the documented refusal exit code");
  assert.match(run.stderr, /run with sudo/, "and it says why, and that nothing was changed");
  assert.match(run.stderr, /Nothing was changed/, "… in so many words");
  assert.equal(existsSync(calls), false,
    `no privileged tool ran before the refusal: ${existsSync(calls) ? readFileSync(calls, "utf8") : ""}`);
  assert.deepEqual(readdirSync(work).filter((name) => name !== "bin"), [],
    "and nothing was created (no backup directory, not even in TMPDIR)");
});

test("bash -n parses install.sh", () => {
  const run = spawnSync("bash", ["-n", join(DIR, INSTALL)], { encoding: "utf8" });
  assert.equal(run.status, 0, `bash -n said: ${run.stderr}`);
  assert.equal(run.stderr.trim(), "");
});