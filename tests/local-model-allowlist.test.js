/**
 * THE LOCAL-MODEL ALLOWLIST (security): an own-host provider row is a model
 * server only when something outside crow.db vouches for its address AND port,
 * and when the process actually holding the listening socket is not a bot.
 *
 * The threat this file exists for: a contained bot shares the host network
 * (CROW_PI_CONTAIN_NET=off) and can write crow.db, so it points its own
 * `providers` row at `http://127.0.0.1:<free port>/v1` and listens there with a
 * relay to a cloud API. Every address-CLASS check says "loopback, fine".
 *
 * Red-first: this file was written against the rule, not against the
 * implementation. `unverified-local` is the new class — this machine, no model
 * server vouching for the port — and it is neither local (never forwarded, never
 * offered as a local model) nor cloud (never cloud-consent eligible, never
 * through the cloud door).
 *
 * Every host read is a seam (servers/gateway/models/local-model-servers.js): the
 * resolver, own addresses, the /proc root, the uid, this process's pid and user
 * namespace, the docker runner, the clock. The squat case uses a REAL listener on
 * the port it is refused on. Placeholders only (100.64.20.x, 10.0.0.x,
 * example.ts.net).
 */
import { test, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import http from "node:http";
import { appendFileSync, mkdirSync, mkdtempSync, readFileSync, realpathSync, rmSync, statSync, symlinkSync, writeFileSync } from "node:fs";
import * as nodeFs from "node:fs";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import express from "express";

import llmRouterRouter, { completeText } from "../servers/gateway/routes/llm-router.js";
import createOpenAIAdapter from "../servers/gateway/ai/adapters/openai.js";
import { SELF_REFUSED_MESSAGE } from "../servers/gateway/ai/adapter-guard.js";
import {
  isKnownLocalModelTarget,
  isKnownLocalModelTargetCached,
  isUnverifiedLocalTarget,
  decodeProcNetAddress,
  logUnvouchedProviderRows,
  managedLlamaServerBinPaths,
  parseProcNet,
  parseProcNetConnections,
  publishedPortsOf,
  readComposePins,
  readContainerPins,
  readPins,
  resetLocalModelVouchCache,
  verifyAcceptedConnection,
  whenLocalModelVouchReady,
  COMPOSE_WORKING_DIR_LABEL,
  DOCKER_INSPECT_FORMAT,
  DOCKER_REFRESH_MIN_MS,
  PIN_FILE,
} from "../servers/gateway/models/local-model-servers.js";
import { spawnUntrustedListener } from "./fixtures/untrusted-listener.mjs";
import { listDoorModels } from "../servers/gateway/models/door-resolve.js";
import { buildManagedEntries } from "../servers/shared/pi-models-sync.js";
import { isCloudRow, cloudDoorIneligibleReason } from "../servers/shared/cloud-consent.js";
import { isCloudTarget, resolveCloudTarget } from "../servers/gateway/models/cloud-door.js";
import { main as pinMain } from "../scripts/cli/local-model-pin.js";

const GW_UID = typeof process.getuid === "function" ? process.getuid() : 0;
const GW_USERNS = "user:[4026531837]";
const OTHER_USERNS = "user:[4026532999]";
const GW_CGROUP = "0::/system.slice/crow-gateway.service";
const DOCKER_SCOPE = "0::/system.slice/docker-" + "a".repeat(64) + ".scope";

const ROOT = mkdtempSync(join(tmpdir(), "crow-local-model-"));
after(() => rmSync(ROOT, { recursive: true, force: true }));

let seq = 0;
const freshHome = () => { const h = join(ROOT, `home-${++seq}`); mkdirSync(h, { recursive: true }); return h; };

const shaOf = (content) => createHash("sha256").update(content).digest("hex");

/** A `models/state.json` with ONE reservation for `port`, naming `pid` (omit it for
 * a reservation that names nobody). */
function reserve(home, { port, pid }) {
  mkdirSync(join(home, "models"), { recursive: true });
  const owner = Number.isInteger(pid) ? { pid } : {};
  writeFileSync(join(home, "models", "state.json"), JSON.stringify({ reservations: { "crow-embed": { port, owner } } }));
}

/**
 * A release as `ensureRuntime` leaves it: the binary at `relBinPath`, and the
 * manifest with the archive checksum AND the BINARY's own `binSha256`.
 * `recordedContent` (default: the real content) is what the manifest claims the
 * binary's bytes are — different from `content` is the tampered case.
 */
function verifiedInstall(home, { release = "b4567", content = "#!/bin/sh\necho llama\n", recordedContent = content, relBinPath = "llama-server" } = {}) {
  const releaseDir = join(home, "runtimes", "llamacpp", release);
  const bin = join(releaseDir, relBinPath);
  mkdirSync(dirname(bin), { recursive: true });
  writeFileSync(bin, content);
  writeFileSync(join(releaseDir, ".crow-runtime-installed.json"), JSON.stringify({
    key: "linux-x64-cpu", sha256: shaOf("the archive, not the binary"), binSha256: shaOf(recordedContent), relBinPath, installedAt: new Date().toISOString(),
  }));
  return { releaseDir, bin };
}

beforeEach(() => { resetLocalModelVouchCache(); });

// ---------------------------------------------------------------------------
// fixtures
// ---------------------------------------------------------------------------

/** A real HTTP listener on 127.0.0.1 (records every request that reaches it). */
async function squatter() {
  const hits = [];
  const server = http.createServer((req, res) => {
    hits.push(req.url);
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ choices: [{ message: { content: "relayed" } }] }));
  });
  const port = await new Promise((r) => server.listen(0, "127.0.0.1", () => r(server.address().port)));
  return { server, port, hits, close: () => new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); }) };
}

/** A `/proc/net/tcp{,6}` row: `local` is the kernel's hex (little-endian). */
function procRow({ local, port, state = "0A", uid = GW_UID, inode = 1 }) {
  const p = Number(port).toString(16).toUpperCase().padStart(4, "0");
  return `   0: ${local}:${p} 00000000:0000 ${state} 00000000:00000000 00:00000000 00000000 ${String(uid).padStart(5)}        0 ${inode} 1 0000000000000000 100 0 0 10 0`;
}

/** The kernel's hex spelling of an address: four 32-bit words, each written
 * little-endian (tcp6) or the single word of an IPv4 address. */
const v4Hex = (dotted) => dotted.split(".").reverse().map((n) => Number(n).toString(16).padStart(2, "0")).join("").toUpperCase();
const v6Hex = (groups) => {
  const bytes = [];
  for (let i = 0; i < 8; i += 2) {
    const hi = groups[i], lo = groups[i + 1];
    bytes.push(lo & 0xff, (lo >> 8) & 0xff, hi & 0xff, (hi >> 8) & 0xff);
  }
  return bytes.map((b) => b.toString(16).padStart(2, "0")).join("").toUpperCase();
};

/**
 * ONE `docker inspect` line, in the shape the module asks for
 * (`DOCKER_INSPECT_FORMAT`): ONE JSON object per container carrying id, name, its
 * run state, labels and bindings. A container with no labels prints `"labels":null`
 * — the line is still whole, which is what used to depend on three passes staying
 * aligned. `running` is carried because the NAT branch requires a RUNNING
 * container (a stopped one keeps its bindings but has no NAT rules).
 */
const inspectLine = ({ id = "c0ffee", name = "/c0ffee", running = true, labels = null, bindings = null } = {}) =>
  JSON.stringify({ id, name, running, labels, ports: bindings });

/**
 * A fake /proc tree. `/proc/net/tcp{,6}` hold the rows; each live pid gets an fd
 * linked to `socket:[inode]`, and optionally a cgroup / exe link / user
 * namespace / stat line.
 */
function fakeProc({ tcp = [], tcp6 = [], procs = [] } = {}) {
  const root = join(ROOT, `proc-${++seq}`);
  mkdirSync(join(root, "net"), { recursive: true });
  writeFileSync(join(root, "net", "tcp"), `${"  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"}${tcp.join("\n")}\n`);
  writeFileSync(join(root, "net", "tcp6"), `${"  sl  local_address                         remote_address                        st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"}${tcp6.join("\n")}\n`);
  for (const p of procs) {
    const dir = join(root, String(p.pid));
    mkdirSync(join(dir, "fd"), { recursive: true });
    for (const inode of p.inodes || []) symlinkSync(`socket:[${inode}]`, join(dir, "fd", `${inode}.sock`));
    if (p.cgroup) writeFileSync(join(dir, "cgroup"), p.cgroup);
    if (p.exe) symlinkSync(p.exe, join(dir, "exe"));
    if (p.userns) { mkdirSync(join(dir, "ns"), { recursive: true }); symlinkSync(p.userns, join(dir, "ns", "user")); }
    if (p.ppid) writeFileSync(join(dir, "stat"), `${p.pid} (llama-server) S ${p.ppid} ${p.pid} ${p.pid} 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 1 0 0\n`);
  }
  mkdirSync(join(root, "self", "ns"), { recursive: true });
  symlinkSync(GW_USERNS, join(root, "self", "ns", "user"));
  return root;
}

// ---------------------------------------------------------------------------
// (1) THE SQUAT: a stopped model's port, held by a listener that is a bot.
// ---------------------------------------------------------------------------

test("SQUAT: a vouched port whose listener is not a known server is refused at the door, and that listener never sees the request", async () => {
  const squat = await squatter();
  try {
    const home = freshHome();
    // The docker snapshot vouches 127.0.0.1:<port> for a STOPPED container — that
    // is the whole attack: the port is legitimately the model's, and free.
    const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port: squat.port, inode: 5150 })], procs: [{ pid: 6161, inodes: [5150] }] });
    const lines = [];
    const providers = {
      squat: { baseUrl: `http://127.0.0.1:${squat.port}/v1`, apiKey: "none", models: [{ id: "m" }], gpuPolicy: { door_forward: true } },
    };
    const app = express();
    app.use(express.json());
    app.use(llmRouterRouter({
      acquireFn: async () => true,
      resolveKeyFn: async () => ({ baseUrl: providers.squat.baseUrl, model: "m", apiKey: "none" }),
      probeReadyFn: async () => true,
      loadProvidersFn: () => ({ providers }),
      remoteAddressFn: (req) => req.socket?.remoteAddress || "",
      classifyDoorCallerFn: async () => ({ cls: "loopback" }),
      recordUsageFn: async () => {},
      logFn: (l) => lines.push(l),
      listenPortsFn: () => new Set([9]),
      // The real predicate, with the environment faked: this process is NOT the
      // gateway (a bot's listener is another process), /proc is ours.
      knownLocalTargetFn: (url) => isKnownLocalModelTarget(url, {
        crowHome: home, procRoot, selfPid: -1, uid: GW_UID,
        dockerEntries: [{ address: "127.0.0.1", port: squat.port }],
      }),
    }));
    const server = http.createServer(app);
    const gwPort = await new Promise((r) => server.listen(0, "127.0.0.1", () => r(server.address().port)));
    try {
      const res = await fetch(`http://127.0.0.1:${gwPort}/llm/p/squat/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hi" }] }),
      });
      const body = await res.json();
      assert.equal(res.status, 400, JSON.stringify(body));
      assert.equal(body?.error?.code, "NOT_FORWARDABLE", "the door's existing not-forwardable refusal");
      assert.deepEqual(squat.hits, [], "the squatter never received a request");
      const refusals = lines.filter((l) => l.startsWith("[door] own-host target"));
      assert.deepEqual(refusals, [
        `[door] own-host target 127.0.0.1:${squat.port} is not a known model server (provider squat, listener-not-trusted)`,
      ], "exactly one log line, in the fixed shape");
    } finally {
      await new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
    }
  } finally {
    await squat.close();
  }
});

test("SQUAT predicate: vouched + a listener owned by an unexplained process is listener-not-trusted", async () => {
  const port = 18004;
  const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 7 })], procs: [{ pid: 4242, inodes: [7] }] });
  const r = await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, {
    crowHome: freshHome(), procRoot, selfPid: -1, uid: GW_UID,
    dockerEntries: [{ address: null, port }],
  });
  assert.deepEqual(r, { local: false, reason: "listener-not-trusted", address: "127.0.0.1" });
});

// ---------------------------------------------------------------------------
// (1b) The VOICE path is refused too, with one log line, before any dial.
// ---------------------------------------------------------------------------

test("VOICE: an own-host row nothing vouches for is refused (not-forwardable), logged once, nothing dialled", async () => {
  const squat = await squatter();
  try {
    const lines = [];
    const voiceUp = { baseUrl: `http://127.0.0.1:${squat.port}/v1`, model: "m", apiKey: "none" };
    const app = express();
    app.use(express.json());
    app.use(llmRouterRouter({
      acquireFn: async () => true,
      resolveKeyFn: async () => voiceUp,
      probeReadyFn: async () => true,
      loadProvidersFn: () => ({ providers: {} }),
      remoteAddressFn: (req) => req.socket?.remoteAddress || "",
      classifyDoorCallerFn: async () => ({ cls: "loopback" }),
      recordUsageFn: async () => {},
      logFn: (l) => lines.push(l),
      listenPortsFn: () => new Set([9]),
      knownLocalTargetFn: (url) => isKnownLocalModelTarget(url, { crowHome: freshHome(), selfPid: -1, uid: GW_UID }),
    }));
    const server = http.createServer(app);
    const gwPort = await new Promise((r) => server.listen(0, "127.0.0.1", () => r(server.address().port)));
    try {
      const res = await fetch(`http://127.0.0.1:${gwPort}/llm/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "crow-companion", messages: [{ role: "user", content: "hi" }] }),
      });
      const body = await res.json();
      assert.equal(res.status, 400, JSON.stringify(body));
      assert.equal(body?.error?.code, "NOT_FORWARDABLE", "the voice path's existing not-forwardable refusal");
      assert.deepEqual(squat.hits, [], "the squatter never received a turn");
      const refusals = lines.filter((l) => l.startsWith("[door] own-host target"));
      assert.equal(refusals.length, 1, lines.join("\n"));
      assert.equal(refusals[0], `[door] own-host target 127.0.0.1:${squat.port} is not a known model server (provider crow-voice, not-vouched)`);
    } finally {
      await new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
    }
  } finally {
    await squat.close();
  }
});

test("SQUAT: a vouched port with NO listener at all is no-listener (a start that never came up is not a model server)", async () => {
  const procRoot = fakeProc({ tcp: [] });
  const r = await isKnownLocalModelTarget("http://127.0.0.1:18005/v1", {
    crowHome: freshHome(), procRoot, selfPid: -1, uid: GW_UID,
    dockerEntries: [{ address: "127.0.0.1", port: 18005 }],
  });
  assert.deepEqual(r, { local: false, reason: "no-listener", address: "127.0.0.1" });
});

// ---------------------------------------------------------------------------
// (2) The trusting half: uid 0, a native runtime, a docker cgroup, a pin.
// ---------------------------------------------------------------------------

test("a vouched port whose listener runs as ANOTHER uid (docker-proxy, root) is local", async () => {
  const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port: 18006, uid: 0, inode: 11 })] });
  const r = await isKnownLocalModelTarget("http://127.0.0.1:18006/v1", {
    crowHome: freshHome(), procRoot, uid: GW_UID, selfPid: -1,
    dockerEntries: [{ address: "", port: 18006 }],
  });
  assert.deepEqual(r, { local: true, reason: "vouched", address: "127.0.0.1" });
});

test("the native runtime's OWN pid — a LIVE native handle for that port — is local, and ancestry is not", async () => {
  const port = 18007;
  const home = freshHome();
  // The reservation (outside crow.db) is what suggests the port is a model's; the
  // HANDLE is what says which process may hold it.
  mkdirSync(join(home, "models"), { recursive: true });
  writeFileSync(join(home, "models", "state.json"), JSON.stringify({ reservations: { "crow-chat": { port, owner: { crowHome: home, pid: 400 } } } }));

  const direct = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 21 })], procs: [{ pid: 400, inodes: [21] }] });
  const deps = { crowHome: home, procRoot: direct, uid: GW_UID, selfPid: -1, nativeHandles: [{ pid: 400, port }], isProcessAlive: (pid) => pid === 400 };
  assert.deepEqual(await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, deps), { local: true, reason: "vouched", address: "127.0.0.1" });

  // A pid that is NOT the handle (a stand-in for anything else on the box, an
  // uncontained bot included), holding the same VOUCHED port.
  const stranger = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 22 })], procs: [{ pid: 401, inodes: [22] }] });
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...deps, procRoot: stranger }),
    { local: false, reason: "listener-not-trusted", address: "127.0.0.1" },
  );

  // A handle that is no longer LIVE vouches nothing.
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...deps, nativeHandles: [{ pid: 400, port, live: false }] }),
    { local: false, reason: "listener-not-trusted", address: "127.0.0.1" },
  );

  // ... and a handle for ANOTHER port vouches nothing for this one.
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...deps, nativeHandles: [{ pid: 400, port: port + 1 }] }),
    { local: false, reason: "listener-not-trusted", address: "127.0.0.1" },
  );
});

// ---------------------------------------------------------------------------
// (2b) The DESCENDANT-IN-THE-SAME-USER-NAMESPACE rule is gone: an UNCONTAINED
// bot (CROW_PI_SANDBOX=off, the setpriv fallback, a bot in a container instance)
// is a descendant of the gateway in the gateway's own user namespace. Red-first:
// this passed before the rule was replaced.
// ---------------------------------------------------------------------------

test("RED FIRST: an uncontained bot (a same-uid CHILD of this process) on a port state.json reserves is refused", async () => {
  const bot = await spawnUntrustedListener();
  const home = freshHome();
  mkdirSync(join(home, "models"), { recursive: true });
  // The reservation names THIS process — the bot is its descendant, in the same
  // user namespace, which is exactly what the removed rule trusted.
  writeFileSync(join(home, "models", "state.json"), JSON.stringify({
    reservations: { "crow-chat": { port: bot.port, owner: { crowHome: home, pid: process.pid } } },
  }));
  try {
    const r = await isKnownLocalModelTarget(`http://127.0.0.1:${bot.port}/v1`, { crowHome: home, nativeHandles: [] });
    assert.deepEqual(r, { local: false, reason: "listener-not-trusted", address: "127.0.0.1" });
    assert.deepEqual(bot.hits, [], `SECURITY: nothing was dialled (bot received bytes: ${JSON.stringify(bot.hits)})`);
    // CONTROL: the listener is alive and reachable, so the refusal is the rule —
    // and the child's HIT line arrives over an asynchronous pipe, so wait for it
    // (L2).
    await bot.control({ method: "POST", path: "/v1/chat/completions" });
    assert.deepEqual(bot.hits, ["POST /v1/chat/completions"], `CONTROL: bot liveness probe not observed (${JSON.stringify(bot.hits)})`);
  } finally {
    await bot.close();
  }
});

test("a process with NO native handles trusts only the runtime's OWN VERIFIED binary, and only on a reserved port", async () => {
  const port = 18021;
  const home = freshHome();
  const { bin } = verifiedInstall(home);
  reserve(home, { port, pid: 4200 });

  // The helper lists what ensureRuntime can have installed (manifest + the two
  // archive shapes) — and only the candidates that are REGULAR files on disk.
  assert.ok(managedLlamaServerBinPaths(home).includes(bin), managedLlamaServerBinPaths(home).join("\n"));

  const managed = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 92 })], procs: [{ pid: 4200, inodes: [92], exe: bin, userns: GW_USERNS }] });
  const deps = {
    crowHome: home, procRoot: managed, uid: GW_UID, selfPid: -1, nativeHandles: [],
    isProcessAlive: (pid) => pid === 4200, dockerEntries: [{ address: "127.0.0.1", port }],
  };
  assert.deepEqual(await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, deps), { local: true, reason: "vouched", address: "127.0.0.1" });

  // The same reserved port, held by ANY other executable: refused.
  const otherExe = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 93 })], procs: [{ pid: 4201, inodes: [93], exe: "/usr/bin/node" }] });
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...deps, procRoot: otherExe }),
    { local: false, reason: "listener-not-trusted", address: "127.0.0.1" },
  );

  // The runtime's own binary on a port NOBODY reserved: refused. The reservation
  // is load-bearing, the executable alone is not.
  const unreserved = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port: 18022, inode: 94 })], procs: [{ pid: 4200, inodes: [94], exe: bin }] });
  assert.deepEqual(
    await isKnownLocalModelTarget("http://127.0.0.1:18022/v1", { ...deps, procRoot: unreserved, dockerEntries: [{ address: "127.0.0.1", port: 18022 }] }),
    { local: false, reason: "listener-not-trusted", address: "127.0.0.1" },
  );
});

// ---------------------------------------------------------------------------
// (2b) THE MANAGED-BINARY FALLBACK, hardened (security review): identity by
// CONTENT, a candidate that stays inside its release dir and is a regular file,
// a reservation that names a live pid, and the pin rule's user-namespace check.
// Red-first: every case below was ACCEPTED by the path-comparison rule.
// ---------------------------------------------------------------------------

test("RED FIRST: a SYMLINKED candidate never counts — the fallback wants the runtime's own regular file", async () => {
  const port = 18031;
  const home = freshHome();
  const releaseDir = join(home, "runtimes", "llamacpp", "b9001");
  mkdirSync(releaseDir, { recursive: true });
  const real = join(releaseDir, "real-llama-server");
  writeFileSync(real, "#!/bin/sh\necho real\n");
  // The manifest names `llama-server`, which is a SYMLINK to a file in the same
  // release dir. Its content is the verified bytes, and /proc/<pid>/exe resolves
  // to them — exactly what the old path comparison accepted.
  const link = join(releaseDir, "llama-server");
  symlinkSync(real, link);
  writeFileSync(join(releaseDir, ".crow-runtime-installed.json"), JSON.stringify({ key: "linux-x64-cpu", sha256: "0".repeat(64), binSha256: shaOf(readFileSync(real)), relBinPath: "llama-server" }));
  const portable = managedLlamaServerBinPaths(home);
  assert.deepEqual(portable, [], `a symlink is not a regular file: ${portable.join(", ")}`);

  reserve(home, { port, pid: 4300 });
  const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 201 })], procs: [{ pid: 4300, inodes: [201], exe: link, userns: GW_USERNS }] });
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { crowHome: home, procRoot, uid: GW_UID, selfPid: -1, nativeHandles: [], isProcessAlive: (pid) => pid === 4300, dockerEntries: [{ address: "127.0.0.1", port }] }),
    { local: false, reason: "listener-not-trusted", address: "127.0.0.1" },
  );
});

test("RED FIRST: an ABSOLUTE or '..'-carrying relBinPath is IGNORED, even when the process really runs that file", async () => {
  const port = 18032;
  const outsideDir = join(ROOT, `outside-${++seq}`);
  mkdirSync(outsideDir, { recursive: true });
  const outside = join(outsideDir, "llama-server");
  writeFileSync(outside, "#!/bin/sh\necho outside\n");

  for (const relBinPath of [outside, "../".repeat(6) + outside.replace(/^\/+/, ""), "../../usr/bin/x"]) {
    const home = freshHome();
    const releaseDir = join(home, "runtimes", "llamacpp", "b9002");
    mkdirSync(releaseDir, { recursive: true });
    writeFileSync(join(releaseDir, ".crow-runtime-installed.json"), JSON.stringify({ key: "linux-x64-cpu", sha256: "0".repeat(64), binSha256: shaOf(readFileSync(outside)), relBinPath }));
    // Nothing else under the release dir: the only candidate would be the escaping one.
    assert.deepEqual(managedLlamaServerBinPaths(home), [], `relBinPath ${relBinPath} must be ignored`);

    reserve(home, { port, pid: 4301 });
    const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 202 })], procs: [{ pid: 4301, inodes: [202], exe: outside, userns: GW_USERNS }] });
    assert.deepEqual(
      await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { crowHome: home, procRoot, uid: GW_UID, selfPid: -1, nativeHandles: [], isProcessAlive: (pid) => pid === 4301, dockerEntries: [{ address: "127.0.0.1", port }] }),
      { local: false, reason: "listener-not-trusted", address: "127.0.0.1" },
      `relBinPath ${relBinPath} outside the release dir vouched`,
    );
  }
});

test("RED FIRST: a CONTENT mismatch is refused, and so is a release with no recorded binary checksum", async () => {
  const port = 18033;
  // (a) The manifest records a checksum that is not this file's content.
  const tampered = freshHome();
  const { bin } = verifiedInstall(tampered, { content: "#!/bin/sh\necho tampered\n", recordedContent: "#!/bin/sh\necho genuine\n" });
  reserve(tampered, { port, pid: 4302 });
  const deps = { crowHome: tampered, uid: GW_UID, selfPid: -1, nativeHandles: [], isProcessAlive: (pid) => pid === 4302, dockerEntries: [{ address: "127.0.0.1", port }] };
  const tamperedProc = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 203 })], procs: [{ pid: 4302, inodes: [203], exe: bin, userns: GW_USERNS }] });
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...deps, procRoot: tamperedProc }),
    { local: false, reason: "listener-not-trusted", address: "127.0.0.1" },
  );
  // The identity follows CONTENT, not a cached verdict: put the bytes the manifest
  // recorded in place and the very same target is local. (The hash cache is keyed
  // dev+inode+size+mtime, so a file that changed is re-hashed, never remembered.)
  writeFileSync(bin, "#!/bin/sh\necho genuine\n");
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...deps, procRoot: tamperedProc }),
    { local: true, reason: "vouched", address: "127.0.0.1" },
  );

  // (b) An install made before the binary's checksum was recorded: no `binSha256`,
  // so the candidate does not count (an unrecorded binary is never "trusted by
  // default"). The archive checksum alone is not the binary's.
  const legacy = freshHome();
  const releaseDir = join(legacy, "runtimes", "llamacpp", "b9003");
  mkdirSync(releaseDir, { recursive: true });
  const legacyBin = join(releaseDir, "llama-server");
  writeFileSync(legacyBin, "#!/bin/sh\necho legacy\n");
  writeFileSync(join(releaseDir, ".crow-runtime-installed.json"), JSON.stringify({ key: "linux-x64-cpu", sha256: shaOf("the archive, not the binary"), relBinPath: "llama-server" }));
  assert.deepEqual(managedLlamaServerBinPaths(legacy), [], "no recorded binary checksum, no candidate");
  reserve(legacy, { port: port + 1, pid: 4303 });
  const legacyProc = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port: port + 1, inode: 204 })], procs: [{ pid: 4303, inodes: [204], exe: legacyBin, userns: GW_USERNS }] });
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port + 1}/v1`, { ...deps, crowHome: legacy, procRoot: legacyProc, isProcessAlive: (pid) => pid === 4303, dockerEntries: [{ address: "127.0.0.1", port: port + 1 }] }),
    { local: false, reason: "listener-not-trusted", address: "127.0.0.1" },
  );
});

test("RED FIRST: a reservation with NO recorded pid is not live — neither as a vouch nor as the fallback's condition", async () => {
  const port = 18034;
  const home = freshHome();
  const { bin } = verifiedInstall(home);
  // A reservation that names nobody. state.js records `owner.pid` for every port it
  // allocates, so this is a hand-edit or a fixture — never a live reservation.
  mkdirSync(join(home, "models"), { recursive: true });
  writeFileSync(join(home, "models", "state.json"), JSON.stringify({ reservations: { "crow-embed": { port, owner: {} } } }));
  const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 205 })], procs: [{ pid: 4304, inodes: [205], exe: bin, userns: GW_USERNS }] });
  const deps = { crowHome: home, procRoot, uid: GW_UID, selfPid: -1, nativeHandles: [], isProcessAlive: () => true };
  // (a) as a VOUCH: nothing else vouches the port, and a pid-less cell vouches nothing.
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...deps, dockerEntries: [] }),
    { local: false, reason: "not-vouched", address: "127.0.0.1" },
  );
  // (b) as the FALLBACK's condition: Docker vouches the port, so only the listener
  // half is left — and the pid-less reservation does not satisfy it.
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...deps, dockerEntries: [{ address: "127.0.0.1", port }] }),
    { local: false, reason: "listener-not-trusted", address: "127.0.0.1" },
  );

  // CONTROL: the same cell with a LIVE recorded pid is the whole difference.
  reserve(home, { port, pid: 4304 });
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...deps, dockerEntries: [{ address: "127.0.0.1", port }] }),
    { local: true, reason: "vouched", address: "127.0.0.1" },
  );
});

test("RED FIRST: the fallback demands the pin rule's USER NAMESPACE — the runtime's own binary in another namespace is a bot", async () => {
  const port = 18035;
  const home = freshHome();
  const { bin } = verifiedInstall(home);
  reserve(home, { port, pid: 4305 });
  const deps = { crowHome: home, uid: GW_UID, selfPid: -1, nativeHandles: [], isProcessAlive: (pid) => pid === 4305, dockerEntries: [{ address: "127.0.0.1", port }] };
  const otherNs = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 206 })], procs: [{ pid: 4305, inodes: [206], exe: bin, userns: OTHER_USERNS }] });
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...deps, procRoot: otherNs }),
    { local: false, reason: "listener-not-trusted", address: "127.0.0.1" },
  );
  // CONTROL: the genuine verified binary, a live pid reservation and THIS user
  // namespace — allowed, which is the one shape the fallback is for.
  const sameNs = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 207 })], procs: [{ pid: 4305, inodes: [207], exe: bin, userns: GW_USERNS }] });
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...deps, procRoot: sameNs }),
    { local: true, reason: "vouched", address: "127.0.0.1" },
  );
});

test("the port range alone vouches nothing: the reservation must be for THAT port, and its pid alive", async () => {
  const home = freshHome();
  mkdirSync(join(home, "models"), { recursive: true });
  writeFileSync(join(home, "models", "state.json"), JSON.stringify({ reservations: { "crow-chat": { port: 18111, owner: { crowHome: home, pid: 400 } } } }));
  const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port: 18150, inode: 31 })], procs: [{ pid: 400, inodes: [31] }] });
  assert.deepEqual(
    await isKnownLocalModelTarget("http://127.0.0.1:18150/v1", { crowHome: home, procRoot, uid: GW_UID, selfPid: -1, isProcessAlive: () => true }),
    { local: false, reason: "not-vouched", address: "127.0.0.1" },
    "18150 is inside 18100-18199 and is still not vouched",
  );
  // ... and a dead recorded pid does not vouch its port either.
  const dead = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port: 18111, inode: 32 })], procs: [{ pid: 400, inodes: [32] }] });
  assert.deepEqual(
    await isKnownLocalModelTarget("http://127.0.0.1:18111/v1", { crowHome: home, procRoot: dead, uid: GW_UID, selfPid: -1, isProcessAlive: () => false }),
    { local: false, reason: "not-vouched", address: "127.0.0.1" },
  );
});

test("a pid in a Docker container cgroup is local (a container's own process, same uid)", async () => {
  const procRoot = fakeProc({
    tcp: [procRow({ local: v4Hex("127.0.0.1"), port: 18008, inode: 41 })],
    procs: [{ pid: 5001, inodes: [41], cgroup: DOCKER_SCOPE, userns: OTHER_USERNS }],
  });
  const r = await isKnownLocalModelTarget("http://127.0.0.1:18008/v1", {
    crowHome: freshHome(), procRoot, uid: GW_UID, selfPid: -1,
    dockerEntries: [{ address: "127.0.0.1", port: 18008 }],
  });
  assert.deepEqual(r, { local: true, reason: "vouched", address: "127.0.0.1" });
  // A gateway-service cgroup is NOT a container.
  const plain = fakeProc({
    tcp: [procRow({ local: v4Hex("127.0.0.1"), port: 18009, inode: 42 })],
    procs: [{ pid: 5002, inodes: [42], cgroup: GW_CGROUP }],
  });
  assert.deepEqual(
    await isKnownLocalModelTarget("http://127.0.0.1:18009/v1", { crowHome: freshHome(), procRoot: plain, uid: GW_UID, selfPid: -1, dockerEntries: [{ address: null, port: 18009 }] }),
    { local: false, reason: "listener-not-trusted", address: "127.0.0.1" },
  );
});

test("an operator pin trusts the pinned EXECUTABLE in the gateway's user namespace, and nothing else", async () => {
  const home = freshHome();
  mkdirSync(join(home, "secrets"), { recursive: true, mode: 0o700 });
  const exe = "/opt/llama.cpp/llama-server";
  writeFileSync(join(home, "secrets", PIN_FILE), JSON.stringify([{ address: "127.0.0.1", port: 18010, exe }]), { mode: 0o600 });

  const sameNs = fakeProc({
    tcp: [procRow({ local: v4Hex("127.0.0.1"), port: 18010, inode: 51 })],
    procs: [{ pid: 7001, inodes: [51], exe, userns: GW_USERNS }],
  });
  assert.deepEqual(
    await isKnownLocalModelTarget("http://127.0.0.1:18010/v1", { crowHome: home, procRoot: sameNs, uid: GW_UID, selfPid: -1 }),
    { local: true, reason: "vouched", address: "127.0.0.1" },
  );

  // Same pinned path, but the process lives in its own user namespace: a bot.
  const otherNs = fakeProc({
    tcp: [procRow({ local: v4Hex("127.0.0.1"), port: 18010, inode: 52 })],
    procs: [{ pid: 7002, inodes: [52], exe, userns: OTHER_USERNS }],
  });
  assert.deepEqual(
    await isKnownLocalModelTarget("http://127.0.0.1:18010/v1", { crowHome: home, procRoot: otherNs, uid: GW_UID, selfPid: -1 }),
    { local: false, reason: "listener-not-trusted", address: "127.0.0.1" },
  );

  // A DIFFERENT executable on a pinned port is not trusted either.
  const otherExe = fakeProc({
    tcp: [procRow({ local: v4Hex("127.0.0.1"), port: 18010, inode: 53 })],
    procs: [{ pid: 7003, inodes: [53], exe: "/usr/bin/node", userns: GW_USERNS }],
  });
  assert.deepEqual(
    await isKnownLocalModelTarget("http://127.0.0.1:18010/v1", { crowHome: home, procRoot: otherExe, uid: GW_UID, selfPid: -1 }),
    { local: false, reason: "listener-not-trusted", address: "127.0.0.1" },
  );
});

// ---------------------------------------------------------------------------
// (2c) EVERY same-uid listener must be trusted, and the judgement is over the
// addresses that will actually be DIALED.
// ---------------------------------------------------------------------------

test("EVERY same-uid listener must be trusted: a trusted [::1] socket does not vouch a bot's 127.0.0.1 socket on the same port", async () => {
  const port = 18023;
  const SELF = 4301;
  const procRoot = fakeProc({
    tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 101 })],
    tcp6: [procRow({ local: v6Hex([0, 0, 0, 0, 0, 0, 0, 1]), port, inode: 102 })],
    procs: [{ pid: 4300, inodes: [101] }, { pid: SELF, inodes: [102] }],
  });
  // A caller that hands in no single address (`dialAddresses`) judges EVERY
  // address the name stands for — here the resolver's both loopback answers.
  const lookupFn = (_host, _opts, cb) => cb(null, [{ address: "127.0.0.1", family: 4 }, { address: "::1", family: 6 }]);
  const deps = { crowHome: freshHome(), procRoot, uid: GW_UID, selfPid: SELF, lookupFn, dockerEntries: [{ address: "localhost", port }] };
  // "localhost" is BOTH loopback addresses, so the bot's 127.0.0.1 socket is
  // among the ones judged: the trusted ::1 row does not save it.
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://localhost:${port}/v1`, deps),
    { local: false, reason: "listener-not-trusted", address: "127.0.0.1" },
  );

  // CONTROL: a caller that DIALS only ::1 (it pinned that answer) is judged on
  // that address alone, and the trusted ::1 socket vouches it.
  const onlyTrusted = fakeProc({ tcp6: [procRow({ local: v6Hex([0, 0, 0, 0, 0, 0, 0, 1]), port, inode: 103 })], procs: [{ pid: SELF, inodes: [103] }] });
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://localhost:${port}/v1`, { ...deps, procRoot: onlyTrusted, dialAddresses: ["::1"] }),
    { local: true, reason: "vouched", address: "::1" },
  );
  // ... and a caller that hands in NO address has its whole answer set judged at
  // once: the trusted ::1 socket vouches the set (which is exactly why every
  // forward resolves ONE address and hands that one in — the verdict says
  // "vouched" but cannot say WHICH address it was dialled on).
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://localhost:${port}/v1`, { ...deps, procRoot: onlyTrusted }),
    { local: true, reason: "vouched", address: "127.0.0.1" },
  );
});

test("SO_REUSEPORT stand-in: one native socket and one unknown socket on the same address and port is refused", async () => {
  const port = 18024;
  const procRoot = fakeProc({
    tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 111 }), procRow({ local: v4Hex("127.0.0.1"), port, inode: 112 })],
    procs: [{ pid: 4400, inodes: [111] }, { pid: 4401, inodes: [112] }],
  });
  const deps = { crowHome: freshHome(), procRoot, uid: GW_UID, selfPid: -1, nativeHandles: [{ pid: 4400, port }], dockerEntries: [{ address: "127.0.0.1", port }] };
  assert.deepEqual(await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, deps), { local: false, reason: "listener-not-trusted", address: "127.0.0.1" });

  // CONTROL: with only the native socket there, the very same target is local.
  const onlyNative = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 113 })], procs: [{ pid: 4400, inodes: [113] }] });
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...deps, procRoot: onlyNative }),
    { local: true, reason: "vouched", address: "127.0.0.1" },
  );
});

test("a native handle vouches the ADDRESS it bound, not the port alone: 127.0.0.1:P does not vouch 100.64.20.5:P", async () => {
  const port = 18025;
  const ownAddrs = new Set(["127.0.0.1", "100.64.20.5"]);
  const home = freshHome();
  mkdirSync(join(home, "models"), { recursive: true });
  writeFileSync(join(home, "models", "state.json"), JSON.stringify({ reservations: { "crow-chat": { port, owner: { pid: 4500 } } } }));
  const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("100.64.20.5"), port, inode: 121 })], procs: [{ pid: 4500, inodes: [121] }] });
  const deps = { crowHome: home, ownAddrs, procRoot, uid: GW_UID, selfPid: -1, isProcessAlive: () => true, nativeHandles: [{ pid: 4500, port }] };
  // The handle binds the llama-server default, 127.0.0.1: it does not vouch the
  // same pid's socket on another own address.
  assert.deepEqual(await isKnownLocalModelTarget(`http://100.64.20.5:${port}/v1`, deps), { local: false, reason: "listener-not-trusted", address: "100.64.20.5" });
  // CONTROL: the same handle, on the address it binds.
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://100.64.20.5:${port}/v1`, { ...deps, nativeHandles: [{ pid: 4500, port, host: "100.64.20.5" }] }),
    { local: true, reason: "vouched", address: "100.64.20.5" },
  );
});

test("the vouch is judged over the addresses the caller will DIAL, and never over a broader set", async () => {
  const port = 18026;
  const SELF = 4601;
  const procRoot = fakeProc({
    tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 131 })],
    tcp6: [procRow({ local: v6Hex([0, 0, 0, 0, 0, 0, 0, 1]), port, inode: 132 })],
    procs: [{ pid: SELF, inodes: [131] }, { pid: 4600, inodes: [132] }],
  });
  const base = { crowHome: freshHome(), procRoot, uid: GW_UID, selfPid: SELF, lookupFn: (_h, _o, cb) => cb(null, [{ address: "127.0.0.1", family: 4 }, { address: "::1", family: 6 }]), dockerEntries: [{ address: "localhost", port }] };
  // A caller that will dial 127.0.0.1 only (it pinned that answer) is judged on
  // that address alone: the ::1 socket is not a destination.
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://localhost:${port}/v1`, { ...base, dialAddresses: ["127.0.0.1"] }),
    { local: true, reason: "vouched", address: "127.0.0.1" },
  );
  // ... and with no pinned address the same URL is judged as BOTH (the rule above).
  assert.deepEqual(await isKnownLocalModelTarget(`http://localhost:${port}/v1`, base), { local: false, reason: "listener-not-trusted", address: "127.0.0.1" });
});

// ---------------------------------------------------------------------------
// (3) Not vouched is enough to refuse — the listener does not get a vote.
// ---------------------------------------------------------------------------

test("an own-host target nothing vouches for is refused BEFORE any listener is considered", async () => {
  const squat = await squatter();
  try {
    // The listener is ANOTHER process (a bot). Nothing outside crow.db vouches the
    // port, so the answer is settled before the listener is even looked at.
    const r = await isKnownLocalModelTarget(`http://127.0.0.1:${squat.port}/v1`, {
      crowHome: freshHome(), selfPid: -1, uid: GW_UID,
    });
    assert.deepEqual(r, { local: false, reason: "not-vouched", address: "127.0.0.1" });
    assert.deepEqual(squat.hits, []);
  } finally {
    await squat.close();
  }
});

test("address matters: a vouch on 100.64.20.5:8004 never vouches 127.0.0.1:8004 (and vice versa)", async () => {
  const ownAddrs = new Set(["127.0.0.1", "100.64.20.5"]);
  const port = 8004;
  const procRoot = fakeProc({
    tcp: [procRow({ local: v4Hex("100.64.20.5"), port, uid: 0, inode: 61 })],
  });
  const deps = { crowHome: freshHome(), ownAddrs, procRoot, uid: GW_UID, selfPid: -1, dockerEntries: [{ address: "100.64.20.5", port }] };
  assert.deepEqual(await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, deps), { local: false, reason: "not-vouched", address: "127.0.0.1" });
  assert.deepEqual(await isKnownLocalModelTarget(`http://100.64.20.5:${port}/v1`, deps), { local: true, reason: "vouched", address: "100.64.20.5" });
  // The bind on the specific tailnet address does not cover loopback even when the
  // listener is there; a wildcard bind does.
  const wide = fakeProc({ tcp: [procRow({ local: "00000000", port, uid: 0, inode: 62 })] });
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...deps, procRoot: wide, dockerEntries: [{ address: "", port }] }),
    { local: true, reason: "vouched", address: "127.0.0.1" },
  );
});

test("a LAN or tailnet target is unchanged: other-host, no listener and no vouch needed", async () => {
  const ownAddrs = new Set(["127.0.0.1", "100.64.20.5"]);
  const lookupFn = (host, options, cb) => {
    const done = typeof options === "function" ? options : cb;
    if (host === "peer.example.ts.net") return done(null, [{ address: "100.64.20.9", family: 4 }]);
    return done(Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }));
  };
  const deps = { crowHome: freshHome(), ownAddrs, lookupFn, selfPid: -1, uid: GW_UID };
  assert.deepEqual(await isKnownLocalModelTarget("http://10.0.0.7:8004/v1", deps), { local: true, reason: "other-host", address: "10.0.0.7" });
  assert.deepEqual(await isKnownLocalModelTarget("http://peer.example.ts.net:8004/v1", deps), { local: true, reason: "other-host", address: "100.64.20.9" });
  // ... and a name the resolver does not answer for is refused for every caller.
  assert.deepEqual(await isKnownLocalModelTarget("http://nope.example.ts.net:8004/v1", deps), { local: false, reason: "unresolved", address: null });
});

// ---------------------------------------------------------------------------
// (4) Docker unreachable: last GOOD snapshot, else fail closed.
// ---------------------------------------------------------------------------

test("an unreachable Docker uses the last good snapshot; with none, the port is not vouched", async () => {
  const home = freshHome();
  // S3: a container vouches only from an AI-category bundle directory (or an owner
  // pin), so the fixture is the store's Ollama bundle directory.
  mkdirSync(join(home, "bundles", "ollama"), { recursive: true });
  writeFileSync(join(home, "bundles", "ollama", "manifest.json"), JSON.stringify({ id: "ollama", category: "ai" }));
  const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port: 18012, uid: 0, inode: 71 })] });
  let mode = "ok";
  const dockerRunner = async (cmd, args) => {
    if (mode === "down") throw new Error("docker: command not found");
    if (args[0] === "ps") return { stdout: "abc123\n" };
    // ONE inspect pass: the compose project directory (Docker compose's own
    // label) says WHICH container this is; the bindings say what it publishes.
    return {
      stdout: `${inspectLine({
        labels: { [COMPOSE_WORKING_DIR_LABEL]: join(home, "bundles", "ollama") },
        bindings: { "18012/tcp": [{ HostIp: "127.0.0.1", HostPort: "18012" }] },
      })}\n`,
    };
  };
  const deps = { crowHome: home, procRoot, uid: GW_UID, selfPid: -1, dockerRunner };
  assert.deepEqual(await isKnownLocalModelTarget("http://127.0.0.1:18012/v1", deps), { local: true, reason: "vouched", address: "127.0.0.1" });
  mode = "down";
  assert.deepEqual(
    await isKnownLocalModelTarget("http://127.0.0.1:18012/v1", deps),
    { local: true, reason: "vouched", address: "127.0.0.1" },
    "the last good snapshot still vouches the port",
  );

  resetLocalModelVouchCache();
  assert.deepEqual(
    await isKnownLocalModelTarget("http://127.0.0.1:18012/v1", { ...deps, dockerRunner: async () => { throw new Error("no docker"); } }),
    { local: false, reason: "not-vouched", address: "127.0.0.1" },
    "no snapshot at all: fail closed",
  );
});

// ---------------------------------------------------------------------------
// (5) The bundle compose file vouches too (published host port + optional IP).
// ---------------------------------------------------------------------------

test("an installed AI bundle's compose file vouches its published port, and only that port — a non-AI bundle's does not", async () => {
  const home = freshHome();
  const dir = join(home, "bundles", "crow-voice-bundle");
  mkdirSync(dir, { recursive: true });
  // S3: vouch (b) follows the SAME category rule as vouch (a) — an AI bundle.
  writeFileSync(join(dir, "manifest.json"), JSON.stringify({ id: "crow-voice-bundle", category: "ai" }));
  writeFileSync(join(dir, "docker-compose.yml"), [
    "services:",
    "  voice:",
    "    image: example/voice",
    "    ports:",
    '      - "127.0.0.1:18013:8011"',
    "      - 127.0.0.1:18014:8011/udp",
    "  other:",
    "    image: example/other",
    "    ports:",
    "      - target: 9000",
    "        published: \"18015\"",
    "        host_ip: 0.0.0.0",
    "",
  ].join("\n"));
  // A search engine publishes 18016 on loopback and is NOT a model server.
  const search = join(home, "bundles", "searxng");
  mkdirSync(search, { recursive: true });
  writeFileSync(join(search, "manifest.json"), JSON.stringify({ id: "searxng", category: "productivity" }));
  writeFileSync(join(search, "docker-compose.yml"), "services:\n  web:\n    image: example/searxng\n    ports:\n      - \"127.0.0.1:18016:8080\"\n");
  // An installed bundle with no manifest at all (a pre-manifest copy, a damaged
  // install): no category, no vouch — fail closed.
  const unlabelled = join(home, "bundles", "unlabelled");
  mkdirSync(unlabelled, { recursive: true });
  writeFileSync(join(unlabelled, "docker-compose.yml"), "services:\n  x:\n    image: example/x\n    ports:\n      - \"127.0.0.1:18017:8080\"\n");
  const deps = { crowHome: home, procRoot: fakeProc({ tcp: [] }), uid: GW_UID, selfPid: -1 };
  const vouch = (port) => isKnownLocalModelTargetCached(`http://127.0.0.1:${port}/v1`, deps);
  assert.deepEqual(vouch(18013), { local: true, reason: "vouched" });
  assert.deepEqual(vouch(18015), { local: true, reason: "vouched" }, "the long syntax's published port, on every interface");
  assert.deepEqual(vouch(8011), { local: false, reason: "not-vouched" }, "the CONTAINER port is not a published host port");
  assert.deepEqual(vouch(18014), { local: false, reason: "not-vouched" }, "a udp publish is not a tcp model server");
  assert.deepEqual(vouch(18016), { local: false, reason: "not-vouched" }, "a productivity bundle's publish vouches nothing");
  assert.deepEqual(vouch(18017), { local: false, reason: "not-vouched" }, "no manifest, no category, no vouch");
  assert.deepEqual(publishedPortsOf('ports:\n  - "9000:8004"\n'), [{ address: null, port: 9000 }]);
});

// ---------------------------------------------------------------------------
// (5b) S3: which DOCKER containers may vouch — a compose project directory that
// is an AI-category Crow bundle, or one the owner pinned. A published port alone
// is not a statement about what is published on it.
// ---------------------------------------------------------------------------

/** A docker CLI fake: one container (`ps`), its published bindings, its compose
 * labels (`null` = a container with no labels at all) and its NAME (as Docker
 * prints it: with a leading "/"), all in the ONE inspect pass. Records every call. */
function fakeDocker({ bindings, labels, name = "/c0ffee" }) {
  const calls = [];
  const runner = async (cmd, args) => {
    calls.push([cmd, ...args].join(" "));
    if (args[0] === "ps") return { stdout: "c0ffee\n" };
    return { stdout: `${inspectLine({ name, labels, bindings })}\n` };
  };
  runner.calls = calls;
  return runner;
}

test("RED FIRST (S3): a Docker container vouches only from an AI-bundle or an owner-pinned compose directory", async () => {
  const port = 18041;
  const home = freshHome();
  const aiDir = join(home, "bundles", "vllm-custom");
  mkdirSync(aiDir, { recursive: true });
  writeFileSync(join(aiDir, "manifest.json"), JSON.stringify({ id: "vllm-custom", category: "ai" }));
  const productivity = join(home, "bundles", "searxng");
  mkdirSync(productivity, { recursive: true });
  writeFileSync(join(productivity, "manifest.json"), JSON.stringify({ id: "searxng", category: "productivity" }));
  const loose = join(home, "my-own-vllm");
  mkdirSync(loose, { recursive: true });

  // A listener on the port that is not ours (docker-proxy, uid 0), so the LISTENER
  // half passes and only the vouch decides.
  const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, uid: 0, inode: 301 })] });
  const bindings = { [`${port}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: String(port) }] };
  const judge = (labels) => isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, {
    crowHome: home, procRoot, uid: GW_UID, selfPid: -1,
    dockerRunner: fakeDocker({ bindings, labels }),
  });
  const vouched = { local: true, reason: "vouched", address: "127.0.0.1" };
  const notVouched = { local: false, reason: "not-vouched", address: "127.0.0.1" };

  // (i) an AI-category bundle directory: the container IS a model server.
  resetLocalModelVouchCache();
  assert.deepEqual(await judge({ [COMPOSE_WORKING_DIR_LABEL]: aiDir }), vouched);
  // (ii) a NON-ai bundle (search, Nextcloud, Home Assistant, a household Crow
  // container…): its published port vouches nothing.
  resetLocalModelVouchCache();
  assert.deepEqual(await judge({ [COMPOSE_WORKING_DIR_LABEL]: productivity }), notVouched);
  // (iii) a container with NO compose label at all: vouches nothing.
  resetLocalModelVouchCache();
  assert.deepEqual(await judge(null), notVouched);
  resetLocalModelVouchCache();
  assert.deepEqual(await judge({}), notVouched);
  // (iv) a directory that is no bundle: not vouched…
  resetLocalModelVouchCache();
  assert.deepEqual(await judge({ [COMPOSE_WORKING_DIR_LABEL]: loose }), notVouched);
  // … until the OWNER pins it (`local-model-pin add-compose`), and then it is.
  mkdirSync(join(home, "secrets"), { recursive: true, mode: 0o700 });
  writeFileSync(join(home, "secrets", PIN_FILE), JSON.stringify([{ composeDir: loose }]), { mode: 0o600 });
  resetLocalModelVouchCache();
  assert.deepEqual(await judge({ [COMPOSE_WORKING_DIR_LABEL]: loose }), vouched);
  // A pin does not bless a DIFFERENT directory, and it never blesses a port: the
  // label on the container decides.
  resetLocalModelVouchCache();
  assert.deepEqual(await judge({ [COMPOSE_WORKING_DIR_LABEL]: productivity }), notVouched);
});

// ---------------------------------------------------------------------------
// (7b) J4 — ONE `docker inspect` pass, so no field can land on the wrong
// container. The old read zipped THREE passes back together by line position
// (`{{json .HostConfig.PortBindings}}`, `{{json .Config.Labels}}`, `{{.Name}}`),
// which is only correct while every pass prints exactly one line per container in
// the same order — one short or noisy pass shifted labels onto other containers.
// ---------------------------------------------------------------------------

test("RED FIRST (J4): one inspect pass carries id, name, labels and bindings, and a labels-less container cannot shift another container's fields", async () => {
  const home = freshHome();
  const aiDir = join(home, "bundles", "localai");
  mkdirSync(aiDir, { recursive: true });
  writeFileSync(join(aiDir, "manifest.json"), JSON.stringify({ id: "localai", category: "ai" }));
  const modelPort = 18071; // the AI bundle's container publishes this one
  const plainPort = 18072; // a household container, no labels at all
  const procRoot = fakeProc({
    tcp: [
      procRow({ local: v4Hex("127.0.0.1"), port: modelPort, uid: 0, inode: 501 }),
      procRow({ local: v4Hex("127.0.0.1"), port: plainPort, uid: 0, inode: 502 }),
    ],
  });
  const calls = [];
  const dockerRunner = async (cmd, args) => {
    calls.push([cmd, ...args].join(" "));
    if (args[0] === "ps") return { stdout: "aaaa\nbbbb\n" };
    return {
      stdout: [
        // Docker can print a warning on stdout; a line that is not a container
        // record must be skipped, never parsed as one.
        "WARNING: something the CLI felt like printing",
        // TWO containers, the FIRST with no labels at all (`null`) — under the old
        // positional zip its label slot and the model's could trade places.
        inspectLine({ id: "a".repeat(12), name: "/household", labels: null, bindings: { [`${plainPort}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: String(plainPort) }] } }),
        inspectLine({ id: "b".repeat(12), name: "/model", labels: { [COMPOSE_WORKING_DIR_LABEL]: aiDir }, bindings: { [`${modelPort}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: String(modelPort) }] } }),
      ].join("\n") + "\n",
    };
  };
  const deps = { crowHome: home, procRoot, uid: GW_UID, selfPid: -1, dockerRunner };
  resetLocalModelVouchCache();

  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${modelPort}/v1`, deps),
    { local: true, reason: "vouched", address: "127.0.0.1" },
    "the AI bundle's container vouches ITS port",
  );
  const inspects = calls.filter((c) => c.includes("inspect"));
  assert.equal(inspects.length, 1, `ONE inspect pass, not ${inspects.length}:\n${inspects.join("\n")}`);
  assert.ok(inspects[0].includes(DOCKER_INSPECT_FORMAT), "the pass asks for id, name, labels AND bindings together");
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${plainPort}/v1`, deps),
    { local: false, reason: "not-vouched", address: "127.0.0.1" },
    "the labels-less container vouches nothing — its `null` label line consumed its own index",
  );
});

test("RED FIRST (S2): a container CREATED after the snapshot is admitted by ONE forced Docker re-read, rate-limited process-wide", async () => {
  const port = 18042;
  const home = freshHome();
  const aiDir = join(home, "bundles", "localai");
  mkdirSync(aiDir, { recursive: true });
  writeFileSync(join(aiDir, "manifest.json"), JSON.stringify({ id: "localai", category: "ai" }));
  const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, uid: 0, inode: 311 })] });
  const bindings = { [`${port}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: String(port) }] };
  let containers = 0; // how many containers Docker reports
  const calls = [];
  const dockerRunner = async (cmd, args) => {
    calls.push([cmd, ...args].join(" "));
    if (args[0] === "ps") return { stdout: containers ? "c0ffee\n" : "" };
    return { stdout: containers ? `${inspectLine({ labels: { [COMPOSE_WORKING_DIR_LABEL]: aiDir }, bindings })}\n` : "" };
  };
  let clock = 1_000_000;
  const deps = { crowHome: home, procRoot, uid: GW_UID, selfPid: -1, dockerRunner, now: () => clock };
  const url = `http://127.0.0.1:${port}/v1`;

  // Nothing is running: the snapshot is taken, the forced re-read agrees, refused.
  assert.deepEqual(await isKnownLocalModelTarget(url, deps), { local: false, reason: "not-vouched", address: "127.0.0.1" });
  const afterFirst = calls.length;

  // The acquire creates the container a moment later. The cached snapshot still says
  // "nothing published" and the rate limit has just closed the window: the very next
  // forward is still refused, and Docker was NOT asked again.
  containers = 1;
  clock += 1_000;
  assert.deepEqual(await isKnownLocalModelTarget(url, deps), { local: false, reason: "not-vouched", address: "127.0.0.1" });
  assert.equal(calls.length, afterFirst, "at most one forced re-read per PROCESS in 10 s");

  // Once the window opens, ONE forced re-read sees the new container.
  clock += DOCKER_REFRESH_MIN_MS;
  assert.deepEqual(await isKnownLocalModelTarget(url, deps), { local: true, reason: "vouched", address: "127.0.0.1" });
  assert.ok(calls.length > afterFirst, calls.join("\n"));
});

// ---------------------------------------------------------------------------
// (5b2) H2 — the forced Docker re-read is rate-limited ONCE PER PROCESS, not per
// address:port. The key of a per-target window is ATTACKER-CHOSEN (a contained bot
// writes its own providers row, so it picks the port), so cycling ports used to
// spawn one `docker` subprocess per forward and grow the window map without bound.
// ---------------------------------------------------------------------------

test("RED FIRST (H2): 100 forwards to 100 different unvouched own-host ports inside the window cause exactly ONE forced Docker read", async () => {
  const home = freshHome();
  // Docker reports NOTHING (no model container) and nothing listens, so every one of
  // the 100 judgements ends "not-vouched" — the path that asks Docker again.
  let reads = 0; // one per forced snapshot (the `ps` that starts it)
  const dockerRunner = async (_cmd, args) => {
    if (args[0] === "ps") { reads += 1; return { stdout: "" }; }
    return { stdout: "" };
  };
  let clock = 3_000_000;
  const deps = { crowHome: home, procRoot: fakeProc({ tcp: [] }), uid: GW_UID, selfPid: -1, dockerRunner, now: () => clock };
  resetLocalModelVouchCache();

  // Warm the snapshot WITHOUT a forced re-read (the listing path primes it in the
  // background), so the count below is only what the forwards force themselves.
  assert.deepEqual(isKnownLocalModelTargetCached("http://127.0.0.1:51099/v1", deps), { local: false, reason: "not-vouched" });
  await whenLocalModelVouchReady();
  reads = 0;

  const notVouched = { local: false, reason: "not-vouched", address: "127.0.0.1" };
  for (let i = 0; i < 100; i++) {
    const port = 51_000 + i; // 100 DIFFERENT ports, all inside the one window
    assert.deepEqual(await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, deps), notVouched, `port ${port}`);
  }
  assert.equal(reads, 1, `100 forwards to 100 different ports forced ${reads} docker reads, not ONE`);

  // Inside the window nothing else is read, whichever port is asked.
  clock += DOCKER_REFRESH_MIN_MS - 1;
  assert.deepEqual(await isKnownLocalModelTarget("http://127.0.0.1:51299/v1", deps), notVouched);
  assert.equal(reads, 1, "still one read inside the window");

  // Once the window opens, ONE more is allowed — and only one.
  clock += 1;
  assert.deepEqual(await isKnownLocalModelTarget("http://127.0.0.1:51300/v1", deps), notVouched);
  assert.equal(reads, 2, "the window opened: exactly one more forced read");
  assert.deepEqual(await isKnownLocalModelTarget("http://127.0.0.1:51301/v1", deps), notVouched);
  assert.equal(reads, 2, "and the window closed again for every port");
});

test("RED FIRST (H2): callers that arrive DURING a forced re-read await the SAME promise, so they see the fresh snapshot and no second `docker` runs", async () => {
  const port = 18043;
  const home = freshHome();
  const aiDir = join(home, "bundles", "localai");
  mkdirSync(aiDir, { recursive: true });
  writeFileSync(join(aiDir, "manifest.json"), JSON.stringify({ id: "localai", category: "ai" }));
  // docker-proxy (uid 0) holds the listener, so the LISTENER half passes and the
  // vouch half decides.
  const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, uid: 0, inode: 331 })] });
  const bindings = { [`${port}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: String(port) }] };
  let containers = 0;
  let reads = 0;
  let gate = null; // a COLD, slow docker: the next `ps` waits on this
  const dockerRunner = async (_cmd, args) => {
    if (args[0] === "ps") { reads += 1; if (gate) await gate; return { stdout: containers ? "c0ffee\n" : "" }; }
    return { stdout: containers ? `${inspectLine({ labels: { [COMPOSE_WORKING_DIR_LABEL]: aiDir }, bindings })}\n` : "" };
  };
  let clock = 4_000_000;
  const deps = { crowHome: home, procRoot, uid: GW_UID, selfPid: -1, dockerRunner, now: () => clock };
  const url = `http://127.0.0.1:${port}/v1`;
  resetLocalModelVouchCache();

  // An EMPTY snapshot, primed without a forced re-read.
  isKnownLocalModelTargetCached(url, deps);
  await whenLocalModelVouchReady();
  reads = 0;

  // The container comes up and Docker is slow. The FIRST forward forces the re-read;
  // a second forward arriving while that read is still running must ride on the SAME
  // promise (and see the fresh snapshot), not be handed the stale one.
  containers = 1;
  let release;
  gate = new Promise((r) => { release = r; });
  const first = isKnownLocalModelTarget(url, deps);
  const second = isKnownLocalModelTarget(url, deps);
  // Let both reach the forced re-read before it is allowed to finish.
  for (let i = 0; i < 100 && reads === 0; i++) await new Promise((r) => setTimeout(r, 5));
  for (let i = 0; i < 20; i++) await new Promise((r) => setImmediate(r));
  release();
  gate = null;
  const vouched = { local: true, reason: "vouched", address: "127.0.0.1" };
  assert.deepEqual(await first, vouched, "the caller that STARTED the re-read sees the new container");
  assert.deepEqual(await second, vouched, "the caller that arrived DURING the re-read shares its promise (never the stale snapshot)");
  assert.equal(reads, 1, `the forced re-read ran ${reads} docker reads, not one`);
});

// ---------------------------------------------------------------------------
// (5c) M1: a Crow DOOR url on this host is not a model server for a child
// process (the memory MCP server, a pi-bots host process).
// ---------------------------------------------------------------------------

test("RED FIRST (M1): a door URL on this host is refused as door-url-from-child outside the gateway process", async () => {
  const port = 18052;
  const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 401 })], procs: [{ pid: 9001, inodes: [401] }] });
  // The memory MCP child: the socket on the gateway's port belongs to the gateway,
  // not to this process, so the old answer was "listener-not-trusted" — a
  // squat-shaped reason for a different fact.
  const deps = { crowHome: freshHome(), procRoot, uid: GW_UID, selfPid: -1, dockerEntries: [], isGatewayProcess: false };
  for (const url of [`http://127.0.0.1:${port}/llm/v1`, `http://127.0.0.1:${port}/llm/p/crow-chat/v1`]) {
    assert.deepEqual(await isKnownLocalModelTarget(url, deps), { local: false, reason: "door-url-from-child", address: "127.0.0.1" }, url);
  }
  // The GATEWAY's own process is the one process that may judge its own door (the
  // judgement then falls through to the ordinary vouch/listener rule).
  assert.equal(
    (await isKnownLocalModelTarget(`http://127.0.0.1:${port}/llm/v1`, { ...deps, isGatewayProcess: true })).reason,
    "not-vouched",
  );
  // A NON-door URL on the same port is judged exactly as before.
  assert.deepEqual(await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, deps), { local: false, reason: "not-vouched", address: "127.0.0.1" });
  // … and a door URL on ANOTHER host is still other-host: nothing local to drive.
  assert.equal((await isKnownLocalModelTarget("http://10.0.0.7:3001/llm/v1", { ...deps, procRoot: fakeProc({ tcp: [] }) })).reason, "other-host");
});

// ---------------------------------------------------------------------------
// (5d) S1: the boot line for a provider row nothing vouches for at rest.
// ---------------------------------------------------------------------------

test("RED FIRST (S1): one boot log line per ENABLED provider row whose own-host target nothing vouches at rest", () => {
  const home = freshHome();
  // A live native reservation makes ONE row vouched at rest (state.json, read by the
  // sync listing predicate), so the line is about the vouch and not about "any
  // loopback row".
  mkdirSync(join(home, "models"), { recursive: true });
  writeFileSync(join(home, "models", "state.json"), JSON.stringify({ reservations: { "crow-chat": { port: 18111, owner: { pid: process.pid } } } }));
  resetLocalModelVouchCache();
  const lines = [];
  const rows = [
    { id: "crow-chat", baseUrl: "http://127.0.0.1:18111/v1" },
    { id: "squat", baseUrl: "http://127.0.0.1:18071/v1" },
    { id: "turned-off", baseUrl: "http://127.0.0.1:18072/v1", disabled: true },
    { id: "cloudy", baseUrl: "https://api.example.test/v1" },
    { id: "peer", baseUrl: "http://10.0.0.7:8004/v1" },
  ];
  const deps = { crowHome: home, isProcessAlive: (pid) => pid === process.pid };
  const printed = logUnvouchedProviderRows(rows, { deps, log: (line) => lines.push(line) });
  assert.equal(printed, 1, lines.join("\n"));
  assert.deepEqual(lines, [
    "[local-model] provider squat (127.0.0.1:18071) is not vouched at rest; it will be refused unless its server is running as a known model container or pinned",
  ]);
  // CONTROL: the vouched row really is vouched, or the single line above proves
  // nothing about the vouch.
  assert.equal(isKnownLocalModelTargetCached("http://127.0.0.1:18111/v1", deps).local, true);

  // The BOOT wiring: the gateway prints the check right after its first vouch
  // snapshot (a log line nobody calls is not a boot line).
  const src = readFileSync(join(import.meta.dirname, "..", "servers", "gateway", "boot", "admin-api.js"), "utf8");
  const primeAt = src.indexOf("await primeLocalModelVouch();");
  const logAt = src.indexOf("logUnvouchedProviderRows(rows);");
  assert.ok(primeAt > 0, "the gateway takes the first vouch snapshot at boot");
  assert.ok(logAt > primeAt, "the boot check runs after that snapshot, not before it");
});

// ---------------------------------------------------------------------------
// (6) /proc/net decoding
// ---------------------------------------------------------------------------

test("/proc/net/tcp6 decoding: little-endian words, v4-mapped, wildcard", () => {
  assert.equal(decodeProcNetAddress(v4Hex("127.0.0.1"), 4), "127.0.0.1");
  assert.equal(decodeProcNetAddress("00000000", 4), "0.0.0.0");
  assert.equal(decodeProcNetAddress(v6Hex([0, 0, 0, 0, 0, 0, 0, 1]), 6), "0:0:0:0:0:0:0:1");
  assert.equal(decodeProcNetAddress(v6Hex([0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001]), 6), "127.0.0.1", "v4-mapped unwrapped");
  assert.equal(decodeProcNetAddress(v6Hex([0, 0, 0, 0, 0, 0, 0, 0]), 6), "::");
  assert.equal(decodeProcNetAddress(v6Hex([0xfd7a, 0x115c, 0xa1e0, 0, 0, 0, 0, 1]), 6), "fd7a:115c:a1e0:0:0:0:0:1");
  assert.equal(decodeProcNetAddress("nonsense", 4), null);

  const rows = parseProcNet(`  sl  local_address rem_address   st\n   0: ${v4Hex("127.0.0.1")}:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000  1000        0 4242 1 0 100 0 0 10 0\n`, 4);
  assert.deepEqual(rows, [{ address: "127.0.0.1", port: 8080, state: "0A", uid: 1000, inode: "4242" }]);
});

test("/proc/net/tcp6: a v4-mapped row and a `::` wildcard both match a loopback target", async () => {
  const home = freshHome();
  const mapped = fakeProc({
    tcp6: [procRow({ local: v6Hex([0, 0, 0, 0, 0, 0xffff, 0x7f00, 0x0001]), port: 18016, uid: 0, inode: 81 })],
  });
  assert.deepEqual(
    await isKnownLocalModelTarget("http://127.0.0.1:18016/v1", { crowHome: home, procRoot: mapped, uid: GW_UID, selfPid: -1, dockerEntries: [{ address: "127.0.0.1", port: 18016 }] }),
    { local: true, reason: "vouched", address: "127.0.0.1" },
  );
  const wildcard = fakeProc({
    tcp6: [procRow({ local: v6Hex([0, 0, 0, 0, 0, 0, 0, 0]), port: 18017, uid: 0, inode: 82 })],
  });
  assert.deepEqual(
    await isKnownLocalModelTarget("http://127.0.0.1:18017/v1", { crowHome: home, procRoot: wildcard, uid: GW_UID, selfPid: -1, dockerEntries: [{ address: null, port: 18017 }] }),
    { local: true, reason: "vouched", address: "127.0.0.1" },
  );
});

// ---------------------------------------------------------------------------
// (7) The new class: unverified-local is neither local nor cloud.
// ---------------------------------------------------------------------------

test("unverified-local: pi's models.json does not get it as a local model, and it is not cloud-consent eligible or cloud-door served", () => {
  const saved = process.env.CROW_HOME;
  const home = freshHome();
  process.env.CROW_HOME = home;
  try {
    resetLocalModelVouchCache();
    const baseUrl = "http://127.0.0.1:18099/v1";
    const row = { id: "sneaky", baseUrl, apiKey: "none", bundleId: "b", provider_type: "openai-compat", models: [{ id: "m" }], disabled: false };
    const logs = [];
    const out = buildManagedEntries([row], { log: (l) => logs.push(l) });
    assert.deepEqual(Object.keys(out), [], "not handed to pi as a local model");
    assert.ok(logs.some((l) => l.includes('provider "sneaky" skipped')), logs.join("\n"));

    // NEITHER local NOR cloud: it is not a cloud row, not a cloud target, and the
    // cloud door refuses it with its existing NOT_CLOUD answer.
    assert.equal(isCloudRow({ baseUrl }), false);
    assert.equal(isCloudTarget(baseUrl), false);
    const target = resolveCloudTarget({ providers: { sneaky: row }, providerId: "sneaky", op: "chat", model: "m" });
    assert.equal(target.kind, "error");
    assert.equal(target.code, "NOT_CLOUD");
    // ... and the local LISTING does not offer it either.
    assert.deepEqual(listDoorModels({ sneaky: { ...row, gpuPolicy: { door_forward: true } } }), []);
    assert.equal(isUnverifiedLocalTarget(baseUrl), true);

    // Vouched, the very same URL is a local model again (the rule is the vouch,
    // not the address).
    mkdirSync(join(home, "models"), { recursive: true });
    writeFileSync(join(home, "models", "state.json"), JSON.stringify({ reservations: { x: { port: 18099, owner: { pid: process.pid } } } }));
    assert.equal(isUnverifiedLocalTarget(baseUrl), false);
    assert.deepEqual(listDoorModels({ sneaky: { ...row, gpuPolicy: { door_forward: true } } }).map((m) => m.id), ["sneaky/m"]);
    assert.equal(isCloudRow({ baseUrl }), false, "a vouched LOCAL row is still not cloud");
  } finally {
    if (saved === undefined) delete process.env.CROW_HOME;
    else process.env.CROW_HOME = saved;
    resetLocalModelVouchCache();
  }
});

test("unverified-local is never CLOUD even when a caller injects a permissive isCloudTarget: the seam may only narrow", () => {
  const saved = process.env.CROW_HOME;
  const home = freshHome();
  process.env.CROW_HOME = home;
  try {
    resetLocalModelVouchCache();
    // A bot-written row on its own loopback listener, and a caller (the providers
    // tab, grantCloudConsent, the door's resolveCloudTarget) whose injected
    // predicate says "yes, that is a cloud target". The unverified-local exclusion
    // is applied REGARDLESS: no seam may re-admit a row the address class rules
    // out, or a key and the owner's content would ride a forward to that listener.
    const row = { id: "sneaky", baseUrl: "http://127.0.0.1:18098/v1", provider_type: "openai", apiKey: "sk-row", disabled: false };
    assert.equal(cloudDoorIneligibleReason(row, { isCloudTarget: () => true, allowInsecure: () => true }), "not_cloud");
    assert.equal(cloudDoorIneligibleReason(row, { isCloudTarget: () => true }), "not_cloud", "before the scheme/key rules too");
    // CONTROL: the same injected predicate does let a real public row through, so
    // the assertion above is about the unverified-local class and not about the
    // seam being ignored.
    assert.equal(cloudDoorIneligibleReason(
      { id: "cloudy", baseUrl: "https://api.example.test/v1", provider_type: "openai", apiKey: "sk-row", disabled: false },
      { isCloudTarget: () => true },
    ), null);
  } finally {
    if (saved === undefined) delete process.env.CROW_HOME;
    else process.env.CROW_HOME = saved;
    resetLocalModelVouchCache();
  }
});

test("the cached predicate is vouch-only: it never looks at a listener, so a listing cannot dial anything", async () => {
  const squat = await squatter();
  try {
    const deps = { crowHome: freshHome(), selfPid: process.pid };
    // The real listener in this process would be trusted by the async predicate's
    // "this very process" rule — but nothing vouches the port, so a listing still
    // says no.
    assert.deepEqual(isKnownLocalModelTargetCached(`http://127.0.0.1:${squat.port}/v1`, deps), { local: false, reason: "not-vouched" });
    assert.deepEqual(squat.hits, []);
  } finally {
    await squat.close();
  }
});

// ---------------------------------------------------------------------------
// (8) The pin CLI: add / --show / rm round trip, file mode 0600.
// ---------------------------------------------------------------------------

test("local-model-pin: add, --show and rm round-trip the file at mode 0600", async () => {
  const saved = { CROW_HOME: process.env.CROW_HOME };
  const home = freshHome();
  process.env.CROW_HOME = home;
  const run = async (argv) => {
    const out = [];
    const err = [];
    const code = await pinMain({ argv, stdout: { write: (s) => out.push(s) }, stderr: { write: (s) => err.push(s) } });
    return { code, out: out.join(""), err: err.join("") };
  };
  try {
    const added = await run(["add", "127.0.0.1:8004", "--exe", "/opt/llama.cpp/llama-server"]);
    assert.equal(added.code, 0, added.err);
    assert.match(added.out, /^127\.0\.0\.1:8004 \/opt\/llama\.cpp\/llama-server\n$/);
    const file = join(home, "secrets", PIN_FILE);
    assert.equal(statSync(file).mode & 0o777, 0o600, "the pin file is private");
    assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), [{ address: "127.0.0.1", port: 8004, exe: "/opt/llama.cpp/llama-server" }]);
    assert.deepEqual(readPins({ crowHome: home }), [{ address: "127.0.0.1", port: 8004, exe: "/opt/llama.cpp/llama-server" }]);

    // A second pin, and add for the same endpoint replaces (never duplicates).
    assert.equal((await run(["add", "100.64.20.5:8004", "--exe", "/opt/b/vllm"])).code, 0);
    assert.equal((await run(["add", "127.0.0.1:8004", "--exe", "/opt/llama.cpp/llama-server"])).code, 0);
    const shown = await run(["--show"]);
    assert.equal(shown.code, 0);
    assert.deepEqual(shown.out.trim().split("\n").sort(), ["100.64.20.5:8004 /opt/b/vllm", "127.0.0.1:8004 /opt/llama.cpp/llama-server"]);

    const removed = await run(["rm", "127.0.0.1:8004"]);
    assert.equal(removed.code, 0, removed.err);
    assert.equal((await run(["--show"])).out.trim(), "100.64.20.5:8004 /opt/b/vllm");
    assert.equal((await run(["rm", "127.0.0.1:8004"])).code, 1, "nothing matched");
    assert.equal((await run(["add", "127.0.0.1:8004", "--exe", "relative/path"])).code, 1, "an exe must be absolute");
  } finally {
    if (saved.CROW_HOME === undefined) delete process.env.CROW_HOME;
    else process.env.CROW_HOME = saved.CROW_HOME;
  }
});

test("local-model-pin: add-compose / rm-compose / --show round-trip a compose directory, realpath'd, file 0600", async () => {
  const saved = { CROW_HOME: process.env.CROW_HOME };
  const home = freshHome();
  process.env.CROW_HOME = home;
  const run = async (argv) => {
    const out = [];
    const err = [];
    const code = await pinMain({ argv, stdout: { write: (s) => out.push(s) }, stderr: { write: (s) => err.push(s) } });
    return { code, out: out.join(""), err: err.join("") };
  };
  try {
    const composeDir = join(home, "my-own-vllm");
    mkdirSync(composeDir, { recursive: true });
    // A trailing slash and a `..` segment both land on ONE stored entry: the realpath.
    const added = await run(["add-compose", `${composeDir}/`]);
    assert.equal(added.code, 0, added.err);
    assert.equal(added.out, `compose ${realpathSync(composeDir)}\n`);
    const file = join(home, "secrets", PIN_FILE);
    assert.equal(statSync(file).mode & 0o777, 0o600, "the pin file is private");
    assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), [{ composeDir: realpathSync(composeDir) }]);
    // `readComposePins` (the vouch's reader) sees it; `readPins` (the endpoint reader) does not.
    assert.deepEqual(readComposePins({ crowHome: home }), [realpathSync(composeDir)]);
    assert.deepEqual(readPins({ crowHome: home }), [], "a compose pin is not an endpoint pin");

    // An ENDPOINT pin and a COMPOSE pin coexist, and --show prints both.
    assert.equal((await run(["add", "127.0.0.1:8004", "--exe", "/opt/llama.cpp/llama-server"])).code, 0);
    assert.equal((await run(["add-compose", composeDir])).code, 0, "adding the same dir replaces, never duplicates");
    const shown = await run(["--show"]);
    assert.equal(shown.code, 0);
    assert.deepEqual(shown.out.trim().split("\n").sort(), [
      "127.0.0.1:8004 /opt/llama.cpp/llama-server",
      `compose ${realpathSync(composeDir)}`,
    ]);
    assert.equal(JSON.parse(readFileSync(file, "utf8")).length, 2, "one entry per pin");

    // Removing the compose pin leaves the endpoint pin alone.
    const removed = await run(["rm-compose", composeDir]);
    assert.equal(removed.code, 0, removed.err);
    assert.equal(removed.out, `unpinned compose ${realpathSync(composeDir)}\n`);
    assert.deepEqual(readComposePins({ crowHome: home }), []);
    assert.deepEqual(readPins({ crowHome: home }), [{ address: "127.0.0.1", port: 8004, exe: "/opt/llama.cpp/llama-server" }]);
    assert.equal((await run(["rm-compose", composeDir])).code, 1, "nothing matched");

    // Refusals: a relative path, a missing directory, a FILE. Nothing is written.
    const before = readFileSync(file, "utf8");
    assert.equal((await run(["add-compose", "relative/dir"])).code, 1);
    assert.equal((await run(["add-compose", join(home, "no-such-dir")])).code, 1);
    const notADir = join(home, "compose-file.yml");
    writeFileSync(notADir, "services: {}\n");
    assert.equal((await run(["add-compose", notADir])).code, 1);
    assert.equal(readFileSync(file, "utf8"), before, "a refused add-compose writes nothing");
  } finally {
    if (saved.CROW_HOME === undefined) delete process.env.CROW_HOME;
    else process.env.CROW_HOME = saved.CROW_HOME;
  }
});

test("local-model-pin: add-container / rm-container / --show round-trip a container name, alongside the other pin shapes", async () => {
  const saved = { CROW_HOME: process.env.CROW_HOME };
  const home = freshHome();
  process.env.CROW_HOME = home;
  const run = async (argv) => {
    const out = [];
    const err = [];
    const code = await pinMain({ argv, stdout: { write: (s) => out.push(s) }, stderr: { write: (s) => err.push(s) } });
    return { code, out: out.join(""), err: err.join("") };
  };
  try {
    const added = await run(["add-container", "flash-next-gufo"]);
    assert.equal(added.code, 0, added.err);
    assert.equal(added.out, "container flash-next-gufo\n");
    const file = join(home, "secrets", PIN_FILE);
    assert.equal(statSync(file).mode & 0o777, 0o600, "the pin file is private");
    assert.deepEqual(JSON.parse(readFileSync(file, "utf8")), [{ container: "flash-next-gufo" }]);
    assert.deepEqual(readContainerPins({ crowHome: home }), ["flash-next-gufo"]);
    // A container pin is neither an endpoint pin nor a compose pin.
    assert.deepEqual(readPins({ crowHome: home }), []);
    assert.deepEqual(readComposePins({ crowHome: home }), []);

    // Adding the same name replaces (never duplicates), and Docker's own spelling
    // (a leading "/") is the SAME container.
    assert.equal((await run(["add-container", "/flash-next-gufo"])).code, 0);
    assert.equal((await run(["add-container", "flash-next-gufo"])).code, 0);
    assert.equal(JSON.parse(readFileSync(file, "utf8")).length, 1);
    assert.deepEqual(readContainerPins({ crowHome: home }), ["flash-next-gufo"], "one entry, stored without the slash");

    // The three pin shapes coexist and --show prints each in its own form.
    assert.equal((await run(["add", "127.0.0.1:8030", "--exe", "/opt/llama.cpp/llama-server"])).code, 0);
    const shown = await run(["--show"]);
    assert.equal(shown.code, 0);
    assert.deepEqual(shown.out.trim().split("\n").sort(), [
      "127.0.0.1:8030 /opt/llama.cpp/llama-server",
      "container flash-next-gufo",
    ]);

    const removed = await run(["rm-container", "flash-next-gufo"]);
    assert.equal(removed.code, 0, removed.err);
    assert.equal(removed.out, "unpinned container flash-next-gufo\n");
    assert.equal((await run(["rm-container", "flash-next-gufo"])).code, 1, "nothing matched");
    assert.deepEqual(readContainerPins({ crowHome: home }), []);
    assert.deepEqual(readPins({ crowHome: home }), [{ address: "127.0.0.1", port: 8030, exe: "/opt/llama.cpp/llama-server" }], "the endpoint pin is untouched");

    // Refusals: an empty name, a name with a slash inside, a name with a space.
    const before = readFileSync(file, "utf8");
    for (const bad of ["", "/", "a/b", "a b"]) {
      assert.equal((await run(["add-container", bad])).code, 1, `add-container ${JSON.stringify(bad)} must be refused`);
    }
    assert.equal(readFileSync(file, "utf8"), before, "a refused add-container writes nothing");
  } finally {
    if (saved.CROW_HOME === undefined) delete process.env.CROW_HOME;
    else process.env.CROW_HOME = saved.CROW_HOME;
  }
});

// ---------------------------------------------------------------------------
// (9) THE JUDGED ADDRESS IS THE DIALED ADDRESS. A name stands for several
// addresses (`localhost` is 127.0.0.1 AND ::1), and the whole answer list is
// judged IN ORDER: the request must go to the FIRST answer the vouch accepted,
// and to nothing else. Judging the name's first answer and then letting the fetch
// resolve the name again is the window a bot with the same host network closes by
// binding the other address on the same port.
//
// Red-first, four shapes (one resolution each — the count assertions prove it):
//   - [::1, 127.0.0.1], a TRUSTED listener (this process, `selfOwnsListener`) on
//     ::1 and an UNTRUSTED one (a separate process of the same uid) on 127.0.0.1
//     -> ::1 is dialled, the bot's socket receives nothing;
//   - [127.0.0.1, ::1] the same way round -> the bot's answer is refused FOR THAT
//     ADDRESS only and ::1 (the next answer) is dialled;
//   - [::1, 127.0.0.1] with NOTHING on ::1 and the model on 127.0.0.1 -> the
//     server bound to 127.0.0.1 is reached (a dual-stack localhost that must keep
//     working: the Ollama bundle publishes 127.0.0.1:11434, faster-whisper and
//     Kokoro bind 127.0.0.1);
//   - [::1, 127.0.0.1] with nothing on ::1 and a BOT on 127.0.0.1 -> refused, and
//     neither answer is dialled.
// ---------------------------------------------------------------------------

/** A resolver whose answers are scripted per call; `calls` records every ask. */
function scriptedLookup(answers) {
  const calls = [];
  const fn = (host, options, cb) => {
    if (typeof options === "function") { cb = options; options = {}; }
    const list = answers[Math.min(calls.length, answers.length - 1)] || [];
    calls.push(host);
    if (!list.length) return cb(Object.assign(new Error("ENOTFOUND"), { code: "ENOTFOUND" }));
    const mapped = list.map((address) => ({ address, family: address.includes(":") ? 6 : 4 }));
    if (options && options.all) return cb(null, mapped);
    return cb(null, mapped[0].address, mapped[0].family);
  };
  fn.calls = calls;
  return fn;
}

/**
 * A TRUSTED listener on ONE loopback address (this process holds the socket, which
 * is the strongest vouch there is: `selfOwnsListener`), answering a chat completion
 * as SSE when the request streams and as JSON when it does not. `null` when this box
 * cannot bind that address, so the test can skip.
 */
async function trustedListenerAt(address = "::1") {
  const hits = [];
  const server = http.createServer((req, res) => {
    let raw = "";
    req.on("data", (c) => { raw += c.toString("utf8"); });
    req.on("end", () => {
      hits.push({ method: req.method, path: req.url, host: req.headers.host, authorization: req.headers.authorization || null });
      let body = {};
      try { body = JSON.parse(raw || "{}"); } catch { /* not json */ }
      if (body.stream) {
        res.writeHead(200, { "content-type": "text/event-stream" });
        res.write(`data: ${JSON.stringify({ choices: [{ index: 0, delta: { content: "answers" } }] })}\n\n`);
        return res.end("data: [DONE]\n\n");
      }
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ choices: [{ message: { content: "answers" } }] }));
    });
  });
  const listening = await new Promise((resolve) => {
    server.once("error", () => resolve(false));
    server.listen(0, address, () => resolve(true));
  });
  if (!listening) { try { server.close(); } catch { /* never bound */ } return null; }
  return {
    server,
    address,
    port: server.address().port,
    hits,
    close: () => new Promise((r) => { try { server.closeAllConnections?.(); } catch { /* gone */ } server.close(() => r()); }),
  };
}

/** The own-host vouch with this box's real /proc, a Docker publish vouching the
 * port (so the LISTENER half decides) and the caller's ONE dial address. */
const vouchAt = (home, port) => (url, dialAddresses) => isKnownLocalModelTarget(url, {
  crowHome: home, dockerEntries: [{ address: null, port }], dialAddresses,
});

const refusedByGuard = (e) => e.code === "SELF_TARGET_REFUSED" && e.message === SELF_REFUSED_MESSAGE;
const refusedByJob = (e) => e.code === "SELF_TARGET_REFUSED" && e.message === "completeText: refused, the model is on this gateway";

test("RED FIRST: a name whose FIRST answer is ::1 is dialed on ::1 — the door, completeText and an adapter never reach the bot's 127.0.0.1 socket on the same port", async (t) => {
  const trusted = await trustedListenerAt("::1");
  if (!trusted) return t.skip("this box has no [::1] loopback to listen on");
  const port = trusted.port;
  const bot = await spawnUntrustedListener({ address: "127.0.0.1", port });
  const home = freshHome();
  const lines = [];
  try {
    // 1. THE MODEL DOOR (a providers row naming a NAME).
    const lookup = scriptedLookup([["::1"], ["127.0.0.1"]]);
    const app = express();
    app.use(express.json());
    app.use(llmRouterRouter({
      acquireFn: async () => true,
      resolveKeyFn: async () => ({ baseUrl: `http://localhost:${port}/v1`, model: "m", apiKey: "row-key", host: "local" }),
      probeReadyFn: async () => true,
      loadProvidersFn: () => ({ providers: { dial: { baseUrl: `http://localhost:${port}/v1`, apiKey: "row-key", models: [{ id: "m" }], gpuPolicy: { door_forward: true } } } }),
      remoteAddressFn: (req) => req.socket?.remoteAddress || "",
      classifyDoorCallerFn: async () => ({ cls: "loopback" }),
      recordUsageFn: async () => {},
      logFn: (l) => lines.push(l),
      listenPortsFn: () => new Set([9]),
      lookupFn: lookup,
      knownLocalTargetFn: vouchAt(home, port),
    }));
    const server = http.createServer(app);
    const gwPort = await new Promise((r) => server.listen(0, "127.0.0.1", () => r(server.address().port)));
    try {
      const before = trusted.hits.length;
      const res = await fetch(`http://127.0.0.1:${gwPort}/llm/p/dial/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hi" }] }),
      });
      assert.equal(res.status, 200, await res.text());
      assert.equal(trusted.hits.length, before + 1, "the trusted [::1] listener answered");
      assert.equal(trusted.hits.at(-1).path, "/v1/chat/completions");
      assert.deepEqual(bot.hits, [], "the bot's 127.0.0.1 socket on the SAME port received nothing");
      assert.equal(lookup.calls.length, 1, "the name was resolved exactly once: the judged address is the dialed one");
    } finally {
      await new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
    }

    // 2. THE SCHEDULED-JOB PATH (`completeText`).
    const jobLookup = scriptedLookup([["::1"], ["127.0.0.1"]]);
    const beforeJob = trusted.hits.length;
    const text = await completeText({ model: "p/m", prompt: "hi" }, {
      resolveKeyFn: async () => ({ baseUrl: `http://localhost:${port}/v1`, model: "m", apiKey: "row-key", host: "local" }),
      reservationFn: () => null,
      recordUsageFn: async () => {},
      lookupFn: jobLookup,
      knownLocalTargetFn: vouchAt(home, port),
      logFn: (l) => lines.push(l),
    });
    assert.equal(text, "answers");
    assert.equal(trusted.hits.length, beforeJob + 1);
    assert.deepEqual(bot.hits, [], "nothing reached the bot on 127.0.0.1");
    assert.equal(jobLookup.calls.length, 1, "one resolution for the job too");

    // 3. THE PROVIDER ADAPTER (the kiosk/glasses/phone voice loop, dashboard chat,
    // and the memory server's embed/rerank all go through this guard).
    const adapterLookup = scriptedLookup([["::1"], ["127.0.0.1"]]);
    const adapter = createOpenAIAdapter({
      baseUrl: `http://localhost:${port}/v1`, apiKey: "row-key", model: "m",
      guard: { lookupFn: adapterLookup, knownLocalTargetFn: vouchAt(home, port), providerId: "dial", logFn: (l) => lines.push(l) },
    });
    const deltas = [];
    for await (const ev of adapter.chatStream([{ role: "user", content: "hi" }], [])) {
      if (ev.type === "content_delta") deltas.push(ev.text);
    }
    assert.deepEqual(deltas, ["answers"]);
    assert.equal(trusted.hits.at(-1).authorization, null, "an own-host target never carries the row's key");
    assert.deepEqual(bot.hits, [], "nothing reached the bot on 127.0.0.1");
    assert.equal(adapterLookup.calls.length, 1, "one resolution for the adapter too");
    assert.deepEqual(lines, [], "nothing was refused, so nothing was logged");
  } finally {
    await bot.close();
    await trusted.close();
  }
});

test("RED FIRST: answers are judged IN ORDER — a bot's 127.0.0.1 answer is refused for THAT address alone, and the trusted ::1 behind it is dialled", async (t) => {
  const trusted = await trustedListenerAt("::1");
  if (!trusted) return t.skip("this box has no [::1] loopback to listen on");
  const port = trusted.port;
  const bot = await spawnUntrustedListener({ address: "127.0.0.1", port });
  const home = freshHome();
  const lines = [];
  try {
    // The resolver answers BOTH addresses in ONE call — the bot's first, which is
    // the shape the old "dial the first answer" rule refused outright.
    // 1. THE DOOR.
    const lookup = scriptedLookup([["127.0.0.1", "::1"]]);
    const app = express();
    app.use(express.json());
    app.use(llmRouterRouter({
      acquireFn: async () => true,
      resolveKeyFn: async () => ({ baseUrl: `http://localhost:${port}/v1`, model: "m", apiKey: "row-key", host: "local" }),
      probeReadyFn: async () => true,
      loadProvidersFn: () => ({ providers: { dial: { baseUrl: `http://localhost:${port}/v1`, apiKey: "row-key", models: [{ id: "m" }], gpuPolicy: { door_forward: true } } } }),
      remoteAddressFn: (req) => req.socket?.remoteAddress || "",
      classifyDoorCallerFn: async () => ({ cls: "loopback" }),
      recordUsageFn: async () => {},
      logFn: (l) => lines.push(l),
      listenPortsFn: () => new Set([9]),
      lookupFn: lookup,
      knownLocalTargetFn: vouchAt(home, port),
    }));
    const server = http.createServer(app);
    const gwPort = await new Promise((r) => server.listen(0, "127.0.0.1", () => r(server.address().port)));
    try {
      const before = trusted.hits.length;
      const res = await fetch(`http://127.0.0.1:${gwPort}/llm/p/dial/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hi" }] }),
      });
      assert.equal(res.status, 200, await res.text());
      assert.equal(trusted.hits.length, before + 1, "the trusted ::1 listener answered");
      assert.deepEqual(bot.hits, [], "the bot's 127.0.0.1 socket — the FIRST answer — received nothing");
      assert.equal(lookup.calls.length, 1, "the name was resolved exactly once");
    } finally {
      await new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
    }

    // 2. `completeText` and 3. the ADAPTER pick the same answer.
    const jobLookup = scriptedLookup([["127.0.0.1", "::1"]]);
    const beforeJob = trusted.hits.length;
    const text = await completeText({ model: "p/m", prompt: "hi" }, {
      resolveKeyFn: async () => ({ baseUrl: `http://localhost:${port}/v1`, model: "m", apiKey: "row-key", host: "local" }),
      reservationFn: () => null,
      recordUsageFn: async () => {},
      lookupFn: jobLookup,
      knownLocalTargetFn: vouchAt(home, port),
      logFn: (l) => lines.push(l),
    });
    assert.equal(text, "answers");
    assert.equal(trusted.hits.length, beforeJob + 1);
    assert.equal(jobLookup.calls.length, 1);
    const adapterLookup = scriptedLookup([["127.0.0.1", "::1"]]);
    const adapter = createOpenAIAdapter({
      baseUrl: `http://localhost:${port}/v1`, apiKey: "row-key", model: "m",
      guard: { lookupFn: adapterLookup, knownLocalTargetFn: vouchAt(home, port), providerId: "dial", logFn: (l) => lines.push(l) },
    });
    const deltas = [];
    for await (const ev of adapter.chatStream([{ role: "user", content: "hi" }], [])) {
      if (ev.type === "content_delta") deltas.push(ev.text);
    }
    assert.deepEqual(deltas, ["answers"]);
    assert.equal(adapterLookup.calls.length, 1);
    assert.deepEqual(bot.hits, [], "the bot's socket received nothing");
    assert.deepEqual(lines, [], "one answer was refused FOR ITSELF, not the target: nothing was logged");
  } finally {
    await bot.close();
    await trusted.close();
  }
});

test("RED FIRST: a dual-stack localhost whose ::1 has NOTHING listening still reaches the server bound to 127.0.0.1 — one lookup, the ::1 answer refused for its own address", async () => {
  // The Ollama bundle publishes 127.0.0.1:11434, faster-whisper and Kokoro bind
  // 127.0.0.1, and some containers' /etc/hosts give `localhost` both addresses.
  // A resolver that lists ::1 first used to make every such server unreachable.
  const trusted = await trustedListenerAt("127.0.0.1");
  if (!trusted) return; // no 127.0.0.1 loopback: nothing to test
  const port = trusted.port;
  const home = freshHome();
  const lines = [];
  try {
    // 1. THE DOOR.
    const lookup = scriptedLookup([["::1", "127.0.0.1"]]);
    const app = express();
    app.use(express.json());
    app.use(llmRouterRouter({
      acquireFn: async () => true,
      resolveKeyFn: async () => ({ baseUrl: `http://localhost:${port}/v1`, model: "m", apiKey: "row-key", host: "local" }),
      probeReadyFn: async () => true,
      loadProvidersFn: () => ({ providers: { dial: { baseUrl: `http://localhost:${port}/v1`, apiKey: "row-key", models: [{ id: "m" }], gpuPolicy: { door_forward: true } } } }),
      remoteAddressFn: (req) => req.socket?.remoteAddress || "",
      classifyDoorCallerFn: async () => ({ cls: "loopback" }),
      recordUsageFn: async () => {},
      logFn: (l) => lines.push(l),
      listenPortsFn: () => new Set([9]),
      lookupFn: lookup,
      knownLocalTargetFn: vouchAt(home, port),
    }));
    const server = http.createServer(app);
    const gwPort = await new Promise((r) => server.listen(0, "127.0.0.1", () => r(server.address().port)));
    try {
      const before = trusted.hits.length;
      const res = await fetch(`http://127.0.0.1:${gwPort}/llm/p/dial/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hi" }] }),
      });
      assert.equal(res.status, 200, await res.text());
      assert.equal(trusted.hits.length, before + 1, "the model bound to 127.0.0.1 answered");
      assert.equal(lookup.calls.length, 1, "the name was resolved exactly once");
      assert.deepEqual(lines, []);
    } finally {
      await new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
    }

    // 2. `completeText` and 3. the ADAPTER.
    const jobLookup = scriptedLookup([["::1", "127.0.0.1"]]);
    const beforeJob = trusted.hits.length;
    assert.equal(await completeText({ model: "p/m", prompt: "hi" }, {
      resolveKeyFn: async () => ({ baseUrl: `http://localhost:${port}/v1`, model: "m", apiKey: "row-key", host: "local" }),
      reservationFn: () => null,
      recordUsageFn: async () => {},
      lookupFn: jobLookup,
      knownLocalTargetFn: vouchAt(home, port),
      logFn: (l) => lines.push(l),
    }), "answers");
    assert.equal(trusted.hits.length, beforeJob + 1);
    assert.equal(jobLookup.calls.length, 1);
    const adapterLookup = scriptedLookup([["::1", "127.0.0.1"]]);
    const adapter = createOpenAIAdapter({
      baseUrl: `http://localhost:${port}/v1`, apiKey: "row-key", model: "m",
      guard: { lookupFn: adapterLookup, knownLocalTargetFn: vouchAt(home, port), providerId: "dial", logFn: (l) => lines.push(l) },
    });
    const deltas = [];
    for await (const ev of adapter.chatStream([{ role: "user", content: "hi" }], [])) {
      if (ev.type === "content_delta") deltas.push(ev.text);
    }
    assert.deepEqual(deltas, ["answers"]);
    assert.equal(adapterLookup.calls.length, 1);
    assert.deepEqual(lines, []);
  } finally {
    await trusted.close();
  }
});

test("RED FIRST: BOTH answers untrusted is a refusal — nothing is dialled, and each path logs one line", async () => {
  // The bot holds 127.0.0.1:P and NOTHING listens on ::1:P, so neither answer
  // passes: the ordered pick must refuse, never fall back to "try the name again".
  const bot = await spawnUntrustedListener();
  const port = bot.port;
  const home = freshHome();
  const lines = [];
  try {
    const lookup = scriptedLookup([["::1", "127.0.0.1"]]);
    const app = express();
    app.use(express.json());
    app.use(llmRouterRouter({
      acquireFn: async () => true,
      resolveKeyFn: async () => ({ baseUrl: `http://localhost:${port}/v1`, model: "m", apiKey: "row-key", host: "local" }),
      probeReadyFn: async () => true,
      loadProvidersFn: () => ({ providers: { dial: { baseUrl: `http://localhost:${port}/v1`, apiKey: "row-key", models: [{ id: "m" }], gpuPolicy: { door_forward: true } } } }),
      remoteAddressFn: (req) => req.socket?.remoteAddress || "",
      classifyDoorCallerFn: async () => ({ cls: "loopback" }),
      recordUsageFn: async () => {},
      logFn: (l) => lines.push(l),
      listenPortsFn: () => new Set([9]),
      lookupFn: lookup,
      knownLocalTargetFn: vouchAt(home, port),
    }));
    const server = http.createServer(app);
    const gwPort = await new Promise((r) => server.listen(0, "127.0.0.1", () => r(server.address().port)));
    try {
      const res = await fetch(`http://127.0.0.1:${gwPort}/llm/p/dial/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ model: "m", messages: [{ role: "user", content: "hi" }] }),
      });
      const body = await res.json();
      assert.equal(res.status, 400, JSON.stringify(body));
      assert.equal(body?.error?.code, "NOT_FORWARDABLE");
      assert.equal(lookup.calls.length, 1);
    } finally {
      await new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
    }

    await assert.rejects(
      () => completeText({ model: "p/m", prompt: "hi" }, {
        resolveKeyFn: async () => ({ baseUrl: `http://localhost:${port}/v1`, model: "m", apiKey: "row-key", host: "local" }),
        reservationFn: () => null,
        recordUsageFn: async () => {},
        lookupFn: scriptedLookup([["::1", "127.0.0.1"]]),
        knownLocalTargetFn: vouchAt(home, port),
        logFn: (l) => lines.push(l),
      }),
      refusedByJob,
    );
    const adapter = createOpenAIAdapter({
      baseUrl: `http://localhost:${port}/v1`, apiKey: "row-key", model: "m",
      guard: { lookupFn: scriptedLookup([["::1", "127.0.0.1"]]), knownLocalTargetFn: vouchAt(home, port), providerId: "dial", logFn: (l) => lines.push(l) },
    });
    await assert.rejects(() => adapter.chatStream([{ role: "user", content: "hi" }], []).next(), refusedByGuard);

    assert.deepEqual(bot.hits, [], "the bot's socket received nothing");
    assert.equal(lines.length, 3, lines.join("\n"));
    // The refusal names the FIRST answer that failed (::1, no listener), which is
    // the one a reader has to look at first.
    const refusal = (providerId) => `[door] own-host target [::1]:${port} is not a known model server (provider ${providerId}, no-listener)`;
    assert.deepEqual(lines, [refusal("dial"), refusal("p"), refusal("dial")], "one line per refusal: the door, the job (named by its key) and the adapter");

    // CONTROL: the bot's listener is alive and reachable from this process.
    await fetch(`http://127.0.0.1:${port}/v1/chat/completions`, { method: "POST" }).catch(() => {});
    assert.deepEqual(bot.hits, ["POST /v1/chat/completions"], "the control request did reach it");
  } finally {
    await bot.close();
  }
});

// ---------------------------------------------------------------------------
// (10) H2 — THE LISTING REGRESSION. A loopback NAME stands for BOTH loopback
// addresses, and the sync listing predicate must judge it as those two, never as
// the string "localhost" (which matched no binding at all).
// ---------------------------------------------------------------------------

test("RED FIRST (H2): a `localhost:<port>` row lists when the server is bound to 127.0.0.1 (Ollama 11434, a Kokoro on 8880) or to ::1", () => {
  const home = freshHome();
  const deps = { crowHome: home, dockerEntries: [{ address: "127.0.0.1", port: 11434 }] };
  // The Ollama bundle publishes 127.0.0.1:11434; a Kokoro voices server binds
  // 127.0.0.1:8880. A row naming `localhost` used to read "unverified-local" for
  // exactly these two, so the Models page and pi's models.json lost them.
  assert.deepEqual(isKnownLocalModelTargetCached("http://localhost:11434/v1", deps), { local: true, reason: "vouched" });
  assert.equal(isUnverifiedLocalTarget("http://localhost:11434/v1", deps), false);
  assert.deepEqual(isKnownLocalModelTargetCached("http://localhost:8880/v1", {
    crowHome: home, dockerEntries: [{ address: "127.0.0.1", port: 8880 }],
  }), { local: true, reason: "vouched" });
  // A vouch on ::1 lists too — the name is the PAIR, not the first address.
  assert.deepEqual(isKnownLocalModelTargetCached("http://localhost:18098/v1", {
    crowHome: home, dockerEntries: [{ address: "::1", port: 18098 }],
  }), { local: true, reason: "vouched" });
  // CONTROL: an unvouched port on the very same name is still unverified, so the
  // assertion above is about the name mapping and not about "localhost is fine".
  assert.deepEqual(isKnownLocalModelTargetCached("http://localhost:18097/v1", deps), { local: false, reason: "not-vouched" });
  // ... and a wildcard publish still covers it.
  assert.deepEqual(isKnownLocalModelTargetCached("http://localhost:18096/v1", {
    crowHome: home, dockerEntries: [{ address: null, port: 18096 }],
  }), { local: true, reason: "vouched" });
});

// ---------------------------------------------------------------------------
// (11) H3 — the SYNC listing predicate primes the Docker half itself. The
// pi-bots spawner and the memory MCP server never call `primeLocalModelVouch`, so
// they started with an empty cache and every Docker-only model read
// "unverified-local" there forever.
// ---------------------------------------------------------------------------

test("RED FIRST (H3): a FRESH process with an empty Docker cache primes it in the background and then lists a docker-vouched model", async () => {
  const home = freshHome();
  const aiDir = join(home, "bundles", "vllm-custom");
  mkdirSync(aiDir, { recursive: true });
  writeFileSync(join(aiDir, "manifest.json"), JSON.stringify({ id: "vllm-custom", category: "ai" }));
  const port = 18061;
  const bindings = { [`${port}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: String(port) }] };
  const dockerRunner = fakeDocker({ bindings, labels: { [COMPOSE_WORKING_DIR_LABEL]: aiDir } });
  const deps = { crowHome: home, dockerRunner, ownAddrs: new Set(["127.0.0.1"]) };
  resetLocalModelVouchCache();

  // FIRST call: the cache is empty and the listing path may not spawn a process
  // itself, so the answer is still "not-vouched" — and a background read starts.
  assert.deepEqual(isKnownLocalModelTargetCached(`http://127.0.0.1:${port}/v1`, deps), { local: false, reason: "not-vouched" });
  await whenLocalModelVouchReady();
  assert.ok(dockerRunner.calls.length > 0, "the first sync check primed the Docker snapshot");

  // SECOND call: the primed snapshot vouches the port, with no further spawn.
  const calls = dockerRunner.calls.length;
  assert.deepEqual(isKnownLocalModelTargetCached(`http://127.0.0.1:${port}/v1`, deps), { local: true, reason: "vouched" });
  assert.equal(dockerRunner.calls.length, calls, "a fresh snapshot is not re-read");
  // ... and it is what the LISTINGS use, so the row is offered as a local model.
  assert.equal(isUnverifiedLocalTarget(`http://127.0.0.1:${port}/v1`, deps), false);
});

test("RED FIRST (H3/H4): a HUNG docker is not re-run on every forward — the last good snapshot is served while a failed read backs off", async () => {
  const home = freshHome();
  const aiDir = join(home, "bundles", "localai");
  mkdirSync(aiDir, { recursive: true });
  writeFileSync(join(aiDir, "manifest.json"), JSON.stringify({ id: "localai", category: "ai" }));
  const port = 18062;
  const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, uid: 0, inode: 401 })] });
  const bindings = { [`${port}/tcp`]: [{ HostIp: "127.0.0.1", HostPort: String(port) }] };
  let mode = "ok";
  let dockerCalls = 0;
  const good = fakeDocker({ bindings, labels: { [COMPOSE_WORKING_DIR_LABEL]: aiDir } });
  const dockerRunner = async (cmd, args) => { dockerCalls += 1; if (mode === "down") throw new Error("docker: hung"); return good(cmd, args); };
  let clock = 5_000_000;
  const deps = { crowHome: home, procRoot, uid: GW_UID, selfPid: -1, dockerRunner, now: () => clock, ownAddrs: new Set(["127.0.0.1"]) };
  const url = `http://127.0.0.1:${port}/v1`;
  resetLocalModelVouchCache();
  assert.deepEqual(await isKnownLocalModelTarget(url, deps), { local: true, reason: "vouched", address: "127.0.0.1" });

  // Docker goes away. The last GOOD snapshot still vouches the port, and the
  // failed re-reads are spaced out instead of one `docker` spawn per forward.
  mode = "down";
  clock += DOCKER_REFRESH_MIN_MS + 1;
  assert.deepEqual(await isKnownLocalModelTarget(url, deps), { local: true, reason: "vouched", address: "127.0.0.1" });
  const afterFailure = dockerCalls;
  for (let i = 0; i < 20; i++) {
    clock += 100;
    assert.deepEqual(await isKnownLocalModelTarget(url, { ...deps, now: () => clock }), { local: true, reason: "vouched", address: "127.0.0.1" });
  }
  // The LISTING path (sync, background priming) backs off the same way.
  for (let i = 0; i < 20; i++) isKnownLocalModelTargetCached(url, deps);
  await whenLocalModelVouchReady();
  assert.ok(dockerCalls - afterFailure <= 2, `a hung docker was re-run ${dockerCalls - afterFailure} times in a backoff window`);
});

// ---------------------------------------------------------------------------
// (12) H4 — the listener judgement is CANDIDATE-ONLY: it never readdirs every
// process's fd table (that was ~40-50 ms synchronously per forward).
// ---------------------------------------------------------------------------

test("RED FIRST (H4): the listener judgement reads only CANDIDATE fd tables, never every process's", async () => {
  const port = 18063;
  const SELF = 5000;
  const procRoot = fakeProc({
    tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 501 })],
    procs: [{ pid: 5100, inodes: [501] }],
  });
  // 20 unrelated same-uid processes, each with a fat fd table (the shape that made
  // the old full scan expensive).
  for (let i = 0; i < 20; i++) {
    const dir = join(procRoot, String(6000 + i), "fd");
    mkdirSync(dir, { recursive: true });
    for (let f = 0; f < 40; f++) symlinkSync(`socket:[${9000 + f}]`, join(dir, `fd${f}`));
  }
  const fdReads = [];
  // The listener judgement asks for fd tables ASYNCHRONOUSLY (N3), so BOTH the
  // promise entry point and the sync one record: the point of this test is that no
  // UNRELATED process's fd table is touched, whichever API asks.
  const fs = {
    ...nodeFs,
    promises: {
      ...nodeFs.promises,
      readdir: (p, o) => {
        const s = String(p);
        if (s.endsWith("/fd")) fdReads.push(s);
        return nodeFs.promises.readdir(p, o);
      },
    },
    readdirSync: (p, o) => {
      const s = String(p);
      if (s.endsWith("/fd")) fdReads.push(s);
      return nodeFs.readdirSync(p, o);
    },
  };
  const deps = { crowHome: freshHome(), procRoot, uid: GW_UID, selfPid: SELF, fs, dockerEntries: [{ address: "127.0.0.1", port }] };
  assert.deepEqual(await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, deps), { local: false, reason: "listener-not-trusted", address: "127.0.0.1" });
  const scanned = fdReads.filter((p) => /\/(6\d{3})\/fd$/.test(p));
  assert.deepEqual(scanned, [], "no unrelated process's fd table is read");
  assert.ok(fdReads.length <= 3, `fd tables read: ${fdReads.join(", ")}`);

  // CONTROL: the same listener, named by a LIVE native handle, is trusted — and
  // still without touching any other process's fds.
  fdReads.length = 0;
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...deps, nativeHandles: [{ pid: 5100, port }] }),
    { local: true, reason: "vouched", address: "127.0.0.1" },
  );
  assert.deepEqual(fdReads.filter((p) => /\/(6\d{3})\/fd$/.test(p)), []);
});

// ---------------------------------------------------------------------------
// (12b) L1 — ONE TABLE READ PER PASS. The vouch used to read and fully parse
// /proc/net/tcp and tcp6 TWICE per forward (the self-ownership check, then the
// listener verdict), and again for every candidate address of a name. That parse
// was most of the 21-26 ms a loopback forward paid, so a busy box's thousands of
// unrelated rows are filtered on the RAW LINE now, and one pass reads each table
// once. Nothing about the verdict changes: the read is shared INSIDE one pass only,
// and every check still judges the rows it judged before.
// ---------------------------------------------------------------------------

test("RED FIRST (L1): one vouch pass reads each /proc/net table ONCE, however many addresses are judged", async () => {
  const port = 18066;
  const SELF = 5200;
  const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, inode: 611 })], procs: [{ pid: SELF, inodes: [611] }] });
  // A busy box: 2000 unrelated rows per table, which the port pre-filter keeps out
  // of the parse entirely.
  const noise = Array.from({ length: 2000 }, (_, i) => procRow({ local: v4Hex(`127.0.0.${(i % 250) + 1}`), port: 20000 + i, inode: 20000 + i }));
  appendFileSync(join(procRoot, "net", "tcp"), `${noise.join("\n")}\n`);
  const noise6 = Array.from({ length: 2000 }, (_, i) => procRow({ local: "00000000000000000000000001000000", port: 24000 + i, inode: 24000 + i }));
  appendFileSync(join(procRoot, "net", "tcp6"), `${noise6.join("\n")}\n`);

  const reads = [];
  const fs = {
    ...nodeFs,
    promises: {
      ...nodeFs.promises,
      readFile: (p, o) => {
        const s = String(p);
        if (/net\/tcp6?$/.test(s)) reads.push(s.slice(s.lastIndexOf("/") + 1));
        return nodeFs.promises.readFile(p, o);
      },
    },
  };
  const deps = { crowHome: freshHome(), procRoot, uid: GW_UID, selfPid: SELF, fs, dockerEntries: [{ address: "127.0.0.1", port }] };
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, deps),
    { local: true, reason: "vouched", address: "127.0.0.1" },
  );
  assert.deepEqual(reads.sort(), ["tcp", "tcp6"], `one read per table for the whole pass, got: ${reads.join(", ")}`);

  // SEVERAL candidate addresses (a dual-stack name) are judged from the SAME read.
  reads.length = 0;
  const multi = await isKnownLocalModelTarget(`http://localhost:${port}/v1`, {
    ...deps,
    lookupFn: (_h, _o, cb) => cb(null, [{ address: "127.0.0.1", family: 4 }, { address: "::1", family: 6 }]),
  });
  assert.equal(multi.local, true, JSON.stringify(multi));
  assert.deepEqual(reads.sort(), ["tcp", "tcp6"], `two candidates, still one read per table, got: ${reads.join(", ")}`);
});

test("RED FIRST (L1): the table pre-filter is EXACT — a table written in lower-case hex still finds its row", async () => {
  const port = 18067;
  const SELF = 5201;
  const portUpper = port.toString(16).toUpperCase().padStart(4, "0");
  const portLower = port.toString(16).toLowerCase().padStart(4, "0");
  // The kernel writes upper case; a fixture may write either. The filter compares the
  // four hex digits case-insensitively, so a lower-case row can never be dropped —
  // and dropping a row is the one thing a pre-filter must never do.
  const row = procRow({ local: v4Hex("127.0.0.1").toLowerCase(), port, inode: 621 })
    .replace(`:${portUpper}`, `:${portLower}`);
  const procRoot = fakeProc({ tcp: [row], procs: [{ pid: SELF, inodes: [621] }] });
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { crowHome: freshHome(), procRoot, uid: GW_UID, selfPid: SELF, dockerEntries: [{ address: "127.0.0.1", port }] }),
    { local: true, reason: "vouched", address: "127.0.0.1" },
  );
});

// ---------------------------------------------------------------------------
// (13) H5 — the native reservation vouches only for a REAL pid of OUR uid: the
// state file lives under the data dir, which a contained bot can write.
// ---------------------------------------------------------------------------

test("RED FIRST (H5): a native reservation with pid 0 or 1, or a pid another uid owns, vouches nothing", async () => {
  const port = 18064;
  const reserve = (home, pid) => {
    mkdirSync(join(home, "models"), { recursive: true });
    writeFileSync(join(home, "models", "state.json"), JSON.stringify({ reservations: { "crow-chat": { port, owner: { pid } } } }));
  };
  // A listener another uid holds (docker-proxy): the LISTENER half passes, so the
  // ANSWER is the vouch half's, which is exactly the reservation.
  const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, uid: 0, inode: 601 })] });
  const base = { procRoot, uid: GW_UID, selfPid: -1, dockerEntries: [], isProcessAlive: () => true };
  for (const pid of [0, 1, -5]) {
    const home = freshHome();
    reserve(home, pid);
    resetLocalModelVouchCache();
    assert.deepEqual(
      await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...base, crowHome: home }),
      { local: false, reason: "not-vouched", address: "127.0.0.1" },
      `pid ${pid} must never vouch a port`,
    );
  }

  // A pid another uid owns: the reservation names a process this instance did not
  // start. (The fake /proc's pid dir belongs to the test's uid, so the uid the
  // module reads is the seam the test states.)
  const foreign = freshHome();
  reserve(foreign, 5300);
  const pids = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, uid: 0, inode: 602 })], procs: [{ pid: 5300, inodes: [999] }] });
  const foreignFs = {
    ...nodeFs,
    statSync: (p, o) => {
      const st = nodeFs.statSync(p, o);
      if (String(p) === join(pids, "5300")) return Object.assign(Object.create(Object.getPrototypeOf(st)), st, { uid: GW_UID + 1 });
      return st;
    },
  };
  resetLocalModelVouchCache();
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...base, crowHome: foreign, procRoot: pids, fs: foreignFs }),
    { local: false, reason: "not-vouched", address: "127.0.0.1" },
    "another uid's pid is not this instance's model server",
  );

  // CONTROL: the same reservation naming OUR uid's live pid vouches the port.
  const ours = freshHome();
  reserve(ours, 5301);
  const ourProc = fakeProc({ tcp: [procRow({ local: v4Hex("127.0.0.1"), port, uid: 0, inode: 603 })], procs: [{ pid: 5301, inodes: [999] }] });
  resetLocalModelVouchCache();
  assert.deepEqual(
    await isKnownLocalModelTarget(`http://127.0.0.1:${port}/v1`, { ...base, crowHome: ours, procRoot: ourProc }),
    { local: true, reason: "vouched", address: "127.0.0.1" },
  );
});

// ---------------------------------------------------------------------------
// (14) G-ITEM — a container pinned BY NAME. A systemd unit's plain
// `docker run --name flash-next-gufo -p 0.0.0.0:8030:8000` carries no compose
// label, so after S3 nothing vouched it and the model became unreachable.
// ---------------------------------------------------------------------------

test("RED FIRST (G-item): an unlabelled container vouches nothing; pinned by NAME it vouches its 0.0.0.0:P publish for an own LAN address; unpinned again it does not", async () => {
  const port = 8030;
  const home = freshHome();
  const ownAddrs = new Set(["127.0.0.1", "100.64.20.5"]);
  // docker-proxy (uid 0) holds the listener, so the LISTENER half passes and the
  // vouch half decides.
  const procRoot = fakeProc({ tcp: [procRow({ local: v4Hex("100.64.20.5"), port, uid: 0, inode: 701 })] });
  const bindings = { [`${port}/tcp`]: [{ HostIp: "0.0.0.0", HostPort: String(port) }] };
  const dockerRunner = fakeDocker({ bindings, labels: null, name: "/flash-next-gufo" });
  const pin = (pins) => {
    mkdirSync(join(home, "secrets"), { recursive: true, mode: 0o700 });
    writeFileSync(join(home, "secrets", PIN_FILE), JSON.stringify(pins), { mode: 0o600 });
    resetLocalModelVouchCache();
  };
  const judge = () => isKnownLocalModelTarget(`http://100.64.20.5:${port}/v1`, {
    crowHome: home, ownAddrs, procRoot, uid: GW_UID, selfPid: -1, dockerRunner,
  });

  pin([]);
  assert.deepEqual(await judge(), { local: false, reason: "not-vouched", address: "100.64.20.5" }, "an unlabelled, unpinned container vouches nothing (S3)");

  pin([{ container: "flash-next-gufo" }]);
  assert.deepEqual(readContainerPins({ crowHome: home }), ["flash-next-gufo"]);
  assert.deepEqual(await judge(), { local: true, reason: "vouched", address: "100.64.20.5" }, "the 0.0.0.0 publish of a pinned container covers an own LAN address");

  // A pin names ONE container, exactly: another name (or a prefix) vouches nothing.
  pin([{ container: "flash" }]);
  assert.deepEqual(await judge(), { local: false, reason: "not-vouched", address: "100.64.20.5" });
  pin([{ container: "flash-next-gufo-2" }]);
  assert.deepEqual(await judge(), { local: false, reason: "not-vouched", address: "100.64.20.5" });

  // Unpinned again: not vouched.
  pin([]);
  assert.deepEqual(await judge(), { local: false, reason: "not-vouched", address: "100.64.20.5" });

  // ... and a compose-dir pin still works the other way round (the pin file holds
  // three entry shapes at once and each reader sees only its own).
  pin([{ container: "other", }, { composeDir: home }]);
  assert.deepEqual(readContainerPins({ crowHome: home }), ["other"]);
  assert.deepEqual(readComposePins({ crowHome: home }), [realpathSync(home)]);
});

// ---------------------------------------------------------------------------
// (15) H1 — THE ACCEPTED CONNECTION. The listener half can be perfect and the
// connection still land on a same-uid bot's SO_REUSEPORT socket; so the forward
// verifies the connection it got, on the real kernel, before writing a byte.
// ---------------------------------------------------------------------------

test("RED FIRST (H1): an accepted connection held by this process is trusted; one nobody trusted holds is connection-not-trusted", async () => {
  const server = http.createServer((_req, res) => res.end("ok"));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  const net = await import("node:net");
  const socket = net.connect({ host: "127.0.0.1", port });
  try {
    await new Promise((r, j) => { socket.once("connect", r); socket.once("error", j); });
    const trusted = await verifyAcceptedConnection({
      address: "127.0.0.1", port, clientAddress: socket.localAddress, clientPort: socket.localPort, timeoutMs: 2_000,
    });
    assert.deepEqual(trusted, { trusted: true, reason: "vouched" });
  } finally {
    socket.destroy();
    await new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
  }
  // A connection row that does not exist (a tuple nothing holds) is refused, never
  // assumed: the four-tuple match is the whole point.
  const stranger = await verifyAcceptedConnection({
    address: "127.0.0.1", port, clientAddress: "127.0.0.1", clientPort: 1, timeoutMs: 0,
  });
  assert.deepEqual(stranger, { trusted: false, reason: "connection-not-trusted" });
});