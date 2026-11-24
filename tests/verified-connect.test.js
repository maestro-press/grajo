/**
 * THE VERIFIED CONNECTION (H1), at the transport module's own boundary — the
 * shape `tests/local-model-listener-vouch.test.js` drives through real forwards
 * (a same-uid SO_REUSEPORT bot on the model's port) and
 * `tests/local-model-allowlist.test.js` pins at the predicate level.
 *
 * What is proved here:
 *   - a socket THIS process opened to its own listener is accepted (the accepted
 *     row's inode is held by this process);
 *   - one whose four-tuple nobody holds is refused as `connection-not-trusted`
 *     rather than assumed good;
 *   - a connection with NO server-side row in this network namespace — the shape a
 *     Docker publish produces, because the kernel DNATs host-originated traffic to
 *     the host's own address straight into the container's namespace — is trusted as
 *     `nat-to-container`, but ONLY for a port a docker binding vouches and only when
 *     no same-uid listener exists there (J1);
 *   - a connect that never completed is an UPSTREAM failure (J2), never the refusal a
 *     positively untrusted owner produces;
 *   - `safeRequest(… verifiedConnection)` never pools: every request is its own
 *     connection and says `Connection: close`, which is what stops one stolen
 *     connection from serving many requests.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import http from "node:http";
import { mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { normalizeAddress, parseProcNet, parseProcNetConnections, verifyAcceptedConnection } from "../servers/gateway/models/local-model-servers.js";
import { openVerifiedSocket, CONNECTION_NOT_TRUSTED } from "../servers/gateway/models/verified-connect.js";
import { safeRequest } from "../servers/gateway/models/safe-upstream.js";
import { spawnHalfCloseListener } from "./fixtures/half-close-listener.mjs";

// ---------------------------------------------------------------------------
// mocked /proc fixtures: a Docker publish's connection shape (J1)
// ---------------------------------------------------------------------------

/** The uid the gateway (and every bot in a contained tier) runs as, in these
 * fixtures. Rows with uid 0 are docker-proxy and other services. */
const GW_UID = 1000;
const TCP_HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode";
/** An IPv4 address in the kernel's spelling: one 32-bit word, little-endian. */
const v4Hex = (dotted) => dotted.split(".").reverse().map((n) => Number(n).toString(16).padStart(2, "0")).join("").toUpperCase();
/** One `/proc/net/tcp` row. `state` 0A is a listener, 01 an established socket. */
function procRow({ local, port, state = "0A", uid = 0, inode = 1, remote = "00000000", remotePort = 0 }) {
  const p = Number(port).toString(16).toUpperCase().padStart(4, "0");
  const rp = Number(remotePort).toString(16).toUpperCase().padStart(4, "0");
  return `   0: ${local}:${p} ${remote}:${rp} ${state} 00000000:00000000 00:00000000 00000000 ${String(uid).padStart(5)}        0 ${inode} 1 0000000000000000 100 0 0 10 0`;
}

/**
 * THE "HOST NAT" SHAPE, as a fixture — the case a real host produced and this file
 * used to get wrong: a container publishes `address:port`, docker-proxy holds a
 * LISTEN row on it as ANOTHER uid, and the connection the gateway opened has NO
 * server-side row in this namespace at all (Docker's OUTPUT DNAT took it into the
 * container's netns). Only our client row would exist, which this fixture leaves
 * out: nothing in the module reads the client row.
 *
 * `sameUidListener` adds a listener a BOT could have opened on the same
 * address:port, `vouched: false` states a port no docker binding publishes, and
 * `running` is the vouching container's state (a STOPPED container keeps its
 * published bindings and has no NAT rules — see `noLocalRowIsDockerNat`).
 */
function hostNatFixture({ port, address = "100.64.20.5", sameUidListener = false, vouched = true, running = true, gwUid = GW_UID } = {}) {
  const rows = [procRow({ local: v4Hex(address), port, uid: 0, inode: 901 })];
  if (sameUidListener) rows.push(procRow({ local: v4Hex(address), port, uid: gwUid, inode: 902 }));
  return {
    deps: { procNetTcp: `${TCP_HEADER}\n${rows.join("\n")}\n`, procNetTcp6: `${TCP_HEADER}\n`, uid: gwUid, selfPid: -1 },
    snapshot: {
      docker: vouched ? [{ address: "0.0.0.0", port, composeDir: "/srv/bundles/ollama", container: "ollama", running }] : [],
      bundles: [], native: [], pins: [], selfPorts: [], crowHome: null,
    },
  };
}

/** Real /proc rows, for the tests that need a real kernel state (K1). */
function realProcRows() {
  const read = (p) => { try { return readFileSync(p, "utf8"); } catch { return ""; } };
  return [...parseProcNetConnections(read("/proc/net/tcp"), 4), ...parseProcNetConnections(read("/proc/net/tcp6"), 6)];
}

/** Wait (bounded) for the SERVER end of our connection to reach one of `states`.
 * That is the moment the kernel is in the state under test — no sleeps and no
 * guessing about FIN timing. */
async function waitForServerRow({ port, clientPort, states, ms = 5_000 }) {
  const deadline = Date.now() + ms;
  for (;;) {
    const row = realProcRows().find((r) => r.port === port && r.remotePort === Number(clientPort) && states.includes(r.state));
    if (row) return row;
    if (Date.now() >= deadline) throw new Error(`no server-side row for :${port} <- :${clientPort} in states ${states.join("/")}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

test("an accepted connection this process holds is trusted; a four-tuple nobody holds is refused", async () => {
  const server = http.createServer((_req, res) => res.end("ok"));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  const net = await import("node:net");
  const socket = net.connect({ host: "127.0.0.1", port });
  try {
    await new Promise((r, j) => { socket.once("connect", r); socket.once("error", j); });
    assert.deepEqual(
      await verifyAcceptedConnection({ address: "127.0.0.1", port, clientAddress: socket.localAddress, clientPort: socket.localPort, timeoutMs: 2_000 }),
      { trusted: true, reason: "vouched" },
    );
  } finally {
    socket.destroy();
    await new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
  }
  assert.deepEqual(
    await verifyAcceptedConnection({ address: "127.0.0.1", port, clientAddress: "127.0.0.1", clientPort: 1, timeoutMs: 0 }),
    { trusted: false, reason: "connection-not-trusted" },
  );
});

test("openVerifiedSocket hands back a verified socket, and safeRequest sends a request on it unpooled", async () => {
  const seen = [];
  let connections = 0;
  const server = http.createServer((req, res) => {
    seen.push({ method: req.method, path: req.url, connection: req.headers.connection || null });
    res.writeHead(200, { "content-type": "application/json" });
    res.end(JSON.stringify({ ok: true }));
  });
  server.on("connection", () => { connections += 1; });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  try {
    const socket = await openVerifiedSocket({ address: "127.0.0.1", port, timeoutMs: 2_000 });
    assert.equal(socket.remotePort, port);
    socket.destroy();

    for (let i = 0; i < 3; i++) {
      const res = await safeRequest(`http://127.0.0.1:${port}/v1/chat/completions`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: "{}",
        timeoutMs: 3_000,
        idleTimeoutMs: 0,
        allowAddressFn: () => true,
        verifiedConnection: { address: "127.0.0.1" },
      });
      assert.equal(res.status, 200);
      res.stream.destroy();
    }
    assert.equal(connections, 4, "one connection for the probe socket and one per forward: nothing is pooled");
    assert.deepEqual([...new Set(seen.map((s) => s.connection))], ["close"]);
    assert.deepEqual(seen.map((s) => s.path), Array(3).fill("/v1/chat/completions"));
  } finally {
    await new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
  }
});

test("a verified connection to a port nothing listens on fails with the socket's own error, never a false success", async () => {
  const http2 = await import("node:http");
  const probe = http2.createServer((_req, res) => res.end("x"));
  await new Promise((r) => probe.listen(0, "127.0.0.1", r));
  const port = probe.address().port;
  await new Promise((r) => { probe.closeAllConnections?.(); probe.close(() => r()); });
  await assert.rejects(
    () => openVerifiedSocket({ address: "127.0.0.1", port, timeoutMs: 1_000 }),
    // J2: a REFUSED connect is the provider's problem — an upstream error the
    // caller's existing unreachable path reports, never the refusal a squat gets.
    (e) => e.code === "ECONNREFUSED" && e.code !== CONNECTION_NOT_TRUSTED && e.reason === undefined,
  );
});

// ---------------------------------------------------------------------------
// (J1) THE HOST-NAT SHAPE: the connection the gateway opened has no server-side
// row in THIS network namespace, because Docker's OUTPUT DNAT delivered it into a
// container's namespace. Verified on a real host: the module used to poll to its
// deadline and refuse a perfectly good model server.
// ---------------------------------------------------------------------------

test("RED FIRST (J1): a vouched published port with NO local server row is trusted as nat-to-container", async () => {
  const port = 18081;
  const { deps, snapshot } = hostNatFixture({ port });
  assert.deepEqual(
    await verifyAcceptedConnection({
      address: "100.64.20.5", port, clientAddress: "100.64.20.5", clientPort: 51234,
      snapshot, deps, timeoutMs: 1_000, pollMs: 5,
    }),
    { trusted: true, reason: "nat-to-container" },
  );
});

test("RED FIRST (J1): the same shape with a SAME-UID listener present is never the nat branch — the inode rule owns it and refuses", async () => {
  const port = 18082;
  const { deps, snapshot } = hostNatFixture({ port, sameUidListener: true });
  assert.deepEqual(
    await verifyAcceptedConnection({
      address: "100.64.20.5", port, clientAddress: "100.64.20.5", clientPort: 51234,
      snapshot, deps, timeoutMs: 120, pollMs: 5,
    }),
    { trusted: false, reason: "connection-not-trusted" },
    "a bot's own listener on the port means the ordinary inode verification applies — and finds nothing to trust",
  );
});

test("RED FIRST (J1): no local server row and NO docker vouch is refused — the nat branch needs the publish", async () => {
  const port = 18083;
  const { deps, snapshot } = hostNatFixture({ port, vouched: false });
  assert.deepEqual(
    await verifyAcceptedConnection({
      address: "100.64.20.5", port, clientAddress: "100.64.20.5", clientPort: 51234,
      snapshot, deps, timeoutMs: 120, pollMs: 5,
    }),
    { trusted: false, reason: "connection-not-trusted" },
  );
});

// ---------------------------------------------------------------------------
// (N1) SYN_RECV IS PENDING, NOT A REFUSAL.
//
// Under load our connect() completes (the client sees ESTABLISHED) before the
// server has processed the final ACK, so the server-side row sits in 03 for a
// moment. That row used to be an immediate refusal — a healthy model server refused
// exactly while it was busy. It is now WAITED ON within the accept budget, and a
// row that never leaves it is still refused (a wait is never a trust).
// ---------------------------------------------------------------------------

/** A fake /proc root with ONE candidate pid's fd table holding `socket:[inode]`. */
function candidateProcRoot(pid, inode) {
  const root = mkdtempSync(join(tmpdir(), "crow-syn-recv-proc-"));
  mkdirSync(join(root, String(pid), "fd"), { recursive: true });
  symlinkSync(`socket:[${inode}]`, join(root, String(pid), "fd", "7.sock"));
  return root;
}

test("RED FIRST (N1): a same-uid server row in SYN_RECV is PENDING — trusted once it is accepted within the budget, refused when it never is", async () => {
  const port = 18091;
  const clientPort = 51241;
  const holder = 7400;
  const inode = 777;
  const procRoot = candidateProcRoot(holder, inode);
  const synRecv = procRow({
    local: v4Hex("127.0.0.1"), port, state: "03", uid: GW_UID, inode: 0,
    remote: v4Hex("127.0.0.1"), remotePort: clientPort,
  });
  const accepted = procRow({
    local: v4Hex("127.0.0.1"), port, state: "01", uid: GW_UID, inode,
    remote: v4Hex("127.0.0.1"), remotePort: clientPort,
  });
  try {
    // THE LOADED BOX: two looks find the row still in SYN_RECV, the third finds the
    // socket an application holds. Nothing else about the row changes.
    let reads = 0;
    const deps = {
      procRoot,
      procNetTcp: () => (++reads < 3 ? `${TCP_HEADER}\n${synRecv}\n` : `${TCP_HEADER}\n${accepted}\n`),
      procNetTcp6: `${TCP_HEADER}\n`,
      uid: GW_UID, selfPid: -1, nativeHandles: [{ pid: holder, port }], crowHome: null,
    };
    assert.deepEqual(
      await verifyAcceptedConnection({
        address: "127.0.0.1", port, clientAddress: "127.0.0.1", clientPort,
        deps, timeoutMs: 1_000, pollMs: 5,
      }),
      { trusted: true, reason: "vouched" },
      "a SYN_RECV row is waited on, and the accepted trusted inode it becomes is honoured",
    );

    // A row that NEVER leaves SYN_RECV is refused at the accept budget: waiting is
    // not trusting.
    assert.deepEqual(
      await verifyAcceptedConnection({
        address: "127.0.0.1", port, clientAddress: "127.0.0.1", clientPort,
        deps: { ...deps, procNetTcp: `${TCP_HEADER}\n${synRecv}\n` }, timeoutMs: 200, pollMs: 5,
      }),
      { trusted: false, reason: "connection-not-trusted" },
    );

    // ... and the FIN_WAIT states stay REFUSALS (the peer hung up on a connection
    // that IS in this namespace): only 03 changed meaning.
    for (const state of ["04", "05", "08", "09", "0B"]) {
      const row = procRow({
        local: v4Hex("127.0.0.1"), port, state, uid: GW_UID, inode,
        remote: v4Hex("127.0.0.1"), remotePort: clientPort,
      });
      assert.deepEqual(
        await verifyAcceptedConnection({
          address: "127.0.0.1", port, clientAddress: "127.0.0.1", clientPort,
          deps: { ...deps, procNetTcp: `${TCP_HEADER}\n${row}\n` }, timeoutMs: 200, pollMs: 5,
        }),
        { trusted: false, reason: "connection-not-trusted" },
        `state ${state} is a refusal, not a wait`,
      );
    }
  } finally {
    rmSync(procRoot, { recursive: true, force: true });
  }
});

// ---------------------------------------------------------------------------
// (N2) THE NAT BRANCH WANTS `running: true`.
//
// An injected docker entry that says nothing about its container's state is not
// evidence that the kernel holds NAT rules for the port: a STOPPED container keeps
// its published bindings, so "no local row" for it is a free port a squatter can
// take. A live `docker inspect` always states `.State.Running`; only a fixture (or
// a snapshot from an older build) omits it, and silence is not "running".
// ---------------------------------------------------------------------------

test("RED FIRST (N2): a docker entry that does not state running:true is not evidence of NAT — the same entry with running:true is", async () => {
  const port = 18092;
  const noRows = { procNetTcp: `${TCP_HEADER}\n`, procNetTcp6: `${TCP_HEADER}\n` };
  const snapshotFor = (extra) => ({
    docker: [{ address: "0.0.0.0", port, composeDir: "/srv/bundles/ollama", container: "ollama", ...extra }],
    bundles: [], native: [], pins: [], selfPorts: [], crowHome: null,
  });
  assert.deepEqual(
    await verifyAcceptedConnection({
      address: "100.64.20.5", port, clientAddress: "100.64.20.5", clientPort: 51243,
      snapshot: snapshotFor({}), deps: { ...noRows, uid: GW_UID, selfPid: -1 },
      timeoutMs: 200, pollMs: 5,
    }),
    { trusted: false, reason: "connection-not-trusted" },
    "an entry that does not say `running: true` is refused",
  );
  // CONTROL: the SAME shape, with the flag stated, IS the NAT case — so the refusal
  // above is the missing statement and not a blanket refusal of this shape.
  assert.deepEqual(
    await verifyAcceptedConnection({
      address: "100.64.20.5", port, clientAddress: "100.64.20.5", clientPort: 51243,
      snapshot: snapshotFor({ running: true }), deps: { ...noRows, uid: GW_UID, selfPid: -1 },
      timeoutMs: 200, pollMs: 5,
    }),
    { trusted: true, reason: "nat-to-container" },
  );
});

// ---------------------------------------------------------------------------
// (K1) THE STOPPED-CONTAINER SQUAT, proven on a real kernel.
//
// The NAT explanation above is a claim about the KERNEL: "no server-side row in
// this namespace, because Docker DNATed the connection into a container's". A bot
// squatting the published port of a STOPPED model container produces the SAME
// "no row" shape — it accepts our connection, shuts its write side down (the row
// becomes FIN_WAIT, which an ESTABLISHED-only match does not see) and closes its
// listener (no LISTEN row either) — and a stopped container has no NAT rules, so
// the port really is free. The audit's PoC won that 19 times out of 20.
// ---------------------------------------------------------------------------

test("RED FIRST (K1): a same-uid squatter that ACCEPTS, HALF-CLOSES and drops its listener on a STOPPED container's published port is refused", async () => {
  const bot = await spawnHalfCloseListener();
  const net = await import("node:net");
  const socket = net.connect({ host: "127.0.0.1", port: bot.port });
  try {
    await new Promise((r, j) => { socket.once("connect", r); socket.once("error", j); });
    await bot.halfClosed;
    // The kernel state the squat produces: the server end in FIN_WAIT1/2, and not a
    // single LISTEN row left on the port. (The attack as a fact about the real
    // kernel — not a mocked /proc table.)
    await waitForServerRow({ port: bot.port, clientPort: socket.localPort, states: ["04", "05", "08"] });
    assert.equal(
      parseProcNet(readFileSync("/proc/net/tcp", "utf8"), 4).filter((r) => r.port === bot.port && r.state === "0A").length,
      0, "the squatter's listener is gone",
    );
    const verdict = await verifyAcceptedConnection({
      address: "127.0.0.1", port: bot.port,
      clientAddress: socket.localAddress, clientPort: socket.localPort,
      // A STOPPED container keeps its published bindings — the vouch the attack
      // rides on.
      snapshot: {
        docker: [{ address: "127.0.0.1", port: bot.port, running: false, container: "stopped-model", composeDir: "/srv/bundles/ollama" }],
        bundles: [], native: [], pins: [], selfPorts: [], crowHome: null,
      },
      timeoutMs: 400, pollMs: 5,
    });
    assert.deepEqual(verdict, { trusted: false, reason: "connection-not-trusted" });
  } finally {
    socket.destroy();
    await bot.close();
  }
});

test("RED FIRST (K1): a stopped container's binding never earns the nat explanation — a running one with no local row does", async () => {
  const port = 18087;
  // No local row at all (only the client side, which nothing here reads) and a
  // container that is STOPPED: no NAT rules exist, so this is a free port.
  const stopped = hostNatFixture({ port, running: false });
  const noRows = { procNetTcp: `${TCP_HEADER}\n`, procNetTcp6: `${TCP_HEADER}\n` };
  assert.deepEqual(
    await verifyAcceptedConnection({
      address: "100.64.20.5", port, clientAddress: "100.64.20.5", clientPort: 51237,
      snapshot: stopped.snapshot, deps: { ...stopped.deps, ...noRows },
      timeoutMs: 200, pollMs: 5,
    }),
    { trusted: false, reason: "connection-not-trusted" },
  );
  // The same nothing-local shape with a RUNNING container is the real NAT case.
  const running = hostNatFixture({ port, running: true });
  assert.deepEqual(
    await verifyAcceptedConnection({
      address: "100.64.20.5", port, clientAddress: "100.64.20.5", clientPort: 51237,
      snapshot: running.snapshot, deps: { ...running.deps, ...noRows },
      timeoutMs: 200, pollMs: 5,
    }),
    { trusted: true, reason: "nat-to-container" },
  );
});

test("RED FIRST (K1): a FIN_WAIT server row owned by our uid is refused — only a TIME_WAIT row from an earlier connection is ignored", async () => {
  const port = 18088;
  const clientPort = 51238;
  const finRow = procRow({
    local: v4Hex("100.64.20.5"), port, state: "05", uid: GW_UID, inode: 904,
    remote: v4Hex("100.64.20.5"), remotePort: clientPort,
  });
  const deps = { procNetTcp: `${TCP_HEADER}\n${finRow}\n`, procNetTcp6: `${TCP_HEADER}\n`, uid: GW_UID, selfPid: -1 };
  const { snapshot } = hostNatFixture({ port, running: true });
  assert.deepEqual(
    await verifyAcceptedConnection({
      address: "100.64.20.5", port, clientAddress: "100.64.20.5", clientPort,
      snapshot, deps, timeoutMs: 200, pollMs: 5,
    }),
    { trusted: false, reason: "connection-not-trusted" },
    "a half-closed local connection IS local: the nat explanation must never stand in for it",
  );
  // A TIME_WAIT row belongs to a CLOSED earlier connection that reused our client
  // port; it says nothing about this connection, so it must not block the nat
  // branch either.
  const timeWait = procRow({
    local: v4Hex("100.64.20.5"), port, state: "06", uid: GW_UID, inode: 0,
    remote: v4Hex("100.64.20.5"), remotePort: clientPort,
  });
  assert.deepEqual(
    await verifyAcceptedConnection({
      address: "100.64.20.5", port, clientAddress: "100.64.20.5", clientPort,
      snapshot, deps: { ...deps, procNetTcp: `${TCP_HEADER}\n${timeWait}\n` },
      timeoutMs: 200, pollMs: 5,
    }),
    { trusted: true, reason: "nat-to-container" },
  );
});

test("RED FIRST (K1): a socket the peer already closed is never handed to http, even when the vouch would say nat-to-container", async () => {
  const net = await import("node:net");
  // A listener that ACCEPTS and immediately shuts its write side down: the socket
  // this process gets back has already received EOF.
  const server = net.createServer((socket) => { socket.end(); });
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  // The /proc tables are empty on purpose: the vouch is forced to the nat branch (a
  // RUNNING container vouches the port, nothing local), so ONLY the EOF check can
  // refuse this socket.
  const baseDeps = {
    procNetTcp: `${TCP_HEADER}\n`, procNetTcp6: `${TCP_HEADER}\n`,
    uid: typeof process.getuid === "function" ? process.getuid() : 0, selfPid: -1,
  };
  const dockerFor = (p) => [{ address: "127.0.0.1", port: p, running: true, container: "model", composeDir: "/srv/bundles/ollama" }];
  try {
    await assert.rejects(
      () => openVerifiedSocket({ address: "127.0.0.1", port, deps: { ...baseDeps, dockerEntries: dockerFor(port) }, timeoutMs: 1_000 }),
      (e) => e.code === CONNECTION_NOT_TRUSTED,
      "a half-closed socket can never answer a request",
    );
  } finally {
    await new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
  }
  // CONTROL: the same kind of listener, answering normally, IS handed back — so the
  // refusal above is the EOF and not a blanket refusal of this shape.
  const healthy = http.createServer((_req, res) => res.end("ok"));
  await new Promise((r) => healthy.listen(0, "127.0.0.1", r));
  const okPort = healthy.address().port;
  try {
    const socket = await openVerifiedSocket({ address: "127.0.0.1", port: okPort, deps: { ...baseDeps, dockerEntries: dockerFor(okPort) }, timeoutMs: 1_000 });
    socket.destroy();
  } finally {
    await new Promise((r) => { healthy.closeAllConnections?.(); healthy.close(() => r()); });
  }
});

/** A connector whose socket is CONNECTED at once (a test states the connection
 * without a kernel), with a local address/port of the test's choosing. */
function fakeConnectedSocket({ localAddress = "127.0.0.1", localPort = 51239 } = {}) {
  const socket = new EventEmitter();
  Object.assign(socket, {
    localAddress, localPort,
    destroyed: false, readableEnded: false, writableEnded: false, writable: true, readableLength: 0,
  });
  socket.destroy = () => { socket.destroyed = true; };
  setImmediate(() => socket.emit("connect"));
  return socket;
}

test("RED FIRST (K1 nit): a refusal the ACCEPT BUDGET produces still logs the one refusal line", async () => {
  const port = 18089;
  const clientPort = 51239;
  // A connection row whose inode never stops being 0: the kernel never handed it to
  // an application, so the verifier keeps waiting — and the accept budget ends the
  // wait first.
  const row = procRow({
    local: v4Hex("127.0.0.1"), port, state: "01", uid: GW_UID, inode: 0,
    remote: v4Hex("127.0.0.1"), remotePort: clientPort,
  });
  let ticks = 0;
  const deps = {
    procNetTcp: `${TCP_HEADER}\n${row}\n`, procNetTcp6: `${TCP_HEADER}\n`,
    uid: GW_UID, selfPid: -1,
    // "now" advances 1 ms per read, so the verifier's own deadline (40 ms) is far
    // away in wall clock while the accept budget is real.
    now: () => (ticks += 1),
  };
  const logs = [];
  await assert.rejects(
    () => openVerifiedSocket({
      address: "127.0.0.1", port, deps, timeoutMs: 40,
      log: (line) => logs.push(line), providerId: "squat",
      connectFn: () => fakeConnectedSocket({ localPort: clientPort }),
    }),
    (e) => e.code === CONNECTION_NOT_TRUSTED,
  );
  assert.deepEqual(logs, [`[door] own-host target 127.0.0.1:${port} is not a known model server (provider squat, connection-not-trusted)`]);
});

// ---------------------------------------------------------------------------
// (J2) A CONNECT FAILURE IS AN UPSTREAM FAILURE. The refusal is kept for a
// positively untrusted owner only: a broken/absent model server must read as
// "unreachable", not as an attempted squat (`400 NOT_FORWARDABLE` on the door).
// ---------------------------------------------------------------------------

/** A connector whose socket never connects and never errors: only the budget ends it. */
function stalledConnect() {
  const socket = new EventEmitter();
  socket.destroy = () => {};
  return socket;
}

/** A connector whose socket fails at once, with `code`. */
function failingConnect(code) {
  const socket = new EventEmitter();
  socket.destroy = () => {};
  setImmediate(() => socket.emit("error", Object.assign(new Error(`connect ${code}`), { code })));
  return socket;
}

test("RED FIRST (J2): a connect that never completes is ETIMEDOUT on the upstream path, never CONNECTION_NOT_TRUSTED", async () => {
  await assert.rejects(
    () => openVerifiedSocket({ address: "100.64.20.5", port: 8003, timeoutMs: 40, connectFn: stalledConnect }),
    (e) => {
      assert.notEqual(e.code, CONNECTION_NOT_TRUSTED);
      assert.equal(e.code, "ETIMEDOUT");
      assert.equal(e.name, "TimeoutError", "the door's isTimeoutError path reports it as an upstream timeout");
      assert.equal(e.reason, undefined, "never the refusal marker (that would log a squat line and answer 400)");
      return true;
    },
  );
});

test("RED FIRST (J2): a no-route connect surfaces as the socket's own upstream error, never CONNECTION_NOT_TRUSTED", async () => {
  await assert.rejects(
    () => openVerifiedSocket({ address: "100.64.20.5", port: 8003, timeoutMs: 1_000, connectFn: () => failingConnect("EHOSTUNREACH") }),
    (e) => e.code === "EHOSTUNREACH" && e.code !== CONNECTION_NOT_TRUSTED && e.reason === undefined,
  );
});

// ---------------------------------------------------------------------------
// (J3) THE IPv4-MAPPED SPELLING. A URL may name [::ffff:127.0.0.1] or
// [::ffff:7f00:1]; the kernel row says 127.0.0.1. Without the hex unwrap the
// four-tuple never matched and a verified connect to a mapped address was refused.
// ---------------------------------------------------------------------------

test("RED FIRST (J3): normalizeAddress unwraps BOTH spellings of an IPv4-mapped address", () => {
  assert.equal(normalizeAddress("::ffff:7f00:1"), "127.0.0.1");
  assert.equal(normalizeAddress("[::FFFF:7F00:1]"), "127.0.0.1");
  assert.equal(normalizeAddress("::ffff:127.0.0.1"), "127.0.0.1");
  assert.equal(normalizeAddress("[::ffff:127.0.0.1]"), "127.0.0.1");
  assert.equal(normalizeAddress("0:0:0:0:0:ffff:7f00:1"), "127.0.0.1");
  // An unmapped IPv6 address is untouched.
  assert.equal(normalizeAddress("[::1]"), "::1");
});

test("RED FIRST (J3): a HEX-mapped spelling matches the kernel's dotted row at both ends of the four-tuple", async () => {
  // The kernel says 127.0.0.1 on both sides; the URL/socket spell both as
  // ::ffff:7f00:1. Docker-proxy (another uid) holds the accepted socket, so the
  // ONLY thing under test is the four-tuple match.
  const port = 18084;
  const clientPort = 51235;
  const rows = [procRow({
    local: v4Hex("127.0.0.1"), port, state: "01", uid: 0, inode: 903,
    remote: v4Hex("127.0.0.1"), remotePort: clientPort,
  })];
  assert.deepEqual(
    await verifyAcceptedConnection({
      address: "::ffff:7f00:1", port, clientAddress: "::ffff:7f00:1", clientPort,
      deps: { procNetTcp: `${TCP_HEADER}\n${rows.join("\n")}\n`, procNetTcp6: `${TCP_HEADER}\n`, uid: GW_UID, selfPid: -1 },
      timeoutMs: 0,
    }),
    { trusted: true, reason: "vouched" },
  );
});

test("RED FIRST (J3): a connection judged by its HEX v4-mapped spelling matches the real kernel row", async (t) => {
  const net = await import("node:net");
  const server = http.createServer((_req, res) => res.end("ok"));
  await new Promise((r) => server.listen(0, "127.0.0.1", r));
  const port = server.address().port;
  const socket = net.connect({ host: "::ffff:127.0.0.1", port });
  try {
    try {
      await new Promise((r, j) => { socket.once("connect", r); socket.once("error", j); });
    } catch (e) {
      // A host with IPv6 switched off cannot dial a mapped literal at all; that is
      // an environment fact, not this rule's subject.
      if (["EAFNOSUPPORT", "EADDRNOTAVAIL", "ENETUNREACH", "ECONNREFUSED"].includes(e.code)) return t.skip(`no IPv4-mapped IPv6 here (${e.code})`);
      throw e;
    }
    assert.deepEqual(
      await verifyAcceptedConnection({
        address: "::ffff:7f00:1", port, clientAddress: socket.localAddress, clientPort: socket.localPort, timeoutMs: 2_000,
      }),
      { trusted: true, reason: "vouched" },
    );
  } finally {
    socket.destroy();
    await new Promise((r) => { server.closeAllConnections?.(); server.close(() => r()); });
  }
});
