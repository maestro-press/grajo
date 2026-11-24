/**
 * A LISTENER NOBODY IN CROW PUT THERE: a real HTTP server in a SEPARATE process
 * of the SAME uid (a test sandbox has one uid, and a contained bot's own relay
 * would run as the gateway's uid too).
 *
 * That is exactly the shape `servers/gateway/models/local-model-servers.js` calls
 * "listener-not-trusted": the port may be vouched by Docker, a bundle compose
 * file or an operator pin, but the socket still belongs to a process Crow never
 * started, so an own-host provider/speech row must not reach it.
 *
 * Every request it answers is reported on stdout (`HIT <method> <url>`), so a
 * test can prove two things at once: a CONTROL request from the test process
 * reaches it (the fixture is alive), and a REFUSED forward sent it nothing.
 *
 * BOTH HALVES ARE SYNCHRONISED (L2), because a CHILD'S STDOUT IS ASYNCHRONOUS: the
 * child writes its `HIT` line before it replies, but the parent can receive the
 * reply before the pipe's 'data' event for that line has run. Asserting `hits`
 * right after a request therefore raced the pipe (one CONTROL in ~26 loaded runs
 * of tests/memory-provider-target-guard.test.js), and asserting `hits` is EMPTY
 * right after a refusal could pass by simply not having looked yet.
 *
 * So the child answers `SIGUSR2` with ONE `SYNC` marker on the SAME ordered stream:
 * a parent that has read the marker has already read every hit the child reported
 * before it — nothing is missed, and nothing is asserted too early. `control()`
 * and `settle()` below are the two halves built on it.
 *
 * (A signal is used rather than an HTTP round trip on purpose: a fixture that
 * SHARES its port with a trusted SO_REUSEPORT listener — the H1 squat tests —
 * would have that request answered by the OTHER server half the time, and the
 * marker would never arrive.)
 */
import { spawn } from "node:child_process";

const SCRIPT = (address, port) => `
const http = require("node:http");
const server = http.createServer((req, res) => {
  process.stdout.write("HIT " + req.method + " " + req.url + "\\n");
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({
    choices: [{ message: { content: "relayed by a bot" } }],
    data: [{ embedding: [9, 9] }],
    text: "relayed by a bot",
    embeddings: [[9, 9]],
  }));
});
server.listen(${Number(port) || 0}, ${JSON.stringify(address)}, () => process.stdout.write("PORT " + server.address().port + "\\n"));
// THE ACK: one marker on the same ordered stdout stream as every HIT line, so a
// parent that has read it has read every hit reported before it.
process.on("SIGUSR2", () => process.stdout.write("SYNC\\n"));
const stop = () => { try { server.close(); } catch { /* already gone */ } process.exit(0); };
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
`;

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

/** Poll `check` (bounded) and fail with `what` when it never holds. */
async function waitFor(check, what, ms = 2_000) {
  const deadline = Date.now() + ms;
  for (;;) {
    if (check()) return;
    if (Date.now() >= deadline) throw new Error(what);
    await delay(5);
  }
}

/** `127.0.0.1` -> `127.0.0.1`, `::1` -> `[::1]`. */
const urlHost = (address) => (String(address).includes(":") ? `[${address}]` : String(address));

/**
 * Spawn the listener and wait for its port.
 *
 * `address`/`port` are for the tests about ONE address of a name that stands for
 * two (`localhost` is 127.0.0.1 AND ::1): a trusted listener in the test process
 * binds the address it likes and picks the port, then this one binds the OTHER
 * address on that same port — the squat that a forward resolving the name twice
 * would land on.
 * @returns {Promise<{port:number, hits:string[], pid:number, control:Function, settle:Function, close: () => Promise<void>}>}
 */
export async function spawnUntrustedListener({ address = "127.0.0.1", port: wantedPort = 0 } = {}) {
  const child = spawn(process.execPath, ["-e", SCRIPT(address, wantedPort)], { stdio: ["ignore", "pipe", "pipe"] });
  const hits = [];
  let syncs = 0;
  let buffered = "";
  let stderr = "";
  let resolvePort;
  const portReady = new Promise((resolve) => { resolvePort = resolve; });
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffered += chunk;
    let at;
    while ((at = buffered.indexOf("\n")) >= 0) {
      const line = buffered.slice(0, at);
      buffered = buffered.slice(at + 1);
      if (line.startsWith("PORT ")) resolvePort(Number(line.slice(5)));
      else if (line.startsWith("HIT ")) hits.push(line.slice(4));
      else if (line === "SYNC") syncs += 1;
    }
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const port = await Promise.race([
    portReady,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`untrusted listener did not report a port: ${stderr}`)), 15_000)),
  ]);
  return {
    port,
    hits,
    get pid() { return child.pid; },
    /**
     * THE CONTROL HALF: make ONE request the fixture is known to answer, then wait
     * (bounded) until the child has REPORTED it. Asserting on `hits` straight after
     * the request raced the child's stdout pipe (L2) — the HTTP response can reach
     * this process before the 'data' event for the HIT line does.
     */
    async control({ method = "POST", path = "/" } = {}) {
      const before = hits.length;
      await fetch(`http://${urlHost(address)}:${port}${path}`, { method }).catch(() => {});
      await waitFor(
        () => hits.length > before,
        `CONTROL: bot liveness probe not observed (${method} ${path} was never reported by the fixture)`,
      );
      return hits[before];
    },
    /**
     * THE SECURITY HALF: give the child a bounded window to report anything a refused
     * forward sent it, then take the ack round-trip, so every hit it wrote before the
     * marker is already parsed here. A refusal is expected to produce NOTHING; this
     * only makes sure "nothing" is not just "not yet".
     */
    async settle({ quietMs = 200 } = {}) {
      if (quietMs > 0) await delay(quietMs);
      const want = syncs + 1;
      try { child.kill("SIGUSR2"); } catch { /* the wait below reports a dead child */ }
      await waitFor(() => syncs >= want, "SECURITY: the fixture never acknowledged the sync round-trip (its stdout stream is gone)");
    },
    async close() {
      if (child.exitCode !== null || child.signalCode !== null) return;
      child.kill("SIGTERM");
      await new Promise((resolve) => {
        const timer = setTimeout(() => { try { child.kill("SIGKILL"); } catch { /* already gone */ } resolve(); }, 3000);
        child.once("exit", () => { clearTimeout(timer); resolve(); });
      });
    },
  };
}