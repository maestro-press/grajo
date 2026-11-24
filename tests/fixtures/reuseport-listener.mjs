/**
 * A SAME-UID BOT LISTENING ON A PORT THAT ALREADY HAS A LISTENER — the exact shape
 * of H1's race: llama.cpp's server sets SO_REUSEPORT, a contained bot shares the
 * host network and the gateway's uid, so it can open its OWN reuseport listener on
 * the model's address and port and the kernel may hand it the connection.
 *
 * It reports `CONN` for every accepted TCP connection and `HIT <method> <url>` for
 * every request it manages to PARSE, so a test proves the two halves separately:
 * the kernel did give it connections (otherwise the test is vacuous), and not one
 * request line, header or body byte ever arrived (the forward refused it first).
 *
 * Both of those reports travel over an ASYNCHRONOUS stdout pipe, so `SIGUSR2`
 * answers with ONE `SYNC` marker on the same ordered stream (L2): a parent that has
 * read the marker has read every CONN/HIT the child reported before it, which is
 * what makes "the bot received nothing" a fact instead of a race. A signal is used
 * rather than an HTTP round trip because this listener SHARES its port with a
 * trusted SO_REUSEPORT server: a request could be answered by the other half.
 */
import { spawn } from "node:child_process";

const SCRIPT = (address, port) => `
const http = require("node:http");
const server = http.createServer({ reusePort: true }, (req, res) => {
  process.stdout.write("HIT " + req.method + " " + req.url + "\\n");
  res.writeHead(200, { "content-type": "application/json" });
  res.end(JSON.stringify({ choices: [{ message: { content: "relayed by a bot" } }] }));
});
server.on("connection", () => process.stdout.write("CONN\\n"));
server.on("error", (e) => process.stdout.write("ERR " + e.code + "\\n"));
server.listen({ port: ${Number(port)}, host: ${JSON.stringify(address)}, reusePort: true }, () =>
  process.stdout.write("PORT " + server.address().port + "\\n"));
// THE ACK (see the header): one marker on the same ordered stdout stream.
process.on("SIGUSR2", () => process.stdout.write("SYNC\\n"));
const stop = () => { try { server.close(); } catch { /* already gone */ } process.exit(0); };
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
`;

/**
 * Spawn a reuseport listener on an address and port a TRUSTED listener already
 * holds. Resolves once it is bound; `connections` counts accepted TCP connections
 * and `hits` counts parsed requests.
 * @returns {Promise<{port:number, hits:string[], connections:number, pid:number, close:() => Promise<void>}>}
 */
export async function spawnReusePortListener({ address = "127.0.0.1", port } = {}) {
  const child = spawn(process.execPath, ["-e", SCRIPT(address, Number(port))], { stdio: ["ignore", "pipe", "pipe"] });
  const hits = [];
  let connections = 0;
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
      else if (line === "CONN") connections += 1;
      else if (line.startsWith("HIT ")) hits.push(line.slice(4));
      else if (line === "SYNC") syncs += 1;
      else if (line.startsWith("ERR ")) stderr += line;
    }
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  await Promise.race([
    portReady,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`reuseport listener did not bind: ${stderr}`)), 15_000)),
  ]);
  return {
    port: Number(port),
    hits,
    get connections() { return connections; },
    get pid() { return child.pid; },
    get stderr() { return stderr; },
    /**
     * Give the child a bounded window, then take the ack round-trip (L2): a parent
     * that has read the marker has read every CONN/HIT the child reported before it,
     * so "the bot received nothing" is a fact rather than a race with the pipe.
     */
    async settle({ quietMs = 200 } = {}) {
      if (quietMs > 0) await new Promise((r) => setTimeout(r, quietMs));
      const want = syncs + 1;
      try { child.kill("SIGUSR2"); } catch { /* the wait below reports a dead child */ }
      const deadline = Date.now() + 2_000;
      for (;;) {
        if (syncs >= want) return;
        if (Date.now() >= deadline) throw new Error("SECURITY: the reuseport fixture never acknowledged the sync round-trip");
        await new Promise((r) => setTimeout(r, 5));
      }
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