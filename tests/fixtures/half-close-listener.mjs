/**
 * A SAME-UID SQUATTER THAT HALF-CLOSES (K1): a real listener in a SEPARATE process
 * of the SAME uid (a contained bot shares the gateway's uid and host network) that
 * ACCEPTS our connection, shuts down its write side and then drops the listener.
 *
 * That is the shape a real kernel produced (a bot squatting a STOPPED model
 * container's published port, proven with a PoC): after the half-close the server
 * end of the connection sits in FIN_WAIT (state 04/05), the LISTEN row is gone, and
 * a verifier that only looks for an ESTABLISHED row or a LISTEN row sees "nothing
 * local" — which the Docker-NAT explanation used to fill in. It reports
 *   CONN   an accepted TCP connection
 *   HALF   the write side was shut down and the listener closed
 * so a test can wait for the exact moment the kernel is in that state.
 */
import { spawn } from "node:child_process";

const SCRIPT = (address, port) => `
const net = require("node:net");
const server = net.createServer((socket) => {
  process.stdout.write("CONN\\n");
  socket.end();                       // half-close: FIN out, our read side still open
  try { server.close(); } catch { /* already gone */ }
  process.stdout.write("HALF\\n");
});
server.on("error", (e) => process.stdout.write("ERR " + e.code + "\\n"));
server.listen(${Number(port) || 0}, ${JSON.stringify(address)}, () =>
  process.stdout.write("PORT " + server.address().port + "\\n"));
const stop = () => process.exit(0);
process.on("SIGTERM", stop);
process.on("SIGINT", stop);
`;

/**
 * Spawn the half-closing squatter. Resolves once it listens; `closed()` resolves
 * when its half-close has been performed (`HALF`).
 * @returns {Promise<{port:number, halfClosed: Promise<void>, pid:number, close: () => Promise<void>}>}
 */
export async function spawnHalfCloseListener({ address = "127.0.0.1", port = 0 } = {}) {
  const child = spawn(process.execPath, ["-e", SCRIPT(address, port)], { stdio: ["ignore", "pipe", "pipe"] });
  let buffered = "";
  let stderr = "";
  let resolvePort;
  let resolveHalf;
  const portReady = new Promise((resolve) => { resolvePort = resolve; });
  const halfReady = new Promise((resolve) => { resolveHalf = resolve; });
  child.stdout.setEncoding("utf8");
  child.stdout.on("data", (chunk) => {
    buffered += chunk;
    let at;
    while ((at = buffered.indexOf("\n")) >= 0) {
      const line = buffered.slice(0, at);
      buffered = buffered.slice(at + 1);
      if (line.startsWith("PORT ")) resolvePort(Number(line.slice(5)));
      else if (line === "HALF") resolveHalf();
      else if (line.startsWith("ERR ")) stderr += line;
    }
  });
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => { stderr += chunk; });
  const reported = await Promise.race([
    portReady,
    new Promise((_, reject) => setTimeout(() => reject(new Error(`half-close listener did not report a port: ${stderr}`)), 15_000)),
  ]);
  return {
    port: reported,
    halfClosed: Promise.race([
      halfReady,
      new Promise((_, reject) => setTimeout(() => reject(new Error("the squatter never half-closed")), 15_000)),
    ]),
    get pid() { return child.pid; },
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