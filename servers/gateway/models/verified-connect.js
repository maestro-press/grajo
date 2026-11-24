/**
 * THE VERIFIED CONNECTION (H1) — the socket a forward uses is the socket that was
 * judged, and no request byte is written on it before that judgement.
 *
 * THE RACE. `isKnownLocalModelTarget` judges the LISTEN sockets on an own-host
 * address and port. A forward then connects. Between those two moments a same-uid
 * listener can take the connection: llama.cpp's own server sets SO_REUSEPORT, the
 * kernel allows any process to open a reuseport listener on an address and port
 * that already has one, and a contained bot shares the host network
 * (CROW_PI_CONTAIN_NET=off) and the gateway's uid. So "every LISTEN row is ours"
 * proves nothing about the socket the SYN actually landed on, and a pooled
 * keep-alive connection would carry one win over many requests.
 *
 * THE FIX, in two halves, both here because both are about the same socket:
 *
 *   a. OWN-HOST FORWARDS ARE NEVER POOLED. Every request opens a fresh connection
 *      (`agent: false` plus a one-request Agent we hand the socket to) and says
 *      `Connection: close`, so a connection can be won once at most and the next
 *      request starts from a fresh, judged connect.
 *
 *   b. THE ACCEPTED CONNECTION IS VERIFIED BEFORE ANY BYTE IS WRITTEN. We open the
 *      TCP socket ourselves (`net.connect` to the judged address and port), then
 *      find the SERVER side of THIS connection in /proc/net/tcp{,6}: state
 *      ESTABLISHED (01), local = the server address:port, remote = our socket's
 *      own localAddress:localPort. That row is the connection we hold, not a
 *      listener:
 *        - its uid is not ours -> trusted (docker-proxy runs as root, and a bot
 *          cannot become another uid);
 *        - our own uid -> wait, bounded (`ACCEPT_POLL_MS`), until its inode stops
 *          being 0 (that is the kernel saying an application ACCEPTED it), then
 *          trust it only when that inode is held by a trusted candidate pid — this
 *          process, a live native handle for that port, a pinned/managed-binary
 *          holder, or a docker-cgroup pid (`verifyAcceptedConnection` in
 *          local-model-servers.js owns that rule, the same one the LISTEN check
 *          uses; the search is candidate-only, H4);
 *        - NO row for our four-tuple at all -> trusted as "nat-to-container", but
 *          only when a RUNNING Docker container's binding vouches the address:port
 *          and no same-uid listener existed there: Docker publishes a host port by
 *          NAT, and a connection from this host to its OWN address on it is DNAT'd
 *          straight into the container's namespace, so the peer legitimately has no
 *          socket in ours (`noLocalRowIsDockerNat` in local-model-servers.js owns
 *          the rule and states why a bot cannot fake that shape). A row in ANY live
 *          state — FIN_WAIT after the peer's half-close, not only ESTABLISHED —
 *          means this connection IS local, so this explanation is never used for
 *          it, and a same-uid row in such a state is a refusal;
 *        - a socket that has ALREADY been closed by the peer (readable-ended,
 *          destroyed, not writable, 'end' seen) is refused too: a bot that accepts
 *          and shuts down its write side would otherwise be handed to http as a
 *          connection that can never answer;
 *        - anything else: the socket is DESTROYED and the forward refused with
 *          `CONNECTION_NOT_TRUSTED` ("connection-not-trusted"), before a request
 *          line, a header or a body byte exists.
 *
 *   c. A CONNECT FAILURE IS AN UPSTREAM FAILURE, NOT A REFUSAL (J2). A timeout, a
 *      dropped SYN, no route, a refused port: the provider did not answer, and the
 *      caller's existing unreachable/upstream path is the right answer (`502` on the
 *      door, never the `400 NOT_FORWARDABLE` a refusal produces). `CONNECTION_NOT_TRUSTED`
 *      is kept for the ONE case it means — a connection that was established and
 *      then found to be held by nobody Crow trusts — so a broken model server never
 *      reads as an attempted squat.
 *
 * WHAT THIS IS NOT. It is not a TLS pin and not a second address resolution: the
 * address dialled is the one `pinnedTargetOf`/the own-host vouch accepted (the
 * caller passes it in), and an https socket is wrapped with the ordinary TLS
 * rules (SNI = the URL's host, certificate verification on) on top of the verified
 * TCP socket.
 *
 * The module is deliberately small and side-effect free: it opens ONE socket, asks
 * `local-model-servers.js` about it, and hands it (or an error) back.
 */
import net from "node:net";
import tls from "node:tls";

import { verifyAcceptedConnection, logOwnHostTargetRefusal } from "./local-model-servers.js";

/** The refusal a forward raises when the connection it got is not one Crow
 * accepts. Wording is `safe-upstream.js`'s fixed one: no user-visible text. */
export const CONNECTION_NOT_TRUSTED = "CONNECTION_NOT_TRUSTED";
export const CONNECTION_REFUSED_MESSAGE = "Crow will not contact that address";

/** How long to wait for the kernel to hand an accepted connection to a socket.
 * Bounded on purpose: a listener that never accepts is a refusal, not a hang. */
export const ACCEPT_POLL_MS = 2_000;

export function connectionNotTrusted(reason = "connection-not-trusted") {
  return Object.assign(new Error(CONNECTION_REFUSED_MESSAGE), { code: CONNECTION_NOT_TRUSTED, reason });
}

/**
 * A connect that never completed (J2). The provider did not answer in time, which is
 * an UPSTREAM failure exactly like ECONNREFUSED or EHOSTUNREACH — the socket's own
 * error is what a caller already knows how to report. `code` is node's own code for
 * it and `name` is the one `isTimeoutError` (`servers/shared/http-timeout.js`) — and
 * so the door's "upstream connect timeout" line — keys on. Never carries a `reason`,
 * so it never takes the refusal-log path a `connection-not-trusted` verdict uses.
 */
function connectTimedOut() {
  return Object.assign(new Error("connect timeout"), { code: "ETIMEDOUT", name: "TimeoutError" });
}

/**
 * Open ONE TCP (or TLS) connection to `address:port`, verified before it is
 * returned.
 *
 *   { address, port, family }        where to connect (the judged address)
 *   { servername, tls }              wrap in TLS (`servername` = the URL's host)
 *   { deps, timeoutMs }              the vouch seams / the connect + accept budget
 *   { log }                          where the ONE refusal line goes (optional)
 *   { connectFn }                    the connector itself (`net.connect`), a seam a
 *                                    test uses to state "this connect never completes"
 *
 * Resolves the connected socket. Rejects `CONNECTION_NOT_TRUSTED` when the
 * connection is not one Crow accepts (the socket is destroyed first), or with the
 * socket's own error code for a connect failure — including ETIMEDOUT for one that
 * never completed.
 */
export function openVerifiedSocket({
  address, port, family, servername = null, tls: wantTls = false,
  deps = {}, timeoutMs = ACCEPT_POLL_MS, log = null, providerId = "?",
  connectFn = net.connect,
} = {}) {
  const budget = Math.max(1, Number(timeoutMs) || ACCEPT_POLL_MS);
  return new Promise((resolve, reject) => {
    const socket = connectFn({ host: address, port: Number(port), ...(family ? { family } : {}) });
    let settled = false;
    // Which phase the budget ran out in decides what the failure MEANS: no
    // connection at all is the provider's problem (upstream); a connection that
    // completed and was never accepted is the one Crow refuses.
    let connected = false;
    // A PEER THAT ALREADY HUNG UP. The FIN a half-closing squatter sends a moment
    // before our judgement has to be visible HERE, before http gets the socket: a
    // 'readable' listener makes the stream ask the kernel in PAUSED mode (any bytes
    // stay buffered for http), and a 'readable' with nothing buffered is the EOF.
    let sawEnd = false;
    const onEnd = () => { sawEnd = true; };
    const onReadable = () => { if (socket.readableLength === 0) sawEnd = true; };
    socket.once("end", onEnd);
    socket.on("readable", onReadable);
    const timer = setTimeout(() => finish(connected ? connectionNotTrusted("accept-timeout") : connectTimedOut()), budget);
    const cleanup = () => {
      clearTimeout(timer);
      socket.removeListener("error", onError);
      socket.removeListener("readable", onReadable);
    };
    function finish(err, value) {
      if (settled) return;
      settled = true;
      cleanup();
      if (err) {
        try { socket.destroy(); } catch { /* already gone */ }
        // EVERY refusal gets the one line — an accept-timeout is as much "this
        // socket is not Crow's model server" as a wrong owner is (K1 nit).
        if (err.code === CONNECTION_NOT_TRUSTED && typeof log === "function") {
          // The callers own the refusal line; this is the same fixed shape the
          // door prints, with the reason the race exists for.
          logOwnHostTargetRefusal({ address, port: Number(port), providerId, reason: "connection-not-trusted" }, log);
        }
        reject(err);
        return;
      }
      resolve(value);
    }
    function onError(err) { finish(err); }
    socket.once("error", onError);
    socket.once("connect", () => {
      connected = true;
      const clientAddress = socket.localAddress;
      const clientPort = socket.localPort;
      verifyAcceptedConnection({
        address, port: Number(port), clientAddress, clientPort, deps, timeoutMs: budget,
      }).then(async (verdict) => {
        if (!verdict || verdict.trusted !== true) {
          finish(connectionNotTrusted(verdict && verdict.reason));
          return;
        }
        // One turn of the loop, so a FIN that landed while the vouch was running is
        // read by the 'readable' probe above rather than by http.
        await new Promise((r) => setImmediate(r));
        if (socket.destroyed || socket.readableEnded || socket.writableEnded || sawEnd || socket.writable === false) {
          finish(connectionNotTrusted("connection-closed"));
          return;
        }
        if (!wantTls) { finish(null, socket); return; }
        // The verified TCP socket is wrapped, never replaced: TLS rides THIS
        // connection, so the address judged is the address talked to.
        const secure = tls.connect({ socket, servername: servername || undefined });
        secure.once("error", (err) => { try { secure.destroy(); } catch { /* gone */ } finish(err); });
        secure.once("secureConnect", () => { cleanup(); if (!settled) { settled = true; resolve(secure); } });
      }).catch(() => finish(connectionNotTrusted()));
    });
  });
}

/**
 * The `createConnection` node's http(s) Agent calls, answered with the ONE
 * verified socket. `agent: false` on the request plus a one-request Agent carrying
 * this function keeps the connection unpooled.
 */
export function createConnectionFor(socket) {
  return () => socket;
}