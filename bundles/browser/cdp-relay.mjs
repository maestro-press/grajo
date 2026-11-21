#!/usr/bin/env node
/**
 * crow-browser CDP relay: Chromium on a pipe, one token-gated WebSocket for the host.
 *
 * TWO PROCESSES, TWO UIDS, ONE PIPE. The entrypoint starts this file with `--supervise`,
 * as root. That process starts Chromium — which STAYS root, because the image's /root is
 * 0700 and the profile lives under it — and starts the relay itself as the GATEWAY's uid:
 *
 *   setpriv --reuid U --regid G --clear-groups --inh-caps=-all --bounding-set=-all \
 *           --no-new-privs -- /usr/bin/node /app/cdp-relay.mjs --attach
 *
 * handing it Chromium's pipe on fds 3 and 4 and a one-line report pipe on fd 5. The
 * supervisor listens on NO socket, and writes CROW_CDP_READY_FILE itself once the relay
 * has reported ready — into a root-owned 0755 directory the relay's uid cannot write to
 * (directly or through /proc/<relay>/root), so no process on that uid can announce a
 * browser that is not up.
 *
 * A third, tiny process belongs to the same design: a HOLDER child (`--holder`) the
 * supervisor starts beside the relay with its own copies of Chromium's pipe on fds 3 and 4.
 * It never reads or writes them; it exists so the pipe does not reach EOF while the
 * supervisor reacts to a relay that died (Chromium reads EOF as "the browser is over" and
 * runs the pages' pagehide/unload traffic), and it is SIGKILLed only once Chromium is
 * confirmed gone.
 *
 * Why the uid split: a browser add-on runs behind a wall, and the wall's listener-owner
 * check (scripts/addon-sandbox/listener-owner.mjs) identifies a loopback port by who holds
 * the socket and, for a same-uid holder, by the container that holder runs in. A listener
 * owned by the GATEWAY's uid inside this add-on's own container is that add-on's own
 * service, provided the process can be identified: /proc/<pid>/fd, cwd, exe and cgroup must
 * be readable by the gateway, and argv must carry an absolute script path. A process exec'd
 * through setpriv keeps all of that; a process that calls setuid() itself becomes
 * non-dumpable and its /proc entries become unreadable, so this file NEVER drops privileges
 * in-process — it re-execs itself.
 *
 * The split does NOT contain Chromium. The token is full CDP control of a browser that
 * still runs as root: whoever holds it can read the profile's cookies and saved logins, and
 * can make the browser open file:// URLs for anything the container can read. What the
 * split buys is identification — the wall can tell that this listener belongs to the
 * browser add-on's own container and refuse it to every other add-on — not a boundary
 * around the browser.
 *
 * Why a relay at all: Chrome DevTools Protocol has no authentication, and under
 * `network_mode: host` a CDP port on 127.0.0.1 is reachable by every process on the
 * machine (and by a web page via DNS rebinding). So Chromium runs with
 * `--remote-debugging-pipe` and opens NO port; the relay owns the pipe (fd 3 = what it
 * writes to Chromium, fd 4 = what it reads back) and serves the host contract,
 * `127.0.0.1:${CDP_PORT}`, to anyone holding the per-instance
 * `CROW_BROWSER_CDP_TOKEN`. The token is read from a 0400 file (compose mounts it root
 * only; the entrypoint copies it into a directory the relay's uid owns), is compared in
 * constant time, and never reaches Chromium: not in its argv, and stripped from the env
 * Chromium inherits. It is never in the relay's argv or in an environment VALUE either —
 * CROW_CDP_TOKEN_FILE is only a path.
 *
 * A pipe is ONE connection, so the relay multiplexes: each client gets its own flat
 * browser session (`Target.attachToBrowserTarget` → `S_c`), the relay remaps message
 * ids per client, stamps `sessionId: S_c` on a client's sessionless messages, routes
 * responses and session-bearing events back by that session, and refuses a
 * `sessionId` the client does not own (-32001).
 *
 * Node builtins only (the image installs Node 24 LTS, and no Node 22+ API is used here):
 * the image has no `ws`, and a minimal RFC 6455 server for text frames (handshake,
 * text/continuation, ping/pong, close, mask handling) is smaller than adding a
 * dependency to a security-sensitive hop.
 *
 * What the gate keeps out: other uids, other containers and web pages. It does NOT keep
 * out a process of this same uid that can read the token file — and such a process has the
 * whole root Chromium through that token (cookies, saved logins, file:// reads). The uid
 * split is an identification for the add-on wall, not a containment boundary; closing that
 * gap is the CROW_BOT_UID containment arc.
 */
import { spawn } from "node:child_process";
import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import { constants, closeSync, existsSync, mkdirSync, openSync, readdirSync, readFileSync, renameSync, rmSync, statSync, writeSync } from "node:fs";
import http from "node:http";
import net from "node:net";
import { basename, dirname, join } from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

/** The longest request head the relay reads; Node answers 431 beyond it. */
export const MAX_HEADER_BYTES = 16 * 1024;
/** How long a connection may take to send its request head (no slowloris). */
export const HANDSHAKE_TIMEOUT_MS = 10_000;
/** Concurrent connections, HTTP and WebSocket together. */
export const MAX_CONNECTIONS = 32;
/** Largest frame in either direction: one CDP message, from a client or from Chromium. The
 *  pipe framer closes (and so the browser stops) past it, so it matches Playwright's own
 *  client limit: a page cannot make one message big enough to stop the browser below that. */
export const MAX_FRAME_BYTES = 256 * 1024 * 1024;
/** Per-client output BACKLOG; past it that client alone is dropped (close 1009). A client whose
 *  buffer is empty may still take one message up to MAX_FRAME_BYTES, so a single large message
 *  never drops an idle client, while a slow one cannot pile up hundreds of MB in a container
 *  whose memory limit is shared with Chromium. */
export const MAX_CLIENT_BUFFER_BYTES = 64 * 1024 * 1024;
/** How long a graceful stop waits for Chromium to close itself after `Browser.close`. */
export const CLOSE_TIMEOUT_MS = 10_000;
/** How long the stop path waits for the pipe to reach EOF before it escalates — twice. */
const STOP_EOF_MS = 2000;
/** The gate's start budget: attach, auto-attach, Fetch on every existing page, verify. */
export const START_DEADLINE_MS = 10_000;
/** How long an intent client may take between its upgrade and `Crow.guardReady`. */
export const CONNECTING_DEADLINE_MS = 30_000;
/** The budget for one cleanup, and the commit wait of one page inside it (the cleanup
 *  itself is the relay's next step; the numbers travel with the caps so an operator cannot
 *  switch anything on or off with them). */
export const CLEANUP_BUDGET_MS = 5_000;
export const COMMIT_BUDGET_MS = 3_000;
/** The grace after a gate session's detach before the target list is read again (gate loss). */
export const SETTLE_MS = 500;
/**
 * How long a reply to `Target.createTarget` / `Target.attachToTarget` may wait for the client's
 * OWN `Target.attachedToTarget` to go out first (see `holdResponse`). Past it the client gets an
 * error for the command: a reply it cannot use is worse than a failure it can act on.
 */
export const RESPONSE_HOLD_MS = 5_000;
/**
 * The guard's init-script marker. `bundles/browser/server/private-address.js` installs a
 * main-world init script whose source contains this string (as `// <marker>`), and the
 * gate's coverage rule looks for it with a "contains" test — Playwright wraps every init
 * script in `(() => { ... })();`, so it is never the first line of the CDP `source`.
 */
const GUARD_MARKER = "crow-private-address-guard:v1";
/**
 * Chromium's OWN component-extension ids the gate leaves alone — a fixed set pinned in code,
 * and nothing else.
 *
 * Chromium 145.0.7632.6 (Playwright 1.58.2's chromium-1208) LISTS one as
 * `service_worker chrome-extension://nkeimhogjdpnpccoofpliimaahmaaome/thunk.js` and never
 * attaches it, found by a live `Target.getTargets` in the built image over 16 starts. Because
 * it is never attached, the attach path can never grant it its exemption: the listing has to.
 * That id stays on the list so a rollback, or an install still pinned to the older lock,
 * keeps resolving.
 *
 * Chromium 159.0.8154.6 (since 1.9.1, Playwright 1.65.1's chromium-1255) has TWO of them, both
 * `service_worker chrome-extension://<id>/background.js`, seen at start in 3 of 3 fresh-profile
 * starts on the real image. Both are VERIFIED against Chromium's own source at tag 159.0.8154.6:
 *   - admccjkmockfdflocgggjfgdacdodkdf is extension_misc::kGlicExtensionId, "the Gemini transition
 *     extension" (chrome/common/extensions/extension_constants.h line 58);
 *   - glbjnfimcajjenihimblfaponejbkoph is extension_misc::kContextualTasksExtensionId, "the
 *     Contextual Tasks component extension" (extensions/common/constants.h lines 336-338);
 * and both are members of IsComponentExtensionAllowlisted()'s kAllowed set
 * (chrome/browser/extensions/component_extensions_allowlist/allowlist.cc lines 44-45): Chromium's
 * own built-in component extensions — not a foreign or a guessed id.
 *
 * An allow-listed id that is absent is fine. Any OTHER extension worker before the gate is
 * ready is NOT exempt: the start fails closed, with one log line naming the id, so a Chromium
 * upgrade that changes these ids is visible to an operator instead of silently tolerated. The
 * exemption is PRE-READY ONLY, for both ids: it covers a service worker whose targetId was
 * recorded before the gate was ready, and nothing that shows up after that.
 */
const COMPONENT_EXTENSION_IDS = new Set(["nkeimhogjdpnpccoofpliimaahmaaome", "admccjkmockfdflocgggjfgdacdodkdf", "glbjnfimcajjenihimblfaponejbkoph"]);
/** The token shape Crow mints (hex32 or base64url) — the same rule the entrypoint applies. */
export const TOKEN_RE = /^[A-Za-z0-9_-]{32,256}$/;
/** How long the supervisor waits for the relay's one "ready <json>" line (the entrypoint waits 60 s). */
export const READY_TIMEOUT_MS = 60_000;
/** The largest ready line the supervisor accepts; anything bigger is a broken relay. */
const MAX_READY_LINE_BYTES = 4096;
/** The largest uid/gid accepted (the Linux id_t ceiling): anything else is a typo, not an id. */
const MAX_ID = 2147483647;
/** The one privileged helper used to start the relay on another uid (`util-linux`, in the base image). */
const SETPRIV = "/usr/bin/setpriv";
/** This script, absolutely, for the supervisor's re-exec (no relative path ever). */
const SELF = fileURLToPath(import.meta.url);
/**
 * The ONLY variables the supervisor gives the relay: a path to start with, the port, the
 * token's FILE (a path, never the token), the debug flag and the caps. Everything else of
 * the supervisor's environment stays with the supervisor — and none of these is a secret
 * except in name, which is why the token's location is a path and the value is in a file.
 */
const RELAY_ENV_KEYS = [
  "PATH", "CDP_PORT", "CROW_CDP_TOKEN_FILE", "CROW_CDP_DEBUG",
  "CROW_CDP_MAX_FRAME", "CROW_CDP_MAX_CLIENT_BUFFER", "CROW_CDP_MAX_CONNECTIONS", "CROW_CDP_MAX_HEADER",
  "CROW_CDP_HANDSHAKE_TIMEOUT_MS", "CROW_CDP_CLOSE_TIMEOUT_MS",
  "CROW_CDP_START_DEADLINE_MS", "CROW_CDP_CONNECTING_DEADLINE_MS", "CROW_CDP_CLEANUP_BUDGET_MS",
  "CROW_CDP_COMMIT_BUDGET_MS", "CROW_CDP_SETTLE_MS", "CROW_CDP_RESPONSE_HOLD_MS",
];

const WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
const LOOPBACK_HOST_RE = /^(127\.0\.0\.1|localhost):(\d{1,5})$/;
/** Env names the Chromium child never sees: whatever holds a secret in this process. */
const SECRET_ENV_RE = /TOKEN|SECRET|PASSWORD/i;

const die = (msg) => {
  console.error(`[cdp-relay] FATAL: ${msg}`);
  process.exit(1);
};

/**
 * Constant-time bearer check.
 *
 * Both sides are hashed first, so the comparison walks a fixed 32 bytes no matter how
 * long or how wrong the presented value is — the timing leaks neither the token's
 * length nor a shared prefix.
 */
export function tokenMatches(presented, expected) {
  if (typeof expected !== "string" || expected === "") return false;
  const a = createHash("sha256").update(typeof presented === "string" ? presented : "").digest();
  const b = createHash("sha256").update(expected).digest();
  return timingSafeEqual(a, b);
}

/**
 * Chromium's `--remote-debugging-pipe` framing: JSON messages, each terminated by a NUL
 * byte, in both directions. Copied from the gateway preview's cdp-pipe.js (an installed
 * bundle cannot import outside its own directory); a frame that does not start with "{"
 * or is over the cap closes the pipe, which takes the relay down with Chromium.
 */
function createPipeFramer({ input, output, maxFrameBytes }) {
  let parts = [];
  let size = 0;
  let done = false;
  const handlers = { message: () => {}, close: () => {} };

  function finish(reason) {
    if (done) return;
    done = true;
    output.off("data", onData);
    output.off("end", onEnd);
    output.off("close", onEnd);
    parts = [];
    size = 0;
    handlers.close(reason);
  }

  function take(bytes) {
    if (!bytes.length) return true;
    if (size === 0 && bytes[0] !== 0x7b) { finish("bad_frame"); return false; }
    size += bytes.length;
    if (size > maxFrameBytes) { finish("bad_frame"); return false; }
    parts.push(bytes);
    return true;
  }

  function onData(chunk) {
    const buf = typeof chunk === "string" ? Buffer.from(chunk) : chunk;
    let start = 0;
    while (!done) {
      const nul = buf.indexOf(0, start);
      if (nul === -1) { take(buf.subarray(start)); return; }
      if (!take(buf.subarray(start, nul))) return;
      start = nul + 1;
      const frame = parts.length === 1 ? parts[0] : Buffer.concat(parts);
      parts = [];
      size = 0;
      let msg;
      try { msg = JSON.parse(frame.toString("utf8")); } catch { finish("bad_frame"); return; }
      if (!msg || typeof msg !== "object" || Array.isArray(msg)) { finish("bad_frame"); return; }
      handlers.message(msg);
    }
  }

  function onEnd() { finish(size > 0 ? "bad_frame" : "eof"); }

  output.on("data", onData);
  output.once("end", onEnd);
  output.once("close", onEnd);
  output.on("error", () => finish("eof"));
  input.on("error", () => finish("eof"));

  return {
    write(msg) {
      if (done) return false;
      try { input.write(JSON.stringify(msg) + "\0"); return true; } catch { return false; }
    },
    on(event, fn) { handlers[event] = fn; },
    isClosed: () => done,
  };
}

/**
 * A minimal RFC 6455 server connection for text frames: the handshake is done by the
 * caller, this is the frame layer (masked client frames, continuation, ping/pong,
 * close). `onText` gets whole messages; `onClose` fires exactly once, after which
 * nothing more is read or written.
 */
function createWsConnection(socket, head, { maxFrameBytes, onText, onClose, onTooBig }) {
  let buf = head && head.length ? Buffer.from(head) : Buffer.alloc(0);
  let parts = [];
  let partsSize = 0;
  let closed = false;
  let closeSent = false;

  socket.setNoDelay(true);
  socket.setTimeout(0); // an idle CDP client is normal: no request timeout applies after the upgrade

  function finish(why) {
    if (closed) return;
    closed = true;
    socket.off("data", onData);
    socket.off("end", onEnd);
    socket.off("close", onEnd);
    socket.off("error", onEnd);
    parts = [];
    partsSize = 0;
    buf = Buffer.alloc(0);
    onClose(why);
  }

  function writeFrame(opcode, payload) {
    if (closed || socket.destroyed || !socket.writable) return false;
    const n = payload.length;
    let header;
    if (n < 126) header = Buffer.from([0x80 | opcode, n]);
    else if (n < 65536) { header = Buffer.alloc(4); header[0] = 0x80 | opcode; header[1] = 126; header.writeUInt16BE(n, 2); }
    else { header = Buffer.alloc(10); header[0] = 0x80 | opcode; header[1] = 127; header.writeBigUInt64BE(BigInt(n), 2); }
    try { return socket.write(Buffer.concat([header, payload])); } catch { return false; }
  }

  function sendClose(code) {
    if (closeSent || closed) return;
    closeSent = true;
    const payload = Buffer.alloc(2);
    payload.writeUInt16BE(code || 1000, 0);
    writeFrame(0x8, payload);
    try { socket.end(); } catch { /* gone */ }
    // Give the close frame time to flush before the fd goes away (the peer must see 1009).
    const t = setTimeout(() => { try { socket.destroy(); } catch { /* gone */ } }, 1000);
    if (typeof t.unref === "function") t.unref();
  }

  function handleFrame(fin, opcode, payload) {
    if (opcode === 0x8) { sendClose(1000); finish("client_close"); return; }
    if (opcode === 0x9) { writeFrame(0xa, payload); return; }
    if (opcode === 0xa) return;
    if (opcode === 0x2) { sendClose(1003); finish("binary_frame"); return; }
    if (opcode !== 0x1 && opcode !== 0x0) { sendClose(1002); finish("bad_opcode"); return; }
    if (opcode === 0x1 && partsSize > 0) { sendClose(1002); finish("interleaved_message"); return; }
    parts.push(payload);
    partsSize += payload.length;
    if (partsSize > maxFrameBytes) { onTooBig(); return; }
    if (!fin) return;
    const text = (parts.length === 1 ? parts[0] : Buffer.concat(parts)).toString("utf8");
    parts = [];
    partsSize = 0;
    onText(text);
  }

  function onData(chunk) {
    buf = buf.length ? Buffer.concat([buf, chunk]) : chunk;
    while (!closed) {
      if (buf.length < 2) return;
      const b0 = buf[0];
      const b1 = buf[1];
      const fin = (b0 & 0x80) !== 0;
      const opcode = b0 & 0x0f;
      const masked = (b1 & 0x80) !== 0;
      let len = b1 & 0x7f;
      let offset = 2;
      // No extension is negotiated, so RSV1-3 must be zero; a client frame is always masked.
      if ((b0 & 0x70) !== 0) { sendClose(1002); finish("reserved_bits"); return; }
      if (!masked) { sendClose(1002); finish("unmasked"); return; }
      if (len === 126) {
        if (buf.length < 4) return;
        len = buf.readUInt16BE(2);
        offset = 4;
      } else if (len === 127) {
        if (buf.length < 10) return;
        const big = buf.readBigUInt64BE(2);
        if (big > BigInt(maxFrameBytes)) { onTooBig(); return; }
        len = Number(big);
        offset = 10;
      }
      if (opcode >= 0x8 && (!fin || len > 125)) { sendClose(1002); finish("bad_control_frame"); return; }
      if (len > maxFrameBytes || partsSize + len > maxFrameBytes) { onTooBig(); return; }
      if (buf.length < offset + 4 + len) return;
      const mask = buf.subarray(offset, offset + 4);
      const payload = Buffer.allocUnsafe(len);
      for (let i = 0; i < len; i++) payload[i] = buf[offset + 4 + i] ^ mask[i & 3];
      buf = buf.subarray(offset + 4 + len);
      handleFrame(fin, opcode, payload);
    }
  }

  function onEnd() { finish("socket_end"); }

  socket.on("data", onData);
  socket.once("end", onEnd);
  socket.once("close", onEnd);
  socket.on("error", onEnd);
  // Permanent: finish() removes onEnd, but the socket can still error while a close frame
  // flushes (sendClose keeps it up to 1 s). An unhandled error would crash the relay.
  socket.on("error", () => {});

  return {
    sendText(text) { return writeFrame(0x1, Buffer.from(text, "utf8")); },
    close(code) { sendClose(code || 1000); finish("relay_close"); },
    bufferedBytes() { return socket.writableLength || 0; },
  };
}

const delay = (ms) => new Promise((resolve) => { const t = setTimeout(resolve, ms); if (typeof t.unref === "function") t.unref(); });

/** CDP_PORT: a port number, 0 for "pick one" (tests), 9222 when unset. */
function parsePort(value) {
  if (value === undefined || value === null || value === "") return 9222;
  const n = Number(String(value).trim());
  return Number.isInteger(n) && n >= 0 && n <= 65535 ? n : null;
}

/**
 * A uid or gid as this bundle accepts it: a decimal integer in 0..MAX_ID, and nothing
 * else. `undefined`, an empty string, "root", a negative number or a name all fail, so a
 * compose file that forgot to pass CROW_GATEWAY_UID stops the container instead of
 * silently listening as root.
 *
 * The value returned is CANONICAL decimal (a Number): "0010" and "10" are the same uid,
 * and the entrypoint's `listener_uid_is` compares the kernel's uid column against this
 * spelling as a string, so a leading zero must never reach setpriv or that comparison.
 * Exported for the unit test of exactly that.
 */
export function parseId(value) {
  const s = typeof value === "string" ? value.trim() : "";
  if (!/^\d{1,10}$/.test(s)) return null;
  const n = Number(s);
  return Number.isInteger(n) && n >= 0 && n <= MAX_ID ? n : null;
}

/** The size caps and timeouts from the environment (never a secret). */
function capsFromEnv() {
  const cap = (name, fallback) => {
    const n = Number(process.env[name]);
    return Number.isInteger(n) && n > 0 ? n : fallback;
  };
  return {
    maxFrameBytes: cap("CROW_CDP_MAX_FRAME", MAX_FRAME_BYTES),
    maxClientBuffer: cap("CROW_CDP_MAX_CLIENT_BUFFER", MAX_CLIENT_BUFFER_BYTES),
    maxConnections: cap("CROW_CDP_MAX_CONNECTIONS", MAX_CONNECTIONS),
    maxHeaderBytes: cap("CROW_CDP_MAX_HEADER", MAX_HEADER_BYTES),
    handshakeTimeoutMs: cap("CROW_CDP_HANDSHAKE_TIMEOUT_MS", HANDSHAKE_TIMEOUT_MS),
    closeTimeoutMs: cap("CROW_CDP_CLOSE_TIMEOUT_MS", CLOSE_TIMEOUT_MS),
    startDeadlineMs: cap("CROW_CDP_START_DEADLINE_MS", START_DEADLINE_MS),
    connectingDeadlineMs: cap("CROW_CDP_CONNECTING_DEADLINE_MS", CONNECTING_DEADLINE_MS),
    // The default here is the relay's own 5_000 ms cleanup budget (CLEANUP_BUDGET_MS): the
    // supervisor's stop budget adds it, so the two numbers have to mean the same thing.
    cleanupBudgetMs: cap("CROW_CDP_CLEANUP_BUDGET_MS", 5_000),
    commitBudgetMs: cap("CROW_CDP_COMMIT_BUDGET_MS", COMMIT_BUDGET_MS),
    settleMs: cap("CROW_CDP_SETTLE_MS", SETTLE_MS),
    responseHoldMs: cap("CROW_CDP_RESPONSE_HOLD_MS", RESPONSE_HOLD_MS),
  };
}

/** The token, read from its 0400 file (never from the environment). */
function readToken() {
  const tokenFile = process.env.CROW_CDP_TOKEN_FILE || "/run/secrets/crow-cdp-token";
  let token = "";
  try { token = readFileSync(tokenFile, "utf8").trim(); } catch { token = ""; }
  if (!TOKEN_RE.test(token)) {
    die(`the CDP token (${tokenFile}) is missing or malformed. Crow generates CROW_BROWSER_CDP_TOKEN at install, in this bundle's .env, and compose hands it in as that file; the relay never opens an ungated port instead.`);
  }
  return token;
}

/** CDP_PORT from the environment, or a fatal. */
function readPort() {
  const port = parsePort(process.env.CDP_PORT);
  if (port === null) die(`CDP_PORT '${process.env.CDP_PORT}' is not a port number`);
  return port;
}

/** The Chromium argv: the test seam first, else CHROME_PATH from the entrypoint. */
function chromiumCommand() {
  const chromePath = process.env.CHROME_PATH || "";
  const seam = process.env.CROW_CDP_CHROMIUM_ARGV;
  if (seam) {
    try {
      const parsed = JSON.parse(seam);
      if (!Array.isArray(parsed) || parsed.length === 0) throw new Error("not an argv");
      return [...parsed.map(String), ...chromiumArguments()];
    } catch { die("CROW_CDP_CHROMIUM_ARGV is not a JSON argv array"); }
  }
  if (!chromePath) die("CHROME_PATH is not set: the entrypoint finds Playwright's Chrome and passes it in");
  return [chromePath, ...chromiumArguments()];
}

/**
 * The relay's report pipe (fd 5): `ready <json>` once, then — for the relay's whole life —
 * the kill line of its stop path, or `closing` for a graceful close. The ready line is the
 * supervisor's cue that Chromium's pipe answered and the port is listening (the same evidence
 * the ready FILE records); every line after it goes to `onReport`, and so does EOF (`null`).
 *
 * ONE reader for the fd's whole life, installed before the first byte arrives: closing the
 * ready-line reader and opening a second one would leave a gap, and a `kill` written in the
 * same chunk as the ready line would be dropped in it. A line that arrives beside the ready
 * line is therefore handled now, not lost.
 */
function readReadyLine(stream, timeoutMs, onReport) {
  return new Promise((resolve, reject) => {
    let buf = "";
    let isReady = false;
    let settled = false;
    let ended = false;
    const report = typeof onReport === "function" ? onReport : () => {};
    if (!stream) { reject(new Error("the relay has no report pipe (fd 5)")); return; }
    const off = () => {
      stream.off("data", onData);
      stream.off("end", onEnd);
      stream.off("close", onEnd);
      stream.off("error", onReportError);
      // The fd outlives this reader: a late error on it must never become an uncaught one.
      stream.on("error", () => {});
    };
    const settle = (fn, value) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      fn(value);
    };
    const timer = setTimeout(() => settle(reject, new Error(`the relay did not report ready within ${Math.round(timeoutMs / 1000)}s`)), timeoutMs);
    if (typeof timer.unref === "function") timer.unref();
    function onData(chunk) {
      buf += typeof chunk === "string" ? chunk : chunk.toString("utf8");
      let nl;
      while ((nl = buf.indexOf("\n")) >= 0) {
        const line = buf.slice(0, nl).replace(/\r$/, "");
        buf = buf.slice(nl + 1);
        if (!isReady) {
          const m = /^ready (\{.*\})$/.exec(line.trim());
          if (!m) { off(); settle(reject, new Error("the relay's first line on fd 5 was not a ready line")); return; }
          let info = null;
          try { info = JSON.parse(m[1]); } catch { info = null; }
          if (!info || typeof info !== "object" || !Number.isInteger(info.port) || info.port < 1 || info.port > 65535) {
            off();
            settle(reject, new Error("the relay's ready line carried no port"));
            return;
          }
          isReady = true;
          settle(resolve, info);
          continue;
        }
        report(line);
      }
      if (buf.length > MAX_READY_LINE_BYTES) {
        if (!isReady) { off(); settle(reject, new Error("the relay's ready line is too long")); return; }
        // Not a line and never will be: a broken relay either way, so hand it over as one.
        const overlong = buf;
        buf = "";
        report(overlong);
      }
    }
    function onEnd() {
      if (ended) return;
      ended = true;
      off();
      if (!isReady) { settle(reject, new Error("the relay closed fd 5 without reporting ready")); return; }
      report(null);
    }
    function onReportError() {
      if (ended) return;
      ended = true;
      off();
      if (!isReady) { settle(reject, new Error("the relay's ready pipe failed")); return; }
      report(null);
    }
    stream.on("data", onData);
    stream.once("end", onEnd);
    stream.once("close", onEnd);
    stream.once("error", onReportError);
  });
}

/**
 * What one line on the report pipe means to the supervisor.
 *
 * `closing` is the relay's graceful close: Browser.close went out after a clean scan, so fd 5's
 * EOF and the relay's own exit are expected and Chromium's own exit is what is waited for. It
 * softens nothing else: `kill` and every other line is the stop path in every state, and EOF
 * is a kill unless `closing` came first.
 */
export function relayReportAction(line, { closing = false } = {}) {
  if (line === null) return closing ? "wait" : "kill";
  return String(line).trim() === "closing" ? "closing" : "kill";
}

/**
 * Start the relay: spawn Chromium on a pipe, wait until the pipe answers
 * `Browser.getVersion`, then listen on 127.0.0.1:`port` for gated clients.
 *
 * Message flow: a client's sessionless command is stamped with its own browser session
 * (`S_c`) and given a relay-wide id; the response to that id goes back to that client
 * with its original id, and without `sessionId` when it is `S_c`; an event carrying a
 * session goes to that session's owner (also stripped when it is `S_c`); a reply the RELAY
 * itself synthesised (`Crow.*`, a refusal) follows the same rule about `sessionId`
 * (`replyTo`) — a sessionless reply would be routed to Playwright's root session and kill
 * the MCP; a message
 * naming a session the client does not own is answered -32001 and never forwarded; and
 * a disconnecting client's child sessions and then its `S_c` are detached while its
 * pending ids are discarded, so a late response has nowhere to go but the bin.
 */
export async function createRelay(config) {
  const {
    token,
    port = 9222,
    chromiumArgv,
    pipe = null,
    /** `--attach` only: write `kill\n` on fd 5 and return true, or return false. */
    killLine = null,
    /**
     * `--attach` only: write `closing\n` on fd 5 (before Browser.close) and return true, or
     * return false. The supervisor then waits for Chromium's own exit instead of killing it
     * when fd 5 reaches EOF.
     */
    closingLine = null,
    childEnv = process.env,
    log = () => {},
    debug = () => {},
    compareToken = tokenMatches,
    maxFrameBytes = MAX_FRAME_BYTES,
    maxClientBuffer = MAX_CLIENT_BUFFER_BYTES,
    maxConnections = MAX_CONNECTIONS,
    maxHeaderBytes = MAX_HEADER_BYTES,
    handshakeTimeoutMs = HANDSHAKE_TIMEOUT_MS,
    closeTimeoutMs = CLOSE_TIMEOUT_MS,
    startDeadlineMs = START_DEADLINE_MS,
    connectingDeadlineMs = CONNECTING_DEADLINE_MS,
    cleanupBudgetMs = CLEANUP_BUDGET_MS,
    commitBudgetMs = COMMIT_BUDGET_MS,
    settleMs = SETTLE_MS,
    responseHoldMs = RESPONSE_HOLD_MS,
  } = config || {};

  if (!TOKEN_RE.test(String(token || ""))) throw new Error("the CDP token is missing or malformed");
  // Two ways to own the pipe: spawn Chromium here (the pre-1.7.0 shape, and what the unit
  // tests drive), or attach to the pipe the supervisor handed over on fds 3 and 4.
  const pipeMode = !!(pipe && typeof pipe === "object" && pipe.input && pipe.output);
  if (!pipeMode && (!Array.isArray(chromiumArgv) || chromiumArgv.length === 0)) throw new Error("no Chromium command");

  let child = null;
  let input;
  let output;
  if (pipeMode) {
    input = pipe.input;
    output = pipe.output;
  } else {
    // Chromium is its own process group (detached): one kill then reaches its renderers and
    // zygotes, which is what makes "the relay dies, Chromium dies" true on the paths this
    // process cannot run code on. Belt and braces: Chromium exits on pipe EOF too, and the
    // supervisor treats a dead relay as a dead container.
    const safeEnv = {};
    for (const [k, v] of Object.entries(childEnv)) if (!SECRET_ENV_RE.test(k)) safeEnv[k] = v;
    child = spawn(chromiumArgv[0], chromiumArgv.slice(1), {
      stdio: ["ignore", "inherit", "inherit", "pipe", "pipe"],
      detached: true,
      env: safeEnv,
    });
    input = child.stdio[3];
    output = child.stdio[4];
  }

  let childExited = pipeMode;
  // In pipe mode the framer's close IS "Chromium is gone": its end of the pipe went away.
  // `pipeCode` is the exit code that event reports, so an exit route that finds the pipe
  // already closed can still exit on it.
  let pipeGone = false;
  let pipeCode = 1;
  let resolvePipeClosed = () => {};
  const pipeClosed = new Promise((resolve) => { resolvePipeClosed = resolve; });
  const exited = pipeMode ? pipeClosed : new Promise((resolve) => {
    child.once("exit", (code, signal) => { childExited = true; resolve({ code, signal }); });
    child.once("error", (err) => {
      childExited = true;
      console.error(`[cdp-relay] FATAL: cannot start Chromium (${err && err.code ? err.code : "error"})`);
      resolve({ code: 127, signal: null });
    });
  });

  let stopping = false;
  /** True once `closing` went out on fd 5: a graceful close, and the exit hook owes no kill. */
  let closingReported = false;
  /**
   * True once a `Browser.close` has actually been WRITTEN to the pipe, by either path (the stop
   * path's own write, or a client's close forwarded by `handleBrowserClose`). It is what tells a
   * later `shutdown()` that the cleanup owed for that close has already run: what a joining stop
   * owes then is the wait for Chromium's exit, never a second cleanup.
   */
  let closeForwarded = false;
  /** True once `kill` went out on fd 5: it is written once, never again by the exit hook. */
  let killReported = false;

  /**
   * Tell the supervisor that this is a graceful close: `closing` on the report pipe, written
   * before Browser.close. Only `--attach` has a supervisor to tell, and it is told once.
   */
  function reportClosing() {
    if (closingReported) return true;
    if (typeof closingLine !== "function") return false;
    try { if (closingLine() !== true) return false; } catch { return false; }
    closingReported = true;
    return true;
  }

  /**
   * Tell the supervisor the browser has to be stopped now: `kill` on the report pipe. Written
   * once per process — the stop path writes it, and the exit hook is then owed nothing.
   */
  function reportKill() {
    if (killReported) return true;
    if (typeof killLine !== "function") return false;
    try { if (killLine() !== true) return false; } catch { return false; }
    killReported = true;
    return true;
  }

  /** SIGKILL the Chromium child's whole process group (no-flag mode owns the child). */
  function signalChromiumGroup(signal = "SIGKILL") {
    if (pipeMode || !child || !child.pid || childExited) return false;
    try { process.kill(-child.pid, signal); return true; } catch { /* the group is gone */ }
    try { child.kill(signal); return true; } catch { /* the process is gone */ return false; }
  }

  function killChromium(signal = "SIGKILL") {
    if (pipeMode) {
      // There is no child of ours to signal: the pipe is the whole relationship. Closing it
      // here is exactly what must NOT happen while pages are live — it drops every session and
      // releases every paused request and held target (S1 e1, e2) before Chromium is dead — so
      // a live browser is stopped through the one stop path. With the pipe already closed,
      // Chromium is gone and all that is left is this process's exit, on the pipe's own code.
      if (pipeGone) { process.exit(pipeCode); return; }
      stopPath("Chromium has to be stopped while this relay is still serving");
      return;
    }
    signalChromiumGroup(signal);
  }

  if (!input || !output) {
    killChromium();
    throw new Error(pipeMode ? "the pipe arrived without both fds (3 and 4)" : "Chromium did not get its pipe (fds 3 and 4)");
  }
  const framer = createPipeFramer({ input, output, maxFrameBytes });

  const relayId = randomBytes(16).toString("hex");
  const clients = new Set();
  /** relay id → { client, originalId, method } — a client's in-flight command. */
  const pending = new Map();
  /** relay id → handler — the relay's own commands (bootstrap, getVersion, detach). */
  const internal = new Map();
  /** CDP sessionId → the client that owns it (its `S_c` and every child session). */
  const sessionOwner = new Map();
  const stats = { clientsCreated: 0, activeClients: 0, sessionlessEvents: 0, orphanEvents: 0, refused: 0, slowDropped: 0, closed: 0, framesIn: 0, framesOut: 0 };
  let nextId = 1;
  let clientSeq = 0;
  let actualPort = port;

  // -----------------------------------------------------------------------------------
  // The guard gate.
  //
  // The gate is relay code and knows nothing about addresses: it decides whether a guard is
  // DEMONSTRABLY present for a page right now, and fails every request from a page where it
  // is not. It has NO off switch (no env var, argv flag, header or option disables it).
  //
  // It attaches its own session to the browser target before a single client can connect,
  // so it is the oldest auto-attacher and the oldest Fetch interceptor on every page that
  // exists at start and every page created later (S1's ordering facts). Its session ids live
  // in `gateSessions`, never in `sessionOwner`, so a client that guesses one is answered
  // "Session not owned" like any other unowned session, and its events are relay code's own
  // (never forwarded, never counted as client traffic).
  // -----------------------------------------------------------------------------------

  /** False from here until the start sequence finished: upgrades 503, no `Crow-Guard`. */
  let gateReady = false;
  /** null until the gate is ready; then IDLE | CONNECTING | GUARDED | CLEANUP. */
  let gateState = null;
  /** The gate's own browser-level session: the oldest auto-attacher on every page. */
  let gateBrowserSession = null;
  /** True once the stop path ran: the relay is on its way out, nothing else is decided. */
  let gateLost = false;
  /**
   * gate sessionId → { targetId, type, url, parent, ownerTargetId, dead }. Entries are never
   * deleted: a late event for a gate session that has gone away must not fall through to the
   * owner lookup (where it would be counted as an orphan). Everything is keyed by sessionId,
   * never by targetId (an iframe target's id is its frame id and survives a swap).
   */
  const gateSessions = new Map();
  /** targetId → the gate's record of that target (created by `newGateTarget`). */
  const gateTargets = new Map();
  /** client sessionId → targetId, from Chromium's own attach events and responses ONLY. */
  const clientSessionTarget = new Map();
  /** client sessionId → the session whose attach event carried it (its parent), or null. */
  const sessionParent = new Map();
  /** client sessionId → { fetchAll, markerIdentifier }: what the relay saw that session send. */
  const sessionCoverage = new Map();
  /** child sessionId → { client, targetId }: attach events a client must never see. */
  const swallowedSessions = new Map();
  /** Request ids the gate's own sessions are holding: no client may answer one. */
  const gateRequestIds = new Set();
  /**
   * The targetIds of ALLOW-LISTED component-extension SERVICE workers recorded while the gate
   * was still starting — by an attach event (`onGateAttached`) or by one of the gate's own
   * listings (`listGateTargets`; Chromium 145 lists one as `thunk.js` and never attaches it, so
   * a listing is the only place that one is ever seen, and it has no `gateTargets` record).
   *
   * The ID is the exemption, never an origin. This set is written only while `!gateReady`, and
   * `onGateAttached` reads it afterwards: a worker whose targetId is not in it is closed like
   * any other, so a LATER worker at an allow-listed id — a second service worker, a SharedWorker
   * a document starts — is a new targetId and is never exempt. A `shared_worker` is never
   * recorded at all: it belongs to a document at that origin, not to the browser.
   */
  const exemptTargetIds = new Set();
  /** The extension ids already logged as unknown at start: one line per id, never more. */
  const unknownExtensionIds = new Set();
  /**
   * Why the start must STOP rather than neutralise, or null: an extension worker off the
   * component allow-list, and nothing else. Read once, by `startGate`, which fails closed and
   * stops Chromium.
   */
  let startFatalFailure = null;
  /**
   * The DEFAULT browser context's id, learned from Chromium's own `Target.getBrowserContexts`
   * (`defaultBrowserContextId`). A real Chromium reports an opaque hex string there and does
   * NOT list the default context in `browserContextIds`, so comparing against the literal
   * "default" would call the real default context non-default — and the start sequence and
   * every cleanup would fail. Null until learned (an older or fake build that does not report
   * it): "default" and an absent id are the default context then, as they always were.
   */
  let defaultContextId = null;
  /** The one cleanup in flight, or null: a cleanup runs once at a time. */
  let cleanupRun = null;
  /** The replacement page of the cleanup on the move: resumed at once, never navigated. */
  let cleanupReplacementId = null;
  /**
   * How many asks for a `Browser.close` are outstanding. A COUNT, never one flag, because two
   * different owners ask — the stop path (`shutdown()`, SIGTERM) and a client's `Browser.close`
   * — and neither may undo the other's ask. Above zero, the cleanup that comes back clean must
   * NOT re-open the gate: Chromium keeps running its pages between `Browser.close` and its own
   * exit (pagehide beacons, image requests), so a gate that declared itself open in that window
   * would pass them.
   *
   * `shutdown()` increments it and never decrements — a SIGTERM stop is terminal, so the count
   * can only return to zero on the client path. `handleBrowserClose()` increments it before the
   * cleanup and decrements it when no `Browser.close` goes out at all (its asker is gone, or the
   * stop path owns the exit); only with the count back at zero, nothing stopping, and a clean
   * scan does the gate re-open. Both increment BEFORE the cleanup runs, so a cleanup already in
   * flight that they join honours them too (the counter is read when the run ends).
   */
  let closeIntents = 0;
  /** Resolvers waiting for the cleanup to reach IDLE (new upgrades, held client input). */
  const idleWaiters = [];
  /** gate sessionId → { seen: Set<loaderId>, waiters: [{ loaderIds, resolve }] } (commits). */
  const commitWatch = new Map();

  /** A gate command: the `internal` map plus the gate session on the envelope. Never throws. */
  function gateRequest(sessionId, method, params = {}, timeoutMs = 5000) {
    return new Promise((resolve) => {
      const id = nextId++;
      const timer = setTimeout(() => { internal.delete(id); resolve(null); }, timeoutMs);
      if (typeof timer.unref === "function") timer.unref();
      internal.set(id, (msg) => {
        clearTimeout(timer);
        resolve(msg && msg.error ? { error: msg.error } : msg && msg.result ? { result: msg.result } : null);
      });
      const frame = { id, method, params };
      if (sessionId) frame.sessionId = sessionId;
      if (!pipeSend(frame)) { clearTimeout(timer); internal.delete(id); resolve(null); }
    });
  }

  /** Wait for the pipe to reach EOF (Chromium's end closed), or give up after `ms`. */
  const waitPipeClosed = (ms) => Promise.race([pipeClosed.then(() => true), delay(ms).then(() => false)]);

  /**
   * THE ONE STOP PATH.
   *
   * Something showed that the gate is no longer in front of the pages — gate loss, a cleanup
   * that cannot be made clean, a `Browser.close` that may not be written. Chromium is stopped
   * by the only route that touches no session: never `Browser.close`, which runs every
   * pagehide/unload the pages have queued, and never by destroying the pipe, which drops every
   * session and releases every paused request and held target first (S1 e1, e2). Nothing is
   * closed, detached or otherwise waved through on the way.
   *
   * In `--attach` the supervisor owns Chromium, so the relay writes `kill` on fd 5 and waits for
   * the pipe to reach EOF (2 s); past that it asks the browser to crash itself (`Browser.crash`)
   * and waits 2 s more; then it exits non-zero regardless. A write that fails skips straight to
   * the crash. In no-flag mode this process owns the Chromium child, so it SIGKILLs the whole
   * process group and exits non-zero. Every other exit route that runs while pages may be live
   * comes through here.
   */
  function stopPath(reason) {
    if (gateLost) return;
    gateLost = true;
    gateReady = false;
    stopping = true; // no other route decides anything from here
    log(`the stop path: ${reason} — Chromium is stopped before any session goes away`);
    // Chromium's death is what ends this process; the exit code below is the belt for a
    // browser that dies with code 0, and the hard bound for a supervisor that never acts.
    process.exitCode = 1;
    void (async () => {
      if (typeof killLine !== "function") {
        // Nobody above us owns the browser: the group kill IS the stop.
        signalChromiumGroup("SIGKILL");
        process.exit(1);
        return;
      }
      let wrote = false;
      wrote = reportKill();
      if (wrote && (await waitPipeClosed(STOP_EOF_MS))) { process.exit(1); return; }
      // The supervisor did not act, or the line never reached it: the browser is asked to
      // crash itself, which stops it without a graceful close (no unload, no beacons).
      if (gateBrowserSession) pipeSend({ id: nextId++, method: "Browser.crash", params: {}, sessionId: gateBrowserSession });
      await waitPipeClosed(STOP_EOF_MS);
      process.exit(1);
    })();
  }

  /**
   * The gate's record of one target. `covered` holds the CLIENT SESSION ids that demonstrably
   * guard it right now (a G client's own session with `Fetch.enable {*}` and the marker script
   * both acknowledged); `acks` is the promise of the gate's own interception on the current
   * gate session of this target, which is what a client-bound attach event waits for.
   */
  function newGateTarget(targetId, type, url, ownerTargetId) {
    return {
      targetId,
      type,
      url,
      gateSessionId: null,
      gateSessions: new Set(),
      covered: new Set(),
      held: false,
      resumed: false,
      closed: false,
      /**
       * True only when the GATE ITSELF closed this target (`closeGateTarget`, and the cleanup's
       * own close paths). `closed` is also set by Chromium events the gate never chose — a
       * crash, a destroy, a settle that finds the target gone — and those may not take the
       * request rule with them: a page that CRASHED is not a page the gate closed.
       */
      gateClosed: false,
      exemptWorker: false,
      ownerTargetId: ownerTargetId || null,
      acks: Promise.resolve(true),
      ackEpoch: null,
      ackOk: null,
      /** Client-bound `Target.attachedToTarget` events held for the gate's acks, in order. */
      pendingEvents: [],
      /**
       * Replies held behind those events, in order: `{ client, out, command, timer }`. A reply
       * to the command that created or attached this target hands the client a target id it
       * looks up AT ONCE, so it may only go out after the events above (see `holdResponse`).
       */
      heldResponses: [],
    };
  }

  /** Every client a guard: it declared intent with the header AND sent `Crow.guardReady`. */
  function isGuardClient(client) {
    return !!(client && !client.closed && client.intent && client.declared);
  }

  /** The gate's state line. One per transition, and only once the gate is ready. */
  function setState(next) {
    if (!gateReady || gateState === next) return;
    gateState = next;
    log(`gate state ${next}`);
    if (next === "IDLE" || next === "GUARDED") reconcileAll();
  }

  function recomputeState() {
    if (!gateReady) return;
    // The cleanup owns the state until it ends: a client that connects during it must not move
    // the gate to CONNECTING/GUARDED, which would let requests through mid-cleanup.
    if (gateState === "CLEANUP") return;
    let guards = 0;
    let connecting = 0;
    for (const client of clients) {
      if (client.closed || !client.intent) continue;
      if (client.declared) guards++;
      else connecting++;
    }
    if (guards > 0) setState("GUARDED");
    else if (connecting > 0) setState("CONNECTING");
    else setState("IDLE");
  }

  // -----------------------------------------------------------------------------------
  // The cleanup (plan section 4): the relay's own, because nothing else can run it once the
  // guard-bearing client is dead. Every command goes out on the gate's own sessions, and the
  // gate's request rule is already failing everything from the moment CLEANUP starts.
  // -----------------------------------------------------------------------------------

  /** The commit watcher of one gate page session. */
  function commitEntry(sessionId) {
    let entry = commitWatch.get(sessionId);
    if (!entry) { entry = { seen: new Set(), waiters: [] }; commitWatch.set(sessionId, entry); }
    return entry;
  }

  /** A page committed when the gate's OWN session saw `Page.frameNavigated` for its loaderId. */
  function onGateFrameNavigated(sessionId, params) {
    const frame = params && params.frame && typeof params.frame === "object" ? params.frame : null;
    const loaderId = frame && typeof frame.loaderId === "string" ? frame.loaderId : null;
    if (!loaderId) return;
    const entry = commitEntry(sessionId);
    entry.seen.add(loaderId);
    for (const waiter of [...entry.waiters]) {
      if (!waiter.loaderIds.has(loaderId)) continue;
      entry.waiters.splice(entry.waiters.indexOf(waiter), 1);
      waiter.resolve(true);
    }
  }

  /**
   * Watch one page session for the commit of a navigation whose `loaderId` arrives with the
   * `Page.navigate` REPLY. A reply can be written after the commit event it belongs to (a
   * delayed reply), so loader ids the gate saw before `add()` count too.
   */
  function watchCommit(sessionId, timeoutMs) {
    const entry = commitEntry(sessionId);
    const waiter = { loaderIds: new Set(), resolve: () => {} };
    let settle = () => {};
    const committed = new Promise((resolve) => { settle = resolve; });
    const timer = setTimeout(() => {
      const at = entry.waiters.indexOf(waiter);
      if (at >= 0) entry.waiters.splice(at, 1);
      settle(false);
    }, Math.max(50, timeoutMs));
    if (typeof timer.unref === "function") timer.unref();
    waiter.resolve = (value) => { clearTimeout(timer); settle(value); };
    entry.waiters.push(waiter);
    const add = (loaderId) => {
      if (typeof loaderId !== "string" || !loaderId) return;
      waiter.loaderIds.add(loaderId);
      if (!entry.seen.has(loaderId)) return;
      const at = entry.waiters.indexOf(waiter);
      if (at >= 0) entry.waiters.splice(at, 1);
      waiter.resolve(true);
    };
    return { add, committed };
  }

  /** A gate target's record once it has a live gate session, or null when it never gets one. */
  function waitForGateSession(targetId, timeoutMs) {
    return new Promise((resolve) => {
      const deadlineAt = Date.now() + timeoutMs;
      const tick = () => {
        const record = gateTargets.get(targetId);
        if (record && !record.closed && record.gateSessionId) { resolve(record); return; }
        if (Date.now() >= deadlineAt) { resolve(null); return; }
        const timer = setTimeout(tick, 20);
        if (typeof timer.unref === "function") timer.unref();
      };
      tick();
    });
  }

  /**
   * Is what exists at start ALREADY the neutral state the cleanup leaves — one page, at
   * `about:blank`, one history entry, no opener, the default context, nothing else but
   * Chromium's own component-extension workers? That page is the browser's own fresh start page
   * (Chromium was launched on `about:blank`), not a restored tab and not a pre-ready VNC
   * document: a navigation in the pre-ready window grows its history, which takes the full
   * neutralisation below. So does anything else — a second tab, a bot page from an earlier life,
   * a non-default context.
   */
  async function startPagesAreClean() {
    const listed = await listGateTargets();
    if (!listed) return false;
    // A browser that starts with a context of its own is not at the neutral state either, even
    // when the only page in the listing is a clean default-context one.
    const contexts = noteDefaultContext(await gateRequest(gateBrowserSession, "Target.getBrowserContexts", {}, 2000));
    const contextIds = contexts && contexts.result && Array.isArray(contexts.result.browserContextIds) ? contexts.result.browserContextIds : null;
    if (!contextIds) return false;
    for (const contextId of contextIds) {
      if (typeof contextId === "string" && !isDefaultContext(contextId)) return false;
    }
    let page = null;
    for (const [targetId, info] of listed) {
      if (info.type === "page") {
        if (page) return false;
        page = { targetId, info };
        continue;
      }
      // A component extension's SERVICE worker is Chromium's own, and is not page content: it
      // is tolerated as the gate's EXEMPT one — attached before ready, or only listed at start
      // at an allow-listed id (see `exemptTargetIds`). Anything else — a shared worker at that
      // same id included — is a target the gate is not in front of, so this is not the neutral
      // state: the full neutralisation runs and closes it. That is a NEUTRALISATION, not a start
      // failure — only a service worker whose extension id is off the allow-list stops a start
      // (see `noteStartExtensionWorker`).
      if (isExemptNonPageTarget(targetId)) continue;
      return false;
    }
    if (!page) return false;
    const info = page.info;
    if (info.openerId) return false;
    // Exactly `about:blank`: a missing (or non-string) url says nothing about what the page is.
    if (info.url !== "about:blank") return false;
    if (!isDefaultContext(info.browserContextId)) return false;
    const record = gateTargets.get(page.targetId);
    if (!record || !record.gateSessionId) return false;
    const history = await gateRequest(record.gateSessionId, "Page.getNavigationHistory", {}, 2000);
    const entries = history && history.result && Array.isArray(history.result.entries) ? history.result.entries : null;
    return !!(entries && entries.length === 1);
  }

  /**
   * Steps a to e of section 4, on the gate's own sessions. True when the scan came back clean;
   * false hands the caller to the stop path — and NOTHING on that path is closed, because a
   * page whose commit was never observed is a document the cleanup did not leave.
   */
  async function runCleanupSequence() {
    if (!gateBrowserSession) return false;
    const deadlineAt = Date.now() + cleanupBudgetMs;
    const left = () => Math.max(0, deadlineAt - Date.now());
    const budget = (ms) => Math.max(100, Math.min(ms, left()));

    // (a) The fresh replacement, ALWAYS first: headful Chromium exits on its last page, and no
    // page the bot (or a pre-ready document) left is trusted by its URL — a scripted
    // about:blank popup keeps its opener's script and a reused page keeps its history.
    const created = await gateRequest(gateBrowserSession, "Target.createTarget", { url: "about:blank" }, budget(2000));
    const replacementId = created && created.result && typeof created.result.targetId === "string" ? created.result.targetId : null;
    if (!replacementId) return false;
    cleanupReplacementId = replacementId;
    const replacement = await waitForGateSession(replacementId, budget(2000));
    if (!replacement) return false;

    // The pages that exist: the gate's own records, plus anything the browser lists that the
    // gate has not recorded yet (a target created a moment ago). A page with no gate session is
    // a page the gate is not in front of, so it is never navigated, closed or trusted.
    const pageIds = new Set();
    const listed = await listGateTargets();
    if (listed) for (const [targetId, info] of listed) if (info.type === "page") pageIds.add(targetId);
    for (const [targetId, record] of gateTargets) if (record.type === "page" && !record.closed) pageIds.add(targetId);
    const pages = [];
    for (const targetId of pageIds) {
      if (targetId === replacementId) continue; // the replacement is never navigated
      const record = await waitForGateSession(targetId, budget(1000));
      if (!record) return false;
      pages.push(record);
    }

    // (b) The pages the gate never resumed run nothing: each is closed AS IT IS — no
    // `Page.enable`, no navigate, no commit to wait for. A live (resumed) page keeps the
    // navigate -> observed commit -> close rule below.
    const livePages = [];
    for (const record of pages) {
      if (record.resumed) { livePages.push(record); continue; }
      record.closed = true;
      record.gateClosed = true; // the GATE closed it: its requests fail in every state
      record.resumed = true;
      dropGateEvents(record);
      await gateRequest(gateBrowserSession, "Target.closeTarget", { targetId: record.targetId }, budget(1000));
    }

    // Script execution off on EVERY live page session AT ONCE, before the `Page.enable` round
    // trips: while requests already fail, an open socket or a timer must not get one more word
    // out (S5 case 7 kept it). It is never turned back on — each live page is closed after its
    // commit.
    await Promise.all(livePages.map((record) => gateRequest(record.gateSessionId, "Emulation.setScriptExecutionDisabled", { value: true }, budget(1000))));

    // `Page.enable` on the gate's page sessions for the WHOLE cleanup: the commit event needs
    // it, not only a dialog.
    for (const record of livePages) {
      const prepared = await gateRequest(record.gateSessionId, "Page.enable", {}, budget(1000));
      if (!prepared || prepared.error) return false;
    }
    await gateRequest(replacement.gateSessionId, "Page.enable", {}, budget(1000));

    // (c) Every live page is navigated to about:blank — pages already at about:blank too — and
    // the commit is OBSERVED, per page, on the gate's own session (the loaderId `Page.navigate`
    // returned; never a URL read back from `Target.getTargets`, which never shows the commit).
    const committed = [];
    for (const record of livePages) {
      const sessionId = record.gateSessionId;
      const watcher = watchCommit(sessionId, Math.min(commitBudgetMs, Math.max(100, left())));
      const nav = await gateRequest(sessionId, "Page.navigate", { url: "about:blank" }, budget(2000));
      if (!nav || nav.error || !nav.result) return false;
      watcher.add(nav.result.loaderId);
      if (!(await watcher.committed)) return false;
      committed.push(record);
    }

    // (c, for the replacement) One history entry: no history, no opener, nothing to go back to.
    const history = await gateRequest(replacement.gateSessionId, "Page.getNavigationHistory", {}, budget(1000));
    const entries = history && history.result && Array.isArray(history.result.entries) ? history.result.entries : null;
    if (!entries || entries.length !== 1) return false;

    // (d) ONLY a page whose commit was observed is closed, one close per page, never a detach
    // in front of it (a detach can count as the resume that releases a held target).
    for (const record of committed) {
      record.closed = true;
      record.gateClosed = true; // the GATE closed it: its requests fail in every state
      record.resumed = true;
      dropGateEvents(record);
      await gateRequest(gateBrowserSession, "Target.closeTarget", { targetId: record.targetId }, budget(1000));
    }

    // …then every other target the browser still lists: a held target, a worker, an iframe,
    // anything the gate will not run. A component extension's own worker is Chromium's, not the
    // bot's, and is left alone (section 3).
    const remainder = new Set();
    for (const [targetId, record] of gateTargets) if (!record.closed) remainder.add(targetId);
    const afterCloses = await listGateTargets();
    if (afterCloses) for (const targetId of afterCloses.keys()) remainder.add(targetId);
    for (const targetId of remainder) {
      if (targetId === replacementId) continue;
      const record = gateTargets.get(targetId);
      // A page that appeared after the navigation pass is never closed here: a close may only
      // follow an observed commit, so the scan below fails and the stop path decides.
      if (record && record.type === "page") continue;
      if (!record && afterCloses && afterCloses.get(targetId)?.type === "page") continue;
      // A component-extension worker the gate only ever LISTED (no record, no close) is
      // Chromium's, exactly like the attached one: it is never closed.
      if (isExemptNonPageTarget(targetId)) continue;
      if (record) { record.closed = true; record.gateClosed = true; record.resumed = true; dropGateEvents(record); }
      await gateRequest(gateBrowserSession, "Target.closeTarget", { targetId }, budget(1000));
    }

    // …and every non-default browser context: a bot's `newContext()` fallback outlives its
    // pages, and IDLE must start on the default context only.
    const contexts = noteDefaultContext(await gateRequest(gateBrowserSession, "Target.getBrowserContexts", {}, budget(1000)));
    if (!contexts || !contexts.result || !Array.isArray(contexts.result.browserContextIds)) return false;
    // Only ids the browser LISTS are contexts something created: a real Chromium leaves the
    // default context out of that array altogether.
    for (const contextId of contexts.result.browserContextIds) {
      if (typeof contextId !== "string" || isDefaultContext(contextId)) continue;
      await gateRequest(gateBrowserSession, "Target.disposeBrowserContext", { browserContextId: contextId }, budget(1000));
    }

    // (e) The scan: exactly the replacement page, no worker and no other target, default context.
    const scan = await listGateTargets();
    if (!scan || !scan.has(replacementId)) return false;
    for (const [targetId, info] of scan) {
      if (targetId === replacementId) {
        if (info.type !== "page") return false;
        if (!isDefaultContext(info.browserContextId)) return false;
        continue;
      }
      if (isExemptNonPageTarget(targetId)) continue;
      return false;
    }
    const contextsAfter = noteDefaultContext(await gateRequest(gateBrowserSession, "Target.getBrowserContexts", {}, budget(1000)));
    if (!contextsAfter || !contextsAfter.result || !Array.isArray(contextsAfter.result.browserContextIds)) return false;
    for (const contextId of contextsAfter.result.browserContextIds) {
      if (typeof contextId === "string" && !isDefaultContext(contextId)) return false;
    }

    // (f) `Page.disable` on the gate's live page sessions: IDLE leaves no page event enabled.
    for (const [sessionId, meta] of gateSessions) {
      if (meta.dead || meta.type !== "page") continue;
      void gateRequest(sessionId, "Page.disable", {}, 1000);
    }
    cleanupReplacementId = null;
    return true;
  }

  /** The cleanup ended clean: IDLE, and everyone it deferred resumes. */
  function completeCleanup() {
    setState("IDLE");
    releaseDeferred();
    // A guard-bearing client that connected (or is still connecting) during the cleanup now has
    // the state it would have had without it; requests stay failed while it is CONNECTING.
    recomputeState();
  }

  /** Let everything the CLEANUP deferred go: waiting upgrades, and held client frames. */
  function releaseDeferred() {
    for (const resolve of idleWaiters.splice(0)) { try { resolve(); } catch { /* gone */ } }
    for (const client of [...clients]) {
      if (client.closed || !client.sc) continue;
      flush(client);
    }
  }

  /**
   * Run (or join) the one cleanup; true when it came back clean, false when the caller must
   * take the stop path. A cleanup runs once at a time: a second trigger is ignored.
   */
  function startCleanup() {
    if (cleanupRun) return cleanupRun;
    if (gateReady && gateState !== "CLEANUP") setState("CLEANUP");
    cleanupRun = (async () => {
      let ok = false;
      try { ok = await runCleanupSequence(); } catch { ok = false; }
      cleanupRun = null;
      if (!ok) {
        // Whoever started it, a cleanup that is not clean ends in the stop path: left in
        // CLEANUP, the gate would fail every request for the rest of the relay's life.
        if (gateReady && !gateLost) stopPath("the cleanup could not leave the pages clean");
        return false;
      }
      if (gateReady && !gateLost) {
        if (closeIntents > 0 || stopping) {
          // A close is still owed (or a stop owns the exit): the gate stays CLEANUP through the
          // close window, so the IDLE reconcile that normally resumes the page the cleanup left
          // never runs. Resume what is left HERE, without touching the state: this is what gives
          // the close window a LIVE page whose traffic has to reach the gate, where CLEANUP fails
          // it. It is NOT what makes the close safe — the gate staying in CLEANUP is, and this
          // block never moves the state.
          for (const record of gateTargets.values()) {
            if (record.closed) continue;
            resumeTarget(record);
            // A connected client auto-attaches with `waitForDebuggerOnStart` too, so the same
            // target is held by the client's own session as well — and that client's resume
            // frame is still in the queue this path never flushes. Release the hold on the
            // client's session here, so the page RUNS and only the gate is in front of it
            // (its own Fetch.enable, if any, is in the same never-flushed queue).
            for (const [sessionId, targetId] of clientSessionTarget) {
              if (targetId !== record.targetId) continue;
              void gateRequest(sessionId, "Runtime.runIfWaitingForDebugger", {});
            }
          }
          return true;
        }
        completeCleanup();
      }
      return true;
    })();
    return cleanupRun;
  }

  /**
   * The last guard-bearing (or connecting) client left: every request fails and every new
   * target is held until the cleanup ends in IDLE.
   */
  function enterCleanup() {
    if (!gateReady || gateLost || stopping) return;
    // A close is owed (`closeIntents` above zero): the gate already sits in CLEANUP for it and
    // the browser is already on its way out. A SECOND cleanup here would run against a closing
    // browser — its replacement page and its closes would fail on a browser that is exiting,
    // and the failure takes the kill path instead of the polite close the owner asked for. The
    // close's own cleanup is the only one this window gets; return before anything moves.
    if (closeIntents > 0) return;
    if (cleanupRun) return; // one at a time: a second trigger changes nothing
    setState("CLEANUP");
    // NO CLIENT-HELD REQUEST MAY SURVIVE THIS CLEANUP'S `Target.closeTarget`. A PLAIN client (no
    // intent header) can still hold its own `Fetch.enable {*}` session on a page, newer than the
    // gate's, so a request of that page pauses at the CLIENT's session first. In CLEANUP the
    // relay defers a client's answers, so that request would sit there while the cleanup's close
    // takes every session of the page at once — and it would then advance past the sessions that
    // vanished and PASS, with the gate never in front of it. A session that DETACHES releases
    // what it held ONWARD to the gate's session instead, which fails it in CLEANUP. So every
    // client still attached is released here, BEFORE the cleanup may close any target (the pipe
    // is ordered, so these detaches are processed before its first `Target.closeTarget`), and
    // `keepOwnSession` leaves each one its `S_c` — the reply channel the next turn uses. The gate
    // is already CLEANUP above, so the released requests are FAILED, never passed.
    //
    // A GUARD-BEARING client cannot be attached here: this trigger runs only once the last
    // intent-bearing client is gone (the scan in `dropClient`), so this loop touches plain
    // clients only.
    for (const client of [...clients]) {
      if (client.closed) continue;
      releaseClientSessions(client, { keepOwnSession: true });
    }
    void startCleanup().then((clean) => {
      if (clean) return;
      stopPath("the pages a guard-bearing client left could not be made clean");
    });
  }

  // -----------------------------------------------------------------------------------
  // Coverage: what makes a page guarded
  // -----------------------------------------------------------------------------------

  /** A world name means the script is NOT main-world, and only a main-world script counts. */
  const isMainWorld = (worldName) => worldName === undefined || worldName === null || worldName === "";

  /**
   * Does ONE Fetch pattern reach every request? `urlPattern` must be `*` (or absent — a pattern
   * without one matches everything), it must name NO `resourceType`, and its `requestStage` must
   * be absent or "Request": a pattern narrowed by either one leaves requests the guard would
   * have seen reaching the network with no newer session in front of them.
   */
  function patternCoversAll(pattern) {
    if (!pattern || typeof pattern !== "object" || Array.isArray(pattern)) return false;
    if (!(pattern.urlPattern === undefined || pattern.urlPattern === "*")) return false;
    if (!(pattern.resourceType === undefined || pattern.resourceType === null)) return false;
    if (!(pattern.requestStage === undefined || pattern.requestStage === null || pattern.requestStage === "Request")) return false;
    return true;
  }

  /** Does this `Fetch.enable` reach every request through at least one of its patterns? */
  function fetchCoversAll(params) {
    const patterns = params && Array.isArray(params.patterns) ? params.patterns : null;
    return !!patterns && patterns.some(patternCoversAll);
  }

  function coverageEntry(sessionId) {
    let entry = sessionCoverage.get(sessionId);
    if (!entry) { entry = { fetchAll: false, markerIdentifier: null }; sessionCoverage.set(sessionId, entry); }
    return entry;
  }

  /** Recompute one client session's coverage, then the target's resume rule. */
  function updateCoverage(sessionId) {
    const targetId = clientSessionTarget.get(sessionId);
    const record = targetId ? gateTargets.get(targetId) : null;
    if (!record) return;
    const owner = sessionOwner.get(sessionId);
    const entry = sessionCoverage.get(sessionId);
    const covered = !!(entry && entry.fetchAll && entry.markerIdentifier && isGuardClient(owner));
    if (covered) record.covered.add(sessionId);
    else record.covered.delete(sessionId);
    reconcileRecord(record);
  }

  /** A session's coverage ends (its detach, its client's drop, its `Fetch.disable`). */
  function clearSessionCoverage(sessionId) {
    sessionCoverage.delete(sessionId);
    const targetId = clientSessionTarget.get(sessionId);
    const record = targetId ? gateTargets.get(targetId) : null;
    if (record) record.covered.delete(sessionId);
  }

  /**
   * Every session the client's attach events put BELOW this one (children, grandchildren). The
   * parent links come from the client-bound `Target.attachedToTarget` events alone, and a
   * session that goes away with its parent is never announced as detached on its own.
   */
  function sessionSubtree(sessionId) {
    const out = new Set();
    let frontier = [sessionId];
    while (frontier.length) {
      const next = [];
      for (const parent of frontier) {
        for (const [child, parentOf] of sessionParent) {
          if (parentOf !== parent || out.has(child)) continue;
          out.add(child);
          next.push(child);
        }
      }
      frontier = next;
    }
    return out;
  }

  /** A session and everything it announced lose coverage (an indirect detach takes it all). */
  function clearSubtreeCoverage(sessionId) {
    for (const child of sessionSubtree(sessionId)) clearSessionCoverage(child);
    clearSessionCoverage(sessionId);
  }

  /** A session that is gone: coverage, ownership, its tree link and the target's current one. */
  function forgetSession(sessionId) {
    const owner = sessionOwner.get(sessionId);
    const targetId = clientSessionTarget.get(sessionId);
    clearSessionCoverage(sessionId);
    if (owner && targetId && owner.currentSession.get(targetId) === sessionId) owner.currentSession.delete(targetId);
    sessionOwner.delete(sessionId);
    sessionParent.delete(sessionId);
    clientSessionTarget.delete(sessionId);
  }

  /**
   * The session is still this client's, and still the one the target's latest attach event
   * named for it: an ack that lands after an indirect detach, or after the target was announced
   * again, earns nothing.
   */
  function coverageStillCurrent(client, sessionId) {
    if (!client || client.closed) return false;
    if (sessionOwner.get(sessionId) !== client) return false;
    const targetId = clientSessionTarget.get(sessionId);
    if (!targetId) return true;
    const current = client.currentSession.get(targetId);
    return current === undefined || current === sessionId;
  }

  /**
   * The commands that END coverage do it when the relay FORWARDS them, never when Chromium
   * answers: a session that disables Fetch or detaches releases its paused requests onward,
   * and they can reach the gate before any event says the session is going away.
   *
   * `sessionId` is the client's ENVELOPE session, so it is null for a browser-level command —
   * and `Target.detachFromTarget` is exactly the command a guard sends that way, naming its
   * victim in params. That rule therefore runs before the envelope is looked at: a sessionless
   * `{sessionId}` detaches that session, and a `{targetId}` detaches every session the relay
   * mapped to that target. ONLY the calling client's own sessions are cleared (forwardText has
   * already refused a command DRIVEN on another client's session): a command naming a session
   * that is somebody else's ends nothing here.
   */
  function coverageBeforeForward(client, sessionId, msg) {
    if (!msg || typeof msg.method !== "string") return;
    if (sessionId && sessionOwner.get(sessionId) !== client) return;
    if (msg.method === "Target.detachFromTarget") {
      const params = msg.params && typeof msg.params === "object" && !Array.isArray(msg.params) ? msg.params : {};
      const victims = new Set();
      if (typeof params.sessionId === "string") victims.add(params.sessionId);
      if (typeof params.targetId === "string") {
        // A targetId resolves to every session the relay ever mapped to it (a swapped-in iframe
        // has more than one over its life); only this client's own are its to end.
        for (const [sid, targetId] of clientSessionTarget) if (targetId === params.targetId) victims.add(sid);
      }
      for (const victim of victims) {
        if (sessionOwner.get(victim) !== client) continue;
        // A parent's detach takes its children and grandchildren with it, and they get no
        // detach event of their own: their coverage goes here.
        clearSubtreeCoverage(victim);
      }
      return;
    }
    if (msg.method === "Target.setAutoAttach" && msg.params && msg.params.autoAttach === false) {
      // Auto-attach off on a session: Chromium stops announcing its children — and the ones it
      // did announce are the subtree below it, which ends coverage for that subtree alone.
      const parent = sessionId || client.sc || null;
      if (parent && sessionOwner.get(parent) === client) {
        for (const child of sessionSubtree(parent)) clearSessionCoverage(child);
      }
      return;
    }
    if (!sessionId) return;
    if (msg.method === "Page.disable") {
      // The marker script's world and page events are no longer trusted: the session's coverage
      // ends BEFORE the command is written, as with `Fetch.disable`.
      clearSessionCoverage(sessionId);
      return;
    }
    if (msg.method === "Fetch.disable") {
      const entry = sessionCoverage.get(sessionId);
      if (entry && entry.fetchAll) { entry.fetchAll = false; updateCoverage(sessionId); }
      return;
    }
    if (msg.method === "Fetch.enable") {
      // A later Fetch.enable REPLACES the earlier patterns on that session, so `fetchAll` is
      // recomputed from THIS call alone: a set that does not reach every request stops coverage
      // now, before the command is written. A set that DOES is set by its reply (an unacknowledged
      // enable intercepts nothing), which is also why a failed enable leaves this false.
      if (fetchCoversAll(msg.params)) return;
      const entry = sessionCoverage.get(sessionId);
      if (entry && entry.fetchAll) { entry.fetchAll = false; updateCoverage(sessionId); }
      return;
    }
    if (msg.method === "Page.removeScriptToEvaluateOnNewDocument") {
      const identifier = msg.params && typeof msg.params.identifier === "string" ? msg.params.identifier : null;
      const entry = sessionCoverage.get(sessionId);
      if (identifier && entry && entry.markerIdentifier === identifier) {
        entry.markerIdentifier = null;
        updateCoverage(sessionId);
      }
      return;
    }
  }

  /** The bookkeeping that a SUCCESSFUL command completes (an ack, not the write). */
  function coverageCompletion(client, sessionId, msg) {
    if (!sessionId || !sessionOwner.has(sessionId) || !msg || typeof msg.method !== "string") return null;
    if (msg.method === "Fetch.enable") {
      // The other half of the pattern rule ran before the write (`coverageBeforeForward`): a set
      // that does not reach every request already cleared coverage. The ACK is what sets it,
      // because only an acknowledged enable intercepts anything.
      const coversAll = fetchCoversAll(msg.params);
      return (reply) => {
        if (!reply || reply.error) return;
        if (!coverageStillCurrent(client, sessionId)) return;
        coverageEntry(sessionId).fetchAll = coversAll;
        updateCoverage(sessionId);
      };
    }
    if (msg.method === "Page.addScriptToEvaluateOnNewDocument") {
      const params = msg.params && typeof msg.params === "object" ? msg.params : {};
      if (!isMainWorld(params.worldName)) return null;
      if (typeof params.source !== "string" || !params.source.includes(GUARD_MARKER)) return null;
      return (reply) => {
        if (!reply || reply.error) return;
        if (!coverageStillCurrent(client, sessionId)) return;
        const identifier = reply.result && typeof reply.result.identifier === "string" ? reply.result.identifier : null;
        if (!identifier) return;
        coverageEntry(sessionId).markerIdentifier = identifier;
        updateCoverage(sessionId);
      };
    }
    return null;
  }

  // -----------------------------------------------------------------------------------
  // Resume rules, per target type
  // -----------------------------------------------------------------------------------

  function resumeTarget(record) {
    const sessionId = record.gateSessionId;
    if (!sessionId || record.resumed || record.closed) return;
    record.resumed = true;
    void gateRequest(sessionId, "Runtime.runIfWaitingForDebugger", {});
  }

  /**
   * page and iframe: only once a guard demonstrably covers the target (or in IDLE, where
   * nothing is held over). A worker: with its own covered owner, or in IDLE at once — Fetch
   * does not exist on a worker target, so a rule that waited for its own coverage would hang
   * every `new Worker()`. shared/service workers and every other type are never resumed here
   * (they are closed, first thing, without a detach in front of the close).
   */
  function reconcileRecord(record) {
    if (!record || record.closed || !record.gateSessionId) return;
    if (record.type === "worker") {
      const owner = record.ownerTargetId ? gateTargets.get(record.ownerTargetId) : null;
      if (gateState === "IDLE" || (owner && owner.covered.size > 0)) resumeTarget(record);
      return;
    }
    if (record.type !== "page" && record.type !== "iframe") return;
    if (gateState === "IDLE" || record.covered.size > 0) resumeTarget(record);
  }

  function reconcileAll() {
    for (const record of gateTargets.values()) reconcileRecord(record);
  }

  /** `Target.closeTarget` for a target the gate will not run (close first, never detach). */
  function closeGateTarget(record) {
    if (!record || record.closed) return;
    record.closed = true;
    record.gateClosed = true; // the GATE closed it: its requests fail in every state
    dropGateEvents(record);
    record.resumed = true; // never resumed again for any reason
    void gateRequest(gateBrowserSession, "Target.closeTarget", { targetId: record.targetId });
  }

  /** The extension id of a `chrome-extension://<id>/...` target URL, or null. */
  function extensionId(url) {
    const m = /^chrome-extension:\/\/([^/]+)\//.exec(typeof url === "string" ? url : "");
    return m ? m[1] : null;
  }

  /**
   * ONE component-extension SERVICE worker seen before the gate was ready (by an attach event or
   * by a listing). An allow-listed id is left to the caller to record as an exempt targetId; any
   * other id is logged once and fails the start. Returns the id when it is allow-listed, else
   * null.
   */
  function noteStartExtensionWorker(url) {
    const id = extensionId(url);
    if (!id) return null;
    if (COMPONENT_EXTENSION_IDS.has(id)) return id;
    if (!unknownExtensionIds.has(id)) {
      unknownExtensionIds.add(id);
      log(`gate: unknown extension worker at start, not on the component allow-list: ${id}`);
    }
    if (!startFatalFailure) startFatalFailure = `an extension worker at start is not on the component allow-list (${id})`;
    return null;
  }

  /**
   * A non-page target the gate tolerates: an exempt component-extension service worker recorded
   * by an attach event before ready, or one only ever LISTED at start (see `exemptTargetIds`).
   * Nothing else is tolerated, and neither covers a targetId first seen after ready.
   */
  function isExemptNonPageTarget(targetId) {
    const record = gateTargets.get(targetId);
    return !!((record && record.exemptWorker) || exemptTargetIds.has(targetId));
  }

  /**
   * Is this browser context the DEFAULT one? Three things are: no id at all, the literal
   * "default" (an older Chromium, and the fixtures), and the id Chromium itself named as
   * `defaultBrowserContextId`. Everything else is a context something created, and IDLE must
   * start on the default one only.
   */
  function isDefaultContext(contextId) {
    if (contextId === undefined || contextId === null) return true;
    if (contextId === "default") return true;
    return typeof defaultContextId === "string" && defaultContextId !== "" && contextId === defaultContextId;
  }

  /**
   * Learn the default context's id from a `Target.getBrowserContexts` answer. Never a failure
   * on its own: a build that does not report it keeps "default"/absent as the default context.
   */
  function noteDefaultContext(reply) {
    const id = reply && reply.result && typeof reply.result.defaultBrowserContextId === "string"
      ? reply.result.defaultBrowserContextId
      : null;
    if (id) defaultContextId = id;
    return reply;
  }

  // -----------------------------------------------------------------------------------
  // The forwarding barrier: client attach events wait for the gate's acks
  //
  // A reply that names a target the client is about to be handed waits behind that client's
  // event: Playwright's `newPage()` looks the page up by targetId the moment the reply lands,
  // so a reply that overtakes the event is a page the client cannot find. Both halves fail
  // closed — an event that is dropped is never followed by the reply it was ordering.
  // -----------------------------------------------------------------------------------

  /** What a held reply answers with when its event will never go out in front of it. */
  const HELD_RESPONSE_ERRORS = {
    "Target.createTarget": "Target.createTarget: the relay could not cover the new page in time",
    "Target.attachToTarget": "Target.attachToTarget: the relay could not cover the target in time",
  };

  /**
   * The target a reply is about, when the reply is one a client's own page lookup hangs on:
   * the page `Target.createTarget` made, or the target an explicit `Target.attachToTarget`
   * named. Anything else, and a reply without a target id, is not held.
   */
  function responseTargetId(entry, msg) {
    if (entry.method === "Target.createTarget") {
      return msg.result && typeof msg.result.targetId === "string" ? msg.result.targetId : null;
    }
    if (entry.method === "Target.attachToTarget") return typeof entry.targetId === "string" ? entry.targetId : null;
    return null;
  }

  /**
   * Hold one reply until `flushGateEvents` has sent this client the attach event it is waiting
   * for. The rewrite (`entry.originalId`, no `sessionId` when it is the client's own browser
   * session) is already done in `out`, exactly as on the direct path. The wait is bounded: the
   * event is held for the gate's acks, and a gate that never acks must not leave a client
   * waiting — it gets the error instead, and the page is left to the gate's own reconcile.
   */
  function holdResponse(record, client, entry, out) {
    const held = { client, out, command: entry.method, timer: null };
    held.timer = setTimeout(() => {
      const at = record.heldResponses.indexOf(held);
      if (at >= 0) record.heldResponses.splice(at, 1);
      failHeldResponse(held);
    }, responseHoldMs);
    if (typeof held.timer.unref === "function") held.timer.unref();
    record.heldResponses.push(held);
  }

  /** Answer a held reply with an error, once; a client that closed meanwhile is not written to. */
  function failHeldResponse(held) {
    if (held.timer) { clearTimeout(held.timer); held.timer = null; }
    if (!held.client || held.client.closed) return; // `send` refuses a closed client anyway
    const out = { ...held.out };
    delete out.result;
    out.error = { code: -32000, message: HELD_RESPONSE_ERRORS[held.command] || HELD_RESPONSE_ERRORS["Target.createTarget"] };
    send(held.client, out);
  }

  /**
   * Release the replies held for the clients whose events `flushGateEvents` just sent, in the
   * order they arrived. The events are already written, which is the whole point of holding;
   * a reply held for a client with no event in this flush waits for the flush that serves it.
   */
  function releaseHeldResponses(record, delivered) {
    if (!record.heldResponses.length) return;
    const keep = [];
    for (const held of record.heldResponses) {
      if (!delivered.has(held.client)) { keep.push(held); continue; }
      sendHeldResponse(held);
    }
    record.heldResponses = keep;
  }

  /** The reply itself, once — and never to a client that has closed in the meantime. */
  function sendHeldResponse(held) {
    if (held.timer) { clearTimeout(held.timer); held.timer = null; }
    if (!held.client || held.client.closed) return; // `send` refuses a closed client anyway
    send(held.client, held.out);
  }

  /**
   * Release every reply still held for a record, as the browser answered it. For the gate's own
   * loss only: the browser is stopped next, so the events those replies were ordered behind
   * will never be forwarded, and the client is owed the answer it already has while its
   * connection still exists.
   */
  function releaseAllHeldResponses(record) {
    const held = record.heldResponses;
    record.heldResponses = [];
    for (const item of held) sendHeldResponse(item);
  }

  function dropGateEvents(record) {
    for (const item of record.pendingEvents) {
      const child = item.msg.params && typeof item.msg.params.sessionId === "string" ? item.msg.params.sessionId : null;
      if (child) swallowedSessions.set(child, { client: item.client, targetId: record.targetId });
    }
    record.pendingEvents = [];
    // The events the held replies were ordered behind are dropped (the target closed, the gate
    // has no session for it, an ack failed): fail closed, never answer with a success the
    // client cannot use.
    const held = record.heldResponses;
    record.heldResponses = [];
    for (const item of held) failHeldResponse(item);
  }

  /**
   * Release the events buffered for this target, but only on the CURRENT gate session's
   * successful acks: a target whose gate session went away, or whose interception failed, is
   * never handed to a client (fail closed). A swap re-waits on the new epoch's acks.
   */
  function flushGateEvents(record) {
    if (!record.pendingEvents.length) return;
    if (record.closed) { dropGateEvents(record); return; }
    const epoch = record.gateSessionId;
    if (!epoch) { dropGateEvents(record); return; }
    if (record.ackEpoch !== epoch) return; // the acks for this epoch are still in flight
    if (record.ackOk !== true) return;     // a failed ack never forwards anything
    const queued = record.pendingEvents;
    record.pendingEvents = [];
    const delivered = new Set();
    for (const item of queued) {
      const client = item.client;
      if (!client || client.closed) continue;
      const out = { ...item.msg };
      if (typeof out.sessionId === "string" && out.sessionId === client.sc) delete out.sessionId;
      send(client, out);
      delivered.add(client);
    }
    // …and only now the replies that were waiting for those events.
    releaseHeldResponses(record, delivered);
  }

  /**
   * The gate could not take its interception place on a target. If the target is gone, the
   * buffered events for it are dropped; if it is still listed, the gate is not in front of a
   * page that can still make requests, which is gate loss and the stop path.
   */
  async function onGateAckFailure(record, epoch) {
    if (record.gateSessionId && record.gateSessionId !== epoch) return; // a swapped-in epoch decides
    if (!gateReady) return; // the start sequence owns the failure (it stops Chromium itself)
    const listed = await listGateTargets();
    if (record.closed || (listed && !listed.has(record.targetId))) {
      record.closed = true;
      dropGateEvents(record);
      return;
    }
    // The gate could not take its interception place on a target that is still listed: the stop
    // path ends the browser next. The client-bound events will never be forwarded, so a reply
    // they were ordering is answered as the browser produced it rather than left waiting for an
    // event nobody will send — the page itself is only alive for as long as the stop takes.
    releaseAllHeldResponses(record);
    stopPath("the gate could not take its interception place on a target that is still listed");
  }

  // -----------------------------------------------------------------------------------
  // Chromium's events on the gate's own sessions
  // -----------------------------------------------------------------------------------

  async function listGateTargets() {
    const reply = await gateRequest(gateBrowserSession, "Target.getTargets", {}, 5000);
    if (!reply || !reply.result || !Array.isArray(reply.result.targetInfos)) return null;
    // While the gate is still starting, its own listing is a SECOND source of component-extension
    // workers, beside the attach events: Chromium 145 LISTS one as
    // `service_worker chrome-extension://<id>/thunk.js` and never attaches it, so nothing else
    // would ever record it. An allow-listed id is recorded here (never attached, never closed);
    // any other one fails the start. NEVER after `gateReady`: a worker listed or attached after
    // ready is closed as any other worker is.
    if (!gateReady) {
      for (const info of reply.result.targetInfos) {
        // Only a SERVICE worker can be exempt (see onGateAttached). A `shared_worker` at an
        // allow-listed id is not recorded, so the start's cleanup closes it like any other
        // non-page target: a shared worker is a document's, not the browser's.
        if (!info || info.type !== "service_worker") continue;
        if (!noteStartExtensionWorker(info.url)) continue;
        if (typeof info.targetId === "string") exemptTargetIds.add(info.targetId);
      }
    }
    return new Map(reply.result.targetInfos.map((info) => [info.targetId, info]));
  }

  function onGateEvent(sessionId, msg) {
    if (msg.method === "Target.attachedToTarget") { onGateAttached(sessionId, msg.params || {}); return; }
    if (msg.method === "Target.detachedFromTarget") {
      const child = msg.params && typeof msg.params.sessionId === "string" ? msg.params.sessionId : null;
      if (child) onGateDetached(child);
      return;
    }
    if (msg.method === "Fetch.requestPaused") { onGateRequestPaused(sessionId, msg.params || {}); return; }
    // The cleanup's own observations: a page commit is the `frameNavigated` for the loaderId its
    // `Page.navigate` returned, and a dialog (`beforeunload`) is accepted, never left open.
    if (msg.method === "Page.frameNavigated") { onGateFrameNavigated(sessionId, msg.params || {}); return; }
    if (msg.method === "Page.javascriptDialogOpening") {
      void gateRequest(sessionId, "Page.handleJavaScriptDialog", { accept: true }, 5000);
      return;
    }
    if (msg.method === "Target.targetDestroyed" || msg.method === "Target.targetCrashed") {
      const targetId = msg.params && typeof msg.params.targetId === "string" ? msg.params.targetId : null;
      const record = targetId ? gateTargets.get(targetId) : null;
      if (record) { record.closed = true; dropGateEvents(record); }
      return;
    }
    // Everything else on a gate session belongs to relay code and is consumed here, never
    // forwarded and never counted.
  }

  /** The gate's own session on a target: record it, take the interception place, then act. */
  function onGateAttached(parentSessionId, params) {
    const child = typeof params.sessionId === "string" ? params.sessionId : null;
    if (!child) return;
    const info = params.targetInfo && typeof params.targetInfo === "object" ? params.targetInfo : {};
    const targetId = typeof info.targetId === "string" ? info.targetId : null;
    const type = typeof info.type === "string" ? info.type : "other";
    const url = typeof info.url === "string" ? info.url : "";
    const parent = gateSessions.get(parentSessionId);
    gateSessions.set(child, {
      targetId,
      type,
      url,
      parent: parentSessionId,
      ownerTargetId: parent ? parent.targetId : null,
      dead: false,
    });
    if (!targetId) return;
    let record = gateTargets.get(targetId);
    if (!record) {
      record = newGateTarget(targetId, type, url, parent ? parent.targetId : null);
      gateTargets.set(targetId, record);
    } else {
      // The same targetId with a NEW session: a cross-site iframe navigation (an OOPIF
      // swap) attaches a new session and detaches the old one, in either order. The new
      // session is the current one, and the target starts uncovered and held again —
      // coverage was per client session, and the new client session has to re-earn it.
      record.covered.clear();
      record.closed = false;
      // The record is live again, and only a close the GATE performs sets the flag back: the
      // close that marked it belonged to the session that just went away (a swap).
      record.gateClosed = false;
    }
    record.type = type;
    record.url = url;
    record.ownerTargetId = parent ? parent.targetId : null;
    record.gateSessionId = child;
    record.gateSessions.add(child);
    record.held = params.waitingForDebugger === true;
    record.resumed = !record.held;

    const installs = [];
    if (type === "page" || type === "iframe") {
      installs.push(gateRequest(child, "Fetch.enable", { patterns: [{ urlPattern: "*" }] }));
      // Nested auto-attach: this is how cross-process iframes and dedicated workers are
      // reached (a browser-level auto-attacher never sees them).
      installs.push(gateRequest(child, "Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }));
    }
    const epoch = child;
    record.acks = Promise.all(installs).then((replies) => {
      const failed = replies.some((reply) => !reply || reply.error);
      record.ackEpoch = epoch;
      record.ackOk = !failed;
      if (failed) { onGateAckFailure(record, epoch).catch(() => {}); return false; }
      flushGateEvents(record);
      return true;
    });

    if (type === "shared_worker" || type === "service_worker") {
      // Fetch cannot intercept a shared or service worker, and a held one runs as soon as
      // ANY resumer resumes it, so holding or refusing cannot work: the gate closes it, and
      // the client never sees the attach event (so it never resumes it). The one exception is
      // a component extension's SERVICE worker that existed before the gate was ready: it is
      // Chromium's own and is left alone — but only on the FIXED allow-list. An id off that
      // list is logged once and fails the start (fail closed).
      //
      // What exempts is a targetId RECORDED BEFORE `gateReady` (in `exemptTargetIds`), never an
      // origin: this attach records the targetId of an allow-listed service worker while the
      // gate is still starting, and `listGateTargets` records the one a build only ever lists.
      // After ready the set is READ and never written, so a worker whose targetId is not in it
      // — a second service worker at an allow-listed id, a SharedWorker a document starts at
      // that origin — is closed as any other worker is. A re-attach of a recorded targetId
      // stays exempt, because the id is the same one.
      //
      // A `shared_worker` is never exempt, before ready or after: it belongs to a document at
      // that origin, not to the browser, so it is never recorded and the gate's normal rules
      // (this close, or the start's cleanup) take it.
      if (!gateReady && type === "service_worker" && noteStartExtensionWorker(url)) {
        exemptTargetIds.add(targetId);
        record.exemptWorker = true;
        resumeTarget(record);
        return;
      }
      if (exemptTargetIds.has(targetId)) {
        record.exemptWorker = true;
        resumeTarget(record);
        return;
      }
      closeGateTarget(record);
      return;
    }
    if (type !== "page" && type !== "iframe" && type !== "worker") {
      // worklet, shared_storage_worklet, auction_worklet, other, webview, a speculation-rules
      // prerender page target, anything new: held and closed, never resumed.
      closeGateTarget(record);
      return;
    }
    if (cleanupReplacementId && targetId === cleanupReplacementId && (gateState === "CLEANUP" || !gateReady)) {
      // The gate's own fresh replacement page: resumed AT ONCE (so the headful browser always
      // has a live page) and never navigated by the relay.
      resumeTarget(record);
      return;
    }
    reconcileRecord(record);
  }

  /**
   * Per request: continue when the gate is in idle or the page is covered, else fail it. A
   * CLEANUP fails every request, coverage or not: a page it has not closed yet is a document
   * it is about to leave, so nothing it issues may reach the network. A target the GATE closed
   * fails in EVERY state, IDLE included: its document can still answer `requestPaused` on a
   * session that has not detached yet (pagehide beacons, a last image request), and that
   * traffic may not pass through a gate that never resumed it. The flag is the GATE's own
   * (`gateClosed`, set where the gate closes a target itself): a target that CRASHED is not
   * one of those, and its requests are decided by the state and coverage rules like any other.
   */
  function onGateRequestPaused(sessionId, params) {
    const requestId = params && typeof params.requestId === "string" ? params.requestId : null;
    if (!requestId) return;
    gateRequestIds.add(requestId);
    const meta = gateSessions.get(sessionId);
    const record = meta && meta.targetId ? gateTargets.get(meta.targetId) : null;
    const covered = !!(record && record.covered.size > 0);
    const pass = !(record && record.gateClosed) && (gateState === "IDLE" || (gateState !== "CLEANUP" && covered));
    const method = pass ? "Fetch.continueRequest" : "Fetch.failRequest";
    const answer = pass ? { requestId } : { requestId, errorReason: "BlockedByClient" };
    void gateRequest(sessionId, method, answer, 10_000).then(() => gateRequestIds.delete(requestId));
  }

  /** A gate session went away: a swap (the target is still covered by a new session) or loss. */
  function onGateDetached(childSessionId) {
    const meta = gateSessions.get(childSessionId);
    if (!meta) return;
    meta.dead = true;
    if (childSessionId === gateBrowserSession) { stopPath("the gate's browser-level session detached"); return; }
    const record = meta.targetId ? gateTargets.get(meta.targetId) : null;
    if (!record) return;
    record.gateSessions.delete(childSessionId);
    if (record.gateSessionId !== childSessionId) return; // an old session of a target that was swapped
    record.gateSessionId = null;
    record.resumed = true;
    settleTarget(record).catch(() => {});
  }

  /**
   * The settle: after the grace, one `Target.getTargets`. Still listed with no live gate
   * session for it (and no destroy/crash seen) is gate loss; a swapped-in session or a
   * target that is gone is ordinary.
   */
  async function settleTarget(record) {
    await delay(settleMs);
    if (gateLost || record.closed) return;
    if (record.gateSessionId) return;               // a new session took over (a swap)
    if (record.gateSessions.size > 0) return;       // another live gate session serves the target
    const listed = await listGateTargets();
    if (!listed) { stopPath("the target list could not be read after a gate session was lost"); return; }
    if (!listed.has(record.targetId)) { record.closed = true; dropGateEvents(record); return; }
    stopPath("a gate session was lost and its target is still listed");
  }

  // -----------------------------------------------------------------------------------
  // The handshake: the intent header, Crow.guardReady, and the state machine
  // -----------------------------------------------------------------------------------

  function noteIntentClient(client) {
    if (client.deadline) { clearTimeout(client.deadline); client.deadline = null; }
    const timer = setTimeout(() => {
      client.deadline = null;
      if (client.closed || client.declared) return;
      log(`gate: an intent client missed the connecting deadline (${Math.round(connectingDeadlineMs / 1000)}s), dropping it`);
      dropClient(client, 1001, "the connecting deadline passed");
    }, connectingDeadlineMs);
    if (typeof timer.unref === "function") timer.unref();
    client.deadline = timer;
    if (!gateReady) return;
    // The cleanup owns the state until it ends: a new intent client is accepted, but the gate
    // stays CLEANUP (requests fail) until the scan is clean.
    if (gateState === "CLEANUP") return;
    // Announce CONNECTING (the state this client would put the gate in), then re-assert the
    // effective state: with another guard already present the gate stays GUARDED, because
    // coverage is per page and one connecting client must not uncover everybody else.
    setState("CONNECTING");
    recomputeState();
  }

  /** Every `Crow.*` command: relay-handled, never forwarded, answered to the client's own id. */
  function handleCrowCommand(client, msg) {
    const reply = (body) => replyTo(client, msg, body);
    if (msg.method !== "Crow.guardReady") {
      reply({ error: { code: -32601, message: `method not found: ${String(msg.method).slice(0, 64)}` } });
      return;
    }
    if (!client.intent) {
      reply({ error: { code: -32601, message: "method not found: Crow.guardReady" } });
      return;
    }
    if (client.deadline) { clearTimeout(client.deadline); client.deadline = null; }
    const params = msg.params && typeof msg.params === "object" ? msg.params : {};
    const hash = typeof params.exceptionsHash === "string" ? params.exceptionsHash.slice(0, 128) : "none";
    const v = Number.isInteger(params.v) ? params.v : "?";
    client.declared = true;
    // Logged once, and used for nothing else (the exceptions are the MCP guard's business).
    log(`guard declared (v=${v}, exceptionsHash=${hash || "none"})`);
    // A page this client hooked BEFORE it declared is covered from now on: its evidence was
    // already on the wire, only the client's status changed.
    for (const sessionId of client.sessions) updateCoverage(sessionId);
    reply({ result: {} });
    recomputeState();
  }

  /**
   * A client's `Browser.close` is handled the way a `Crow.*` command is: relay code runs the
   * cleanup first, and the browser is asked to close only when the scan after it is clean.
   * Anything else would run a live page's pagehide/unload with the guard already gone (S4 11).
   * A client's `Browser.crash` passes through untouched: it runs no unload.
   *
   * The close intent is counted BEFORE the cleanup so the gate stays CLEANUP through the close
   * window: Chromium keeps running its pages' pagehide beacons and image requests between
   * `Browser.close` and its own exit, and IDLE would pass them. It is this client's OWN intent
   * that is withdrawn below, never the count as a whole: a stop path that joined the same
   * cleanup keeps the gate in CLEANUP, because its ask is the one that will write the close.
   */
  function handleBrowserClose(client, msg) {
    closeIntents++;
    // NO REQUEST MAY REACH THE NETWORK THROUGH AN ADVANCING FETCH CHAIN. A live client has its
    // own Fetch session on a page, NEWER than the gate's, so that page's request pauses at the
    // CLIENT's session first. While the relay is in CLEANUP it defers a client's answers, so the
    // request would stay held there — and the cleanup's `Target.closeTarget` takes every session
    // of the page at once, after which the request advances past the sessions that vanished and
    // PASSES, with the gate never having seen it. A session that DETACHES instead releases what
    // it held ONWARD to the next session in the chain — the gate's — which fails it in CLEANUP.
    // So, before `startCleanup()` can close any target: the gate goes CLEANUP first (a released
    // request must be FAILED, never passed), and EVERY client — the asker and every other one —
    // is released ONWARD here, its top-level sessions detached on the envelopes that own them
    // (`releaseClientSessions`, the asker's included) and forgotten; a nested child goes with its
    // parent page session. The asker's own `S_c` is the one thing that stays: it is the reply
    // channel the forwarded close still needs, and the replies it holds behind dropping events
    // are failed by the cleanup's own bookkeeping. The pipe to Chromium is ORDERED, so every
    // detach written here is processed before the cleanup's first `Target.closeTarget`.
    if (gateReady && !gateLost && gateState !== "CLEANUP") setState("CLEANUP");
    for (const other of [...clients]) {
      if (other === client) continue;
      releaseClientSessions(other, { keepOwnSession: true });
    }
    releaseClientSessions(client, { keepOwnSession: true });
    startCleanup().then((clean) => {
      if (!clean || gateLost || client.closed) {
        // No `Browser.close` is going out — the stop path owns the exit, or the client that
        // asked has gone — so this ask is withdrawn and the count drops by one. Only when that
        // was the LAST ask, nothing is stopping, and the scan was clean does the cleanup get
        // the re-open it owes; otherwise the gate stays CLEANUP, where the close window's
        // traffic fails.
        closeIntents = Math.max(0, closeIntents - 1);
        if (closeIntents === 0 && !stopping && clean && gateReady && !gateLost) completeCleanup();
        return;
      }
      // A forwarded close is not an exit: Chromium may answer `Browser.close` and not go. The
      // graceful stop bounds that wait with `closeTimeoutMs` and kills the browser when it
      // overruns, and this path takes the same budget to the same stop path — otherwise a close
      // Chromium ignored would leave this relay waiting forever. `delay` unrefs its timer, so a
      // browser that does exit leaves no timer behind to hold the process up.
      //
      // ARMED FIRST, before anything else in this branch can throw: the count above is what
      // keeps the gate in CLEANUP, and a step that threw between it and a late arm would leave
      // the count above zero with no timer to bring it back — every request failed for the rest
      // of the relay's life.
      void Promise.race([exited.then(() => "exited"), delay(closeTimeoutMs).then(() => "timeout")]).then((how) => {
        if (how === "timeout" && !stopping) stopPath("Chromium did not exit after a client's Browser.close");
      });
      // The scan was clean and the browser IS going: every other client is dropped whole now
      // (its sessions were already released before the cleanup above, so this is the socket and
      // its bookkeeping only). NOT before the cleanup: an asker that has already gone by the time
      // the scan ends withdraws the close (the branch above), the gate re-opens IDLE, and the
      // clients still attached have to still be usable there — dropping them on the way in would
      // close sockets for a close that is never written.
      for (const other of [...clients]) {
        if (other === client) continue;
        dropClient(other, 1001, "the relay is closing the browser");
      }
      // The scan was clean, so this is a graceful close: the supervisor hears about it before
      // the command that closes the browser goes out.
      reportClosing();
      forwardToPipe(client, msg);
      // The close is on the wire: a later `shutdown()` owes a wait for the exit, no cleanup.
      closeForwarded = true;
    }).catch(() => {
      // A throw anywhere in this handler is never swallowed: the close is owed, nothing else is
      // going to end this browser, and a swallowed failure would leave the gate in CLEANUP with
      // that count above zero forever. The stop path takes it.
      if (!stopping) stopPath("a client's Browser.close handling threw");
    });
  }

  // -----------------------------------------------------------------------------------
  // Client-bound attach events: the barrier, and what a client must never be handed
  // -----------------------------------------------------------------------------------

  function onClientAttached(owner, msg) {
    const params = msg.params && typeof msg.params === "object" ? msg.params : {};
    const child = typeof params.sessionId === "string" ? params.sessionId : null;
    const info = params.targetInfo && typeof params.targetInfo === "object" ? params.targetInfo : {};
    const targetId = typeof info.targetId === "string" ? info.targetId : null;
    const type = typeof info.type === "string" ? info.type : null;
    // The session-to-target map comes from THIS event (or an attach response), never from a
    // param a client supplied. The event also says which session announced the child, and
    // makes the child the target's current session for this client.
    const parentSessionId = typeof msg.sessionId === "string" ? msg.sessionId : null;
    if (child) sessionParent.set(child, parentSessionId);
    if (child && targetId) clientSessionTarget.set(child, targetId);
    const record = targetId ? gateTargets.get(targetId) : null;
    // A component extension's own worker is left running, but no client is handed it: a client
    // could hold it, hook it or drive Chromium's own worker.
    const forwardable = type === "page" || type === "iframe" || type === "worker";
    // Whatever is announced from a session this client was never handed goes with it, so a
    // swallowed target's children are swallowed too, at any depth.
    const swallowedParent = parentSessionId ? swallowedSessions.get(parentSessionId) : null;
    if (!forwardable || !record || record.closed || swallowedParent) {
      // A shared or service worker, a component extension's own worker, or any other type the
      // gate closes — and any target the gate never attached: the client never sees the event,
      // so it never resumes it.
      if (child) swallowedSessions.set(child, { client: owner, targetId });
      return;
    }
    if (child) {
      registerSession(child, owner);
      if (targetId) owner.currentSession.set(targetId, child);
    }
    record.pendingEvents.push({ client: owner, msg });
    flushGateEvents(record);
  }

  function onClientDetached(owner, msg) {
    const parentSessionId = typeof msg.sessionId === "string" ? msg.sessionId : null;
    const child = msg.params && typeof msg.params.sessionId === "string" ? msg.params.sessionId : null;
    if (child && swallowedSessions.has(child)) {
      // Its attach event was swallowed: the detach must be too.
      swallowedSessions.delete(child);
      sessionParent.delete(child);
      clientSessionTarget.delete(child);
      return;
    }
    if (child) {
      // What it announced goes with it: those sessions get no detach event of their own, so
      // their coverage is cleared here.
      clearSubtreeCoverage(child);
      forgetSession(child);
    }
    const out = { ...msg };
    if (parentSessionId && parentSessionId === owner.sc) delete out.sessionId;
    send(owner, out);
  }

  // -----------------------------------------------------------------------------------
  // Parameters that name a gate session (or a request the gate is holding)
  // -----------------------------------------------------------------------------------

  function namesGateSession(params) {
    if (!params || typeof params !== "object") return false;
    if (Array.isArray(params)) return params.some((value) => namesGateSession(value));
    for (const value of Object.values(params)) {
      if (typeof value === "string" && gateSessions.has(value)) return true;
      if (value && typeof value === "object" && namesGateSession(value)) return true;
    }
    return false;
  }

  function answersGateRequest(msg) {
    if (typeof msg.method !== "string" || !msg.method.startsWith("Fetch.")) return false;
    const requestId = msg.params && typeof msg.params.requestId === "string" ? msg.params.requestId : null;
    return !!requestId && gateRequestIds.has(requestId);
  }

  // -----------------------------------------------------------------------------------
  // The explicit attach: held until the gate's acks, refused where the gate has no session
  //
  // The COMMAND is held here, not the reply: by the time `holdExplicitAttach` forwards it the
  // target's client-bound events have been flushed, so its reply finds nothing pending and the
  // ordering rule in `fromPipe` passes it straight through — unchanged behaviour.
  // -----------------------------------------------------------------------------------

  function waitForGateTarget(targetId, timeoutMs) {
    return new Promise((resolve) => {
      const deadlineAt = Date.now() + timeoutMs;
      const tick = () => {
        const record = gateTargets.get(targetId);
        if (record && !record.closed) { resolve(record); return; }
        if (Date.now() >= deadlineAt) { resolve(null); return; }
        const timer = setTimeout(tick, 25);
        if (typeof timer.unref === "function") timer.unref();
      };
      tick();
    });
  }

  async function holdExplicitAttach(record, deliver, reply) {
    const refuse = () => reply({ error: { code: -32602, message: "Target.attachToTarget refused: the relay's interception is not in place for that target" } });
    if (!record || record.closed) { refuse(); return; }
    if (record.exemptWorker) { refuse(); return; }
    const type = record.type;
    if (type !== "page" && type !== "iframe" && type !== "worker") { refuse(); return; }
    const epoch = record.gateSessionId;
    if (!epoch) { refuse(); return; }
    await record.acks;
    if (record.closed) { refuse(); return; }
    if (record.gateSessionId !== epoch) {
      // A swap while we waited: the NEW session's acks are the ones that order this attach.
      if (record.gateSessionId) { holdExplicitAttach(record, deliver, reply).catch(() => {}); return; }
      refuse();
      return;
    }
    if (!record.ackOk) { refuse(); return; }
    deliver();
  }

  function gateAttachTarget(client, msg) {
    const reply = (body) => replyTo(client, msg, body);
    const targetId = msg.params && typeof msg.params.targetId === "string" ? msg.params.targetId : null;
    const deliver = () => forwardToPipe(client, msg);
    if (!targetId) { deliver(); return; }
    const known = gateTargets.get(targetId);
    if (known) { holdExplicitAttach(known, deliver, reply).catch(() => {}); return; }
    // The gate may learn a target a moment after a client creates it: wait a bounded time
    // for that, then refuse (a target the gate has no session for may be one it is closing).
    waitForGateTarget(targetId, 1000).then((record) => {
      if (!record) {
        reply({ error: { code: -32602, message: `Target.attachToTarget refused: the relay's gate has no session for ${targetId}` } });
        return;
      }
      holdExplicitAttach(record, deliver, reply).catch(() => {});
    }).catch(() => {});
  }

  // -----------------------------------------------------------------------------------
  // The start sequence: the gate is in place before a single client can connect
  // -----------------------------------------------------------------------------------

  async function startGate() {
    const deadlineAt = Date.now() + startDeadlineMs;
    const left = () => Math.max(50, Math.min(5000, deadlineAt - Date.now()));

    // 1. The target list, read before the gate attaches. The listing itself records the
    //    component-extension workers that were ALREADY there (see listGateTargets): an
    //    allow-listed one is exempt even when it is never attached, an unknown one fails the
    //    start. This listing is only half of "present when the gate started": a real Chromium
    //    does not list its component-extension workers in it at all, they attach a moment
    //    later, so the attach path records those too while the gate is still starting (see
    //    onGateAttached), and so does every later listing made before `gateReady`.
    const first = await listGateTargets();
    if (!first) return "the browser's target list could not be read";

    // 2. The gate's own browser session: created before any client can connect, so the gate
    //    is the oldest auto-attacher (and Fetch interceptor) on every page.
    const attach = await gateRequest(null, "Target.attachToBrowserTarget", {}, left());
    if (!attach || !attach.result || typeof attach.result.sessionId !== "string") return "no browser session";
    gateBrowserSession = attach.result.sessionId;
    gateSessions.set(gateBrowserSession, { targetId: null, type: "browser", url: "", parent: null, ownerTargetId: null, dead: false });

    // 3. Which context is the DEFAULT one. In a real Chromium it is an opaque hex id, not the
    //    literal "default" (and it is not in `browserContextIds`), so every later test of
    //    "is this target in the default context" needs the id Chromium reports. Best effort:
    //    a build that does not report one keeps "default"/absent as the default context.
    noteDefaultContext(await gateRequest(gateBrowserSession, "Target.getBrowserContexts", {}, left()));

    // 4. Auto-attach: this attaches the existing targets too (no second explicit attach, so
    //    no target gets two gate sessions).
    const auto = await gateRequest(gateBrowserSession, "Target.setAutoAttach", { autoAttach: true, waitForDebuggerOnStart: true, flatten: true }, left());
    if (!auto || auto.error) return "auto-attach was refused";

    // 5. Cross-check: every page and iframe the browser lists has the gate's own session.
    //    The `Target.getTargets` reply is read after the attach events Chromium already
    //    wrote, so this is the whole picture, not a guess.
    const listed = await listGateTargets();
    if (!listed) return "the target list could not be read again";
    for (const [targetId, info] of listed) {
      if (info.type !== "page" && info.type !== "iframe") continue;
      const record = gateTargets.get(targetId);
      if (!record || !record.gateSessionId) return `no session on ${info.type} ${targetId}`;
    }

    // 6. Every interception the gate took must have been ACKNOWLEDGED by Chromium: an ack is
    //    the only ordering that holds whatever Chromium does internally.
    for (const record of gateTargets.values()) {
      if (!(await record.acks)) return "an interception was refused";
    }

    // 7. A short bounded settle, before the target list is JUDGED. A real Chromium's
    //    component-extension workers are not in the listing step 1 made at all: they attach
    //    to the gate's auto-attach a moment later. "Present when the gate started" means
    //    "seen before the gate is ready" — by an attach (recorded as exempt in
    //    `onGateAttached`) or by a listing (recorded in `listGateTargets`, for the build that
    //    only ever LISTS one) — so they must have arrived before `startPagesAreClean()` reads
    //    the list. The settle gives them that moment.
    await delay(Math.max(0, Math.min(settleMs, left())));

    // 8. Nothing will serve an older service worker; best effort, never a start failure.
    void gateRequest(gateBrowserSession, "ServiceWorker.stopAllWorkers", {}, left());

    // 9. Neutralise whatever exists (a restored profile, an earlier life of the container, a
    //    pre-ready document): the same steps as the cleanup, with the fresh replacement page
    //    created first. A browser that is already at the neutral state — its own single fresh
    //    `about:blank` page — has nothing to neutralise. A page that does not commit is never
    //    closed: the start fails through the stop path, so no caller can announce a browser
    //    whose pages were not left.
    const cleanStart = await startPagesAreClean();
    if (startFatalFailure) return startFatalFailure;
    if (!cleanStart) {
      const cleaned = await startCleanup();
      if (!cleaned) return "the pages that existed at start could not be made clean";
    }
    // An extension worker off the component allow-list, seen at any point before this one —
    // the start's own cleanup included — fails the start: the gate does not guess what a
    // changed Chromium named. Every OTHER target the browser listed was neutralised by the
    // cleanup above (closed), never judged.
    return startFatalFailure;
  }

  function pipeSend(msg) { return framer.write(msg); }

  function internalRequest(method, params = {}, timeoutMs = 5000) {
    return new Promise((resolve) => {
      const id = nextId++;
      const timer = setTimeout(() => { internal.delete(id); resolve(null); }, timeoutMs);
      if (typeof timer.unref === "function") timer.unref();
      internal.set(id, (msg) => { clearTimeout(timer); resolve(msg); });
      if (!pipeSend({ id, method, params })) { clearTimeout(timer); internal.delete(id); resolve(null); }
    });
  }

  function registerSession(sessionId, client) {
    sessionOwner.set(sessionId, client);
    client.sessions.add(sessionId);
  }

  /**
   * Detach ONE session, on the envelope of the session that OWNS it.
   *
   * Chromium looks a session up for `Target.detachFromTarget` only in the session the
   * `Target.attachToTarget` / `Target.setAutoAttach` that created it was issued on: sent on
   * any other envelope — the root included — the command is answered "No session with given
   * id" and NOTHING is detached. That matters here because the detach is what releases the
   * session's held requests ONWARD to the next, older Fetch session — the gate's: a detach
   * that silently does nothing leaves the request to be released by the cleanup's own
   * `Target.closeTarget`, which advances it past the sessions that vanished and PASSES it
   * with no gate in front of it.
   *
   * `ownerSessionId` is that owner wherever the relay knows one: `sessionParent.get(sid)` for
   * a nested child (a session announced BY another session — an attach event, or the RESPONSE to
   * an attach the client sent on that session's envelope), otherwise the client's own `S_c` —
   * every session a client attached sessionless was stamped with `sessionId = S_c` by
   * `forwardToPipe`. `S_c` itself has NO owner: `Target.attachToBrowserTarget` went out
   * sessionless (the root), so it detaches at the root, exactly as before.
   *
   * A refusal is LOGGED, never swallowed: one line naming the session and Chromium's error. A
   * detach that did nothing is the leak this whole path exists to prevent, so it must be visible
   * to an operator instead of being a silent `() => {}` — except for the one refusal that is not
   * a fault ("No session with given id": Chromium already took the session away), which goes to
   * the debug log so a real wrong-owner refusal stands out.
   */
  function detachSession(sessionId, ownerSessionId = null) {
    const id = nextId++;
    const owner = typeof ownerSessionId === "string" && ownerSessionId ? ownerSessionId : null;
    internal.set(id, (msg) => {
      if (!msg || !msg.error) return;
      const reason = String(msg.error.message || "");
      const line = `detach of session ${sessionId} on its owner ${owner || "(root)"} was refused: ${msg.error.code} ${reason}`;
      // "No session with given id" is the ONE refusal that is expected and harmless: Chromium
      // has already taken the session away with the owner or the target that closed it, so there
      // is nothing left to detach. Every OTHER reason — an owner the relay got wrong included —
      // means a session stayed attached while the relay believed it was gone, which is how a
      // request it held leaks past the gate: that one stays an operator-visible line.
      if (reason === "No session with given id") debug(line);
      else log(line);
    });
    const frame = { id, method: "Target.detachFromTarget", params: { sessionId } };
    if (owner) frame.sessionId = owner;
    if (!pipeSend(frame)) internal.delete(id);
  }

  function send(client, msg) {
    if (!client || client.closed) return false;
    const text = typeof msg === "string" ? msg : JSON.stringify(msg);
    const size = Buffer.byteLength(text, "utf8");
    // Outbound frame cap, and then the per-client buffer cap: past either one, that client
    // alone goes (close 1009). The pipe and its siblings never wait on it.
    if (size + 10 > maxFrameBytes) { dropClient(client, 1009, "outbound frame over the cap"); return false; }
    const buffered = client.ws.bufferedBytes();
    if (buffered > 0 && buffered + size + 10 > maxClientBuffer) {
      stats.slowDropped++;
      dropClient(client, 1009, "output buffer over the cap");
      return false;
    }
    const ok = client.ws.sendText(text);
    stats.framesOut++;
    return ok;
  }

  /**
   * A reply the RELAY synthesised, never Chromium's own.
   *
   * It carries the request's `sessionId` back when the request had one — except when that is
   * the client's own browser session (`S_c`), which every FORWARDED reply on it strips too.
   *
   * This is not cosmetic. Playwright's connection routes a response to the session it names
   * and a sessionLESS one to the ROOT session, where `_CRSession._onMessage` runs
   * `assert(!object.id)`: an uncaught exception that kills the MCP process. The MCP declares
   * the guard through `browser.newBrowserCDPSession()`, so its `Crow.guardReady` arrives on a
   * session of its own — and a sessionless `{}` written back takes that whole process down a
   * moment after the guard was declared.
   */
  function replyTo(client, msg, body) {
    if (!client || !msg || msg.id === undefined) return false;
    const out = { id: msg.id, ...body };
    const asked = typeof msg.sessionId === "string" ? msg.sessionId : null;
    if (asked && asked !== client.sc) out.sessionId = asked;
    return send(client, out);
  }

  /**
   * Release a client's sessions to the browser — the ONE per-session release, shared by a whole
   * client's drop, the partial release a `Browser.close` does for its asker, and the release
   * every attached client gets before a turn-end cleanup closes anything.
   *
   * The order is load-bearing. Coverage goes FIRST, before any detach is written: a session that
   * detaches (or disables Fetch) releases its paused requests ONWARD to the next session in the
   * Fetch chain, and they can reach the gate's own session before any event says the session is
   * going away. Clearing coverage afterwards would let the gate pass a request the dead guard
   * never approved. Then the ownership bookkeeping, then the detach itself, the client's own
   * browser session LAST — every child session goes before the session its replies come back on.
   *
   * ONLY TOP-LEVEL sessions are detached, and each on its OWNER's envelope (see
   * `detachSession`). A client's top-level sessions are its `S_c` (ownerless: it detaches at the
   * root) and the sessions `S_c` attached — children announced on `S_c`, and explicit attaches,
   * which `forwardToPipe` stamps with `sessionId = S_c`. A session announced BY one of those — an
   * iframe the client auto-attached under its own page session, or the child an attach RESPONSE
   * announced for an attach the client sent on that session's envelope (`sessionParent` is set
   * from the forwarded envelope in both paths) — is owned by that session, not by `S_c`:
   * Chromium takes it silently when its parent goes, and a detach sent anywhere else is answered
   * "No session with given id" and detaches nothing. So it is never detached separately — only
   * its bookkeeping goes, so a later release does not try to detach a session whose owner has
   * already gone.
   *
   * `keepOwnSession` leaves `S_c`, the client's own browser session, attached and owned: a
   * client that asked for `Browser.close` still owns its reply channel, so the close the relay
   * forwards can be answered to it. That client is not closed and its socket stays open.
   */
  function releaseClientSessions(client, { keepOwnSession = false } = {}) {
    if (!client) return;
    for (const sid of client.sessions) clearSessionCoverage(sid);
    const victims = [];
    for (const sid of client.sessions) {
      if (sid === client.sc) continue;
      const parent = sessionParent.get(sid);
      if (typeof parent === "string" && parent && parent !== client.sc) {
        // A nested child: its parent page session owns it, so it dies with that session.
        forgetSession(sid);
        client.sessions.delete(sid);
        continue;
      }
      victims.push(sid);
    }
    if (!keepOwnSession && client.sc) victims.push(client.sc);
    for (const sid of victims) {
      const parent = sessionParent.get(sid);
      const owner = sid === client.sc ? null : typeof parent === "string" && parent ? parent : client.sc;
      sessionOwner.delete(sid);
      clientSessionTarget.delete(sid);
      client.sessions.delete(sid);
      sessionParent.delete(sid);
      detachSession(sid, owner);
    }
  }

  function dropClient(client, code, why) {
    if (!client || client.closed) return;
    const wasIntent = client.intent === true;
    client.closed = true;
    stats.closed++;
    if (client.deadline) { clearTimeout(client.deadline); client.deadline = null; }
    for (const [child, meta] of [...swallowedSessions]) if (meta.client === client) swallowedSessions.delete(child);
    // Coverage first, then the detaches (see releaseClientSessions): a session that detaches
    // releases what it held onward, and the gate has to already see it uncovered.
    releaseClientSessions(client);
    client.sessions.clear();
    // Its in-flight ids die with it: a late response then finds no owner and is discarded.
    for (const [id, entry] of [...pending]) if (entry.client === client) pending.delete(id);
    // A reply held behind an event this client will never be handed goes with it: the timer is
    // cleared and nothing is written to a closed socket.
    for (const record of gateTargets.values()) {
      if (!record.heldResponses.length) continue;
      const keep = [];
      for (const held of record.heldResponses) {
        if (held.client !== client) { keep.push(held); continue; }
        if (held.timer) clearTimeout(held.timer);
      }
      record.heldResponses = keep;
    }
    client.queue = [];
    client.queueBytes = 0;
    clients.delete(client);
    stats.activeClients = clients.size;
    // The last guard-bearing (or connecting) client left: the cleanup trigger — but never while
    // this relay is on its way out (a stop path already owns the exit, and its own client drops
    // must not start a second cleanup on a browser that is being stopped).
    if (wasIntent && gateReady && !stopping) {
      let remaining = false;
      for (const other of clients) { if (other.intent && !other.closed) { remaining = true; break; } }
      if (!remaining) enterCleanup();
      else recomputeState();
    } else {
      recomputeState();
    }
    client.ws.close(code || 1000);
    debug(`client ${client.id} dropped (${code}): ${why}`);
  }

  /**
   * Send a client's queued frames, in order — but only while doing so is still safe. The state
   * is re-read for EVERY frame, never once before the loop: a `Browser.close` is relay-handled
   * and starts its cleanup SYNCHRONOUSLY, so the frames queued behind it belong to that
   * cleanup's window, not to the IDLE the flush began in. They are put back (re-deferred, ahead
   * of anything that arrived meanwhile) instead of being forwarded into a closing browser.
   */
  function flush(client) {
    if (!client.sc || client.closed) return;
    if (gateState === "CLEANUP") return; // held: the cleanup flushes every queue at IDLE
    const queued = client.queue;
    client.queue = [];
    client.queueBytes = 0;
    for (let i = 0; i < queued.length; i++) {
      if (client.closed) return; // the socket is gone: nothing is owed to it
      if (gateState === "CLEANUP") {
        // A frame in front of this batch started a cleanup: hold the rest of it.
        const rest = queued.slice(i).concat(client.queue);
        client.queue = rest;
        client.queueBytes = rest.reduce((n, text) => n + text.length, 0);
        return;
      }
      forwardText(client, queued[i]);
    }
  }

  function attachBrowserSession(client) {
    const id = nextId++;
    internal.set(id, (msg) => {
      const sessionId = msg && msg.result && msg.result.sessionId;
      if (typeof sessionId !== "string") {
        log(`client ${client.id}: no browser session (${msg && msg.error ? "error " + msg.error.code : "no sessionId"}) — refusing it`);
        dropClient(client, 1011, "browser session unavailable");
        return;
      }
      client.sc = sessionId;
      registerSession(sessionId, client);
      debug(`client ${client.id} attached with its own browser session`);
      flush(client);
    });
    pipeSend({ id, method: "Target.attachToBrowserTarget", params: {} });
  }

  /**
   * Would this message make Chromium open a target AT a URL?
   *
   * `Target.createTarget {url}` hands the URL to the browser with the request: Chromium
   * starts fetching it before any Playwright-side guard (the page-side private-address
   * guard, a route interceptor) can be attached to that target, so a client could reach a
   * private address through a target the guard never sees. Playwright's `newPage()` is not
   * affected: it creates the target as `about:blank` and navigates it afterwards, with the
   * guard already in place — which is exactly the shape this allows through. Only an
   * absent/undefined url, an exact `""` and an exact `"about:blank"` pass; anything else,
   * a non-string included, is refused. The operator's own new tab is opened through
   * Chrome's UI over VNC (a click in the browser window), not through CDP, so it is
   * unaffected by this rule.
   */
  function refusesInitialUrl(msg) {
    if (!msg || msg.method !== "Target.createTarget") return false;
    const params = msg.params;
    if (!params || typeof params !== "object" || Array.isArray(params)) return false;
    if (!Object.prototype.hasOwnProperty.call(params, "url")) return false;
    const url = params.url;
    return !(url === undefined || url === "" || url === "about:blank");
  }

  /**
   * Write one client message to Chromium: the relay's own id, and `sessionId` stamped with
   * the client's browser session when the client sent none (a flat session is addressed).
   */
  function forwardToPipe(client, msg) {
    const sessionId = (typeof msg.sessionId === "string" ? msg.sessionId : null) || client.sc;
    if (msg.id === undefined) { pipeSend({ ...msg, sessionId }); stats.framesIn++; return; }
    const relayMsgId = nextId++;
    const entry = { client, originalId: msg.id, method: typeof msg.method === "string" ? msg.method : null };
    // The ENVELOPE this frame goes out on: `S_c` for every browser-level command (that is what
    // `sessionId` above defaults to), or the client's own session the frame named. A session an
    // attach response announces is owned by THIS envelope in Chromium — the session whose
    // `Target.attachToTarget` / `setAutoAttach` created it — so the response path books the child
    // as nested under it (see `fromPipe`).
    entry.envelope = sessionId;
    // A session can be announced by a response (Target.attachToTarget): the map from a session
    // to its target comes from Chromium's own reply, with the target id the client asked for.
    if (entry.method && entry.method.startsWith("Target.attach") && msg.params && typeof msg.params.targetId === "string") {
      entry.targetId = msg.params.targetId;
    }
    const done = coverageCompletion(client, typeof msg.sessionId === "string" ? msg.sessionId : null, msg);
    if (done) entry.done = done;
    pending.set(relayMsgId, entry);
    pipeSend({ ...msg, id: relayMsgId, sessionId });
    stats.framesIn++;
  }

  function forwardText(client, text) {
    let msg;
    try { msg = JSON.parse(text); } catch { debug(`client ${client.id}: a frame that is not JSON, dropped`); return; }
    if (!msg || typeof msg !== "object" || Array.isArray(msg)) return;
    // Every relay-handled `Crow.*` command, at the VERY TOP: a copy that carries a
    // `sessionId` and one that sat in the pre-session queue take this same path, and neither
    // ever reaches the pipe.
    if (typeof msg.method === "string" && msg.method.startsWith("Crow.")) { handleCrowCommand(client, msg); return; }
    // `Browser.close` is relay-handled too (cleanup first, close only on a clean scan);
    // `Browser.crash` is not: it runs no unload and passes straight through.
    if (msg.method === "Browser.close") {
      // Only the browser may close the browser: a close that NAMES a session is one Chromium
      // refuses, so it closes nothing. Refused here, BEFORE any cleanup and before a close is
      // counted — otherwise the cleanup would run for a close that never happens and leave the
      // gate in CLEANUP with a close owed for the rest of the relay's life, failing every
      // request after one frame. The client's own id comes back, as with the refusals below.
      if (typeof msg.sessionId === "string" && msg.sessionId !== "") {
        replyTo(client, msg, { error: { code: -32602, message: "Browser.close takes no sessionId: the browser is closed by the relay, not by a session" } });
        return;
      }
      handleBrowserClose(client, msg);
      return;
    }
    if (refusesInitialUrl(msg)) {
      // Refused before anything is forwarded: an initial-URL target would fetch its URL
      // before the guard could attach (see refusesInitialUrl). The client's own id comes
      // back, so it sees a normal CDP error and the connection stays open; nothing is
      // queued and no pending entry is created.
      debug(`client ${client.id}: a Target.createTarget with an initial URL was refused`);
      replyTo(client, msg, { error: { code: -32602, message: "Target.createTarget with a URL is refused: create the page as about:blank and navigate it" } });
      return;
    }
    // Non-flat sessions carry their commands in a string param: past the envelope check,
    // past refusesInitialUrl and past every bookkeeping rule. Playwright only uses flat
    // sessions, so both are refused outright, not only when they name a gate session.
    if (msg.method === "Target.sendMessageToTarget") {
      replyTo(client, msg, { error: { code: -32602, message: "Target.sendMessageToTarget is refused: only flat sessions are relayed" } });
      return;
    }
    if (msg.method === "Target.setAutoAttach" && msg.params && typeof msg.params === "object" && msg.params.flatten === false) {
      replyTo(client, msg, { error: { code: -32602, message: "Target.setAutoAttach {flatten:false} is refused: only flat sessions are relayed" } });
      return;
    }
    // `Target.exposeDevToolsProtocol` opens a second protocol driver on a target the gate is
    // in front of. Refused outright, never forwarded.
    if (msg.method === "Target.exposeDevToolsProtocol") {
      replyTo(client, msg, { error: { code: -32602, message: "Target.exposeDevToolsProtocol is refused: a target's protocol is not a client's to hand out" } });
      return;
    }
    // A non-flat attach routes its commands through the root session, a transport the relay
    // does not carry. Only an EXPLICIT flatten:false is refused here, exactly as for
    // setAutoAttach; an absent flatten is forwarded as it always was.
    if (msg.method === "Target.attachToTarget" && msg.params && typeof msg.params === "object" && msg.params.flatten === false) {
      replyTo(client, msg, { error: { code: -32602, message: "Target.attachToTarget {flatten:false} is refused: only flat sessions are relayed" } });
      return;
    }
    const asked = typeof msg.sessionId === "string" ? msg.sessionId : null;
    if (asked && sessionOwner.get(asked) !== client) {
      // Another client's session (or one that never was): refuse, never forward. Forwarding
      // would let one client drive another's page.
      replyTo(client, msg, { error: { code: -32001, message: "Session not owned" } });
      return;
    }
    // Params that name one of the gate's own sessions (`Target.detachFromTarget`, the
    // non-flat transports, anything else in the Target family) are refused: the gate's
    // interception is not a client's to drive. Fetch ids are handled below.
    if (typeof msg.method === "string" && msg.method.startsWith("Target.") && namesGateSession(msg.params)) {
      replyTo(client, msg, { error: { code: -32602, message: "that session belongs to the relay, not to a client" } });
      return;
    }
    if (answersGateRequest(msg)) {
      replyTo(client, msg, { error: { code: -32602, message: "that request belongs to the relay, not to a client" } });
      return;
    }
    // The forwarding barrier on explicit attaches: the command is held until the gate's own
    // interception on that target has been acknowledged (and refused where there is none).
    if (msg.method === "Target.attachToTarget") { gateAttachTarget(client, msg); return; }
    // Coverage ENDS when the relay forwards these, so the bookkeeping runs before the write.
    coverageBeforeForward(client, asked, msg);
    forwardToPipe(client, msg);
  }

  /**
   * Hold one frame a connected client sent during the CLEANUP. `Target.createTarget` is the one
   * command that is answered instead of held: a client must not open a page while the cleanup is
   * closing them. Everything resumes at IDLE.
   */
  function deferInput(client, text) {
    let msg = null;
    try { msg = JSON.parse(text); } catch { msg = null; }
    if (msg && typeof msg === "object" && msg.method === "Target.createTarget") {
      replyTo(client, msg, { error: { code: -32000, message: "Target.createTarget is refused while the relay cleans up after a guard client; retry once it is idle" } });
      return;
    }
    client.queue.push(text);
    client.queueBytes += text.length;
    if (client.queueBytes > maxFrameBytes) dropClient(client, 1009, "queued frames over the cap");
  }

  function fromClient(client, text) {
    if (client.closed) return;
    if (Buffer.byteLength(text, "utf8") > maxFrameBytes) { dropClient(client, 1009, "inbound frame over the cap"); return; }
    if (!client.sc) {
      // Playwright's first commands race the browser-session bootstrap: hold, then flush.
      client.queue.push(text);
      client.queueBytes += text.length;
      if (client.queueBytes > maxFrameBytes) dropClient(client, 1009, "queued frames over the cap");
      return;
    }
    if (gateState === "CLEANUP") {
      // A frame sent DURING the cleanup is held the same way, and flushed at IDLE.
      deferInput(client, text);
      return;
    }
    forwardText(client, text);
  }

  function fromPipe(msg) {
    if (msg.id !== undefined) {
      const handler = internal.get(msg.id);
      if (handler) { internal.delete(msg.id); handler(msg); return; }
      const entry = pending.get(msg.id);
      if (!entry) return; // a late response for a client that is gone: discard
      pending.delete(msg.id);
      const client = entry.client;
      const announced = msg.result && typeof msg.result.sessionId === "string" ? msg.result.sessionId : null;
      // A session can be announced by a response (Target.attachToTarget) or by an event.
      if (announced && entry.method && entry.method.startsWith("Target.attach")) {
        registerSession(announced, client);
        // …and it is owned by the ENVELOPE the command went out on, exactly as Chromium owns it:
        // a client's own `Target.attachToTarget` is stamped with `S_c` by forwardToPipe, so the
        // child is top-level as it always was — but a client may send it on the envelope of one
        // of its OWN sessions (a page session), and then THAT session owns the child. Booking it
        // as nested is what makes `releaseClientSessions` let it die with its parent instead of
        // sending a detach on `S_c`, which Chromium refuses ("No session with given id") and
        // which would leave the session — and any request held at it — unreleased.
        if (typeof entry.envelope === "string" && entry.envelope) sessionParent.set(announced, entry.envelope);
        if (entry.targetId) {
          clientSessionTarget.set(announced, entry.targetId);
          // A target the client auto-attached earlier keeps that session as its current one (a
          // client that never auto-attaches has only this one).
          if (!client.currentSession.has(entry.targetId)) client.currentSession.set(entry.targetId, announced);
        }
      }
      // The gate's coverage bookkeeping runs BEFORE the client sees the answer: a successful
      // Fetch.enable or marker script must count from the moment the client acts on it.
      if (typeof entry.done === "function") { try { entry.done(msg); } catch { /* a bookkeeping slip never stops the relay */ } }
      const out = { ...msg, id: entry.originalId };
      if (out.sessionId === client.sc) delete out.sessionId;
      // ORDERING: a client that auto-attached is handed this target's `attachedToTarget` by
      // `flushGateEvents`, and Playwright's `newPage()` looks the page up by targetId the moment
      // this reply lands — so the reply may never overtake that event. The event is held for
      // the gate's acks, so the reply waits with it (and fails on its own bound). A client with
      // no held event — never auto-attached, already served, or swallowed — is answered now: a
      // raw CDP client must not wait for an event it never asked for.
      const named = responseTargetId(entry, msg);
      const record = named ? gateTargets.get(named) : null;
      if (record && record.pendingEvents.some((item) => item.client === client)) {
        holdResponse(record, client, entry, out);
        return;
      }
      send(client, out);
      return;
    }
    if (typeof msg.method !== "string") return;
    const sessionId = typeof msg.sessionId === "string" ? msg.sessionId : null;
    // The gate's own sessions FIRST: their events are relay code's own, so they are consumed
    // here and never forwarded — and never counted as client traffic in `stats`.
    if (sessionId && gateSessions.has(sessionId)) { onGateEvent(sessionId, msg); return; }
    if (!sessionId) {
      // Every flat browser session is addressed, so a sessionless event has no owner.
      stats.sessionlessEvents++;
      debug(`an event without a session was dropped (${msg.method})`);
      return;
    }
    const owner = sessionOwner.get(sessionId);
    if (!owner) { stats.orphanEvents++; debug(`an event for an unowned session was dropped (${msg.method})`); return; }
    if (msg.method === "Target.attachedToTarget") { onClientAttached(owner, msg); return; }
    if (msg.method === "Target.detachedFromTarget") { onClientDetached(owner, msg); return; }
    const out = { ...msg };
    if (sessionId === owner.sc) delete out.sessionId;
    send(owner, out);
  }

  function addClient(socket, head, intent) {
    const client = {
      id: ++clientSeq, sc: null, sessions: new Set(), queue: [], queueBytes: 0, closed: false, ws: null,
      /** targetId → the session the target's latest attach event named for this client. */
      currentSession: new Map(),
      /** The upgrade carried `X-Crow-Guard-Client: 1`: this client means to be a guard. */
      intent: intent === true,
      /** It sent `Crow.guardReady` after the header: it is G from then on. */
      declared: false,
      /** The CONNECTING deadline's timer (cleared by the declaration, or by the drop). */
      deadline: null,
    };
    client.ws = createWsConnection(socket, head, {
      maxFrameBytes,
      onText: (text) => fromClient(client, text),
      onClose: (why) => dropClient(client, 1000, why),
      onTooBig: () => dropClient(client, 1009, "frame over the cap"),
    });
    clients.add(client);
    stats.clientsCreated = clientSeq;
    stats.activeClients = clients.size;
    if (client.intent) noteIntentClient(client);
    if (gateState === "CLEANUP") {
      // A new upgrade during the cleanup is ACCEPTED, but its browser session waits for IDLE:
      // its connectOverCDP must never initialise a page the cleanup is closing. Its frames sit
      // in the pre-`S_c` queue, exactly as they do before the bootstrap answers.
      void new Promise((resolve) => { idleWaiters.push(resolve); }).then(() => {
        if (!client.closed) attachBrowserSession(client);
      });
    } else {
      attachBrowserSession(client);
    }
    return client;
  }

  /** Only /json/version[/] and the one WebSocket path exist; everything else is unknown. */
  function classify(rawUrl) {
    const path = String(rawUrl || "").split("?")[0].split("#")[0];
    if (path === "/json/version" || path === "/json/version/") return "version";
    const m = /^\/devtools\/browser\/([A-Za-z0-9_-]{1,64})$/.exec(path);
    if (m) return m[1] === relayId ? "ws" : "unknown";
    return "unknown";
  }

  /**
   * One log line per request: method, a fixed label, status. Never a header value, and
   * never the raw path — a client could put the token in a query string, and this line
   * would copy it into the container's log.
   */
  function logLine(method, route, status) {
    const label = route === "version" ? "/json/version" : route === "ws" ? "/devtools/browser" : "(unrecognized path)";
    log(`${method} ${label} ${status}`);
  }

  function authenticate(headers) {
    const raw = headers && headers.authorization;
    const presented = typeof raw === "string" && /^bearer /i.test(raw.trim()) ? raw.trim().slice(7) : "";
    // Always through the comparator, even for an empty or malformed header: one code path,
    // constant time, nothing for an observer to time.
    return compareToken(presented, token);
  }

  function loopbackHost(hostHeader) {
    const host = String(hostHeader || "").trim().toLowerCase();
    const m = LOOPBACK_HOST_RE.exec(host);
    if (!m || Number(m[2]) !== actualPort) return null;
    return host;
  }

  async function readVersion() {
    const msg = await internalRequest("Browser.getVersion");
    return msg && msg.result ? msg.result : null;
  }

  function respond(res, status, body) {
    const text = JSON.stringify(body);
    try {
      res.writeHead(status, {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": Buffer.byteLength(text),
        "Cache-Control": "no-store",
        Connection: "close",
      });
      res.end(text);
    } catch { /* the client went away */ }
  }

  function reject(socket, status, text) {
    try { socket.end(`HTTP/1.1 ${status} ${text}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n`); } catch { /* gone */ }
  }

  async function onRequest(req, res) {
    headSeen.add(req.socket);
    const route = classify(req.url);
    // Auth first: an unauthenticated caller learns nothing about which paths exist.
    if (!authenticate(req.headers)) {
      stats.refused++;
      respond(res, 401, { error: "unauthorized" });
      logLine(req.method, route, 401);
      return;
    }
    if (route === "unknown") {
      respond(res, 404, { error: "not found" });
      logLine(req.method, route, 404);
      return;
    }
    if (route === "ws") {
      respond(res, 426, { error: "this path is for a WebSocket upgrade" });
      logLine(req.method, route, 426);
      return;
    }
    if (req.method !== "GET") {
      respond(res, 405, { error: "method not allowed" });
      logLine(req.method, route, 405);
      return;
    }
    // webSocketDebuggerUrl is only ever built from a loopback Host on this very port, so a
    // page that reaches the relay by name (rebinding, a forward proxy) is told nothing.
    const host = loopbackHost(req.headers.host);
    if (!host) {
      respond(res, 400, { error: "unexpected Host header" });
      logLine(req.method, route, 400);
      return;
    }
    const version = await readVersion();
    if (!version) {
      respond(res, 503, { error: "the browser did not answer" });
      logLine(req.method, route, 503);
      return;
    }
    respond(res, 200, {
      Browser: String(version.product || ""),
      "Protocol-Version": String(version.protocolVersion || ""),
      "User-Agent": String(version.userAgent || ""),
      "V8-Version": String(version.jsVersion || ""),
      "WebKit-Version": version.revision ? `537.36 (@${version.revision})` : "537.36",
      // Present only while the gate is ready: a client that reads it knows it is talking to a
      // relay whose interception is in place (the MCP's status line reads exactly this).
      ...(gateReady ? { "Crow-Guard": "gate/1" } : {}),
      webSocketDebuggerUrl: `ws://${host}/devtools/browser/${relayId}`,
    });
    logLine(req.method, route, 200);
  }

  function onUpgrade(req, socket, head) {
    // Node drops its own socket error handler before handing over an upgrade socket. A peer
    // that resets while we answer (401 included) must never become an uncaught exception,
    // which would take the relay, and Chromium with it, down.
    socket.on("error", () => { try { socket.destroy(); } catch { /* gone */ } });
    headSeen.add(socket);
    const route = classify(req.url);
    if (!authenticate(req.headers)) { stats.refused++; reject(socket, 401, "Unauthorized"); logLine("UPGRADE", route, 401); return; }
    if (route !== "ws") { reject(socket, 404, "Not Found"); logLine("UPGRADE", route, 404); return; }
    if (!loopbackHost(req.headers.host)) { reject(socket, 400, "Bad Request"); logLine("UPGRADE", route, 400); return; }
    const key = typeof req.headers["sec-websocket-key"] === "string" ? req.headers["sec-websocket-key"].trim() : "";
    const wsVersion = String(req.headers["sec-websocket-version"] || "").trim();
    if (!/^[A-Za-z0-9+/]{16,64}={0,2}$/.test(key) || wsVersion !== "13") {
      reject(socket, 400, "Bad Request");
      logLine("UPGRADE", route, 400);
      return;
    }
    const accept = createHash("sha1").update(key + WS_GUID).digest("base64");
    // The gate is installed before a client can connect: a client that gets in front of it
    // would be the one an unguarded page runs on. 503, after the auth and the other checks,
    // and the client may retry (the MCP's connect is retried by its own turn).
    if (!gateReady) {
      reject(socket, 503, "Service Unavailable");
      logLine("UPGRADE", route, 503);
      return;
    }
    socket.write(
      "HTTP/1.1 101 Switching Protocols\r\n" +
      "Upgrade: websocket\r\n" +
      "Connection: Upgrade\r\n" +
      `Sec-WebSocket-Accept: ${accept}\r\n\r\n`,
    );
    // The intent header: this client means to be treated as guard-bearing. It changes no
    // state by itself (a plain client, the watcher, an older MCP): it only arms the
    // CONNECTING deadline and, on `Crow.guardReady`, makes the client G.
    const intent = String(req.headers["x-crow-guard-client"] || "").trim() === "1";
    addClient(socket, head, intent);
    logLine("UPGRADE", route, 101);
  }

  framer.on("message", fromPipe);
  framer.on("close", (reason) => {
    // In pipe mode this is how Chromium's fate reaches the relay: the peer end is gone.
    pipeGone = true;
    // The same code the exit promise below carries, so an exit route that finds the pipe
    // already closed still exits on Chromium's own verdict.
    pipeCode = reason === "eof" ? 0 : 1;
    resolvePipeClosed({ code: reason === "eof" ? 0 : 1, signal: null, reason });
    if (stopping) return;
    // Chromium's output ended: it is gone, or it broke the protocol. Either way this relay
    // has nothing left to serve, and Chromium must not outlive it.
    log(`the pipe to Chromium closed (${reason}) — exiting`);
    killChromium();
  });

  const server = http.createServer({ maxHeaderSize: maxHeaderBytes }, (req, res) => { void onRequest(req, res); });
  server.on("upgrade", onUpgrade);
  server.headersTimeout = handshakeTimeoutMs;
  server.requestTimeout = handshakeTimeoutMs;
  // Node only RE-CHECKS those timers on this interval (default 30 s), which would turn a
  // 10 s handshake timeout into "up to 40 s". Check often enough for the stated timeout.
  server.connectionsCheckingInterval = Math.max(50, Math.min(handshakeTimeoutMs, 1000));
  server.on("clientError", (err, socket) => {
    try { socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"); } catch { /* gone */ }
  });
  const sockets = new Set();
  // Sockets that have delivered a complete request head. Node's own headersTimeout only
  // expires connections on a coarse interval (and not at all before any byte arrives), so
  // the handshake deadline is enforced here too: no head within handshakeTimeoutMs, gone.
  const headSeen = new WeakSet();
  server.on("connection", (socket) => {
    if (sockets.size >= maxConnections) { stats.refused++; try { socket.destroy(); } catch { /* gone */ } return; }
    sockets.add(socket);
    const timer = setTimeout(() => { if (!headSeen.has(socket)) { try { socket.destroy(); } catch { /* gone */ } } }, handshakeTimeoutMs);
    if (typeof timer.unref === "function") timer.unref();
    socket.on("close", () => { clearTimeout(timer); sockets.delete(socket); });
  });

  // reusePort is deliberately NEVER set, here or in the caps: SO_REUSEPORT lets another
  // process of this same uid bind 127.0.0.1:port too, and the kernel would then hand it a
  // share of the connections — its clients' CDP commands and their bearer tokens. One
  // owner of the port, always: this process, or nothing.
  actualPort = await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => resolve(server.address().port));
  });
  // After listen, a server error (an accept failure such as EMFILE) is logged, never thrown:
  // an uncaught one would stop the relay and the browser with it.
  server.on("error", (err) => { try { console.error(`[cdp-relay] server error: ${err && err.code ? err.code : "error"}`); } catch { /* ignore */ } });

  // Readiness is "Chromium answered over the pipe": nothing is served before that.
  const version = await readVersion();
  if (!version) {
    stopping = true;
    try { server.close(); } catch { /* ignore */ }
    killChromium();
    throw new Error("Chromium did not answer Browser.getVersion on its pipe");
  }

  // The gate installs before a single client can connect: `gateReady` was false from the
  // moment this relay existed (upgrades 503, no `Crow-Guard`), and the ready file is written
  // by the callers only once this function returns. One attempt with a hard deadline; on
  // failure the browser stops and this throws, so no caller can announce a gate-less relay.
  {
    const gateFailure = await startGate();
    if (gateFailure) {
      // Exactly one line about it: this is the start sequence's own failure, nothing else.
      log(`gate: the start sequence failed (${gateFailure}) — stopping Chromium`);
      killChromium();
      throw new Error("the relay's private-address interception did not install, so no client may connect");
    }
    gateReady = true;
    log("gate ready");
    // IDLE: no guard, none connecting. Requests pass and the targets that exist resume, so
    // the operator's own browsing between bot turns is not held up.
    gateState = "IDLE";
    log("gate state IDLE");
    reconcileAll();
  }

  /**
   * The tail of every graceful stop, whether this process wrote the close or a client's close
   * had already gone out: the clients go, the listener closes, the pipe ends. Shared so the two
   * stop shapes cannot drift apart.
   */
  async function finishStop(exitCode) {
    for (const client of [...clients]) dropClient(client, 1001, "the relay is stopping");
    await new Promise((resolve) => {
      const t = setTimeout(resolve, 500);
      if (typeof t.unref === "function") t.unref();
      server.close(() => { clearTimeout(t); resolve(); });
    });
    try { input.destroy(); } catch { /* gone */ }
    try { output.destroy(); } catch { /* gone */ }
    process.exitCode = exitCode;
  }

  /**
   * A graceful stop: the cleanup first, then `Browser.close` — and only on a clean scan. Resolves
   * true when the browser was closed through the pipe, false when the stop path owns the exit
   * (the browser is then being stopped, and this process must not exit 0).
   *
   * A `Browser.close` that has ALREADY gone out (a client's, whose cleanup is the one that ran) is
   * not this stop's to run again: a SECOND cleanup would create another replacement page and
   * navigate and close against a browser that is on its way out. What a joining stop owes there
   * is the wait — Chromium's own exit, bounded by `closeTimeoutMs` exactly as below — and then
   * the same tail; the gate is already CLEANUP for that close and stays there.
   */
  async function shutdown(exitCode = 0) {
    if (stopping) return false;
    stopping = true;
    // A close was already forwarded: by `handleBrowserClose` (`closeForwarded`), or — in
    // `--attach` only — the supervisor was already told this is a graceful close
    // (`closingReported`, written immediately before that same write). Either way the cleanup
    // owed for the close has run.
    const closeAlreadyForwarded = closeForwarded || closingReported;
    // The graceful path runs the cleanup FIRST, and `Browser.close` is written only when the scan
    // after it came back clean: closing a page that is still live runs its pagehide and unload
    // traffic with the guard already gone (S4 11). The budgets add up — the cleanup inside its
    // own cap, then the browser's close inside `closeTimeoutMs`.
    //
    // BEFORE the cleanup: a clean scan must NOT re-open the gate here. Chromium keeps running
    // its pages between `Browser.close` and its own exit, and the gate stays CLEANUP (every
    // request failed) until the browser is gone. Counted before the call and never decremented
    // — a stop is terminal — so a cleanup already in flight that this shutdown joins reads it
    // when it ends, and a client's withdrawn ask cannot take this one away.
    closeIntents++;
    if (!closeAlreadyForwarded) {
      // NO REQUEST MAY REACH THE NETWORK THROUGH AN ADVANCING FETCH CHAIN — the same rule
      // `handleBrowserClose` applies, for the stop path. A live client holds its own Fetch
      // session on a page, newer than the gate's, so a request of that page pauses at the
      // CLIENT's session first; the cleanup DEFERS the client's answers, so the request sits
      // there until `Target.closeTarget` takes every session of the page at once, and then it
      // advances past the sessions that vanished and PASSES without the gate ever seeing it. A
      // session that DETACHES releases what it held ONWARD to the gate's session instead, which
      // fails it in CLEANUP. So before the cleanup may close any target: the gate goes CLEANUP
      // first (released requests are FAILED, not passed), then every connected client is dropped
      // (coverage cleared, sessions detached, held requests released onward), and only then does
      // the cleanup run. The pipe to Chromium is ORDERED, so those detaches are processed before
      // the cleanup's first `Target.closeTarget`. The drop loop in `finishStop` stays as the
      // belt for a client that arrives later; it is a no-op for these.
      if (gateReady && !gateLost && gateState !== "CLEANUP") setState("CLEANUP");
      for (const client of [...clients]) dropClient(client, 1001, "the relay is stopping");
      const clean = await startCleanup();
      if (!clean || gateLost) {
        stopPath("a graceful stop could not be preceded by a clean cleanup");
        return false;
      }
      // Nothing may have re-opened the gate between the clean scan and the close: re-assert
      // CLEANUP here, before the supervisor is told and before `Browser.close` is written, so
      // every request the closing Chromium's pages still make fails at the gate.
      if (gateReady && !gateLost && gateState !== "CLEANUP") setState("CLEANUP");
      // The supervisor is told BEFORE the line that closes the browser: from here on fd 5's EOF
      // and this process's exit are expected, and Chromium's own exit is what is waited for (a
      // SIGKILL in the middle of a close loses the cookie commit).
      reportClosing();
      // Ask Chromium to close, which is what commits its cookie store.
      pipeSend({ id: nextId++, method: "Browser.close", params: {} });
      closeForwarded = true;
    }
    const how = await Promise.race([exited.then(() => "exited"), delay(closeTimeoutMs).then(() => "timeout")]);
    if (how === "timeout") {
      log(`Chromium did not close within ${Math.round(closeTimeoutMs / 1000)}s — killing it`);
      killChromium();
      await Promise.race([exited, delay(2000)]);
    }
    await finishStop(exitCode);
    return true;
  }

  return {
    port: actualPort,
    relayId,
    version,
    stats,
    child,
    mode: pipeMode ? "pipe" : "spawn",
    exited,
    shutdown,
    killChromium,
    /**
     * The `process.on("exit")` hook's whole repertoire: the one thing an exit hook can still do
     * is write the kill line, synchronously. False when there is no supervisor (no kill line).
     */
    writeKillLineSync() {
      // A graceful close already went out on that fd: a `kill` now would undo the supervisor's
      // wait and SIGKILL Chromium while it commits its cookie store. A kill the stop path
      // already wrote is not written a second time either.
      if (closingReported) return true;
      return reportKill();
    },
    /** The exit hook's fallback where this process owns Chromium: SIGKILL its group. */
    killChildGroupSync: (signal = "SIGKILL") => signalChromiumGroup(signal),
    /** The stop path ran: whatever ends this process, it must not end it with 0. */
    isGateLost: () => gateLost,
    isChildExited: () => childExited,
    url: `ws://127.0.0.1:${actualPort}/devtools/browser/${relayId}`,
  };
}

/** The profile Chromium is given: the argv below and the pre-launch rewrite both use it. */
function chromiumProfileDir(env = process.env) {
  return env.CROW_CHROMIUM_PROFILE || "/root/.config/chromium-crow";
}

/**
 * Delete a profile's saved-session files, best effort.
 *
 * `Default/Sessions/` holds the session's own files and `Default/` keeps four beside it
 * (`Current Session`, `Current Tabs`, `Last Session`, `Last Tabs`). They are the crashed
 * session's pages, so they go with the rewrite. A missing directory or file is normal (a
 * profile that never crashed has none) and a failed delete is not this caller's problem:
 * neither case throws, and nothing here ever creates a file or a directory.
 */
function removeSavedSessions(defaultDir) {
  const sessionsDir = join(defaultDir, "Sessions");
  let entries = [];
  try { entries = readdirSync(sessionsDir); } catch { entries = []; } // no Sessions dir: nothing inside it
  for (const name of entries) {
    try { rmSync(join(sessionsDir, name), { recursive: true, force: true }); } catch { /* best effort */ }
  }
  for (const name of ["Current Session", "Current Tabs", "Last Session", "Last Tabs"]) {
    try { rmSync(join(defaultDir, name), { force: true }); } catch { /* best effort */ }
  }
}

/**
 * Prepare the profile Chromium is about to open, on EVERY launch (plan r5.1 row 1).
 *
 * A stop-path SIGKILL leaves a profile whose saved session lists the bot's tabs, and a
 * profile set to "continue where you left off" (a VNC operator can set that) reopens them
 * as Chromium starts — before the gate is ready, and before any MCP can be in front of a
 * page. So both halves are done unconditionally, without reading the profile's exit
 * record: the saved session state is deleted, and the startup choice is pointed at the new
 * tab page. A short-uptime kill is exactly the case the old `markProfileExitClean` rule
 * missed: Chromium had not written `profile.exit_type` yet, so it did nothing while the
 * session files were there.
 *
 * Nothing here invents a profile: a Preferences that is missing is not created, and one
 * that does not parse is left byte for byte alone — the session state is removed in both
 * cases, because that removal never depended on the rewrite. The rewrite itself is atomic
 * (temp file in the same directory, same mode, rename), so Chromium never reads half a
 * Preferences. Best effort throughout: no Default directory is normal, and nothing throws
 * for a file this process may not read.
 */
export function prepareProfileForLaunch(profileDir) {
  if (typeof profileDir !== "string" || !profileDir) return;
  const defaultDir = join(profileDir, "Default");
  // The pages first: a rewrite that cannot happen must not leave them to be restored.
  removeSavedSessions(defaultDir);
  rewriteStartupChoice(join(defaultDir, "Preferences"));
}

/**
 * Point one Preferences file at the new tab page with a clean exit record, keeping every
 * other key. Never creates the file; never touches an unparseable one.
 */
function rewriteStartupChoice(prefs) {
  let raw;
  let mode;
  try {
    mode = statSync(prefs).mode & 0o777;
    raw = readFileSync(prefs, "utf8");
  } catch { return; } // no file (or no Default dir): nothing to rewrite, nothing to create
  let parsed;
  try { parsed = JSON.parse(raw); } catch { return; } // unparseable: leave the bytes alone
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return;
  const profile = parsed.profile && typeof parsed.profile === "object" && !Array.isArray(parsed.profile) ? parsed.profile : {};
  const session = parsed.session && typeof parsed.session === "object" && !Array.isArray(parsed.session) ? parsed.session : {};
  // "Continue where you left off" (1, and 4 on some builds) restores the saved session by
  // itself, bubble or no bubble; "open a specific page" (3) would reopen the bot's tabs too.
  // Only the startup choice changes — the operator's start pages and every other key stay.
  session.restore_on_startup = 5;
  parsed.session = session;
  profile.exit_type = "Normal";
  profile.exited_cleanly = true;
  parsed.profile = profile;

  const dir = dirname(prefs);
  const temp = join(dir, `.Preferences.${randomBytes(8).toString("hex")}.tmp`);
  let fd;
  try {
    fd = openSync(temp, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, mode);
    writeSync(fd, JSON.stringify(parsed));
    closeSync(fd);
    fd = undefined;
    renameSync(temp, prefs);
  } catch (err) {
    if (fd !== undefined) { try { closeSync(fd); } catch { /* gone */ } }
    try { rmSync(temp, { force: true }); } catch { /* gone */ }
    throw err;
  }
}

/**
 * Record the last exit as clean in the profile Chromium is about to open — but ONLY when
 * that profile says the last exit CRASHED. After the exit cleanup kills the browser
 * (`Browser.crash`, on purpose), the profile says "Crashed", and the next launch offers to
 * restore that session's pages in the VNC viewer — which can reopen a page the bot loaded.
 * The switch (--hide-crash-restore-bubble) hides the bubble; this makes the record itself
 * clean, so there is nothing to restore. Called BEFORE the spawn: Chromium reads it at
 * startup. A missing file, an unparseable one, or no Default directory does nothing at all
 * (never creates a file, never throws); the rewrite is atomic (temp file in the same
 * directory + rename, same mode), so Chromium never reads half a Preferences.
 *
 * A CLEAN record is left alone, byte for byte (exit_type "Normal", "None", or no
 * `profile.exit_type` at all): the bubble and the crashed-session restore are only a
 * problem AFTER A CRASH, and a crash is exactly what the exit cleanup's `Browser.crash`
 * causes on purpose. Rewriting a clean profile would be destructive in its own right — it
 * re-serialises the operator's own file, overrides a "continue where you left off" they
 * chose deliberately, and deletes session files that belong to a clean exit — so the whole
 * rewrite below is gated on `profile.exit_type === "Crashed"`.
 *
 * The bubble is not the only way a crashed session comes back: a profile whose startup
 * setting is "Continue where you left off" (session.restore_on_startup 1, or 4 on some
 * builds) reopens the crashed tabs by itself, bubble or no bubble. So the same rewrite
 * points that setting at the new tab page (5) — the other keys of `session` are kept, and
 * any other value (the default, "open the new tab page", "open a specific page") is left
 * exactly as the operator set it — and then deletes the saved session it would have
 * restored. Nothing is deleted before the profile is known to be parsable and crashed: a
 * Preferences this function will not touch leaves its session files alone too.
 *
 * Nothing in the launch path calls this any more: `prepareProfileForLaunch` supersedes it
 * and runs unconditionally. It is kept, unchanged and exported, because the supervisor's
 * own tests import it as the CONTROL that shows why the exit-record rule was not enough (a
 * short-uptime SIGKILL leaves no `profile.exit_type`, so this function did nothing while
 * the session files were still there).
 */
export function markProfileExitClean(profileDir) {
  if (typeof profileDir !== "string" || !profileDir) return;
  const prefs = join(profileDir, "Default", "Preferences");
  let raw;
  let mode;
  try {
    mode = statSync(prefs).mode & 0o777;
    raw = readFileSync(prefs, "utf8");
  } catch { return; } // no file (or no Default dir): nothing to rewrite, nothing to create
  let parsed;
  try { parsed = JSON.parse(raw); } catch { return; } // unparseable: leave the bytes alone
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) return;
  const profile = parsed.profile && typeof parsed.profile === "object" && !Array.isArray(parsed.profile) ? parsed.profile : {};
  // ACT ON A CRASHED RECORD ONLY. A clean profile has nothing to restore, so its file,
  // its restore_on_startup setting and its saved session are none of this function's
  // business — and "None" or a missing key says nothing about a crash either.
  if (profile.exit_type !== "Crashed") return;
  profile.exit_type = "Normal";
  profile.exited_cleanly = true;
  parsed.profile = profile;
  // "Continue where you left off" restores the crashed session on its own, bubble or not:
  // only that setting is changed, and only to the new tab page. 3 ("open a specific page")
  // names the operator's own start pages and is none of this rewrite's business.
  const session = parsed.session && typeof parsed.session === "object" && !Array.isArray(parsed.session) ? parsed.session : null;
  if (session && (session.restore_on_startup === 1 || session.restore_on_startup === 4)) {
    session.restore_on_startup = 5;
    parsed.session = session;
  }

  const dir = dirname(prefs);
  const temp = join(dir, `.Preferences.${randomBytes(8).toString("hex")}.tmp`);
  let fd;
  try {
    fd = openSync(temp, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, mode);
    writeSync(fd, JSON.stringify(parsed));
    closeSync(fd);
    fd = undefined;
    renameSync(temp, prefs);
  } catch (err) {
    if (fd !== undefined) { try { closeSync(fd); } catch { /* gone */ } }
    try { rmSync(temp, { force: true }); } catch { /* gone */ }
    throw err;
  }
  // The profile is clean and points at the new tab page; the pages themselves are the one
  // thing left that a launch could reopen, so they go now (after the rewrite: a profile this
  // function refused to touch keeps its session files).
  removeSavedSessions(dir);
}

/** The Chromium argv: the entrypoint's flags, minus the debugging port, plus the pipe. */
export function chromiumArguments(env = process.env) {
  const profileDir = chromiumProfileDir(env);
  const args = [
    "--no-sandbox", "--disable-setuid-sandbox",
    // No --remote-debugging-port and no --remote-allow-origins: with a pipe there is no
    // port to open and no Origin check to disable; the relay's bearer is the control.
    "--remote-debugging-pipe",
    "--disable-blink-features=AutomationControlled",
    // Defence in depth next to the page-level WebRTC disable in server/private-address.js;
    // a live check found Chromium ignoring this switch, so it is not relied on.
    "--force-webrtc-ip-handling-policy=disable_non_proxied_udp",
    // A Back press in the VNC viewer must not restore a page the bot opened from the back-forward cache: the exit cleanup leaves a fresh about:blank page, and a later feature must be comma-merged into this one flag (Chromium honours only the last --disable-features).
    "--disable-features=BackForwardCache",
    "--window-size=1920,1080", "--start-maximized",
    "--no-first-run", "--no-default-browser-check",
    "--disable-infobars", "--disable-extensions",
    // The exit cleanup kills the browser, so a restart would offer to restore the crashed
    // session's pages in the VNC viewer — a way back into a page the bot loaded.
    "--hide-crash-restore-bubble",
    `--user-data-dir=${profileDir}`,
  ];
  if (env.CHROME_PROXY) args.push(`--proxy-server=${env.CHROME_PROXY}`);
  args.push("about:blank");
  return args;
}

/**
 * The CLI. Four modes, and the first two are the container's shape since 1.7.0:
 *
 *   --supervise  root: start Chromium (root) and the relay (the gateway's uid), own both,
 *                and write the ready file once the relay reports in.
 *   --attach     the gateway's uid: serve 127.0.0.1:${CDP_PORT} from the pipe on fds 3/4
 *                and report ready on fd 5. Never writes the ready file, never spawns.
 *   --holder     the supervisor's own child: holds copies of Chromium's pipe on fds 3/4 and
 *                never reads or writes them (see spawnHolder).
 *   (no flag)    the pre-1.7.0 shape, kept for the unit tests: spawn Chromium here, serve,
 *                write the ready file, and share fate with Chromium.
 *
 * Env (none of it secret): CDP_PORT, CHROME_PATH, CHROME_PROXY, CROW_CHROMIUM_PROFILE,
 * CROW_CDP_TOKEN_FILE, CROW_CDP_READY_FILE, CROW_CDP_DEBUG, CROW_CDP_RELAY_UID /
 * CROW_CDP_RELAY_GID (the supervisor's), plus the test seams CROW_CDP_CHROMIUM_ARGV (a
 * JSON argv prefix that speaks the pipe) and the size caps CROW_CDP_MAX_FRAME /
 * CROW_CDP_MAX_CLIENT_BUFFER / CROW_CDP_MAX_CONNECTIONS / CROW_CDP_MAX_HEADER /
 * CROW_CDP_HANDSHAKE_TIMEOUT_MS / CROW_CDP_CLOSE_TIMEOUT_MS.
 */
export async function main(argv = process.argv.slice(2)) {
  if (argv.includes("--holder")) return holderProcess();
  if (argv.includes("--supervise")) return supervise();
  if (argv.includes("--attach")) return attach();
  return serveInProcess();
}

/** The debug-aware loggers every mode uses. */
function loggers() {
  const debugOn = process.env.CROW_CDP_DEBUG === "1";
  const log = (msg) => console.log(`[cdp-relay] ${msg}`);
  const debug = (msg) => { if (debugOn) log(msg); };
  return { log, debug };
}

/** The default ready file: inside the root-owned 0755 directory the entrypoint creates. */
const DEFAULT_READY_FILE = "/run/crow-cdp-ready/cdp-relay.ready";

/**
 * Write the ready file the way root must: unlink whatever is there, create a FRESH file
 * under a random temp name with O_CREAT|O_EXCL|O_NOFOLLOW (so a symlink or a name planted
 * at that path is refused, never followed or truncated), write the body, then rename it
 * into place inside the same directory. The rename is what makes the entrypoint's
 * `[ -s "$CDP_READY_FILE" ]` see either nothing or the whole line, and the directory is
 * root-owned, so no process of the relay's uid can plant or replace it.
 */
function writeReadyFile(readyFile, body) {
  const dir = dirname(readyFile);
  mkdirSync(dir, { recursive: true });
  try { rmSync(readyFile, { force: true, recursive: true }); } catch { /* the create below refuses what is left */ }
  const temp = join(dir, `.${basename(readyFile)}.${randomBytes(8).toString("hex")}.tmp`);
  let fd;
  try {
    fd = openSync(temp, constants.O_CREAT | constants.O_EXCL | constants.O_NOFOLLOW | constants.O_WRONLY, 0o644);
    writeSync(fd, body);
    closeSync(fd);
    fd = undefined;
    renameSync(temp, readyFile);
  } catch (err) {
    if (fd !== undefined) { try { closeSync(fd); } catch { /* gone */ } }
    try { rmSync(temp, { force: true }); } catch { /* gone */ }
    throw err;
  }
}

/**
 * The pre-1.7.0 shape (no flag): Chromium is this process's own child, the ready file is
 * written here, and the exit code is Chromium's. The unit tests drive this directly.
 */
async function serveInProcess() {
  const { log, debug } = loggers();
  const token = readToken();
  const port = readPort();
  const chromiumArgv = chromiumCommand();
  debug(`Chromium: ${chromiumArgv[0]}`);
  // Before the browser reads the profile: no saved session to restore and a startup choice
  // that opens the new tab page, on every launch (plan r5.1 row 1).
  try { prepareProfileForLaunch(chromiumProfileDir()); } catch (err) { debug(`could not prepare the profile: ${(err && err.message) || err}`); }

  let relay;
  try {
    relay = await createRelay({ token, port, chromiumArgv, log, debug, ...capsFromEnv() });
  } catch (err) {
    die(String((err && err.message) || err));
  }

  const readyFile = process.env.CROW_CDP_READY_FILE || DEFAULT_READY_FILE;
  const removeReadyFile = () => { try { rmSync(readyFile, { force: true }); } catch { /* gone */ } };
  try {
    writeReadyFile(readyFile, JSON.stringify({ pid: process.pid, port: relay.port, browser: String(relay.version.product || "") }) + "\n");
  } catch {
    relay.killChromium();
    die(`cannot write the ready file (${readyFile})`);
  }
  log(`ready on 127.0.0.1:${relay.port} — Chromium ${relay.version.product || "(unknown)"} over a pipe, bearer required`);

  let stopping = false;
  void relay.exited.then(({ code }) => {
    // Chromium's fate is ours: the entrypoint sees the relay exit and takes the container
    // down, so a crashed browser restarts instead of leaving a dead port behind. A stop path
    // is never a clean exit, whatever code the pipe reported.
    if (stopping) return;
    log(`Chromium exited (${code === null ? "signal" : `code ${code}`}); exiting with it`);
    removeReadyFile();
    relay.killChromium();
    if (relay.isGateLost()) process.exit(1);
    process.exit(code === null ? 1 : code);
  });

  const stop = async (signal) => {
    if (stopping) return;
    stopping = true;
    log(`${signal}: closing Chromium through the pipe...`);
    const clean = await relay.shutdown(0);
    // The stop path owns the exit when the cleanup did not come back clean: Chromium is being
    // stopped and this process must not pretend it was a graceful stop.
    if (!clean) return;
    removeReadyFile();
    log("stopped.");
    process.exit(0);
  };
  process.on("SIGTERM", () => { void stop("SIGTERM"); });
  process.on("SIGINT", () => { void stop("SIGINT"); });
  const crash = (err) => {
    console.error(`[cdp-relay] FATAL: ${(err && err.message) || err}`);
    relay.killChromium();
    removeReadyFile();
    process.exit(1);
  };
  process.on("uncaughtException", crash);
  process.on("unhandledRejection", crash);
  // Last resort for any other exit path: never leave Chromium running ungated. Where a kill line
  // exists it is written synchronously; otherwise this process owns the child and kills its group.
  process.on("exit", () => { if (!relay.writeKillLineSync()) relay.killChildGroupSync(); });
}

/**
 * --attach: the gateway's uid. The pipe is already open (the supervisor passed Chromium's
 * fds 3 and 4), so this mode wraps them and serves the host contract on the loopback port.
 * It never spawns, never writes the ready file (it could not: it is not root), and exits
 * when the pipe closes — Chromium's death is its death.
 */
async function attach() {
  const { log, debug } = loggers();
  const token = readToken();
  const port = readPort();
  // The inherited fds are socketpairs (Node's `pipe` stdio), so a net.Socket can wrap
  // them: input is the end Chromium reads (we write), output the end it writes (we read).
  const input = new net.Socket({ fd: 3, readable: true, writable: true });
  const output = new net.Socket({ fd: 4, readable: true, writable: true });

  let relay;
  const killLine = () => {
    // fd 5 stays OPEN for the relay's whole life now: it carries `ready` once and then the kill
    // line the supervisor acts on. A failed write is not thrown — it is the stop path's cue to
    // ask the browser to crash itself instead.
    try { writeSync(5, "kill\n"); return true; } catch { return false; }
  };
  /**
   * The graceful close, on the same fd: the supervisor stops treating EOF and this process's
   * exit as a kill and waits for Chromium's own exit instead.
   */
  const closingLine = () => {
    try { writeSync(5, "closing\n"); return true; } catch { return false; }
  };
  try {
    relay = await createRelay({ token, port, pipe: { input, output }, killLine, closingLine, log, debug, ...capsFromEnv() });
  } catch (err) {
    die(String((err && err.message) || err));
  }

  const uid = typeof process.getuid === "function" ? process.getuid() : "?";
  log(`ready on 127.0.0.1:${relay.port} — Chromium ${relay.version.product || "(unknown)"} over a pipe, bearer required, as uid ${uid}`);
  // One line on fd 5 is the supervisor's cue to write the ready file. It carries the port
  // and the browser, never the token. The fd is NOT closed here: the kill line goes down it.
  try {
    writeSync(5, `ready ${JSON.stringify({ port: relay.port, browser: String(relay.version.product || "") })}\n`);
  } catch {
    relay.killChromium();
    die("cannot report ready to the supervisor (fd 5): start this mode through --supervise");
  }

  let stopping = false;
  void relay.exited.then(({ code }) => {
    if (stopping) return;
    log("the pipe to Chromium closed; exiting with it");
    // A stop path is never a clean exit, whatever code the pipe reported.
    process.exit(relay.isGateLost() ? 1 : typeof code === "number" ? code : 1);
  });

  const stop = async (signal) => {
    if (stopping) return;
    stopping = true;
    log(`${signal}: closing Chromium through the pipe...`);
    const clean = await relay.shutdown(0);
    // The stop path owns the exit when the cleanup did not come back clean.
    if (!clean) return;
    log("stopped.");
    process.exit(0);
  };
  process.on("SIGTERM", () => { void stop("SIGTERM"); });
  process.on("SIGINT", () => { void stop("SIGINT"); });
  const crash = (err) => {
    console.error(`[cdp-relay] FATAL: ${(err && err.message) || err}`);
    relay.killChromium();
    process.exit(1);
  };
  process.on("uncaughtException", crash);
  process.on("unhandledRejection", crash);
  // Last resort for any other exit path: the kill line is the only thing an `exit` hook can
  // still do, and it must be synchronous. Never let Chromium outlive this process ungated.
  process.on("exit", () => { relay.writeKillLineSync(); });
}

/**
 * The supervisor's non-reading copy of Chromium's pipe: a child of the supervisor, in its OWN
 * process group, with fds 3 and 4 — this process's ends of the browser's pipe — and nothing
 * else (no environment beyond PATH, Node builtins only).
 *
 * It exists because the pipe has to outlive the relay: Chromium reads EOF on its own fd 3 as
 * "the browser is over" and runs the pages' pagehide/unload traffic, so if the relay dies and
 * nothing else holds the pipe open, Chromium gets its unload window before the supervisor can
 * kill it. A copy kept in this process would be a copy that READS, and a reader here races the
 * relay for frames; a child that never touches fds 3 and 4 holds them without reading a byte.
 */
function spawnHolder(chrome) {
  const env = process.env.PATH === undefined ? {} : { PATH: process.env.PATH };
  try {
    const holder = spawn(process.execPath, [SELF, "--holder"], {
      stdio: ["ignore", "ignore", "ignore", chrome.stdio[3], chrome.stdio[4]],
      detached: true,
      env,
    });
    holder.on("error", () => { /* nothing to do: this process still holds the pipe until the destroy below */ });
    return holder;
  } catch {
    return null;
  }
}

/**
 * --holder: the non-reading copy of Chromium's pipe (see spawnHolder). It never reads or
 * writes fds 3 and 4; it just keeps them open until the supervisor kills it, which it does
 * only after Chromium is confirmed gone, and in every finish(). SIGTERM ends it at once.
 *
 * It also leaves when its parent does: a supervisor killed outright never reaches its own
 * finish(), and a holder left behind would sit on a dead browser's pipe and keep a Chromium
 * with no relay in front of it alive. Leaving turns that into the browser's own pipe-EOF exit.
 */
function holderProcess() {
  const parentPid = process.ppid;
  setInterval(() => {
    // The no-op that keeps this process alive, and the one check it makes: is the supervisor
    // still there? (The kernel reparents an orphan, so its pid is no longer ours.)
    if (process.ppid !== parentPid) process.exit(0);
  }, 250);
  process.on("SIGTERM", () => process.exit(0));
  process.on("SIGINT", () => process.exit(0));
}

/**
 * --supervise: the root process the entrypoint starts. It owns Chromium (left root: the
 * image's /root is 0700 and the profile lives there) and the relay (re-exec'd as the
 * GATEWAY's uid through setpriv), gives the relay Chromium's pipe and a report pipe, and
 * writes the ready file itself. It listens on no socket of any kind.
 *
 * The report pipe is not one-shot: after `ready` the relay writes `kill` on it when its stop
 * path has to take the browser down, and EOF there is the same signal. Both SIGKILL
 * Chromium's whole process group at once — never a `Browser.close`, which would run a live
 * page's unload traffic — and this process then exits non-zero so the container recycles. A
 * `closing` line instead marks a graceful close: EOF and the relay's exit are then expected,
 * and Chromium's own exit is waited for inside the stop budget.
 */
async function supervise() {
  const { log, debug } = loggers();
  const uid = parseId(process.env.CROW_CDP_RELAY_UID);
  if (uid === null) {
    die(`CROW_CDP_RELAY_UID ('${String(process.env.CROW_CDP_RELAY_UID ?? "")}') is not a decimal uid between 0 and ${MAX_ID}. Crow's gateway passes it when it runs compose (from CROW_GATEWAY_UID): the relay must listen as the gateway's own uid, and there is no default.`);
  }
  const gid = parseId(process.env.CROW_CDP_RELAY_GID);
  if (gid === null) {
    die(`CROW_CDP_RELAY_GID ('${String(process.env.CROW_CDP_RELAY_GID ?? "")}') is not a decimal gid between 0 and ${MAX_ID}. Crow's gateway passes it when it runs compose (from CROW_GATEWAY_GID), alongside CROW_CDP_RELAY_UID; there is no default.`);
  }
  const euid = typeof process.geteuid === "function" ? process.geteuid() : null;
  // Root can start the relay on any uid; anything else can only start it on its own, and a
  // relay on a uid the gateway does not have would be refused by the add-on wall anyway.
  const drop = euid === 0 && uid !== 0;
  if (euid === 0) {
    if (!drop) log("CROW_CDP_RELAY_UID is 0: this gateway runs as root, so the relay runs as root too (no uid split).");
    else if (!existsSync(SETPRIV)) die(`${SETPRIV} is missing from this image, so the relay cannot be started as uid ${uid}: rebuild the browser image (the Dockerfile asserts it).`);
  } else if (uid !== euid) {
    die(`CROW_CDP_RELAY_UID (${uid}) is not this process's uid (${euid}): without root the relay can only run as its own uid, and one on another uid would be refused by the add-on wall.`);
  }

  const caps = capsFromEnv();
  // The stop budget: the relay's cleanup inside its cap, then its browser close inside its
  // own, plus 2 s of slack. The SIGTERM stop and the wait after a `closing` line share it.
  const { cleanupBudgetMs: cleanupMs, closeTimeoutMs } = caps;
  const stopBudgetMs = cleanupMs + closeTimeoutMs + 2000;
  const readyFile = process.env.CROW_CDP_READY_FILE || DEFAULT_READY_FILE;
  const chromiumArgv = chromiumCommand();
  debug(`Chromium: ${chromiumArgv[0]}`);
  // The profile belongs to root, and this is the root process: its saved session goes and its
  // startup choice is pointed at the new tab page on EVERY launch (plan r5.1 row 1) — not only
  // after a record that says "Crashed", because a stop-path SIGKILL seconds into the run leaves
  // no exit record at all while the session files are already there.
  try { prepareProfileForLaunch(chromiumProfileDir()); } catch (err) { debug(`could not prepare the profile: ${(err && err.message) || err}`); }

  // Chromium keeps this process's environment minus every secret-shaped name (the token's
  // location included), exactly as before the split.
  const chromeEnv = {};
  for (const [k, v] of Object.entries(process.env)) if (!SECRET_ENV_RE.test(k)) chromeEnv[k] = v;
  const chrome = spawn(chromiumArgv[0], chromiumArgv.slice(1), {
    stdio: ["ignore", "inherit", "inherit", "pipe", "pipe"],
    detached: true,
    env: chromeEnv,
  });
  if (!chrome.stdio || !chrome.stdio[3] || !chrome.stdio[4]) {
    try { chrome.kill("SIGKILL"); } catch { /* gone */ }
    die("Chromium did not get its pipe (fds 3 and 4), so there is nothing for the relay to attach to");
  }

  const relayEnv = {};
  for (const key of RELAY_ENV_KEYS) if (process.env[key] !== undefined) relayEnv[key] = process.env[key];

  const relay = drop
    ? spawn(SETPRIV, [
      "--reuid", String(uid), "--regid", String(gid), "--clear-groups",
      "--inh-caps=-all", "--bounding-set=-all", "--no-new-privs",
      "--", process.execPath, SELF, "--attach",
    ], { stdio: ["ignore", "inherit", "inherit", chrome.stdio[3], chrome.stdio[4], "pipe"], env: relayEnv })
    : spawn(process.execPath, [SELF, "--attach"], {
      stdio: ["ignore", "inherit", "inherit", chrome.stdio[3], chrome.stdio[4], "pipe"],
      env: relayEnv,
    });

  // …and in this same synchronous tick, a HOLDER: a child that is handed this process's copies
  // of Chromium's pipe on fds 3/4 and never reads or writes them. The pipe has to stay open
  // until Chromium is dead even when the relay dies first — Chromium reads EOF as "the browser
  // is over" and runs its pagehide/unload traffic — and this process cannot be the one to keep
  // it open: a net.Socket starts reading the moment it exists, so a listener here would race
  // the relay for frames and corrupt the CDP stream. The holder is killed only once Chromium is
  // confirmed gone (killBrowserGroupForRelay), and in every finish().
  const holder = spawnHolder(chrome);

  // The relay is the pipe's only READER from now on: destroy this process's copies, attach
  // nothing (the holder's copies are its own fds).
  for (const stream of [chrome.stdio[3], chrome.stdio[4]]) { try { stream.destroy(); } catch { /* gone */ } }

  let chromeExited = false;
  let chromeCode = 1;
  let relayExited = false;
  let stopping = false;
  let finished = false;
  /** True once the relay's ready line was read and the ready file written. */
  let readySeen = false;
  let resolveChromeExit = () => {};
  const chromeExit = new Promise((resolve) => { resolveChromeExit = resolve; });
  let resolveRelayExit = () => {};
  const relayExit = new Promise((resolve) => { resolveRelayExit = resolve; });

  const removeReadyFile = () => { try { rmSync(readyFile, { force: true }); } catch { /* gone */ } };
  function killChromiumGroup(signal = "SIGKILL") {
    if (!chrome.pid || chromeExited) return;
    try { process.kill(-chrome.pid, signal); return; } catch { /* the group is gone */ }
    try { chrome.kill(signal); } catch { /* the process is gone */ }
  }
  function killRelay(signal = "SIGKILL") {
    if (relayExited) return;
    try { relay.kill(signal); } catch { /* gone */ }
  }
  /**
   * SIGKILL the holder: its own process group, so nothing else of ours goes with it. It is
   * killed only once Chromium is confirmed gone, and in every finish() — a holder left behind
   * would keep a dead browser's pipe open forever.
   */
  function killHolder(signal = "SIGKILL") {
    if (!holder || !holder.pid) return;
    if (holder.exitCode !== null || holder.signalCode !== null) return;
    try { process.kill(-holder.pid, signal); return; } catch { /* its group is gone */ }
    try { holder.kill(signal); } catch { /* the process is gone */ }
  }
  function finish(code) {
    if (finished) return;
    finished = true;
    // Whatever else happened, nothing of ours may hold Chromium's pipe past this process.
    killHolder("SIGKILL");
    removeReadyFile();
    process.exit(code);
  }
  /** True once the relay's stop path took the browser's group down: one line, one kill. */
  let groupKilled = false;
  /**
   * THE RELAY'S STOP PATH, on this side. `kill` on fd 5 (or EOF on it) is the relay saying the
   * browser has to die NOW, before anything it has queued runs: a paused request that is
   * released, or a page closed gracefully, would run pagehide/unload traffic with no gate in
   * front of it. So the whole process group goes at once — zygotes, renderers and the network
   * service are all in it — and this process follows the normal finish with a non-zero code.
   *
   * It acts in EVERY state: while a SIGTERM stop is in progress (the `stopping` flag is this
   * path's own now, so nothing else decides anything afterwards), and independently of —
   * and before — the relay's `exit` event and its 500 ms grace. The holder keeps Chromium's
   * pipe open until the browser is CONFIRMED gone; only then is the holder killed (finish).
   *
   * A browser that is ALREADY gone (a zombie, with only its exit code still in flight) is not
   * killed: the same 500 ms grace the relay's own exit gets is spent waiting for the kernel's
   * report, so a Chromium that closed its pipe on the way out keeps its own exit code instead
   * of being called a stop path.
   */
  function killBrowserGroupForRelay(why, exitCode = 1, allowGrace = true) {
    if (finished || groupKilled || chromeExited) return;
    if (allowGrace && chromiumIsGone(chrome.pid)) {
      void Promise.race([chromeExit, delay(500)]).then(() => {
        if (finished || groupKilled) return;
        if (chromeExited) { finish(chromeCode); return; }
        killBrowserGroupForRelay(why, exitCode, false);
      });
      return;
    }
    groupKilled = true;
    stopping = true;
    log(`killing the browser group (${why})`);
    killChromiumGroup("SIGKILL");
    killRelay("SIGKILL");
    void (async () => {
      const deadline = Date.now() + 2000;
      while (!chromiumIsGone(chrome.pid) && Date.now() < deadline) await delay(10);
      finish(exitCode);
    })();
  }
  /**
   * One line from the relay AFTER its ready line. `kill`, and anything else that is not
   * `closing`, is the stop path and acts at once in every state. `closing` is a graceful close:
   * EOF on fd 5 and the relay's own exit are expected from then on, and Chromium's own exit is
   * what is waited for. EOF on fd 5 (null) without that line is the same stop path as before.
   */
  function onRelayReport(line) {
    const text = line === null ? "" : String(line).trim();
    const action = relayReportAction(line, { closing: closingSeen });
    if (action === "closing") {
      if (closingSeen) return;
      closingSeen = true;
      log("the relay reported a graceful close on fd 5: waiting for Chromium's own exit");
      waitForChromiumAfterClosing();
      return;
    }
    if (action === "wait") {
      log("fd 5 reached EOF after the relay's closing line — not a kill");
      return;
    }
    if (line === null) { killBrowserGroupForRelay("fd 5 reached EOF after the relay reported ready"); return; }
    if (text === "kill") { killBrowserGroupForRelay("the relay reported kill on fd 5"); return; }
    log(`fd 5: ${text.length} bytes that are not the kill line — a broken relay`);
    killBrowserGroupForRelay("the relay sent a line that is not kill");
  }
  /** True once the relay wrote `closing`: fd 5's EOF and the relay's exit are expected then. */
  let closingSeen = false;
  /**
   * A graceful close, on this side: the relay sent Browser.close after a clean scan, so Chromium
   * is shutting itself down (and committing its cookie store). Its own exit ends this; the stop
   * budget is the only thing that takes the group down.
   */
  function waitForChromiumAfterClosing() {
    void Promise.race([chromeExit, delay(stopBudgetMs).then(() => "timeout")]).then((how) => {
      // A SIGTERM stop is in flight: it owns the same budget, so it does the killing.
      if (finished || chromeExited || stopping || how !== "timeout") return;
      log(`Chromium did not exit within ${Math.round(stopBudgetMs / 1000)}s after the relay's closing line — killing it`);
      killBrowserGroupForRelay("Chromium outlived the relay's closing line");
    });
  }
  /** Is the process gone (zombie or reaped)? Read from /proc, never from an event. */
  function chromiumIsGone(pid) {
    if (!pid) return true;
    try {
      const stat = readFileSync(`/proc/${pid}/stat`, "utf8");
      const close = stat.lastIndexOf(")");
      const state = close >= 0 ? stat.slice(close + 2, close + 3) : "";
      return state === "Z" || state === "X";
    } catch { return true; }
  }
  const failSpawn = (code) => {
    killChromiumGroup("SIGKILL");
    killRelay("SIGKILL");
    finish(code);
  };

  chrome.once("exit", (code, signal) => {
    chromeExited = true;
    chromeCode = code === null ? 1 : code;
    resolveChromeExit();
    if (stopping || finished) return;
    if (relayExited) { finish(chromeCode); return; } // the relay's fate is already settled
    log(`Chromium exited (${code === null ? "signal" : `code ${code}`}); stopping the relay`);
    killRelay("SIGTERM");
    void Promise.race([relayExit, delay(2000)]).then(() => finish(chromeCode));
  });
  chrome.once("error", (err) => {
    if (finished) return;
    console.error(`[cdp-relay] FATAL: cannot start Chromium (${err && err.code ? err.code : "error"})`);
    failSpawn(127);
  });
  relay.once("exit", (code, signal) => {
    relayExited = true;
    resolveRelayExit();
    if (stopping || finished) return;
    if (chromeExited) { finish(chromeCode); return; }
    // A graceful close: the relay is gone and Chromium is finishing its own shutdown, which
    // the closing path waits for and bounds.
    if (closingSeen) return;
    // Chromium closing its fds is exactly what the relay sees as EOF, so when Chromium died
    // first its exit event may still be in flight: if the process is already gone, give the
    // kernel a moment to report its code, and let that code win. If Chromium is still alive,
    // the relay really did go first — kill the group at once, through the same stop path the
    // kill line and fd 5's EOF take (one code path, one log line, never two kills).
    const graceMs = chromiumIsGone(chrome.pid) ? 500 : 0;
    void Promise.race([chromeExit, delay(graceMs)]).then(() => {
      if (stopping || finished) return;
      if (chromeExited) { finish(chromeCode); return; }
      killBrowserGroupForRelay(
        `the CDP relay exited (${signal ? `signal ${signal}` : `code ${code}`})`,
        signal ? 1 : code === null ? 1 : code,
      );
    });
  });
  relay.once("error", (err) => {
    if (finished) return;
    console.error(`[cdp-relay] FATAL: cannot start the relay (${err && err.code ? err.code : "error"})`);
    failSpawn(1);
  });

  // The graceful path: the relay asks Chromium to close over the pipe (which is what
  // commits its cookie store), and Chromium's own exit is the signal that it is done. The
  // budget is the relay's cleanup and then its browser close, plus 2 s: a cleanup that runs
  // inside its cap, a close inside its own, and slack. SIGKILLing the browser in the middle of
  // that cleanup is safe — it is the same stop path the relay asks for — so a slow box that
  // needs the SIGKILL is not a broken stop, only a later one.
  const stop = async (signal) => {
    if (stopping || finished) return;
    stopping = true;
    log(`${signal}: closing Chromium through the relay...`);
    killRelay("SIGTERM");
    // A relay that never reported ready served nothing, so there is no cleanup to run and no
    // close to ask for: the browser goes as soon as the relay is gone, instead of holding the
    // group for a stop budget nothing can shorten.
    if (!readySeen) {
      const early = await Promise.race([
        relayExit.then(() => "relay"),
        chromeExit.then(() => "chromium"),
        delay(stopBudgetMs).then(() => "timeout"),
      ]);
      if (early === "relay" && !closingSeen && !chromeExited) killChromiumGroup("SIGKILL");
    }
    const how = await Promise.race([chromeExit, delay(stopBudgetMs).then(() => "timeout")]);
    if (how === "timeout") {
      log(`Chromium did not close within ${Math.round(stopBudgetMs / 1000)}s — killing it`);
      killChromiumGroup("SIGKILL");
    }
    await Promise.race([relayExit, delay(2000)]);
    // The relay's stop path owns the exit when it took it while this stop was in flight: its
    // kill line is honoured in the stopping state too, and it exits non-zero.
    if (groupKilled || finished) return;
    log("stopped.");
    finish(0);
  };
  process.on("SIGTERM", () => { void stop("SIGTERM"); });
  process.on("SIGINT", () => { void stop("SIGINT"); });
  const crash = (err) => {
    console.error(`[cdp-relay] FATAL: ${(err && err.message) || err}`);
    failSpawn(1);
  };
  process.on("uncaughtException", crash);
  process.on("unhandledRejection", crash);
  // Last resort for every other exit path: leave neither the browser nor the relay behind, and
  // no holder sitting on a dead browser's pipe.
  process.on("exit", () => {
    killChromiumGroup("SIGKILL");
    killRelay("SIGKILL");
    killHolder("SIGKILL");
  });

  let info;
  try {
    // The reader STAYS on fd 5 after the ready line: that is where the relay's `kill` and
    // `closing` lines come from, and EOF there is itself a kill unless `closing` came first.
    info = await readReadyLine(relay.stdio[5], READY_TIMEOUT_MS, onRelayReport);
  } catch (err) {
    const why = String((err && err.message) || err);
    // A SIGTERM can land before the ready line: the relay the stop signalled is the reason the
    // report pipe ended, so this is not a start failure and the stop path owns the exit code.
    if (stopping) { debug(`the start sequence ended in a stop: ${why}`); return; }
    console.error(`[cdp-relay] FATAL: ${why}`);
    failSpawn(1);
    return;
  }
  // Written here, as root, through the same safe writer: the relay's uid cannot write in
  // that directory, and the JSON is the same one the pre-split relay wrote (pid, port,
  // browser — never the token).
  try {
    writeReadyFile(readyFile, JSON.stringify({ pid: relay.pid, port: info.port, browser: String(info.browser || "") }) + "\n");
  } catch {
    console.error(`[cdp-relay] FATAL: cannot write the ready file (${readyFile})`);
    failSpawn(1);
    return;
  }
  readySeen = true;
  log(`ready on 127.0.0.1:${info.port} — Chromium ${info.browser || "(unknown)"} over a pipe, bearer required, relay as uid ${uid}${drop ? "" : " (no uid drop)"}`);
}

if (process.argv[1] && pathToFileURL(process.argv[1]).href === import.meta.url) {
  main().catch((err) => die(String((err && err.message) || err)));
}