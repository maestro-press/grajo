// PR 3a: the reports egress relay's credential injection. A custom step asks
// for `http://<approved host>/...` in absolute form over the PROXY line; the
// relay resolves and checks the host like a CONNECT, opens its OWN verified TLS
// request to port 443, attaches the credential there, and replaces every
// spelling of it in the answer before the step reads a byte.
//
// A real relay on a unix socket and a real TLS upstream on loopback: the lookup
// and the TCP destination are seams (`lookup`, `_connectOverride`), the
// certificate is a throwaway generated here with node:crypto alone (no openssl,
// no key material in the repo) and trusted only through `_injectUpstreamTls`.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import crypto from "node:crypto";
import { connect, createServer as createNetServer } from "node:net";
import { createServer as createHttpsServer } from "node:https";
import { mkdtempSync, realpathSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";

import { createEgressRelay, startEgressRelay } from "../scripts/pi-bots/pi_egress.mjs";
import { secretForms } from "../scripts/pi-bots/pi_inject_redact.mjs";

/** The credential every test injects. Never a real one. */
const SECRET = "rpt_live_9Xk2WmZq4Tb7Hn3Vp";
/** A credential whose url-encoded form is a different string (so a partial echo of that form is a real case). */
const SPECIAL = "rpt+live/9Xk2 WmZq";
const HOST = "api.example.com";
const INJECTED = "Bearer " + SECRET;

/** An own-host view with no addresses (the seam every CONNECT test pins). */
const NO_LOCAL = { v4: [], v6: [], onLink4: [], onLink6: [], v4Failed: false, v6Failed: false, onLinkFailed: false };
/** A global-unicast fixture (the address the relay tests have always used). */
const PUB = "93.184.216.34";

const scratch = realpathSync(mkdtempSync(join(tmpdir(), "crow-inject-egress-")));
const closers = [];
after(async () => {
  for (const c of closers.splice(0)) await c();
  rmSync(scratch, { recursive: true, force: true });
});

/* ------------------------------------------------------- a throwaway TLS certificate */

function derLength(size) {
  if (size < 0x80) return Buffer.from([size]);
  const bytes = [];
  let value = size;
  while (value > 0) {
    bytes.unshift(value & 0xff);
    value = Math.floor(value / 256);
  }
  return Buffer.from([0x80 | bytes.length, ...bytes]);
}

const der = (tag, ...chunks) => Buffer.concat([
  Buffer.from([tag]), derLength(Buffer.concat(chunks.map((c) => (Buffer.isBuffer(c) ? c : Buffer.from(c)))).length),
  ...chunks.map((c) => (Buffer.isBuffer(c) ? c : Buffer.from(c))),
]);
const derSequence = (...chunks) => der(0x30, ...chunks);
const derSet = (...chunks) => der(0x31, ...chunks);
const derOid = (...bytes) => der(0x06, Buffer.from(bytes));
const derTrue = der(0x01, Buffer.from([0xff]));
const derName = (value) => derSequence(derSet(derSequence(derOid(0x55, 0x04, 0x03), der(0x0c, Buffer.from(value, "utf8")))));
const derPem = (label, bytes) => `-----BEGIN ${label}-----\n${(bytes.toString("base64").match(/.{1,64}/g) ?? []).join("\n")}\n-----END ${label}-----\n`;

/** A self-signed certificate for one name, built from node:crypto alone. */
function selfSigned(name) {
  const { privateKey } = crypto.generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const subjectPublicKey = crypto.createPublicKey(privateKey).export({ type: "spki", format: "der" });
  const signatureAlgorithm = derSequence(derOid(0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02));
  const extensions = der(0xa3, derSequence(
    derSequence(derOid(0x55, 0x1d, 0x13), derTrue, der(0x04, derSequence(derTrue))),
    derSequence(derOid(0x55, 0x1d, 0x11), der(0x04, derSequence(der(0x82, Buffer.from(name, "ascii"))))),
    derSequence(derOid(0x55, 0x1d, 0x25), der(0x04, derSequence(derOid(0x2b, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01)))),
  ));
  const toBeSigned = derSequence(
    der(0xa0, der(0x02, Buffer.from([2]))),
    der(0x02, Buffer.from([1])),
    signatureAlgorithm,
    derName(name),
    derSequence(der(0x17, Buffer.from("240101000000Z", "ascii")), der(0x17, Buffer.from("491231235959Z", "ascii"))),
    derName(name),
    subjectPublicKey,
    extensions,
  );
  const signature = crypto.sign("sha256", toBeSigned, privateKey);
  return {
    cert: derPem("CERTIFICATE", derSequence(toBeSigned, signatureAlgorithm, der(0x03, Buffer.from([0]), signature))),
    key: privateKey.export({ type: "pkcs8", format: "pem" }),
  };
}

const PAIR = selfSigned(HOST);

/** An HTTPS upstream that records every request it receives, and how many
 *  TCP connections it was offered. */
function httpsUpstream(handle) {
  return new Promise((resolve) => {
    const reqs = [];
    const live = new Set();
    let conns = 0;
    const srv = createHttpsServer({ key: PAIR.key, cert: PAIR.cert }, (req, res) => {
      const rec = { method: req.method, url: req.url, headers: req.headers, body: [] };
      reqs.push(rec);
      req.on("data", (d) => rec.body.push(d));
      req.on("end", () => { rec.text = Buffer.concat(rec.body).toString("utf8"); handle(req, res, rec); });
    });
    srv.on("connection", (c) => { conns++; live.add(c); c.on("close", () => live.delete(c)); });
    srv.listen(0, "127.0.0.1", () => {
      closers.push(() => {
        for (const c of live) { try { c.destroy(); } catch {} }
        try { srv.closeAllConnections?.(); } catch {}
        return new Promise((r) => srv.close(() => r()));
      });
      resolve({ port: srv.address().port, reqs, connections: () => conns });
    });
  });
}

/** Send bytes and collect the answer until the peer is quiet or closes. */
function talk(sockPath, first, { timeout = 4000, settle = 80 } = {}) {
  return new Promise((resolve) => {
    const c = connect(sockPath);
    let buf = "";
    let done = false;
    let quiet = null;
    const finish = () => {
      if (done) return;
      done = true;
      if (quiet) clearTimeout(quiet);
      try { c.destroy(); } catch {}
      resolve(buf);
    };
    c.on("connect", () => c.write(first));
    c.on("data", (d) => {
      buf += d.toString("latin1");
      if (quiet) clearTimeout(quiet);
      quiet = setTimeout(finish, settle);
    });
    c.on("error", finish);
    c.on("close", finish);
    setTimeout(finish, timeout);
  });
}

const delay = (ms) => new Promise((r) => setTimeout(r, ms));

let seq = 0;
const relayOpts = (o) => ({
  dir: join(scratch, "r" + (++seq)), botId: "step-x", local: NO_LOCAL,
  lookup: async () => [{ address: PUB, family: 4 }],
  egressAllow: [HOST],
  _injectUpstreamTls: { ca: PAIR.cert },
  ...o,
});

async function relay(o = {}) {
  const logs = [];
  const r = await startEgressRelay(relayOpts({ log: (l) => logs.push(l), ...o }));
  closers.push(() => r.close());
  return { r, logs };
}

/** The rule every test starts from: one host, the `/v1` subtree, reads only. A rule names a
 *  subtree and never the whole host, so `/` is refused as a path prefix. */
const PREFIX = "/v1";
const headerRule = (over = {}) => ({
  host: HOST, header: "Authorization", format: "Bearer {}", secret: () => SECRET,
  pathPrefixes: [PREFIX], ...over,
});
const queryRule = (over = {}) => ({
  host: HOST, query: "api_key", secret: () => SECRET, pathPrefixes: [PREFIX], ...over,
});

/** GET, in the absolute form the relay accepts. A path outside the default subtree (say `/x`) is
 *  read as `/v1/x`: the default rule names the `/v1` subtree, exactly as a real one would. */
function get(target, extra = "") {
  const head = `http://${HOST}`;
  const rest = target.startsWith(head) ? target.slice(head.length) : null;
  const url = rest === null || rest === PREFIX || rest.startsWith(PREFIX + "/")
    ? target
    : `${head}${PREFIX}${rest}`;
  return `PROXY\nGET ${url} HTTP/1.1\r\nHost: ignored.example.com\r\n${extra}\r\n`;
}

/** No log line carries any spelling of the credential. */
function assertNoSecret(logs) {
  const text = logs.join("\n");
  assert.equal(text.includes(SECRET), false, "the raw credential is not in a log line: " + text);
  for (const n of secretForms(SECRET)) {
    const form = n.toString("utf8");
    assert.equal(text.includes(form), false, "no spelling of the credential is in a log line");
  }
}

/** The spellings a plain echo of the credential could take, built here by hand. */
function echoForms(secret) {
  const std = Buffer.from(secret).toString("base64");
  return {
    raw: secret,
    "percent-encoded": encodeURIComponent(secret),
    "json escaped": JSON.stringify(secret).slice(1, -1),
    "html entities": [...secret].map((c) => `&#${c.codePointAt(0)};`).join(""),
    "html hex entities": [...secret].map((c) => `&#x${c.codePointAt(0).toString(16)};`).join(""),
    "hex lower": Buffer.from(secret).toString("hex"),
    "hex upper": Buffer.from(secret).toString("hex").toUpperCase(),
    "base64 padded": std,
    "base64 unpadded": std.replace(/=+$/, ""),
    "base64url": std.replace(/\+/g, "-").replace(/\//g, "_"),
  };
}

/* ------------------------------------------------------------ the request */

test("absolute-form http to an inject host gets the header added upstream", async () => {
  const up = await httpsUpstream((req, res) => { res.writeHead(200, { "content-type": "text/plain" }); res.end("found it"); });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });

  const out = await talk(r.socketPath, get("http://api.example.com/v1/search?q=birds&limit=5", "Accept-Encoding: gzip\r\nX-Request-Id: 1\r\n"));
  assert.match(out, /^HTTP\/1\.1 200/);
  assert.match(out, /found it$/);
  assert.equal(up.reqs.length, 1, "one upstream request");
  const seen = up.reqs[0];
  assert.equal(seen.method, "GET");
  assert.equal(seen.url, "/v1/search?q=birds&limit=5", "the path and query are carried as they were sent");
  assert.equal(seen.headers.authorization, INJECTED, "the credential is attached by the relay");
  assert.equal(seen.headers["accept-encoding"], "identity", "the upstream may not encode the answer");
  assert.equal(seen.headers.host, HOST, "Host is the target, never the client's");
  assert.equal(seen.headers["x-request-id"], "1", "an allowlisted header passes through");
  assert.equal(seen.headers["content-length"], "0", "the body is framed, never chunked");
  assert.ok(logs.some((l) => l.includes("allow " + HOST)), logs.join("\n"));
  assertNoSecret(logs);
});

test("a client-supplied Authorization header is dropped, and a query rule replaces its own parameter", async () => {
  const up = await httpsUpstream((req, res) => { res.writeHead(200, { "content-type": "text/plain" }); res.end("ok"); });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const out = await talk(r.socketPath, get(`http://${HOST}/x`, `Authorization: Bearer attacker-chosen-value\r\n`));
  assert.match(out, /^HTTP\/1\.1 200/);
  assert.equal(up.reqs[0].headers.authorization, INJECTED, "the step cannot choose its own credential");
  assertNoSecret(logs);

  const qUp = await httpsUpstream((req, res) => { res.writeHead(200, { "content-type": "text/plain" }); res.end("ok"); });
  const q = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: qUp.port }), inject: [queryRule()] });
  const qOut = await talk(q.r.socketPath, get(`http://${HOST}/x?q=1&api_key=attacker-chosen&b=2`));
  assert.match(qOut, /^HTTP\/1\.1 200/);
  assert.equal(qUp.reqs[0].url, `/v1/x?q=1&b=2&api_key=${encodeURIComponent(SECRET)}`, "the client's own parameter is replaced");
  assert.equal(qUp.reqs[0].headers.authorization, undefined, "a query rule attaches no header");
  assertNoSecret(q.logs);
});

test("a credentialed request carries an allowlist of headers, so no override or hop header reaches the upstream", async () => {
  const up = await httpsUpstream((req, res) => { res.writeHead(200, { "content-type": "text/plain" }); res.end("ok"); });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const extra = "X-HTTP-Method-Override: DELETE\r\nX-HTTP-Method: DELETE\r\nX-Method-Override: DELETE\r\n"
    + "X-Original-URL: /admin\r\nX-Rewrite-URL: /admin\r\nX-Original-URI: /admin\r\n"
    + "X-Forwarded-For: 100.64.20.9\r\nX-Forwarded-Host: other.example.com\r\nForwarded: for=100.64.20.9\r\n"
    + "Via: 1.1 other.example.com\r\nX-Real-IP: 100.64.20.9\r\nAccept-Charset: utf-16le\r\n"
    + "Accept: application/json\r\nX-Request-Id: req-7\r\n";
  const out = await talk(r.socketPath, get(`http://${HOST}/x`, extra));
  assert.match(out, /^HTTP\/1\.1 200/);
  const seen = up.reqs[0];
  assert.equal(seen.method, "GET", "the method the rule allowed is the method that is sent");
  assert.equal(seen.url, "/v1/x", "the path the rule allowed is the path that is sent");
  for (const name of ["x-http-method-override", "x-http-method", "x-method-override",
    "x-original-url", "x-rewrite-url", "x-original-uri", "x-forwarded-for", "x-forwarded-host",
    "forwarded", "via", "x-real-ip", "accept-charset"]) {
    assert.equal(seen.headers[name], undefined, name + " never reaches the upstream");
  }
  assert.equal(seen.headers.accept, "application/json", "an allowlisted header passes through");
  assert.equal(seen.headers["x-request-id"], "req-7", "and so does a correlation id");
  assert.equal(seen.headers["accept-encoding"], "identity", "the relay still chooses the encoding");
  assertNoSecret(logs);
});

test("a format is literal text: a secret holding $& and $` goes upstream as it is", async () => {
  const odd = "$&-$'--$$-`-replacement";
  const up = await httpsUpstream((req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(String(req.headers.authorization || ""));
  });
  const { r, logs } = await relay({
    _connectOverride: () => ({ host: "127.0.0.1", port: up.port }),
    inject: [headerRule({ secret: () => odd, format: "Token {}" })],
  });
  const out = await talk(r.socketPath, get(`http://${HOST}/x`));
  assert.match(out, /^HTTP\/1\.1 200/);
  assert.equal(up.reqs[0].headers.authorization, "Token " + odd, "no replacement pattern is expanded");
  assert.equal(out.slice(out.indexOf("\r\n\r\n") + 4), "[redacted]", "the formatted value is redacted whole");
  assertNoSecret(logs);
});

test("a POST body is carried with its declared length", async () => {
  const up = await httpsUpstream((req, res, rec) => { res.writeHead(201, { "content-type": "text/plain" }); res.end("len=" + rec.text.length); });
  const { r } = await relay({
    _connectOverride: () => ({ host: "127.0.0.1", port: up.port }),
    inject: [headerRule({ methods: ["GET", "HEAD", "POST"] })],
  });
  const out = await talk(r.socketPath, `PROXY\nPOST http://${HOST}/v1/search HTTP/1.1\r\nHost: x\r\nContent-Length: 9\r\n\r\n{"a":"b"}`);
  assert.match(out, /^HTTP\/1\.1 201/);
  assert.match(out, /len=9$/);
  assert.equal(up.reqs[0].method, "POST");
  assert.equal(up.reqs[0].text, '{"a":"b"}');
  assert.equal(up.reqs[0].headers["content-length"], "9");
});

/* ------------------------------------------------------------ the answer */

test("echoed credential is redacted in the body in every form", async () => {
  const forms = echoForms(SECRET);
  const up = await httpsUpstream((req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(Object.values(forms).join("\n"));
  });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const out = await talk(r.socketPath, get(`http://${HOST}/x`));
  assert.match(out, /^HTTP\/1\.1 200/);
  const body = out.slice(out.indexOf("\r\n\r\n") + 4);
  for (const [label, text] of Object.entries(forms)) assert.equal(body.includes(text), false, label + " does not reach the step");
  assert.equal(body.trim().split("\n").length, Object.keys(forms).length, "one line per spelling");
  for (const line of body.trim().split("\n")) assert.equal(line, "[redacted]");
  assertNoSecret(logs);
});

test("a credential echoed inside a larger base64 blob is redacted at every alignment", async () => {
  const bodies = [0, 1, 2].map((k) => Buffer.concat([
    Buffer.from("x".repeat(k)), Buffer.from("head-"), Buffer.from(SECRET), Buffer.from("-tail"),
  ]).toString("base64"));
  const up = await httpsUpstream((req, res) => { res.writeHead(200, { "content-type": "text/plain" }); res.end(bodies.join("\n")); });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const out = await talk(r.socketPath, get(`http://${HOST}/x`));
  const body = out.slice(out.indexOf("\r\n\r\n") + 4);
  assert.equal(body.split("[redacted]").length - 1, 3, "each blob lost the part that belongs to the credential: " + body);
  for (const n of secretForms(SECRET)) assert.equal(body.includes(n.toString("utf8")), false, "no base64 spelling survives");
  assertNoSecret(logs);
});

test("a credential split across chunks is redacted", async () => {
  const up = await httpsUpstream(async (req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    const body = Buffer.from(`A${SECRET}B`);
    res.socket.setNoDelay(true);
    for (const byte of body) { res.write(Buffer.from([byte])); await delay(1); }
    res.end();
  });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const out = await talk(r.socketPath, get(`http://${HOST}/x`));
  const body = out.slice(out.indexOf("\r\n\r\n") + 4);
  assert.equal(body, "A[redacted]B", "one byte at a time does not slip through");
  assertNoSecret(logs);
});

test("a partial echo of the credential is never forwarded: raw, base64, hex, url-encoded", async () => {
  const cases = [
    { label: "raw", secret: SECRET, form: SECRET, from: 4, to: 16 },
    { label: "base64", secret: SECRET, form: Buffer.from(SECRET).toString("base64"), from: 4, to: 16 },
    // A hex spelling is judged at 16 bytes: sixteen symbols make a short run a coincidence.
    { label: "hex", secret: SECRET, form: Buffer.from(SECRET).toString("hex"), from: 4, to: 20 },
    { label: "url-encoded", secret: SPECIAL, form: encodeURIComponent(SPECIAL), from: 4, to: 16 },
  ];
  for (const c of cases) {
    const piece = c.form.slice(c.from, c.to);
    assert.equal(piece.length, c.to - c.from, c.label + ": a partial form");
    assert.ok(c.secret.length > piece.length, c.label + ": a slice, not the whole form");
    const up = await httpsUpstream((req, res) => {
      res.writeHead(200, { "content-type": "text/plain" });
      res.end("before " + piece + " after");
    });
    const { r, logs } = await relay({
      _connectOverride: () => ({ host: "127.0.0.1", port: up.port }),
      inject: [headerRule({ secret: () => c.secret })],
    });
    const out = await talk(r.socketPath, get(`http://${HOST}/x`));
    // The head is not on the wire yet when the body is judged, so the whole answer is refused
    // rather than cut: the step never sees a status it could read as an answer.
    assert.match(out, /^HTTP\/1\.1 502/, c.label);
    assert.equal(out.includes(piece), false, c.label + ": no byte of the partial echo reaches the step");
    assert.ok(logs.some((l) => l.includes("tainted_response_refused")), c.label + ": " + logs.join("\n"));
    assertNoSecret(logs);
  }
});

test("a short hex run is not a window: 12 hex characters pass, 16 are refused", async () => {
  const hex = Buffer.from(SECRET).toString("hex");
  const short = hex.slice(4, 16);
  const long = hex.slice(4, 20);
  const up = await httpsUpstream((req, res) => { res.writeHead(200, { "content-type": "text/plain" }); res.end("value " + short); });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const out = await talk(r.socketPath, get(`http://${HOST}/x`));
  assert.match(out, /^HTTP\/1\.1 200/, "twelve hex characters are not the credential");
  assert.ok(out.includes(short), "and they pass through as they are");
  assert.equal(logs.some((l) => l.includes("tainted_response_refused")), false, logs.join("\n"));

  const wide = await httpsUpstream((req, res) => { res.writeHead(200, { "content-type": "text/plain" }); res.end("value " + long); });
  const second = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: wide.port }), inject: [headerRule()] });
  const refused = await talk(second.r.socketPath, get(`http://${HOST}/x`));
  assert.match(refused, /^HTTP\/1\.1 502/, "sixteen hex characters are a window and the whole answer is refused");
  assert.equal(refused.includes(long), false, "no byte of it is forwarded");
  assert.ok(second.logs.some((l) => l.includes("tainted_response_refused")), second.logs.join("\n"));
});

test("a partial echo split across two chunks is still refused", async () => {
  const piece = SECRET.slice(4, 16);
  const up = await httpsUpstream(async (req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.socket.setNoDelay(true);
    res.write(piece.slice(0, 6));
    await delay(40);
    res.write(piece.slice(6));
    res.end();
  });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const out = await talk(r.socketPath, get(`http://${HOST}/x`));
  assert.match(out, /^HTTP\/1\.1 502/, "the window is found before the head is sent, so the answer is refused whole");
  assert.equal(out.includes(piece.slice(0, 6)), false, "no half of the window reaches the step");
  assert.equal(out.includes(piece), false, "nor the whole run");
  assert.ok(logs.some((l) => l.includes("tainted_response_refused")), logs.join("\n"));
  assertNoSecret(logs);
});

test("a partial echo in a response header refuses the whole answer", async () => {
  const piece = SECRET.slice(4, 16);
  const up = await httpsUpstream((req, res) => {
    res.writeHead(200, { "content-type": "text/plain", "x-note": "seen " + piece });
    res.end("the body must not arrive either");
  });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const out = await talk(r.socketPath, get(`http://${HOST}/x`));
  assert.match(out, /^HTTP\/1\.1 502/, "the head is judged before it is written");
  assert.equal(out.includes(piece), false);
  assert.equal(out.includes("the body must not arrive either"), false, "no body byte is forwarded");
  assert.ok(logs.some((l) => l.includes("tainted_response_refused")), logs.join("\n"));
  assertNoSecret(logs);
});

test("a 206 upstream is refused whole, and no body byte is forwarded", async () => {
  const up = await httpsUpstream((req, res) => {
    res.writeHead(206, { "content-type": "text/plain", "content-range": "bytes 0-4/100" });
    res.end("slice");
  });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const out = await talk(r.socketPath, get(`http://${HOST}/x`));
  assert.match(out, /^HTTP\/1\.1 502/);
  assert.equal(out.includes("slice"), false, "no body byte of a partial answer is forwarded");
  assert.ok(logs.some((l) => l.includes("partial_response_refused")), logs.join("\n"));
});

test("a Content-Range header alone refuses the whole answer", async () => {
  const up = await httpsUpstream((req, res) => {
    res.writeHead(200, { "content-type": "text/plain", "content-range": "bytes 0-4/100" });
    res.end("slice");
  });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const out = await talk(r.socketPath, get(`http://${HOST}/x`));
  assert.match(out, /^HTTP\/1\.1 502/);
  assert.equal(out.includes("slice"), false);
  assert.ok(logs.some((l) => l.includes("partial_response_refused")), logs.join("\n"));
});

test("client Range, its validators and Cookie never reach the upstream", async () => {
  const up = await httpsUpstream((req, res) => { res.writeHead(200, { "content-type": "text/plain" }); res.end("ok"); });
  const { r } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const extra = "Range: bytes=0-5\r\nIf-Range: \"abc\"\r\nIf-Match: \"m\"\r\nIf-None-Match: \"n\"\r\n"
    + "If-Modified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\nIf-Unmodified-Since: Thu, 01 Jan 1970 00:00:00 GMT\r\n"
    + "Cookie: session=attacker-chosen\r\nX-Request-Id: 1\r\n";
  const out = await talk(r.socketPath, get(`http://${HOST}/x`, extra));
  assert.match(out, /^HTTP\/1\.1 200/);
  const seen = up.reqs[0].headers;
  for (const name of ["range", "if-range", "if-match", "if-none-match", "if-modified-since", "if-unmodified-since", "cookie", "te", "upgrade"]) {
    assert.equal(seen[name], undefined, name + " is not forwarded");
  }
  assert.equal(seen["x-request-id"], "1", "an allowlisted header still passes through");
});

test("a POST to a rule that allows reads only is refused with 405 and opens nothing upstream", async () => {
  const up = await httpsUpstream((req, res) => { res.end("x"); });
  const { r, logs } = await relay({
    _connectOverride: () => ({ host: "127.0.0.1", port: up.port }),
    inject: [headerRule({ pathPrefixes: ["/v1"] })],
  });
  const out = await talk(r.socketPath, `PROXY\nPOST http://${HOST}/v1/search HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n`);
  assert.match(out, /^HTTP\/1\.1 405/);
  assert.equal(up.connections(), 0, "no upstream connection was opened");
  assert.equal(up.reqs.length, 0);
  assert.ok(logs.some((l) => l.includes("inject_method_not_allowed")), logs.join("\n"));
});

test("a path outside the rule's prefixes is refused with 403 and opens nothing upstream", async () => {
  const up = await httpsUpstream((req, res) => { res.end("x"); });
  const { r, logs } = await relay({
    _connectOverride: () => ({ host: "127.0.0.1", port: up.port }),
    inject: [headerRule({ pathPrefixes: ["/v1/items"] })],
  });
  for (const path of ["/v1/search", "/", "/v1", "/v1/itemsx"]) {
    assert.match(await talk(r.socketPath, get(`http://${HOST}${path}`)), /^HTTP\/1\.1 403/, path);
  }
  assert.equal(up.connections(), 0, "no upstream connection was opened");
  assert.ok(logs.some((l) => l.includes("inject_path_not_allowed")), logs.join("\n"));
});

test("segment-boundary and encoding bypass attempts are all refused", async () => {
  const up = await httpsUpstream((req, res) => { res.end("x"); });
  const { r, logs } = await relay({
    _connectOverride: () => ({ host: "127.0.0.1", port: up.port }),
    inject: [headerRule({ pathPrefixes: ["/v1/items"] })],
  });
  const attempts = [
    ["/v1/itemsx", "not a path-segment boundary"],
    ["/v1/items%2fsecret", "an encoded slash"],
    ["/v1/items%2Fsecret", "an encoded slash, upper case"],
    ["/v1/items/%2e%2e/secret", "encoded dot segments"],
    ["/v1/items/../secret", "dot segments"],
    ["/v1/items//../secret", "a double slash then dot segments"],
    ["/v1//itemsx", "a double slash, still not a boundary"],
    ["/v1/items\\..\\secret", "backslash separators"],
    ["/v1/items%5c..%5csecret", "encoded backslashes"],
    ["/v1/items%00x", "an encoded NUL"],
    ["/v1/items%zz", "a broken escape"],
  ];
  for (const [path, label] of attempts) {
    const out = await talk(r.socketPath, `PROXY\nGET http://${HOST}${path} HTTP/1.1\r\nHost: x\r\n\r\n`);
    assert.match(out, /^HTTP\/1\.1 403/, label + " (" + path + ")");
  }
  assert.equal(up.connections(), 0, "nothing reached the upstream");
  assertNoSecret(logs);
});

test("a path inside the prefixes is sent upstream normalised", async () => {
  const up = await httpsUpstream((req, res) => { res.writeHead(200, { "content-type": "text/plain" }); res.end("ok"); });
  const { r } = await relay({
    _connectOverride: () => ({ host: "127.0.0.1", port: up.port }),
    inject: [headerRule({ pathPrefixes: ["/v1/items"] })],
  });
  const first = await talk(r.socketPath, get(`http://${HOST}/v1//items/./9?tab=x`));
  assert.match(first, /^HTTP\/1\.1 200/);
  assert.equal(up.reqs[0].url, "/v1/items/9?tab=x", "double slashes collapsed, dot segment dropped");
  const second = await talk(r.socketPath, get(`http://${HOST}/v1/%69tems/10`));
  assert.match(second, /^HTTP\/1\.1 200/);
  assert.equal(up.reqs[1].url, "/v1/items/10", "an encoded unreserved byte is the same segment");
  const third = await talk(r.socketPath, get(`http://${HOST}/v1/items`));
  assert.match(third, /^HTTP\/1\.1 200/);
  assert.equal(up.reqs[2].url, "/v1/items", "the prefix itself is allowed");
});

test("response headers that can carry a derived credential are dropped, a normal one is not", async () => {
  const up = await httpsUpstream((req, res) => {
    res.writeHead(200, {
      "content-type": "text/plain",
      "set-cookie": ["session=derived-1; Path=/", "second=derived-2; Path=/"],
      "set-cookie2": "session2=derived-3",
      authorization: "Bearer derived-4",
      "proxy-authenticate": "Basic realm=x",
      "www-authenticate": "Basic realm=x",
      "authentication-info": "nextnonce=derived-5",
      "proxy-authentication-info": "nextnonce=derived-6",
      "x-auth-token": "derived-7",
      "x-api-key": "derived-8",
      "x-session-id": "derived-9",
      "x-credential-hint": "derived-10",
      "x-csrf-token": "derived-11",
      "pipeline-token": "derived-12",
      apikey: "derived-13",
      "x-request-id": "req-9",
      "x-ratelimit-remaining": "42",
    });
    res.end("ok");
  });
  const { r } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const out = await talk(r.socketPath, get(`http://${HOST}/x`));
  assert.match(out, /^HTTP\/1\.1 200/);
  const head = out.slice(0, out.indexOf("\r\n\r\n"));
  for (const gone of ["set-cookie", "set-cookie2", "authorization", "proxy-authenticate", "www-authenticate",
    "authentication-info", "proxy-authentication-info", "x-auth-token", "x-api-key", "x-session-id",
    "x-credential-hint", "x-csrf-token", "pipeline-token", "apikey"]) {
    assert.equal(new RegExp("^" + gone + ":", "m").test(head), false, gone + " is dropped whole: " + head);
  }
  for (const kept of ["derived-1", "derived-3", "derived-7", "derived-12", "derived-13"]) {
    assert.equal(head.includes(kept), false, kept + " never reaches the step");
  }
  assert.match(head, /^x-request-id: req-9$/m, "a normal header passes");
  assert.match(head, /^x-ratelimit-remaining: 42$/m, "an ordinary x- header is not a credential");
  assert.match(out, /ok$/);
});

test("a benign 16 MB body is passed through and scanned inside its budget", async () => {
  const size = 16 * 1024 * 1024;
  const pattern = Buffer.from("the quick brown fox jumps over the lazy dog. rpt_0123456789 ");
  const block = Buffer.alloc(64 * 1024);
  for (let i = 0; i < block.length; i++) block[i] = pattern[i % pattern.length];
  const count = size / block.length;
  const up = await httpsUpstream((req, res) => {
    res.writeHead(200, { "content-type": "application/octet-stream" });
    let written = 0;
    const pump = () => {
      while (written < count) { written++; if (!res.write(block)) return res.once("drain", pump); }
      res.end();
    };
    pump();
  });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const started = Date.now();
  const out = await talk(r.socketPath, get(`http://${HOST}/x`), { timeout: 20000, settle: 200 });
  const elapsed = Date.now() - started;
  assert.match(out, /^HTTP\/1\.1 200/);
  assert.ok(out.length >= size, "the whole body arrived: " + out.length);
  assert.equal(out.includes("[redacted]"), false, "nothing was redacted from a clean body");
  assert.ok(out.includes("quick brown fox"), "the body is byte-for-byte what the upstream sent");
  assert.equal(logs.some((l) => l.includes("response too large")), false);
  assert.ok(elapsed < 10000, "a 16 MB body stays well inside the budget: " + elapsed + " ms");
});

test("echoes in a response header are redacted, and a cookie is dropped rather than redacted", async () => {
  const up = await httpsUpstream((req, res) => {
    res.writeHead(302, {
      location: `https://${HOST}/next?token=${SECRET}`,
      "set-cookie": [`session=${SECRET}; Path=/`, "plain=1; Path=/"],
      "www-authenticate": `Bearer realm="${SECRET}"`,
      link: `<https://${HOST}/docs>; rel="next"`,
      "content-type": "text/plain",
    });
    res.end("moved");
  });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const out = await talk(r.socketPath, get(`http://${HOST}/x`));
  assert.match(out, /^HTTP\/1\.1 302/, "a redirect is passed through, never followed");
  const head = out.slice(0, out.indexOf("\r\n\r\n"));
  assert.equal(head.includes(SECRET), false, "no header value carries the credential: " + head);
  assert.match(head, /^location: https:\/\/api\.example\.com\/next\?token=\[redacted\]$/m);
  assert.equal(/^set-cookie:/m.test(head), false, "a cookie is dropped whole, never forwarded");
  assert.equal(/^www-authenticate:/m.test(head), false, "a challenge header is dropped whole");
  assert.match(head, /^link: <https:\/\/api\.example\.com\/docs>; rel="next"$/m);
  assert.match(head, /^connection: close$/m);
  assert.equal(/^content-length:/m.test(head), false, "the length is dropped: redaction can shorten the body");
  assertNoSecret(logs);
});

test("gzip echo refused: the whole response is refused and no body byte reaches the client", async () => {
  const up = await httpsUpstream((req, res) => {
    const zipped = gzipSync(Buffer.from(`compressed ${SECRET} inside`));
    res.writeHead(200, { "content-type": "text/plain", "content-encoding": "gzip", "content-length": zipped.length });
    res.end(zipped);
  });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const out = await talk(r.socketPath, get(`http://${HOST}/x`));
  assert.match(out, /^HTTP\/1\.1 502/, "an encoded answer is refused");
  assert.equal(out.includes(SECRET), false);
  assert.equal(out.includes("compressed"), false, "nothing from the body is forwarded");
  assert.equal(out.includes("[redacted]"), false, "not even a redacted body");
  assert.ok(logs.some((l) => l.includes("encoded_response_refused")), logs.join("\n"));
  assertNoSecret(logs);
});

test("a wide-character answer is refused: its charset header, and a UTF-16 BOM in the body", async () => {
  const echoed = Buffer.concat([Buffer.from([0xff, 0xfe]), Buffer.from("the credential is " + SECRET, "utf16le")]);
  const withCharset = await httpsUpstream((req, res) => {
    res.writeHead(200, { "content-type": "text/plain; charset=UTF-16LE" });
    res.end(echoed);
  });
  const first = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: withCharset.port }), inject: [headerRule()] });
  const out = await talk(first.r.socketPath, get(`http://${HOST}/x`));
  assert.match(out, /^HTTP\/1\.1 502/, "a charset this relay cannot judge is refused");
  assert.equal(out.slice(out.indexOf("\r\n\r\n") + 4), "upstream response refused", "no body byte is forwarded");
  assert.ok(first.logs.some((l) => l.includes("charset_refused")), first.logs.join("\n"));
  assertNoSecret(first.logs);

  // The same bytes with no charset at all: the BOM is the tell, and it is judged before the head is sent.
  const bomOnly = await httpsUpstream((req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    res.end(echoed);
  });
  const second = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: bomOnly.port }), inject: [headerRule()] });
  const bom = await talk(second.r.socketPath, get(`http://${HOST}/x`));
  assert.match(bom, /^HTTP\/1\.1 502/, "a UTF-16 BOM is refused too");
  assert.equal(bom.slice(bom.indexOf("\r\n\r\n") + 4), "upstream response refused", "nothing of the body is forwarded");
  assert.ok(second.logs.some((l) => l.includes("charset_refused")), second.logs.join("\n"));

  // ucs-2 is the same family, in any spelling and any case.
  for (const charset of ["charset=ucs-2", "charset=\"UTF-32\"", "charset=utf-32be"]) {
    const wide = await httpsUpstream((req, res) => {
      res.writeHead(200, { "content-type": "text/json; " + charset });
      res.end("plain ascii, still refused");
    });
    const third = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: wide.port }), inject: [headerRule()] });
    const refused = await talk(third.r.socketPath, get(`http://${HOST}/x`));
    assert.match(refused, /^HTTP\/1\.1 502/, charset);
    assert.ok(third.logs.some((l) => l.includes("charset_refused")), charset + ": " + third.logs.join("\n"));
  }

  // A narrow charset is judged normally.
  const utf8 = await httpsUpstream((req, res) => {
    res.writeHead(200, { "content-type": "text/plain; charset=utf-8" });
    res.end("fine");
  });
  const wide = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: utf8.port }), inject: [headerRule()] });
  const kept = await talk(wide.r.socketPath, get(`http://${HOST}/x`));
  assert.match(kept, /^HTTP\/1\.1 200/);
  assert.match(kept, /fine$/);
});

test("a Location carrying a DERIVED token is passed on: only an exact echo is redacted", async () => {
  // Accepted risk, pinned here: a signed redirect URL can carry a token the endpoint minted
  // from the credential, and only the exact secret (and its spellings) is redacted.
  const derived = "tok_" + crypto.createHash("sha256").update(SECRET).digest("hex").slice(0, 16);
  const up = await httpsUpstream((req, res) => {
    res.writeHead(302, { location: `https://${HOST}/next?sig=${derived}`, "content-type": "text/plain" });
    res.end("moved");
  });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const out = await talk(r.socketPath, get(`http://${HOST}/x`));
  assert.match(out, /^HTTP\/1\.1 302/);
  const head = out.slice(0, out.indexOf("\r\n\r\n"));
  const location = head.split("\r\n").find((line) => line.toLowerCase().startsWith("location:"));
  assert.equal(location, `location: https://${HOST}/next?sig=${derived}`,
    "a derived token is not the credential and is not redacted: " + head);
  assert.equal(head.includes(SECRET), false, "the credential itself is nowhere in it");
  assertNoSecret(logs);
});

test("cross-host redirect: the Location passes through, and a follow-up to the other host carries no credential", async () => {
  const other = await httpsUpstream((req, res) => { res.writeHead(200, { "content-type": "text/plain" }); res.end("other"); });
  const up = await httpsUpstream((req, res) => {
    res.writeHead(307, { location: `http://other.example.com/next?t=${SECRET}` });
    res.end();
  });
  const { r, logs } = await relay({
    lookup: async (h) => [{ address: h === HOST ? PUB : "93.184.216.35", family: 4 }],
    _connectOverride: () => ({ host: "127.0.0.1", port: up.port }),
    inject: [headerRule()],
  });
  const first = await talk(r.socketPath, get(`http://${HOST}/x`));
  assert.match(first, /^HTTP\/1\.1 307/);
  const head = first.slice(0, first.indexOf("\r\n\r\n"));
  assert.match(head, /^location: http:\/\/other\.example\.com\/next\?t=\[redacted\]$/m, "the target is kept, the credential is not");

  // The step follows the redirect itself. The other host is not an inject host,
  // so nothing is opened upstream and no credential is attached.
  const second = await talk(r.socketPath, get("http://other.example.com/next?t=anything"));
  assert.match(second, /^HTTP\/1\.1 403/, "only an inject host is served at all");
  assert.equal(other.reqs.length, 0, "the other upstream was never contacted");
  assert.ok(logs.some((l) => l.includes("deny other.example.com (not an inject host)")), logs.join("\n"));
  assertNoSecret(logs);
});

test("the response body cap ends the answer instead of streaming past it", async () => {
  const cap = 16 * 1024 * 1024;
  const up = await httpsUpstream((req, res) => {
    res.writeHead(200, { "content-type": "text/plain" });
    const chunk = Buffer.alloc(1024 * 1024, 0x79);
    let written = 0;
    const pump = () => {
      while (written <= cap + 1024 * 1024) { written += chunk.length; if (!res.write(chunk)) return res.once("drain", pump); }
      res.end();
    };
    pump();
  });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  const out = await talk(r.socketPath, get(`http://${HOST}/x`), { timeout: 15000, settle: 200 });
  assert.match(out, /^HTTP\/1\.1 200/);
  assert.ok(out.length <= cap + 1024 * 1024, "the answer stops at the cap: " + out.length);
  assert.ok(logs.some((l) => l.includes("response too large")), logs.join("\n"));
});

/* ------------------------------------------------------- what is refused */

test("CONNECT to an inject host is refused, and any other CONNECT is unchanged", async () => {
  const up = await httpsUpstream((req, res) => { res.end("x"); });
  const echo = await new Promise((resolve) => {
    const srv = createNetServer((c) => c.on("data", (d) => c.write("U:" + d.toString())));
    srv.listen(0, "127.0.0.1", () => {
      closers.push(() => new Promise((r) => srv.close(() => r())));
      resolve(srv.address().port);
    });
  });
  const { r, logs } = await relay({
    egressAllow: [HOST, "other.example.com"],
    _connectOverride: (addr) => ({ host: "127.0.0.1", port: addr === PUB ? echo : up.port }),
    inject: [headerRule()],
  });
  assert.match(await talk(r.socketPath, `PROXY\nCONNECT ${HOST}:443 HTTP/1.1\r\n\r\n`), /^HTTP\/1\.1 403/);
  assert.ok(logs.some((l) => l.includes("inject_host_requires_http_form")), logs.join("\n"));
  assert.equal(up.reqs.length, 0);

  // A tunnel to another host still behaves as it always did.
  const other = await talk(r.socketPath, "PROXY\nCONNECT other.example.com:443 HTTP/1.1\r\n\r\n", { settle: 60 });
  assert.match(other, /^HTTP\/1\.1 200/);
});

test("construction refuses an inject host that the egress list does not allow", () => {
  const pre = { pathPrefixes: ["/v1"] };
  const bad = [
    [{ host: "other.example.com", header: "Authorization", secret: () => SECRET, ...pre }, "inject_host_not_allowed"],
    [{ host: "*.example.com", header: "Authorization", secret: () => SECRET, ...pre }, "inject_bad_host"],
    [{ host: "API.example.com", header: "Authorization", secret: () => SECRET, ...pre }, "inject_bad_host"],
    [{ host: "100.64.20.9", header: "Authorization", secret: () => SECRET, ...pre }, "inject_bad_host"],
    [{ host: HOST, secret: () => SECRET, ...pre }, "inject_bad_target"],
    [{ host: HOST, header: "Authorization", query: "api_key", secret: () => SECRET, ...pre }, "inject_bad_target"],
    [{ host: HOST, header: "Host", secret: () => SECRET, ...pre }, "inject_bad_header"],
    [{ host: HOST, header: "Content-Length", secret: () => SECRET, ...pre }, "inject_bad_header"],
    [{ host: HOST, header: "Proxy-Authorization", secret: () => SECRET, ...pre }, "inject_bad_header"],
    [{ host: HOST, header: "Trans fer", secret: () => SECRET, ...pre }, "inject_bad_header"],
    [{ host: HOST, header: "Authorization", format: "Bearer", secret: () => SECRET, ...pre }, "inject_bad_format"],
    [{ host: HOST, header: "Authorization", format: "{} and {}", secret: () => SECRET, ...pre }, "inject_bad_format"],
    [{ host: HOST, query: "api key", secret: () => SECRET, ...pre }, "inject_bad_query"],
    [{ host: HOST, query: "k".repeat(65), secret: () => SECRET, ...pre }, "inject_bad_query"],
    [{ host: HOST, header: "Authorization", secret: SECRET, ...pre }, "inject_bad_secret"],
    [[headerRule(), headerRule({ header: "X-Other" })], "inject_duplicate_host"],
  ];
  for (const [entry, code] of bad) {
    assert.throws(
      () => createEgressRelay(relayOpts({ inject: Array.isArray(entry) ? entry : [entry], dir: join(scratch, "bad" + (++seq)) })),
      (e) => e instanceof Error && e.code === code,
      JSON.stringify(entry) + " -> " + code,
    );
  }
  // And a rule that is fine constructs, with no listening socket left behind.
  const r = createEgressRelay(relayOpts({ inject: [headerRule()], dir: join(scratch, "ok" + (++seq)) }));
  closers.push(() => r.close());
});

test("construction refuses a rule with no usable pathPrefixes, and a rule with bad methods", () => {
  const bad = [
    [{ host: HOST, header: "Authorization", secret: () => SECRET }, "inject_bad_path_prefixes", "absent"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: [] }, "inject_bad_path_prefixes", "empty"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: "/v1" }, "inject_bad_path_prefixes", "not an array"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: ["v1"] }, "inject_bad_path_prefixes", "no leading slash"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: ["/v1/../admin"] }, "inject_bad_path_prefixes", "dot segments"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: ["/v1?x=1"] }, "inject_bad_path_prefixes", "a query"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: ["/v1#x"] }, "inject_bad_path_prefixes", "a fragment"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: ["/v1\u0000"] }, "inject_bad_path_prefixes", "a NUL"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: ["/" + "x".repeat(200)] }, "inject_bad_path_prefixes", "too long"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: Array.from({ length: 21 }, (_, i) => "/p" + i) }, "inject_bad_path_prefixes", "too many"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: [12] }, "inject_bad_path_prefixes", "not a string"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: ["/"] }, "inject_bad_path_prefixes", "the whole host"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: ["//"] }, "inject_bad_path_prefixes", "no segment"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: ["///"] }, "inject_bad_path_prefixes", "no segment at all"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: ["/v1"], methods: "GET" }, "inject_bad_methods", "not an array"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: ["/v1"], methods: [] }, "inject_bad_methods", "empty"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: ["/v1"], methods: ["get"] }, "inject_bad_methods", "lower case"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: ["/v1"], methods: ["FETCH"] }, "inject_bad_methods", "not an inject method"],
    [{ host: HOST, header: "Authorization", secret: () => SECRET, pathPrefixes: ["/v1"], methods: [1] }, "inject_bad_methods", "not a string"],
  ];
  for (const [entry, code, label] of bad) {
    assert.throws(
      () => createEgressRelay(relayOpts({ inject: [entry], dir: join(scratch, "badp" + (++seq)) })),
      (e) => e instanceof Error && e.code === code,
      label + " -> " + code,
    );
  }
});

test("a bad method is refused with 405, and a target that is not a plain http URL is refused", async () => {
  const up = await httpsUpstream((req, res) => { res.end("x"); });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  for (const method of ["TRACE", "OPTIONS", "PATCHY"]) {
    assert.match(await talk(r.socketPath, `PROXY\n${method} http://${HOST}/x HTTP/1.1\r\nHost: x\r\n\r\n`), /^HTTP\/1\.1 405/, method);
  }
  for (const target of [
    `http://user:pw@${HOST}/x`, `http://${HOST}.example.net/x`, `http://${HOST}#frag`, `http://${HOST}:8080/x`,
    `https://${HOST}/x`, `/${HOST}/x`, `http://10.20.30.40/x`,
  ]) {
    const out = await talk(r.socketPath, `PROXY\nGET ${target} HTTP/1.1\r\nHost: x\r\n\r\n`);
    assert.match(out, /^HTTP\/1\.1 (403|400)/, target);
  }
  assert.match(await talk(r.socketPath, `PROXY\nGET http://${HOST}./x HTTP/1.1\r\nHost: x\r\n\r\n`), /^HTTP\/1\.1 403/, "trailing dot");
  assert.equal(up.reqs.length, 0, "nothing reached the upstream");
  assertNoSecret(logs);
});

test("a private or loopback resolution is refused before any connection", async () => {
  let accepted = 0;
  const up = await httpsUpstream((req, res) => { accepted++; res.end("x"); });
  for (const address of ["127.0.0.1", "10.20.30.40", "169.254.169.254", "100.64.20.9"]) {
    const { r, logs } = await relay({
      lookup: async () => [{ address, family: 4 }],
      _connectOverride: () => ({ host: "127.0.0.1", port: up.port }),
      inject: [headerRule()],
    });
    assert.match(await talk(r.socketPath, get(`http://${HOST}/v1/x`)), /^HTTP\/1\.1 403/, address);
    assert.ok(logs.some((l) => l.includes("deny " + HOST)), logs.join("\n"));
  }
  // One address of a name resolving to a refused one refuses the whole name.
  const mixed = await relay({
    lookup: async () => [{ address: PUB, family: 4 }, { address: "127.0.0.1", family: 4 }],
    _connectOverride: () => ({ host: "127.0.0.1", port: up.port }),
    inject: [headerRule()],
  });
  assert.match(await talk(mixed.r.socketPath, get(`http://${HOST}/x`)), /^HTTP\/1\.1 403/);
  assert.equal(accepted, 0, "no upstream connection was opened");
});

test("a chunked request body is refused with 411, and nothing is sent", async () => {
  const up = await httpsUpstream((req, res) => { res.end("x"); });
  const { r, logs } = await relay({
    _connectOverride: () => ({ host: "127.0.0.1", port: up.port }),
    inject: [headerRule({ methods: ["POST"] })],
  });
  const out = await talk(r.socketPath,
    `PROXY\nPOST http://${HOST}/v1/x HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n`);
  assert.match(out, /^HTTP\/1\.1 411/);
  assert.ok(logs.some((l) => l.includes("chunked_request_refused")), logs.join("\n"));
  assert.equal(up.reqs.length, 0);
});

test("a request body over 8 MB is refused, and Expect is refused", async () => {
  const up = await httpsUpstream((req, res) => { res.end("x"); });
  const { r, logs } = await relay({
    _connectOverride: () => ({ host: "127.0.0.1", port: up.port }),
    inject: [headerRule({ methods: ["POST"] })],
  });
  assert.match(await talk(r.socketPath,
    `PROXY\nPOST http://${HOST}/v1/x HTTP/1.1\r\nHost: x\r\nContent-Length: ${9 * 1024 * 1024}\r\n\r\n`), /^HTTP\/1\.1 413/);
  assert.match(await talk(r.socketPath,
    `PROXY\nPOST http://${HOST}/v1/x HTTP/1.1\r\nHost: x\r\nContent-Length: 5\r\nExpect: 100-continue\r\n\r\n`), /^HTTP\/1\.1 417/);
  assert.match(await talk(r.socketPath,
    `PROXY\nPOST http://${HOST}/v1/x HTTP/1.1\r\nHost: x\r\nExpect: something-else\r\n\r\n`), /^HTTP\/1\.1 417/);
  assert.equal(up.reqs.length, 0);
  assertNoSecret(logs);
});

test("an empty or short secret is refused with 503, and no upstream connection is opened", async () => {
  let accepted = 0;
  const up = await httpsUpstream((req, res) => { accepted++; res.end("x"); });
  // A secret shorter than 16 bytes cannot be told apart from ordinary text under the taint
  // window, so it is never used at all.
  for (const value of ["", "short", "123456789012345", null, undefined]) {
    const { r, logs } = await relay({
      _connectOverride: () => ({ host: "127.0.0.1", port: up.port }),
      inject: [headerRule({ secret: () => value })],
    });
    assert.match(await talk(r.socketPath, get(`http://${HOST}/x`)), /^HTTP\/1\.1 503/, String(value));
    assert.ok(logs.some((l) => l.includes("inject_secret_missing")), logs.join("\n"));
  }
  // A 16 byte secret is used.
  const short = "0123456789abcdef";
  const ok = await relay({
    _connectOverride: () => ({ host: "127.0.0.1", port: up.port }),
    inject: [headerRule({ secret: () => short })],
  });
  assert.match(await talk(ok.r.socketPath, get(`http://${HOST}/x`)), /^HTTP\/1\.1 200/, "sixteen bytes is a credential");
  accepted = 0;
  // A secret function that throws is the same refusal, and its message is not logged.
  const thrown = await relay({
    _connectOverride: () => ({ host: "127.0.0.1", port: up.port }),
    inject: [headerRule({ secret: () => { throw new Error("keychain said no"); } })],
  });
  assert.match(await talk(thrown.r.socketPath, get(`http://${HOST}/x`)), /^HTTP\/1\.1 503/);
  assert.equal(thrown.logs.join("\n").includes("keychain said no"), false, "the error text is not logged");
  assert.equal(accepted, 0, "no request was ever sent");
});

test("the upstream certificate is verified: without the test's anchor the request fails closed", async () => {
  const up = await httpsUpstream((req, res) => { res.end("x"); });
  const { r, logs } = await relay({
    _connectOverride: () => ({ host: "127.0.0.1", port: up.port }),
    _injectUpstreamTls: undefined,
    inject: [headerRule()],
  });
  const out = await talk(r.socketPath, get(`http://${HOST}/x`));
  assert.match(out, /^HTTP\/1\.1 502/, "an untrusted certificate is a refusal");
  assert.equal(up.reqs.length, 0, "no request line was ever spoken");
  assert.ok(logs.some((l) => l.includes("inject upstream failed")), logs.join("\n"));
  assert.equal(logs.join("\n").includes("CERT"), false, "no TLS error text reaches the log");
  assertNoSecret(logs);
});

test("one request per connection, and an upstream that stalls is cut", async () => {
  const up = await httpsUpstream((req, res) => { res.writeHead(200, { "content-type": "text/plain" }); res.end("first"); });
  const { r } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()], maxUpstream: 1 });
  await talk(r.socketPath, get(`http://${HOST}/a`) + get(`http://${HOST}/b`));
  await delay(200);
  assert.equal(up.reqs.length, 1, "the second request on one connection never reaches upstream");

  const silent = await new Promise((resolve) => {
    const srv = createHttpsServer({ key: PAIR.key, cert: PAIR.cert }, () => {});
    srv.listen(0, "127.0.0.1", () => {
      closers.push(() => { try { srv.closeAllConnections?.(); } catch {} return new Promise((rr) => srv.close(() => rr())); });
      resolve(srv.address().port);
    });
  });
  const stalled = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: silent }), inject: [headerRule()], plainStallMs: 200, maxUpstream: 1 });
  const t0 = Date.now();
  const out = await talk(stalled.r.socketPath, get(`http://${HOST}/x`), { timeout: 3000, settle: 60 });
  assert.ok(Date.now() - t0 < 3000, "the answer arrived inside the bound");
  assert.match(out, /^HTTP\/1\.1 502/);
  assert.ok(stalled.logs.some((l) => l.includes("inject upstream failed")), stalled.logs.join("\n"));
});

test("without an inject list the relay is unchanged: an absolute-form request is still refused", async () => {
  const { r, logs } = await relay({});
  const out = await talk(r.socketPath, get(`http://${HOST}/x`));
  assert.match(out, /^HTTP\/1\.1 405/, "the bot path still only speaks CONNECT");
  assert.ok(logs.some((l) => l.includes("(only CONNECT)")), logs.join("\n"));
});

test("no log line from any of this carries the credential, in any spelling", async () => {
  const forms = echoForms(SECRET);
  const up = await httpsUpstream((req, res) => {
    res.writeHead(500, { "content-type": "text/plain", location: `https://${HOST}/e?t=${SECRET}` });
    res.end(Object.values(forms).join("\n"));
  });
  const { r, logs } = await relay({ _connectOverride: () => ({ host: "127.0.0.1", port: up.port }), inject: [headerRule()] });
  await talk(r.socketPath, get(`http://${HOST}/x`));
  await talk(r.socketPath, get(`http://${HOST}/y?api_key=${encodeURIComponent(SECRET)}`));
  await talk(r.socketPath, `PROXY\nCONNECT ${HOST}:443 HTTP/1.1\r\n\r\n`);
  await talk(r.socketPath, get("http://other.example.com/x"));
  assert.ok(logs.length > 0, "the relay logged its decisions");
  assertNoSecret(logs);
});