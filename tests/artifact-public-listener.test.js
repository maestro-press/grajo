/**
 * The public-link listener: the surface a mailed report link reaches.
 *
 * WHAT THIS PINS, AND WHY IT IS SHAPED LIKE THIS: every case runs the REAL listener (`createListener`) over
 * a REAL HTTP socket, against a FAKE door on a unix socket in a temp directory that records every line it
 * receives. That way the two things that matter are observed from the outside: what a stranger can make
 * the listener answer, and what the listener is willing to say to the door. Nothing here reaches a
 * database, the gateway, or any file outside the temp directory.
 *
 * The four approved sentences are hard-coded below (copied from the approved copy) rather than read from a
 * file, so this test is the record of the exact bytes the listener is allowed to write itself.
 */
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { once } from "node:events";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { request as httpRequest } from "node:http";
import { connect as netConnect, createServer as createNetServer } from "node:net";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { after, test } from "node:test";
import { fileURLToPath } from "node:url";

import { createListener } from "../scripts/artifact-public/server.mjs";

const ROOT = fileURLToPath(new URL("..", import.meta.url));
const LISTENER_SOURCE = join(ROOT, "scripts", "artifact-public", "server.mjs");

/* ------------------------------------------------------------- the approved copy */

const A2_EN = "This link doesn't open a report. Ask the sender for a new one.";
const A2_ES = "Este enlace no abre ningún informe. Pide uno nuevo a quien te lo envió.";
const A3_EN = "This report is unavailable right now. Try again in a few minutes.";
const A3_ES = "Este informe no está disponible ahora. Inténtalo de nuevo en unos minutos.";

/* --------------------------------------------------------------- the fixed headers */

const CSP_BASE =
  "sandbox allow-popups allow-popups-to-escape-sandbox; default-src 'none'; img-src data:; style-src 'unsafe-inline'";
const CSP_FORM =
  "sandbox allow-popups allow-popups-to-escape-sandbox allow-forms; default-src 'none'; img-src data:; style-src 'unsafe-inline'; form-action 'self'";

/* ------------------------------------------------------------------ fixtures */

/** Two distinct tokens of the one shape a path may carry: 43 base64url characters. */
const TOKEN = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFG";
const OTHER_TOKEN = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFH";

const OK_HTML = "<!doctype html><html><body><p>a report</p></body></html>";
const COMMENT_HTML = '<!doctype html><html><body><form class="comment-form" method="post" action="">'
  + '<textarea name="text"></textarea></form></body></html>';
const MISSING_HTML = "<!doctype html><html><body><p>the door's unknown-link page</p></body></html>";
const GONE_HTML = "<!doctype html><html><body><p>the door's expired page</p></body></html>";

const ROOT_TMP = mkdtempSync(join(tmpdir(), "artifact-public-listener-"));
after(() => {
  try { rmSync(ROOT_TMP, { recursive: true, force: true }); } catch { /* nothing left to remove */ }
});

/* --------------------------------------------------------------------- helpers */

/**
 * The fake door: newline-delimited JSON, one request per connection, every request recorded.
 * `reply(request)` returns the object to send back, or null to answer nothing at all.
 */
function fakeDoor(socketPath, reply) {
  const seen = [];
  const live = new Set();
  const server = createNetServer((socket) => {
    live.add(socket);
    socket.on("close", () => live.delete(socket));
    socket.on("error", () => { /* the client hung up */ });
    let buffer = "";
    socket.setEncoding("utf8");
    socket.on("data", (chunk) => {
      buffer += chunk;
      const at = buffer.indexOf("\n");
      if (at < 0) return;
      const line = buffer.slice(0, at);
      buffer = buffer.slice(at + 1);
      let parsed;
      try {
        parsed = JSON.parse(line);
      } catch {
        parsed = null;
      }
      seen.push(parsed);
      const answer = reply(parsed);
      if (answer == null) return;
      try {
        socket.end(`${JSON.stringify(answer)}\n`);
      } catch { /* the client hung up */ }
    });
  });
  return {
    server,
    seen,
    close() {
      for (const socket of live) {
        try { socket.destroy(); } catch { /* already gone */ }
      }
      try { server.close(); } catch { /* already closed */ }
    },
  };
}

/** One request to the listener. `body` is sent with an explicit content length. */
function send(port, path, { method = "GET", headers = {}, body = null } = {}) {
  return new Promise((resolve, reject) => {
    const sent = { ...headers };
    if (body != null) sent["content-length"] = Buffer.byteLength(body, "utf8");
    const req = httpRequest({ host: "127.0.0.1", port, path, method, headers: sent, agent: false }, (res) => {
      let text = "";
      res.setEncoding("utf8");
      res.on("data", (chunk) => { text += chunk; });
      res.on("end", () => resolve({ status: res.statusCode, headers: res.headers, body: text }));
    });
    req.on("error", reject);
    req.end(body == null ? undefined : body);
  });
}

/**
 * A listener plus (unless `startDoor` is false) a fake door under one temp directory, on an injected clock
 * the rate-limit cases move by hand. Always closed by the case's own `finally`.
 */
async function startCase({
  reply = () => ({ status: 200, html: OK_HTML }),
  listener = {},
  startDoor = true,
} = {}) {
  const dir = mkdtempSync(join(ROOT_TMP, "case-"));
  const doorPath = join(dir, "door.sock");
  const door = fakeDoor(doorPath, reply);
  if (startDoor) {
    door.server.listen(doorPath);
    await once(door.server, "listening");
  }
  const logged = [];
  const clock = { value: 1_700_000_000_000 };
  const server = createListener({
    doorPath,
    now: () => clock.value,
    log: (line) => logged.push(line),
    ...listener,
  });
  server.listen(0, "127.0.0.1");
  await once(server, "listening");
  const port = server.address().port;
  return {
    dir,
    doorPath,
    door,
    logged,
    clock,
    server,
    port,
    async startDoor() {
      door.server.listen(doorPath);
      await once(door.server, "listening");
    },
    async close() {
      await new Promise((resolve) => {
        server.close(() => resolve());
        server.closeAllConnections?.();
      });
      door.close();
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* already gone */ }
    },
  };
}

/* ------------------------------------------------------------- the routing surface */

test("the public listener serves nothing but /r/<token> and /r/<token>/comment", async () => {
  const c = await startCase();
  try {
    const paths = [
      "/",
      `/a/${TOKEN}`,
      "/dashboard",
      "/api/x",
      "/r/short",
      `/r/${"a".repeat(44)}`,
      `/r/${TOKEN.slice(0, 42)}!`,
      `/r/${TOKEN}/`,
      `/r/${TOKEN}/comment/x`,
      "/r/../x",
      `/r/${TOKEN}/../..`,
    ];
    for (const path of paths) {
      const res = await send(c.port, path);
      assert.equal(res.status, 404, `${path} is the 404 page`);
      assert.ok(res.body.includes(A2_EN), `${path} carries the approved A2 line`);
      assert.ok(!res.body.includes(OK_HTML), `${path} is never a report`);
    }
    // Other methods on a valid path are the same 404: there is no third route.
    for (const [method, path] of [
      ["HEAD", `/r/${TOKEN}`],
      ["POST", `/r/${TOKEN}`],
      ["GET", `/r/${TOKEN}/comment`],
      ["PUT", `/r/${TOKEN}/comment`],
      ["DELETE", `/r/${TOKEN}`],
    ]) {
      const res = await send(c.port, path, { method });
      assert.equal(res.status, 404, `${method} ${path} is the 404 page`);
    }
    assert.equal(c.door.seen.length, 0, "the door never heard about a single one of them");
  } finally {
    await c.close();
  }
});

test("any query string is 404", async () => {
  const c = await startCase();
  try {
    for (const path of [`/r/${TOKEN}?x=1`, `/r/${TOKEN}?`, `/r/${TOKEN}/comment?`]) {
      const res = await send(c.port, path);
      assert.equal(res.status, 404, `${path} is the 404 page`);
      assert.ok(res.body.includes(A2_EN));
    }
    assert.equal(c.door.seen.length, 0, "the door never heard about any of them");
  } finally {
    await c.close();
  }
});

/* ------------------------------------------------------------------- the headers */

test("every response, including 404, 429 and 503, carries the sandbox CSP and no-store", async () => {
  const plain = (res, where) => {
    assert.equal(res.headers["content-security-policy"], CSP_BASE, `${where}: the sandbox CSP`);
    assert.ok(!String(res.headers["content-security-policy"]).includes("allow-forms"),
      `${where}: no form permission`);
    assert.equal(res.headers["cache-control"], "no-store, private", `${where}: nothing is cached`);
    assert.equal(res.headers["referrer-policy"], "no-referrer", `${where}: no referrer`);
    assert.equal(res.headers["x-robots-tag"], "noindex", `${where}: not indexed`);
    assert.equal(res.headers["x-content-type-options"], "nosniff", `${where}: not sniffed`);
    assert.equal(res.headers["content-type"], "text/html; charset=utf-8", `${where}: an html page`);
    assert.equal(res.headers["set-cookie"], undefined, `${where}: no cookie is ever set`);
    assert.equal(res.headers.location, undefined, `${where}: nothing ever redirects`);
  };

  const notFound = await startCase();
  try {
    plain(await send(notFound.port, "/"), "404");
  } finally {
    await notFound.close();
  }

  const limited = await startCase({ listener: { perTokenLimit: 1 } });
  try {
    assert.equal((await send(limited.port, `/r/${TOKEN}`)).status, 200);
    const res = await send(limited.port, `/r/${TOKEN}`);
    assert.equal(res.status, 429);
    plain(res, "429");
  } finally {
    await limited.close();
  }

  const down = await startCase({ reply: () => ({ status: 503 }) });
  try {
    const res = await send(down.port, `/r/${TOKEN}`);
    assert.equal(res.status, 503);
    plain(res, "503");
  } finally {
    await down.close();
  }

  const comment = await startCase({
    reply: () => ({
      status: 200, ok: true, line: "Thanks.", html: COMMENT_HTML, form: true,
    }),
  });
  try {
    const res = await send(comment.port, `/r/${TOKEN}/comment`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "formNonce=n1&text=hello",
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers["content-security-policy"], CSP_FORM, "the comment page alone may post");
    assert.ok(String(res.headers["content-security-policy"]).includes("allow-forms"));
    assert.ok(String(res.headers["content-security-policy"]).includes("form-action 'self'"));
    assert.equal(res.headers["cache-control"], "no-store, private");
    assert.equal(res.headers["referrer-policy"], "no-referrer");
    assert.equal(res.headers["x-robots-tag"], "noindex");
    assert.equal(res.headers["x-content-type-options"], "nosniff");
    assert.equal(res.headers["content-type"], "text/html; charset=utf-8");
    assert.equal(res.headers["set-cookie"], undefined);
  } finally {
    await comment.close();
  }
});

/* ------------------------------------------- the form permission comes from the door */

test("allow-forms comes only from the door's form: true, never from the page's html", async () => {
  // The page carries the marker every comment page carries, and the door does NOT say it has a form: the
  // sandbox stays shut. A stored report's own text could contain that marker, so it is never read here.
  const markerOnly = await startCase({ reply: () => ({ status: 200, html: COMMENT_HTML }) });
  try {
    const res = await send(markerOnly.port, `/r/${TOKEN}`);
    assert.equal(res.status, 200);
    assert.equal(res.body, COMMENT_HTML, "the door's page is relayed exactly as it came");
    assert.equal(res.headers["content-security-policy"], CSP_BASE, "no form permission for a marker");
  } finally {
    await markerOnly.close();
  }

  const explicitFalse = await startCase({
    reply: () => ({ status: 200, html: COMMENT_HTML, form: false }),
  });
  try {
    const res = await send(explicitFalse.port, `/r/${TOKEN}`);
    assert.equal(res.headers["content-security-policy"], CSP_BASE, "`form: false` is no form");
  } finally {
    await explicitFalse.close();
  }

  // Only strictly `true` counts: a truthy string is not a page this process trusts itself to relax for.
  const notABoolean = await startCase({
    reply: () => ({ status: 200, html: COMMENT_HTML, form: "true" }),
  });
  try {
    const res = await send(notABoolean.port, `/r/${TOKEN}`);
    assert.equal(res.headers["content-security-policy"], CSP_BASE, "`\"true\"` is not `true`");
  } finally {
    await notABoolean.close();
  }

  // And the other way round: a page with no marker at all still gets the form permission when the door
  // says it carries the form, because the door's word is the only thing that decides.
  const explicitTrue = await startCase({
    reply: () => ({ status: 200, html: OK_HTML, form: true }),
  });
  try {
    const view = await send(explicitTrue.port, `/r/${TOKEN}`);
    assert.equal(view.headers["content-security-policy"], CSP_FORM, "the door said form: true");
    assert.ok(String(view.headers["content-security-policy"]).includes("form-action 'self'"));

    const posted = await send(explicitTrue.port, `/r/${TOKEN}/comment`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "formNonce=n1&text=hello",
    });
    assert.equal(posted.status, 200);
    assert.equal(posted.headers["content-security-policy"], CSP_FORM, "the comment reply too");
  } finally {
    await explicitTrue.close();
  }

  // A refusal the door renders on a page that still offers the form keeps the permission, so a reader can
  // correct what they typed.
  const refused = await startCase({
    reply: () => ({ status: 200, ok: false, line: "Try again.", html: COMMENT_HTML, form: true }),
  });
  try {
    const res = await send(refused.port, `/r/${TOKEN}/comment`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "formNonce=n1&text=hello",
    });
    assert.equal(res.status, 200);
    assert.equal(res.headers["content-security-policy"], CSP_FORM);
  } finally {
    await refused.close();
  }
});

/* ---------------------------------------------------------- the parser's own refusals */

/** One raw request over a plain TCP socket: the reply bytes as they came, until the peer closes. */
function rawRequest(port, payload) {
  return new Promise((resolve, reject) => {
    const socket = netConnect(port, "127.0.0.1");
    let raw = "";
    const timer = setTimeout(() => {
      try { socket.destroy(); } catch { /* already gone */ }
      resolve(raw);
    }, 5_000);
    socket.setEncoding("utf8");
    socket.on("connect", () => socket.write(payload));
    socket.on("data", (chunk) => { raw += chunk; });
    socket.on("error", () => { clearTimeout(timer); resolve(raw); });
    socket.on("close", () => { clearTimeout(timer); resolve(raw); });
    socket.on("timeout", () => { clearTimeout(timer); reject(new Error("no reply at all")); });
  });
}

/** The fixed header set and the approved A2 page of a raw reply, checked as headers, not as text. */
function assertRawReply(raw, where) {
  const split = raw.indexOf("\r\n\r\n");
  assert.ok(split > 0, `${where}: a complete reply`);
  const head = raw.slice(0, split);
  const body = raw.slice(split + 4);
  const [statusLine, ...lines] = head.split("\r\n");
  const headers = new Map(lines.map((line) => {
    const at = line.indexOf(":");
    return [line.slice(0, at).toLowerCase(), line.slice(at + 1).trim()];
  }));
  assert.equal(headers.get("content-security-policy"), CSP_BASE, `${where}: the base sandbox CSP`);
  assert.equal(headers.get("cache-control"), "no-store, private", `${where}: nothing is cached`);
  assert.equal(headers.get("referrer-policy"), "no-referrer", `${where}: no referrer`);
  assert.equal(headers.get("x-robots-tag"), "noindex", `${where}: not indexed`);
  assert.equal(headers.get("x-content-type-options"), "nosniff", `${where}: not sniffed`);
  assert.equal(headers.get("content-type"), "text/html; charset=utf-8", `${where}: an html page`);
  assert.equal(headers.get("connection"), "close", `${where}: the socket is closed after it`);
  assert.equal(headers.get("content-length"), String(Buffer.byteLength(body, "utf8")),
    `${where}: the length matches the body`);
  assert.ok(body.includes(A2_EN), `${where}: the approved A2 line, in English`);
  assert.ok(!body.includes(A3_EN), `${where}: and no other line`);
  return statusLine;
}

test("a request node's own parser refuses gets the fixed page and headers", async () => {
  const c = await startCase();
  try {
    const tooBig = await rawRequest(c.port, `GET / HTTP/1.1\r\nX-Big: ${"a".repeat(20_000)}\r\n\r\n`);
    assert.equal(assertRawReply(tooBig, "431"), "HTTP/1.1 431 Request Header Fields Too Large");

    const invalid = await rawRequest(c.port,
      "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: nope\r\n\r\n");
    assert.equal(assertRawReply(invalid, "400"), "HTTP/1.1 400 Bad Request");

    assert.equal(c.door.seen.length, 0, "the door never heard about either of them");
    assert.ok(!c.logged.join("\n").includes("HPE_"), "the parser's own detail is never logged");
    assert.ok(!c.logged.join("\n").includes("Content-Length"), "nor the request's own text");
  } finally {
    await c.close();
  }
});

/* --------------------------------------------------------------- the socket ceiling */

test("the listener holds at most maxConnections sockets, 64 by default", () => {
  assert.equal(createListener().maxConnections, 64, "the default ceiling");
  assert.equal(createListener({ maxConnections: 7 }).maxConnections, 7, "it is an option");
  assert.equal(createListener({ maxConnections: 0 }).maxConnections, 64,
    "an unusable value falls back to the default");
});

/* ------------------------------------------------------------ nothing is leaked */

test("cookies in the request never reach the door or logs", async () => {
  const c = await startCase();
  try {
    const res = await send(c.port, `/r/${TOKEN}`, {
      headers: { cookie: "crow_session=session-value-do-not-keep; other=1" },
    });
    assert.equal(res.status, 200);
    const received = JSON.stringify(c.door.seen);
    assert.equal(c.door.seen.length, 1);
    assert.ok(!JSON.stringify(c.door.seen[0]).toLowerCase().includes("cookie"), "no cookie field");
    assert.ok(!received.includes("session-value-do-not-keep"), "no cookie value reaches the door");
    const logged = c.logged.join("\n");
    assert.ok(!logged.includes("session-value-do-not-keep"), "no cookie value is logged");
    assert.ok(!logged.includes(TOKEN), "the token is never logged");
  } finally {
    await c.close();
  }
});

test("the listener sends the raw token and never a hash", async () => {
  const c = await startCase();
  try {
    assert.equal((await send(c.port, `/r/${TOKEN}`)).status, 200);
    assert.deepEqual(c.door.seen[0], { op: "view", token: TOKEN, acceptLanguage: "" });
  } finally {
    await c.close();
  }
  const source = readFileSync(LISTENER_SOURCE, "utf8");
  assert.ok(!source.includes("createHash"), "no hashing in the listener");
  assert.ok(!/\bcrypto\b/.test(source), "no crypto import in the listener");
});

test("listener imports nothing but node: built-ins", () => {
  const source = readFileSync(LISTENER_SOURCE, "utf8");
  const patterns = [
    /\bfrom\s*["']([^"']+)["']/g,
    /\bimport\s+["']([^"']+)["']/g,
    /\bimport\s*\(\s*["']([^"']+)["']/g,
    /\brequire\s*\(\s*["']([^"']+)["']/g,
  ];
  const specifiers = [];
  for (const pattern of patterns) {
    for (const match of source.matchAll(pattern)) specifiers.push(match[1]);
  }
  assert.ok(specifiers.length > 0, "the scan found the imports at all");
  for (const specifier of specifiers) {
    assert.ok(specifier.startsWith("node:"), `${specifier} is a node: built-in`);
  }
});

/* ------------------------------------------------------------- the door's failures */

test("gateway down gives the 503 page and the next request reconnects", async () => {
  const c = await startCase({ startDoor: false });
  try {
    const down = await send(c.port, `/r/${TOKEN}`);
    assert.equal(down.status, 503);
    assert.ok(down.body.includes(A3_EN), "the approved unavailable line");

    await c.startDoor();
    const back = await send(c.port, `/r/${TOKEN}`);
    assert.equal(back.status, 200);
    assert.equal(back.body, OK_HTML, "the very next request is served");
    assert.equal(c.door.seen.length, 1);
  } finally {
    await c.close();
  }
});

test("the door timeout gives the 503 page", async () => {
  const c = await startCase({ reply: () => null, listener: { doorTimeoutMs: 100 } });
  try {
    const res = await send(c.port, `/r/${TOKEN}`);
    assert.equal(res.status, 503);
    assert.ok(res.body.includes(A3_EN));
    assert.equal(c.door.seen.length, 1, "the request did reach the door");
  } finally {
    await c.close();
  }
});

test("a door 410 and 200 are relayed with their html; a door 404 is relayed", async () => {
  let mode = "ok";
  const c = await startCase({
    reply: () => {
      if (mode === "gone") return { status: 410, html: GONE_HTML };
      if (mode === "missing") return { status: 404, html: MISSING_HTML };
      if (mode === "bare") return { status: 503 };
      if (mode === "junk") return { status: 400 };
      return { status: 200, html: OK_HTML };
    },
  });
  try {
    mode = "gone";
    const gone = await send(c.port, `/r/${TOKEN}`);
    assert.equal(gone.status, 410, "an expired link keeps its own status");
    assert.equal(gone.body, GONE_HTML, "and the door's page");

    mode = "ok";
    const ok = await send(c.port, `/r/${TOKEN}`);
    assert.equal(ok.status, 200);
    assert.equal(ok.body, OK_HTML);

    mode = "missing";
    const missing = await send(c.port, `/r/${TOKEN}`);
    assert.equal(missing.status, 404);
    assert.equal(missing.body, MISSING_HTML, "the door's own approved 404 page");

    mode = "bare";
    const bare = await send(c.port, `/r/${TOKEN}`);
    assert.equal(bare.status, 503);
    assert.ok(bare.body.includes(A3_EN));

    mode = "junk";
    const junk = await send(c.port, `/r/${TOKEN}`);
    assert.equal(junk.status, 404, "a bare 400 is the unknown-link page");
    assert.ok(junk.body.includes(A2_EN));
  } finally {
    await c.close();
  }
});

/* --------------------------------------------------------------------- comments */

test("a comment POST relays formNonce and text and returns the door's html", async () => {
  const c = await startCase({
    reply: () => ({
      status: 200, ok: true, line: "Thanks.", html: COMMENT_HTML, form: true,
    }),
  });
  try {
    const res = await send(c.port, `/r/${TOKEN}/comment`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "formNonce=nonce-1&text=Hello%20there%2C%20world",
    });
    assert.equal(res.status, 200);
    assert.equal(res.body, COMMENT_HTML);
    assert.deepEqual(c.door.seen[0], {
      op: "comment",
      token: TOKEN,
      formNonce: "nonce-1",
      text: "Hello there, world",
      acceptLanguage: "",
    });
  } finally {
    await c.close();
  }
});

test("a comment POST over 8 KB or with a wrong content type never reaches the door", async () => {
  const c = await startCase();
  try {
    const big = await send(c.port, `/r/${TOKEN}/comment`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: `formNonce=n1&text=${"a".repeat(9_000)}`,
    });
    assert.equal(big.status, 413, "a body over the cap is refused");
    assert.ok(big.body.includes(A2_EN), "with the approved A2 page");

    const wrongType = await send(c.port, `/r/${TOKEN}/comment`, {
      method: "POST",
      headers: { "content-type": "text/plain" },
      body: "formNonce=n1&text=hello",
    });
    assert.equal(wrongType.status, 404);
    assert.ok(wrongType.body.includes(A2_EN));

    const missingField = await send(c.port, `/r/${TOKEN}/comment`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: "formNonce=n1",
    });
    assert.equal(missingField.status, 404);

    assert.equal(c.door.seen.length, 0, "the door never heard about any of them");
  } finally {
    await c.close();
  }
});

/* ------------------------------------------------------------------ the ceilings */

test("per-token rate limit answers 429 with the A3 text and the next token is unaffected", async () => {
  const c = await startCase({ listener: { perTokenLimit: 2 } });
  try {
    assert.equal((await send(c.port, `/r/${TOKEN}`)).status, 200);
    assert.equal((await send(c.port, `/r/${TOKEN}`)).status, 200);
    const limited = await send(c.port, `/r/${TOKEN}`);
    assert.equal(limited.status, 429);
    assert.ok(limited.body.includes(A3_EN), "the approved unavailable line, no new copy");
    assert.equal(limited.headers["retry-after"], "60");

    assert.equal((await send(c.port, `/r/${OTHER_TOKEN}`)).status, 200, "another token is unaffected");

    c.clock.value += 61_000;
    assert.equal((await send(c.port, `/r/${TOKEN}`)).status, 200, "a new window starts the count again");
  } finally {
    await c.close();
  }
});

test("forwarded headers are ignored", async () => {
  const c = await startCase({ listener: { perTokenLimit: 2 } });
  try {
    const statuses = [];
    for (const forwarded of ["203.0.113.7", "198.51.100.9", "192.0.2.44"]) {
      const res = await send(c.port, `/r/${TOKEN}`, { headers: { "x-forwarded-for": forwarded } });
      statuses.push(res.status);
    }
    assert.deepEqual(statuses, [200, 200, 429], "a claimed client address buys no extra requests");
    const received = JSON.stringify(c.door.seen);
    for (const forwarded of ["203.0.113.7", "198.51.100.9", "192.0.2.44"]) {
      assert.ok(!received.includes(forwarded), "no forwarding header reaches the door");
    }
  } finally {
    await c.close();
  }
});

/* -------------------------------------------------------------------- the language */

test("Accept-Language es gives the Spanish pages", async () => {
  const c = await startCase({ reply: () => ({ status: 503 }) });
  try {
    const notFound = await send(c.port, "/", { headers: { "accept-language": "  ES-es,es;q=0.9" } });
    assert.equal(notFound.status, 404);
    assert.ok(notFound.body.includes(A2_ES), "the approved Spanish A2 line");
    assert.ok(notFound.body.includes('<html lang="es">'));

    const down = await send(c.port, `/r/${TOKEN}`, { headers: { "accept-language": "es" } });
    assert.equal(down.status, 503);
    assert.ok(down.body.includes(A3_ES), "the approved Spanish A3 line");

    // Any other prefix is English.
    const english = await send(c.port, "/", { headers: { "accept-language": "en-US,en;q=0.9" } });
    assert.ok(english.body.includes(A2_EN));
  } finally {
    await c.close();
  }
});

/* ------------------------------------------------------------------ the entry point */

test("the listener refuses to start without an IPv4 bind", () => {
  const env = { ...process.env };
  delete env.CROW_ARTIFACT_PUBLIC_BIND;
  delete env.CROW_ARTIFACT_PUBLIC_PORT;

  const unset = spawnSync(process.execPath, [LISTENER_SOURCE], { env, timeout: 5_000, encoding: "utf8" });
  assert.equal(unset.status, 1, "an unset bind is refused");
  assert.equal(unset.stderr.trim().split("\n").length, 1, "one line on stderr");
  assert.match(unset.stderr, /CROW_ARTIFACT_PUBLIC_BIND/);

  const notAnAddress = spawnSync(process.execPath, [LISTENER_SOURCE], {
    env: { ...env, CROW_ARTIFACT_PUBLIC_BIND: "localhost" },
    timeout: 5_000,
    encoding: "utf8",
  });
  assert.equal(notAnAddress.status, 1, "a host name is not an IPv4 address");
  assert.equal(notAnAddress.stderr.trim().split("\n").length, 1, "one line on stderr");

  const empty = spawnSync(process.execPath, [LISTENER_SOURCE], {
    env: { ...env, CROW_ARTIFACT_PUBLIC_BIND: "" },
    timeout: 5_000,
    encoding: "utf8",
  });
  assert.equal(empty.status, 1, "an empty bind is refused");

  // The wildcard, built here so no such literal is written into scripts/artifact-public.
  const wildcard = spawnSync(process.execPath, [LISTENER_SOURCE], {
    env: { ...env, CROW_ARTIFACT_PUBLIC_BIND: ["0", "0", "0", "0"].join(".") },
    timeout: 5_000,
    encoding: "utf8",
  });
  assert.equal(wildcard.status, 1, "an all-zero bind is refused, not widened to every interface");
  assert.equal(wildcard.stderr.trim().split("\n").length, 1, "one line on stderr");
  assert.match(wildcard.stderr, /CROW_ARTIFACT_PUBLIC_BIND/);
});