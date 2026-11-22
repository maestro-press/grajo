/**
 * A fake OAuth 2.0 token endpoint for Crow Mail's provider calls (servers/gateway/mail/oauth/flow.js),
 * served over a real HTTP server on loopback so the code under test uses the real `fetch`, the real
 * form encoding and the real timeout — never the internet.
 *
 * It understands one shape of path, a POST ending in `/token` (so `/token` and Microsoft's
 * `/common/oauth2/v2.0/token` both land here) and both grant types Crow sends
 * (`authorization_code` and `refresh_token`). Each request's parsed form, and the path it was sent to,
 * is recorded in `fake.requests`, so a test can prove what was sent (the verifier was there, the
 * client secret was not, the tenant was substituted).
 *
 * Answers come from a queue: `fake.queueResponse({...})` pushes one for the next request, and when the
 * queue is empty the default answer follows the grant type — a success with a fresh access token, and a
 * refresh token only for an authorization_code grant (so a plain refresh does not rotate). A queued
 * response is how a test asks for:
 *
 *   - a success without a refresh token, or a rotated one: `body: { access_token, expires_in, refresh_token }`
 *   - a refusal: `{ status: 400, body: { error: "invalid_grant" } }`, `... "invalid_client"`
 *   - a server fault: `{ status: 500, body: { error: "server_error" } }`
 *   - a slow answer: `{ delayMs: 2000, ... }`
 *   - a body that echoes the request, which is what a real OAuth server does in
 *     `error_description`: `body: (form) => ({ error: "invalid_request",
 *     error_description: `code ${form.code} secret ${form.client_secret}` })`
 *   - silence: `{ hang: true }` — the request is accepted and never answered, so only the caller's
 *     own timeout can end it.
 *   - headers and then silence: `{ headersThenHang: true }` — the ANSWER LINE arrives and the body never
 *     does, which is the case a caller's timeout has to cover while reading the body, not only while
 *     waiting for the headers.
 *   - an answer the test releases later: `{ hold: true, ... }` — the request is recorded and parked, and
 *     `fake.releaseHeld()` sends the queued answer when the test is ready. That is how a test keeps a
 *     refresh observably in flight and then decides what it answers.
 *
 * Usage:
 *   const fake = await startFakeOAuthProvider();
 *   fake.tokenUrl;                                  // "http://127.0.0.1:<port>/token"
 *   fake.baseUrl;                                   // "http://127.0.0.1:<port>"
 *   await exchangeCode({ ..., endpoints: { tokenUrl: fake.tokenUrl } });
 *   fake.requests;                                  // [{ path, method, form, raw }]
 *   fake.releaseHeld();                             // send every `{ hold: true }` answer now
 *   await fake.close();                             // in an `after` hook; destroys hung sockets
 */
import http from "node:http";

/** A token endpoint path: `/token`, or a tenant-prefixed one such as `/common/oauth2/v2.0/token`. */
const TOKEN_PATH = /(^|\/)token$/;

function readBody(req) {
  return new Promise((resolvePromise, reject) => {
    const chunks = [];
    req.on("data", (chunk) => chunks.push(chunk));
    req.on("end", () => resolvePromise(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

/**
 * Start the fake provider on 127.0.0.1 with an OS-assigned port.
 *
 * @param {object} [options]
 * @param {string} [options.host] loopback by default; never a routable address
 * @returns {Promise<{
 *   tokenUrl: string, baseUrl: string,
 *   requests: Array<{path: string, method: string, form: object, raw: string}>,
 *   queueResponse: (response: object) => void, close: () => Promise<void>,
 * }>}
 */
export async function startFakeOAuthProvider({ host = "127.0.0.1" } = {}) {
  /** Every request, in order: what was asked for, exactly as it was encoded. */
  const requests = [];
  /** Queued answers; each is { status?, body?, delayMs?, hang? }. */
  const queue = [];
  /** Sockets kept open by a `hang` response, so `close()` can end them. */
  const hung = new Set();
  /** Answers parked by `{ hold: true }`, in request order, waiting for `releaseHeld()`. */
  const held = [];

  /** The answer when the queue is empty: a success, with a refresh token only for a code grant. */
  function defaultBody(form) {
    if (form.grant_type === "authorization_code") {
      return { access_token: "fake-access-token", expires_in: 3600, token_type: "Bearer", refresh_token: "fake-refresh-token" };
    }
    return { access_token: "fake-access-token-refreshed", expires_in: 3600, token_type: "Bearer" };
  }

  function send(res, response, form) {
    const status = Number.isInteger(response.status) ? response.status : 200;
    const given = typeof response.body === "function" ? response.body(form) : response.body;
    const body = given === undefined ? defaultBody(form) : given;
    const text = typeof body === "string" ? body : JSON.stringify(body ?? {});
    res.writeHead(status, {
      "content-type": typeof body === "string" ? "text/plain; charset=utf-8" : "application/json",
      "content-length": Buffer.byteLength(text),
      // A real provider never lets a token response be cached.
      "cache-control": "no-store",
    });
    res.end(text);
  }

  const server = http.createServer(async (req, res) => {
    const url = new URL(req.url ?? "/", `http://${host}`);
    const method = String(req.method ?? "GET").toUpperCase();
    const raw = method === "POST" ? await readBody(req) : "";
    const form = Object.fromEntries(new URLSearchParams(raw));
    requests.push({ path: url.pathname, method, form, raw });

    if (method !== "POST" || !TOKEN_PATH.test(url.pathname)) {
      res.writeHead(404, { "content-type": "application/json" });
      res.end(JSON.stringify({ error: "not_found" }));
      return;
    }

    const response = queue.shift() ?? {};
    if (response.hang) {
      // Accepted and never answered: only the caller's own timeout can end this.
      const socket = res.socket;
      if (socket) {
        hung.add(socket);
        socket.once("close", () => hung.delete(socket));
      }
      return;
    }
    if (response.headersThenHang) {
      // The status line and headers go out and the body never follows: a caller that reads the body is
      // waiting on a server that has stopped talking, and only its own abort can end that wait.
      res.writeHead(200, { "content-type": "application/json", "content-length": 256 });
      res.flushHeaders?.();
      const socket = res.socket;
      if (socket) {
        hung.add(socket);
        socket.once("close", () => hung.delete(socket));
      }
      return;
    }
    if (response.hold) {
      // Parked until `releaseHeld()`: the request is recorded, the caller is waiting, and the test
      // decides what (if anything) the answer is.
      held.push({ res, response, form });
      return;
    }
    if (Number.isInteger(response.delayMs) && response.delayMs > 0) {
      setTimeout(() => { if (!res.writableEnded) send(res, response, form); }, response.delayMs).unref();
      return;
    }
    send(res, response, form);
  });

  const port = await new Promise((resolvePromise, reject) => {
    server.once("error", reject);
    server.listen(0, host, () => resolvePromise(server.address().port));
  });

  return {
    tokenUrl: `http://${host}:${port}/token`,
    baseUrl: `http://${host}:${port}`,
    requests,
    /** Queue the answer to the next request (see the header for the shapes). */
    queueResponse: (response) => { queue.push(response); },
    /** Send every parked `{ hold: true }` answer now, oldest first. */
    releaseHeld: () => {
      for (const entry of held.splice(0)) {
        if (!entry.res.writableEnded) send(entry.res, entry.response, entry.form);
      }
    },
    close: () => new Promise((resolvePromise) => {
      for (const entry of held.splice(0)) { try { entry.res.destroy(); } catch { /* gone */ } }
      for (const socket of hung) socket.destroy();
      hung.clear();
      server.closeAllConnections?.();
      server.close(() => resolvePromise());
    }),
  };
}