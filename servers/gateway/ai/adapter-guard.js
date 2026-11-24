/**
 * THE ADAPTER GUARD: one decision, in front of every model call a provider
 * adapter makes.
 *
 * Round A taught the model DOOR (`routes/llm-router.js` `forwardDoor`), the
 * voice route (`handleChat`) and `completeText` that the URL they POST to comes
 * from a BOT-WRITABLE row (`providers.base_url`/`api_key` are plaintext and a
 * contained bot has crow.db bound read-write) and that a request which lands on
 * this host leaves the gateway as a FRESH, UNMARKED loopback socket carrying
 * whatever key the bot chose (see models/self-target.js). But the real
 * in-process voice loop (`voice/turn.js` → `ai/provider.js`
 * `createAdapterFromProfile`) and dashboard chat (`routes/chat.js`) read the
 * same rows and call the model through the provider ADAPTER, which opened its
 * own `fetch` — so the same bot could make the owner's next kiosk / glasses /
 * phone / dashboard turn POST to `http://127.0.0.1:3001/llm/acquire?x=` (the
 * appended `/chat/completions` swallowed by the query), or rebind a name to
 * 127.0.0.1, and the adapter would carry the row's key along.
 *
 * This module is that decision, ONCE, for every adapter module
 * (`adapters/{openai,anthropic,google,ollama}.js`), `ai/vision.js` and
 * `provider.js`'s `getEmbedding()` — so every model call through an adapter is
 * covered regardless of which caller asked for it. The rules are round A's,
 * reused, not re-derived:
 *
 *   a. TARGET ON THIS HOST (any port: loopback, 0.0.0.0, any of the box's own
 *      interface addresses — a providers row pointing at the host's own tailnet
 *      IP on ports 8001-8014 is own-host) is allowed ONLY at a path
 *      `isAllowedSelfPath()` accepts: an exact `/v1/<op>` or `/llm/v1/<op>`
 *      model operation, no query, no fragment. Anything else is refused BEFORE
 *      any socket opens. An own-host target never receives the row's
 *      credentials: `Authorization` / `x-api-key` / `api-key` /
 *      `x-goog-api-key` are dropped (no own-host model server needs a key, and
 *      a key is exactly what must never ride a request that lands on this box).
 *      The `speech` and `ollama` kinds have their own exact operation lists
 *      (`SELF_SPEECH_PATHS`, `SELF_OLLAMA_PATHS`); the ollama one additionally
 *      requires an own-host OLLAMA port (`isOwnHostOllamaPort`, i.e. 11434 — the
 *      bundle's fixed published port), so Ollama's native `/api/chat` and
 *      `/api/embed` reach an own-host Ollama on 11434 and NOTHING else on this
 *      box: not a local Caddy on 80/443, not a co-hosted gateway on 3001/3008,
 *      not any port a bot chose.
 *   b. A DNS-NAME target that is not `localhost`, `*.localhost` or `*.ts.net`
 *      is resolved ONCE (`pinnedTargetOf`, 2 s cap) and refused when any answer
 *      is this host, when it does not resolve, or when nothing in the answer is
 *      dialable; otherwise the socket is opened to EXACTLY the vetted
 *      address(es) (`pinnedLookup`). The host name still rides the URL, so
 *      https keeps its SNI and certificate check, and a public cloud host keeps
 *      its `Authorization`. This is the DNS-rebinding window round A closed on
 *      the other three paths.
 *   c. A FORBIDDEN ADDRESS — link-local (169.254/16, cloud metadata) or a named
 *      metadata host — is refused for EVERY caller, literal or resolved
 *      (`models/self-target.js` `isForbiddenSelfTarget`). An IP literal used to
 *      be called "not this host" and simply dialled.
 *
 * The own-host path rule is picked per call kind (`selfPathAllowed`): a model
 * call may reach a model operation, the operator's health probe may also read
 * `/v1/models`, and a SPEECH adapter may reach only the speech operations — a
 * speech profile cannot drive a chat endpoint on this box, and a chat row
 * cannot reach a speech one.
 *
 * The pinned transport is round A's `safeRequest` (node http/https, one socket,
 * never a redirect, `allowAddressFn` safe because `pinned` already passed the
 * own-host/forbidden vetting), wrapped to look like a `fetch` Response so the
 * adapters keep their streaming code unchanged: `Readable.toWeb` streams SSE
 * bytes as they arrive, never buffered. A target that needs no pinning (an IP
 * literal, `localhost`, `*.ts.net`) goes out over plain `fetch` with
 * `redirect: "manual"` — the same "a forward never follows a redirect" rule the
 * door and the voice path apply.
 *
 * Refusal is `Error` with `code: "SELF_TARGET_REFUSED"` and
 * `safe-upstream.js`'s fixed wording ("Crow will not contact that address"):
 * no new user-visible text, and the bot-written URL is never quoted back.
 */
import { Readable } from "node:stream";
import {
  pinnedTargetOf, pinnedLookup, isAllowedSelfPath, isRebindableHost,
  isAllowedSelfProbePath, isAllowedSelfSpeechPath, isAllowedSelfOllamaPath,
  isOwnHostOllamaPort,
} from "../models/self-target.js";
import { safeRequest } from "../models/safe-upstream.js";
import { LLM_CONNECT_TIMEOUT_MS } from "../../shared/http-timeout.js";

/** The refusal every adapter raises; wording is safe-upstream.js's, unchanged. */
export const SELF_REFUSED_MESSAGE = "Crow will not contact that address";

export function selfTargetRefused() {
  return Object.assign(new Error(SELF_REFUSED_MESSAGE), { code: "SELF_TARGET_REFUSED" });
}

/** Header names that carry a provider credential. Compared lower-case. */
const CREDENTIAL_HEADERS = new Set([
  "authorization", "x-api-key", "api-key", "x-goog-api-key",
  // The speech adapters' own credential headers: Azure's subscription key and
  // ElevenLabs' xi-api-key. Deepgram rides `Authorization: Token …`, which the
  // first entry already covers. A request that lands on this box carries none.
  "ocp-apim-subscription-key", "xi-api-key",
]);

/** The same headers with every credential name removed (an own-host target). */
export function withoutCredentials(headers) {
  const out = {};
  for (const [k, v] of Object.entries(headers || {})) {
    if (!CREDENTIAL_HEADERS.has(String(k).toLowerCase())) out[k] = v;
  }
  return out;
}

/** Does this header set still carry a provider credential? (tests and callers) */
export function carriesCredentials(headers) {
  return Object.keys(headers || {}).some((k) => CREDENTIAL_HEADERS.has(String(k).toLowerCase()));
}

/**
 * WHICH own-host path rule a call is judged by. `models/self-target.js` owns the
 * lists; this only picks one:
 *
 *   "model"   the default — an exact `/v1/<op>` or `/llm/v1/<op>` model call
 *   "probe"   an operator health probe: the model ops plus `/v1/models`
 *   "speech"  the speech adapters' operations only (`/v1/audio/transcriptions`,
 *             `/v1/audio/speech`, `/v1/audio/voices`, whisper.cpp's `/inference`)
 *   "ollama"  Ollama's native `/api/chat` and `/api/embed`, and ONLY on an
 *             own-host Ollama PORT (`OLLAMA_OWN_HOST_PORTS`, 11434 — the store's
 *             Ollama bundle auto-configures `http://localhost:11434`)
 *
 * A speech profile must NOT be able to drive a chat/embeddings endpoint on this
 * box and a chat row must not be able to reach a speech one, so the lists stay
 * separate rather than one wide list. Same for ollama: a chat row still refuses
 * `/api/chat` on this host, and an Ollama row reaches `/api/chat` only where an
 * own-host Ollama can be — 11434, and no other port on this box.
 *
 * `port` is the port the target would dial; `ports` is this gateway's listen
 * ports (default `gatewayListenPorts()`).
 */
export function selfPathAllowed(url, kind = "model", { port } = {}) {
  if (kind === "speech") return isAllowedSelfSpeechPath(url);
  if (kind === "probe") return isAllowedSelfProbePath(url);
  if (kind === "ollama") return isAllowedSelfOllamaPath(url) && isOwnHostOllamaPort(port);
  return isAllowedSelfPath(url);
}

/**
 * Judge a model call's full request URL against this host. Never throws.
 *
 *   { mode: "refused", target }   a forbidden address (link-local / cloud
 *                                 metadata, literal or resolved), this host at a
 *                                 path that is not one of `kind`'s operations,
 *                                 or a name that answers with this host / does not
 *                                 resolve / has no dialable answer — send nothing
 *   { mode: "own", target }       this host at an allowed operation path: plain
 *                                 fetch, credentials dropped
 *   { mode: "pinned", target, pinned }
 *                                 a rebindable name: connect to `pinned` only
 *   { mode: "direct", target }    not this host and not rebindable (an IP
 *                                 literal, localhost, *.ts.net): plain fetch
 *
 * `guard` carries the seams (all optional, all defaulting to this box):
 * `ownAddrs` (a Set of this host's addresses), `lookupFn` (a `dns.lookup`
 * shape), `ports` (this gateway's listen ports, defaulting to `gatewayListenPorts()`;
 * the own-host path rule of every kind judges ANY port — an own-host model
 * server lives on any port — except `ollama`, which requires an own-host Ollama
 * port, 11434) and `kind` (which own-host path rule applies; see
 * `selfPathAllowed`).
 */
export async function judgeAdapterTarget(url, { ownAddrs, lookupFn, kind = "model" } = {}) {
  const opts = {};
  if (ownAddrs) opts.ownAddrs = ownAddrs;
  if (lookupFn) opts.lookupFn = lookupFn;
  const target = await pinnedTargetOf(url, opts);
  // A forbidden ADDRESS is refused before anything else, for every caller:
  // pinnedTargetOf reports it for an IP literal (judged on the address) and for
  // a name whose answers are all off limits (nothing dialable is left).
  if (target.forbidden) return { mode: "refused", target };
  // A host we could NOT resolve is refused for EVERY caller too (N1), not only a
  // relayed one: the request would fail anyway, and judging nothing here would
  // leave the fetch to make the only resolution of a name we never saw. This is
  // a name the resolver did not answer for — `*.ts.net`, an arbitrary DNS name —
  // never an IP literal and never a localhost name (both are known addresses).
  if (target.unresolved) return { mode: "refused", target };
  if (target.own && !selfPathAllowed(url, kind, { port: target.port })) return { mode: "refused", target };
  if (isRebindableHost(url)) {
    if (target.own || !target.pinned) return { mode: "refused", target };
    return { mode: "pinned", target, pinned: target.pinned };
  }
  return { mode: target.own ? "own" : "direct", target };
}

/** A web ReadableStream's whole body as text (the fetch Response shape adapters use). */
async function readAllText(body) {
  if (!body) return "";
  const reader = body.getReader();
  const chunks = [];
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      chunks.push(Buffer.from(value));
    }
  } finally {
    try { reader.releaseLock(); } catch { /* already released */ }
  }
  return Buffer.concat(chunks).toString("utf8");
}

/**
 * A `safeRequest` result (`{status, headers, stream}`) as the slice of a fetch
 * Response the adapters use: `ok`, `status`, `headers.get`, `body.getReader()`
 * (incremental — the SSE bytes stream through as they arrive), `text`, `json`.
 */
export function responseFromStream(res) {
  const status = Number(res?.status);
  const nodeStream = res?.stream || null;
  const body = nodeStream ? Readable.toWeb(nodeStream) : null;
  const headerValue = (name) => {
    const v = res?.headers?.[String(name).toLowerCase()];
    return v == null ? null : Array.isArray(v) ? v.join(", ") : String(v);
  };
  return {
    ok: status >= 200 && status < 300,
    status,
    statusText: "",
    url: "",
    headers: {
      get: headerValue,
      has: (name) => res?.headers?.[String(name).toLowerCase()] != null,
    },
    body,
    text: () => readAllText(body),
    async json() { return JSON.parse(await readAllText(body)); },
  };
}

/** Is this request body a `FormData` (a multipart upload)? */
const isFormData = (b) => typeof FormData !== "undefined" && b instanceof FormData;

/**
 * The one guarded transport.
 *
 * `guard` seams: `{ ownAddrs, lookupFn, kind, requestFn, fetchFn }` — the
 * adapter config may carry them (`config.guard`) so tests can inject this
 * host's addresses, a resolver and a transport; production passes none.
 * `timeoutMs` is the connect budget for the PINNED transport (default: the LLM
 * connect timeout; the speech / embedding callers pass their own).
 */
export async function guardedFetch(url, { method = "POST", headers = {}, body, signal, timeoutMs, guard = {} } = {}) {
  const decision = await judgeAdapterTarget(url, guard);
  if (decision.mode === "refused") throw selfTargetRefused();
  // Never the row's key on a request that lands on this box.
  const sendHeaders = decision.mode === "own" ? withoutCredentials(headers) : headers;
  if (decision.mode === "pinned") {
    // A rebindable name: safeRequest opens the socket to the EXACT addresses
    // vetted above (pinnedLookup), never to a second answer for the name.
    // allowAddressFn is safe: `pinned` already passed the own-host/forbidden
    // vetting. idleTimeoutMs 0: once the headers are in, a quiet SSE stream is
    // not a failure (the same shape fetch has).
    const pinnedHeaders = { ...sendHeaders };
    let requestBody = body;
    if (isFormData(body)) {
      // safeRequest writes a string or a Buffer; a multipart upload (the speech
      // adapters' audio) is encoded ONCE here, with the boundary in its own
      // content-type.
      const encoded = new Response(body);
      requestBody = Buffer.from(await encoded.arrayBuffer());
      if (!Object.keys(pinnedHeaders).some((h) => h.toLowerCase() === "content-type")) {
        pinnedHeaders["Content-Type"] = encoded.headers.get("content-type") || "multipart/form-data";
      }
    }
    const requestFn = guard.requestFn || safeRequest;
    const res = await requestFn(url, {
      method, headers: pinnedHeaders, body: requestBody, signal,
      timeoutMs: timeoutMs ?? LLM_CONNECT_TIMEOUT_MS, idleTimeoutMs: 0,
      lookupFn: pinnedLookup(decision.pinned), allowAddressFn: () => true,
    });
    return responseFromStream(res);
  }
  const fetchFn = guard.fetchFn || fetch;
  // NO REDIRECTS: a 3xx comes back as an !ok status, exactly as it does on the
  // door and the voice path.
  return fetchFn(url, { method, headers: sendHeaders, body, signal, redirect: "manual" });
}

/**
 * The SAME decision for a WebSocket CONNECT (Deepgram's live stream).
 *
 * A `ws://` / `wss://` URL is judged with the same `kind`'s own-host path rule
 * and the same forbidden/pinning rules; a refused or own-host target throws the
 * one fixed refusal (a live socket to a speech route on this box is not one of
 * the reviewed operations), and a rebindable name answers `{ lookup }` — the
 * `ws` package hands that to node's socket, so the handshake goes to the vetted
 * address and never to a second answer for the name.
 */
export async function guardSocketTarget(url, guard = {}) {
  const decision = await judgeAdapterTarget(url, guard);
  if (decision.mode === "refused" || decision.mode === "own") throw selfTargetRefused();
  return decision.mode === "pinned" ? { lookup: pinnedLookup(decision.pinned) } : {};
}