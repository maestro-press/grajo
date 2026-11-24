/**
 * "Is this URL my own gateway?" — the one question a forward may never leave to
 * the socket it opens (confused deputy, security review 2026-11).
 *
 * The rules here are EVERY caller's, not only a relayed one: the operator's own
 * voice turn and a background job (`completeText`) read the same bot-writable
 * row, so `isAllowedSelfPath`/`isAllowedSelfForward` gate the door forward, the
 * voice path and `completeText` alike, and `pinnedTargetOf` resolves a NAME target
 * ONCE, reporting BOTH the answer a rebindable name must be pinned to (`pinned`)
 * and the ordered answers an own-host name may be dialled at (`dialAnswers`). The
 * own-host vouch judges those IN ORDER and names the ONE it accepted
 * (`isKnownLocalModelTarget`'s `address`, carried by `dialAt`), and that literal is
 * what the socket is opened to, on the door,
 * the voice path, `completeText` and every adapter (`ai/adapter-guard.js`): a name
 * is one address here, never two resolutions. Only the extra narrowing (a
 * rebindable name refused outright, a name that does not resolve, `/llm/v1` on
 * our own port only, the peer relay's name/query rule) is asked of a relayed
 * caller.
 *
 * Two more rules live here because they are the same question, asked of the same
 * rows, and every caller needs them:
 *   - `isForbiddenSelfTarget` — link-local (169.254/16, cloud metadata) and the
 *     named metadata hosts are refused on the ADDRESS, literal or resolved, for
 *     everyone (the door already did this for every provider row; a forward path
 *     that only looked at names dialled an IP-literal metadata endpoint);
 *   - `isAllowedSelfProbePath` / `isAllowedSelfSpeechPath` — the own-host path
 *     rule for the two callers that are not model calls: the operator's provider
 *     health probe (`/v1/models`) and the speech adapters' audio operations.
 *
 * The gateway re-sends a request to a URL that a request-triggered read took
 * from a BOT-WRITABLE row: `providers` (base_url, api_key and gpu_policy are
 * plaintext, and a contained bot has crow.db bound read-write) and
 * `crow_instances` (gateway_url, written through instance sync). A forward whose
 * target is this box on the gateway's own listen port leaves the gateway as a
 * FRESH, UNMARKED loopback socket carrying whatever bearer the bot chose — the
 * egress relay's mark (isRelayedSocket, servers/shared/bot-doors.js) is gone, so
 * every "a relayed socket never authenticates as the owner" rule is bypassed in
 * one hop. That is how a bot reaches `/llm/models/<m>/start`, the kiosk's
 * announce routes, `/api/reload-backends`, `/relay/store`, the storage HTTP API
 * or `/llm/acquire`: none of them is a bot door, and all of them are loopback
 * work a bot may not do.
 *
 * The predicate is deliberately about ADDRESSES, never strings:
 *   - loopback (127/8, ::1, any v4-mapped spelling) and the unspecified address
 *     (0.0.0.0, ::) are this host;
 *   - every one of this host's OWN interface addresses is this host — the
 *     gateway binds 0.0.0.0, so `http://<tailnet-ip>:3001` and
 *     `http://<lan-ip>:3001` answer on the gateway exactly as 127.0.0.1 does;
 *   - a NAME is resolved first (localhost, the host's own names, *.ts.net
 *     MagicDNS). A name that does not resolve is not this gateway: the forward
 *     then fails on its own (502), never on our say-so.
 * An on-link NEIGHBOUR is deliberately NOT this host: a paired peer's gateway
 * on the LAN or the tailnet listens on the same port and is somebody else's to
 * answer. That is also why `isOwnNetworkIp` (which includes on-link prefixes) is
 * not enough on its own here.
 *
 * A FORWARD's target is judged by `ownTargetOf` alone, never by a port list:
 * co-hosted sibling gateways exist (crow on :3001 and crow-r4 on :3008 on the
 * same box, possibly others), so "this host on a port I listen on" is neither
 * necessary nor sufficient. `own` ("is this host at all, any port") is what the
 * credential rule (never attach a provider's api_key to a forward that lands on
 * this box), the peer relay and `isAllowedSelfPath` use.
 *
 * `ports` is the set of ports this gateway listens on (`gatewayListenPorts`), so
 * `self` still answers "this gateway's own door" where that exact question is
 * asked. It is never the boundary for a relayed forward any more.
 *
 * `resolved`/`unresolved` report a host we could NOT judge: a name the resolver
 * did not answer for (timeout, throw, NXDOMAIN). `unresolved` is distinct from
 * "not this host" on purpose — a relayed caller must fail closed on it, because
 * our lookup and the fetch's own lookup are two resolutions of the same name
 * (DNS rebinding). An unparseable URL is `resolved: false, unresolved: false`:
 * it cannot be this host, and the fetch itself then fails.
 */
import { isIP } from "node:net";
import dns from "node:dns";
import { ownAddresses, addressRefused } from "./safe-upstream.js";
import { gatewayPort } from "./door.js";
import { classifyIp } from "../../shared/ip-classify.js";
import { isForbiddenTarget } from "./door-resolve.js";

/** The ports this gateway listens on: the same env door.js reads (PORT, else
 *  CROW_GATEWAY_PORT, else 3001), so a co-hosted second instance (:3008) judges
 *  its OWN door. */
export function gatewayListenPorts(env = process.env) {
  return new Set([gatewayPort(env)]);
}

/**
 * The ports an own-host OLLAMA server may be reached on, and the whole of the
 * port half of the Ollama allowance (`isAllowedSelfOllamaPath` judges the path).
 *
 * It matches `bundles/ollama/docker-compose.yml`, which publishes exactly
 * `127.0.0.1:11434:11434` — FIXED, not configurable (the bundle's `OLLAMA_HOST`
 * is a full URL setting, `routes/bundles.js` `getAiProviderConfig`, not a port
 * option), so there is no such thing as an operator-chosen Ollama port. If the
 * bundle ever makes its port configurable, this list must be read from there.
 *
 * An ALLOW-list, not a deny-list of gateway ports: any OTHER own-host port —
 * 80/443 behind a local Caddy, a co-hosted gateway on 3001/3008, an
 * undocumented port, a service a bot chose — is refused for this kind, because
 * Ollama is the only native `/api/...` server Crow itself puts on this box.
 */
export const OLLAMA_OWN_HOST_PORTS = Object.freeze([11434]);

/** Is `port` one an own-host Ollama may be reached on? Judged on the PORT; a
 *  missing/unknown port fails closed. */
export function isOwnHostOllamaPort(port) {
  const n = Number(port);
  if (!Number.isInteger(n) || n <= 0) return false;
  return OLLAMA_OWN_HOST_PORTS.includes(n);
}

/** Loopback or the unspecified address, in any spelling. */
const LOOPBACKISH = new Set(["loopback", "unspecified"]);

/** Names that always mean this host, before any DNS is asked (RFC 6761). */
const LOOPBACK_NAMES = new Set(["localhost", "ip6-localhost", "ip6-loopback", "localhost.localdomain"]);

/** A URL's host for comparison: brackets off, zone off, lower-case, one
 *  trailing dot off. `null` when the URL does not parse. */
export function targetHost(url) {
  let h;
  try { h = new URL(String(url)).hostname; } catch { return null; }
  let x = String(h || "").replace(/^\[|\]$/g, "").replace(/%.*$/, "").toLowerCase();
  if (x.endsWith(".")) x = x.slice(0, -1);
  return x || null;
}

/** The URL's port as a number (80/443 by scheme, as the socket would). */
export function targetPort(url) {
  let u;
  try { u = new URL(String(url)); } catch { return null; }
  const p = Number(u.port || (u.protocol === "https:" ? 443 : 80));
  return Number.isFinite(p) && p > 0 ? p : null;
}

/**
 * Is this ADDRESS this host? Loopback, the unspecified address, or one of the
 * box's own interface addresses (docker/bridge ones included: the gateway binds
 * 0.0.0.0 and answers there too). `ownAddrs` is a Set of addresses (tests pass
 * their own); it defaults to `ownAddresses()` in safe-upstream.js, which is
 * loopback names plus every interface.
 */
export function isOwnHostAddress(address, ownAddrs = ownAddresses()) {
  const a = String(address ?? "").replace(/^\[|\]$/g, "").replace(/%.*$/, "").trim().toLowerCase();
  if (!a) return false;
  const { cls, v4 } = classifyIp(a);
  if (LOOPBACKISH.has(cls)) return true;
  if (ownAddrs.has(a)) return true;
  // "::ffff:100.64.20.1" and friends compare as the IPv4 they carry.
  return v4 != null && ownAddrs.has(v4);
}

/**
 * Every address `host` names, as `[{address, family}]`, or [] when it cannot be
 * resolved. An IP literal needs no lookup.
 *
 * THE 2 s CAP. A NAME target is resolved with a 2 s deadline (a resolver that
 * hangs must not stall a voice turn or a scheduled job), and every caller that
 * connects reuses THIS ONE answer — `pinnedTargetOf`'s `dial` — because a second
 * resolution of the same name is exactly the rebinding window this file exists to
 * close. A lookup that throws or answers nothing is [] (the caller's
 * `unresolved`), never a silent "not this host".
 */
/** Is this host a name that always means this host (RFC 6761)? */
function isLoopbackName(host) {
  return LOOPBACK_NAMES.has(host) || String(host || "").endsWith(".localhost");
}

/** Ask the resolver ONCE, with the 2 s cap: `[{address, family}]`, [] when it
 * throws or answers nothing. */
async function resolveOnce(host, lookupFn) {
  try {
    const answer = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => resolve(null), 2000);
      try {
        lookupFn(host, { all: true }, (err, list) => { clearTimeout(timer); if (err) return reject(err); return resolve(list); });
      } catch (err) { clearTimeout(timer); reject(err); }
    });
    if (!answer) return [];
    return (Array.isArray(answer) ? answer : [answer])
      .map((x) => (typeof x === "string" ? { address: x, family: isIP(x) } : x))
      .filter((x) => x && typeof x.address === "string" && x.address)
      .map((x) => ({ address: x.address, family: x.family ?? isIP(x.address) }));
  } catch {
    return [];
  }
}

async function lookupAll(host, lookupFn) {
  if (isIP(host)) return [{ address: host, family: isIP(host) }];
  const answers = await resolveOnce(host, lookupFn);
  if (!isLoopbackName(host)) return answers;
  // A LOOPBACK NAME is loopback whatever the resolver says (RFC 6761: `localhost`
  // is 127.0.0.1 and ::1). Only ITS loopback answers are kept — a host file that
  // points the name elsewhere cannot move "this host" — and a resolver with no
  // entry for it falls back to the RFC 6761 pair. It is asked at all because a
  // caller connects to ONE literal (`pinnedTargetOf`'s `dial`), and which one it
  // dials must be the one that was judged.
  const loopback = answers.filter((a) => classifyIp(a.address).cls === "loopback");
  if (loopback.length) return loopback;
  return [{ address: "127.0.0.1", family: 4 }, { address: "::1", family: 6 }];
}

/** Every address `host` names, or [] when it cannot be resolved. */
async function addressesOf(host, lookupFn) {
  return (await lookupAll(host, lookupFn)).map((x) => x.address);
}

/** Every address a target URL names — the list `ownTargetOf` judges — as
 * `[{address, family}]`, or [] when the host cannot be resolved. Same resolver
 * seam and the same 2 s cap; used by callers that must know WHICH address a name
 * stood for (an address-and-port vouch, models/local-model-servers.js). */
export async function targetAddresses(url, { lookupFn = dns.lookup } = {}) {
  const host = targetHost(url);
  if (!host) return [];
  return (await lookupAll(host, lookupFn)).map((x) => ({ address: x.address, family: x.family ?? isIP(x.address) }));
}

/**
 * Resolve a target URL against this host once: `{ own, self, port, resolved,
 * unresolved }`.
 *   own         the URL names this host (loopback, 0.0.0.0, or one of its own
 *               interface addresses; a name is resolved first)
 *   port        the port it would dial
 *   resolved    we judged the host (an IP literal, a loopback name, or a name
 *               the resolver answered for)
 *   unresolved  the host is a NAME the resolver did not answer for: we cannot
 *               say whether it is this host. A relayed caller refuses on this.
 * `self` is additionally true when that port is one of `ports` (default: this
 * gateway's own listen ports; `ports: null` asks about any port).
 * Never throws: an unparseable URL is not this gateway (the forward fails on its
 * own).
 */
export async function ownTargetOf(url, { ports = gatewayListenPorts(), ownAddrs = ownAddresses(), lookupFn = dns.lookup } = {}) {
  const host = targetHost(url);
  const port = targetPort(url);
  if (!host || port == null) return { own: false, self: false, port, resolved: false, unresolved: false };
  const addrs = await addressesOf(host, lookupFn);
  if (!addrs.length) return { own: false, self: false, port, resolved: false, unresolved: true };
  const own = addrs.some((a) => isOwnHostAddress(a, ownAddrs));
  const self = own && (ports == null ? true : ports.has(port));
  return { own, self, port, resolved: true, unresolved: false };
}

/**
 * Resolve a target ONCE and say where the socket must be opened.
 *
 * This is `ownTargetOf`'s judgement PLUS the two statements a forward needs:
 * `pinned` (a rebindable NAME's vetted answer) and `dial` (the ONE literal a NAME
 * stands for). Four callers use it — the model door (`forwardDoor`), the voice
 * path (`handleChat`), `completeText` and the adapter guard — because the target
 * comes from a bot-writable row (`providers`), and judging a name and then letting
 * the fetch resolve it again is the rebinding window.
 *
 *   - an IP LITERAL is already the address the socket opens to: no lookup, no
 *     `dial` (the URL carries it), and `forbidden` says whether that class is off
 *     limits (link-local / cloud metadata). Before this, a literal
 *     `169.254.169.254` was simply "not this host" and the caller dialled it;
 *   - a NAME (a loopback name included: `localhost` is 127.0.0.1 AND ::1) is
 *     resolved once (2 s cap, `lookupAll`), and `dialAnswers` is EVERY answer in
 *     resolver order. The caller hands that list to the own-host vouch, which judges
 *     them in order and answers with the first one that is a known model server; it
 *     then connects to THAT address with `pinnedLookup`, so no second resolution
 *     happens and the address dialled is an address judged. `dial` stays the first
 *     answer (the shape a caller with no vouch to ask uses); a loopback name's
 *     answers are its loopback addresses;
 *   - if ANY answer is this host (`isOwnHostAddress`) the target is own-host and
 *     never pinned (`pinned: null`), and if none is left dialable (link-local,
 *     cloud metadata, unspecified, multicast) `forbidden` says so;
 *   - otherwise `pinned` is the first vetting address (with the whole vetted set
 *     in `addresses`), and the host name still rides the URL, so https keeps its
 *     SNI and certificate check.
 *
 * Never throws: an unparseable URL is not this gateway (the request fails on its
 * own), and a name nobody answers for is `unresolved`.
 */
export async function pinnedTargetOf(url, { ports = gatewayListenPorts(), ownAddrs = ownAddresses(), lookupFn = dns.lookup } = {}) {
  const host = targetHost(url);
  const port = targetPort(url);
  if (!host || port == null) return { own: false, self: false, port, resolved: false, unresolved: false, pinned: null, forbidden: false, dial: null, dialAnswers: [] };
  if (isIP(host)) {
    // An IP LITERAL is the address itself: `forbidden` says whether the address
    // class is off limits (link-local / cloud metadata) and there is nothing to
    // resolve or to pin.
    const own = isOwnHostAddress(host, ownAddrs);
    const self = own && (ports == null ? true : ports.has(port));
    return { own, self, port, resolved: true, unresolved: false, pinned: null, forbidden: isForbiddenSelfTarget(url), dial: null, dialAnswers: [] };
  }
  const answers = await lookupAll(host, lookupFn);
  if (!answers.length) return { own: false, self: false, port, resolved: false, unresolved: true, pinned: null, forbidden: false, dial: null, dialAnswers: [] };
  const own = answers.some((a) => isOwnHostAddress(a.address, ownAddrs));
  const self = own && (ports == null ? true : ports.has(port));
  // EVERY answer, in resolver order, with the family the socket needs: the caller
  // judges them in order (the own-host vouch) and dials the first it accepted.
  const listed = answers.map((a) => ({ address: a.address, family: a.family ?? isIP(a.address) }));
  if (own) return { own, self, port, resolved: true, unresolved: false, pinned: null, forbidden: false, dial: { ...listed[0] }, dialAnswers: listed };
  const dialable = answers.filter((a) => !addressRefused(a.address, { mode: "other", ownAddrs }));
  // The whole vetted set rides along: a dual-stack host must still be able to try
  // its other vetted address (Happy Eyeballs asks for `all`), and none of them is a
  // second resolution of the name.
  const pinned = dialable.length ? { ...dialable[0], addresses: dialable } : null;
  return { own, self, port, resolved: true, unresolved: false, pinned, forbidden: dialable.length === 0, dial: pinned ? { address: pinned.address, family: pinned.family } : null, dialAnswers: [] };
}

/**
 * WHERE THE SOCKET OPENS for a NAME target, once the own-host vouch has spoken.
 *
 * `pinnedTargetOf` hands over EVERY answer the name stood for (`dialAnswers`), but
 * it cannot know which of them is a model server. The vouch can
 * (`models/local-model-servers.js` `isKnownLocalModelTarget`): it judges them IN
 * ORDER and answers with the ONE address that passed. That address — never the
 * name's first answer by assumption — is what the transport is pinned to
 * (`pinnedLookup`), so the judged address is the dialled one, and a dual-stack
 * `localhost` whose ::1 has nothing listening still reaches a server bound to
 * 127.0.0.1.
 */
export function dialAt(verdict, fallback = null) {
  const address = verdict && typeof verdict.address === "string" && verdict.address ? verdict.address : null;
  if (!address) return fallback || null;
  const family = isIP(address);
  return family ? { address, family } : { address };
}

/** A `lookup` for http.request that always answers the address(es) a target was
 *  pinned to (see `pinnedTargetOf`), whatever name it is asked about. */
export function pinnedLookup({ address, family, addresses } = {}) {
  const list = Array.isArray(addresses) && addresses.length
    ? addresses.map((a) => ({ address: a.address, family: a.family ?? isIP(a.address) }))
    : [{ address, family: family ?? isIP(address) }];
  return function lookup(_hostname, options, callback) {
    if (typeof options === "function") { callback = options; options = {}; }
    const opts = typeof options === "number" ? { family: options } : (options || {});
    if (opts.all) return callback(null, list);
    return callback(null, list[0].address, list[0].family);
  };
}

/** Is this URL this host at all, on any port? */
export async function isOwnHostTarget(url, opts = {}) {
  return (await ownTargetOf(url, { ...opts, ports: null })).own;
}

/** Is this URL this gateway (this host, on a port it listens on)? */
export async function isSelfTarget(url, opts = {}) {
  return (await ownTargetOf(url, opts)).self;
}

/**
 * THE PATH RULE for a forward that lands on this host (relayed or not).
 *
 * A port list cannot say "this machine" any more: co-hosted sibling gateways
 * exist (crow :3001 and crow-r4 :3008 on one box), so "own host on a port I do
 * not listen on" is still this box's own loopback work. What a forward may
 * legitimately do here is narrow and known, so the path decides:
 *
 *   /v1/<op>        a native / bundle / external-engine model server's own port
 *                   (the row's base_url ends in /v1)
 *   /llm/v1/<op>    this gateway's own model door, which is a bot door already
 *                   (`/llm/v1/` is in BOT_DOOR_PREFIXES, servers/shared/
 *                   bot-doors.js), so a bot may call it directly with no bearer
 *                   at all — forwarding to it (a provider row such as `crow-llm`,
 *                   base_url `http://localhost:3001/llm/v1`) grants nothing it
 *                   did not have
 * with <op> in SELF_PATH_OPS, and NO query string and NO fragment.
 *
 * The query rule is the load-bearing half: `${base}/chat/completions` turns a
 * base_url of `http://127.0.0.1:3001/llm/models/m/start?x=` into a POST to the
 * model START route (the appended operation is swallowed by the query).
 * Percent-escapes and dot segments are refused rather than reasoned about: a
 * path a later layer could decode into another route is not this operation.
 *
 * Everything else on this host is off limits to a forward: /llm/models/<m>/start,
 * /llm/acquire, /llm/p/<id>/v1/…, the cloud door, the kiosk announce routes,
 * /relay/store, the storage API and the dashboard.
 */
export const SELF_PATH_OPS = Object.freeze(["chat/completions", "completions", "embeddings", "rerank"]);

/**
 * The ONE MORE operation a health PROBE may run on this host.
 *
 * `servers/shared/providers.js` `probeProvider` (the Models page's Test button
 * and the health tab) GETs `${base_url}/models` with the row's `api_key`, and a
 * provider row is bot-writable, so that probe is a request-time read of the
 * same row as every forward. It is not a model call, so it gets its own tiny
 * rule rather than widening `SELF_PATH_OPS` for chat/door forwards: a probe may
 * reach `/v1/models` (or `/llm/v1/models`) on this host and nothing else, and
 * never with a credential.
 */
export const SELF_PROBE_PATH_OPS = Object.freeze([...SELF_PATH_OPS, "models"]);

/**
 * THE SPEECH OPERATIONS an own-host STT/TTS server may be driven at.
 *
 * The speech adapters (`ai/stt/adapters/*`, `ai/tts/adapters/*`) send audio to
 * a profile's base URL, which lives in bot-writable `dashboard_settings`, so an
 * own-host target is judged by the FINAL request URL each adapter builds — and
 * only these operations are allowed:
 *
 *   POST /v1/audio/transcriptions   faster-whisper, openai, groq (`<base>/v1`)
 *   POST /v1/audio/speech           kokoro (its base may already end in /v1)
 *   GET  /v1/audio/voices           kokoro's voice list
 *   POST /inference                 whisper.cpp's own server
 *
 * These are EXACT paths, not a suffix: an own-host target allows these four and
 * nothing else. A hosted profile base such as groq's `/openai/v1` is not on this
 * host and never reaches this rule; the same shape pointed at a loopback server
 * is refused (`/openai/v1/audio/transcriptions` is not `/v1/audio/transcriptions`),
 * so a bot-written profile cannot drive an arbitrary path on this box by naming
 * a base that happens to end in a speech operation. A credential is never sent
 * to an own-host speech server (see `adapter-guard.js` `withoutCredentials`).
 */
export const SELF_SPEECH_PATHS = Object.freeze([
  "/v1/audio/transcriptions", "/v1/audio/speech", "/v1/audio/voices", "/inference",
]);

/**
 * THE OLLAMA OPERATIONS an own-host Ollama server may be driven at, for the
 * Ollama adapter and the Ollama embedding path ONLY (`kind: "ollama"`).
 *
 * The store's Ollama bundle auto-configures provider "ollama" at
 * `http://localhost:11434` (`routes/bundles.js` `getAiProviderConfig`), so the
 * rule every other own-host target obeys (only `/v1/<op>`, `/llm/v1/<op>`) would
 * refuse that install's very first turn: Ollama's native API is `/api/chat`
 * (the adapter) and `/api/embed` (`ai/provider.js` `getEmbedding`). They are
 * allowed EXACTLY and only when the target's PORT is one an own-host Ollama can
 * be on (`OLLAMA_OWN_HOST_PORTS`, i.e. 11434 — the bundle's fixed published
 * port). Every other own-host port is refused for this kind: 80/443 behind a
 * local Caddy, a co-hosted gateway's 3001/3008, any port a bot chose.
 * A credential never rides these either (`adapter-guard.js`
 * `withoutCredentials`), and the path is exact — no query, no fragment, no
 * escapes, no dot segments (`safePathname`) — so a base that ends in one of
 * these cannot address a deeper route.
 *
 * `/api/tags` is deliberately NOT here: no Crow code calls it (the Ollama
 * bundle's skill documents it for a person curling the server), and a list of
 * reviewed operations is only as wide as the code that uses it.
 */
export const SELF_OLLAMA_PATHS = Object.freeze(["/api/chat", "/api/embed"]);

/** The pathname of `url`, or null when it is not a safe path to judge at all
 *  (unparseable, a query, a fragment, an escape or a dot segment). */
function safePathname(url) {
  let u;
  try { u = new URL(String(url)); } catch { return null; }
  // A query string or a fragment is never part of an operation path.
  if (u.search || u.hash) return null;
  const p = u.pathname;
  if (p.includes("%") || p.includes("..") || p.includes("//") || p.includes("\\")) return null;
  return p;
}

const OP_RULES = new Map();

/** `^/(llm/)?v1/<op>/?$` for a list of operations, built once per list. */
function opRule(ops) {
  const key = ops.join("|");
  let re = OP_RULES.get(key);
  if (!re) {
    re = new RegExp(`^/(?:llm/)?v1/(?:${ops.map((op) => op.split("/").join("\\/")).join("|")})/?$`, "i");
    OP_RULES.set(key, re);
  }
  return re;
}

function allowedOpPath(url, ops) {
  const p = safePathname(url);
  return p != null && opRule(ops).test(p);
}

/** Is this URL one of the operations a forward may run against this host? */
export function isAllowedSelfPath(url) {
  return allowedOpPath(url, SELF_PATH_OPS);
}

/** May an operator health probe run here? (`/v1/models` and the model ops.) */
export function isAllowedSelfProbePath(url) {
  return allowedOpPath(url, SELF_PROBE_PATH_OPS);
}

/** Is this URL one of the operations an own-host SPEECH server may be driven at?
 *  Exact pathname equality only (a trailing slash tolerated, as `isAllowedSelfPath`
 *  does): a deeper or shallower path is a different route on this box. */
export function isAllowedSelfSpeechPath(url) {
  const p = safePathname(url);
  if (p == null) return false;
  return SELF_SPEECH_PATHS.includes(p.toLowerCase().replace(/\/+$/, ""));
}

/** Is this URL one of the OLLAMA operations an own-host Ollama server may be
 *  driven at? Exact pathname equality only (a trailing slash tolerated), the
 *  same shape `isAllowedSelfSpeechPath` uses. The PORT half of the rule is the
 *  caller's (`adapter-guard.js` `selfPathAllowed`, with `isOwnHostOllamaPort`). */
export function isAllowedSelfOllamaPath(url) {
  const p = safePathname(url);
  if (p == null) return false;
  return SELF_OLLAMA_PATHS.includes(p.toLowerCase().replace(/\/+$/, ""));
}

/**
 * FORBIDDEN TARGETS, for EVERY caller.
 *
 * `isForbiddenTarget` (door-resolve.js) is the one address-class rule: IPv4
 * link-local (169.254/16, cloud metadata included), IPv6 link-local (fe80::/10)
 * and the named metadata hosts (`metadata.google.internal`, `100.100.100.200`,
 * the 100.100.100.100 wireguard-metadata address, …), judged on the LITERAL
 * host so it costs no lookup. It is the rule the DOOR already applied to every
 * provider row; the forward paths and the adapter guard applied it only to a
 * relayed caller or to a name whose answer happened to be filtered, so an
 * IP-literal `http://169.254.169.254/v1` went out.
 *
 * A target that does not parse is NOT forbidden here: this rule is about
 * addresses, and an unparseable URL fails on its own (`isForbiddenTarget` says
 * `true` for it, which would turn a malformed row into this refusal).
 */
export function isForbiddenSelfTarget(url) {
  try { new URL(String(url)); } catch { return false; }
  return isForbiddenTarget(url);
}

/**
 * Is this URL's host a DNS NAME that a relayed caller's forward must not be
 * rebound through?
 *
 * True for a name that is neither an IP literal nor a name that always means a
 * local/tailnet address (`localhost`, any `*.localhost`, `*.ts.net`). The model
 * door already refuses to forward to a row whose host is an arbitrary DNS name;
 * the voice path resolved its key and forwarded anyway, so a bot could write the
 * fast/escalate row with any name of its choosing and let the resolver — not
 * Crow — pick the address. Judged on the string alone: no lookup, so refusing
 * costs no DNS query. An unparseable URL is false (the fetch fails on its own).
 */
export function isRebindableHost(url) {
  const host = targetHost(url);
  if (!host) return false;
  if (isIP(host)) return false;                                  // an IP literal is judged by address
  if (LOOPBACK_NAMES.has(host) || host.endsWith(".localhost")) return false;
  return !host.endsWith(".ts.net");
}

/**
 * THE PATH RULE for a forward, for EVERY caller (the door's own predicate, with
 * the one relayed-only refinement).
 *
 * `isAllowedSelfPath(url)` is the base rule: on this host only an exact
 * `/v1/<op>` or `/llm/v1/<op>` model call with no query and no fragment.
 *
 * For a RELAYED caller, `/llm/v1/<op>` is additionally limited to a port THIS
 * gateway listens on (`self`, from `ownTargetOf`). Co-hosted sibling gateways
 * exist (crow :3001 and crow-r4 :3008 on one box), and `/llm/v1` on ours is a bot
 * door a bot may already call; `/llm/v1` on the sibling's is a door this gateway
 * would be driving on the bot's behalf — not the bot's to use. `/v1/<op>` on any
 * own-host port stays allowed: that is a model server's own port, whichever one
 * it picked.
 */
export function isAllowedSelfForward(url, { relayed = false, self = false } = {}) {
  if (!isAllowedSelfPath(url)) return false;
  if (!relayed) return true;
  let path;
  try { path = new URL(String(url)).pathname; } catch { return false; }
  return !/^\/llm\/v1\//i.test(path) || self === true;
}
