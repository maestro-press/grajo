/**
 * "Is this URL my own gateway?" — the one question a relayed caller may never
 * answer itself (confused deputy, security review 2026-11).
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
import { ownAddresses } from "./safe-upstream.js";
import { gatewayPort } from "./door.js";
import { classifyIp } from "../../shared/ip-classify.js";

/** The ports this gateway listens on: the same env door.js reads (PORT, else
 *  CROW_GATEWAY_PORT, else 3001), so a co-hosted second instance (:3008) judges
 *  its OWN door. */
export function gatewayListenPorts(env = process.env) {
  return new Set([gatewayPort(env)]);
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
 * Every address `host` names, or [] when it cannot be resolved. An IP literal
 * needs no lookup; a localhost name is judged as loopback (RFC 6761) and never
 * asked of a resolver that could be rebound.
 */
async function addressesOf(host, lookupFn) {
  if (isIP(host)) return [host];
  if (LOOPBACK_NAMES.has(host) || host.endsWith(".localhost")) return ["127.0.0.1", "::1"];
  try {
    const answer = await new Promise((resolve, reject) => {
      const timer = setTimeout(() => resolve(null), 2000);
      try {
        lookupFn(host, { all: true }, (err, list) => { clearTimeout(timer); if (err) return reject(err); return resolve(list); });
      } catch (err) { clearTimeout(timer); reject(err); }
    });
    if (!answer) return [];
    return (Array.isArray(answer) ? answer : [answer])
      .map((x) => (typeof x === "string" ? x : x?.address))
      .filter((x) => typeof x === "string" && x);
  } catch {
    return [];
  }
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

const SELF_PATH_RE = new RegExp(
  `^/(?:llm/)?v1/(?:${SELF_PATH_OPS.map((op) => op.split("/").join("\\/")).join("|")})/?$`,
  "i"
);

/** Is this URL one of the operations a forward may run against this host? */
export function isAllowedSelfPath(url) {
  let u;
  try { u = new URL(String(url)); } catch { return false; }
  // A query string or a fragment is never part of an operation path.
  if (u.search || u.hash) return false;
  const p = u.pathname;
  if (p.includes("%") || p.includes("..") || p.includes("//") || p.includes("\\")) return false;
  return SELF_PATH_RE.test(p);
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