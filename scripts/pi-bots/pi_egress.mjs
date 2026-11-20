/**
 * Egress relay for contained pi spawns (queue item 19, migration step 2c).
 *
 * A contained bot runs in a network namespace with only `lo` (bwrap
 * --unshare-net). Its one way out is a unix socket, bound into the sandbox,
 * whose other end is this relay in the SPAWNING process (gateway or bot
 * runner). Policy is enforced here, outside the sandbox; the in-sandbox
 * forwarder (pi_netns_entry.mjs) is a convenience a bot gains nothing by
 * killing or replacing.
 *
 * Each connection starts with one line:
 *   PORT <n>\n  speak HTTP to 127.0.0.1:<n> from this relay. Only the spawn's
 *               own gateway port, and there only the bot doors
 *               (servers/shared/bot-doors.js): every request on the
 *               connection, keep-alive included, is judged by one HTTP
 *               parser, upgrades and CONNECT are refused, and every upstream
 *               socket carries the relay mark (127.0.77.1), which the gateway
 *               refuses for /internal. Nothing else on loopback is reachable:
 *               other instances, unused model servers, a browser's DevTools
 *               port, adb.
 *   PROXY\n     an HTTP CONNECT request follows (the bot's HTTPS_PROXY). Only
 *               CONNECT, on ports from egressPorts (default 443), and the
 *               network is CLOSED (the operator's ruling): a destination is
 *               reachable only when EVERY address the name resolves to is
 *               global unicast, is not one of this host's own addresses and is
 *               not in the operator's deny list. Nothing on the LAN, the
 *               tailnet, loopback, cloud metadata or this host is reachable; a
 *               bot that needs a lab service gets a door for it. Every address
 *               is checked and the checked one connected (no DNS rebinding);
 *               IP literals the same; an `egress` list (exact or *.suffix)
 *               narrows further.
 *
 * Every decision is logged once per (decision, host:port) per spawn,
 * `[pi-egress] bot=<id> allow|deny <host>:<port> (<reason>)`. A per-spawn
 * connection cap bounds what one bot can open.
 */
import { createServer, connect as netConnect, isIP, BlockList } from "node:net";
import { createServer as createHttpServer, request as httpRequest } from "node:http";
import { request as httpsRequest } from "node:https";
import { isDoorPath, RELAY_SOURCE_V4, ADDON_RELAY_SOURCE_V4 } from "../../servers/shared/bot-doors.js";
import { createStreamRedactor, createTaintDetector, redactHeaderValues } from "./pi_inject_redact.mjs";
import { TTS_PORT_EXCEPTION, addrInCidr, bridgeSubnetsFromInterfaces } from "../addon-sandbox/listener-owner.mjs";
import { spawnSync } from "node:child_process";
import { lookup as dnsLookup } from "node:dns/promises";
import { chmodSync, existsSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { join } from "node:path";

// The closed network (the operator's ruling, spec §10): a CONNECT reaches a
// destination only when EVERY address its name resolves to is global unicast,
// is not one of this host's own addresses and is not in the operator's deny
// list. Every special-purpose range is refused, because each is a way around
// another control rather than a destination class: the LAN and the tailnet
// (100.64/10, fd7a:115c:a1e0::/48) are the operator's own network, loopback is
// governed by the PORT door allowlist, cloud metadata is credentials, and
// multicast/reserved/documentation ranges are not destinations a bot has any
// business reaching. A bot that needs a lab service gets a door for it.
// The own-host view is the kernel's LOCAL table only (readLocalTable): an
// interface list can omit an address on a link with no carrier.
// Networks this host is DIRECTLY attached to are refused too: every other
// machine on a LAN has a global address of its own, and nothing in that address
// says so. They come from the MAIN table (a row with a dst other than `default`
// and no gateway, e.g. `192.0.2.0/24 dev eth0 scope link`), and the /64 of every
// global IPv6 address this host owns is refused as well — even with no on-link
// row, whatever prefix the router announces.
// IPv4 embedded in IPv6 (v4-mapped, v4-compatible, SIIT, NAT64, 6to4, both
// Teredo fields, ISATAP) is unwrapped and judged as the IPv4 address; the
// discard prefix is refused. Zone ids are stripped (the CONNECT parser refuses
// '%' anyway).
// Not detectable from this host's tables, so an operator lists them in
// CROW_PI_EGRESS_DENY_NETS (spawner env, comma-separated CIDRs): Kubernetes
// service ranges, a network-specific NAT64 prefix, a router that hairpins the
// host's public address back to it.
/** [network, prefix length, reason] — every IPv4 range that is not global unicast. */
const SPECIAL_V4 = [
  // metadata and host plumbing first: 100.100.100.0/24 sits inside 100.64/10
  ["169.254.0.0", 16, "cloud metadata"], ["168.63.129.16", 32, "cloud metadata"], ["100.100.100.0", 24, "cloud metadata"],
  ["127.0.0.0", 8, "loopback"],
  ["0.0.0.0", 8, "not unicast"],
  ["10.0.0.0", 8, "private network"], ["172.16.0.0", 12, "private network"], ["192.168.0.0", 16, "private network"],
  ["100.64.0.0", 10, "tailnet/CGNAT"],
  ["192.0.0.0", 24, "reserved"], ["192.0.2.0", 24, "documentation range"],
  ["192.31.196.0", 24, "reserved"], ["192.52.193.0", 24, "reserved"], ["192.88.99.0", 24, "reserved"],
  ["192.175.48.0", 24, "reserved"], ["198.51.100.0", 24, "documentation range"], ["203.0.113.0", 24, "documentation range"],
  ["198.18.0.0", 15, "benchmarking range"],
  ["224.0.0.0", 4, "not unicast"], ["240.0.0.0", 4, "not unicast"],
].map(([net, plen, why]) => { const b = new BlockList(); b.addSubnet(net, plen, "ipv4"); return [b, why]; });

function expand6(a) {
  let s = String(a).toLowerCase().split("%")[0];
  const dot = s.lastIndexOf(".");
  if (dot > 0) {
    const lastColon = s.lastIndexOf(":");
    const q = s.slice(lastColon + 1).split(".").map(Number);
    s = s.slice(0, lastColon + 1) + ((q[0] << 8) | q[1]).toString(16) + ":" + ((q[2] << 8) | q[3]).toString(16);
  }
  const [head, tail] = s.includes("::") ? s.split("::") : [s, null];
  const h = head ? head.split(":") : [];
  const t = tail === null ? [] : (tail ? tail.split(":") : []);
  const fill = tail === null ? [] : Array(8 - h.length - t.length).fill("0");
  return [...h, ...fill, ...t].map((x) => parseInt(x || "0", 16));
}
const key6 = (a) => expand6(a).join(":");
const v4From = (hi, lo) => [hi >> 8, hi & 255, lo >> 8, lo & 255].join(".");

const IP_CANDIDATES = ["/usr/sbin/ip", "/sbin/ip", "/usr/bin/ip", "/bin/ip"];

/** `ip -j <args>`, parsed; throws when ip(8) is missing or the read fails. */
function ipJson(args) {
  const ip = IP_CANDIDATES.find((p) => existsSync(p));
  if (!ip) throw new Error("ip(8) not found");
  const r = spawnSync(ip, ["-j", ...args], { encoding: "utf8", timeout: 2000 });
  if (r.status !== 0) throw Object.assign(new Error("ip " + args.join(" ") + ": exit " + r.status), { stderr: String(r.stderr || "") });
  const v = JSON.parse(r.stdout || "null");
  if (!Array.isArray(v)) throw new Error("ip " + args.join(" ") + ": not a list");
  return v;
}

/** The dst of every local-table row: that table is about this host alone. */
function parseLocalRows(rows) {
  const out = [];
  for (const r of rows || []) {
    const dst = String((r && r.dst) || "").split("%")[0];
    if (dst && isIP(dst.split("/")[0])) out.push(dst);
  }
  return out;
}

/** /proc/net/fib_trie: a `|-- a.b.c.d` line followed by `/NN host LOCAL` (a /32 is an address, a shorter prefix a subnet this host owns). */
function parseFibTrie(text) {
  const out = [];
  let cand = null;
  for (const line of String(text || "").split("\n")) {
    const m = /^\s*\|--\s+(\d{1,3}(?:\.\d{1,3}){3})\s*$/.exec(line);
    if (m) { cand = m[1]; continue; }
    const p = /^\s*\/(\d{1,2})\s+host\s+LOCAL\b/.exec(line);
    if (p) {
      const plen = Number(p[1]);
      if (cand && plen <= 32) out.push(plen === 32 ? cand : cand + "/" + plen);
      cand = null;
      continue;
    }
    if (line.trim()) cand = null;
  }
  return out;
}

function hex6(h) {
  const s = String(h || "").toLowerCase();
  if (!/^[0-9a-f]{32}$/.test(s)) return null;
  return s.match(/.{4}/g).map((x) => parseInt(x, 16));
}

/** RFC 5952 form: lowercase, no leading zeros, the longest (first) zero run as "::". */
function fmt6(h) {
  const g = h.map((x) => x.toString(16));
  let best = -1, bestLen = 1;
  for (let i = 0; i < 8;) {
    if (h[i] !== 0) { i++; continue; }
    let j = i;
    while (j < 8 && h[j] === 0) j++;
    if (j - i > bestLen) { best = i; bestLen = j - i; }
    i = j;
  }
  if (best < 0) return g.join(":");
  return g.slice(0, best).join(":") + "::" + g.slice(best + bestLen).join(":");
}

/** /proc/net/ipv6_route: rows whose flags carry RTF_LOCAL (0x80000000) are own addresses. */
function parseIpv6Route(text) {
  const out = [];
  for (const line of String(text || "").split("\n")) {
    const c = line.trim().split(/\s+/);
    if (c.length < 10) continue;
    if (!(parseInt(c[8], 16) & 0x80000000)) continue;
    const g = hex6(c[0]);
    const plen = parseInt(c[1], 16);
    if (!g || !(plen >= 0 && plen <= 128)) continue;
    const addr = fmt6(g);
    out.push(plen === 128 ? addr : addr + "/" + plen);
  }
  return out;
}

/** Route types that are not a link this host sits on. */
const NOT_A_LINK = new Set(["unreachable", "blackhole", "prohibit", "throw", "multicast"]);

/**
 * The dst of every MAIN-table row that is a network on a link this host sits
 * on: a dst other than `default` and no gateway between, e.g.
 * `192.0.2.0/24 dev eth0 scope link` or `2001:db8:10:20::/64 dev eth0 proto ra`.
 */
function parseOnLinkRows(rows) {
  const out = [];
  for (const r of rows || []) {
    const dst = String((r && r.dst) || "").split("%")[0];
    if (!dst || dst === "default") continue;
    if (r.gateway) continue; // a route THROUGH a router, not onto the link
    if (r.type && NOT_A_LINK.has(String(r.type))) continue;
    if (!isIP(dst.split("/")[0])) continue;
    out.push(dst);
  }
  return out;
}

/** An 8-digit little-endian hex IPv4 field (/proc/net/route), as four octets. */
function hex4le(h) {
  const s = String(h || "");
  if (!/^[0-9a-f]{8}$/i.test(s)) return null;
  return [6, 4, 2, 0].map((i) => parseInt(s.slice(i, i + 2), 16));
}

/**
 * /proc/net/route (the ip(8)-less fallback for the MAIN table): Destination and
 * Mask are little-endian hex, and a Gateway of 00000000 means the network is
 * on-link rather than behind a router.
 */
function parseProcRoute(text) {
  const out = [];
  for (const line of String(text || "").split("\n").slice(1)) {
    const c = line.trim().split(/\s+/);
    if (c.length < 8) continue;
    if (!/^0{8}$/.test(c[2])) continue;
    const d = hex4le(c[1]), m = hex4le(c[7]);
    if (!d || !m) continue;
    const plen = m.reduce((n, o) => n + (o.toString(2).split("1").length - 1), 0);
    if (plen < 1) continue; // the default route is not a network of its own
    out.push(d.map((o, i) => o & m[i]).join(".") + "/" + plen);
  }
  return out;
}

/**
 * /proc/net/ipv6_route (the ip(8)-less fallback for the MAIN table): a next hop
 * of all zeros with a prefix shorter than /128 is a network on a link. RTF_LOCAL
 * rows are own addresses, not networks.
 */
function parseIpv6OnLink(text) {
  const out = [];
  for (const line of String(text || "").split("\n")) {
    const c = line.trim().split(/\s+/);
    if (c.length < 10) continue;
    if (parseInt(c[8], 16) & 0x80000000) continue;
    const plen = parseInt(c[1], 16);
    if (!(plen > 0 && plen < 128)) continue;
    if (!/^0{32}$/.test(c[4].toLowerCase())) continue; // a next hop: via a router
    const g = hex6(c[0]);
    if (g) out.push(fmt6(g) + "/" + plen);
  }
  return out;
}

/** Did this read fail because the kernel has no IPv6 at all (not a failure)? */
function noV6Kernel(e) {
  const t = String((e && (e.stderr || e.message)) || "");
  return !!(e && (e.code === "ENOENT" || /address family not supported|EAFNOSUPPORT/i.test(t)));
}

/**
 * Is the /64 of this own IPv6 address a global-unicast network? The non-global
 * ranges are refused by their own reason anyway, and a neighbour on them should
 * keep that reason rather than gain a vaguer one.
 */
function global6(h) {
  if ((h[0] & 0xfe00) === 0xfc00) return false; // ULA
  if ((h[0] & 0xffc0) === 0xfe80) return false; // link-local
  if ((h[0] & 0xffc0) === 0xfec0) return false; // site-local
  if ((h[0] & 0xff00) === 0xff00) return false; // multicast
  if (h[0] === 0x100 && h.slice(1, 4).every((x) => x === 0)) return false; // discard-only
  if (h[0] === 0x2001 && (h[1] === 2 || h[1] === 0x0db8)) return false; // benchmarking / documentation
  if (h[0] === 0x3fff && (h[1] & 0xf000) === 0) return false; // documentation
  return true;
}

/**
 * This host's own addresses and prefixes, from the kernel's LOCAL table ONLY:
 * `ip -j [-6] route show table local`, falling back to /proc/net/fib_trie and
 * /proc/net/ipv6_route. The OS interface list is deliberately not a source: it
 * omits an address on an interface with no carrier (a bridge that comes up
 * later), which is the hole the S2c review named.
 *
 * The networks this host is directly attached to come from the MAIN table (see
 * parseOnLinkRows), because every other machine on one of them has a global
 * address that no range check would recognise.
 *
 * A family that cannot be read is REPORTED, never hidden: the caller refuses
 * that family's targets (every target when IPv4 fails). A kernel with no IPv6
 * (EAFNOSUPPORT, or no /proc/net/ipv6_route) is not a failure. o.run/o.readFile
 * are test seams.
 * @returns {{v4: string[], v6: string[], onLink4: string[], onLink6: string[], v4Failed: boolean, v6Failed: boolean, onLinkFailed: boolean}}
 */
export function readLocalTable(o = {}) {
  const run = o.run || ipJson;
  const readFile = o.readFile || ((p) => readFileSync(p, "utf8"));
  let noV6 = false;
  let v4 = null;
  try { v4 = parseLocalRows(run(["route", "show", "table", "local"])); } catch { v4 = null; }
  // An empty successful read is a parse that failed, not a host without
  // addresses: the LOCAL table always carries at least loopback.
  if (!v4 || !v4.length) {
    try { v4 = parseFibTrie(readFile("/proc/net/fib_trie")); } catch { v4 = null; }
  }
  const v4Failed = !v4 || !v4.length;
  if (v4Failed) v4 = [];
  let v6 = null, v6Failed = false;
  try { v6 = parseLocalRows(run(["-6", "route", "show", "table", "local"])); }
  catch (e) { v6 = null; noV6 = noV6Kernel(e); }
  if (!v6 || !v6.length) {
    try {
      v6 = parseIpv6Route(readFile("/proc/net/ipv6_route"));
      if (!v6.length) v6Failed = true;
    } catch (e) {
      v6 = [];
      // A kernel booted without IPv6 has no ipv6_route file at all.
      if (e && e.code === "ENOENT") noV6 = true;
      else v6Failed = true;
    }
  }
  // The networks on this host's links: the MAIN table, read the same two ways.
  const mainTable = (args, proc, fromRows, fromProc) => {
    let rows = null;
    try { rows = fromRows(run(args)); } catch { rows = null; }
    if (!rows) { try { rows = fromProc(readFile(proc)); } catch { rows = null; } }
    return Array.isArray(rows) ? rows : null;
  };
  const onLink4 = mainTable(["route", "show", "table", "main"], "/proc/net/route", parseOnLinkRows, parseProcRoute);
  const onLink6 = mainTable(["-6", "route", "show", "table", "main"], "/proc/net/ipv6_route", parseOnLinkRows, parseIpv6OnLink);
  // A host with a real (non-loopback) IPv4 address always has an on-link IPv4
  // network: an empty read then is a read that missed it, and fails closed.
  const hasRealV4 = v4.some((a) => !String(a).startsWith("127."));
  const onLink4Failed = !onLink4 || (onLink4.length === 0 && hasRealV4), onLink6Failed = !onLink6;
  return {
    v4, v6,
    onLink4: onLink4 || [],
    onLink6: onLink6 || [],
    // A family whose on-link read failed fails closed like its own-host read: a
    // view that cannot list the networks this host sits on cannot be trusted to
    // let anything out. A kernel with no IPv6 has no on-link rows to miss.
    v4Failed: v4Failed || onLink4Failed,
    v6Failed: v6Failed || (onLink6Failed && !noV6),
    onLinkFailed: onLink4Failed || (onLink6Failed && !noV6),
  };
}

/** The local table is cached briefly (addresses come and go; a spawn makes many decisions). */
const LOCAL_TTL_MS = 5000;
let localCache = null; // { at, value }
let localTableReader = null; // test seam
/** Test seam: replace the kernel reader (null restores it). */
export function _setLocalTableReaderForTest(fn) { localTableReader = fn; }
/** Test seam: forget the cached read. */
export function _resetLocalTableCacheForTest() { localCache = null; }
function cachedLocalTable() {
  const now = Date.now();
  if (!localCache || now - localCache.at > LOCAL_TTL_MS) {
    let value = null;
    // A failure is cached AS a failure and is never remembered as a success.
    try { value = (localTableReader || readLocalTable)(); } catch { value = null; }
    if (!value || typeof value !== "object") value = { v4: [], v6: [], onLink4: [], onLink6: [], v4Failed: true, v6Failed: true, onLinkFailed: true };
    localCache = { at: now, value };
  }
  return localCache.value;
}

/**
 * This host's view: the addresses and prefixes the kernel's LOCAL table says
 * it owns (o.local, a readLocalTable result), plus o.hostAddrs (extra own
 * addresses, e.g. a router that hairpins the host's public address back to
 * it), plus the networks it sits on (the MAIN table's on-link rows, and the
 * /64 of every own global IPv6 address). There is no interface enumeration and
 * no bridge/VM name or kind logic: under the closed network every private range
 * is refused anyway, and the kernel table finds an address on an interface with
 * no carrier.
 */
function localView(o = {}) {
  const t = o.local || cachedLocalTable();
  const addrs = new Set();
  const own6 = []; // bare own IPv6 addresses, for the /64 rule below
  const nets4 = new BlockList(), nets6 = new BlockList();
  const onLink4 = new BlockList(), onLink6 = new BlockList();
  let failed = !!t.v4Failed, failed6 = !!t.v6Failed;
  const add = (x) => {
    const s = String(x || "").split("%")[0];
    const parts = s.split("/");
    if (parts.length > 2) { failed = failed6 = true; return; }
    const fam = isIP(parts[0]);
    // An entry the relay cannot read fails the view closed: a source that
    // emits garbage cannot be trusted to have listed every own address.
    if (!fam) { failed = failed6 = true; return; }
    const max = fam === 4 ? 32 : 128;
    const plen = parts.length === 2 ? (/^\d+$/.test(parts[1]) ? Number(parts[1]) : NaN) : max;
    if (!(plen <= max)) { failed = failed6 = true; return; }
    if (plen === max) {
      addrs.add(fam === 6 ? key6(parts[0]) : parts[0]);
      if (fam === 6) own6.push(parts[0]);
    } else { try { (fam === 4 ? nets4 : nets6).addSubnet(parts[0], plen, fam === 4 ? "ipv4" : "ipv6"); } catch { failed = failed6 = true; } }
  };
  for (const a of t.v4 || []) add(a);
  for (const a of t.v6 || []) add(a);
  for (const a of o.hostAddrs || []) add(a);
  // The networks this host is directly attached to. Every other machine on one
  // of them is a neighbour with an address of its own, and nothing in that
  // address says which link it sits on: refused as this host's network.
  const addNet = (x, fam) => {
    const s = String(x || "").split("%")[0];
    const parts = s.split("/");
    const max = fam === 4 ? 32 : 128;
    const plen = parts.length === 2 ? (/^\d+$/.test(parts[1]) ? Number(parts[1]) : NaN) : max;
    if (!isIP(parts[0]) || !(plen <= max)) { failed = failed6 = true; return; }
    try { (fam === 4 ? onLink4 : onLink6).addSubnet(parts[0], plen, fam === 4 ? "ipv4" : "ipv6"); }
    catch { failed = failed6 = true; }
  };
  for (const n of t.onLink4 || []) addNet(n, 4);
  for (const n of t.onLink6 || []) addNet(n, 6);
  // The /64 of every global IPv6 address this host owns, announced by a router
  // or not: a neighbour shares it, and only the local table knows about it.
  for (const a of own6) {
    const h = expand6(a);
    if (global6(h)) onLink6.addSubnet(fmt6([h[0], h[1], h[2], h[3], 0, 0, 0, 0]), 64, "ipv6");
  }
  // operator-listed networks that lead back into this host but are not
  // visible in its tables (Kubernetes ClusterIP ranges DNAT'd in nat
  // OUTPUT, a network-specific NAT64 prefix): refused like an own address.
  const deny4 = new BlockList(), deny6 = new BlockList();
  let denyBroken = false;
  for (const n of o.denyNets || []) {
    const parts = String(n).trim().split("/");
    if (parts.length > 2) { denyBroken = true; continue; }
    const [net, plen] = parts;
    const fam = isIP(net);
    const len = plen === undefined ? (fam === 4 ? 32 : 128) : (/^\d+$/.test(plen) ? Number(plen) : NaN);
    if (!fam || !(len <= (fam === 4 ? 32 : 128))) { denyBroken = true; continue; }
    try { (fam === 4 ? deny4 : deny6).addSubnet(net, len, fam === 4 ? "ipv4" : "ipv6"); } catch { denyBroken = true; continue; }
    // An entry written as IPv4-mapped IPv6 (::ffff:a.b.c.d/96+) also denies
    // the IPv4 network, so its other wrappings and the bare address are covered.
    if (fam === 6 && len >= 96) {
      const h = expand6(net);
      if (h.slice(0, 5).every((x) => x === 0) && h[5] === 0xffff) {
        try { deny4.addSubnet(v4From(h[6], h[7]), len - 96, "ipv4"); } catch { denyBroken = true; }
      }
    }
  }
  return { addrs, nets4, nets6, onLink4, onLink6, failed, failed6, deny4, deny6, denyBroken };
}

function v4Reason(a, L) {
  // The operator deny list first, so every IPv4-in-IPv6 path gets it too.
  if (L.deny4 && L.deny4.check(a, "ipv4")) return "operator-denied network";
  if (L.addrs.has(a) || L.nets4.check(a, "ipv4")) return "this host";
  // A network this host is directly attached to, BEFORE the range list: a lab
  // numbered out of a documentation range is still the operator's LAN, and the
  // neighbour's address is only recognisable by the network it sits on.
  if (L.onLink4 && L.onLink4.check(a, "ipv4")) return "this host's network";
  for (const [net, why] of SPECIAL_V4) if (net.check(a, "ipv4")) return why;
  if (L.failed) return "own-host view unreadable";
  return null;
}

function v6Reason(a, L) {
  const h = expand6(a);
  const zero = (x, y) => h.slice(x, y).every((v) => v === 0);
  // Unspecified and loopback first: an embedded-IPv4 reading of ::1 would
  // otherwise say "not unicast" and hide the real reason.
  if (zero(0, 8)) return "not unicast";
  if (zero(0, 7) && h[7] === 1) return "loopback";
  // Cloud metadata and host plumbing: ULA endpoints, not peers.
  if ((h[0] === 0xfd00 && h[1] === 0x0ec2 && zero(2, 4)) || key6(a) === key6("fd20:ce::254") || key6(a) === key6("fd7a:115c:a1e0::53")) {
    return "cloud metadata";
  }
  // IPv4 inside IPv6: every prefix known to embed an IPv4 address is judged by
  // that address (and, when that is clean, still by the checks below: this host
  // may own a 6to4/Teredo/NAT64 address). Judged BEFORE the range checks so a
  // wrapper around an operator-denied address keeps that specific reason.
  let embedded = null;
  if (zero(0, 5) && (h[5] === 0xffff || h[5] === 0)) embedded = v4Reason(v4From(h[6], h[7]), L);       // ::ffff:a.b.c.d, ::a.b.c.d
  else if (zero(0, 4) && h[4] === 0xffff && h[5] === 0) embedded = v4Reason(v4From(h[6], h[7]), L);   // SIIT ::ffff:0:a.b.c.d
  else if (h[0] === 0x64 && h[1] === 0xff9b && zero(2, 6)) embedded = v4Reason(v4From(h[6], h[7]), L); // NAT64 64:ff9b::/96
  else if (h[0] === 0x64 && h[1] === 0xff9b && h[2] === 1) {
    // NAT64 local-use /48 (RFC 6052): the u octet (bits 64-71) must be zero;
    // then the IPv4 sits in bits 48-63 and 72-87. An unreadable layout is
    // refused rather than guessed at.
    if (h[4] >> 8) return "NAT64 local-use prefix (embedding unreadable)";
    embedded = v4Reason(v4From(h[3], ((h[4] & 0xff) << 8) | (h[5] >> 8)), L);
  }
  else if (h[0] === 0x2002) embedded = v4Reason(v4From(h[1], h[2]), L);                                // 6to4
  else if (h[0] === 0x2001 && h[1] === 0) {                                                            // Teredo: server, and client XOR ffff:ffff
    embedded = v4Reason(v4From(h[2], h[3]), L) || v4Reason(v4From(h[6] ^ 0xffff, h[7] ^ 0xffff), L);
  }
  else if ((h[4] === 0 || h[4] === 0x200) && h[5] === 0x5efe) embedded = v4Reason(v4From(h[6], h[7]), L);   // ISATAP ::0:5efe:a.b.c.d
  if (embedded) return embedded;
  // One of this host's own addresses, then a network this host is directly
  // attached to (a LAN neighbour's global address shares this host's /64). Both
  // are more specific than the ranges below, which cannot tell a neighbour from
  // any other host on the internet.
  if (L.addrs.has(key6(a)) || L.nets6.check(a, "ipv6")) return "this host";
  if (L.onLink6 && L.onLink6.check(a, "ipv6")) return "this host's network";
  // Address classes that say what the address IS, whatever link it is on.
  if ((h[0] & 0xfe00) === 0xfc00) return "private network";  // fc00::/7 ULA (the tailnet's fd7a:115c:a1e0::/48 is in it)
  if ((h[0] & 0xffc0) === 0xfe80) return "link-local";       // fe80::/10
  if ((h[0] & 0xffc0) === 0xfec0) return "site-local";       // fec0::/10 (deprecated)
  if ((h[0] & 0xff00) === 0xff00) return "not unicast";      // ff00::/8 multicast
  // Every remaining IPv6 range that is not global unicast.
  if (h[0] === 0x100 && zero(1, 4)) return "discard-only prefix";
  if (h[0] === 0x2001 && h[1] === 2) return "benchmarking range";            // 2001:2::/48
  if (h[0] === 0x2001 && h[1] === 0x0db8) return "documentation range";       // 2001:db8::/32
  if (h[0] === 0x3fff && (h[1] & 0xf000) === 0) return "documentation range"; // 3fff::/20
  if (L.failed || L.failed6) return "own-host view unreadable";
  return null;
}

/**
 * null when the relay may connect to `addr`, else the reason it may not. The
 * network is closed: only a global-unicast address that is not this host's own
 * and not in the operator's deny list passes. o.local is a readLocalTable
 * result (default: the cached kernel read); o.hostAddrs adds own addresses;
 * o.denyNets is the operator list.
 */
export function egressDenyReason(addr, o = {}) {
  const a = String(addr || "").replace(/^\[|\]$/g, "").split("%")[0];
  const fam = isIP(a);
  if (!fam) return "not an IP address";
  const L = o.view || localView(o);
  // The operator's deny list is a stated intent: an entry that cannot be read
  // refuses everything rather than silently not refusing what it meant.
  if (L.denyBroken) return "operator deny list (CROW_PI_EGRESS_DENY_NETS) has an unreadable entry: refusing all targets";
  if (fam === 6 && L.deny6 && L.deny6.check(a, "ipv6")) return "operator-denied network";
  return fam === 4 ? v4Reason(a, L) : v6Reason(a, L);
}

const norm = (h) => String(h || "").trim().toLowerCase().replace(/\.$/, "");
/** No list: any host. A list: exact names and "*.suffix" (not the bare suffix). */
export function hostAllowed(host, list) {
  if (!Array.isArray(list)) return true;
  const h = norm(host);
  return list.some((p) => {
    const q = norm(p);
    if (q.startsWith("*.")) return h.endsWith(q.slice(1)) && h.length > q.length - 1;
    return h === q;
  });
}

const MAX_HEAD = 16 * 1024;
const MAX_LOGGED = 1000;
const HOSTNAME_RE = /^(?=.{1,253}$)([a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)(\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*$/;

// ---- add-on mode: per-add-on allow lists -----------------------------------
// A walled add-on gets its own relay: no bot doors, a list of loopback ports
// splice-checked against the listener's owner (an owner-typed URL may reach a
// process of this user; a manifest default may reach only a published port;
// a gateway-computed `gateway-tts` entry may reach only the TTS add-ons' own
// published project, the one named cross-add-on exception), exact CONNECT
// entries that may be private, and (D1) absolute-form plain HTTP to those same
// entries. None of this is reachable when `o.addon` is absent (the bot path).

/** The last N refused targets a relay keeps for the owner's status card. */
const MAX_DENIALS = 20;
/** The refusal reasons a listed entry may still override (a private destination is what was listed). */
const SOFT_REASONS = new Set(["private network", "tailnet/CGNAT", "this host's network"]);
/** Methods an absolute-form plain-HTTP request may use (D1). */
const PLAIN_RE = /^(GET|POST|PUT|PATCH|DELETE|HEAD)\s+(http:\/\/[^\s]+)\s+HTTP\/1\.[01]$/;
/** The same forbidden shapes the door allowlist refuses, kept here so an add-on's door predicate is only ever shown a clean origin-form path. */
const ADDON_FORBIDDEN = /[\u0000-\u0020\u007f\\*]/;

/** Ranges a listed entry may never reach, whatever reason the closed-network check gives. */
const HARD_V4 = [["169.254.0.0", 16], ["168.63.129.16", 32], ["100.100.100.0", 24], ["0.0.0.0", 8], ["127.0.0.0", 8], ["224.0.0.0", 4], ["240.0.0.0", 4]];
const HARD_V6 = [["::", 128], ["::1", 128], ["ff00::", 8], ["fe80::", 10], ["fd00:ec2::", 32], ["fd20:ce::254", 128], ["fd7a:115c:a1e0::53", 128]];
const v4Int = (a) => a.split(".").reduce((n, o) => n * 256 + Number(o), 0);
const in4 = (a, net, plen) => plen <= 0 || (v4Int(a) >>> (32 - plen)) === (v4Int(net) >>> (32 - plen));
const big6 = (g) => g.reduce((acc, x) => (acc << 16n) | BigInt(x), 0n);
const in6 = (a, net, plen) => {
  if (plen <= 0) return true;
  const shift = BigInt(128 - plen);
  return (big6(expand6(a)) >> shift) === (big6(expand6(net)) >> shift);
};

/** A host name as an allow list holds it: lower case, no trailing dot. */
const addonHost = (h) => (typeof h === "string" ? h.trim().toLowerCase().replace(/\.$/, "") : "");
/** The only shape an owner value may have before it is read as an add-on id. */
const ADDON_OWNER_ID_RE = /^[a-z0-9][a-z0-9-]*$/;
const isPortNumber = (p) => Number.isInteger(p) && p > 0 && p < 65536;

/** One address spelling for comparison: brackets/zone dropped, v4-mapped becomes its IPv4. */
function canonTargetAddr(addr) {
  const s = String(addr ?? "").trim().replace(/^\[(.*)\]$/, "$1").split("%")[0].toLowerCase();
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/.exec(s);
  return mapped ? mapped[1] : s;
}

/** Is `addr` in the range a listed entry may never reach (also inside a ::ffff: wrapper)? */
function addonHardDenied(addr) {
  const a = canonTargetAddr(addr);
  const fam = isIP(a);
  if (fam === 4) return HARD_V4.some(([n, p]) => in4(a, n, p));
  if (fam !== 6) return true;
  const h = expand6(a);
  if (h.slice(0, 5).every((x) => x === 0) && h[5] === 0xffff) {
    const v4 = v4From(h[6], h[7]);
    if (HARD_V4.some(([n, p]) => in4(v4, n, p))) return true;
  }
  return HARD_V6.some(([n, p]) => in6(a, n, p));
}

/**
 * How this address carries an IPv4 address, if it does: `"mapped"` for
 * `::ffff:a.b.c.d` (judged as that IPv4), `"v6"` for every other embedding the
 * closed-network check unwraps (v4-compatible, SIIT, NAT64 64:ff9b::/96 and the
 * /48 local-use form, 6to4, Teredo, ISATAP), else null. Unspecified and
 * loopback are NOT embeddings here: those two are named by their own ranges.
 */
function v4Embedding(a) {
  const h = expand6(a);
  const zero = (x, y) => h.slice(x, y).every((v) => v === 0);
  if (zero(0, 5) && h[5] === 0xffff) return "mapped";                                  // ::ffff:a.b.c.d
  if (zero(0, 8) || (zero(0, 7) && h[7] === 1)) return null;                            // :: and ::1
  if (zero(0, 5) && h[5] === 0) return "v6";                                            // ::a.b.c.d (v4-compatible)
  if (zero(0, 4) && h[4] === 0xffff && h[5] === 0) return "v6";                         // SIIT ::ffff:0:a.b.c.d
  if (h[0] === 0x64 && h[1] === 0xff9b && zero(2, 6)) return "v6";                      // NAT64 64:ff9b::/96
  if (h[0] === 0x64 && h[1] === 0xff9b && h[2] === 1) return "v6";                      // NAT64 local-use 64:ff9b:1::/48
  if (h[0] === 0x2002) return "v6";                                                     // 6to4
  if (h[0] === 0x2001 && h[1] === 0) return "v6";                                       // Teredo
  if ((h[4] === 0 || h[4] === 0x200) && h[5] === 0x5efe) return "v6";                   // ISATAP ::0:5efe:a.b.c.d
  return null;
}

/**
 * A listed entry's address: null when allowed. A private or on-link destination
 * is allowed (the owner listed it), but never cloud metadata, loopback, the
 * unspecified/multicast/reserved ranges, an IPv4 wrapped in a tunnelled or
 * translated IPv6 address, or anything while the view is broken. The one
 * embedding that is judged as what it carries is a bare `::ffff:a.b.c.d`.
 */
function listedAddrReason(addr, view) {
  let a = canonTargetAddr(addr);
  let fam = isIP(a);
  if (!fam) return "not an IP address";
  if (fam === 6) {
    const kind = v4Embedding(a);
    if (kind === "mapped") {
      // The hex spelling of a v4-mapped address (canonTargetAddr unwraps the
      // dotted one): judged as the IPv4 it carries.
      const h = expand6(a);
      a = v4From(h[6], h[7]);
      fam = 4;
    } else if (kind === "v6") {
      return "IPv4 inside IPv6 is not allowed for a listed host";
    }
  }
  const r = egressDenyReason(a, { view });
  if (r === null) return null;
  if (r === "loopback") return "own host";
  if (!SOFT_REASONS.has(r)) return r;
  if (addonHardDenied(a)) return "not allowed for a listed host";
  if (fam === 4 ? view.failed : view.failed || view.failed6) return "own-host view unreadable";
  return null;
}

/** The validated view of `o.addon` (nothing here trusts its shape). */
function normalizeAddon(raw) {
  const targets = (list) => {
    const out = new Map();
    for (const e of Array.isArray(list) ? list : []) {
      if (!e || typeof e !== "object") continue;
      const port = Number(e.port);
      const host = addonHost(e.host);
      if (!host || !isPortNumber(port)) continue;
      const key = host + ":" + port;
      if (!out.has(key)) out.set(key, { host, port });
    }
    return out;
  };
  const splices = (list) => {
    const out = new Map();
    for (const e of Array.isArray(list) ? list : []) {
      if (!e || typeof e !== "object") continue;
      const port = Number(e.port);
      if (!isPortNumber(port) || out.has(port)) continue;
      const ownerProject = typeof e.ownerProject === "string" && e.ownerProject ? e.ownerProject : null;
      // "owner": the owner typed this URL into the field. "gateway-tts": the
      // gateway computed it from the TTS add-ons' repo-copy manifests and
      // compose (the one named cross-add-on exception), which an add-on's own
      // manifest or config can never produce. Anything else is a manifest
      // default, which may only reach a published port of this add-on.
      const source = e.source === "owner" ? "owner" : e.source === "gateway-tts" ? "gateway-tts" : "default";
      out.set(port, { port, ownerProject, source });
    }
    return out;
  };
  const st = raw.selfTargets && typeof raw.selfTargets === "object" ? raw.selfTargets : {};
  const names = new Set((Array.isArray(st.names) ? st.names : []).map(addonHost).filter(Boolean));
  const addrs = new Set((Array.isArray(st.addrs) ? st.addrs : []).map(canonTargetAddr).filter(Boolean));
  const cacheMs = Number(raw.ownerCacheMs);
  return {
    id: String(raw.id ?? "?"),
    isDoor: typeof raw.isDoor === "function" ? raw.isDoor : () => false,
    internet: raw.internet === true,
    loopback: splices(raw.loopback),
    hosts: targets(raw.hosts),
    plainHttpHosts: targets(raw.plainHttpHosts),
    selfNames: names,
    selfAddrs: addrs,
    listenerOwner: typeof raw.listenerOwner === "function" ? raw.listenerOwner : null,
    ownerCacheMs: Number.isFinite(cacheMs) && cacheMs >= 0 ? cacheMs : 2000,
    // The container-address answer for a listed entry: given by the caller
    // (the gateway's docker view), or absent, in which case a bridge address
    // on this computer is refused. `_interfaces` is the interface-list seam.
    containerOwner: typeof raw.containerOwner === "function" ? raw.containerOwner : null,
    ifaces: raw._interfaces && typeof raw._interfaces === "object" ? raw._interfaces : null,
    httpTarget: typeof raw._httpTarget === "function" ? raw._httpTarget : null,
  };
}

/** Origin-form and free of anything that could rewrite the path, before a door predicate sees it. */
function safeDoorTarget(rawTarget) {
  if (typeof rawTarget !== "string" || rawTarget === "") return false;
  if (rawTarget[0] !== "/" || rawTarget[1] === "/") return false;
  if (ADDON_FORBIDDEN.test(rawTarget)) return false;
  return !(rawTarget.includes("//") || rawTarget.includes("..") || rawTarget.includes("%"));
}

// ---- inject mode: one credentialed upstream, for a reports custom step ------
// A custom step is untrusted code, and it never holds a credential. It asks for
// `http://<host>/...` in absolute form through this relay; the relay resolves
// and checks the host exactly as it does for CONNECT, opens its OWN verified
// TLS request to port 443, and attaches the credential there. The answer comes
// back with every spelling of the credential replaced, an encoded answer is
// refused rather than decoded, and a redirect is passed on untouched: the
// credential is there for this one host and this one request. The credential
// lives in the locals of one request in `forwardInject` and nowhere else, not
// on the relay object, not in a log line, not in an error.
//
// What a rule may name is deliberately narrow. It names ONE host and the path
// prefixes a report actually needs: a report that reads an issue list names
// `/v1/issues`, not `/`. A scoped, read-only credential is preferred over a
// full-access one, because a rule can restrain where a credential is sent but
// never what the endpoint does with it. The relay cannot know whether an
// allowed endpoint mints ANOTHER credential (a token, a session cookie, a
// signed URL) and hands it back, so it does the next best thing: response
// headers that commonly carry a derived credential are dropped whole, and a
// body or a header holding even a partial echo of the injected secret is not
// passed on at all. A response slice (206, Content-Range) is refused whole,
// because one part of a body is a part the relay cannot judge. An answer in a
// wide charset is refused too, and the request carries an allowlist of headers,
// so a step cannot re-aim the request it already got judged.
//
// One accepted risk, named here rather than half handled: a `Location` value is
// redacted only for the exact secret (and its spellings). A redirect URL that
// carries a token DERIVED from the credential is passed on, because only the
// upstream can mint one. A rule names only the endpoints a report needs, and a
// signed redirect URL may carry a derived token.

/** Methods an inject-mode request may use. */
const INJECT_METHODS = new Set(["GET", "HEAD", "POST", "PUT", "PATCH", "DELETE"]);
/** What a rule allows when it names no methods: a report reads. */
const INJECT_DEFAULT_METHODS = ["GET", "HEAD"];
/** A rule's path prefixes: at most this many, each at most this many characters. */
const INJECT_MAX_PREFIXES = 20;
const INJECT_MAX_PREFIX_CHARS = 200;
/** The bytes a normalised path segment keeps as they are (RFC 3986 pchar). */
const INJECT_PCHAR = /[A-Za-z0-9\-._~!$&'()*+,;=:@]/;
/** The taint window: this many consecutive bytes of a spelling is no coincidence. */
const INJECT_TAINT_WINDOW = 8;
/** The request headers an inject request carries: an ALLOWLIST, not a subtractive list.
 *  A step may name an ordinary header (a media type, a language, a user agent, a
 *  correlation id) and nothing that could re-aim a request the relay already judged:
 *  a method override (X-HTTP-Method-Override, X-Method-Override) would walk around
 *  the methods rule, a rewrite header (X-Original-URL, X-Rewrite-URL, X-Forwarded-*)
 *  would walk around the path prefixes and the host, and a charset for the answer or
 *  a session of the step's own (Cookie, Range and its validators) is state the rule
 *  never approved. Everything else a client sends is dropped here. */
const INJECT_REQUEST_HEADERS = new Set(["accept", "accept-language", "content-type", "user-agent", "x-request-id"]);
/** A charset whose answer this relay cannot judge: two or four bytes per character, so
 *  a spelling of the credential looks nothing like the bytes that were injected. */
const INJECT_WIDE_CHARSET_RE = /charset\s*=\s*"?[^";]*?(utf-?16|utf-?32|ucs-?2)/i;
/** Response headers that can carry a credential DERIVED from the injected one
 *  (a token, a session, a challenge, a signed URL). They are dropped whole and
 *  never redacted-and-passed-on: a redacted derived credential is still a
 *  credential the step could try. */
const INJECT_DROP_RESPONSE = new Set(["set-cookie", "set-cookie2", "authorization",
  "proxy-authenticate", "www-authenticate", "authentication-info", "proxy-authentication-info"]);
const INJECT_DROP_RESPONSE_RE = /^x-.*(token|key|secret|auth|session|credential)/i;
const INJECT_DROP_RESPONSE_SUFFIX_RE = /(^|-)(token|apikey|api-key)$/i;
/** A credential shorter than this is not used at all, and nothing is sent: a short
 *  value cannot be told apart from ordinary text in the taint window's terms. */
export const INJECT_SECRET_MIN_BYTES = 16;
/** Bodies: what the step may upload, and what it may receive. */
const INJECT_MAX_REQUEST = 8 * 1024 * 1024;
const INJECT_MAX_RESPONSE = 16 * 1024 * 1024;
/** An HTTP token (RFC 9110), and the query name a credential may be carried in. */
const INJECT_TOKEN_RE = /^[!#$%&'*+\-.^_`|~0-9A-Za-z]+$/;
const INJECT_QUERY_RE = /^[A-Za-z0-9_.-]{1,64}$/;
/** Header names a credential is never attached to: they frame the request itself. */
const INJECT_BAD_HEADER = new Set(["host", "content-length", "transfer-encoding", "connection"]);

const injectError = (code, message) => Object.assign(new Error(message), { code });

/** Does a body start with a UTF-16 or UTF-32 byte order mark? */
function startsWithWideBom(buf) {
  if (!buf || buf.length < 2) return false;
  if (buf[0] === 0xff && buf[1] === 0xfe) return true;   // UTF-16LE, and the UTF-32LE prefix
  if (buf[0] === 0xfe && buf[1] === 0xff) return true;   // UTF-16BE
  return buf.length >= 4 && buf[0] === 0x00 && buf[1] === 0x00 && buf[2] === 0xfe && buf[3] === 0xff;
}

/**
 * The path prefixes a rule must name. A rule without one is refused: an empty
 * or absent prefix list, and a bare `/` that names no segment at all, would make
 * the credential reachable everywhere on the host, which is the thing the list
 * exists to prevent.
 * @returns {string[]}
 */
function normalizeInjectPrefixes(raw) {
  const bad = (why) => injectError("inject_bad_path_prefixes", why);
  if (!Array.isArray(raw) || raw.length === 0) throw bad("pathPrefixes must be a non-empty array of strings");
  if (raw.length > INJECT_MAX_PREFIXES) throw bad("pathPrefixes holds at most " + INJECT_MAX_PREFIXES + " entries");
  const out = [];
  for (const p of raw) {
    if (typeof p !== "string" || p === "") throw bad("a path prefix must be a non-empty string");
    if (p.length > INJECT_MAX_PREFIX_CHARS) throw bad("a path prefix is at most " + INJECT_MAX_PREFIX_CHARS + " characters");
    if (p[0] !== "/") throw bad("a path prefix starts with /");
    if (!p.split("/").some((segment) => segment !== "")) {
      throw bad("a path prefix names at least one path segment");
    }
    if (p.includes("..") || p.includes("?") || p.includes("#")) throw bad("a path prefix holds no .., ? or #");
    if (/[\u0000-\u001f\u007f]/.test(p)) throw bad("a path prefix holds no control character");
    if (!out.includes(p)) out.push(p);
  }
  return out;
}

/** The methods a rule allows: GET and HEAD unless it says, drawn from the inject set. */
function normalizeInjectMethods(raw) {
  if (raw === undefined || raw === null) return new Set(INJECT_DEFAULT_METHODS);
  const bad = (why) => injectError("inject_bad_methods", why);
  if (!Array.isArray(raw) || raw.length === 0) throw bad("methods must be a non-empty array");
  const out = new Set();
  for (const m of raw) {
    if (typeof m !== "string" || !INJECT_METHODS.has(m)) throw bad("a method is one of " + [...INJECT_METHODS].join(", "));
    out.add(m);
  }
  return out;
}

/**
 * Validate `o.inject`: exact hosts, each with exactly one of a header or a query
 * parameter, a format holding one `{}`, a secret function, and the path
 * prefixes (and optionally the methods) the rule covers. A bad entry is a
 * construction error with a stable `code`, never a relay that half works: a
 * guess here would attach a credential somewhere nobody approved. `allow` is the
 * relay's own egress list, which the host must also pass.
 * @returns {Map<string, {host, header, query, format, secret, pathPrefixes: string[], methods: Set<string>}>}
 */
function normalizeInject(list, allow) {
  const out = new Map();
  if (list === undefined || list === null) return out;
  if (!Array.isArray(list)) throw injectError("inject_bad_list", "inject must be an array");
  for (const raw of list) {
    if (!raw || typeof raw !== "object") throw injectError("inject_bad_entry", "an inject entry must be an object");
    const host = typeof raw.host === "string" ? raw.host : "";
    if (!host || host !== host.toLowerCase() || isIP(host) || !HOSTNAME_RE.test(host)) {
      throw injectError("inject_bad_host", "an inject host must be one exact lower-case host name");
    }
    if (out.has(host)) throw injectError("inject_duplicate_host", "an inject host is listed twice: " + host);
    const hasHeader = raw.header !== undefined && raw.header !== null;
    const hasQuery = raw.query !== undefined && raw.query !== null;
    if (hasHeader === hasQuery) throw injectError("inject_bad_target", "exactly one of header or query is required");
    if (typeof raw.secret !== "function") throw injectError("inject_bad_secret", "secret must be a function");
    if (!hostAllowed(host, allow)) {
      throw injectError("inject_host_not_allowed", "an inject host must also be in the egress list: " + host);
    }
    let header = null;
    let query = null;
    let format = "{}";
    if (hasHeader) {
      header = String(raw.header);
      const lower = header.toLowerCase();
      if (!INJECT_TOKEN_RE.test(header) || INJECT_BAD_HEADER.has(lower) || lower.startsWith("proxy-")) {
        throw injectError("inject_bad_header", "not a header a credential may be attached to: " + header);
      }
      if (raw.format !== undefined && raw.format !== null) {
        format = String(raw.format);
        if (format.split("{}").length !== 2) throw injectError("inject_bad_format", "format must hold {} exactly once");
      }
    } else {
      query = String(raw.query);
      if (!INJECT_QUERY_RE.test(query)) throw injectError("inject_bad_query", "a query name is 1-64 of A-Z a-z 0-9 _ . -");
      if (raw.format !== undefined && raw.format !== null) {
        throw injectError("inject_bad_format", "format applies to a header, not to a query parameter");
      }
    }
    out.set(host, {
      host, header, query, format, secret: raw.secret,
      pathPrefixes: normalizeInjectPrefixes(raw.pathPrefixes),
      methods: normalizeInjectMethods(raw.methods),
    });
  }
  return out;
}

/**
 * The absolute-form request line's target, parsed without trusting it: an http
 * URL to a bare host name, port 80 (written or not), no userinfo, no fragment
 * and no trailing dot. `host` comes back even when the shape is refused, so the
 * log line names the host and nothing else, but only for a host name that is
 * well formed.
 */
function parseInjectTarget(rawTarget) {
  if (typeof rawTarget !== "string" || rawTarget.length > 4096) return { host: "", reason: "not an absolute-form http target" };
  const at = rawTarget.indexOf("://");
  if (at < 0 || rawTarget.slice(0, at).toLowerCase() !== "http") return { host: "", reason: "not an absolute-form http target" };
  let u = null;
  try { u = new URL(rawTarget); } catch { u = null; }
  if (!u || u.protocol !== "http:") return { host: "", reason: "not an absolute-form http target" };
  const host = String(u.hostname || "").toLowerCase();
  const name = HOSTNAME_RE.test(host) && !isIP(host)
    ? host
    : (host.endsWith(".") ? host.slice(0, -1) : "");
  const deny = (reason) => ({ host: name, reason });
  if (rawTarget.includes("#")) return deny("fragment refused");
  if (u.username || u.password) return deny("userinfo refused");
  if (host.endsWith(".")) return deny("trailing dot refused");
  if (!name) return deny("not a host name");
  // Only the default port: an inject host is one host, and a port is a second
  // destination the approval never named.
  if (u.port && Number(u.port) !== 80) return deny("port not allowed");
  // The path is read from the request line as it was WRITTEN, not from what the
  // URL parser made of it: normalisation happens once, in one place, on the
  // bytes that will be sent upstream.
  const rest = rawTarget.slice(at + 3);
  const slash = rest.indexOf("/");
  const qmark = rest.indexOf("?");
  const path = slash >= 0 ? rest.slice(slash) : "/" + (qmark >= 0 ? rest.slice(qmark) : "");
  return { host: name, path };
}

/** `path` with every parameter of `name` removed and `name=value` appended. */
function withInjectQuery(path, name, value) {
  const at = path.indexOf("?");
  const base = at < 0 ? path : path.slice(0, at);
  const query = at < 0 ? "" : path.slice(at + 1);
  const keep = query.split("&").filter((part) => {
    if (!part) return false;
    const eq = part.indexOf("=");
    const key = eq < 0 ? part : part.slice(0, eq);
    if (key === name) return false;
    let decoded = key;
    try { decoded = decodeURIComponent(key.replace(/\+/g, " ")); } catch { decoded = key; }
    return decoded !== name;
  });
  keep.push(name + "=" + value);
  return base + "?" + keep.join("&");
}

/**
 * One percent-decode of a path segment, or null when an escape is not two hex
 * digits: a broken escape does not read the same way twice, so it is refused
 * rather than guessed at. Bytes are kept as latin1 code units, so re-encoding
 * one is exact.
 */
function decodePathSegment(text) {
  let out = "";
  for (let i = 0; i < text.length; i++) {
    const ch = text[i];
    if (ch !== "%") { out += ch; continue; }
    const hex = text.slice(i + 1, i + 3);
    if (!/^[0-9A-Fa-f]{2}$/.test(hex)) return null;
    out += String.fromCharCode(parseInt(hex, 16));
    i += 2;
  }
  return out;
}

/** A decoded segment in the one spelling that goes on the wire (latin1 bytes). */
function encodePathSegment(seg) {
  let out = "";
  for (let i = 0; i < seg.length; i++) {
    const ch = seg[i];
    if (INJECT_PCHAR.test(ch)) out += ch;
    else out += "%" + (seg.charCodeAt(i) & 0xff).toString(16).toUpperCase().padStart(2, "0");
  }
  return out;
}

/**
 * The path an inject request is JUDGED on and the bytes it is SENT with: one
 * percent-decode per segment, dot segments dropped, double slashes collapsed,
 * re-encoded to one canonical spelling. Check and use are the same bytes by
 * construction, so an encoding cannot read as one path here and another at the
 * upstream. An encoded `/`, `\` or NUL, a control character, or a `..` that
 * survives the decode is refused: those are the shapes that name two routes.
 * @returns {{path: string, full: string}|{reason: string}}
 */
function normalizeInjectPath(rawTarget) {
  const text = String(rawTarget ?? "");
  const at = text.indexOf("?");
  const rawPath = at < 0 ? text : text.slice(0, at);
  const query = at < 0 ? "" : text.slice(at);
  const reason = "inject_path_not_allowed";
  if (!rawPath.startsWith("/")) return { reason };
  // A space or a control character in the query would end the request line
  // early, whatever the upstream made of the path.
  if (/[\u0000-\u0020\u007f]/.test(query)) return { reason };
  const kept = [];
  for (const rawSeg of rawPath.split("/")) {
    if (rawSeg === "") continue;
    const seg = decodePathSegment(rawSeg);
    if (seg === null) return { reason };
    if (seg === ".") continue;
    if (seg.includes("..") || seg.includes("/") || seg.includes("\\") || /[\u0000-\u001f\u007f]/.test(seg)) {
      return { reason };
    }
    kept.push(encodePathSegment(seg));
  }
  let path = "/" + kept.join("/");
  if (kept.length && rawPath.endsWith("/")) path += "/";
  return { path, full: path + query };
}

/** Does `path` sit at, or below, one of `prefixes`, at a path-segment boundary? */
function pathAllowed(path, prefixes) {
  for (const p of prefixes) {
    if (p.endsWith("/")) { if (path.startsWith(p)) return true; }
    else if (path === p || path.startsWith(p + "/")) return true;
  }
  return false;
}

/** Is this response header one that can carry a derived credential (so: dropped)? */
const dropsDerivedCredential = (name) => {
  const lower = String(name || "").toLowerCase();
  return INJECT_DROP_RESPONSE.has(lower)
    || INJECT_DROP_RESPONSE_RE.test(lower)
    || INJECT_DROP_RESPONSE_SUFFIX_RE.test(lower);
};

/**
 * @param {object} o
 * @param {string} o.dir            fresh dir for the socket (created 0700, removed on close)
 * @param {string} o.botId
 * @param {number} o.gatewayPort    the one loopback port served, over the doors only
 * @param {boolean} [o.doorFilter=true]  test seam: false forwards without the door check
 * @param {string[]|null} o.egressAllow
 * @param {number[]} [o.egressPorts=[443]]
 * @param {object} [o.local]        readLocalTable result (test seam); default: the cached kernel LOCAL table
 * @param {string[]} [o.hostAddrs]  extra own addresses
 * @param {string[]} [o.denyNets]   operator-denied networks (default CROW_PI_EGRESS_DENY_NETS)
 * @param {number} [o.maxConns=64]
 * @param {number} [o.maxUpstream=maxConns]  requests in flight upstream, relay-wide
 * @param {number} [o.headTimeoutMs=10000]
 * @param {number} [o.idleMs=120000]  idle keep-alive timeout on a door connection
 * @param {number} [o.abandonMs=30000]  a bot that half-closes while its request waits: closed after this
 * @param {Function} [o.lookup]     async (host) => [{address, family}]
 * @param {Array} [o.inject]        credential injection: [{host, pathPrefixes, methods?, header|query, format?, secret: () => string}]
 * @param {object} [o._injectUpstreamTls]  test seam: {ca} adds trust anchors for the inject upstream
 * @param {Function} [o.log]
 * @returns {Promise<{dir, socketPath, close: () => Promise<void>}>}
 */
export async function startEgressRelay(o) {
  const r = createEgressRelay(o);
  await r.ready;
  return r;
}

/**
 * Synchronous start (PiRpc spawns synchronously): the socket is bound by the
 * time pi can connect; `ready` settles when it is listening. A bind failure
 * leaves the bot with no network at all (fail closed) and is logged.
 */
export function createEgressRelay(o) {
  // An `inject` list is judged before anything is created: a bad entry is a
  // construction error, not a relay that listens and then refuses everything.
  const injectRules = normalizeInject(o.inject, Array.isArray(o.egressAllow) ? o.egressAllow : null);
  const dir = o.dir;
  mkdirSync(dir, { recursive: true, mode: 0o700 });
  chmodSync(dir, 0o700);
  const socketPath = join(dir, "relay.sock");
  // The gateway port is the ONE loopback port a contained bot reaches, and
  // only over the doors below: nothing else on loopback is policy here.
  const gatewayPort = Number(o.gatewayPort) || 0;
  // Test seam: false still forwards through node:http and still sets the mark,
  // but skips the door check — the way to prove the gateway-side guard alone.
  const doorFilter = o.doorFilter !== false;
  // CONNECT is for TLS; plain http:// needs an absolute-form GET, which this
  // relay does not proxy. 443 by default.
  const ports = new Set((o.egressPorts || [443]).map(Number));
  const allow = Array.isArray(o.egressAllow) ? o.egressAllow : null;
  // A walled add-on's relay. Absent for a bot: every `if (addon)` branch below
  // is then unreachable and the bot path is unchanged.
  const addon = o.addon && typeof o.addon === "object" ? o.addon : null;
  const cfg = addon ? normalizeAddon(addon) : null;
  // Injection is a bot-relay feature only: a walled add-on's relay has its own
  // lists and never sees this path.
  const injectOn = injectRules.size > 0 && !addon;
  const log = o.log || ((l) => console.error(l));
  const local = { local: o.local, hostAddrs: o.hostAddrs,
    denyNets: o.denyNets || String(process.env.CROW_PI_EGRESS_DENY_NETS || "").split(",").map((x) => x.trim()).filter(Boolean) };
  // In add-on mode the wall's own selfTargets are own addresses TOO: a
  // destination that resolves to this host in a wrapped form (NAT64, 6to4,
  // v4-mapped) or in another IPv6 spelling must read as "this host", which is
  // not a soft reason a listed entry may override. A separate object keeps the
  // bot path's view exactly as it was.
  const addonLocal = addon && cfg.selfAddrs.size
    ? { ...local, hostAddrs: [...(Array.isArray(o.hostAddrs) ? o.hostAddrs : []), ...cfg.selfAddrs] }
    : local;
  if (local.denyNets.length && localView({ local: { v4: [], v6: [], v4Failed: false, v6Failed: false }, denyNets: local.denyNets }).denyBroken) {
    log(`[pi-egress] bot=${o.botId || "?"} CROW_PI_EGRESS_DENY_NETS has an unreadable entry: this relay refuses every target until it is fixed`);
  }
  // One line per relay when this host's own addresses cannot be read: from
  // then every target is refused, which the operator must see in the log.
  let ownHostViewLogged = false;
  const noteOwnHostView = (view) => {
    if (!view.failed || ownHostViewLogged) return;
    ownHostViewLogged = true;
    log(`[pi-egress] bot=${o.botId || "?"} own-host view unreadable: refusing every target`);
  };
  const maxConns = o.maxConns ?? 64;
  // Relay-wide cap on requests in flight upstream: one bot connection holds at
  // most one at a time (below), and every connection together no more than this.
  const maxUpstream = o.maxUpstream ?? maxConns;
  const headTimeoutMs = o.headTimeoutMs ?? 10000;
  const idleMs = o.idleMs ?? 120000;
  const abandonMs = o.abandonMs ?? 30000;
  // A plain-HTTP upstream that accepts and then stalls would hold a relay slot
  // for the rest of the spawn: an idle upstream socket is cut after this.
  const plainStallMs = o.plainStallMs ?? 30000;
  const lookup = o.lookup || ((h) => dnsLookup(h, { all: true, verbatim: true }));
  // One line per (decision, target), bounded: a bot that sprays distinct
  // hosts must not grow the spawner's memory (one summary line instead).
  const logged = new Set();
  let suppressed = 0;
  // Add-on mode keeps the last refused targets for the owner's status card.
  const denials = [];
  const note = (decision, target, reason) => {
    const key = decision + " " + target;
    if (logged.has(key)) return;
    if (logged.size >= MAX_LOGGED) {
      if (suppressed++ === 0) log((addon ? `[addon-egress] addon=${cfg.id}` : `[pi-egress] bot=${o.botId || "?"}`) + ` more than ${MAX_LOGGED} distinct targets; further decisions are not logged`);
      return;
    }
    logged.add(key);
    if (addon) {
      if (decision === "deny") {
        denials.push(String(target).slice(0, 200));
        if (denials.length > MAX_DENIALS) denials.shift();
      }
      log(`[addon-egress] addon=${cfg.id} ${decision} ${target}${reason ? " (" + reason + ")" : ""}`);
      return;
    }
    log(`[pi-egress] bot=${o.botId || "?"} ${decision} ${target}${reason ? " (" + reason + ")" : ""}`);
  };
  let live = 0;
  let upstreamLive = 0;
  const sockets = new Set();

  /**
   * Splice client <-> upstream. Candidates are already-checked addresses,
   * tried in order (dual-stack hosts whose first address has no route). Ends
   * are propagated gracefully (half-close kept); each side is destroyed only
   * on error or once both directions are done.
   */
  const splice = (client, candidates, port, preface) => {
    let i = 0;
    let up = null;
    // The client's own listeners are registered ONCE, outside the retry loop:
    // a second attempt must not stack another pair on the same socket.
    const dropUp = () => { try { if (up && !up.destroyed) up.destroy(); } catch {} };
    client.on("error", dropUp);
    client.once("close", () => {
      if (up && !up.destroyed) up.end();
      const t = setTimeout(dropUp, 30000);
      if (t.unref) t.unref();
    });
    const tryNext = () => {
      if (client.destroyed) return;
      const addr = candidates[i++];
      const target = o._connectOverride ? o._connectOverride(addr, port) : { host: addr, port, allowHalfOpen: true };
      up = netConnect({ ...target, allowHalfOpen: true });
      const mine = up;
      sockets.add(mine);
      mine.once("close", () => sockets.delete(mine));
      let connected = false;
      mine.once("connect", () => {
        connected = true;
        if (client.destroyed) { mine.destroy(); return; }
        if (preface) client.write(preface);
        client.pipe(mine); mine.pipe(client);
      });
      mine.on("error", () => {
        if (!connected && i < candidates.length && !client.destroyed) { mine.destroy(); tryNext(); return; }
        if (!connected && preface) { try { client.end("HTTP/1.1 502 Bad Gateway\r\n\r\n"); } catch {} }
        else { try { client.destroy(); } catch {} }
        mine.destroy();
      });
      mine.once("close", () => { if (connected && !client.destroyed) { client.end(); setTimeout(() => client.destroy(), 30000).unref(); } });
    };
    tryNext();
  };

  const refuse = (c, status, text) => { try { c.end(`HTTP/1.1 ${status} ${text}\r\nConnection: close\r\n\r\n`); } catch {} };

  // ---- the doors (containment PR 6) ---------------------------------------
  // The gateway port is no longer spliced. One node:http parser terminates the
  // bot's connection, so EVERY request on it is judged (a spliced connection
  // carried a second request past any one-shot check), upgrades never reach
  // the gateway, and each upstream socket is opened from RELAY_SOURCE_V4 — the
  // mark the gateway refuses for /internal (middleware/internal-guard.js) and
  // the #614 caller check refuses outright. This process runs outside the
  // sandbox, so a bot cannot choose its own source address.
  // A client that sends its request and then FIN must still get the reply (a
  // hand-rolled bot HTTP client may half-close). Node reads this off the
  // server, not from createServer() options.
  const doors = createHttpServer({ requestTimeout: 0, headersTimeout: 60000 });
  doors.httpAllowHalfOpen = true;
  // One connection may hold 1000 requests; beyond that the parser stops
  // (a cheap bound on a bot that never stops asking on one socket).
  doors.maxRequestsPerSocket = 1000;
  // What the relay advertises (Keep-Alive: timeout=) is what it enforces.
  doors.keepAliveTimeout = idleMs;
  // Per-connection pipeline bound: one request in flight, this many waiting.
  const MAX_QUEUED = 8;
  // Methods with no body: nothing here can frame one for the gateway's wire.
  const BODILESS = new Set(["GET", "HEAD", "DELETE", "OPTIONS", "TRACE"]);
  // Hop-by-hop headers belong to the relay's own hop: passing them through
  // would let a body be framed twice (transfer-encoding) or a connection be
  // kept alive in a way the parser here has no say over.
  const HOP_BY_HOP = new Set(["connection", "keep-alive", "proxy-connection", "proxy-authenticate",
    "proxy-authorization", "te", "trailer", "transfer-encoding", "upgrade"]);
  // Headers that tell the gateway who a request came from (a proxy hop, a
  // Tailscale Serve login, a client address). The relay is the only hop a
  // contained bot has, so a bot never gets to speak for one: classifyPeer
  // would otherwise read a forged Serve shape (X-Forwarded-For + -Host) and a
  // Tailscale-User-Login off a door request.
  const IDENTITY = /^(?:forwarded|x-forwarded-.*|x-real-ip|x-client-ip|true-client-ip|cf-connecting-ip|tailscale-.*)$/;
  const targetOf = (req) => `${req.method} ${String(req.url || "").slice(0, 80)}`;
  const endToEnd = (from, { request = false } = {}) => {
    const out = {};
    for (const [k, v] of Object.entries(from || {})) {
      if (HOP_BY_HOP.has(k)) continue;
      if (request && IDENTITY.test(k)) continue;
      out[k] = v;
    }
    return out;
  };

  /** A refusal the relay writes itself: nothing is opened upstream, and the
   *  connection does not survive it (`Connection: close`). */
  function refuseWith(req, res, status, code, reason) {
    note("deny", targetOf(req), reason);
    const body = JSON.stringify({ error: code });
    try {
      res.shouldKeepAlive = false;
      res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(body), connection: "close" });
      res.end(body);
    } catch { try { req.socket.destroy(); } catch {} }
  }

  /** A path/method the doors do not serve. */
  function refuseDoor(req, res, reason) { refuseWith(req, res, 403, "forbidden", reason); }

  /** More work than the relay will carry (a full pipeline queue, the upstream
   *  cap): nothing is opened upstream. */
  function refuseUnavailable(req, res, reason) { refuseWith(req, res, 503, "unavailable", reason); }

  /** A raw-socket refusal ('upgrade', 'connect'): no HTTP parser owns it yet. */
  function refuseRaw(req, socket, reason) {
    note("deny", targetOf(req), reason);
    try { socket.end("HTTP/1.1 403 Forbidden\r\nConnection: close\r\nContent-Length: 0\r\n\r\n"); } catch {}
    const t = setTimeout(() => { try { socket.destroy(); } catch {} }, 1000);
    if (t.unref) t.unref();
  }

  /** Upstream trouble (including a failed bind of the mark): fail closed. */
  function failDoor(req, res, e) {
    note("deny", targetOf(req), "upstream " + ((e && e.code) || "error"));
    if (res.headersSent) { try { res.destroy(); } catch {} return; }
    const body = JSON.stringify({ error: "bad gateway" });
    try {
      res.shouldKeepAlive = false;
      res.writeHead(502, { "content-type": "application/json", "content-length": Buffer.byteLength(body), connection: "close" });
      res.end(body);
    } catch { try { req.socket.destroy(); } catch {} }
  }

  /** The headers sent upstream: end-to-end only, and a body is always framed. */
  function upstreamHeaders(req) {
    const out = endToEnd(req.headers, { request: true });
    // The client's own framing is hop-by-hop and was stripped above. A decoded
    // body written after headers with no framing is a SECOND request on the
    // gateway's wire, so re-declare what the client already used.
    if (req.headers["transfer-encoding"] !== undefined && req.headers["content-length"] === undefined) {
      out["transfer-encoding"] = "chunked";
    }
    return out;
  }

  function forwardDoor(req, res) {
    // Relay-wide: a flood of bot connections must not become a flood of
    // upstream sockets either.
    if (upstreamLive >= maxUpstream) return refuseUnavailable(req, res, "relay upstream cap " + maxUpstream);
    let up;
    try {
      up = httpRequest({
        host: "127.0.0.1", port: gatewayPort, localAddress: addon ? ADDON_RELAY_SOURCE_V4 : RELAY_SOURCE_V4,
        method: req.method, path: req.url, headers: upstreamHeaders(req),
        // No pooling: the mark belongs to this request's socket, and a pooled
        // socket would outlive the request that earned it.
        agent: false,
      });
    } catch (e) { return failDoor(req, res, e); }
    upstreamLive++;
    let released = false;
    const release = () => { if (!released) { released = true; upstreamLive--; } };
    up.on("error", (e) => { release(); failDoor(req, res, e); });
    up.on("close", release);
    up.on("response", (ur) => {
      try {
        res.writeHead(ur.statusCode || 502, endToEnd(ur.headers));
        // Streamed both ways: an SSE answer arrives chunk by chunk and no body
        // is ever held whole in this process.
        ur.pipe(res);
        // An upstream that dies mid-body would leave the bot's connection
        // half-answered for the rest of the spawn: destroy it, so the bot's
        // own client sees a reset and not a body that never ends.
        const cut = () => { if (!ur.complete) { try { res.destroy(); } catch {} } };
        ur.on("error", cut);
        ur.on("aborted", cut);
        ur.on("close", cut);
      } catch (e) { try { ur.destroy(); } catch {} failDoor(req, res, e); }
    });
    // The bot hung up (or the socket died): stop the other leg too, so an SSE
    // stream nobody reads does not hold sockets for the rest of the spawn.
    res.on("close", () => { try { up.destroy(); } catch {} });
    // A bot that only half-closes (FIN) while this request waits would hold the
    // upstream socket and its cap slot for the rest of the spawn: an idle
    // answer never writes, so nothing would ever notice. A legitimate client
    // that sends its request and FIN still gets the reply; one whose answer
    // has not finished within abandonMs of its FIN is closed.
    const sock = req.socket;
    const onEnd = () => {
      const t = setTimeout(() => { try { sock.destroy(); } catch {} }, abandonMs);
      if (t.unref) t.unref();
      res.once("close", () => clearTimeout(t));
      res.once("finish", () => clearTimeout(t));
    };
    if (sock.readableEnded) onEnd(); else sock.once("end", onEnd);
    res.once("close", () => sock.removeListener("end", onEnd));
    req.pipe(up);
  }

  // ---- add-on mode: listed targets, the owner check, D1 plain HTTP --------
  // A walled add-on's loopback ports are spliced raw (WebSocket upgrades pass:
  // it is raw TCP) only after the listener's owner is checked against the
  // entry (who it belongs to, and whether the owner typed the URL), and an
  // absolute-form plain-HTTP request to a listed host:port gets one HTTP parser
  // of its own: one request per connection, `Connection: close` on every
  // answer, and the same target checks a listed CONNECT gets.
  const plainTargets = new WeakMap(); // socket -> { host, port, addr }
  const plainUsed = new WeakSet(); // sockets that have already had their one request
  const ownerCache = new Map(); // "port|ownerProject" -> { at, value }
  const plain = addon ? createHttpServer({ requestTimeout: 0, headersTimeout: 60000 }) : null;
  if (plain) {
    plain.httpAllowHalfOpen = true;
    plain.maxRequestsPerSocket = 1;
    plain.keepAliveTimeout = 0;
    plain.on("request", (req, res) => {
      const ht = headTimers.get(req.socket);
      if (ht) { clearTimeout(ht); headTimers.delete(req.socket); }
      const t = plainTargets.get(req.socket);
      if (!t) return refusePlain(req, res, "not a checked target");
      if (plainUsed.has(req.socket)) {
        refusePlain(req, res, "one request per connection");
        try { req.socket.destroy(); } catch {}
        return;
      }
      plainUsed.add(req.socket);
      const upgrade = req.headers.upgrade !== undefined
        || /(?:^|,)\s*upgrade\s*(?:,|$)/i.test(String(req.headers.connection || ""));
      if (req.method === "CONNECT" || upgrade) return refusePlain(req, res, "upgrade refused");
      if (BODILESS.has(req.method)
        && (req.headers["transfer-encoding"] !== undefined || Number(req.headers["content-length"] || 0) > 0)) {
        return refusePlain(req, res, "body on a bodiless method", 400);
      }
      let u = null;
      try { u = new URL(String(req.url || "")); } catch { u = null; }
      if (!u || u.protocol !== "http:") return refusePlain(req, res, "not an absolute-form target");
      const host = addonHost(u.hostname.replace(/^\[(.*)\]$/, "$1"));
      const port = u.port ? Number(u.port) : 80;
      if (host !== t.host || port !== t.port) return refusePlain(req, res, "a different target than was checked");
      forwardPlain(req, res, t, u.pathname + u.search);
    });
    plain.on("upgrade", (req, socket) => refuseRaw(req, socket, "upgrade refused"));
    plain.on("connect", (req, socket) => refuseRaw(req, socket, "CONNECT refused"));
    plain.on("clientError", (err, socket) => {
      if (!socket.writable || (err && err.code === "ECONNRESET")) { try { socket.destroy(); } catch {} return; }
      try { socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"); } catch { try { socket.destroy(); } catch {} }
    });
  }

  /** A plain-HTTP refusal: nothing was opened upstream, and the connection does not survive it. */
  function refusePlain(req, res, reason, status = 403) {
    note("deny", targetOf(req), reason);
    const body = JSON.stringify({ error: status === 400 ? "bad request" : status === 502 ? "bad gateway" : status === 503 ? "unavailable" : "forbidden" });
    try {
      res.shouldKeepAlive = false;
      res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(body), connection: "close" });
      res.end(body);
    } catch { try { req.socket.destroy(); } catch {} }
  }

  /** Upstream trouble on a plain-HTTP forward: fail closed (502, like a door). */
  function failPlain(req, res, e) {
    // The reason is noted in both cases: a stall after the headers has no
    // response left to carry it.
    const reason = "upstream " + ((e && e.code) || "error");
    if (res.headersSent) { note("deny", targetOf(req), reason); try { res.destroy(); } catch {} return; }
    refusePlain(req, res, reason, 502);
  }

  /** Forward one checked plain-HTTP request upstream, streamed both ways. */
  function forwardPlain(req, res, t, path) {
    if (upstreamLive >= maxUpstream) return refusePlain(req, res, "relay upstream cap " + maxUpstream, 503);
    const dest = cfg.httpTarget ? cfg.httpTarget(t.addr, t.port) : { host: t.addr, port: t.port };
    let up;
    try {
      up = httpRequest({ host: dest.host, port: dest.port, method: req.method, path, headers: upstreamHeaders(req), agent: false });
    } catch (e) { return failPlain(req, res, e); }
    upstreamLive++;
    let released = false;
    const release = () => { if (!released) { released = true; upstreamLive--; } };
    // An upstream that accepted and went quiet: before the response it is the
    // existing 502, after it the client's connection is destroyed.
    up.setTimeout(plainStallMs, () => {
      try { up.destroy(Object.assign(new Error("upstream idle timeout"), { code: "ETIMEDOUT" })); } catch {}
    });
    up.on("error", (e) => { release(); failPlain(req, res, e); });
    up.on("close", release);
    up.on("response", (ur) => {
      try {
        const headers = endToEnd(ur.headers);
        headers.connection = "close";
        res.shouldKeepAlive = false;
        res.writeHead(ur.statusCode || 502, headers);
        ur.pipe(res);
        const cut = () => { if (!ur.complete) { try { res.destroy(); } catch {} } };
        ur.on("error", cut);
        ur.on("aborted", cut);
        ur.on("close", cut);
      } catch (e) { try { ur.destroy(); } catch {} failPlain(req, res, e); }
    });
    res.on("close", () => { try { up.destroy(); } catch {} });
    req.pipe(up);
  }

  /** Hand a checked plain-HTTP connection to its parser (the head bytes are already back on the stream). */
  const enterPlain = (c) => {
    plain.emit("connection", c);
    const ht = setTimeout(() => { try { c.destroy(); } catch {} }, headTimeoutMs);
    if (ht.unref) ht.unref();
    headTimers.set(c, ht);
    c.once("close", () => { clearTimeout(ht); headTimers.delete(c); });
    c.on("timeout", () => { try { c.destroy(); } catch {} });
    c.resume();
  };

  // ---- inject mode: the credentialed upstream ----------------------------
  // The step's request is an absolute-form plain-HTTP request that reaches this
  // relay through the PROXY line. It is judged there (host, method, path) and
  // then handed to its own one-request HTTP parser, which sees the head and
  // body the client sent; `forwardInject` re-originates it over its own TLS.
  const injectedTargets = new WeakMap(); // socket -> { host, addrs, path: the normalised path and query }
  const injectedUsed = new WeakSet(); // sockets that have already had their one request
  const injected = injectOn ? createHttpServer({ requestTimeout: 0, headersTimeout: 60000 }) : null;
  if (injected) {
    injected.httpAllowHalfOpen = true;
    injected.maxRequestsPerSocket = 1;
    injected.keepAliveTimeout = 0;
    injected.on("request", (req, res) => {
      const ht = headTimers.get(req.socket);
      if (ht) { clearTimeout(ht); headTimers.delete(req.socket); }
      const t = injectedTargets.get(req.socket);
      if (!t) return refuseInject(req, res, 403, "forbidden", "not a checked target");
      if (injectedUsed.has(req.socket)) {
        refuseInject(req, res, 403, "forbidden", "one request per connection");
        try { req.socket.destroy(); } catch {}
        return;
      }
      injectedUsed.add(req.socket);
      forwardInject(req, res, t).catch(() => failInject(req, res, t.host));
    });
    // `Expect: 100-continue` would otherwise be answered by node itself.
    injected.on("checkContinue", (req, res) => refuseInject(req, res, 417, "expect_refused", "expect refused"));
    injected.on("upgrade", (req, socket) => refuseRaw(req, socket, "upgrade refused"));
    injected.on("connect", (req, socket) => refuseRaw(req, socket, "CONNECT refused"));
    injected.on("clientError", (err, socket) => {
      if (!socket.writable || (err && err.code === "ECONNRESET")) { try { socket.destroy(); } catch {} return; }
      try { socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"); } catch { try { socket.destroy(); } catch {} }
    });
  }

  /**
   * An inject-mode refusal. The reason is a fixed string: nothing from node, TLS
   * or the upstream (and nothing from the request) reaches the log or the
   * client, and the note carries the host only.
   */
  function refuseInject(req, res, status, code, reason, host = null) {
    const target = host || (injectedTargets.get(req.socket) || {}).host || "inject request";
    note("deny", target, reason);
    const body = JSON.stringify({ error: code });
    try {
      res.useChunkedEncodingByDefault = false;
      res.shouldKeepAlive = false;
      res.writeHead(status, { "content-type": "application/json", "content-length": Buffer.byteLength(body), connection: "close" });
      res.end(body);
    } catch { try { req.socket.destroy(); } catch {} }
  }

  /** Upstream trouble on an inject request: one fixed reason, no error text. */
  function failInject(req, res, host) {
    if (res.headersSent || res.writableEnded || res.destroyed) {
      note("deny", host, "inject upstream failed");
      try { res.destroy(); } catch {}
      return;
    }
    refuseInject(req, res, 502, "bad_gateway", "inject upstream failed", host);
  }

  /**
   * One checked inject request: attach the credential to a TLS request of our
   * own and stream the answer back redacted.
   */
  async function forwardInject(req, res, t) {
    const rule = injectRules.get(t.host);
    if (!rule) return refuseInject(req, res, 403, "forbidden", "not an inject host", t.host);
    // Judged again on the bytes this function is about to send: the request
    // line's head and the parser's request are re-read here, so a difference
    // between what was checked and what is written cannot survive.
    if (!rule.methods.has(req.method)) {
      return refuseInject(req, res, 405, "inject_method_not_allowed", "inject_method_not_allowed", t.host);
    }
    const judged = normalizeInjectPath(t.path);
    if (judged.reason || !pathAllowed(judged.path, rule.pathPrefixes)) {
      return refuseInject(req, res, 403, "inject_path_not_allowed", "inject_path_not_allowed", t.host);
    }
    // Framing: only a declared Content-Length body is carried, so what leaves
    // here is one request and one body with no chunk framing to reinterpret.
    if (req.headers["transfer-encoding"] !== undefined) {
      return refuseInject(req, res, 411, "chunked_request_refused", "chunked_request_refused", t.host);
    }
    if (req.headers.expect !== undefined) {
      return refuseInject(req, res, 417, "expect_refused", "expect refused", t.host);
    }
    const declared = req.headers["content-length"];
    let bodyLen = 0;
    if (declared !== undefined) {
      if (!/^\d+$/.test(String(declared))) return refuseInject(req, res, 400, "bad_request", "bad content length", t.host);
      bodyLen = Number(declared);
      if (bodyLen > INJECT_MAX_REQUEST) {
        return refuseInject(req, res, 413, "request_too_large", "request body too large", t.host);
      }
    }
    if (upstreamLive >= maxUpstream) {
      return refuseInject(req, res, 503, "unavailable", "relay upstream cap " + maxUpstream, t.host);
    }
    // The credential: read once for this request, used once. Nothing is sent
    // when it is missing or too short to be worth redacting.
    let secret = null;
    try { secret = rule.secret(); } catch { secret = null; }
    if (typeof secret !== "string" || Buffer.byteLength(secret, "utf8") < INJECT_SECRET_MIN_BYTES) {
      return refuseInject(req, res, 503, "inject_secret_missing", "inject_secret_missing", t.host);
    }
    // What the upstream may echo: the bytes that were injected, and the bare
    // secret (a server that splits a formatted value may quote the bare part).
    // A format holding `$&`, `$'` or `` $` `` is literal text around the value, never a
    // replacement pattern: the secret goes in whole, as it is.
    const attached = rule.header ? rule.format.split("{}").join(secret) : encodeURIComponent(secret);
    const echoForms = [attached, secret];
    // The request carries an allowlist of headers and nothing else (INJECT_REQUEST_HEADERS):
    // a header a client could use to override the method, rewrite the path, name a hop or
    // pick the answer's charset never leaves this relay. A client may not name the
    // credential's own header either: a step cannot choose its own credential.
    const headers = {};
    for (const name of INJECT_REQUEST_HEADERS) {
      if (rule.header && name === rule.header.toLowerCase()) continue;
      const v = req.headers[name];
      if (v !== undefined) headers[name] = v;
    }
    headers["accept-encoding"] = "identity";
    headers["host"] = t.host;
    headers["connection"] = "close";
    headers["content-length"] = String(bodyLen);
    let path = judged.full;
    if (rule.header) headers[rule.header.toLowerCase()] = attached;
    else path = withInjectQuery(path, rule.query, attached);
    // The address was checked when the connection arrived; connect to that
    // address, not to the name again (no DNS rebinding), and verify the
    // certificate against the host the approval named.
    const addr = t.addrs[0];
    const dest = o._connectOverride ? o._connectOverride(addr, 443) : { host: addr, port: 443 };
    const opts = {
      host: dest.host, port: dest.port, method: req.method, path, headers,
      servername: t.host, rejectUnauthorized: true, minVersion: "TLSv1.2",
      ALPNProtocols: ["http/1.1"], agent: false,
    };
    // A test seam only: extra trust anchors, never a weaker check.
    if (o._injectUpstreamTls && o._injectUpstreamTls.ca) opts.ca = o._injectUpstreamTls.ca;
    let up;
    try { up = httpsRequest(opts); } catch { return failInject(req, res, t.host); }
    upstreamLive++;
    let released = false;
    const release = () => { if (!released) { released = true; upstreamLive--; } };
    // Set once this request's answer is decided (refused whole, capped, or sent
    // to its last byte): a socket error after that is teardown, not a new
    // failure, and must not rewrite an answer the client already has.
    let finished = false;
    up.setTimeout(plainStallMs, () => {
      try { up.destroy(Object.assign(new Error("upstream idle timeout"), { code: "ETIMEDOUT" })); } catch {}
    });
    up.on("error", () => { release(); if (finished) return; failInject(req, res, t.host); });
    up.on("close", release);
    // One place that refuses a whole answer: the upstream socket is destroyed
    // before any body byte is forwarded, and the client gets one fixed 502.
    const refuseAnswer = (ur, reason) => {
      if (finished) return;
      finished = true;
      note("deny", t.host, reason);
      try { ur.destroy(); } catch {}
      try { up.destroy(); } catch {}
      const body = "upstream response refused";
      try {
        res.useChunkedEncodingByDefault = false;
        res.shouldKeepAlive = false;
        res.writeHead(502, { "content-type": "text/plain", "content-length": Buffer.byteLength(body), connection: "close" });
        res.end(body);
      } catch { try { req.socket.destroy(); } catch {} }
    };
    up.on("response", (ur) => {
      // One slice of a body is a body this relay cannot judge: a 206, or any
      // Content-Range, is refused whole and nothing of it is forwarded.
      if (ur.statusCode === 206 || Object.keys(ur.headers).some((k) => k.toLowerCase() === "content-range")) {
        return refuseAnswer(ur, "partial_response_refused");
      }
      // An encoded answer cannot be judged by this relay, so it is not passed
      // on at all: nothing of its body reaches the client.
      const encoding = String(ur.headers["content-encoding"] || "").trim().toLowerCase();
      if (encoding && encoding !== "identity") return refuseAnswer(ur, "encoded_response_refused");
      // A wide-character answer is not the text the step asked for: an echo in UTF-16 or
      // UTF-32 shares no bytes with the injected value, so the relay cannot judge it.
      const charset = String(ur.headers["content-type"] || "");
      if (INJECT_WIDE_CHARSET_RE.test(charset)) return refuseAnswer(ur, "charset_refused");
      const out = {};
      for (const [k, v] of Object.entries(ur.headers)) {
        const lower = k.toLowerCase();
        if (HOP_BY_HOP.has(lower) || lower.startsWith("proxy-")) continue;
        // Redaction can shorten a body, so its length is never carried over:
        // the answer is framed by closing the connection.
        if (lower === "content-length") continue;
        // A header that can carry a credential the endpoint minted from this
        // one is dropped, never redacted and passed on.
        if (dropsDerivedCredential(lower)) continue;
        out[lower] = v;
      }
      const redacted = redactHeaderValues(out, echoForms);
      // The head is judged before it is written: an exact echo was replaced
      // above, and a PARTIAL echo is still bytes of the secret, so a header
      // holding one refuses the whole answer.
      const headTaint = createTaintDetector(echoForms, { window: INJECT_TAINT_WINDOW });
      for (const v of Object.values(redacted)) {
        const text = Array.isArray(v) ? v.join("\n") : String(v ?? "");
        if (headTaint.scan(Buffer.from(text, "latin1"))) return refuseAnswer(ur, "tainted_response_refused");
      }
      redacted.connection = "close";
      const redactor = createStreamRedactor(echoForms);
      const taint = createTaintDetector(echoForms, { window: INJECT_TAINT_WINDOW });
      let sent = 0;
      // The bytes the taint detector has not yet had a full window to judge.
      // They are never written, so a window found late cannot leave with its
      // first bytes already on the wire (the redactor's own held-back tail sits
      // inside this window of raw bytes as well).
      let held = Buffer.alloc(0);
      // The head goes on the wire with the FIRST body byte and not before: the first bytes
      // decide whether this answer is in a charset the relay cannot judge (a BOM), and a 502
      // is only a refusal if no part of the answer has been sent.
      let headWritten = false;
      const writeHeadOnce = () => {
        if (headWritten) return true;
        headWritten = true;
        try {
          res.useChunkedEncodingByDefault = false;
          res.shouldKeepAlive = false;
          res.writeHead(ur.statusCode || 502, redacted);
          res.flushHeaders();
          return true;
        } catch {
          return false;
        }
      };
      let rawHead = Buffer.alloc(0);
      let bomChecked = false;
      /** Judge the body's first bytes; false means the answer was refused whole. */
      const judgeBom = (chunk, final) => {
        if (bomChecked) return true;
        if (chunk.length) rawHead = Buffer.concat([rawHead, chunk]).subarray(0, 4);
        if (rawHead.length < 4 && !final) return true;
        bomChecked = true;
        if (!startsWithWideBom(rawHead)) return true;
        refuseAnswer(ur, "charset_refused");
        return false;
      };
      const write = (buf) => {
        if (!buf.length) return true;
        if (!writeHeadOnce()) { finished = true; return false; }
        if (sent + buf.length > INJECT_MAX_RESPONSE) {
          finished = true;
          const room = INJECT_MAX_RESPONSE - sent;
          if (room > 0) { try { res.write(buf.subarray(0, room)); } catch {} }
          note("deny", t.host, "response too large");
          try { ur.destroy(); } catch {}
          try { res.destroy(); } catch {}
          return false;
        }
        sent += buf.length;
        try { res.write(buf); } catch { return false; }
        return true;
      };
      /** Scan, then write only what no window can still reach. */
      const forward = (buf, final) => {
        const all = held.length ? Buffer.concat([held, buf]) : buf;
        if (taint.scan(buf)) {
          if (finished) return false;
          // Before the head is on the wire the whole answer can be refused: the client gets one
          // 502 and never a status it would read as an answer.
          if (!headWritten) { refuseAnswer(ur, "tainted_response_refused"); return false; }
          // Both ends go at once: the client sees the answer cut, never the
          // bytes of the window that was found.
          finished = true;
          note("deny", t.host, "tainted_response_refused");
          try { ur.destroy(); } catch {}
          try { up.destroy(); } catch {}
          try { req.socket.destroy(); } catch {}
          try { res.destroy(); } catch {}
          return false;
        }
        const cut = final ? all.length : Math.max(0, all.length - taint.holdback);
        held = Buffer.from(all.subarray(cut));
        return cut ? write(all.subarray(0, cut)) : true;
      };
      ur.on("data", (chunk) => {
        if (!judgeBom(chunk, false)) return;
        forward(redactor.push(chunk), false);
      });
      ur.on("end", () => {
        if (!judgeBom(Buffer.alloc(0), true)) return;
        if (!forward(redactor.end(), true)) return;
        if (!writeHeadOnce()) { finished = true; return; }
        finished = true;
        try { res.end(); } catch {}
      });
      const cut = () => { if (finished) return; try { res.destroy(); } catch {} };
      ur.on("error", cut);
      ur.on("aborted", cut);
    });
    res.on("close", () => { try { up.destroy(); } catch {} });
    req.on("error", () => { try { up.destroy(); } catch {} });
    if (bodyLen > 0) req.pipe(up);
    else { req.resume(); up.end(); }
  }

  /** Hand a checked inject connection to its parser (the head bytes are already back on the stream). */
  const enterInject = (c) => {
    injected.emit("connection", c);
    const ht = setTimeout(() => { try { c.destroy(); } catch {} }, headTimeoutMs);
    if (ht.unref) ht.unref();
    headTimers.set(c, ht);
    c.once("close", () => { clearTimeout(ht); headTimers.delete(c); });
    c.on("timeout", () => { try { c.destroy(); } catch {} });
    c.resume();
  };

  /**
   * An absolute-form plain-HTTP request on the PROXY line, when this relay has
   * an inject list: accepted only for an inject host, over the same closed-
   * network checks a CONNECT gets, and only for a method a report step needs.
   * Any throw on the way ends the connection with a fixed reason, never with an
   * error text.
   */
  async function handleInject(c, headText) {
    try {
      return await acceptInject(c, headText);
    } catch {
      note("deny", "inject request", "inject request failed");
      refuse(c, 502, "Bad Gateway");
      try { c.destroy(); } catch {}
    }
  }

  /** The checks an inject request goes through before its own parser sees it. */
  async function acceptInject(c, headText) {
    const line = String(headText).split("\r\n")[0] || "";
    const m = line.match(/^(\S+)\s+(\S+)\s+HTTP\/1\.[01]$/);
    if (!m) return refuse(c, 400, "Bad Request");
    const parsed = parseInjectTarget(m[2]);
    if (parsed.reason) {
      note("deny", parsed.host || "inject request", parsed.reason);
      return refuse(c, 403, "Forbidden");
    }
    const host = parsed.host;
    const rule = injectRules.get(host);
    if (!rule) { note("deny", host, "not an inject host"); return refuse(c, 403, "Forbidden"); }
    // What this rule allows, judged before anything is resolved or opened: a
    // method it does not name, and a path outside its prefixes, cost no DNS
    // query and no connection.
    if (!INJECT_METHODS.has(m[1]) || !rule.methods.has(m[1])) {
      note("deny", host, "inject_method_not_allowed");
      return refuse(c, 405, "Method Not Allowed");
    }
    const judged = normalizeInjectPath(parsed.path);
    if (judged.reason || !pathAllowed(judged.path, rule.pathPrefixes)) {
      note("deny", host, "inject_path_not_allowed");
      return refuse(c, 403, "Forbidden");
    }
    let addrs = null;
    try { addrs = await lookup(host); } catch { note("deny", host, "does not resolve"); return refuse(c, 502, "Bad Gateway"); }
    if (!Array.isArray(addrs) || !addrs.length) { note("deny", host, "no address"); return refuse(c, 403, "Forbidden"); }
    const view = localView(local); // one host view per request, as for a CONNECT
    noteOwnHostView(view);
    const why = addrs.map((a) => egressDenyReason(a && a.address, { view })).find(Boolean);
    if (why) { note("deny", host, why); return refuse(c, 403, "Forbidden"); }
    if (c.destroyed || c.readableEnded) { try { c.destroy(); } catch {} return; }
    note("allow", host, "resolved " + addrs.map((a) => a.address).join(", "));
    injectedTargets.set(c, { host, addrs: addrs.map((a) => a.address), path: judged.full });
    c.pause();
    // The head goes back on the stream AFTER the bytes that came with it.
    c.unshift(Buffer.from(headText + "\r\n\r\n", "latin1"));
    enterInject(c);
  }

  /** Resolve and check one listed target: a CONNECT entry or a D1 plain-HTTP entry. */
  async function checkListedTarget(host) {
    if (cfg.selfNames.has(host)) return { reason: "own host" };
    let addrs;
    if (isIP(host)) addrs = [{ address: host, family: isIP(host) }];
    else {
      try { addrs = await lookup(host); } catch { return { reason: "does not resolve", unresolved: true }; }
    }
    if (!Array.isArray(addrs) || !addrs.length) return { reason: "no address" };
    if (addrs.some((a) => cfg.selfAddrs.has(canonTargetAddr(a && a.address)))) return { reason: "own host" };
    const view = localView(addonLocal); // one host view per decision
    noteOwnHostView(view);
    for (const a of addrs) {
      const r = listedAddrReason(a && a.address, view);
      if (r) return { reason: r };
    }
    // A listed entry may name a container on this computer (a bridge address,
    // or a container's own address): only this add-on's compose project, or
    // the one named TTS exception, may be reached there.
    for (const a of addrs) {
      const addr = a && a.address;
      const v = cfg.containerOwner ? await containerOwnerOf(addr) : containerAddrFallback(addr);
      // Only the two passing answers pass: anything else (a denial, an
      // unexpected shape) is a refusal.
      if (!v || (v.kind !== "docker-container" && v.kind !== "not-container")) {
        return { reason: "a container on this computer: " + ((v && v.kind === "denied" && v.reason) || "owner check failed") };
      }
    }
    return { addrs };
  }

  /** The owner answer for a listed loopback port, cached per port and ownerProject. */
  async function ownerOf(port, ownerProject) {
    const key = port + "|" + (ownerProject || "");
    const now = Date.now();
    const hit = ownerCache.get(key);
    if (hit && now - hit.at <= cfg.ownerCacheMs) return hit.value;
    let value = null;
    try {
      value = cfg.listenerOwner ? await cfg.listenerOwner("127.0.0.1", port) : null;
      if (!value || typeof value !== "object") value = { kind: "denied", reason: "owner check failed" };
    } catch { value = { kind: "denied", reason: "owner check failed" }; }
    ownerCache.set(key, { at: now, value });
    return value;
  }

  // ---- add-on mode: a listed address that belongs to a container ----------
  // A listed host:port may resolve into this computer's docker/podman network.
  // The caller's containerOwner (the gateway's docker view) names the compose
  // project behind that address; without one, a bridge address is refused.
  const containerCache = new Map(); // address -> { at, value }
  let bridgeCache = null;
  /** This computer's bridge ranges, read once per relay. */
  const bridgeSubnets = () => {
    if (!bridgeCache) {
      // No list given: the interface read happens in listener-owner.mjs.
      try { bridgeCache = bridgeSubnetsFromInterfaces(cfg.ifaces || undefined); }
      catch { bridgeCache = []; }
    }
    return bridgeCache;
  };
  /** No container view was given: a bridge address on this computer is refused. */
  const containerAddrFallback = (addr) => {
    for (const c of bridgeSubnets()) {
      try { if (addrInCidr(addr, c)) return { kind: "denied", reason: "no container view" }; } catch {}
    }
    return { kind: "not-container" };
  };
  /** The container-owner answer for one listed address, cached per address. */
  async function containerOwnerOf(addr) {
    const key = canonTargetAddr(addr);
    const now = Date.now();
    const hit = containerCache.get(key);
    if (hit && now - hit.at <= cfg.ownerCacheMs) return hit.value;
    let value = null;
    try {
      const v = await cfg.containerOwner(addr);
      value = v && typeof v === "object" ? v : { kind: "denied", reason: "owner check failed" };
    } catch { value = { kind: "denied", reason: "owner check failed" }; }
    containerCache.set(key, { at: now, value });
    return value;
  }

  /** Why a listed loopback port may not be spliced (null: it may). */
  function loopbackVerdict(owner, entry) {
    const kind = owner && owner.kind;
    if (kind === "denied") {
      const r = String(owner.reason || "denied");
      return r === "gateway" || r === "satellite" ? "a gateway listens there; gateways are reached through doors only" : r;
    }
    if (kind === "own-uid") {
      // A process of this user is trusted only for an address the owner typed.
      // A gateway-computed TTS entry is never one: it is denied as a default.
      if (entry.source !== "owner") return "a default URL never reaches a process of this user";
      return entry.ownerProject ? "the listener is not published by " + entry.ownerProject : null;
    }
    if (kind === "docker-publish") {
      const projectOwner = typeof owner.projectOwner === "string" ? owner.projectOwner : "";
      if (!projectOwner) return "the owner check did not name a compose project";
      // A project owner is an add-on id or nothing: no other value is compared
      // with this add-on's id, and none reaches the TTS exception list.
      if (!ADDON_OWNER_ID_RE.test(projectOwner)) return "foreign project";
      if (entry.source === "gateway-tts") {
        // These entries exist for ONE thing: a TTS add-on's published port,
        // computed by the gateway (D4). This relay re-checks the named
        // exception itself, the entry must name the compose project the
        // listener belongs to, and the source is never this add-on's own
        // project — a gateway-computed entry is only for the TTS exception.
        if (projectOwner === cfg.id) return "foreign project";
        const exception = Object.prototype.hasOwnProperty.call(TTS_PORT_EXCEPTION, cfg.id)
          ? TTS_PORT_EXCEPTION[cfg.id]
          : null;
        if (entry.ownerProject
          && entry.ownerProject === owner.project
          && Array.isArray(exception)
          && exception.includes(projectOwner)) return null;
        return "foreign project";
      }
      if (projectOwner === cfg.id) return !entry.ownerProject || owner.project === entry.ownerProject
        ? null
        : "published by another compose project";
      // Another add-on's compose project: no longer reachable by a manifest
      // default or an owner-typed URL, only by the gateway's own entry above.
      return "published by another add-on's compose project";
    }
    return "owner check failed";
  }

  /** One raw loopback splice, opened from the add-on mark. */
  const spliceAddon = (client, port, leftover) => {
    const target = o._connectOverride ? o._connectOverride("127.0.0.1", port) : { host: "127.0.0.1", port };
    let up;
    try {
      up = netConnect({ host: target.host, port: target.port, localAddress: ADDON_RELAY_SOURCE_V4, allowHalfOpen: true });
    } catch { try { client.destroy(); } catch {} return; }
    sockets.add(up);
    up.once("close", () => { sockets.delete(up); if (!client.destroyed) client.end(); });
    up.on("error", () => { try { client.destroy(); } catch {} });
    client.on("error", () => { try { up.destroy(); } catch {} });
    client.once("close", () => { try { up.destroy(); } catch {} });
    up.once("connect", () => {
      if (client.destroyed) { up.destroy(); return; }
      if (leftover && leftover.length) up.write(leftover);
      client.pipe(up);
      up.pipe(client);
    });
  };

  /** `PORT n` in add-on mode: the gateway port is doors, a listed port is spliced after the owner check. */
  const handleAddonPort = (c, port, buf) => {
    // Paused before any asynchronous owner check: a socket with no 'data'
    // listener must not keep flowing into nothing.
    c.pause();
    if (gatewayPort && port === gatewayPort) {
      note("allow", "127.0.0.1:" + port);
      c.pause();
      if (buf.length) c.unshift(buf);
      enterDoors(c);
      return;
    }
    const entry = cfg.loopback.get(port);
    if (!entry) {
      note("deny", "127.0.0.1:" + port, "not in the add-on's loopback list");
      c.destroy();
      return;
    }
    ownerOf(port, entry.ownerProject).then((owner) => {
      if (c.destroyed) return;
      const why = loopbackVerdict(owner, entry);
      if (why) {
        note("deny", "127.0.0.1:" + port, why);
        c.destroy();
        return;
      }
      note("allow", "127.0.0.1:" + port);
      c.pause();
      spliceAddon(c, port, buf);
    }).catch(() => { try { c.destroy(); } catch {} });
  };

  /** An absolute-form plain-HTTP request (D1): only a listed host:port, after the listed-entry checks. */
  async function handleAddonPlain(c, headText) {
    const line = String(headText).split("\r\n")[0] || "";
    const m = line.match(PLAIN_RE);
    let u = null;
    if (m) { try { u = new URL(m[2]); } catch { u = null; } }
    if (!m || !u || u.protocol !== "http:") {
      note("deny", line.slice(0, 80), "only CONNECT or a listed plain-HTTP target");
      return refuse(c, 405, "Method Not Allowed");
    }
    const host = addonHost(u.hostname.replace(/^\[(.*)\]$/, "$1"));
    const port = u.port ? Number(u.port) : 80;
    const target = host + ":" + port;
    if (!isPortNumber(port) || !cfg.plainHttpHosts.has(target)) {
      note("deny", target, "not in the add-on's plain-HTTP list");
      return refuse(c, 405, "Method Not Allowed");
    }
    const checked = await checkListedTarget(host);
    if (checked.reason) {
      note("deny", target, checked.reason);
      return refuse(c, checked.unresolved ? 502 : 403, checked.unresolved ? "Bad Gateway" : "Forbidden");
    }
    note("allow", target, "resolved " + checked.addrs.map((a) => a.address).join(", "));
    if (c.destroyed) { try { c.destroy(); } catch {} return; }
    plainTargets.set(c, { host, port, addr: checked.addrs[0].address });
    c.pause();
    // The head goes back on the stream AFTER the bytes that came with it, so
    // the parser sees a whole request and then whatever followed it.
    c.unshift(Buffer.from(headText + "\r\n\r\n", "latin1"));
    enterPlain(c);
  }

  /** CONNECT in add-on mode: an exact listed entry (private allowed), or the internet when the owner allowed it. */
  async function handleAddonConnect(c, host, port, target) {
    const listed = cfg.hosts.has(target);
    if (!listed) {
      if (!cfg.internet) { note("deny", target, "internet not allowed for this add-on"); return refuse(c, 403, "Forbidden"); }
      // In add-on mode an unlisted target is always 443, whatever egressPorts says.
      if (port !== 443) { note("deny", target, "port not allowed"); return refuse(c, 403, "Forbidden"); }
      if (!hostAllowed(host, allow)) { note("deny", target, "host not in the add-on's egress list"); return refuse(c, 403, "Forbidden"); }
    }
    let addrs;
    if (listed) {
      const checked = await checkListedTarget(host);
      if (checked.reason) {
        note("deny", target, checked.reason);
        return refuse(c, checked.unresolved ? 502 : 403, checked.unresolved ? "Bad Gateway" : "Forbidden");
      }
      addrs = checked.addrs;
    } else {
      if (cfg.selfNames.has(host)) { note("deny", target, "own host"); return refuse(c, 403, "Forbidden"); }
      if (isIP(host)) addrs = [{ address: host, family: isIP(host) }];
      else {
        try { addrs = await lookup(host); } catch { note("deny", target, "does not resolve"); return refuse(c, 502, "Bad Gateway"); }
      }
      if (!Array.isArray(addrs) || !addrs.length) { note("deny", target, "no address"); return refuse(c, 403, "Forbidden"); }
      if (addrs.some((a) => cfg.selfAddrs.has(canonTargetAddr(a && a.address)))) { note("deny", target, "own host"); return refuse(c, 403, "Forbidden"); }
      const view = localView(addonLocal);
      noteOwnHostView(view);
      const why = addrs.map((a) => egressDenyReason(a && a.address, { view })).find(Boolean);
      if (why) { note("deny", target, why); return refuse(c, 403, "Forbidden"); }
    }
    if (c.destroyed || c.readableEnded) { try { c.destroy(); } catch {} return; }
    note("allow", target, "resolved " + addrs.map((a) => a.address).join(", "));
    splice(c, addrs.map((a) => a.address), port, "HTTP/1.1 200 Connection Established\r\n\r\n");
  }

  /**
   * One request in flight per bot connection. Pipelining used to dial one
   * upstream socket per request the moment it arrived (1,500 sockets from one
   * connection in a probe). Node answers pipelined requests in order, so the
   * extra ones wait here and each starts when the previous response has
   * finished or closed; past MAX_QUEUED the rest is refused.
   */
  const perSocket = new WeakMap(); // socket -> { busy, queue }
  const connState = (socket) => {
    let st = perSocket.get(socket);
    if (!st) {
      st = { busy: false, queue: [] };
      perSocket.set(socket, st);
      socket.once("close", () => { st.busy = false; st.queue.length = 0; });
    }
    return st;
  };

  /** Judge one request and answer it: the whole decision lives here. */
  function serveOne(req, res) {
    const upgrade = req.headers.upgrade !== undefined
      || /(?:^|,)\s*upgrade\s*(?:,|$)/i.test(String(req.headers.connection || ""));
    if (req.method === "CONNECT" || upgrade) return refuseDoor(req, res, "upgrade refused");
    // A body on a bodiless method has no framing this hop may forward (the
    // client's own is hop-by-hop), so it would land raw after the headers as a
    // second request on the gateway's wire. Refused, nothing opened upstream.
    if (BODILESS.has(req.method)
      && (req.headers["transfer-encoding"] !== undefined || Number(req.headers["content-length"] || 0) > 0)) {
      return refuseWith(req, res, 400, "bad request", "body on a bodiless method");
    }
    if (addon) {
      // An add-on gets NO bot doors: only the predicate the wall computed, and
      // only for a target shape that cannot be rewritten into another route.
      if (doorFilter) {
        if (!safeDoorTarget(req.url)) return refuseDoor(req, res, "not a door");
        let door = false;
        try { door = cfg.isDoor(req.url, req.method) === true; } catch { door = false; }
        if (!door) return refuseDoor(req, res, "not a door");
      }
      return forwardDoor(req, res);
    }
    if (doorFilter && !isDoorPath(req.url)) return refuseDoor(req, res, "not a door");
    forwardDoor(req, res);
  }

  /** Start one request, and start the next queued one once its response is done. */
  function startOne(req, res, st) {
    if (req.socket.destroyed) { st.busy = false; return; }
    st.busy = true;
    // No timeout while a request is in flight: an SSE stream is long by design.
    req.socket.setTimeout(0);
    let done = false;
    const next = () => {
      if (done) return;
      done = true;
      st.busy = false;
      const q = st.queue.shift();
      if (q) return startOne(q.req, q.res, st);
      // Keep-alive and nothing in flight: an idle connection is closed here.
      // (no callback: enterDoors registered the one timeout handler)
      req.socket.setTimeout(idleMs);
    };
    res.on("finish", next);
    res.on("close", next);
    serveOne(req, res);
  }

  doors.on("request", (req, res) => {
    // The first request ends the absolute head timer (enterDoors).
    const ht = headTimers.get(req.socket);
    if (ht) { clearTimeout(ht); headTimers.delete(req.socket); }
    const st = connState(req.socket);
    if (st.busy) {
      if (st.queue.length >= MAX_QUEUED) return refuseUnavailable(req, res, "too many pipelined requests");
      st.queue.push({ req, res });
      return;
    }
    startOne(req, res, st);
  });
  // Node hands these two off the request event; neither may reach the gateway.
  doors.on("upgrade", (req, socket) => refuseRaw(req, socket, "upgrade refused"));
  doors.on("connect", (req, socket) => refuseRaw(req, socket, "CONNECT refused"));
  doors.on("clientError", (err, socket) => {
    if (!socket.writable || (err && err.code === "ECONNRESET")) { try { socket.destroy(); } catch {} return; }
    try { socket.end("HTTP/1.1 400 Bad Request\r\nConnection: close\r\n\r\n"); } catch { try { socket.destroy(); } catch {} }
  });

  /** Hand the bot's connection to the HTTP parser once the PORT line is read. */
  const headTimers = new WeakMap();
  const enterDoors = (c) => {
    doors.emit("connection", c);
    // The doors server never listens, so node's own timeout checker never runs
    // for it. The first head gets an ABSOLUTE timer (a trickled header cannot
    // keep it alive), cleared by the first request. After that the socket's
    // idle timeout takes over (startOne), set without a callback: the ONE
    // handler is registered here, so a long keep-alive session never piles up
    // timeout listeners. It is off while a request is in flight (SSE is long).
    const ht = setTimeout(() => { try { c.destroy(); } catch {} }, headTimeoutMs);
    if (ht.unref) ht.unref();
    headTimers.set(c, ht);
    c.once("close", () => { clearTimeout(ht); headTimers.delete(c); });
    c.on("timeout", () => { try { c.destroy(); } catch {} });
    // The parser attaches its own readers; a socket paused for the PORT line
    // must be resumed explicitly (a 'data' listener alone does not unpause it).
    c.resume();
  };

  async function handleProxy(c, head) {
    const first = head.split("\r\n")[0] || "";
    const m = first.match(/^(\S+)\s+(\S+)\s+HTTP\/1\.[01]$/);
    if (!m) return refuse(c, 400, "Bad Request");
    // add-on mode (D1): an absolute-form plain-HTTP request arrives through the
    // same PROXY line the in-namespace forwarder writes for HTTP_PROXY.
    if (addon && m[1] !== "CONNECT") return handleAddonPlain(c, head);
    // inject mode: a plain-HTTP absolute-form request to an approved host is
    // the only shape that gets a credential, and CONNECT never is.
    if (injectOn && m[1] !== "CONNECT") return handleInject(c, head);
    if (m[1] !== "CONNECT") { note("deny", m[1] + " " + m[2].slice(0, 80), "only CONNECT"); return refuse(c, 405, "Method Not Allowed"); }
    const hp = m[2].match(/^\[([0-9a-fA-F:.]+)\]:(\d+)$/) || m[2].match(/^([^:\[\]]+):(\d+)$/);
    if (!hp) return refuse(c, 400, "Bad Request");
    const host = norm(hp[1]), port = Number(hp[2]);
    if (!isIP(host) && !HOSTNAME_RE.test(host)) return refuse(c, 400, "Bad Request");
    const target = host + ":" + port;
    if (addon) return handleAddonConnect(c, host, port, target);
    // A tunnel would carry the step's own TLS: the credential is only ever
    // attached by this relay to a request it wrote itself.
    if (injectRules.has(host)) { note("deny", host, "inject_host_requires_http_form"); return refuse(c, 403, "Forbidden"); }
    if (!ports.has(port)) { note("deny", target, "port not allowed"); return refuse(c, 403, "Forbidden"); }
    if (!hostAllowed(host, allow)) { note("deny", target, "host not in the bot's egress list"); return refuse(c, 403, "Forbidden"); }
    let addrs;
    if (isIP(host)) addrs = [{ address: host, family: isIP(host) }];
    else {
      try { addrs = await lookup(host); } catch { note("deny", target, "does not resolve"); return refuse(c, 502, "Bad Gateway"); }
    }
    const view = localView(local); // one host view per CONNECT
    noteOwnHostView(view);
    const why = addrs.length ? addrs.map((a) => egressDenyReason(a.address, { view })).find(Boolean) : "no address";
    if (why) {
      note("deny", target, why);
      return refuse(c, 403, "Forbidden");
    }
    // The client left during the lookup (half-open sockets see only 'end'):
    // no tunnel is worth opening for a client that has nothing more to send.
    if (c.destroyed || c.readableEnded) { try { c.destroy(); } catch {} return; }
    note("allow", target);
    splice(c, addrs.map((a) => a.address), port, "HTTP/1.1 200 Connection Established\r\n\r\n");
  }

  const server = createServer({ allowHalfOpen: true }, (c) => {
    sockets.add(c);
    c.on("close", () => { sockets.delete(c); });
    if (live >= maxConns) { note("deny", "connection", "per-spawn connection cap " + maxConns); c.destroy(); return; }
    live++;
    c.once("close", () => { live--; });
    let buf = Buffer.alloc(0);
    let verb = null;
    const timer = setTimeout(() => c.destroy(), headTimeoutMs);
    if (timer.unref) timer.unref();
    c.once("close", () => clearTimeout(timer));
    const onData = (d) => {
      buf = Buffer.concat([buf, d]);
      if (verb === null) {
        const nl = buf.indexOf(10);
        if (nl < 0) { if (buf.length > 64) { clearTimeout(timer); c.destroy(); } return; }
        verb = buf.subarray(0, nl).toString("latin1");
        buf = buf.subarray(nl + 1);
        const pm = verb.match(/^PORT (\d{1,5})$/);
        if (pm) {
          c.removeListener("data", onData); clearTimeout(timer);
          const port = Number(pm[1]);
          if (addon) { handleAddonPort(c, port, buf); return; }
          if (!gatewayPort || port !== gatewayPort) {
            // No other loopback port is served at all: the one a contained bot
            // reaches is its own gateway's, and there only the doors. With no
            // gateway port there is no PORT line to serve, 0 included.
            note("deny", "127.0.0.1:" + port, gatewayPort ? "not the bot's gateway port" : "no gateway port");
            c.destroy();
            return;
          }
          note("allow", "127.0.0.1:" + port);
          // Paused until the HTTP parser owns it; bytes that came with the
          // header line (usually a whole request) go back on the stream first.
          c.pause();
          if (buf.length) c.unshift(buf);
          enterDoors(c);
          return;
        }
        if (verb !== "PROXY") { clearTimeout(timer); c.destroy(); return; }
      }
      const end = buf.indexOf("\r\n\r\n");
      if (end < 0 ? buf.length > MAX_HEAD : end > MAX_HEAD) {
        clearTimeout(timer); c.removeListener("data", onData); refuse(c, 431, "Request Header Fields Too Large");
        return;
      }
      if (end < 0) return;
      clearTimeout(timer);
      c.removeListener("data", onData);
      const head = buf.subarray(0, end).toString("latin1");
      const rest = buf.subarray(end + 4);
      c.pause();
      if (rest.length) c.unshift(rest);
      handleProxy(c, head).catch(() => c.destroy());
    };
    c.on("data", onData);
    c.on("error", () => {});
  });
  let listening = false;
  const ready = new Promise((resolve, reject) => {
    // A persistent handler: accept errors (EMFILE, ENFILE) after listening must
    // never be unhandled, which would kill the gateway or bot runner.
    server.on("error", (e) => {
      if (!listening) { log(`[pi-egress] bot=${o.botId || "?"} relay failed to listen: ${e.message}`); reject(e); }
      else log(`[pi-egress] bot=${o.botId || "?"} relay error: ${e.message}`);
    });
    server.listen(socketPath, () => { listening = true; try { chmodSync(socketPath, 0o600); } catch {} resolve(); });
  });
  ready.catch(() => {});
  return {
    dir, socketPath, ready, _server: server, _sockets: sockets,
    denials: () => (addon ? [...denials] : []),
    close: () => new Promise((resolve) => {
      for (const s of sockets) { try { s.destroy(); } catch {} }
      server.close(() => { try { rmSync(dir, { recursive: true, force: true }); } catch {} resolve(); });
    }),
  };
}
