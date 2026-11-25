/**
 * A contained bot's doors on its own gateway, and the mark the egress relay
 * leaves on every socket it opens (containment Phase 1, PR 6).
 *
 * A contained bot has no NIC: its only way to host loopback is the spawner's
 * egress relay (scripts/pi-bots/pi_egress.mjs). That relay used to splice the
 * bot's bytes to the gateway port, which handed the bot every route a plain
 * loopback socket reaches — every `local`-classified route of its own gateway,
 * and the host's /internal routes, the signing relay above all. Two independent
 * layers close that:
 *
 *   1. this allowlist. The relay terminates HTTP itself and judges EVERY
 *      request on the connection (keep-alive included) against these doors.
 *   2. the mark. Every socket the relay opens to loopback is bound to
 *      RELAY_SOURCE_V4, so the gateway can recognise "this came through the
 *      relay" and refuse /internal on it (middleware/internal-guard.js), and
 *      the #614 caller check refuses it outright (bot-host-caller.js). The
 *      mark is set by the relay process, outside the sandbox: a bot cannot
 *      choose its own source address. Any 127/8 address is local on Linux, so
 *      no privilege is needed to bind it.
 *
 * The door list is exact and case-sensitive: owner-authority surfaces
 * (/memory, /projects, /sharing, /tools*, /router, /dashboard, /llm/models,
 * /llm/acquire) are deliberately absent, and an operator's ruling fixed the
 * list. A family added later (a new bot-only mount) is added by the PR that
 * mounts it.
 *
 * THE 2026-11-16 OPERATOR RULING adds `/artifacts/upload/`: the one-time
 * 256-bit upload token bound to bot+thread is the capability, so a contained
 * bot may PUT its file to its own upload's put_url.
 *
 * THE BOT SHARING DOOR adds `/sharing-bot/mcp` (bot door + saved message drafts):
 * a bot's own narrow mount, NOT `/sharing` — the owner surface stays shut. Its
 * path-scoped token plus a required signed `sharing` actor are what admit a call;
 * nothing there can send, and every message it writes is a draft the owner checks.
 *
 * THE REPORTS DOOR adds `/reports/mcp`: the bot tools for building a report, under
 * the reports token and a required signed `reports` actor. Every call lands in the
 * project derived from the verified bot, and nothing there approves, goes live or
 * reads a credential.
 *
 * THE CORE BOT DOORS (design D2) add `/memory-bot/mcp` and `/projects-bot/mcp`: the
 * memory and project tools served by the gateway, so a bot reaches them without opening
 * crow.db itself. Each has its own path-scoped token family and its own signed actor kind
 * (`memory`, `projects`), and admits only a bot whose VERIFIED definition opted in; the
 * bot's identity and project scope come from that verified definition, never from the
 * request. They are NOT `/memory` and `/projects`, which stay the owner's surfaces.
 *
 * A LOCKED TURN'S MOUNT adds one path per kind: `/mail-draft/mcp` for Crow Mail's drafting turn and
 * `/report-pickup/mcp` for a report pickup. Each admits exactly one per-turn token of its own prefix
 * and one signed actor of its own kind, and neither token opens the other's mount.
 *
 * The doors are PATHS ONLY — isDoorPath never sees the request method, so a
 * door admits every method on its path. That is the whole of the upload door:
 * the route behind it is a PUT route, so any other method reaches no handler
 * (express answers 404) and a PUT without a live token is refused 404 by the
 * handler itself. Restricting one door to PUT would need a new method-aware
 * door mechanism, which this ruling deliberately does not build.
 */

export const BOT_DOOR_PREFIXES = Object.freeze([
  "/llm/v1/",      // the model router: the bot's own models, no provider key
  "/llm/p/",       // a provider door (native row, external engine, bundle)
  "/llm/c/",       // a consented cloud door
  "/board/mcp",    // its own board mount, under the board token
  "/phone/mcp",    // phone plans, under the phone token and the actor signature
  "/artifacts/mcp",
  "/artifacts/upload/",  // the upload PUT: the one-time token in the path is the capability (2026-11-16 ruling)
  "/secrets/mcp",  // the bot-only credential-card mount, under the secrets token and a signed Perch actor
  "/sharing-bot/mcp",  // the bot sharing door (saved message drafts only), under the sharing-bot token and a signed `sharing` actor
  "/reports/mcp",  // the reports door (report proposals only), under the reports token and a signed `reports` actor
  "/memory-bot/mcp",  // the core memory door (D2), under the memory-bot token, a signed `memory` actor and a verified, opted-in definition
  "/projects-bot/mcp",  // the core projects door (D2), under the projects-bot token, a signed `projects` actor and a verified, opted-in definition
  "/mail-draft/mcp",  // Crow Mail's drafting mount: a per-turn `mdt_` token and a `mail-draft` actor signature
  "/report-pickup/mcp",  // a report pickup's mount: a per-turn `rpk_` token and a `report-pickup` actor signature
  "/peer-relay/",  // the relay to paired peers, under the relay token
]);

/** The source address the relay binds for every upstream socket it opens. */
export const RELAY_SOURCE_V4 = "127.0.77.1";

/**
 * The same mark for a walled add-on's relay. A separate address, because the
 * two are classified differently: the bot mark keeps today's loopback rules
 * (two bot doors, the peer relay and the cloud door, require a local caller),
 * while peer-class never treats the add-on mark as a local caller. Both marks
 * are refused /internal and the local token (isRelayedSocket).
 */
export const ADDON_RELAY_SOURCE_V4 = "127.0.78.1";

// Anything that could rewrite the path between this check and the gateway's
// router is refused rather than reasoned about: a ".." segment, a second
// slash, a backslash, "*" (OPTIONS *), and ANY percent-escape (a normalised
// door path never needs one, and %2e/%2f/%5c are only the ones we know).
const FORBIDDEN = /[\u0000-\u0020\u007f\\*]/;

/**
 * Is this request target one of the bot doors? Origin-form only ("/path"), so
 * an absolute-form URL ("http://host/path", which a proxy target could carry)
 * is never a door. The query string is dropped before matching: doors are
 * paths, and `/board/mcp?x=1` is the board mount.
 *
 * A door that is a whole mount (`/board/mcp`) matches only itself or a child
 * path, so `/board/mcpx` is not a door; a door that is a prefix (`/llm/v1/`)
 * matches anything under it.
 */
export function isDoorPath(rawTarget) {
  if (typeof rawTarget !== "string" || rawTarget === "") return false;
  // Origin-form only: one leading slash, never two.
  if (rawTarget[0] !== "/" || rawTarget[1] === "/") return false;
  if (FORBIDDEN.test(rawTarget)) return false;
  if (rawTarget.includes("//") || rawTarget.includes("..") || rawTarget.includes("%")) return false;
  const q = rawTarget.indexOf("?");
  const path = q < 0 ? rawTarget : rawTarget.slice(0, q);
  if (path === "/") return false;
  for (const door of BOT_DOOR_PREFIXES) {
    // A whole-mount door is itself or a child path ("?x=1" was already
    // dropped), never a longer word: /board/mcpx is not the board mount.
    if (door.endsWith("/") ? path.startsWith(door) : (path === door || path.startsWith(door + "/"))) return true;
  }
  return false;
}

/** "[::ffff:127.0.77.1]" / "::FFFF:127.0.77.1" / "127.0.77.1" → "127.0.77.1". */
export function normalizeRelayAddr(addr) {
  let s = String(addr ?? "").trim().replace(/^\[(.*)\]$/, "$1");
  const mapped = /^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/i.exec(s);
  if (mapped) s = mapped[1];
  return s;
}

/** Is this address the walled add-on's relay mark, in any spelling? */
export function isAddonRelayAddr(addr) {
  return normalizeRelayAddr(addr) === ADDON_RELAY_SOURCE_V4;
}

/**
 * Did this socket come from an egress relay? True for either mark (a bot's
 * RELAY_SOURCE_V4 or a walled add-on's ADDON_RELAY_SOURCE_V4), in any spelling
 * the kernel may report it (a dual-stack listener sees the v4-mapped form).
 * Every other peer, loopback ones included, is not relayed.
 */
export function isRelayedSocket(socket) {
  if (!socket || typeof socket !== "object") return false;
  const a = normalizeRelayAddr(socket.remoteAddress);
  return a === RELAY_SOURCE_V4 || a === ADDON_RELAY_SOURCE_V4;
}