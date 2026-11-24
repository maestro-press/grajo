/** 66-hex compressed secp256k1 pubkey -> 64-hex x-only (what Nostr `event.pubkey` carries). */
export function xOnly(pubkeyHex) {
  return pubkeyHex.length === 66 ? pubkeyHex.slice(2) : pubkeyHex;
}

/**
 * The three PUBLIC persona authors, as `ramble_settings` rows.
 *
 * The gateway derives every persona at boot (it holds the seed); the stdio MCP
 * server cannot read the identity file inside a bot sandbox, and it never
 * signs — the gateway re-derives the persona from the row's level and signs the
 * event. So the only thing the stdio side needs is the x-only AUTHOR, and this
 * is where the gateway caches it. `local.`-prefixed: instance sync never
 * carries these rows (shouldSyncRow drops them on both the emit and apply
 * side), because they belong to one boot of one instance.
 */
export const PERSONA_CACHE_KEYS = Object.freeze({
  real: "local.persona.real",
  world: "local.persona.world",
  caw: "local.persona.caw",
});

/**
 * The `ramble_settings` key naming WHICH boot's session id the caw author row
 * was derived from (`local.session_id`). The caw slot is boot-scoped: the
 * gateway writes `local.session_id` before it derives the caw persona, so a
 * derivation (or cache write) that failed leaves the PREVIOUS boot's caw row
 * behind. A reader must therefore treat the caw slot as missing unless this
 * key equals the current `local.session_id`.
 */
export const PERSONA_CAW_SESSION_KEY = "local.persona.caw_session";

/**
 * Which cache slot a (level, kind) persona resolves to. This IS `resolvePersona`'s
 * own rule, written once: a real identity uses the instance key for every kind;
 * only a ROTATING caw gets a fresh per-session key; everything else (the stable
 * world pseudonym — pseudonym level, or a rotating mark) is the world key.
 */
export function personaCacheSlot({ level = "rotating", kind = "mark" } = {}) {
  if (level === "real") return "real";
  if (level === "rotating" && kind === "caw") return "caw";
  return "world";
}

/** The `ramble_settings` key a (level, kind) persona's author is cached at. */
export function personaCacheKey(opts) {
  return PERSONA_CACHE_KEYS[personaCacheSlot(opts)];
}

/**
 * The cached author for a (level, kind) persona, or null when the cache does
 * not hold a usable one. `cache` is `{ real, world, caw }` of optional strings.
 *
 * The result has the same shape `resolvePersona` returns minus the key
 * material (`secp256k1Priv`, and `crowId` — which only the signing side needs:
 * the gateway derives the persona itself and puts the crow id in the event).
 * `author_level` echoes the requested level, exactly as `resolvePersona` does.
 */
export function resolveAuthor(cache, level = "rotating", kind = "mark") {
  const author = cache?.[personaCacheSlot({ level, kind })];
  if (typeof author !== "string" || !/^[0-9a-f]{64}$/.test(author)) return null;
  return { author, author_level: level };
}

export function resolvePersona(identity, seed, { level = "rotating", kind = "mark", sessionId = "0", _derive } = {}) {
  const derive = _derive; // production callers pass deriveBotIdentity from identity.js
  if (level === "real") {
    return { author: xOnly(identity.secp256k1Pubkey), author_level: "real", crowId: identity.crowId, secp256k1Priv: identity.secp256k1Priv };
  }
  // pseudonym: always the stable world pseudonym. rotating: marks use the stable pseudonym (attributable),
  // only caws (presence) use a fresh per-session key.
  const rotatesThisKind = level === "rotating" && kind === "caw";
  const botId = rotatesThisKind ? "ramble-session:" + sessionId : "ramble-world";
  const k = derive(seed, botId);
  return { author: xOnly(k.secp256k1Pubkey), author_level: level, crowId: null, secp256k1Priv: k.secp256k1Priv };
}
