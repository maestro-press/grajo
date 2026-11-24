/**
 * Ramble MCP server. Milestone 1 (M1) tools — local core, no network/UI:
 *   ramble_leave_mark, ramble_caw, ramble_query_world, ramble_unlock,
 *   ramble_pet_state, ramble_block, ramble_unblock, ramble_egg_state,
 *   ramble_checkin, ramble_flock, ramble_nests, ramble_claim_nest,
 *   ramble_gift_egg, ramble_propose_swap.
 *
 * Moves (moves design, spec 2026-10-30): ramble_moves_today,
 * ramble_moves_log and ramble_moves_prefs. Done, Swap, "something else" and
 * the library live on the panel; the chores are gone.
 *
 * Phase 3: contacts/group marks, gifts and swaps are queued into
 * `ramble_outbox` here and SENT by the gateway transport on its next tick
 * (this stdio process has no relay socket and no bus, so there is no
 * immediate poke — up to 15 s). Group audiences are the core contact groups
 * (`group:<group_uid>`); the phase-1 `ramble_groups` table is unused.
 *
 * Identity seam (review round 3, D8): options.identity/seed/_derive are
 * injectable (tests inject all three so no identity files are generated).
 * When absent, the persona authors come from the GATEWAY's public-persona
 * cache in `ramble_settings` (`local.persona.real/.world/.caw`, written by
 * servers/gateway/boot/ramble-transport.js at boot); only when those rows are
 * absent — or, for the boot-scoped caw row, left over from an earlier boot
 * (`local.persona.caw_session` ≠ `local.session_id`) — does this fall back to
 * the instance identity, and only
 * `loadIdentityIfPresent` — this bundle's server NEVER mints an identity (a
 * sandbox with an absent seed file and a writable data dir would otherwise
 * create a SECOND identity that no gateway signs for). The import is lazy so
 * the factory itself stays synchronous.
 */
import { randomUUID } from "node:crypto";
import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";
import { z } from "zod";
import { appImport } from "./app-root.js";
import { resolveDataDir } from "./db.js";
import { resolvePersona, resolveAuthor, PERSONA_CACHE_KEYS, PERSONA_CAW_SESSION_KEY } from "./persona.js";
import { createMark, listMarks, unlockMark, blockPersona, unblockPersona } from "./marks.js";
import { encodeGeohash } from "./anchors.js";
import { getGrid } from "./grid.js";
import { petState } from "./pet.js";
import { heartsBalance } from "./hearts.js";
import { eggState, activeBird, isoWeek, layProgress, nextPromotable } from "./eggs.js";
import { feedAll } from "./feed.js";
import { flockState, listNests, claimNest } from "./flock.js";
import { resolveContact, resolveAudience, enqueueMark, contactsByPubkey, CROW_ID_RE, ID_RE } from "./delivery.js";
import { labelFor } from "./labels.js";
import { giftEgg, proposeSwap } from "./trades.js";
import { servedLibrary, ACTIVITY_KINDS } from "./moves/library.js";
import { readPrefs, writePrefs, todayChallenge } from "./moves/today.js";
import { dayCards } from "./moves/slots.js";
import {
  recordLog, movesDay, pointsFor, EFFORTS, LOG_MINUTES_MAX,
} from "./moves/ledger.js";
import { streakState, awardStreakHeart } from "./moves/streak.js";
import { learningFlows } from "./moves/learning.js";
import { stepsState } from "./steps.js";

/** The `ramble_settings` key holding the per-boot session id the gateway signs caws with (R11). */
const SESSION_ID_KEY = "local.session_id";

const text = (t) => ({ content: [{ type: "text", text: t }] });
const errorText = (t) => ({ content: [{ type: "text", text: t }], isError: true });

// `private` ("Just me") is a real audience, not network-facing: the
// transport drain only ever selects visibility='public' rows and
// markToEvent() throws RambleNotPublic for anything else, so a private mark
// can never reach a relay. shouldSyncRow('ramble_marks') is deliberately
// left unchanged — private marks DO still replicate to the author's own
// other instances via the instance-sync outbox; that's the point of "just
// me" (me, everywhere), not "just this device".
const VISIBILITY_RE = /^(public|contacts|private|group:.+)$/;

export function createRambleServer(db, options = {}) {
  const server = new McpServer(
    { name: "crow-ramble", version: "0.1.0" },
    { capabilities: { tools: {} }, instructions: options.instructions },
  );

  // The two sentences this tool answers when it has no author at all. They are
  // different faults, so they are different messages: a MASKED identity file
  // (a bot sandbox: the file is there and reads empty) keeps the sentence the
  // sandbox note documents; no identity file at all means no gateway has run
  // here, so nothing was cached and there is nobody to sign for this mark.
  const MASKED_IDENTITY_ERROR = "ramble: the instance identity is not available to bots (this Crow's identity file is hidden inside the bot sandbox); run this from the dashboard, not a bot turn";
  const NO_GATEWAY_ERROR = "Ramble needs the Crow gateway (with sharing on) to have run.";

  // Identity seam: resolved lazily (once) on first tool call so the factory
  // stays synchronous and tests that inject identity/seed/_derive never
  // touch real identity files. Memoize the IN-FLIGHT PROMISE, not the
  // resolved value: two concurrent first tool calls both read `identityState`
  // before either write lands, so a value-memo lets both calls run the
  // loader (and mint two different sessionIds). Promise-memoizing closes
  // that race — the second caller awaits the first caller's in-flight
  // promise instead of starting its own. Reset to null on rejection so a
  // transient failure (e.g. identity file not yet written) can retry.
  //
  // This is the FALLBACK path only: personaFor() asks the gateway's cache
  // first, so a bot turn normally never reaches it (and therefore never loads
  // the seed).
  let identityPromise = null;
  function getIdentityState() {
    identityPromise ??= (async () => {
      let { identity, seed, _derive } = options;
      if (!identity || !seed || !_derive) {
        const mod = await appImport("servers/sharing/identity.js");
        if (!identity) {
          // loadIdentityIfPresent, never loadOrCreateIdentity: an absent seed
          // file with a writable data dir must never become a second identity.
          // It returns null for a missing file and throws for an unreadable one
          // (the sandbox masks it to an empty file), which are different faults.
          try {
            identity = mod.loadIdentityIfPresent();
          } catch {
            throw new Error(MASKED_IDENTITY_ERROR);
          }
          if (!identity) throw new Error(NO_GATEWAY_ERROR);
        }
        try {
          if (!seed) seed = mod.loadInstanceSeed(resolveDataDir());
        } catch {
          throw new Error(MASKED_IDENTITY_ERROR);
        }
        if (!_derive) _derive = mod.deriveBotIdentity;
      }
      // The memoized sessionId is only the FALLBACK for when no gateway has
      // written one — see storedSessionId()/personaFor() below.
      return { identity, seed, _derive, sessionId: randomUUID() };
    })().catch((err) => { identityPromise = null; throw err; });
    return identityPromise;
  }

  // Sync emit seam: options.emit, else lazily built (promise-memoized for
  // the same reason as identity above) to queue via emitOrQueue (the stdio
  // process has no live sync manager).
  let emitPromise = options.emit ? Promise.resolve(options.emit) : null;
  function getEmit() {
    emitPromise ??= appImport("servers/shared/sync-emit.js")
      .then(({ emitOrQueue }) => (table, op, row) => emitOrQueue(null, db, table, op, row).catch(() => {}))
      .catch((err) => { emitPromise = null; throw err; });
    return emitPromise;
  }

  async function getPublicIdentityLevel() {
    return (await getGrid(db)).identityLevel;
  }

  /**
   * R11: the gateway transport mints the per-boot session id and records it at
   * `ramble_settings` key `local.session_id` (a `local.`-prefixed key, so
   * instance sync never carries it). Reading it makes this stdio process and
   * the gateway derive the SAME rotating-caw key instead of two personas.
   * Returns null when there is no gateway (bundle standalone, or tests).
   */
  async function storedSessionId() {
    try {
      const { rows } = await db.execute({
        sql: "SELECT value FROM ramble_settings WHERE key = ?",
        args: [SESSION_ID_KEY],
      });
      return rows[0]?.value ?? null;
    } catch {
      return null; // table not there yet
    }
  }

  /**
   * The gateway's public-persona cache: the x-only authors it derives at boot
   * and writes to `ramble_settings` (`local.persona.real/.world/.caw`). Read
   * FRESH per call, never memoized — a gateway restart rotates the caw session
   * id and rewrites the caw row in the same boot, so a pinned author would sign
   * caws with a key the gateway has already rotated away from. Returns null
   * when the table is not there yet (no gateway has ever run on this db).
   *
   * The caw slot is BOOT-scoped, and that is what `local.persona.caw_session`
   * is for: the gateway writes `local.session_id` before it derives the caw
   * persona, so a caw derivation (or its write) that failed leaves the PREVIOUS
   * boot's caw row behind, next to a fresh session id. Unless the two agree the
   * caw slot reads as MISSING, and personaFor() takes its normal fallback
   * instead of reporting an author the gateway has already rotated away from.
   */
  async function personaCache() {
    try {
      const { rows } = await db.execute({
        sql: "SELECT key, value FROM ramble_settings WHERE key IN (?, ?, ?, ?, ?)",
        args: [PERSONA_CACHE_KEYS.real, PERSONA_CACHE_KEYS.world, PERSONA_CACHE_KEYS.caw,
          PERSONA_CAW_SESSION_KEY, SESSION_ID_KEY],
      });
      const byKey = new Map(rows.map((r) => [r.key, r.value]));
      const sessionId = byKey.get(SESSION_ID_KEY) ?? null;
      const cawSession = byKey.get(PERSONA_CAW_SESSION_KEY) ?? null;
      return {
        real: byKey.get(PERSONA_CACHE_KEYS.real) ?? null,
        world: byKey.get(PERSONA_CACHE_KEYS.world) ?? null,
        caw: sessionId && cawSession === sessionId ? (byKey.get(PERSONA_CACHE_KEYS.caw) ?? null) : null,
        cawSession,
      };
    } catch {
      return null; // table not there yet
    }
  }

  async function personaFor(kind) {
    const level = await getPublicIdentityLevel();
    // 1. The gateway's cache — the only path a bot turn takes. No seed, no
    //    identity file, no key material: just the author row the gateway will
    //    sign with. For a PUBLIC mark or caw the gateway re-derives the persona
    //    from the row's level and rewrites a mismatched author when it
    //    publishes, so there the cached author is the one that really signs. A
    //    contacts/group/private row keeps its stored author locally: the
    //    delivery payload carries no author, and the receiver assigns it.
    const cached = resolveAuthor(await personaCache(), level, kind);
    if (cached) return cached;
    // 2. No gateway has cached anything: fall back to the instance identity
    //    (never minting one). Either this throws with the message the fault
    //    deserves — "the gateway is not running" or "the identity is masked
    //    in a bot sandbox" — and the tool answers that sentence.
    const { identity, seed, _derive, sessionId } = await getIdentityState();
    // The session id is the ONLY input that changes under this long-lived
    // stdio process: a gateway restart mints a new one. Memoizing it would pin
    // caws to a session key the gateway has already rotated away from, so read
    // it fresh per call — but only where it is actually used (rotating caws).
    // identity/seed/_derive stay memoized.
    let effectiveSessionId = sessionId;
    if (kind === "caw" && level === "rotating") {
      effectiveSessionId = (await storedSessionId()) || sessionId;
    }
    return resolvePersona(identity, seed, { level, kind, sessionId: effectiveSessionId, _derive });
  }

  function checkVisibility(visibility) {
    if (!VISIBILITY_RE.test(visibility)) {
      throw new Error(`invalid visibility: ${visibility}`);
    }
  }

  function register(name, description, shape, handler) {
    server.tool(name, description, shape, handler);
    if (options._exposeHandlers) options._exposeHandlers[name] = handler;
  }

  register(
    "ramble_leave_mark",
    "Leave a proximity mark (a note, photo reference, or other content) at a geographic location for others to discover nearby.",
    {
      lat: z.number().min(-90).max(90),
      lon: z.number().min(-180).max(180),
      accuracy_m: z.number().min(0).max(100000).optional(),
      text: z.string().max(2000),
      visibility: z.string().max(128).optional(),
      reveal: z.string().max(64).optional(),
      content_kind: z.string().max(64).optional(),
      content_ref: z.string().max(1024).optional(),
      ttl_seconds: z.number().int().min(0).optional(),
    },
    async ({ lat, lon, accuracy_m, text: markText, visibility = "public", reveal, content_kind = "none", content_ref, ttl_seconds }) => {
      try {
        checkVisibility(visibility);
        // Phase 3: an audience that cannot be resolved is refused BEFORE a row exists.
        if (visibility.startsWith("group:")) {
          let a = null;
          try { a = await resolveAudience(db, visibility); } catch { a = null; }
          if (!a || !a.ok) return errorText(`unknown group: ${visibility.slice(6)}`);
        }
        const persona = await personaFor("mark");
        const emit = await getEmit();
        const bird = await activeBird(db);
        const row = await createMark(
          db,
          {
            author: persona.author,
            author_level: persona.author_level,
            kind: "mark",
            anchor: { anchor_kind: "geo", lat, lon, accuracy_m },
            visibility,
            reveal,
            content: { content_text: markText, content_kind, content_ref },
            ttlSeconds: ttl_seconds,
            bird,
          },
          { emit },
        );
        let recipients;
        if (visibility === "contacts" || visibility.startsWith("group:")) {
          try { recipients = (await enqueueMark(db, row, { bird, now: Date.now() })).recipients; }
          catch (err) { console.warn("[ramble] enqueueMark failed:", err?.message ?? err); recipients = 0; }
        }
        // Best-effort: a pet/egg-feed failure must never fail a mark.
        try { await feedAll(db, { type: "mark_left" }, { emit }); } catch { /* cosmetic */ }
        return text(JSON.stringify({
          mark_id: row.mark_id,
          geohash: row.geohash,
          expires_at: row.expires_at,
          author: row.author,
          author_level: row.author_level,
          publish_state: row.publish_state,
          ...(recipients === undefined ? {} : { recipients }),
        }));
      } catch (err) {
        return errorText(err.message);
      }
    },
  );

  register(
    "ramble_caw",
    "Broadcast a short-lived, public presence marker (a 'caw') at your current location. Always public, always open (no unlock needed).",
    {
      lat: z.number().min(-90).max(90),
      lon: z.number().min(-180).max(180),
      text: z.string().max(2000),
      ttl_seconds: z.number().int().min(0).optional(),
    },
    async ({ lat, lon, text: cawText, ttl_seconds }) => {
      try {
        const persona = await personaFor("caw");
        const emit = await getEmit();
        const row = await createMark(
          db,
          {
            author: persona.author,
            author_level: persona.author_level,
            kind: "caw",
            anchor: { anchor_kind: "geo", lat, lon },
            visibility: "public",
            reveal: "open",
            content: { content_text: cawText, content_kind: "none" },
            ttlSeconds: ttl_seconds,
          },
          { emit },
        );
        return text(JSON.stringify({
          mark_id: row.mark_id,
          geohash: row.geohash,
          expires_at: row.expires_at,
          author: row.author,
          author_level: row.author_level,
          publish_state: row.publish_state,
        }));
      } catch (err) {
        return errorText(err.message);
      }
    },
  );

  register(
    "ramble_query_world",
    "List nearby marks and caws within the geohash cell containing the given location. Each row carries a label (\"your mark\", \"mark by <contact>\", \"mark by <world name> · <key4>\", or \"mark by <key8>\").",
    {
      lat: z.number().min(-90).max(90),
      lon: z.number().min(-180).max(180),
      visibility: z.string().max(128).optional(),
      precision: z.number().int().min(1).max(12).optional(),
    },
    async ({ lat, lon, visibility = "public", precision }) => {
      try {
        checkVisibility(visibility);
        const envPrecision = Number(process.env.RAMBLE_DEFAULT_GEOHASH_PRECISION);
        const clampedEnvPrecision = Number.isInteger(envPrecision) && envPrecision >= 1 && envPrecision <= 12 ? envPrecision : 5;
        const p = precision ?? clampedEnvPrecision;
        const cell = encodeGeohash(lat, lon, p);
        const rows = await listMarks(db, { visibility, geohashPrefix: cell });
        const byPubkey = await contactsByPubkey(db);
        const marks = rows.map((m) => {
          const c = m.origin === "remote" ? byPubkey.get(String(m.author)) : null;
          return { ...m, label: labelFor(m, { contactName: c ? c.name : null }) };
        });
        return text(JSON.stringify({ cell, marks }));
      } catch (err) {
        return errorText(err.message);
      }
    },
  );

  register(
    "ramble_unlock",
    "Attempt to unlock a locked mark's content by proving proximity to its anchor.",
    {
      mark_id: z.string().max(128),
      lat: z.number().min(-90).max(90),
      lon: z.number().min(-180).max(180),
    },
    async ({ mark_id, lat, lon }) => {
      try {
        const result = await unlockMark(db, mark_id, { lat, lon });
        if (result.unlocked === true) {
          // Best-effort: a pet/egg-feed failure must never fail an unlock.
          try {
            const emit = await getEmit();
            await feedAll(db, { type: "unlock_mark" }, { emit });
          } catch { /* cosmetic */ }
        }
        return text(JSON.stringify(result));
      } catch (err) {
        return errorText(err.message);
      }
    },
  );

  register(
    "ramble_pet_state",
    "Get the Ramble companion pet's current state (mood, energy, weekly activity counters, active bird, and egg progress).",
    {},
    async () => {
      try {
        const [state, bird, egg] = await Promise.all([petState(db), activeBird(db), eggState(db, { now: Date.now() })]);
        // Task 2 (spec 2026-09-08 §4.1): no egg is a valid state — a read
        // must not throw for it, so an absent egg is reported as `null`, not
        // dereferenced.
        return text(JSON.stringify({
          ...state, bird, hearts: await heartsBalance(db),
          egg: egg.egg ?? null,
          lay: await layProgress(db),
          shelf_waiting: (await nextPromotable(db))?.egg_id ?? null,
        }));
      } catch (err) {
        return errorText(err.message);
      }
    },
  );

  register(
    "ramble_egg_state",
    "Get the current incubating egg's warmth progress and checklist toward hatching.",
    {},
    async () => {
      try {
        const state = await eggState(db, { now: Date.now() });
        // `lay` matches GET /api/ramble/egg. NOT `shelf_waiting` here — that
        // affordance belongs to ramble_pet_state / GET /api/ramble/pet only.
        return text(JSON.stringify({ ...state, lay: await layProgress(db) }));
      } catch (err) {
        return errorText(err.message);
      }
    },
  );

  register(
    "ramble_checkin",
    "Record today's check-in, crediting warmth toward the incubating egg (once per local day).",
    {},
    async () => {
      try {
        const emit = await getEmit();
        return text(JSON.stringify(await feedAll(db, { type: "checkin" }, { emit })));
      } catch (err) {
        return errorText(err.message);
      }
    },
  );

  register(
    "ramble_flock",
    "Your flock: hatched birds (the active one marked), the egg shelf and the incubating egg, and how many of the 8 species you have found.",
    {},
    async () => {
      try { return text(JSON.stringify(await flockState(db, { now: Date.now() }))); }
      catch (err) { return errorText(err.message); }
    },
  );

  register(
    "ramble_nests",
    "Nests near a location this week (about a 4 km box), nearest first, with whether you already claimed each. Nests are deterministic: everyone sees the same ones.",
    {
      lat: z.number().min(-90).max(90),
      lon: z.number().min(-180).max(180),
    },
    async ({ lat, lon }) => {
      try {
        // ±0.02° (~900 cells, ~37 nests expected; no week through 2040 has
        // fewer than 3 at the test point) — a ±0.01° box can be nearly empty.
        const bbox = { south: Math.max(-90, lat - 0.02), west: Math.max(-180, lon - 0.02), north: Math.min(90, lat + 0.02), east: Math.min(180, lon + 0.02) };
        const out = await listNests(db, bbox, { now: Date.now(), from: { lat, lon } });
        return text(JSON.stringify(out ?? { week: isoWeek(Date.now()), nests: [] }));
      } catch (err) {
        return errorText(err.message);
      }
    },
  );

  register(
    "ramble_claim_nest",
    "Claim the nest at your location (or at an explicit 7-character geohash cell you are within 75 m of) for an egg. It goes on your shelf, or straight into the incubating slot if that is empty. One claim per day; shelf holds 5. Claiming credits no warmth.",
    {
      lat: z.number().min(-90).max(90),
      lon: z.number().min(-180).max(180),
      cell: z.string().regex(/^[0-9b-hjkmnp-z]{7}$/).optional(),
    },
    async ({ lat, lon, cell }) => {
      try {
        const emit = await getEmit();
        const now = Date.now();
        const result = await claimNest(db, {
          cell: cell ?? encodeGeohash(lat, lon, 7), week: isoWeek(now), here: { lat, lon }, now, emit,
        });
        return text(JSON.stringify(result));
      } catch (err) {
        return errorText(err.message);
      }
    },
  );

  register(
    "ramble_gift_egg",
    "Gift an unhatched egg from your shelf to a contact (by crow_id). The egg leaves your shelf and arrives on theirs still unhatched — whoever hatches it rolls the bird. Contacts only; sent on the gateway's next tick.",
    { egg_id: z.string().regex(ID_RE), crow_id: z.string().regex(CROW_ID_RE) },
    async ({ egg_id, crow_id }) => {
      try {
        let contact = null;
        try { contact = await resolveContact(db, crow_id); } catch { contact = null; }
        if (!contact) return errorText(`unknown contact: ${crow_id}`);
        const emit = await getEmit();
        const out = await giftEgg(db, { eggId: egg_id, toCrowId: contact.crow_id, now: Date.now(), emit });
        if (!out.ok) return errorText(out.reason);
        return text(JSON.stringify({ gifted: true, egg_id, to: contact.crow_id, queued: true }));
      } catch (err) {
        return errorText(err.message);
      }
    },
  );

  register(
    "ramble_propose_swap",
    "Offer one of your unhatched shelf eggs to a contact in exchange for one of theirs; they pick which egg to give back. The offer lapses after seven days. Accept or decline incoming offers from the Ramble panel.",
    { egg_id: z.string().regex(ID_RE), crow_id: z.string().regex(CROW_ID_RE) },
    async ({ egg_id, crow_id }) => {
      try {
        let contact = null;
        try { contact = await resolveContact(db, crow_id); } catch { contact = null; }
        if (!contact) return errorText(`unknown contact: ${crow_id}`);
        const emit = await getEmit();
        const out = await proposeSwap(db, { eggId: egg_id, toCrowId: contact.crow_id, now: Date.now(), emit });
        if (!out.ok) return errorText(out.reason);
        return text(JSON.stringify({ proposed: true, trade_id: out.trade.trade_id, egg_id, to: contact.crow_id, expires_at: out.trade.expires_at, queued: true }));
      } catch (err) {
        return errorText(err.message);
      }
    },
  );

  register(
    "ramble_block",
    "Block a persona (by its x-only pubkey) from appearing in your world queries and remove its already-stored remote marks.",
    {
      persona: z.string().max(128),
      reason: z.string().max(64).optional(),
    },
    async ({ persona, reason }) => {
      try {
        const emit = await getEmit();
        const row = await blockPersona(db, persona, reason, { emit });
        return text(JSON.stringify(row));
      } catch (err) {
        return errorText(err.message);
      }
    },
  );

  register(
    "ramble_unblock",
    "Remove a persona from your block list.",
    {
      persona: z.string().max(128),
    },
    async ({ persona }) => {
      try {
        const emit = await getEmit();
        await unblockPersona(db, persona, { emit });
        return text(JSON.stringify({ unblocked: true, persona }));
      } catch (err) {
        return errorText(err.message);
      }
    },
  );

  /* ------------------------------------------------------------------ moves */

  // The SERVED library only (reviewed, licensed). Cached for this process: the
  // set changes only when the bundle is reinstalled.
  let servedMovesCache = null;
  const servedMoves = () => (servedMovesCache ??= servedLibrary());

  /** An entry without its joint-angle `pose` object (a chat answer needs no drawing data). */
  function withoutPose(entry) {
    if (!entry || typeof entry !== "object") return null;
    const { pose, ...rest } = entry;
    return rest;
  }

  /**
   * For You's place, read here too so a challenge picked from chat weighs the
   * same weather the panel would. No place, `weather:false`, or any failure is
   * simply no weather; the picker treats that as neutral.
   */
  async function movesWeather(prefs) {
    if (!prefs || prefs.weather === false) return null;
    try {
      const [{ readForYouSettings }, { weatherFor }] = await Promise.all([
        appImport("servers/gateway/for-you/settings.js"),
        appImport("servers/gateway/for-you/weather.js"),
      ]);
      const settings = await readForYouSettings(db);
      if (!settings || !settings.place) return null;
      if (settings.sections && settings.sections.weather === false) return null; // For You's own weather switch
      const w = await weatherFor(settings.place);
      return w ? { rain: w.rain, temp: w.temp, code: w.code } : null;
    } catch { return null; }
  }

  /** Today's card, made exactly as the panel makes it (same picker, same prefs). */
  async function movesToday() {
    const now = Date.now();
    const library = servedMoves();
    const prefs = await readPrefs(db);
    const weather = await movesWeather(prefs);
    const learning = await learningFlows(db, library);
    const emit = await getEmit();
    // The day's cards are drawn first, exactly as the panel draws them: that
    // draw mirrors the day's Now card into `moves.today`, the row
    // todayChallenge reads back, so chat and the panel never show two cards for
    // one day. A failure drawing them is logged and the card still answers
    // from the stored one.
    try {
      await dayCards(db, { now, weather, emit, library });
    } catch (err) {
      try { console.warn(`[ramble server] moves day cards unavailable: ${err?.message ?? err}`); } catch {}
    }
    const today = await todayChallenge(db, { now, weather, emit, library, learning });
    const pet = await petState(db, { now });
    const steps = await stepsState(db, { now });
    const streak = await streakState(db, { now });
    return {
      challenge: today ? {
        day: today.day,
        // No joint-angle data on a chat answer: that belongs to the panel view.
        entry: withoutPose(today.entry),
        reasons: Array.isArray(today.reasons) ? today.reasons : [],
        why: typeof today.why === "string" ? today.why : "",
        done: !!today.done,
        off: !!today.off,
        swap: Number.isInteger(today.swap) ? today.swap : 0,
      } : null,
      health: { energy: pet.energy, max: pet.energy_max, mood: pet.mood },
      steps: { day: steps.day, goal: steps.goal, steps: steps.steps, goal_met: steps.goal_met, walked: steps.walked },
      streak: { days: streak.days, nextHeartAt: streak.nextHeartAt, todayGood: streak.todayGood },
    };
  }

  register(
    "ramble_moves_today",
    "Today's movement challenge (or that challenges are paused), plus the bird's Health, today's steps and the current streak. It never pays Health — Done and Swap live on the Ramble panel.",
    {},
    async () => {
      try { return text(JSON.stringify(await movesToday())); }
      catch (err) { return errorText(err.message); }
    },
  );

  register(
    "ramble_moves_log",
    "Log a self-reported activity (a walk, a bike ride, a swim, ...) so it counts toward the bird's Health. Only the fixed vocabulary is stored — activity, minutes and effort — never the words the user used to describe it. For 'tell my AI about my ride', parse the sentence into those three fields here.",
    {
      activity: z.enum(ACTIVITY_KINDS),
      minutes: z.number().int().min(1).max(LOG_MINUTES_MAX),
      effort: z.enum(EFFORTS),
    },
    async ({ activity, minutes, effort }) => {
      try {
        // Validated here too, not only by the zod shape: an in-process caller
        // (the panel tests, another tool) bypasses the MCP schema validation.
        if (!ACTIVITY_KINDS.includes(activity)) {
          return errorText("activity must be one of " + ACTIVITY_KINDS.join(", "));
        }
        if (!Number.isInteger(minutes) || minutes < 1 || minutes > LOG_MINUTES_MAX) {
          return errorText(`minutes must be a whole number from 1 to ${LOG_MINUTES_MAX}`);
        }
        if (!EFFORTS.includes(effort)) return errorText("effort must be one of " + EFFORTS.join(", "));
        const emit = await getEmit();
        const now = Date.now();
        const out = await recordLog(db, { activity, minutes, effort, now, emit });
        await awardStreakHeart(db, { now, emit });
        return text(JSON.stringify({
          paid: out.paid,
          points: out.points,
          already: out.already,
          day: out.day,
          capped: !!out.capped,
          points_for: pointsFor({ activity, minutes, effort }),
          ...(await movesDay(db, { day: out.day, now })),
          streak: await streakState(db, { now }),
        }));
      } catch (err) { return errorText(err.message); }
    },
  );

  register(
    "ramble_moves_prefs",
    "Read the movement preferences, or change a few fields (on, kinds, equipment, limits, level, weather). With no arguments this only reads.",
    {
      patch: z.object({
        on: z.boolean().optional(),
        weather: z.boolean().optional(),
        level: z.number().int().min(1).max(3).optional(),
        kinds: z.array(z.string().max(32)).max(16).optional(),
        equipment: z.array(z.string().max(16)).max(8).optional(),
        limits: z.array(z.string().max(32)).max(16).optional(),
      }).optional(),
    },
    async (args = {}) => {
      try {
        // No patch is a read, never a write of the defaults over the row.
        const patch = args && typeof args.patch === "object" && !Array.isArray(args.patch) ? args.patch : null;
        if (!patch) return text(JSON.stringify({ prefs: await readPrefs(db) }));
        const emit = await getEmit();
        return text(JSON.stringify({ prefs: await writePrefs(db, patch, { emit }) }));
      } catch (err) { return errorText(err.message); }
    },
  );

  return server;
}
