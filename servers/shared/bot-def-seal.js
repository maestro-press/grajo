/**
 * The bot-definition WRITE seam (design: one chokepoint writer, reachable from bot-loadable code).
 *
 * A `pi_bot_defs` row carries a keyed MAC over its whole definition (`servers/shared/bot-def-mac.js`),
 * and the key behind it is host-only: `servers/shared/token-mac.js` is on
 * `tests/bot-seed-import-guard.test.js`'s guarded list. That is not negotiable — a bot that could
 * import the key module could mint the very MACs the MACs exist to require.
 *
 * But some legitimate WRITERS live in code the seed guard treats as bot-reachable, because any
 * add-on's `server/` directory and all of `scripts/pi-bots/**` are walked as starting trees:
 * Studio's "Update" (bundles/studio/server/give-tools.js), the artifacts companion migration
 * (scripts/pi-bots/artifacts-companions.mjs), skill promotion
 * (scripts/pi-bots/skill_promote.mjs). Those modules never run inside a bot's process — they are
 * loaded by the gateway, the bridge or a panel — but a static import of the key module from them
 * would be a real hole in the guard, and a raw UPDATE would leave the row's MAC stale (the bot
 * would then be refused at its next spawn).
 *
 * So the writer travels through this seam, exactly as provider keys travel through
 * `servers/shared/provider-keyring.js`: `servers/shared/bot-def-store.js` INSTALLS the real
 * implementation into this module when it is imported (any host process that verifies or writes a
 * definition imports it), and everybody else calls through here.
 *
 * THIS MODULE IMPORTS NOTHING AND HOLDS NO KEY — that is what makes it safe on a bot-reachable
 * load path.
 *
 * ONE SLOT PER PROCESS, NOT PER MODULE INSTANCE. An installed bundle copy (under
 * `<CROW_HOME>/bundles/<id>/`) resolves this file through its own `appImport`, which answers with
 * `process.env.CROW_APP_ROOT` when the gateway exported one and falls back to `~/crow` otherwise —
 * so the gateway and an installed panel could otherwise end up holding TWO module instances of
 * this file in one process, and the panel's copy would look uninstalled (every write refused with
 * `BOT_DEF_SEAL_UNAVAILABLE`). The slot therefore lives on `globalThis` under a registered symbol,
 * so every copy of this file in a process shares one installation. (The gateway also exports
 * `CROW_APP_ROOT` for itself and its children, which makes the two copies the same URL in the
 * normal case; the symbol makes it true even when they are not.)
 *
 * NONE INSTALLED → THE WRITE REFUSES (`BOT_DEF_SEAL_UNAVAILABLE`), the safe direction: nothing is
 * written, so no row can be left with a MAC that does not cover its definition. A process that
 * legitimately writes bot definitions imports the store at boot (the gateway's pre-listen bot-def
 * converter does), which installs it.
 */

/** Thrown by `writeBotDefSealed`/`signBotDefSealed` in a process with no store installed. */
export const BOT_DEF_SEAL_UNAVAILABLE = "BOT_DEF_SEAL_UNAVAILABLE";

/** The one installation slot, shared by every copy of this module in the process (see the header). */
const SLOT = Symbol.for("crow.bot-def-seal/1");
const slot = globalThis[SLOT] || (globalThis[SLOT] = {
  write: null, sign: null, setEnabled: null, verify: null,
});

/**
 * Install the store's implementation:
 *
 *   write(db, args)      → `writeBotDef`'s result ({ rowsAffected, generation })
 *   setEnabled(db, botId, enabled, opts) → the same shape (`opts` carries the `expect*` values)
 *   sign(row)            → `{ generation, def_mac, definition }` for a caller that issues its own
 *                          SQL (the version-history restore), which does not touch the database
 *                          itself. `definition` is the CANONICAL text the MAC covers: the caller
 *                          writes exactly that, so the row's text is canonical by construction.
 *   verify(row, opts)    → `{ ok, reason }`, SYNCHRONOUS (the era marker read from the secrets
 *                          side), for a caller that must decide inside its own transaction
 *                          (scripts/pi-bots/skill_promote.mjs) or over a captured version
 *                          (`{ replay: false }`, the history restore). `opts.anyMac` /
 *                          `opts.h1ValuesExist` carry the evidence the caller scanned, exactly as
 *                          the bridge's spawn gate passes it: the era decides whether a row that
 *                          lost its `def_mac` COLUMN is refused (`no-mac-column`), never the row's
 *                          shape (round C, items E3/M4).
 *
 * @param {{write?: Function|null, setEnabled?: Function|null, sign?: Function|null,
 *          verify?: Function|null}} impl
 */
export function installBotDefSeal(impl = {}) {
  slot.write = typeof impl.write === "function" ? impl.write : null;
  slot.setEnabled = typeof impl.setEnabled === "function" ? impl.setEnabled : null;
  slot.sign = typeof impl.sign === "function" ? impl.sign : null;
  slot.verify = typeof impl.verify === "function" ? impl.verify : null;
}

/** Forget the installed implementation (the test seam, and a shutdown). */
export function clearBotDefSeal() {
  slot.write = null;
  slot.setEnabled = null;
  slot.sign = null;
  slot.verify = null;
}

/** True when this process can write (or sign) a bot definition. */
export function botDefSealInstalled() {
  return typeof slot.write === "function" || typeof slot.sign === "function";
}

/** True when this process can VERIFY a bot definition synchronously. */
export function botDefVerifyInstalled() {
  return typeof slot.verify === "function";
}

function unavailable() {
  const err = new Error("Crow cannot write a bot definition in this process (no bot-def store installed).");
  err.code = BOT_DEF_SEAL_UNAVAILABLE;
  return err;
}

/**
 * Write one bot definition through the installed store — the ONE write path for a
 * `pi_bot_defs` row. `args` is `writeBotDef`'s own (bot_id, definition, enabled, project_id,
 * display_name, mode, ownerFullReplace) and, for an UPDATE, the three values the caller read
 * (`expectDefinition`, `expectEnabled`, `expectProjectId` — REQUIRED, see the store: a partial write
 * must state the row it read, or it throws `BOT_DEF_EXPECT_REQUIRED`). The store computes the
 * generation and the MAC, and writes the approved copy. A row that does not verify refuses with
 * `code === "BOT_DEF_UNVERIFIED"` unless the caller is a full owner-facing save
 * (`ownerFullReplace`).
 *
 * @throws an Error with `code = BOT_DEF_SEAL_UNAVAILABLE` when nothing is installed.
 * @returns {Promise<{rowsAffected: number, generation: number}>}
 */
export async function writeBotDefSealed(db, args) {
  if (typeof slot.write !== "function") throw unavailable();
  return slot.write(db, args);
}

/** Toggle `enabled` through the installed store (`enabled` is inside the MAC, so this re-MACs). */
export async function setBotEnabledSealed(db, botId, enabled, opts = {}) {
  if (typeof slot.setEnabled !== "function") throw unavailable();
  return slot.setEnabled(db, botId, enabled, opts);
}

/**
 * Sign a definition a caller is about to write ITSELF (the version-history restore, whose UPDATE
 * is issued by a generic table-driven runner inside one transaction, and skill promotion, whose
 * UPDATE is its own): returns the MAC, the generation AND the canonical definition text to put in
 * the same statement. Bumps the generations file exactly like a write does, so a crash between
 * this call and the row's write is the header's "pending" case.
 *
 * @throws an Error with `code = BOT_DEF_SEAL_UNAVAILABLE` when nothing is installed.
 * @returns {{generation: number, def_mac: string, definition: string|null,
 *            settle: () => boolean, abandon: () => boolean}}
 */
export function signBotDefSealed(row) {
  if (typeof slot.sign !== "function") throw unavailable();
  return slot.sign(row);
}

/**
 * Verify one row WITHOUT a database: the synchronous rule set (`verifyBotDefSync`) with the era
 * taken from the secrets side — plus, when the caller scanned it, its own evidence (`anyMac`,
 * `h1ValuesExist`). `{ replay: false }` verifies a CAPTURED version at the generation it was written
 * at (the history restore), never skipping the MAC.
 *
 * A process with no store installed answers `{ ok: false, reason: "unverified" }` — never `ok`.
 *
 * @returns {{ok: boolean, reason: string}}
 */
export function verifyBotDefSealed(row, opts = {}) {
  if (typeof slot.verify !== "function") return { ok: false, reason: "unverified" };
  return slot.verify(row, opts);
}