/**
 * Crow Recurring Reports' approvals: going live, pausing, resuming, and the recipe saves that may or
 * may not move a live report.
 *
 * A report is allowed to run only while it carries a go-live seal over the "live set" — the exact
 * revision, the two hashes, the schedule row and its zone, the sender, the bot, the project, the artifact,
 * the delivery rule, the comment defaults, the AI switch and the resolved model — made under the
 * keychain key (reports/seal.js). This module is the only writer of that seal, and every write of it
 * needs an owner actor: `{kind: "owner"}`. A bot may save a recipe (`botSaveRecipe`), and may never
 * re-stamp; an owner route may re-stamp a live report only when nothing the owner approved has moved
 * (the same sources hash, the same model-call status).
 *
 * `isLive` is the reader's whole answer to "may this report run": the status is `live`, a revision row
 * exists for `live_rev`, the schedule resolves and is enabled, the model the recipe needs resolves NOW
 * (never read from the row), and the seal verifies over the report's current values. Any direct UPDATE
 * of a live-set column, or a model resolution that changed, breaks it. It never throws: a broken report
 * is `false`. `verifyLive` is the same answer carrying the verified live set, and the parsed recipe of
 * the sealed revision those hashes came from, instead of a bare boolean.
 *
 * Sealing and verifying never trust the hash columns of the revision row. They parse the sealed
 * revision's own `recipe_json`, recompute both hashes under this module's block registry, and refuse
 * when the recomputed pair disagrees with what the row stores beside it. A direct UPDATE of the recipe
 * text, or of either hash column, therefore cannot leave a seal verifying; and the report head is
 * never read for them, so a later save cannot silently re-bless the seal either.
 *
 * THE MODEL A ROLE NAMES (`modelRole` on an AI block). The live set's sealed `modelRef` is the RESOLVED
 * reference of that role at go-live time: `liveSetFor` seals what `freshModelRef` resolved a moment
 * ago, and `freshModelRef` reads the role the sealed revision's own recipe names and resolves it through
 * `resolveRoleKey` with the loaded role context (asked for a CHAT model: a report's block writes, so an
 * embed, score or transcription binding is not one), then the provider row behind the key
 * (the same chain `defaultResolveModelRef` takes for a bot's model). A role that resolves nothing,
 * resolves to an endpoint that is not on this machine, or resolves to one the completion would refuse
 * (a lazy loader, a `/llm/v1` door) is `model_unresolved` at go-live: no live set and
 * nothing sealed. At every later check the role is resolved AGAIN and its reference compared with the
 * sealed one, so a role rebound to another model (or another endpoint) breaks the seal exactly like a
 * bot repointed at another model does, and the report pauses on the same path with the same notice. The
 * block itself never calls a model other than the sealed one (blocks/present/ai-commentary.js).
 *
 * WHAT THE SEAL DOES NOT COVER, stated here so no reader has to infer it:
 *
 *   - `status` is not a sealed field. A direct `UPDATE reports SET status = 'live'` therefore undoes an
 *     owner pause as far as this module's reader is concerned, and only the seal, the schedule, the
 *     revision row and the model resolution stand in the way. A row whose seal still verifies (an owner
 *     pause keeps it, see below) and whose status was flipped back from the outside WOULD read live.
 *     PR 1b's runner must therefore refuse a run whose status was changed outside this module.
 *   - An owner or system pause keeps the seal ON PURPOSE, so a resume can prove that nothing moved while
 *     the report was stopped. What does drop the seal is a settings change to a live-set field on a live
 *     report: the pause and the null live_seal/live_nonce are one write, so flipping the column back
 *     cannot revive the old approval and only a fresh go-live re-approves.
 *   - The pause audit row says `decided: "refused"`. The audit vocabulary
 *     (`report_approvals_audit.decided`, store.js's APPROVAL_DECISIONS) has only approved, refused and
 *     revoked: there is no "paused" word to write, so a pause is recorded as the approval being refused
 *     for as long as the pause lasts.
 *   - The replay limit: an old `live_rev`, `live_seal` and `live_nonce` restored TOGETHER with every
 *     column they were made over still verify. A seal is a tamper check over content, not a capability
 *     and not a clock, so a whole-row rollback is outside what it can see. A partial restore, or a
 *     restore that misses one covered field, does not verify.
 *
 * Every function takes `(db, deps, input)`. `deps` is the whole seam, and each member falls back to
 * the real thing only when it is absent:
 *   - `loadSeed()`: the keychain seed (`{seed}` or the raw bytes). Missing -> `keychain_key_missing`.
 *   - `now()`: epoch ms for audit rows. The stores stamp the report row with their own clock.
 *   - `getRun(db, runId)`: a preview or run row, or null. Runs arrive in PR 1b, so the default answers
 *     null: there is no preview to approve, and go-live therefore cannot succeed in production until
 *     that PR injects the real reader. It is not stubbed out on purpose, it is that the tables do not
 *     exist yet.
 *   - `getSchedule(db, report)`: `{cron, tz}` from the report's `schedules` row, or null. The default
 *     also answers null for a disabled row (`enabled = 0`): a switched-off schedule fires nothing.
 *   - `resolveModelRef(db, report)`: `{providerId, model, locality, baseUrlHost}`, or null.
 *   - `resolveRoleModelRef(db, modelRole)`: the same shape, for a recipe whose AI block names a role
 *     (`modelRole: "role:<id>"`). It resolves the role NOW, through `resolveRoleKey` and this instance's
 *     loaded role context. See THE MODEL A ROLE NAMES below.
 *   - `senderReady(db, accountId)`: whether that Crow Mail account can send right now. Nothing is
 *     injected by default and the default answers false (fail closed): the real reader lives in
 *     `reports/sender-ready.js`, which the routes inject, because this module imports nothing under
 *     `mail/`.
 *   - `registry`: the block registry (`{type: {sourceBearing}}`) or null. It is the server's own and
 *     never a caller's: it defaults to `blocks/index.js`'s `blockRegistry`, so a save, a seal and a
 *     verification all read the same flags. A caller may narrow it (a test), and null still counts every
 *     block as source-bearing (fail closed) for a caller measuring exactly that.
 *   - `getSecrets()`: literal secret values a pause reason is scrubbed of.
 *   - `linkFor(db, {report, recipient, run, sendId})`: the link one recipient's mail opens, or null when
 *     this PR cannot make one for that recipient (`reports/links.js`). Go-live asks it about every
 *     approved recipient, so a report that would mail a link going nowhere is never taken live.
 *
 * Every refusal is an Error with a `code`: `owner_only`, `not_found`, `bad_input`, `bad_recipe`,
 * `keychain_key_missing`, `preview_missing`, `preview_stale`, `preview_failed`, `no_schedule`,
 * `sender_not_ready`, `model_unresolved`, `go_live_needed`, `bad_seal_field`, `link_unavailable` (an
 * approved recipient has no link kind, so its mail would point nowhere) and `recipient_changed`
 * for a recipient write whose row moved under the decision.
 *
 * Recipients live at the bottom of this module: propose (by the owner or a bot), approve, refuse and
 * revoke, plus the list a page reads and the check the send door makes. A recipient is NOT part of the
 * live set, so adding or changing one never changes the report's status; what an approved row carries is
 * its own seal over the report, the row, the address and the tier (or the empty string for "the report's
 * default"). Custom steps, hosts, credential bindings and proposals are later PRs: they have their own
 * kinds in seal.js and no approval path here yet.
 */
import { randomBytes } from "node:crypto";
import { MODEL_BLOCK_TYPES, canonicalJson, recipeCallsModel, recipeHash, sourcesHash } from "./recipe-hash.js";
import { blockRegistry } from "./blocks/index.js";
import { approvalSeal, newApprovalNonce, verifyApprovalSeal } from "./seal.js";
import { sealAuthorRevision } from "./revision-author.js";
import { SENDER_SEAL_KEY, sealSender } from "./sender-seal.js";
import { getReport, getRevision, recordAudit, saveRecipe, setState, updateReportColumns } from "./store.js";
import { linkFor } from "./links.js";
import { loadKeychainKey } from "../keychain/key.js";
import { resolveProviderConfig } from "../ai/resolve-profile.js";
import { getSecretValues } from "../../shared/secret-values.js";
import { redactSecrets } from "../../shared/redact-secrets.js";
import { isLocallyOrchestratable } from "../../shared/locality.js";
import { isLazyLoader } from "../../shared/lazy-loader.js";
import { isDoorUrl } from "../models/door-resolve.js";

/* ------------------------------------------------------------------------ the words */

/** The only actor kind that may approve anything. */
export const OWNER_ACTOR = Object.freeze({ kind: "owner" });

/** A live report's status word (the store validates none of these: this module owns them). */
export const REPORT_LIVE = "live";
export const REPORT_PAUSED = "paused";

/** The delivery rules a report may carry. */
export const DELIVERY_MODES = Object.freeze(["email_full", "email_link", "both", "crow_only"]);

/** The comment tiers (`a` is the most open) and the two comment visibilities. */
export const COMMENT_TIERS = Object.freeze(["a", "b", "c"]);
export const COMMENT_VISIBILITIES = Object.freeze(["own", "all"]);

/** The head columns `updateSettings` may write. */
export const REPORT_SETTING_KEYS = Object.freeze([
  "sender_account_id", "delivery_mode", "comment_tier_default", "comment_visibility", "ai_commentary",
  "title", "notify_every_run",
]);

/** The five settings that are part of the live set: changing one on a live report stops it. */
const LIVE_SETTING_KEYS = Object.freeze([
  "sender_account_id", "delivery_mode", "comment_tier_default", "comment_visibility", "ai_commentary",
]);

/** The pause reason a live-set settings change leaves (plain words, no dash). */
export const SETTINGS_CHANGED_PAUSE_REASON = "You changed settings. Preview and go live again.";

/** The longest pause reason kept: a wall of text is not a reason, and it is shown on a card. */
const PAUSE_REASON_MAX = 300;

/** The longest title `updateSettings` accepts. */
const TITLE_MAX = 200;

/**
 * The few helpers a sibling approval module borrows instead of copying: the owner rule, the keychain
 * seed reader, the report lookup, the refusal constructor, the string coercion and the provenance word
 * (`owner` or `bot:<id>`). Frozen, and read-only by construction: nothing here writes or decides
 * anything on its own, so `reports/steps.js` can hold the same rules without a second copy that could
 * drift. Every existing export of this module is unchanged.
 */
export const approvalInternals = Object.freeze({
  fail,
  text,
  requireOwner,
  requireReport,
  seedOf,
  resolveDeps,
  normalizeProposedBy,
});

/** C0 controls, DEL, C1 controls and the Unicode line and paragraph separators. */
const CONTROL_CHARS_ALL = /[\u0000-\u001f\u007f\u0080-\u009f\u2028\u2029]+/g;

function fail(code, detail) {
  const err = new Error(detail ? `${code}: ${detail}` : code);
  err.code = code;
  if (detail) err.detail = detail;
  return err;
}

/* --------------------------------------------------------------------------- helpers */

function text(value) {
  if (value == null) return "";
  return typeof value === "string" ? value : String(value);
}

/** A 0/1 column as the number the seal carries. */
function flagNumber(value) {
  return value === 1 || value === true ? 1 : 0;
}

/** The actor rule: every approving function needs the owner and nobody else. */
function requireOwner(actor) {
  if (!actor || typeof actor !== "object" || actor.kind !== "owner") throw fail("owner_only");
  return actor;
}

async function requireReport(db, reportId) {
  if (typeof reportId !== "string" || !reportId) throw fail("bad_input", "reportId");
  const report = await getReport(db, reportId);
  if (!report) throw fail("not_found", "report");
  return report;
}

/** A stored recipe JSON text as an object. A body that is not a recipe is `bad_recipe`. */
function recipeOf(json) {
  if (json == null || json === "") return { blocks: [] };
  try {
    return JSON.parse(json);
  } catch {
    throw fail("bad_recipe", "recipe_json");
  }
}

/** Does this recipe need a model? A recipe this module cannot read counts as needing one. */
function callsModel(recipe, aiFlag) {
  try {
    return recipeCallsModel(recipe, aiFlag);
  } catch {
    return true;
  }
}

/**
 * A resolved model reference as the canonical JSON text the seal carries: `{providerId, model,
 * locality, baseUrlHost}`, or "" when no model is called. `null`, a blank string and an object that
 * cannot be written as canonical JSON all come back as "".
 */
export function modelRefText(value) {
  if (value == null) return "";
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return "";
    try {
      return canonicalJson(JSON.parse(trimmed));
    } catch {
      return trimmed;
    }
  }
  if (typeof value !== "object") return "";
  try {
    return canonicalJson(value);
  } catch {
    return "";
  }
}

/**
 * The locality word a resolved model reference carries: `local` or `cloud`.
 *
 * This is the same rule `defaultResolveModelRef` applies at go-live, read from the ref it answered
 * (`{providerId, model, locality, baseUrlHost}`), or recomputed from a `baseUrl` with
 * `isLocallyOrchestratable` when the ref carries none. A ref that carries neither is `cloud`: a model
 * nobody can place on this machine is not one a report may send its items to.
 */
export function modelRefLocality(value) {
  if (value == null) return "cloud";
  if (typeof value === "string") {
    const trimmed = value.trim();
    if (!trimmed) return "cloud";
    try {
      return modelRefLocality(JSON.parse(trimmed));
    } catch {
      return "cloud";
    }
  }
  if (typeof value !== "object") return "cloud";
  if (typeof value.locality === "string" && value.locality) return value.locality;
  return isLocallyOrchestratable({ baseUrl: value.baseUrl }) ? "local" : "cloud";
}

/* ------------------------------------------------------------------------ the defaults */

function defaultLoadSeed() {
  return loadKeychainKey()?.seed ?? null;
}

/**
 * There is no run to look up yet: `reports` has no preview or run tables until PR 1b adds them, so the
 * default answers null and go-live refuses with `preview_missing`. PR 1b injects the real reader; this
 * is a missing table, not a stub that pretends a preview exists.
 */
async function defaultGetRun() {
  return null;
}

/**
 * The report's own `schedules` row, or null when it has none, when the row is disabled (`enabled = 0`)
 * or when there is no schedules table. A switched-off schedule is no schedule: nothing will fire, so a
 * report anchored to it must not read as live.
 */
async function defaultGetSchedule(db, report) {
  const raw = report?.schedule_id;
  if (raw == null || raw === "") return null;
  const id = Number(raw);
  if (!Number.isInteger(id)) return null;
  let row;
  try {
    const { rows } = await db.execute({
      sql: "SELECT cron_expression, tz FROM schedules WHERE id = ? AND enabled = 1",
      args: [id],
    });
    row = rows[0];
  } catch {
    return null;
  }
  if (!row || typeof row.cron_expression !== "string" || !row.cron_expression.trim()) return null;
  return { cron: row.cron_expression.trim(), tz: typeof row.tz === "string" ? row.tz : "" };
}

/** A `provider/model` key split on its FIRST slash (model ids carry no slash). */
function splitKey(key) {
  const s = text(key);
  const i = s.indexOf("/");
  if (i <= 0) return { providerId: "", model: "" };
  return { providerId: s.slice(0, i), model: s.slice(i + 1) };
}

/** The host (and port) of a base URL, or "" when it is not a URL. */
function hostOf(baseUrl) {
  try {
    return new URL(String(baseUrl)).host;
  } catch {
    return "";
  }
}

/**
 * The model key a bot's own spawn uses: `pi_bot_defs.definition.models.default`, a `provider/model`
 * key or a `role:<id>` reference. A role is resolved against this instance's bindings (the same
 * resolver a bot's session uses), because the key a bot stores may name a role rather than a row.
 * Null when the bot names no model (it runs on the instance default) or the def cannot be read.
 */
async function botModelKey(db, botId) {
  if (typeof botId !== "string" || !botId) return null;
  let definition;
  try {
    const { rows } = await db.execute({
      sql: "SELECT definition FROM pi_bot_defs WHERE bot_id = ?",
      args: [botId],
    });
    definition = rows[0]?.definition;
  } catch {
    return null;
  }
  let def;
  try {
    def = JSON.parse(definition || "{}");
  } catch {
    return null;
  }
  const key = typeof def?.models?.default === "string" ? def.models.default.trim() : "";
  if (!key) return null;
  if (!key.startsWith("role:")) return key;
  try {
    const { resolveRole } = await import("../../shared/model-roles-store.js");
    const resolved = await resolveRole(db, key, { need: "chat" });
    return resolved && typeof resolved.key === "string" && resolved.key ? resolved.key : null;
  } catch {
    return null;
  }
}

/**
 * The provider row behind a key, and the reference a seal carries for it: the same read, so a caller that
 * has to judge the ENDPOINT (not only its locality or host) never resolves the row twice.
 * Null when the key is not a key, or no provider row can be read for it.
 */
async function providerForKey(db, key) {
  const { providerId, model } = splitKey(key);
  if (!providerId || !model) return null;
  let config;
  try {
    config = await resolveProviderConfig(db, providerId, model);
  } catch {
    return null;
  }
  const baseUrl = text(config?.baseUrl);
  return {
    baseUrl,
    providerType: text(config?.provider_type || config?.providerType),
    ref: {
      providerId,
      model: text(config?.model) || model,
      locality: isLocallyOrchestratable({ baseUrl }) ? "local" : "cloud",
      baseUrlHost: hostOf(baseUrl),
    },
  };
}

/**
 * A raw `provider/model` key as the resolved reference every seal carries
 * (`{providerId, model, locality, baseUrlHost}`): the provider row behind the key (a DB row first,
 * then models.json), then the locality of that endpoint. The host is sealed too, so a provider
 * repointed from one cloud endpoint to another under the same id changes the live set. Null when the
 * key is not a key, or no provider row can be read for it.
 */
async function modelRefForKey(db, key) {
  const found = await providerForKey(db, key);
  return found ? found.ref : null;
}

/**
 * Resolve the model a report's bot would run with, the way a chat request resolves one: the bot's
 * stored key, then the provider row behind it. A bot whose stored key is a `role:<id>` is resolved
 * through this instance's bindings first (the same resolver a bot's session uses).
 *
 * The chain is a few existing accessors rather than one: `pi_bot_defs.definition.models.default` (the
 * key every gateway panel reads), `resolveRole` (model-roles-store.js, for a `role:` key),
 * `resolveProviderConfig` (ai/resolve-profile.js, the same resolver /llm/v1 uses) and
 * `isLocallyOrchestratable` (shared/locality.js). There is no single bot-model accessor in the
 * gateway; a caller that wants a different chain injects `resolveModelRef`, and the production
 * callers take this one through `buildApprovalsDeps` (reports/approvals-deps.js).
 */
export async function defaultResolveModelRef(db, report) {
  const key = await botModelKey(db, report?.bot_id);
  if (!key) return null;
  return modelRefForKey(db, key);
}

/** The prefix a recipe's `modelRole` setting carries: the one vocabulary model-roles.js owns. */
const ROLE_PREFIX = "role:";

let roleModules = null;

/** The two role modules, loaded on first use so the approvals module never costs a boot its roles. */
function loadRoleModules() {
  if (!roleModules) {
    roleModules = Promise.all([
      import("../../shared/model-roles.js"),
      import("../../shared/model-roles-store.js"),
    ]).then(([roles, store]) => ({ roles, store }));
  }
  return roleModules;
}

/**
 * The reference a model role names NOW: `role:<id>` -> its chain (`resolveRoleKey`, over this
 * instance's loaded role context, asked for a CHAT model) -> the raw `provider/model` it resolves to ->
 * the provider row behind it. The same shape `defaultResolveModelRef` answers, so a seal made over a
 * role's reference compares with a bot's the same way. Null when the role resolves nothing (unbound,
 * unknown, unconfigured, foreign, a class or capability refusal), when no provider row can be read for
 * what it does resolve, or when that row is an endpoint the completion itself refuses (a lazy loader
 * that would load its model on the first request, or a `/llm/v1` door: `isLazyLoader`, `isDoorUrl`).
 *
 * This is what `liveSetFor` seals for a recipe whose AI block names a role, and what the block and every
 * later verification resolve again to compare with the sealed reference.
 */
export async function defaultResolveRoleModelRef(db, modelRole) {
  if (typeof modelRole !== "string" || !modelRole.startsWith(ROLE_PREFIX)) return null;
  let key = null;
  try {
    const { roles, store } = await loadRoleModules();
    const ctx = await store.loadRoleContext(db);
    // `need: "chat"`: a report's block asks a model to WRITE, so a role bound to an embedding, re-rank or
    // transcription model is not a model this report may use, whatever capability the role itself declares.
    const resolved = roles.resolveRoleKey(modelRole, { ...ctx, need: "chat" });
    key = resolved && typeof resolved.key === "string" && resolved.key ? resolved.key : null;
  } catch {
    return null;
  }
  if (!key) return null;
  const found = await providerForKey(db, key);
  if (!found) return null;
  // The completion refuses both of these, so a report sealed over one could never run: refused here,
  // where the reference is resolved, so go-live answers `model_unresolved`.
  if (isLazyLoader({ baseUrl: found.baseUrl, providerType: found.providerType })) return null;
  if (isDoorUrl(found.baseUrl)) return null;
  return found.ref;
}

/**
 * The role a recipe's AI blocks name, or null. A `modelRole` that does not begin with `role:` is not a
 * role: it is validated away at save (`blocks/present/ai-commentary.js`), and a value that reached a
 * stored recipe some other way resolves to nothing rather than silently sealing a different model.
 * One role per report: `validateRecipe` refuses a recipe naming two different ones.
 */
export function modelRoleOfRecipe(recipe) {
  const blocks = Array.isArray(recipe?.blocks) ? recipe.blocks : [];
  for (const block of blocks) {
    if (block == null || typeof block !== "object" || Array.isArray(block)) continue;
    if (!MODEL_BLOCK_TYPES.includes(block.type)) continue;
    const settings = block.settings;
    if (settings == null || typeof settings !== "object" || Array.isArray(settings)) continue;
    const role = settings.modelRole;
    if (typeof role === "string" && role.startsWith(ROLE_PREFIX)) return role;
  }
  return null;
}

/**
 * Nothing injected, no sender: fail closed. The real reader is `reports/sender-ready.js`, which reads
 * the Crow Mail account row and its keychain credential, and which the routes inject. This module does
 * not import it (the reports code reaches mail through that one injected seam), so go-live without an
 * injected reader refuses with `sender_not_ready` rather than approving a sender nobody looked at.
 */
async function defaultSenderReady() {
  return false;
}

function defaultGetSecrets() {
  try {
    return getSecretValues();
  } catch {
    return [];
  }
}

/** `deps` with every member present; a member that is absent falls back to the real thing. */
function resolveDeps(deps) {
  const given = deps == null ? {} : deps;
  const fn = (key, fallback) => (typeof given[key] === "function" ? given[key] : fallback);
  return {
    loadSeed: fn("loadSeed", defaultLoadSeed),
    now: fn("now", Date.now),
    getRun: fn("getRun", defaultGetRun),
    getSchedule: fn("getSchedule", defaultGetSchedule),
    resolveModelRef: fn("resolveModelRef", defaultResolveModelRef),
    resolveRoleModelRef: fn("resolveRoleModelRef", defaultResolveRoleModelRef),
    senderReady: fn("senderReady", defaultSenderReady),
    getSecrets: fn("getSecrets", defaultGetSecrets),
    // The block registry is the server's own; a caller may narrow it, and an explicit null still means
    // "no registry at all" (every block source-bearing), which is the safe side to be wrong on.
    registry: given.registry === undefined ? blockRegistry : given.registry,
    linkFor: fn("linkFor", linkFor),
  };
}

/** The keychain seed as bytes, or `keychain_key_missing`: no seal can be made without it. */
async function seedOf(deps) {
  const loaded = await deps.loadSeed();
  const seed = loaded == null
    ? null
    : (Buffer.isBuffer(loaded) || loaded instanceof Uint8Array ? loaded : loaded.seed);
  if (!Buffer.isBuffer(seed) && !(seed instanceof Uint8Array)) throw fail("keychain_key_missing");
  if (!seed.length) throw fail("keychain_key_missing");
  return seed;
}

/* ------------------------------------------------------------------------ the live set */

/**
 * One revision's two hashes, recomputed from its own recipe text under `registry`. Null when that text
 * is not a recipe at all (a row a direct UPDATE broke), which every caller treats as a refusal.
 */
function recomputedHashes(revision, registry) {
  if (revision == null) return null;
  let recipe;
  try {
    recipe = recipeOf(revision.recipe_json);
  } catch {
    return null;
  }
  try {
    return { recipeHash: recipeHash(recipe), sourcesHash: sourcesHash(recipe, registry) };
  } catch {
    return null;
  }
}

/**
 * A revision's hashes as the seal carries them: recomputed from the revision's OWN `recipe_json`, and
 * refused (`bad_recipe`) when that pair disagrees with the hash columns stored beside it. The columns
 * are a fast path for readers, never the truth: otherwise a direct UPDATE of the text (a new source
 * URL, a new model block) or of a column would leave a seal verifying over content nobody approved. A
 * report with no revision row yet (a draft at revision 0) hashes as "".
 */
function sealedHashes(revision, registry) {
  if (revision == null) return { recipeHash: "", sourcesHash: "" };
  const hashes = recomputedHashes(revision, registry);
  if (!hashes) throw fail("bad_recipe", "revision_json");
  if (hashes.recipeHash !== text(revision.recipe_hash)
    || hashes.sourcesHash !== text(revision.sources_hash)) {
    throw fail("bad_recipe", "revision_hash");
  }
  return hashes;
}

/** The largest integer a JS number names exactly: an id column past it is not an id the seal made. */
const MAX_SAFE_ID = Number.MAX_SAFE_INTEGER;

/** What `idField` answers for a column holding something an id column cannot hold. */
const NOT_AN_ID = Symbol("not-an-id");

/**
 * An id column as the seal carries it: a positive safe-integer NUMBER (or a bigint in that range, which
 * some drivers hand back), "" when the column is unset, and `NOT_AN_ID` for anything else.
 *
 * There is deliberately no coercion. A TEXT column holding "12", "12.0" or "0x0c" is not the number 12
 * the seal was made over even though `Number()` reads all three as 12, and neither is a zero, a
 * negative, a fraction or a number past the safe range an id. A row spelled that way is not live.
 */
function idField(value) {
  if (value == null) return "";
  if (typeof value === "string") return value === "" ? "" : NOT_AN_ID;
  if (typeof value === "number") {
    return Number.isSafeInteger(value) && value > 0 ? value : NOT_AN_ID;
  }
  if (typeof value === "bigint") {
    return value > 0n && value <= BigInt(MAX_SAFE_ID) ? Number(value) : NOT_AN_ID;
  }
  return NOT_AN_ID;
}

/**
 * The fields the go-live seal covers, in the shape seal.js's `live` kind takes.
 *
 * Every string is normalised to "" when the column is null, an id column to a number or "", and
 * `aiCommentary` to 0/1, so an untouched row always seals to the same payload. `recipeHash` and
 * `sourcesHash` are recomputed from the revision row for the sealed revision (never from the head
 * columns and never from that row's own hash columns: `sealedHashes` refuses a row whose text and
 * columns disagree), so a later save moves the head without re-blessing the seal. `title` is not a
 * sealed field: it is a label the owner renames freely, and PR 2b must treat it as untrusted text when
 * it uses it as a subject line.
 *
 * `overrides` exists for go-live, the one writer that needs a value before it is on the row: `rev` (the
 * head revision being sealed), `nonce` (the fresh one about to be written) and `modelRef` (resolved a
 * moment ago). Every other writer passes none of them: a re-stamp seals the live set it just verified,
 * so it neither re-reads the schedule nor resolves the model again.
 *
 * `modelRef` is the sealed model reference: for a recipe whose AI block names a role, the RESOLVED
 * reference of that role at go-live time (`{providerId, model, locality, baseUrlHost}`, see THE MODEL A
 * ROLE NAMES in the header), and otherwise the bot's own model as before.
 *
 * @param {object} db
 * @param {object} [deps]
 * @param {object} report a report row
 * @param {{rev?: number, nonce?: string, modelRef?: string}} [overrides]
 * @returns {Promise<object>} the `live` field list including the nonce
 * @throws {Error} `bad_recipe` when the sealed revision's text and its hash columns disagree, or
 *   `bad_input` when an id column holds something that is not an id (a text spelling, a zero, a
 *   fraction): such a row cannot be sealed over, so it never verifies either
 */
export async function liveSetFor(db, deps, report, overrides = {}) {
  const d = resolveDeps(deps);
  if (report == null || typeof report !== "object") throw fail("not_found", "report");
  const over = overrides == null ? {} : overrides;
  const rev = over.rev !== undefined ? over.rev : report.live_rev;
  const revision = Number.isInteger(Number(rev)) ? await getRevision(db, report.id, Number(rev)) : null;
  const hashes = sealedHashes(revision, d.registry);
  const schedule = await d.getSchedule(db, report);
  const projectId = idField(report.project_id);
  const scheduleId = idField(report.schedule_id);
  if (projectId === NOT_AN_ID || scheduleId === NOT_AN_ID) throw fail("bad_input", "id column");
  return {
    reportId: report.id,
    rev: Number.isFinite(Number(rev)) ? Number(rev) : 0,
    recipeHash: hashes.recipeHash,
    sourcesHash: hashes.sourcesHash,
    cron: text(schedule?.cron),
    tz: text(schedule?.tz),
    senderAccountId: text(report.sender_account_id),
    botId: text(report.bot_id),
    projectId,
    artifactId: text(report.artifact_id),
    scheduleId,
    deliveryMode: text(report.delivery_mode),
    commentTierDefault: text(report.comment_tier_default),
    commentVisibility: text(report.comment_visibility),
    aiCommentary: flagNumber(report.ai_commentary),
    modelRef: over.modelRef !== undefined ? modelRefText(over.modelRef) : modelRefText(report.model_ref),
    nonce: text(over.nonce !== undefined ? over.nonce : report.live_nonce),
  };
}

/**
 * The model reference a revision needs, resolved afresh: "" when that recipe calls no model, otherwise
 * the canonical text of what the recipe's own model answers now. Null when the recipe needs a model and
 * none resolved.
 *
 * WHICH MODEL: a recipe whose AI block names a role (`modelRole: "role:<id>"`) is resolved through
 * `deps.resolveRoleModelRef` (the role, through `resolveRoleKey` with the loaded role context), and one
 * that names none through `deps.resolveModelRef` (the report's bot). A role that resolves to an endpoint
 * that is not on this machine is `model_unresolved` here too: it is the same rule a preview applies, and
 * a report may not go live on a model nowhere near this box.
 */
async function freshModelRef(db, deps, report, revision) {
  if (!revision) return "";
  let recipe;
  try {
    recipe = recipeOf(revision.recipe_json);
  } catch {
    return null;
  }
  if (!callsModel(recipe, report.ai_commentary)) return "";
  const modelRole = modelRoleOfRecipe(recipe);
  const resolved = modelRole
    ? await deps.resolveRoleModelRef(db, modelRole)
    : await deps.resolveModelRef(db, report);
  const ref = modelRefText(resolved);
  if (ref === "") return null;
  if (modelRole && modelRefLocality(resolved) !== "local") return null;
  return ref;
}

/**
 * This report's seal, verified: the live-set fields it covers and the parsed recipe of the sealed
 * revision the two hashes were recomputed from (the same `revision` row, read once), or null. That is
 * everything `isLive` checks except the status word, so a paused report can be asked whether its
 * approval is still good. Never throws.
 *
 * @returns {Promise<{fields: object, recipe: object}|null>}
 */
async function verifiedLive(db, deps, report) {
  try {
    const d = resolveDeps(deps);
    if (report == null || typeof report !== "object") return null;
    const rev = Number(report.live_rev);
    if (!Number.isInteger(rev) || rev < 1) return null;
    if (typeof report.live_nonce !== "string" || !report.live_nonce) return null;
    if (typeof report.live_seal !== "string" || !report.live_seal) return null;
    if (typeof report.id !== "string" || !report.id) return null;
    const revision = await getRevision(db, report.id, rev);
    if (!revision) return null;
    const recipe = recipeOf(revision.recipe_json);
    const schedule = await d.getSchedule(db, report);
    if (!schedule || !text(schedule.cron)) return null;
    // The model is resolved now, never read from the row: a bot repointed at another provider, or a
    // provider repointed at another endpoint, must stop the report.
    const modelRef = await freshModelRef(db, d, report, revision);
    if (modelRef == null) return null;
    const seed = await seedOf(d);
    const fields = await liveSetFor(db, d, report, { modelRef });
    if (!verifyApprovalSeal("live", fields, report.live_seal, seed)) return null;
    return { fields, recipe };
  } catch {
    return null;
  }
}

/** The verified live-set fields alone, or null. Never throws. */
async function verifiedLiveSet(db, deps, report) {
  const verified = await verifiedLive(db, deps, report);
  return verified ? verified.fields : null;
}

/** Does this report's seal still verify, whatever its status says? Never throws. */
async function sealVerifies(db, deps, report) {
  return (await verifiedLive(db, deps, report)) !== null;
}

/**
 * The verified live set of a report that may run, or null. `null` means one of: not an object, not
 * `live`, or the seal does not verify over the row's current values (a direct UPDATE of a live-set
 * column or of the sealed revision, a schedule that stopped resolving, a model that resolves
 * differently now, no keychain seed). Never throws.
 *
 * When it is not null the answer is the live-set object the seal was verified over, spread out for the
 * reader (`rev`, `cron`, `tz`, `senderAccountId`, `deliveryMode`, ... `nonce`) and also under
 * `liveSet`, so a caller can hand exactly those fields back to `verifyApprovalSeal` without rebuilding
 * them, plus `recipe`: the parsed recipe of the revision those hashes came from (the sealed revision,
 * never the head), so a reader can see what the owner approved without re-reading the row.
 *
 * @param {object} db
 * @param {object} [deps]
 * @param {object|null} report a report row (or null)
 * @returns {Promise<object|null>} the verified live set, under `liveSet`, with `recipe`
 */
export async function verifyLive(db, deps, report) {
  try {
    if (!report || typeof report !== "object") return null;
    if (report.status !== REPORT_LIVE) return null;
    const verified = await verifiedLive(db, deps, report);
    if (!verified) return null;
    return { ...verified.fields, liveSet: verified.fields, recipe: verified.recipe };
  } catch {
    return null;
  }
}

/**
 * May this report run right now? `true` only when the status is `live` AND the seal verifies over the
 * row's current values of every live-set field, the revision row exists, the schedule resolves and the
 * model still resolves to the same provider, model, locality and endpoint. Never throws.
 *
 * @param {object} db
 * @param {object} [deps]
 * @param {object|null} report a report row (or null)
 * @returns {Promise<boolean>}
 */
export async function isLive(db, deps, report) {
  return !!(await verifyLive(db, deps, report));
}

/**
 * Re-seal a live report at a newer revision with a fresh nonce, in one write, and audit it.
 *
 * `verified` is the live set a `verifyLive` / `verifiedLiveSet` call just verified over this report's
 * row. Its fields are the seal's: the schedule, its zone, the sender, the bot, the project, the
 * artifact, the delivery rule, the comment defaults, the AI switch and the model are taken from THERE
 * and never read again, so a schedule row (or a model resolution) that moved between the verification
 * and this write cannot be sealed in. Only the revision, that revision's own recipe hash, the sources
 * hash and the fresh nonce are replaced.
 *
 * Before sealing, the revision being sealed is derived from its own `recipe_json` under this module's
 * block registry: its sources hash must equal the verified one and its model-call status must be the
 * sealed revision's, or the write is `go_live_needed` and nothing is written. A revision row whose text
 * and hash columns disagree is never blessed.
 */
async function restampLive(db, deps, report, rev, verified) {
  const d = resolveDeps(deps);
  if (verified == null || typeof verified !== "object") throw fail("go_live_needed");
  const revision = await getRevision(db, report.id, rev);
  if (!revision) throw fail("bad_recipe", "revision");
  const hashes = recomputedHashes(revision, d.registry);
  if (!hashes || hashes.sourcesHash !== text(verified.sourcesHash)) throw fail("go_live_needed");
  const sealedRevision = await getRevision(db, report.id, Number(verified.rev));
  if (!sealedRevision) throw fail("go_live_needed");
  if (callsModel(recipeOf(revision.recipe_json), report.ai_commentary)
    !== callsModel(recipeOf(sealedRevision.recipe_json), report.ai_commentary)) {
    throw fail("go_live_needed");
  }
  const seed = await seedOf(d);
  const nonce = newApprovalNonce();
  const fields = { ...verified, rev, recipeHash: hashes.recipeHash, sourcesHash: hashes.sourcesHash, nonce };
  const seal = approvalSeal("live", fields, seed);
  await updateReportColumns(db, report.id, {
    live_rev: rev,
    live_nonce: nonce,
    live_seal: seal,
    pending_free_change: 0,
  });
  await recordAudit(db, {
    reportId: report.id,
    kind: "live",
    subject: null,
    actor: "owner",
    decided: "approved",
    at: d.now(),
  });
}

/* --------------------------------------------------------------------------- go live */

/**
 * Every approved recipient must have a link kind before a report goes live.
 *
 * The link is what the recipient's mail carries, so an approved recipient whose `linkFor` answers null
 * would get a mail pointing nowhere. The refusal names the address as its detail (the API's map answers
 * one fixed sentence for the owner), and nothing is written: the owner removes the recipient or gives it
 * a tier this instance can mail.
 */
async function requireRecipientLinks(db, d, report, previewRun) {
  let recipients = [];
  try {
    recipients = await listRecipients(db, report.id, d);
  } catch {
    recipients = [];
  }
  for (const recipient of recipients) {
    if (recipient == null || recipient.state !== "approved" || recipient.verified !== true) continue;
    let link = null;
    try {
      link = await d.linkFor(db, { report, recipient, run: previewRun, sendId: null });
    } catch {
      // A link that cannot be resolved at all is a recipient that has none.
      link = null;
    }
    if (link == null) {
      // The message is the code and the address with no space, so a log line reads `link_unavailable:<address>`;
      // the address is the detail, and the sentence the owner sees is the API map's own.
      const address = text(recipient.address);
      const err = new Error(`link_unavailable:${address}`);
      err.code = "link_unavailable";
      err.detail = address;
      throw err;
    }
  }
}

/**
 * Approve a report to run: seal the live set over the head revision and make it `live`.
 *
 * The preview must be this report's, of the current head revision, and it must have finished `ok` or
 * `empty`. A schedule must resolve, the sender account must be ready, every APPROVED recipient must have
 * a link its mail can open (`link_unavailable` when one has none), and a recipe that calls a model must
 * resolve one now (a null resolution is `model_unresolved`, never a guessed default). Nothing is written
 * until every check has passed, and the write is one UPDATE with the fresh nonce and seal.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, previewRunId: string, actor: {kind: "owner"}}} input
 * @returns {Promise<{ok: true, liveRev: number}>}
 */
export async function approveGoLive(db, deps, { reportId, previewRunId, actor } = {}) {
  requireOwner(actor);
  const d = resolveDeps(deps);
  const report = await requireReport(db, reportId);

  if (typeof previewRunId !== "string" || !previewRunId) throw fail("preview_missing");
  const run = await d.getRun(db, previewRunId);
  if (!run || run.reportId !== report.id || run.kind !== "preview") throw fail("preview_missing");
  if (Number(run.recipeRev) !== Number(report.recipe_rev)) throw fail("preview_stale");
  if (run.status !== "ok" && run.status !== "empty") throw fail("preview_failed");

  const schedule = await d.getSchedule(db, report);
  if (!schedule || !text(schedule.cron)) throw fail("no_schedule");

  const accountId = text(report.sender_account_id);
  if (!accountId) throw fail("sender_not_ready");
  if ((await d.senderReady(db, accountId)) !== true) throw fail("sender_not_ready");

  await requireRecipientLinks(db, d, report, run);

  const liveRev = Number(report.recipe_rev);
  const revision = Number.isInteger(liveRev) ? await getRevision(db, report.id, liveRev) : null;
  if (!revision) throw fail("bad_recipe", "revision");

  const modelRef = await freshModelRef(db, d, report, revision);
  if (modelRef == null) throw fail("model_unresolved");

  const seed = await seedOf(d);
  const nonce = newApprovalNonce();
  const fields = await liveSetFor(db, d, report, { rev: liveRev, nonce, modelRef });
  const seal = approvalSeal("live", fields, seed);

  await updateReportColumns(db, report.id, {
    status: REPORT_LIVE,
    live_rev: liveRev,
    live_nonce: nonce,
    live_seal: seal,
    approved_preview_run: previewRunId,
    model_ref: modelRef === "" ? null : modelRef,
    pause_reason: null,
    pending_free_change: 0,
  });
  await recordAudit(db, {
    reportId: report.id,
    kind: "live",
    subject: null,
    actor: "owner",
    decided: "approved",
    at: d.now(),
  });
  return { ok: true, liveRev };
}

/* ------------------------------------------------------------------ pause and resume */

/** The reason text a pause stores: one line, no control characters, scrubbed of secret values. */
function pauseReasonOf(reason, deps) {
  const raw = typeof reason === "string" ? reason : "";
  const flat = raw.replace(CONTROL_CHARS_ALL, " ").replace(/\s+/g, " ").trim();
  if (!flat) return null;
  let secrets = [];
  try {
    secrets = deps.getSecrets() || [];
  } catch {
    secrets = [];
  }
  const redacted = redactSecrets(flat, secrets);
  return redacted.length > PAUSE_REASON_MAX ? redacted.slice(0, PAUSE_REASON_MAX) : redacted;
}

async function pauseOne(db, deps, { reportId, reason, actor }) {
  const d = resolveDeps(deps);
  const report = await requireReport(db, reportId);
  const updated = await updateReportColumns(db, report.id, {
    status: REPORT_PAUSED,
    pause_reason: pauseReasonOf(reason, d),
  });
  // A pause is a halt, not a refusal of the approval: the seal stays on the row so a resume can prove
  // that nothing moved in the meantime. The audit row says who halted it.
  await recordAudit(db, {
    reportId: report.id,
    kind: "live",
    subject: null,
    actor,
    decided: "refused",
    at: d.now(),
  });
  return updated;
}

/**
 * The owner's pause: the report stops, the seal stays for a resume, and the audit names the owner.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, reason?: string, actor: {kind: "owner"}}} input
 * @returns {Promise<object>} the report row after the write
 */
export async function pauseReport(db, deps, { reportId, reason, actor } = {}) {
  requireOwner(actor);
  return pauseOne(db, deps, { reportId, reason, actor: "owner" });
}

/**
 * The system's pause, for a broken seal, a cap or a failed migration (PR 1b): same write, no actor,
 * audited as `system`. No owner check, and no way to go live: only `resumeReport` re-activates a
 * paused report, and that one is owner-only.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, reason?: string}} input
 * @returns {Promise<object>} the report row after the write
 */
export async function pauseReportSystem(db, deps, { reportId, reason } = {}) {
  return pauseOne(db, deps, { reportId, reason, actor: "system" });
}

/**
 * The owner's resume: back to `live` only when the seal still verifies, which a pause does not touch.
 * A direct UPDATE of any live-set column while paused fails the seal, and the report stays paused with
 * `go_live_needed`.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, actor: {kind: "owner"}}} input
 * @returns {Promise<object>} the report row after the write
 */
export async function resumeReport(db, deps, { reportId, actor } = {}) {
  requireOwner(actor);
  const d = resolveDeps(deps);
  const report = await requireReport(db, reportId);
  if (!(await sealVerifies(db, d, report))) throw fail("go_live_needed");
  const updated = await updateReportColumns(db, report.id, {
    status: REPORT_LIVE,
    pause_reason: null,
  });
  await recordAudit(db, {
    reportId: report.id,
    kind: "live",
    subject: null,
    actor: "owner",
    decided: "approved",
    at: d.now(),
  });
  return updated;
}

/* ------------------------------------------------------------------------- recipe saves */

/** The saved-head fields a caller is told about, whatever the save did to the seal. */
function savedAnswer(saved, { restamped = false, needsGoLive = false } = {}) {
  return {
    rev: saved.rev,
    hash: saved.hash,
    sourcesHash: saved.sourcesHash,
    restamped,
    needsGoLive,
    // Whether THIS save wrote the revision's author seal (revision-author.js): true on an owner save that
    // had a keychain key to seal with, false on a bot save and on an owner save whose key was unreadable.
    authorSealed: saved != null && saved.authorSealed === true,
  };
}

/**
 * The verified live set when a live report's approval is still good after a save, or null. Both hashes
 * and the model-call status. The live revision's hashes are recomputed from its own recipe text, the
 * way the seal computes them, and then compared with the sources hash the save just wrote (which
 * `saveRecipe` computed from the new recipe's text under the same registry).
 */
async function restampableLiveSet(db, deps, report, saved, newRecipe) {
  const d = resolveDeps(deps);
  if (report.status !== REPORT_LIVE) return null;
  const fields = await verifiedLiveSet(db, d, report);
  if (!fields) return null;
  const liveRevision = await getRevision(db, report.id, Number(report.live_rev));
  if (!liveRevision) return null;
  const liveHashes = recomputedHashes(liveRevision, d.registry);
  if (!liveHashes) return null;
  if (text(saved.sourcesHash) !== liveHashes.sourcesHash) return null;
  if (callsModel(newRecipe, report.ai_commentary)
    !== callsModel(recipeOf(liveRevision.recipe_json), report.ai_commentary)) return null;
  return fields;
}

/**
 * The sealer an OWNER save hands to `saveRecipe`: it loads the keychain seed through this module's own
 * seam and makes the `author` seal over the revision the save is about (revision-author.js).
 *
 * Only an owner save seals a revision; a bot save passes no sealer and writes nothing, so a bot revision
 * can never look owner-written whatever an `author_kind` column says. The sealer throws what the seed
 * reader throws (`keychain_key_missing`), so a caller that must save anyway can catch that one code and
 * write an unsealed revision instead (a revision with no seal is not owner-chain evidence, which is the
 * safe side to be wrong on).
 *
 * @param {object} [deps] the approvals seam (`loadSeed`)
 * @returns {(fields: {reportId: string, rev: number, recipeHash: string, authorKind: string})
 *   => Promise<{nonce: string, seal: string}>}
 */
export function ownerAuthorSealerFor(deps) {
  const d = resolveDeps(deps);
  return async (fields) => sealAuthorRevision(await seedOf(d), fields);
}

/**
 * The `authorSeal` callback `ownerSaveRecipe` passes on: the sealer above, with a missing keychain key
 * answered as "no seal" instead of a refused save. An instance whose keychain key cannot be read can
 * still save a recipe; the revision it writes simply carries no proof that the owner wrote it, so the
 * source gate's owner-history path does not lean on it.
 */
function authorSealForSave(d) {
  const sealAuthor = ownerAuthorSealerFor(d);
  return async (fields) => {
    try {
      return await sealAuthor(fields);
    } catch (err) {
      if (err != null && err.code === "keychain_key_missing") return null;
      throw err;
    }
  };
}

/**
 * The owner's save (route `PUT /recipe`).
 *
 * The recipe is saved first — a refused recipe writes nothing. On a live report whose seal still
 * verifies, the seal is RE-STAMPED at the new revision only when nothing the owner approved moved: the
 * same sources hash and the same model-call status (a free change: a column, a sort, a filter). A save
 * that changed a source-bearing block, or a report whose seal was already broken, leaves the report on
 * its sealed revision and answers `needsGoLive`.
 *
 * The revision this save writes is also sealed as the OWNER's own (`authorSeal`, revision-author.js), in
 * the same transaction as the revision row. That seal is what the source gate's owner-history path reads;
 * the `author_kind` column alone proves nothing. An instance whose keychain key cannot be read still saves
 * (the revision carries no seal, so it is not owner-chain evidence).
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, recipe: object, actor: {kind: "owner"}}} input
 * @returns {Promise<{rev: number, hash: string, sourcesHash: string, restamped: boolean,
 *   needsGoLive: boolean, authorSealed: boolean}>}
 */
export async function ownerSaveRecipe(db, deps, { reportId, recipe, actor } = {}) {
  requireOwner(actor);
  const d = resolveDeps(deps);
  const report = await requireReport(db, reportId);
  const saved = await saveRecipe(db, {
    reportId: report.id,
    recipe,
    authorKind: "owner",
    registry: d.registry,
    // The revision this save writes is sealed as the owner's own, in the same transaction (see
    // revision-author.js): that seal, not the `author_kind` column, is what makes it owner-chain evidence.
    authorSeal: authorSealForSave(d),
  });
  const after = await getReport(db, report.id);
  if (!after) throw fail("not_found", "report");
  const verified = await restampableLiveSet(db, d, after, saved, recipe);
  if (!verified) {
    const live = after.status === REPORT_LIVE;
    return savedAnswer(saved, { needsGoLive: live });
  }
  await restampLive(db, d, after, saved.rev, verified);
  return savedAnswer(saved, { restamped: true });
}

/**
 * A bot's save (this path is used by PR 9a's bot tools). No actor, no re-stamp ever, and no author seal:
 * the seal always means "the owner approved".
 *
 * The block registry is the server's own `deps.registry` and there is deliberately no way for a caller
 * to pass one: a caller that could pick the registry could have its own new source block counted as
 * free, land `pending_free_change` and reach the one-tap Apply below.
 *
 * On a live report whose seal still verifies, a save whose sources hash is unchanged marks
 * `pending_free_change`, so the owner's card can offer Apply (one tap) next to the automatic preview.
 * A save that moved the sources hash, or a report whose seal is already broken, leaves a head revision
 * only and answers `needsGoLive`.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, recipe: object}} input
 * @returns {Promise<{rev: number, hash: string, sourcesHash: string, pendingFreeChange: boolean,
 *   needsGoLive: boolean, authorSealed: boolean}>}
 */
export async function botSaveRecipe(db, deps, { reportId, recipe } = {}) {
  const d = resolveDeps(deps);
  const report = await requireReport(db, reportId);
  const saved = await saveRecipe(db, {
    reportId: report.id,
    recipe,
    authorKind: "bot",
    registry: d.registry,
  });
  const after = await getReport(db, report.id);
  if (!after) throw fail("not_found", "report");

  if (after.status !== REPORT_LIVE) {
    return { ...saved, pendingFreeChange: false, needsGoLive: false };
  }
  if (!(await restampableLiveSet(db, d, after, saved, recipe))) {
    return { ...saved, pendingFreeChange: false, needsGoLive: true };
  }
  await updateReportColumns(db, report.id, { pending_free_change: 1 });
  return { ...saved, pendingFreeChange: true, needsGoLive: false };
}

/**
 * Apply a bot's free change with one owner tap: no fresh preview, no fresh go-live, because nothing the
 * owner approved moved.
 *
 * Requires `pending_free_change` on a live report, a seal that still verifies, a schedule that still
 * resolves, and a head revision whose own recipe text has the same sources hash and the same model-call
 * status as the sealed revision's. Anything else is `go_live_needed`, which is the card's prompt to run
 * a preview and go live properly.
 *
 * Both sides are read from the revision rows' own `recipe_json`, recomputed under the server's block
 * registry: the head hash columns are a cache, and neither a direct UPDATE of `reports.recipe_json`,
 * of `reports.sources_hash`, nor of a revision row may turn a source change into a free one.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, actor: {kind: "owner"}}} input
 * @returns {Promise<{ok: true, liveRev: number}>}
 */
export async function applyPendingFreeChange(db, deps, { reportId, actor } = {}) {
  requireOwner(actor);
  const d = resolveDeps(deps);
  const report = await requireReport(db, reportId);
  if (Number(report.pending_free_change) !== 1) throw fail("bad_input", "pending_free_change");
  if (report.status !== REPORT_LIVE) throw fail("go_live_needed");
  const verified = await verifiedLiveSet(db, d, report);
  if (!verified) throw fail("go_live_needed");
  const headRev = Number(report.recipe_rev);
  if (!Number.isInteger(headRev) || headRev < 1) throw fail("go_live_needed");
  if (!(await getRevision(db, report.id, headRev))) throw fail("go_live_needed");
  // The re-stamp derives the head revision's own hashes and model-call status and refuses when either
  // moved, so nothing here has to trust the head columns.
  await restampLive(db, d, report, headRev, verified);
  return { ok: true, liveRev: headRev };
}

/* ---------------------------------------------------------------------------- settings */

/** One boolean-ish setting: 1/0, true/false. Anything else is not a value this Crow stores. */
function readFlag(value) {
  if (value === 1 || value === true) return 1;
  if (value === 0 || value === false) return 0;
  return null;
}

/**
 * Clear a report's stored sender seal, best effort: it must never fail the settings write around it.
 * The value written is the JSON `null`, which every reader of the key already reads as "no seal".
 */
async function clearSenderSealOnSettings(db, reportId) {
  try {
    await setState(db, reportId, SENDER_SEAL_KEY, null);
  } catch {
    // Best effort: the settings write already landed.
  }
}

/**
 * Seal the sender a settings write has just put on the row, and never fail the write over it.
 *
 * The account is the row's own value read back after the UPDATE, so the seal names what the row holds now
 * rather than what the caller sent. A missing or unreadable keychain key (`keychain_key_missing`) writes
 * no seal at all: the settings are still saved, and an unsealed sender is simply not one a draft preview
 * may read (sender-seal.js, source-approvals.js). No other setting write reaches here.
 *
 * NO NEW SEAL CLEARS THE OLD ONE: when the sender moves from A to B and no seal for B can be made (a
 * missing keychain key, or any failure making or writing it), the seal left over from A is removed. A
 * stale row would otherwise sit there naming A, and a later direct UPDATE of the column back to A would
 * verify again against a seal the owner made for a sender the report no longer had. The clearing write is
 * best effort: a failure of it never makes the settings save (which already landed) throw.
 */
async function sealSenderOnSettings(db, d, report) {
  if (report == null || typeof report !== "object") return;
  const accountId = text(report.sender_account_id);
  if (accountId) {
    try {
      const proof = sealSender(await seedOf(d), { reportId: report.id, accountId });
      await setState(db, report.id, SENDER_SEAL_KEY, proof);
      return;
    } catch {
      // Fail closed: no seal, no trusted row sender. The settings write itself already landed.
    }
  }
  await clearSenderSealOnSettings(db, report.id);
}

/**
 * The owner's settings write (route `PUT /settings`): the sender, the delivery rule, the comment
 * defaults, the AI switch, the title and the notify switch.
 *
 * An unknown key, a word outside an enum or a value of the wrong type is `bad_input` and writes
 * nothing. A sender that is not a send-ready Crow Mail account on this instance is `sender_not_ready`.
 * When a live report's sender, delivery, tier, visibility or AI switch actually changes, the report is
 * paused with the fixed sentence AND its seal and nonce are nulled in the same write: the live seal no
 * longer describes what the report would do, and setting the column back must not revive the old
 * approval. Only a fresh preview and go-live re-approve it (`resumeReport` answers `go_live_needed`).
 * The same change on a PAUSED report that still carries a seal nulls the seal and nonce as well, and
 * leaves its status and pause reason exactly as they were.
 *
 * THE SENDER IS SEALED HERE: a save that carries `sender_account_id` (even the value the row already
 * holds) writes the report's sender seal beside the column, in `report_state` under `sender_seal`
 * (sender-seal.js), so the account a draft's `mail_alerts` block is measured against is provably the
 * owner's choice rather than a column any writer could have set. This is the only writer of that seal: a
 * recipe save, a proposal and the Apply path never touch it, and a settings write that names no sender
 * leaves the seal row exactly as it is. A keychain key that cannot be read still saves the settings, with
 * no seal written and the sender seal CLEARED (fail closed: an unsealed sender is not one a preview may
 * read, and the seal the previous sender left behind must not survive to verify a column moved back). A
 * sender changed by any other path therefore stops being trusted, because the seal names the account it
 * was made over and the reader compares it with the row.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{reportId: string, settings: object, actor: {kind: "owner"}}} input
 * @returns {Promise<object>} the report row after the write
 */
export async function updateSettings(db, deps, { reportId, settings, actor } = {}) {
  requireOwner(actor);
  const d = resolveDeps(deps);
  const report = await requireReport(db, reportId);
  if (settings == null || typeof settings !== "object" || Array.isArray(settings)) {
    throw fail("bad_input", "settings");
  }
  const keys = Object.keys(settings);
  if (!keys.length) throw fail("bad_input", "settings");

  const patch = {};
  for (const key of keys) {
    if (!REPORT_SETTING_KEYS.includes(key)) throw fail("bad_input", key);
    const value = settings[key];
    switch (key) {
      case "sender_account_id": {
        if (typeof value !== "string" || !value.trim()) throw fail("bad_input", key);
        const accountId = value.trim();
        if ((await d.senderReady(db, accountId)) !== true) throw fail("sender_not_ready");
        patch.sender_account_id = accountId;
        break;
      }
      case "delivery_mode":
        if (!DELIVERY_MODES.includes(value)) throw fail("bad_input", key);
        patch.delivery_mode = value;
        break;
      case "comment_tier_default":
        if (!COMMENT_TIERS.includes(value)) throw fail("bad_input", key);
        patch.comment_tier_default = value;
        break;
      case "comment_visibility":
        if (!COMMENT_VISIBILITIES.includes(value)) throw fail("bad_input", key);
        patch.comment_visibility = value;
        break;
      case "ai_commentary":
      case "notify_every_run": {
        const flag = readFlag(value);
        if (flag == null) throw fail("bad_input", key);
        patch[key] = flag;
        break;
      }
      case "title": {
        if (typeof value !== "string") throw fail("bad_input", key);
        const title = value.replace(CONTROL_CHARS_ALL, " ").replace(/\s+/g, " ").trim();
        if (!title || title.length > TITLE_MAX) throw fail("bad_input", key);
        patch.title = title;
        break;
      }
      default:
        throw fail("bad_input", key);
    }
  }

  const liveSetChanged = LIVE_SETTING_KEYS.some((key) => {
    if (!Object.hasOwn(patch, key)) return false;
    return key === "ai_commentary"
      ? flagNumber(patch[key]) !== flagNumber(report[key])
      : text(patch[key]) !== text(report[key]);
  });
  const liveChanged = report.status === REPORT_LIVE && liveSetChanged;
  // A pause keeps the seal so a resume can prove nothing moved while the report was stopped. A live-set
  // change while PAUSED therefore drops the seal too: the report is already paused, its status and its
  // pause reason stay as they are, but an owner who put the value back could otherwise resume onto an
  // approval that no longer describes the report.
  const pausedSealDropped = report.status === REPORT_PAUSED
    && liveSetChanged
    && typeof report.live_seal === "string" && report.live_seal !== "";
  if (liveChanged) {
    patch.status = REPORT_PAUSED;
    patch.pause_reason = SETTINGS_CHANGED_PAUSE_REASON;
    // The dropped seal is the point: without this, an owner who changed a live-set value and then put
    // it back could resume onto the old approval, which no longer describes what this report does.
    patch.live_seal = null;
    patch.live_nonce = null;
  } else if (pausedSealDropped) {
    patch.live_seal = null;
    patch.live_nonce = null;
  }

  const updated = await updateReportColumns(db, report.id, patch);
  if (Object.hasOwn(patch, "sender_account_id")) {
    await sealSenderOnSettings(db, d, updated);
  }
  if (liveChanged) {
    await recordAudit(db, {
      reportId: report.id,
      kind: "live",
      subject: null,
      actor: "owner",
      decided: "refused",
      at: d.now(),
    });
  }
  return updated;
}

/* ------------------------------------------------------------------------- recipients */

/** The four states a recipient row may hold (this module owns the words; there is no CHECK). */
export const RECIPIENT_STATES = Object.freeze(["proposed", "approved", "refused", "revoked"]);

/** The longest address kept: the same ceiling every mail address in this tree is held to. */
const ADDRESS_MAX = 254;
/** A display name is shown beside an address, never in a header, so it is text with a bound. */
const DISPLAY_NAME_MAX = 120;
/** `proposed_by` is the owner or one bot: `bot:<id>`, the same shape a run's requester uses. */
const PROPOSED_BY_RE = /^bot:[A-Za-z0-9._:-]{1,64}$/;
/** The same control characters as CONTROL_CHARS_ALL, without its `g` flag (a test needs no state). */
const RECIPIENT_CONTROL_CHARS = /[\u0000-\u001f\u007f\u0080-\u009f\u2028\u2029]/;

/** The recipient columns a reader needs; the seal and nonce stay off the list a page reads. */
const RECIPIENT_COLUMNS = `id, report_id, address, display_name, comment_tier, state, proposed_by,
  approval_nonce, approval_seal, approved_at, created_at`;

function recipientIdOf(value) {
  if (typeof value !== "string" || !value) throw fail("bad_input", "recipientId");
  return value;
}

/**
 * One address, lower-cased, as the single clean addr-spec a recipient may be: no display name, no
 * angle brackets, no list, no control character. Validated here rather than through Crow Mail's
 * parser: this module imports nothing under `mail/`, and the send door's own `validateOutgoing` is the
 * second, stricter reader at the moment a message is built.
 */
function normalizeRecipientAddress(value) {
  if (typeof value !== "string") throw fail("bad_input", "address");
  if (RECIPIENT_CONTROL_CHARS.test(value)) throw fail("bad_input", "address");
  const address = value.trim().toLowerCase();
  if (!address || address.length > ADDRESS_MAX) throw fail("bad_input", "address");
  if (/[\s<>()",;:\\[\]]/.test(address)) throw fail("bad_input", "address");
  const at = address.indexOf("@");
  if (at <= 0 || at !== address.lastIndexOf("@")) throw fail("bad_input", "address");
  const local = address.slice(0, at);
  const domain = address.slice(at + 1);
  if (!local || !domain || local.startsWith(".") || local.endsWith(".") || local.includes("..")) {
    throw fail("bad_input", "address");
  }
  if (!domain.includes(".") || domain.startsWith(".") || domain.endsWith(".") || domain.includes("..")) {
    throw fail("bad_input", "address");
  }
  return address;
}

/** A tier is `a`, `b` or `c`; null and "" both mean "the report's own default" (spec R15). */
function normalizeCommentTier(value) {
  if (value == null || value === "") return null;
  if (!COMMENT_TIERS.includes(value)) throw fail("bad_input", "commentTier");
  return value;
}

/** A display name with control characters gone and a bound: text, never a header. */
function normalizeRecipientName(value) {
  if (value == null) return null;
  if (typeof value !== "string") throw fail("bad_input", "displayName");
  const name = value.replace(CONTROL_CHARS_ALL, " ").replace(/\s+/g, " ").trim();
  if (!name) return null;
  return name.length > DISPLAY_NAME_MAX ? name.slice(0, DISPLAY_NAME_MAX) : name;
}

/** Who proposed it: the owner, or one bot by id. */
function normalizeProposedBy(value) {
  if (value === "owner") return "owner";
  if (typeof value === "string" && PROPOSED_BY_RE.test(value)) return value;
  throw fail("bad_input", "proposedBy");
}

/** A stored tier as the seal carries it: the empty string when the column is NULL. */
function tierText(row) {
  const value = row.comment_tier !== undefined ? row.comment_tier : row.commentTier;
  return text(value);
}

/** One row as a caller sees it. The seal and the nonce never leave this module. */
function mapRecipient(row) {
  if (!row) return null;
  return {
    id: row.id,
    reportId: row.report_id,
    address: row.address,
    displayName: row.display_name ?? null,
    commentTier: row.comment_tier == null || row.comment_tier === "" ? null : row.comment_tier,
    state: row.state,
    proposedBy: row.proposed_by,
    approvedAt: row.approved_at == null ? null : Number(row.approved_at),
    createdAt: Number(row.created_at),
  };
}

/** One recipient row as stored (seal and nonce included), or null. */
async function getRecipientRow(db, recipientId) {
  if (typeof recipientId !== "string" || !recipientId) return null;
  const { rows } = await db.execute({
    sql: `SELECT ${RECIPIENT_COLUMNS} FROM report_recipients WHERE id = ?`,
    args: [recipientId],
  });
  return rows[0] ?? null;
}

/** One report's row for one address (lower-cased), or null. The unique index makes this at most one. */
async function recipientByAddress(db, reportId, address) {
  const { rows } = await db.execute({
    sql: `SELECT ${RECIPIENT_COLUMNS} FROM report_recipients WHERE report_id = ? AND address = ?`,
    args: [reportId, address],
  });
  return rows[0] ?? null;
}

/**
 * Propose one recipient for one report (an owner route, or a bot's tool).
 *
 * The address is lower-cased and validated, so the unique (report, address) index really does mean
 * "one row per person per report". What an address that already has a row answers depends on who is
 * proposing it, because the owner's add is the owner's word about a person and a bot's proposal is a
 * suggestion:
 *
 *   - the owner (`proposedBy: "owner"`): the submitted name and tier REPLACE whatever the row holds
 *     before the approval that follows, and `proposed_by` becomes `owner`. A `proposed`, `refused` or
 *     `revoked` row takes them and (for the last two) goes back to `proposed` with its seal and nonce
 *     NULLED. An `approved` row whose submitted name or tier differs is RE-SEALED over the owner's
 *     values with a fresh nonce and an `approved` audit row; one that matches is answered unchanged,
 *     so a repeated tap is not a second approval.
 *   - a bot (`bot:<id>`): an address that already has a row is that row, unchanged, when it is
 *     `approved` or was proposed by the owner; a refused or revoked row of the bot's own goes back to
 *     `proposed` with the bot's name and tier. A bot can therefore never move an approval, never put
 *     its own tier on an approved row, and never overwrite what the owner proposed.
 *
 * Proposing never changes the report's status and never approves anything: an owner adds and approves
 * in one action only through the route, which calls this and then `approveRecipient`.
 *
 * @param {object} db
 * @param {object} [deps]
 * @param {{reportId: string, address: string, displayName?: string|null,
 *   commentTier?: "a"|"b"|"c"|null, proposedBy: "owner"|"bot:<id>"}} input
 * @returns {Promise<object>} the recipient row (camelCase, without the seal)
 * @throws {Error} `bad_input` or `not_found`
 */
export async function proposeRecipient(db, deps, {
  reportId, address, displayName, commentTier, proposedBy,
} = {}) {
  const d = resolveDeps(deps);
  const report = await requireReport(db, reportId);
  const addr = normalizeRecipientAddress(address);
  const name = normalizeRecipientName(displayName);
  const tier = normalizeCommentTier(commentTier);
  const by = normalizeProposedBy(proposedBy);

  const existing = await recipientByAddress(db, report.id, addr);
  if (existing) {
    if (by === "owner") return ownerAddOn(db, d, existing, { name, tier });
    // A bot's proposal is a suggestion: it never moves an approval and never rewrites the owner's own
    // proposal. Only the bot's own refused or revoked row may be proposed again.
    if (existing.state === "approved" || existing.proposed_by === "owner") {
      return mapRecipient(existing);
    }
    if (existing.state === "refused" || existing.state === "revoked") {
      await db.execute({
        sql: `UPDATE report_recipients
                 SET state = 'proposed', approval_nonce = NULL, approval_seal = NULL,
                     approved_at = NULL, display_name = ?, comment_tier = ?, proposed_by = ?
               WHERE id = ? AND state = ?`,
        args: [name, tier, by, existing.id, existing.state],
      });
      return mapRecipient(await getRecipientRow(db, existing.id));
    }
    return mapRecipient(existing);
  }

  const id = `rrc-${randomBytes(8).toString("hex")}`;
  try {
    await db.execute({
      sql: `INSERT INTO report_recipients
              (id, report_id, address, display_name, comment_tier, state, proposed_by, created_at)
            VALUES (?, ?, ?, ?, ?, 'proposed', ?, ?)`,
      args: [id, report.id, addr, name, tier, by, d.now()],
    });
  } catch (err) {
    // Another propose of the same address won the unique index first: answer that row, the way a
    // second propose answers the first one's (the owner's values still replace a bot's proposal).
    const raced = await recipientByAddress(db, report.id, addr);
    if (!raced) throw err;
    if (by === "owner") return ownerAddOn(db, d, raced, { name, tier });
    return mapRecipient(raced);
  }
  return mapRecipient(await getRecipientRow(db, id));
}

/**
 * The owner's add of an address that already has a row: the owner's name and tier replace whatever is
 * stored, and an approved row is re-sealed over them so the seal covers the values the owner just
 * submitted.
 *
 * A `proposed`, `refused` or `revoked` row takes the values (and the last two go back to `proposed`,
 * seal NULLED) for the approval that follows. An `approved` row whose values already match is answered
 * untouched; one that differs gets a fresh nonce and seal over the owner's values and a fresh `approved`
 * audit row, because the old seal described a tier or a name the owner has just replaced.
 *
 * Every write is guarded by the state this read saw, so a row that moved underneath answers
 * `recipient_changed` rather than being overwritten.
 */
async function ownerAddOn(db, d, existing, { name, tier }) {
  if (existing.state === "approved") {
    if (text(existing.display_name) === text(name) && text(existing.comment_tier) === text(tier)) {
      return mapRecipient(existing);
    }
    const seed = await seedOf(d);
    const nonce = newApprovalNonce();
    const fields = {
      reportId: existing.report_id,
      recipientId: existing.id,
      address: text(existing.address),
      commentTier: text(tier),
      nonce,
    };
    const seal = approvalSeal("recipient", fields, seed);
    const at = d.now();
    const written = await db.execute({
      sql: `UPDATE report_recipients
               SET display_name = ?, comment_tier = ?, proposed_by = 'owner',
                   approval_nonce = ?, approval_seal = ?, approved_at = ?
             WHERE id = ? AND state = 'approved'`,
      args: [name, tier, nonce, seal, at, existing.id],
    });
    if (Number(written?.rowsAffected ?? 0) !== 1) throw fail("recipient_changed");
    await recordAudit(db, {
      reportId: existing.report_id,
      kind: "recipient",
      subject: existing.id,
      actor: "owner",
      decided: "approved",
      at,
    });
    return mapRecipient(await getRecipientRow(db, existing.id));
  }

  const reopened = existing.state === "refused" || existing.state === "revoked";
  const written = await db.execute({
    sql: reopened
      ? `UPDATE report_recipients
            SET state = 'proposed', approval_nonce = NULL, approval_seal = NULL, approved_at = NULL,
                display_name = ?, comment_tier = ?, proposed_by = 'owner'
          WHERE id = ? AND state = ?`
      : `UPDATE report_recipients
            SET display_name = ?, comment_tier = ?, proposed_by = 'owner'
          WHERE id = ? AND state = ?`,
    args: [name, tier, existing.id, existing.state],
  });
  if (Number(written?.rowsAffected ?? 0) !== 1) throw fail("recipient_changed");
  return mapRecipient(await getRecipientRow(db, existing.id));
}

/**
 * The owner's approval of one recipient: a fresh nonce, a seal over the report, the row, the address
 * and the tier, then the state and the approval time, and an audit row naming the owner.
 *
 * An already-approved row whose seal still verifies is answered as it is, so a repeated tap is not a
 * second approval. Any other state (proposed, refused, revoked) is approved with a FRESH seal: that is
 * what makes a re-approval after a refusal real work rather than a replay.
 *
 * The write is guarded by the state this read saw, so a refuse or a revoke that landed in between
 * answers `recipient_changed` instead of being overwritten by the approval.
 *
 * @param {object} db
 * @param {object} deps
 * @param {{recipientId: string, actor: {kind: "owner"}}} input
 * @returns {Promise<object>} the recipient row after the write
 * @throws {Error} `owner_only`, `bad_input`, `not_found`, `keychain_key_missing`
 */
export async function approveRecipient(db, deps, { recipientId, actor } = {}) {
  requireOwner(actor);
  const d = resolveDeps(deps);
  const id = recipientIdOf(recipientId);
  const row = await getRecipientRow(db, id);
  if (!row) throw fail("not_found", "recipient");
  await requireReport(db, row.report_id);
  if (row.state === "approved" && (await verifyRecipient(db, d, row))) return mapRecipient(row);

  const seed = await seedOf(d);
  const nonce = newApprovalNonce();
  const fields = {
    reportId: row.report_id,
    recipientId: row.id,
    address: text(row.address),
    commentTier: tierText(row),
    nonce,
  };
  const seal = approvalSeal("recipient", fields, seed);
  const at = d.now();
  const written = await db.execute({
    sql: `UPDATE report_recipients
             SET state = 'approved', approval_nonce = ?, approval_seal = ?, approved_at = ?
           WHERE id = ? AND state = ?`,
    args: [nonce, seal, at, row.id, row.state],
  });
  if (Number(written?.rowsAffected ?? 0) !== 1) throw fail("recipient_changed");
  await recordAudit(db, {
    reportId: row.report_id,
    kind: "recipient",
    subject: row.id,
    actor: "owner",
    decided: "approved",
    at,
  });
  return mapRecipient(await getRecipientRow(db, row.id));
}

/**
 * Refuse or revoke one recipient: the state in one word, and BOTH the seal and its nonce set to NULL,
 * so an old seal can never re-approve the row. The audit row says which word was written.
 *
 * The write is guarded by the state this read saw: a decision that landed in between answers
 * `recipient_changed` rather than being overwritten.
 */
async function decideRecipient(db, deps, { recipientId, actor, state, decided } = {}) {
  requireOwner(actor);
  const d = resolveDeps(deps);
  const id = recipientIdOf(recipientId);
  const row = await getRecipientRow(db, id);
  if (!row) throw fail("not_found", "recipient");
  await requireReport(db, row.report_id);
  const at = d.now();
  const written = await db.execute({
    sql: `UPDATE report_recipients
             SET state = ?, approval_nonce = NULL, approval_seal = NULL, approved_at = NULL
           WHERE id = ? AND state = ?`,
    args: [state, row.id, row.state],
  });
  if (Number(written?.rowsAffected ?? 0) !== 1) throw fail("recipient_changed");
  await recordAudit(db, {
    reportId: row.report_id,
    kind: "recipient",
    subject: row.id,
    actor: "owner",
    decided,
    at,
  });
  return mapRecipient(await getRecipientRow(db, row.id));
}

/**
 * The owner's refusal (route `POST /recipients/:rid/refuse`).
 *
 * @param {object} db
 * @param {object} deps
 * @param {{recipientId: string, actor: {kind: "owner"}}} input
 * @returns {Promise<object>} the recipient row after the write
 * @throws {Error} `owner_only`, `bad_input`, `not_found`
 */
export async function refuseRecipient(db, deps, { recipientId, actor } = {}) {
  return decideRecipient(db, deps, { recipientId, actor, state: "refused", decided: "refused" });
}

/**
 * The owner's revocation of an approved recipient (route `POST /recipients/:rid/revoke`).
 *
 * @param {object} db
 * @param {object} deps
 * @param {{recipientId: string, actor: {kind: "owner"}}} input
 * @returns {Promise<object>} the recipient row after the write
 * @throws {Error} `owner_only`, `bad_input`, `not_found`
 */
export async function revokeRecipient(db, deps, { recipientId, actor } = {}) {
  return decideRecipient(db, deps, { recipientId, actor, state: "revoked", decided: "revoked" });
}

/**
 * One report's recipients, oldest first. The seal and the nonce are never in the answer; each row
 * carries `verified` instead, which is `verifyRecipient`'s answer: approved AND a seal that still
 * matches the row's CURRENT address, tier and ids. A row whose seal no longer verifies therefore reads
 * `state: "approved"` with `verified: false`, so a page never shows an approval that is not one.
 *
 * @param {object} db
 * @param {string} reportId
 * @param {object} [deps] the approvals deps (the keychain seed decides whether any seal verifies)
 * @returns {Promise<object[]>}
 * @throws {Error} `bad_input`
 */
export async function listRecipients(db, reportId, deps) {
  if (typeof reportId !== "string" || !reportId) throw fail("bad_input", "reportId");
  const d = resolveDeps(deps);
  const { rows } = await db.execute({
    sql: `SELECT ${RECIPIENT_COLUMNS} FROM report_recipients
           WHERE report_id = ? ORDER BY created_at ASC, id ASC`,
    args: [reportId],
  });
  const out = [];
  for (const row of rows) {
    out.push({ ...mapRecipient(row), verified: await verifyRecipient(db, d, row) });
  }
  return out;
}

/**
 * Does this recipient row still hold the owner's approval?
 *
 * `true` only when the row's state is `approved` AND its seal verifies over the fields the row holds
 * NOW: the report id, the row id, the address and the tier (NULL sealed as the empty string). A direct
 * UPDATE of the address or the tier therefore makes an approved row unapproved, and refusing or
 * revoking (which nulls the seal) can never be undone by restoring the state word. Never throws: a
 * broken row, a missing seed and a malformed seal are all `false`.
 *
 * The row may be the stored shape (`report_id`, `comment_tier`, `approval_seal`, `approval_nonce`)
 * or the camelCase one a caller built; the send door reads the stored row itself and passes that.
 *
 * @param {object} db
 * @param {object} [deps]
 * @param {object|null} recipient a `report_recipients` row
 * @returns {Promise<boolean>}
 */
export async function verifyRecipient(db, deps, recipient) {
  try {
    if (recipient == null || typeof recipient !== "object") return false;
    if (recipient.state !== "approved") return false;
    const id = typeof recipient.id === "string" ? recipient.id : recipient.recipientId;
    const reportId = recipient.report_id !== undefined ? recipient.report_id : recipient.reportId;
    if (typeof id !== "string" || !id) return false;
    if (typeof reportId !== "string" || !reportId) return false;
    const seal = recipient.approval_seal !== undefined ? recipient.approval_seal : recipient.approvalSeal;
    const nonce = recipient.approval_nonce !== undefined ? recipient.approval_nonce : recipient.nonce;
    if (typeof seal !== "string" || !seal) return false;
    if (typeof nonce !== "string" || !nonce) return false;
    const seed = await seedOf(resolveDeps(deps));
    const fields = {
      reportId,
      recipientId: id,
      address: text(recipient.address),
      commentTier: tierText(recipient),
      nonce,
    };
    return verifyApprovalSeal("recipient", fields, seal, seed);
  } catch {
    return false;
  }
}