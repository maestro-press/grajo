/**
 * The recipe executor: one recipe, walked block by block, answering what the run has to record.
 *
 * `runRecipe(db, deps, {report, recipe, run, live, state})` flows `{items, sections}` from block to
 * block and answers `{items, sections, warnings, sourceErrors, stateWrites, document, allowedLinks,
 * summary, email}`:
 *   - `items` is what the last block left (a source block's items, filtered and sorted by the shape
 *     blocks after it); the run engine counts it for the run's status and the block log.
 *   - `sourceErrors` is one `{source: <block id>, message: <code word>}` per source or custom block that
 *     could not read. The run engine's own rule turns any of them into a failed run; a source error does
 *     not stop the blocks after it, so one unreachable feed still records what the others gave.
 *   - `warnings` is the same shape for a shape block that failed. A shape block only arranges data the
 *     sources already produced, so its failure is recorded and the run goes on. A block may also answer
 *     an advisory `warnings: [{message}]` list beside its own section (the chart block's
 *     `chart_rows_dropped`, a custom block's `custom_email_invalid`), and those are recorded here too:
 *     an advisory note never fails a run.
 *   - `stateWrites` is `[{key, value}]` in the order the blocks buffered them, and it is NOT applied
 *     here: the run engine applies it after the version write, only for a run that ends not-failed and
 *     never for a preview.
 *   - `document` is the assembled source the artifact bridge writes (`{markdown, assets?}`),
 *     `allowedLinks` the run's own item URLs and `summary` its counts; see the header's THE DOCUMENT
 *     paragraph.
 *   - `email` is a custom step's own mail body (`{html?, text?}`), or null when no step answered one, and
 *     the LAST valid one wins. Only the `custom` kind may set it: `blocks/custom.js` narrows it to those
 *     two string halves (no recipient, no subject, each within its cap) and the send path sanitises and
 *     neutralises it against the run's own items. It travels to delivery in this result and is never part
 *     of the document, the block log or the version.
 *
 * `ctx` is what one block gets: `{db, deps, report, run, live, block, blockId, getState, setState,
 * fetch, mail, workspaceDir, log, extraStepClaim, extraStepClaimToken, sources}`.
 *   - `run` is the SERVER-SIDE run row the engine was handed (its `trigger` decides cap spending, and
 *     its `requestedBy` and the revision rows decide whether a block is gated). No recipe field can
 *     supply or override it.
 *   - `fetch` IS the guarded request (`guardedRequest` in `servers/shared/fetch-page.js`), bound here
 *     and not a caller's seam: every URL a source reads goes through the scheme, address, redirect and
 *     byte checks, whatever a caller passed in `deps`. A test may inject a fake as `deps.testFetch`,
 *     honoured only when `deps.testSeams === true` (the flag `custom-step.js` and the step runner use);
 *     a `deps.fetch` is ignored. The module is loaded on the first call, so a boot that runs no source
 *     never loads a page parser.
 *   - `workspaceDir` is the report's PROJECT's `workspace_dir`, read for THIS run from
 *     `project_spaces` (an archived, deleted or learner-profile project has none). A report whose
 *     project has no workspace answers `workspace_not_available`. A test may override it with
 *     `deps.workspaceDirFor(report)`, honoured only under `deps.testSeams`; a `deps.workspaceDir` is
 *     ignored, so one directory can never be handed to every report.
 *   - `mail` is the caller's `adapterFor` seam and nothing else: no production default exists yet, so a
 *     build with no seam answers `mail_not_available`. The boot that wires the reports send door's
 *     adapter is a later PR; until then this member is exactly what a caller injected.
 *   - `getState(key)` reads `report_state` through the store, and sees a value this run has already
 *     buffered (so two blocks reading the same key in one run agree).
 *   - `setState(key, value)` BUFFERS only, and refuses (throws `reserved_state_key`) every key the
 *     artifact bridge owns: `preview_artifact_id` and anything under `source_approval:`. A recipe is
 *     bot-authorable, and the bridge trusts those keys to decide where a run writes.
 *   - `extraStepClaim` is a function that takes this run's ONE `extra_step_runs` on the block's behalf
 *     (see THE EXTRA STEP CAP below), and `extraStepClaimToken` is the executor's own
 *     `CLAIMED_BY_EXECUTOR` token (claim-token.js). A block calls the function where the spend really
 *     happens, and a custom block hands the pair on so the step claims through the executor; the token
 *     alone is worth nothing, because neither member is read from a recipe.
 *   - `sources` keeps each source (and custom) block's own output by block id, which is what
 *     `enrich_lookup` joins against. It is deleted with the run: nothing here writes it anywhere.
 *   - `blockUnapproved` is `true` only on a GATED preview (see below) whose model block the owner has not
 *     approved. A model block that names a role writes the templated fallback rather than spending that
 *     role's model, so a bot's new model block costs no model time before the owner's tap.
 *
 * A present block has a `run` now: it turns the items into a document section (and, for a model block,
 * adds one section of the model's writing). Its failures are the SHAPE kind of failure (a warning), with
 * these exceptions that stop the run instead: `model_changed`, `model_unresolved` and `model_not_local`
 * (the model is not the one the live seal names, or a preview resolved no local model, so nothing may be
 * sent), and `too_large` (from the document assembly at the end). A SOURCE block with no
 * `run` yet is not skipped: it is the named source error `source_not_available`, so a recipe that names a
 * source this build cannot read fails honestly instead of quietly reporting an empty run. An unknown block
 * type is the same kind of honesty (`unknown_block_type`): a revision stored under a registry that knew it
 * still fails closed when the registry no longer does.
 *
 * THE DOCUMENT IS ASSEMBLED LAST (reports/document.js): every present block's section, in recipe order,
 * becomes one run document under the artifact renderer's two limits, and the answer carries it as
 * `document` (the source `makeWriteVersion` writes), `allowedLinks` (the run's own item URLs, which is
 * what a version may show) and `summary`. A document over a limit throws `too_large` out of this
 * function, which the run engine records as a failed run with that sentence; a run that already has a
 * source error assembles nothing, because its version is never written.
 *
 * A GATED PREVIEW READS ONLY APPROVED CONTENT: a recipe is bot-authorable, and a preview is the one
 * trigger that runs a revision the owner has not sealed, so every source-shaped block (`kind: "source"`
 * or `kind: "custom"`) of a PREVIEW is gated before its `run` is called unless its CONTENT is approved
 * (`isSourceApprovedForBot`, source-approvals.js): its `{type, settings}` hash is in the verified live
 * recipe, or the owner approved it at that exact hash, or that hash under that block id has an unbroken
 * owner-introduced history up to this revision (the owner put it there and no revision since dropped it
 * or carried the id at another hash). Anything else is gated, whoever asked and whoever
 * saved last. A scheduled or manual run executes the verified live set (`run.js`), which the owner
 * sealed, so it is not gated. A blocked block becomes a source error with the one sentence
 * `Source <blockId> is waiting for your OK`, and nothing reaches the network, a mailbox or a file: the
 * gate is asked first, and the block's `run` is never entered. The run then goes on with the remaining
 * blocks, the same way any other source error does. A `custom` block is gated by this rule as well, on
 * top of its own step approval (steps.js). A MODEL block (`kind: "present"`, `sourceBearing: true`) is
 * asked the same gate, and an answer of "not approved" reaches it as `ctx.blockUnapproved` rather than a
 * source error: it still renders, but a block that names a role writes the templated fallback instead of
 * calling that role's model.
 *
 * ONE READ OF THE REVISIONS PER RUN: the owner-history half of the gate is one map built from a single
 * read of the report's revisions (`ownerChainAnswers`), asked for lazily on the first gated block and
 * reused for every gated block after it. A recipe with ten bot-introduced sources costs one pass over
 * the revisions, not ten.
 *
 * THE EXTRA STEP CAP: the day's ONE `extra_step_runs` belongs to the RUN, and it is taken by the block
 * that really spends it, in the one place that knows it will: a custom block's step claims it inside
 * `custom-step.js` after its own step approval passed (a step that is still waiting spends nothing), and
 * an `http_json` block with a credential claims it after its credential rule resolved and was allowed (a
 * refused credential spends nothing). Both go through the claim this executor builds, so the total is
 * one per run however many counting blocks the recipe names, and a scheduled run claims nothing at all.
 * A refused claim answers the code `cap_reached` for the block that asked, and the run fails, so a
 * recipe cannot spend more than the owner allowed by naming two steps.
 *
 * `runRecipeBlocks` is the `runBlocks` factory the run engine uses by default: it takes the engine's
 * arguments (including the `db` and the engine's own `deps`) and calls `runRecipe`.
 */
import { isReservedStateKey } from "../artifact-bridge.js";
import { claimExtraStepRun, dayInTz, getCaps } from "../caps.js";
import { CLAIMED_BY_EXECUTOR } from "../claim-token.js";
import { assembleDocument, isAiSection } from "../document.js";
import { getState as readState } from "../store.js";
import { isSourceApprovedForBot, ownerChainAnswers, waitingForOkText } from "../source-approvals.js";
import { ACTIVE_PROJECT_WHERE } from "../../../shared/shell-items.js";
import { BLOCKS } from "./index.js";

/** How many items one run may carry out of a block. */
const MAX_ITEMS = 5000;

/** How long one source error's message may be. */
const MESSAGE_MAX = 300;

/**
 * The failure codes a present block may throw to stop the whole run: a model that is not the sealed one
 * (or, on a preview, no model / not a local one), and a document over a limit. Every other present-block
 * failure is a warning.
 */
const HARD_PRESENT_CODES = Object.freeze([
  "model_changed", "model_unresolved", "model_not_local", "too_large",
]);

function fail(code) {
  const err = new Error(code);
  err.code = code;
  return err;
}

/** The guarded request module, loaded on the first source that reads a URL. */
let guardedRequestModule = null;

/**
 * The `fetch` a block gets: the guarded request itself, and never a caller's own function. Loaded on
 * first use so a gateway boot that runs no URL source never loads a page parser.
 *
 * @param {string} url
 * @param {object} request the guarded request's options
 * @returns {Promise<object>}
 */
async function guardedFetch(url, request) {
  if (!guardedRequestModule) {
    guardedRequestModule = import("../../../shared/fetch-page.js").then((mod) => mod.guardedRequest);
  }
  const guarded = await guardedRequestModule;
  return guarded(url, request);
}

/**
 * The directory a `workspace_file` block may read: the report's OWN project's `workspace_dir`, read
 * fresh for this run. A project that is gone, archived, a learner profile or has no folder answers
 * null, which the block reports as `workspace_not_available` rather than reading somewhere else.
 *
 * @param {object} db
 * @param {object} report the server-side report row (`project_id`)
 * @returns {Promise<string|null>}
 */
async function projectWorkspaceDir(db, report) {
  const projectId = Number(report && report.project_id);
  if (!db || !Number.isInteger(projectId) || projectId <= 0) return null;
  try {
    const { rows } = await db.execute({
      sql: `SELECT workspace_dir FROM project_spaces WHERE id = ? AND ${ACTIVE_PROJECT_WHERE}`,
      args: [projectId],
    });
    const value = rows[0] ? rows[0].workspace_dir : null;
    return typeof value === "string" && value ? value : null;
  } catch {
    return null;
  }
}

function message(value) {
  const text = value == null ? "" : String(value);
  return text.length > MESSAGE_MAX ? text.slice(0, MESSAGE_MAX) : text;
}

function isPlainObject(value) {
  return value != null && typeof value === "object" && !Array.isArray(value);
}

/**
 * The report's bot display name, for the document's AI heading. A missing bot row (or no database) leaves
 * the heading with the generic word; a name that cannot be read never fails a run.
 */
async function botNameFor(db, report) {
  const botId = typeof report?.bot_id === "string" ? report.bot_id : "";
  if (!botId || !db) return "";
  try {
    const { rows } = await db.execute({
      sql: "SELECT display_name FROM pi_bot_defs WHERE bot_id = ?",
      args: [botId],
    });
    const name = rows[0]?.display_name;
    return typeof name === "string" && name.trim() ? name.trim() : botId;
  } catch {
    return botId;
  }
}

/** The recipe's own words for a run that found nothing, when it set any. A presentational setting. */
function emptyTextOf(recipe) {
  const value = isPlainObject(recipe) ? recipe.emptyText : null;
  return typeof value === "string" && value.trim() ? value : undefined;
}

/** Is this run a preview, the one trigger that reads a revision the owner has not sealed? */
function isPreview(run) {
  return run != null && typeof run === "object" && run.trigger === "preview";
}

/** The day a cap is counted against: the caller's own, else today in the caller's zone, else UTC. */
function capDay(seam, now) {
  if (typeof seam.day === "string" && /^\d{4}-\d{2}-\d{2}$/.test(seam.day)) return seam.day;
  return dayInTz(now, typeof seam.timeZone === "string" ? seam.timeZone : undefined);
}

/**
 * The day's one extra step run, taken with the same conditional increment `custom-step.js` takes. A
 * refused claim throws `cap_reached`; `true` means this run now holds its claim. A caller with no
 * database or no saved report has nothing to count against, so nothing is claimed.
 */
async function claimExtraStepForRecipe(db, seam, report) {
  const reportId = report && typeof report.id === "string" ? report.id : "";
  if (!db || !reportId) return false;
  const now = Number(typeof seam.now === "function" ? seam.now() : Date.now()) || Date.now();
  const caps = await getCaps(db);
  const claimed = await claimExtraStepRun(db, {
    reportId,
    day: capDay(seam, now),
    max: caps.maxExtraStepRunsPerReportDay,
  });
  if (!claimed) throw fail("cap_reached");
  return true;
}

/**
 * The state access one run gets: reads see buffered writes, writes are buffered and checked.
 *
 * `buffered` maps key -> value for this run (the last write wins on a read, every write is kept in
 * `stateWrites` in order); `seed` is a caller's own pre-read map, and `db`/`reportId` fall back to
 * `report_state` through the store.
 *
 * @param {{db?: object, reportId?: string|null, seed?: Map<string, *>, buffered?: Map<string, *>,
 *   stateWrites?: {key: string, value: *}[]}} [parts]
 * @returns {{getState: (key: string) => Promise<*>, setState: (key: string, value: *) => void}}
 */
export function makeStateAccess(parts = {}) {
  const buffered = parts.buffered instanceof Map ? parts.buffered : new Map();
  const seed = parts.seed instanceof Map ? parts.seed : new Map();
  const stateWrites = Array.isArray(parts.stateWrites) ? parts.stateWrites : [];
  const db = parts.db ?? null;
  const reportId = typeof parts.reportId === "string" && parts.reportId ? parts.reportId : null;

  async function getState(key) {
    if (typeof key !== "string" || !key) return null;
    if (buffered.has(key)) return buffered.get(key);
    if (seed.has(key)) return seed.get(key);
    if (!db || !reportId) return null;
    return readState(db, reportId, key);
  }

  function setState(key, value) {
    if (typeof key !== "string" || !key) throw fail("bad_state_key");
    if (isReservedStateKey(key)) throw fail("reserved_state_key");
    buffered.set(key, value);
    stateWrites.push({ key, value });
  }

  return { getState, setState };
}

/**
 * The workspace directory this run's blocks get: a test harness's own answer under `testSeams`, and
 * otherwise the report's project's folder. There is no third source.
 *
 * @param {object} db
 * @param {object} report
 * @param {object} seam the caller's deps
 * @param {boolean} testSeams
 * @returns {Promise<string|null>}
 */
async function workspaceDirFor(db, report, seam, testSeams) {
  if (testSeams && typeof seam.workspaceDirFor === "function") {
    const value = await seam.workspaceDirFor(report);
    return typeof value === "string" && value ? value : null;
  }
  return projectWorkspaceDir(db, report);
}

/**
 * Run one recipe, block by block.
 *
 * @param {object} db the run's libsql-shaped client
 * @param {object} [deps] the executor seam: `mail`, `log`, plus everything a custom step's own deps take
 *   (`runStep`, `ensureEnv`, `now`, `day`, `getSecrets`, ...). `testFetch` and `workspaceDirFor` are read
 *   only under `testSeams: true`; `fetch` and `workspaceDir` are never read.
 * @param {{report: object, recipe: object, run: object, live?: object|null, state?: object}} input
 * @returns {Promise<{items: object[], sections: object[], warnings: object[],
 *   sourceErrors: object[], stateWrites: {key: string, value: *}[], document: object|null,
 *   allowedLinks: string[], summary: object|null, email: {html?: string, text?: string}|null}>}
 */
export async function runRecipe(db, deps, { report, recipe, run, live = null, state = null } = {}) {
  const seam = isPlainObject(deps) ? deps : {};
  const testSeams = seam.testSeams === true;
  const stateWrites = [];
  const buffered = new Map();
  const seed = isPlainObject(state) ? new Map(Object.entries(state)) : new Map();
  const { getState, setState } = makeStateAccess({
    db,
    reportId: report && typeof report.id === "string" ? report.id : null,
    seed,
    buffered,
    stateWrites,
  });
  const gated = isPreview(run);
  const isSchedule = run != null && typeof run === "object" && run.trigger === "schedule";

  // THIS RUN'S ONE EXTRA STEP RUN, taken by the block that really spends it and never here: a custom
  // block's step claims it after its own step approval passed, a credentialed `http_json` block after
  // its credential rule resolved and was allowed. `taken` is what makes the total one per run, and a
  // scheduled run answers false without touching a counter.
  let extraStepTaken = false;
  const claimExtraStep = async () => {
    if (isSchedule || extraStepTaken) return false;
    extraStepTaken = await claimExtraStepForRecipe(db, seam, report);
    return extraStepTaken;
  };

  const ctx = {
    db,
    deps: seam,
    report,
    run,
    live,
    getState,
    setState,
    // The guarded request, or a test's fake under the test flag; never a caller's `deps.fetch`.
    fetch: testSeams && typeof seam.testFetch === "function" ? seam.testFetch : guardedFetch,
    // No production adapter exists yet: a build with no seam answers `mail_not_available`.
    mail: seam.mail ?? null,
    workspaceDir: await workspaceDirFor(db, report, seam, testSeams),
    log: typeof seam.log === "function" ? seam.log : () => {},
    // The claim function and the token that says who handed it: neither comes from a recipe.
    extraStepClaim: claimExtraStep,
    extraStepClaimToken: CLAIMED_BY_EXECUTOR,
    sources: new Map(),
  };

  const warnings = [];
  const sourceErrors = [];
  let items = [];
  let sections = [];
  // A custom step's own mail body for this run: null until one answers a valid one, the last one wins.
  let email = null;
  const blocks = Array.isArray(recipe?.blocks) ? recipe.blocks : [];

  // The owner-history answers of this run's gate: ONE read of the report's revisions, asked for on the
  // first gated block and reused by every gated block after it.
  let gate = null;
  const gateFor = async () => {
    if (gate === null) {
      const reportId = report && typeof report.id === "string" ? report.id : "";
      const headRev = Number(report?.recipe_rev);
      gate = { headRev, ownerChain: await ownerChainAnswers(db, reportId, headRev) };
    }
    return gate;
  };

  for (const block of blocks) {
    const blockId = block && typeof block.id === "string" ? block.id : "";
    const entry = block && typeof block.type === "string" && Object.hasOwn(BLOCKS, block.type)
      ? BLOCKS[block.type]
      : null;
    if (!entry) {
      sourceErrors.push({ source: blockId, message: "unknown_block_type" });
      continue;
    }
    if (entry.kind === "present" && typeof entry.run !== "function") continue;
    if (typeof entry.run !== "function") {
      // A source block this build cannot read yet: named, never skipped silently.
      sourceErrors.push({ source: blockId, message: "source_not_available" });
      continue;
    }

    // A gated preview reads only approved sources: asked BEFORE the block's `run`, so a blocked block
    // opens no socket, reads no mailbox and opens no file.
    if (gated && (entry.kind === "source" || entry.kind === "custom")) {
      const verdict = await isSourceApprovedForBot(db, seam, report, block, await gateFor());
      if (!verdict || verdict.ok !== true) {
        sourceErrors.push({
          source: blockId,
          message: message(verdict && verdict.text ? verdict.text : waitingForOkText(blockId)),
        });
        continue;
      }
    }

    // A MODEL block is present-shaped but sends the run's items to a model, so a gated preview asks the
    // same gate for it and hands the answer on: an unapproved block that names a role may not spend that
    // role's model, and writes the templated fallback instead (blocks/present/ai-commentary.js).
    let blockUnapproved = false;
    if (gated && entry.kind === "present" && entry.sourceBearing === true) {
      const verdict = await isSourceApprovedForBot(db, seam, report, block, await gateFor());
      blockUnapproved = !(verdict && verdict.ok === true);
    }

    const blockCtx = { ...ctx, block, blockId, blockUnapproved };
    const input = { items, sections };
    let output;
    try {
      output = await entry.run(blockCtx, input);
    } catch (err) {
      const code = message(err && err.code ? err.code : "block_failed");
      if (entry.kind === "present" && HARD_PRESENT_CODES.includes(err && err.code)) throw err;
      const failure = { source: blockId, message: code };
      if (entry.kind === "shape" || entry.kind === "present") warnings.push(failure);
      else sourceErrors.push(failure);
      continue;
    }
    if (output != null && isPlainObject(output.sourceError)) {
      const failure = {
        source: blockId,
        message: message(output.sourceError.message || output.sourceError.code || "block_failed"),
      };
      if (entry.kind === "shape" || entry.kind === "present") warnings.push(failure);
      else sourceErrors.push(failure);
      continue;
    }

    // A block's own advisory notes, beside the section it adds (`chart_rows_dropped`): recorded, and
    // never a reason to fail a run.
    if (output != null && Array.isArray(output.warnings)) {
      for (const note of output.warnings) {
        const code = message(
          note != null && typeof note === "object" ? (note.message ?? note.code) : note,
        );
        if (code) warnings.push({ source: blockId, message: code });
      }
    }

    if (Array.isArray(output?.items)) items = output.items.slice(0, MAX_ITEMS);
    // Only a custom block may name the run's email body, and its own block has already narrowed it to the
    // two string halves (blocks/custom.js): anything that is not a plain object is not a body.
    if (entry.kind === "custom" && isPlainObject(output?.email)) email = { ...output.email };
    if (Array.isArray(output?.sections) && output.sections.length) {
      // A present block answers the list it was handed plus its own section (the block contract), so its
      // answer replaces the list; every other kind answers only its own new sections, which are appended.
      sections = entry.kind === "present"
        ? output.sections.slice()
        : [...sections, ...output.sections];
    }
    if (entry.kind === "source" || entry.kind === "custom") ctx.sources.set(blockId, items);
  }

  let document = null;
  let allowedLinks = [];
  let summary = null;
  if (!sourceErrors.length) {
    // A failed run writes no version, so there is nothing to assemble for one: a source error's own text
    // stays the run's sentence rather than being replaced by a size refusal.
    const assembled = assembleDocument({
      report,
      run,
      sections,
      items,
      allowedLinks: [],
      // The AI heading names the bot; nothing else in the document needs its row, so it is read only when
      // a model block wrote a section.
      botName: sections.some(isAiSection) ? await botNameFor(db, report) : "",
      emptyText: emptyTextOf(recipe),
    });
    document = assembled.source;
    allowedLinks = assembled.allowedLinks;
    summary = assembled.summary;
  }

  return {
    items, sections, warnings, sourceErrors, stateWrites, document, allowedLinks, summary, email,
  };
}

/**
 * The `runBlocks` seam the run engine takes by default. The engine hands over the run row, the recipe
 * it resolved, the verified live set and the run's database; `deps` is the engine's own seam, carried
 * through so a custom block reaches `custom-step.js` with what it needs.
 *
 * @param {{db: object, deps?: object, report: object, recipe: object, run: object, live?: object,
 *   state?: object}} args
 * @returns {Promise<object>} the `runRecipe` answer
 */
export function runRecipeBlocks({ db, deps, report, recipe, run, live, state } = {}) {
  return runRecipe(db, deps, { report, recipe, run, live, state });
}