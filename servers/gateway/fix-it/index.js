/**
 * Fix-it Cards — gateway wiring. Binds the pure registry + DB store to this
 * gateway: registers the v1 detector/remedy, exposes the fire-and-forget
 * `emitFixIt` chokepoints call, and serves the remedy/dismiss POST action.
 *
 * The cards themselves have ONE model (`fixItCardModels`) and two renderers:
 * `renderFixItCards` (the classic Nest's Fix-it section, unchanged markup) and
 * `renderFixItSheetCards` (the new shell's Attention sheet). Nothing but the
 * markup differs between them.
 */
import * as registry from "../../shared/fix-it/registry.js";
import * as store from "../../shared/fix-it/store.js";
import remoteExposureDetector from "./detectors/remote-exposure.js";
import caddyProxySocketDetector from "./detectors/caddy-proxy-socket.js";
import caddyAdminSocketDetector from "./detectors/caddy-admin-socket.js";
import bootGuardDetector from "./detectors/boot-guard.js";
import dataBackendReapprovalDetector from "./detectors/data-backend-reapproval.js";
import bundleBindDriftDetector from "./detectors/bundle-bind-drift.js";
import retiredBundleDetector, { SOURCE as RETIRED_BUNDLE_SOURCE, cardTitle as retiredBundleTitle, cardWhy as retiredBundleWhy } from "./detectors/retired-bundle.js";
import browserImageStaleDetector from "./detectors/browser-image-stale.js";
import sharingBotAclDetector, {
  OPEN_BOT_BUILDER_ACTION as OPEN_BOT_BUILDER_FOR_SHARING,
  SOURCE as SHARING_BOT_ACL_SOURCE,
  cardTitle as sharingCardTitle,
  cardWhy as sharingCardWhy,
} from "./detectors/sharing-bot-acl.js";
import addonWallDetector, {
  SOURCE as ADDON_WALL_SOURCE,
  whyTextForRecord as addonWallWhyTextForRecord,
} from "./detectors/addon-wall.js";
import { renderStoredCard } from "./card-copy.js";
import exposeCapabilityRemedy from "./remedies/expose-capability.js";
import restoreBundleCompose, {
  ACTION_ID as RESTORE_COMPOSE_ACTION,
  ALREADY_RESTARTING_FLASH,
  APPLY_UPDATE_ACTION_ID as APPLY_COMPOSE_UPDATE_ACTION,
  NEEDS_KEY_FLASH,
  OWNER_ONLY_FLASH,
} from "./remedies/restore-bundle-compose.js";
import restartBrowserAddon, {
  ACTION_ID as RESTART_BROWSER_ADDON_ACTION,
} from "./remedies/restart-browser-addon.js";
import addonUnwallRemedy, {
  KEEP_OFF_ACTION,
  UNWALL_ACTION,
  unwallLabel,
  keepOffRemedy,
} from "./remedies/addon-unwall.js";
import removeRetiredBundle, {
  ACTION_ID as REMOVE_RETIRED_ACTION,
  FLASH as RETIRED_REMOVED_FLASH,
  STARTED_FLASH as RETIRED_REMOVING_FLASH,
  label as removeRetiredLabel,
} from "./remedies/remove-retired-bundle.js";
import removeBotSharing, { ACTION_ID as REMOVE_BOT_SHARING_ACTION, label as removeBotSharingLabel } from "./remedies/remove-bot-sharing.js";
import { CARD_DEDUP_PREFIX, liveWallFailureFor, wallFailureByItemId } from "../../../scripts/addon-sandbox/failures.mjs";
import { returnTargetOf, returnUrl } from "./flash.js";
import { recordSuppressedRequest } from "./peer-card-counters.js";
import { CARD_ACTION_IDS } from "./peer-card-policy.js";
import { createNotification } from "../../shared/notifications.js";
import { getInstance } from "../instance-registry.js";
import { escapeHtml } from "../dashboard/shared/components.js";
import { t } from "../dashboard/shared/i18n.js";
import { csrfInput } from "../dashboard/shared/csrf.js";

let wired = false;
export function wireFixIt() {
  if (wired) return;
  registry.registerDetector(remoteExposureDetector);
  registry.registerDetector(caddyProxySocketDetector);
  registry.registerDetector(caddyAdminSocketDetector);
  registry.registerDetector(bootGuardDetector);
  registry.registerDetector(dataBackendReapprovalDetector);
  registry.registerDetector(bundleBindDriftDetector);
  registry.registerDetector(retiredBundleDetector);
  registry.registerDetector(browserImageStaleDetector);
  registry.registerDetector(addonWallDetector);
  // An enabled bot that still selects crow-sharing with no allow-list entry (the bot door's
  // Sharing section is where the owner fixes it; the second button takes messaging away).
  registry.registerDetector(sharingBotAclDetector);
  registry.registerRemedy("expose-capability", exposeCapabilityRemedy);
  // The owner's own copy of a bundle compose, put back with the previous file kept
  // as <composefile>.bak (bundle-bind-drift.js's compose-edited card).
  registry.registerRemedy(RESTORE_COMPOSE_ACTION, restoreBundleCompose);
  // The image-change hold's "Apply the update": the same owner-only apply of the
  // shipped compose, offered when the update would also switch a container's image
  // (bundle-bind-drift.js's image-change card). It never restarts either.
  registry.registerRemedy(APPLY_COMPOSE_UPDATE_ACTION, restoreBundleCompose);
  // The browser add-on running an image built before the files Crow just installed:
  // restart it through the SAME Extensions restart route the Restart button calls
  // (owner only — browser-image-stale.js's card).
  registry.registerRemedy(RESTART_BROWSER_ADDON_ACTION, restartBrowserAddon);
  // An add-on that could not run inside its wall: run it unwalled by the
  // owner's choice, or answer the card and leave it off.
  registry.registerRemedy("addon-unwall", addonUnwallRemedy);
  registry.registerRemedy("addon-keep-off", keepOffRemedy);
  // N1b-8: the peer-scoped card offers three durations, and each button needs
  // its own actionId (the POST carries only action_id). All three run the same
  // one-device grant; the duration rides in the stored args.
  for (const actionId of CARD_ACTION_IDS) registry.registerRemedy(actionId, exposeCapabilityRemedy);
  // A bundle Crow retired that is still installed: one click runs the product's own
  // uninstall for it (keeps its data folder; no undo beyond that).
  registry.registerRemedy(REMOVE_RETIRED_ACTION, removeRetiredBundle);
  // Take crow-sharing out of one bot's definition (the sharing-bot-acl card's undo).
  registry.registerRemedy(REMOVE_BOT_SHARING_ACTION, removeBotSharing);
  wired = true;
}

/**
 * The detectors runBootChecks() drives. A condition no request emits an event for
 * belongs here; the list is exported so the set can be asserted, not grepped.
 */
export const BOOT_CHECK_DETECTORS = Object.freeze([
  caddyProxySocketDetector,
  caddyAdminSocketDetector,
  bootGuardDetector,
  dataBackendReapprovalDetector,
  bundleBindDriftDetector,
  retiredBundleDetector,
  browserImageStaleDetector,
  sharingBotAclDetector,
]);

/**
 * The detector whose re-run the bundle routes already make for ONE bundle after its
 * containers changed: routes/bundles.js calls
 * `runBootCheck(db, "bundle-bind-drift", { only: [id] })` after a Start, a stop and an
 * install's `up`. A detector that watches a RUNNING container's own state (the
 * browser add-on's image age) declares `recheckOnContainerChange` and rides that
 * same pass, so its card clears when the new image is in place — with no second call
 * site added to the routes, and never on a boot pass (which carries no `only`).
 */
const CONTAINER_CHANGE_RECHECK = "bundle-bind-drift";

/**
 * Where a `kind: "link"` remedy may point, held HERE and never read from the
 * card: `fix_it_items.remedies` is a crow.db column, so a stored href is a
 * value anything that can write crow.db controls. A browser reads `/\evil.example`
 * (or a tab-terminated variant) as another host, which a sanitiser based on
 * string prefixes misses. A remedy's actionId selects one of these paths; an
 * unknown actionId renders no link at all.
 */
export const LINK_REMEDIES = Object.freeze({
  // The Projects panel's route (servers/gateway/dashboard/panels/projects.js).
  "open-projects-page": "/dashboard/projects",
  // The Extensions page, where a bundle is restarted (its Restart action) and
  // where its compose file is explained. The compose refresh and the bind-drift
  // card never restart anything themselves.
  "open-extensions-page": "/dashboard/extensions",
});

/** A bot id a Bot Builder link may name (the same shape the panel routes accept). */
const LINK_BOT_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$/;

/** An add-on id is one lowercase slug (the same shape the wall detector accepts). */
const ADDON_ID_RE = /^[a-z0-9][a-z0-9-]*$/;

/**
 * Answer the pending wall card for one add-on that now runs INSIDE its wall. The
 * proxy calls this after a walled connect, with its own connect id — never a value
 * read from crow.db — so only the card that id names is resolved, and only from the
 * add-on wall source. Never throws (it runs off the connect path).
 *
 * A record still live AFTER that resolve is necessarily newer than the connect:
 * the connect cleared the old one synchronously, before the resolve reached here.
 * Resolving alone would therefore hide the newer failure's card, so it is raised
 * again — the detector's upsert reopens the same item id, and its binding accepts
 * the same item for the same record.
 */
export async function resolveAddonWallCard(db, id) {
  if (typeof id !== "string" || !ADDON_ID_RE.test(id)) return;
  try {
    await store.resolveByKey(db, ADDON_WALL_SOURCE, CARD_DEDUP_PREFIX + id);
    const live = liveWallFailureFor(id);
    if (live) await emitFixIt(db, "addon-wall-failed", { id, reason: live.reason, reasonCode: live.reasonCode, ref: live.ref });
  } catch (err) {
    console.warn(`[fix-it] add-on wall card could not be resolved: ${err?.message || err}`);
  }
}

/**
 * A link remedy that needs a PER-BOT destination: the Bot Builder page, with the bot the card is
 * about already selected. The id comes from the entry's stored `args` (a crow.db value), so it is
 * re-checked here and only ever interpolated into a path this file built — never read as a URL.
 */
const LINK_REMEDY_TARGETS = Object.freeze({
  [OPEN_BOT_BUILDER_FOR_SHARING]: (r) => {
    const bot = typeof r.args?.bot === "string" ? r.args.bot : "";
    return LINK_BOT_ID_RE.test(bot)
      ? `/dashboard/bot-builder?bot=${encodeURIComponent(bot)}&tab=safety`
      : "/dashboard/bot-builder";
  },
});

/** The code-held target of a link remedy, or null (never a stored href). */
export function linkRemedyTarget(r) {
  if (!r || typeof r.actionId !== "string") return null;
  if (Object.hasOwn(LINK_REMEDY_TARGETS, r.actionId)) return LINK_REMEDY_TARGETS[r.actionId](r);
  return Object.hasOwn(LINK_REMEDIES, r.actionId) ? LINK_REMEDIES[r.actionId] : null;
}

/**
 * The flash codes a remedy may send the owner back with. Fixed here, never read
 * from the remedy result unchecked: the redirect target is built from it.
 */
export const REMEDY_FLASHES = Object.freeze(["fixit_addon_stale", "fixit_addon_unwalled", OWNER_ONLY_FLASH, ALREADY_RESTARTING_FLASH, NEEDS_KEY_FLASH, RETIRED_REMOVED_FLASH, RETIRED_REMOVING_FLASH]);

/** Build a db-bound store; the bound upsertItem also fires urgent push. */
function boundStore(db) {
  return {
    // A boot check that must read a table of its own (data-backend-reapproval)
    // reaches it through the store it was handed, never through a second client.
    db,
    upsertItem: async (item) => {
      const r = await store.upsertItem(db, item);
      if (item.severity === "urgent" && r.notify) {
        try {
          await createNotification(db, {
            title: item.title, body: item.why || null,
            type: "system", source: "fix-it", priority: "high",
            action_url: "/dashboard/attention",
          });
        } catch (err) { console.warn("[fix-it] push failed:", err.message); }
      }
      return r;
    },
    resolveByKey: (s, k) => store.resolveByKey(db, s, k),
    // N1b-8 rate limits: a detector needs the peer's existing cards to decide
    // whether a denial earns a card, and somewhere to count the ones that don't.
    listBySource: (s) => store.listBySource(db, s),
    recordDuplicate: (id) => store.recordDuplicate(db, id),
    recordSuppressed: (info) => recordSuppressedRequest(db, info),
    // Fix round 3: a pending card raised under another pairing is stale (the
    // remedy refuses it), so the detector answers it before creating the new one.
    markResolved: (id) => store.markResolved(db, id),
  };
}

/**
 * Fire a Fix-it event. Fire-and-forget — never throws, never blocks the caller
 * (it runs on the peer-exposure request path). Enriches the payload with the
 * requesting peer's display name (generic: any payload with `requestingInstance`).
 *
 * N1b-8: for the peer-exposure card the name is ALWAYS resolved here, from this
 * instance's own registry row for the verified id — a payload-supplied name is
 * overwritten. The name is display text only; the card's identity (and the id an
 * "Allow" is scoped to) is `requestingInstance`, which the gate takes from
 * `req.instanceAuth.instance.id`.
 */
export async function emitFixIt(db, eventName, payload) {
  try {
    wireFixIt();
    const p = { ...(payload || {}) };
    if (p.requestingInstance && (!p.requestingInstanceName || eventName === "peer-exposure:denied")) {
      // Resolution may yield nothing (an unknown id): drop whatever the payload
      // claimed rather than display it.
      p.requestingInstanceName = null;
      try {
        const inst = await getInstance(db, p.requestingInstance);
        if (inst && inst.name) p.requestingInstanceName = inst.name;
      } catch { /* best-effort name */ }
    }
    await registry.emit(eventName, p, boundStore(db));
  } catch (err) {
    console.warn("[fix-it] emitFixIt failed:", err.message);
  }
}

/**
 * Re-run ONE boot-check detector now. A dashboard action that answers a boot
 * check (approving the last waiting backend) should clear its card without a
 * gateway restart. Never throws; an unknown source does nothing.
 */
export async function runBootCheck(db, source, opts = {}) {
  const detector = BOOT_CHECK_DETECTORS.find((d) => d.source === source);
  if (!detector) return null;
  wireFixIt();
  let result = null;
  try {
    result = await detector.check(boundStore(db), opts);
  } catch (err) {
    console.warn(`[fix-it] boot check "${source}" failed:`, err?.message || err);
  }
  // A container-change pass (always for ONE bundle) also re-runs the detectors that
  // watch a running container's own state. Isolated one by one, exactly like the boot
  // pass: one broken detector never hides another.
  if (source === CONTAINER_CHANGE_RECHECK && opts.only) {
    for (const extra of BOOT_CHECK_DETECTORS) {
      if (extra === detector || extra.recheckOnContainerChange !== true) continue;
      try {
        await extra.check(boundStore(db), opts);
      } catch (err) {
        console.warn(`[fix-it] boot check "${extra.source}" failed:`, err?.message || err);
      }
    }
  }
  return result;
}

/**
 * Boot checks — conditions no request emits an event for. Two of them are about
 * this machine's Caddy, decided from its Caddyfile alone: one that still dials
 * the gateway over loopback (the security audit's finding), and one whose admin
 * API is Caddy's unauthenticated localhost default. The rest are a boot guard
 * that is installed but did not run (N1c-3 L1), a data backend waiting to be
 * approved again, a bundle bind mount that drifted from its compose file, and the
 * browser add-on running an image built before the files Crow installed.
 * Fire-and-forget: never throws, and one broken detector never hides another.
 */
export async function runBootChecks(db, opts = {}) {
  wireFixIt();
  for (const detector of BOOT_CHECK_DETECTORS) await runBootCheck(db, detector.source, opts);
}

/**
 * One card model's remedy button (the Nest's markup). A link entry is navigation
 * only: nothing is posted, so no remedy runs, and its destination came from
 * LINK_REMEDIES (linkRemedyTarget), never from the stored entry.
 *
 * v1 ships only `instant`. A gated remedy renders disabled with a note so a
 * destructive action can never be a careless one-tap (the framework enforces it
 * here AND in handleFixItAction).
 */
function nestRemedyButton(itemId, r, req, lang) {
  if (r.kind === "link") {
    return `<a class="btn btn-secondary" href="${escapeHtml(r.href)}" data-fixit-link>${escapeHtml(r.label)}</a>`;
  }
  const gated = r.kind === "gated";
  const gatedNote = gated ? ` disabled title="${escapeHtml(t("fixit.comingSoon", lang))}"` : "";
  return `<form method="POST" action="/dashboard/fix-it/action" style="display:inline">
    ${csrfInput(req)}
    <input type="hidden" name="action" value="remedy">
    <input type="hidden" name="item_id" value="${escapeHtml(String(itemId))}">
    <input type="hidden" name="action_id" value="${escapeHtml(r.actionId)}">
    <button type="submit" class="btn btn-secondary" data-fixit-kind="${escapeHtml(r.gatedKind || "instant")}"${gatedNote}>${escapeHtml(r.label)}</button>
  </form>`;
}

/** `lang` as the copy table knows it. */
const LANG = (lang) => (lang === "es" ? "es" : "en");

/**
 * The stored-row remedy, as a model entry (null when it can never render).
 *
 * `ownLabel(r)` is the code-held label for this card KIND, in the dashboard's
 * language (fix-it/card-copy.js `renderStoredCard`): it wins over the stored
 * label, so a button whose words the card owns agrees with the body around it.
 * It answers null for an actionId the kind does not own.
 */
function storedRemedyModel(r, lang, ownLabel = null) {
  if (!r || typeof r !== "object") return null;
  const owned = typeof ownLabel === "function" ? ownLabel(r) : null;
  if (r.kind === "link") {
    // A link whose actionId this file does not hold has no destination and is
    // not rendered at all — a stored href is never read.
    const href = linkRemedyTarget(r);
    if (!href) return null;
    const label = owned || (typeof r.label === "string" && r.label ? r.label : t("fixit.open", lang));
    return { kind: "link", label, href };
  }
  if (typeof r.actionId !== "string" || !r.actionId) return null;
  const gated = r.kind === "confirm" || r.kind === "guided";
  const label = owned || (typeof r.label === "string" && r.label ? r.label : t("fixit.fix", lang));
  return gated
    ? { kind: "gated", label, actionId: r.actionId, gatedKind: r.kind }
    : { kind: "form", label, actionId: r.actionId };
}

/**
 * The Technical details rows of a stored card: the three context values the Nest
 * has always shown, each with its label from the copy table. The values are
 * crow.db data, so the renderers escape them.
 */
function storedDetails(item, lang) {
  const ctx = item.context || {};
  const rows = [];
  if (ctx.capability) rows.push({ label: t("fixit.capability", lang), code: String(ctx.capability) });
  if (ctx.requestingInstance) rows.push({ label: t("fixit.requestingInstance", lang), code: String(ctx.requestingInstance) });
  if (ctx.caddyfile) rows.push({ label: t("fixit.caddyfile", lang), code: String(ctx.caddyfile) });
  return rows;
}

/**
 * ONE card's model. Everything a card shows is decided here — including the three
 * sources whose title, body and buttons are held in CODE (a retired bundle, an
 * add-on that could not run inside its wall, a bot that lost its sharing): their
 * rows are crow.db columns, and the eight add-ons that share crow.db can write
 * them, so nothing stored is rendered for them.
 *
 * @returns {{id: number, count: number, title: string, why: string, remedies: Array<object>, details: Array<{label: string, code: string}>}}
 */
function cardModel(item, lang) {
  const base = { id: item.id, count: item.count };

  if (item.source === RETIRED_BUNDLE_SOURCE) {
    // A retired bundle's card reads NOTHING from the stored row: the title, the body, the
    // button's label and the bundle's name all come from code (retired-bundles.js + this
    // detector), in the dashboard's language — so the button says what the body's instruction
    // says to press, in both languages, whatever a crow.db writer put in the row. The one
    // stored input — the id — selects a code-held entry, so a crow.db writer can raise no
    // card that names anything else.
    const id = typeof item.context?.bundle === "string" ? item.context.bundle : "";
    return {
      ...base,
      title: retiredBundleTitle(id, lang),
      why: retiredBundleWhy(id, lang),
      remedies: [{ kind: "form", label: removeRetiredLabel(lang), actionId: REMOVE_RETIRED_ACTION }],
      details: [],
    };
  }

  if (item.source === ADDON_WALL_SOURCE) {
    // The card is the LIVE failure record bound to this item, or nothing: a stored title,
    // why, label or context is never rendered (see retired-bundle above).
    const record = wallFailureByItemId(Number(item.id));
    const keepOff = { kind: "form", label: t("fixit.addonWall.keepOff", lang), actionId: KEEP_OFF_ACTION };
    if (!record) {
      // No record: the card answers nothing, so it offers no fix at all.
      return { ...base, title: t("fixit.addonWall.title", lang), why: t("fixit.addonWall.stale", lang), remedies: [keepOff], details: [] };
    }
    return {
      ...base,
      title: t("fixit.addonWall.title", lang),
      // The reason is rendered from the record's CODE in the dashboard's language
      // (the stored English sentence is the fallback for an older record).
      why: addonWallWhyTextForRecord(record, lang),
      remedies: [
        { kind: "form", label: unwallLabel(record.id, lang), actionId: UNWALL_ACTION },
        keepOff,
      ],
      details: [],
    };
  }

  if (item.source === SHARING_BOT_ACL_SOURCE) {
    // The retired-bundle card's rule, for the same reason: the row's title, body and button labels
    // are crow.db columns, so the card is rebuilt from CODE in the dashboard's language instead of
    // rendering them. That is what makes a Spanish dashboard show "Compartir" and "Quitar la
    // mensajería a este bot" — words that agree with the Spanish body — rather than the stored EN.
    // The two stored inputs are the bot's id (both remedies re-check it against BOT_ID_RE before
    // acting) and the display name the detector flattened; the name is flattened again here by
    // cardTitle, and every sentence it lands in comes from the copy table. An id that is not a
    // string is treated as no id: the remedies then refuse, and the title falls back to no name.
    const bot = typeof item.context?.bot === "string" ? item.context.bot : "";
    const name = typeof item.context?.name === "string" ? item.context.name : "";
    const builderHref = linkRemedyTarget({ actionId: OPEN_BOT_BUILDER_FOR_SHARING, args: { bot } });
    return {
      ...base,
      title: sharingCardTitle(name, bot, lang),
      why: sharingCardWhy(lang),
      remedies: [
        { kind: "link", label: t("botbuilder.sharing.heading", LANG(lang)), href: builderHref },
        { kind: "form", label: removeBotSharingLabel(lang), actionId: REMOVE_BOT_SHARING_ACTION },
      ],
      details: [],
    };
  }

  // A card the copy table knows renders its title/body/button labels from code in
  // the dashboard's language; the stored text is what a Spanish dashboard used to
  // show, and it stays the answer for every row written before `context.card`
  // existed (and for one whose code or values are not usable).
  const copy = renderStoredCard(item, lang);
  const remedies = (item.remedies || []).map((r) => storedRemedyModel(r, lang, copy?.remedyLabel)).filter(Boolean);
  return {
    ...base,
    title: copy ? copy.title : item.title,
    why: copy ? copy.why : (item.why || ""),
    remedies,
    details: storedDetails(item, lang),
  };
}

/**
 * Every pending card, as a plain model. This is the ONE place that holds card
 * logic; the two renderers below only turn a model into markup.
 *
 * @returns {Promise<Array<object>>} [] when nothing is pending (or the read fails)
 */
export async function fixItCardModels(db, { lang = "en", req } = {}) {
  void req;
  let items = [];
  try { items = await store.listPending(db); } catch { return []; }
  const language = LANG(lang);
  return items.map((item) => cardModel(item, language));
}

/** One model as the Nest's card (byte-identical to what the Nest rendered before). */
function nestCardHtml(card, req, lang) {
  const countBadge = card.count > 1
    ? `<span style="font-size:0.7rem;color:var(--crow-text-muted)">×${escapeHtml(String(card.count))}</span>` : "";
  const buttons = card.remedies.map((r) => nestRemedyButton(card.id, r, req, lang)).join("");
  const details = card.details.length
    ? `<details style="margin-top:0.5rem"><summary style="cursor:pointer;color:var(--crow-text-muted);font-size:0.8rem">${escapeHtml(t("fixit.technicalDetails", lang))}</summary>
           <div style="font-size:0.8rem;color:var(--crow-text-muted);margin-top:0.3rem">${card.details.map((d) => `${escapeHtml(d.label)} <code>${escapeHtml(d.code)}</code>`).join("<br>")}</div></details>`
    : "";
  return `<div class="nest-fixit-card" style="border:1px solid var(--crow-border,#2222);border-left:3px solid var(--crow-warning,#e0a000);border-radius:8px;padding:0.8rem 1rem;margin-bottom:0.6rem;background:var(--crow-surface,rgba(255,255,255,0.02))">
      <div style="font-weight:600;margin-bottom:0.2rem">${escapeHtml(card.title)} ${countBadge}</div>
      ${card.why ? `<div style="color:var(--crow-text-secondary);font-size:0.9rem;margin-bottom:0.6rem">${escapeHtml(card.why)}</div>` : ""}
      <div style="display:flex;gap:0.5rem;align-items:center;flex-wrap:wrap">
        ${buttons}
        <form method="POST" action="/dashboard/fix-it/action" style="display:inline">
          ${csrfInput(req)}
          <input type="hidden" name="action" value="dismiss">
          <input type="hidden" name="item_id" value="${escapeHtml(String(card.id))}">
          <button type="submit" class="btn btn-text" style="background:none;border:none;color:var(--crow-text-muted);cursor:pointer">${escapeHtml(t("fixit.notNow", lang))}</button>
        </form>
      </div>
      ${details}
    </div>`;
}

/** Render the nest Fix-it card section (or "" when nothing pending). */
export async function renderFixItCards(db, { lang = "en", req } = {}) {
  const language = LANG(lang);
  const models = await fixItCardModels(db, { lang: language, req });
  if (!models.length) return "";
  const cards = models.map((card) => nestCardHtml(card, req, language)).join("");
  return `<div class="nest-fixits" style="margin:0 1rem 1rem" aria-label="${escapeHtml(t("fixit.thingsNoticed", language))}">${cards}</div>`;
}

/**
 * One model as an Attention-sheet card: the same title, ×N badge, why, remedies and
 * Technical details, in the shell's own classes. Every form posts to
 * /dashboard/fix-it/action with `return=sheet`; the shell client fills the empty
 * `_csrf` on submit, like the sheet's other forms.
 */
function sheetRemedyHtml(card, r, lang) {
  if (r.kind === "link") {
    return `<a class="shell-fixit-btn" href="${escapeHtml(r.href)}" data-fixit-link>${escapeHtml(r.label)}</a>`;
  }
  const gated = r.kind === "gated";
  const gatedNote = gated ? ` disabled title="${escapeHtml(t("fixit.comingSoon", lang))}"` : "";
  return `<form class="shell-fixit-form" method="POST" action="/dashboard/fix-it/action">`
    + `<input type="hidden" name="_csrf" value="">`
    + `<input type="hidden" name="action" value="remedy">`
    + `<input type="hidden" name="item_id" value="${escapeHtml(String(card.id))}">`
    + `<input type="hidden" name="action_id" value="${escapeHtml(r.actionId)}">`
    + `<input type="hidden" name="return" value="sheet">`
    + `<button type="submit" class="shell-fixit-btn" data-fixit-kind="${escapeHtml(r.gatedKind || "instant")}"${gatedNote}>${escapeHtml(r.label)}</button>`
    + `</form>`;
}

function sheetCardHtml(card, lang) {
  const countBadge = card.count > 1 ? ` <span class="shell-fixit-count">×${escapeHtml(String(card.count))}</span>` : "";
  const remedies = card.remedies.map((r) => sheetRemedyHtml(card, r, lang)).join("");
  const details = card.details.length
    ? `<details class="shell-fixit-details"><summary>${escapeHtml(t("fixit.technicalDetails", lang))}</summary>`
      + card.details.map((d) => `<div class="shell-fixit-detail">${escapeHtml(d.label)} <code>${escapeHtml(d.code)}</code></div>`).join("")
      + `</details>`
    : "";
  return `<div class="shell-fixit-card" data-fixit-item="${escapeHtml(String(card.id))}">`
    + `<div class="shell-fixit-title">${escapeHtml(card.title)}${countBadge}</div>`
    + (card.why ? `<div class="shell-fixit-why">${escapeHtml(card.why)}</div>` : "")
    + `<div class="shell-fixit-actions">${remedies}`
      + `<form class="shell-fixit-form" method="POST" action="/dashboard/fix-it/action">`
        + `<input type="hidden" name="_csrf" value="">`
        + `<input type="hidden" name="action" value="dismiss">`
        + `<input type="hidden" name="item_id" value="${escapeHtml(String(card.id))}">`
        + `<input type="hidden" name="return" value="sheet">`
        + `<button type="submit" class="shell-fixit-btn shell-fixit-btn--quiet">${escapeHtml(t("fixit.notNow", lang))}</button>`
      + `</form>`
    + `</div>`
    + details
    + `</div>`;
}

/** Render the Attention sheet's Fix-it cards (or "" when nothing pending). */
export async function renderFixItSheetCards(db, { lang = "en", req } = {}) {
  const language = LANG(lang);
  const models = await fixItCardModels(db, { lang: language, req });
  if (!models.length) return "";
  return models.map((card) => sheetCardHtml(card, language)).join("");
}

/**
 * POST /dashboard/fix-it/action — remedy or dismiss. Every answer is a redirect to
 * one of the two code-held targets (fix-it/flash.js: the Nest unless the form asked
 * for the Attention sheet), carrying a flash code from FLASH_CODES.
 *
 * A click that resolved answers `fixit_done` — except a SHARING remedy (the
 * expose-capability grant, which every Allow duration alias runs), whose flash stays
 * `fixit_fixed`; a remedy that names its own allowed flash keeps it.
 */
export async function handleFixItAction(req, res, { db }) {
  wireFixIt();
  const body = req.body || {};
  const action = body.action;
  const itemId = Number(body.item_id);
  const returnTo = (flash, params) =>
    res.redirectAfterPost(returnUrl(returnTargetOf(body.return), flash, params));
  try {
    if (!Number.isInteger(itemId)) {
      return returnTo("fixit_error");
    }
    if (action === "dismiss") {
      await store.dismiss(db, itemId, 7);
      return returnTo("fixit_dismissed");
    }
    if (action === "remedy") {
      const item = await store.getItem(db, itemId);
      if (!item) return returnTo("fixit_error");
      // N1b-8 review round 1 (N2): only a card that is still open may run its
      // remedy. A stale page, a double submit or a replayed POST would
      // otherwise re-apply a fix the operator already answered (re-granting an
      // allowance, or granting one for a card they dismissed).
      if (item.status !== "pending") {
        return returnTo("fixit_not_pending");
      }
      const entry = (item.remedies || []).find((r) => r.actionId === body.action_id);
      if (!entry) return returnTo("fixit_error");
      if (entry.kind && entry.kind !== "instant") {
        // v1 only runs instant remedies; confirm/guided are gated.
        return returnTo("fixit_error");
      }
      const fn = registry.getRemedy(entry.actionId);
      if (!fn) return returnTo("fixit_error");
      // `req` rides along for a remedy that must prove the OWNER at this machine's
      // dashboard (the compose restore): it is the request, never stored card data.
      const result = await fn(entry.args || {}, { db, item, req });
      const ownFlash = result && typeof result.flash === "string" && REMEDY_FLASHES.includes(result.flash)
        ? result.flash
        : null;
      if (result && result.resolved) {
        await store.markResolved(db, itemId);
        const done = ownFlash || (fn === exposeCapabilityRemedy ? "fixit_fixed" : "fixit_done");
        return returnTo(done, result.flashParams);
      }
      if (ownFlash) return returnTo(ownFlash, result.flashParams);
      return returnTo("fixit_error");
    }
    return returnTo("fixit_error");
  } catch (err) {
    console.error("[fix-it] action failed:", err.message);
    return returnTo("fixit_error");
  }
}
