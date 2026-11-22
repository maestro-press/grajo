/**
 * Fix-it card copy — the ONE place that knows which i18n keys a card kind uses
 * and which values it takes, so a card can be rendered in the dashboard's
 * language at VIEW time.
 *
 * Why this exists. A card row (`fix_it_items`) stores English text, and half the
 * sources (remote exposure, the boot guard, Caddy, data backends, bundle bind
 * drift, the browser add-on, add-on keys) used to render those stored strings
 * whatever the dashboard's language was. The detectors now build their stored
 * English FROM these same keys (`cardText(code, values, "en")`), so the English
 * a row carries and the English this module renders are identical by
 * construction; a Spanish dashboard renders the approved Spanish from the same
 * keys. A row with no `context.card` (written before this change) keeps
 * rendering its stored text unchanged in every language.
 *
 * Safety. `context` is a crow.db column the eight add-ons that share the
 * database can write, so a value here is data, never code:
 *   - only the fixed, code-held set of value names a card kind declares is read
 *     (everything else in `values` is ignored);
 *   - each value must be a string, a number or null/undefined (anything else
 *     makes `renderStoredCard` return null, so the stored text is used);
 *   - each value is coerced to a string and length-capped;
 *   - `fill()` inserts values verbatim (no $-expansion, one pass, so a value
 *     carrying `{name}` cannot fill itself in), and it does NOT escape — the
 *     Nest/sheet renderers escape the title, body and labels exactly as before;
 *   - a Caddy `{fixCommand}` is recomputed from code here, never read from the
 *     row; the remote-exposure friendly name comes from the code-held map in the
 *     viewer's language, never from stored text.
 */
import { resolve } from "node:path";
import { fill, t } from "../dashboard/shared/i18n.js";
import { HIDDEN_TARGET, wallReasonValues } from "../../../scripts/addon-sandbox/failures.mjs";
import { appRoot } from "./app-root.js";
import { COPY as BROWSER_COPY } from "./browser-image-stale-copy.js";
import { resolveFriendlyName } from "./friendly-names.js";

/** A stored value's cap: enough for a name, a version, a relative path. */
const MAX_VALUE_LENGTH = 512;

/** The only two languages the dashboard has. */
const langOf = (lang) => (lang === "es" ? "es" : "en");

/** True for a plain (non-array) object. */
function isPlainObject(value) {
  return value !== null && typeof value === "object" && !Array.isArray(value);
}

/** The text of one stored value, or null when its type is not safe to read. */
function readValue(value) {
  if (value === null || value === undefined) return "";
  if (typeof value === "string") return value.slice(0, MAX_VALUE_LENGTH);
  if (typeof value === "number" && Number.isFinite(value)) return String(value);
  return null;
}

/** The Caddy fix commands: built from the checkout this gateway runs in. */
export const fixCaddyProxyCommand = () => `sudo bash ${resolve(appRoot(), "scripts", "fix-caddy-proxy-socket.sh")}`;
export const fixCaddyAdminCommand = () => `sudo bash ${resolve(appRoot(), "scripts", "fix-caddy-admin-socket.sh")}`;

/** The i18n key of each boot-guard reason (one whole sentence each). */
const BOOT_GUARD_WHY_KEYS = Object.freeze({
  "boot-guard-recorder": "fixit.card.bootGuard.recorderWhy",
  "boot-guard-launcher": "fixit.card.bootGuard.launcherWhy",
  "boot-guard-other": "fixit.card.bootGuard.otherWhy",
});

/** The boot-guard card code for a detector reason. */
export const bootGuardCardCode = (reason) => (Object.hasOwn(BOOT_GUARD_WHY_KEYS, `boot-guard-${reason}`) ? `boot-guard-${reason}` : "boot-guard-other");

/** The image-change sentence the values select (an added step, a removed one, a swapped image). */
const imageChangeCode = ({ from, to }) => (!from && to ? "image-added" : from && !to ? "image-removed" : "image-swapped");

/** The values one image-change sentence fills: the tail, the step name and the two image names. */
function imageChangeValues(values, lang) {
  return {
    service: values.service || t("fixit.card.bundleImageChange.serviceFallback", lang),
    from: values.from || t("fixit.card.bundleImageChange.none", lang),
    to: values.to || t("fixit.card.bundleImageChange.none", lang),
    tail: t("fixit.card.bundleImageChange.tail", lang),
  };
}

/**
 * The browser card's version sentence, in `lang`: the approved sentence for a
 * known running version, the approved "earlier version" one when the running
 * container could not say, and nothing at all when the installed version is
 * unknown (the body then stands alone, exactly as the detector stores it).
 */
function browserVersionSentence(running, installed, lang) {
  if (!installed) return "";
  const template = running ? BROWSER_COPY.versionKnown[lang] : BROWSER_COPY.versionUnknown[lang];
  return fill(template, { running, new: installed });
}

/** A card whose title and body are plain keys filled with its values. */
const keyed = (values, titleKey, whyKey, extra = {}) => ({
  values,
  title: (v, lang) => fill(t(titleKey, lang), v),
  why: (v, lang) => fill(t(whyKey, lang), v),
  ...extra,
});

/**
 * Every card kind this module renders. `values` is the ONLY set of names read
 * from `context.card.values`; `remedyLabels` maps an actionId this kind owns to
 * the function that produces its label in the viewer's language (an actionId it
 * does not own is left to the stored label).
 */
const CARD_DEFS = {
  "remote-exposure": {
    values: ["peer", "capability", "requestingInstance"],
    title(values, lang) {
      const key = values.peer
        ? "fixit.card.remoteExposure.namedTitle"
        : "fixit.card.remoteExposure.namelessTitle";
      return fill(t(key, lang), {
        peer: values.peer,
        friendly: resolveFriendlyName(values.capability, null, lang),
      });
    },
    why(values, lang) {
      const key = values.peer
        ? "fixit.card.remoteExposure.namedWhy"
        : "fixit.card.remoteExposure.namelessWhy";
      return fill(t(key, lang), { peer: values.peer });
    },
    remedyLabels: {
      "expose-capability-30d": (lang) => t("fixit.card.remedy.allow30d", lang),
      "expose-capability-7d": (lang) => t("fixit.card.remedy.allow7d", lang),
      "expose-capability-forever": (lang) => t("fixit.card.remedy.allowForever", lang),
    },
  },

  "caddy-proxy-socket": {
    values: [],
    title: (_v, lang) => t("fixit.card.caddyProxy.title", lang),
    why: (_v, lang) => fill(t("fixit.card.caddyProxy.why", lang), { fixCommand: fixCaddyProxyCommand() }),
  },
  "caddy-admin-socket": {
    values: [],
    title: (_v, lang) => t("fixit.card.caddyAdmin.title", lang),
    why: (_v, lang) => fill(t("fixit.card.caddyAdmin.why", lang), { fixCommand: fixCaddyAdminCommand() }),
  },

  "data-backend-reapproval": keyed(["n"], "fixit.card.dataBackend.title", "fixit.card.dataBackend.why", {
    remedyLabels: {
      "open-projects-page": (lang) => t("fixit.card.remedy.openProjectsPage", lang),
    },
  }),

  // ── bundle-bind-drift and its four sibling sources ─────────────────────────
  "bind-wider": keyed(["name", "hostIp", "hostPort"], "fixit.card.bundleDrift.title", "fixit.card.bundleDrift.widerWhy", {
    remedyLabels: { "open-extensions-page": (lang) => t("fixit.card.remedy.openExtensions", lang) },
  }),
  "bind-extra": keyed(["name", "hostIp", "hostPort"], "fixit.card.bundleDrift.title", "fixit.card.bundleDrift.extraWhy", {
    remedyLabels: { "open-extensions-page": (lang) => t("fixit.card.remedy.openExtensions", lang) },
  }),
  "compose-edited": keyed(["name", "composeRel"], "fixit.card.bundleComposeEdited.title", "fixit.card.bundleComposeEdited.why", {
    remedyLabels: {
      "restore-bundle-compose": (lang) => t("fixit.card.remedy.restoreCompose", lang),
      "open-extensions-page": (lang) => t("fixit.card.remedy.openExtensions", lang),
    },
  }),
  "repo-drift-edited": keyed(["name"], "fixit.card.bundleRepoDrift.title", "fixit.card.bundleRepoDrift.editedWhy", {
    remedyLabels: { "open-extensions-page": (lang) => t("fixit.card.remedy.openExtensions", lang) },
  }),
  "repo-drift-unknown": keyed(["name"], "fixit.card.bundleRepoDrift.title", "fixit.card.bundleRepoDrift.unknownWhy", {
    remedyLabels: { "open-extensions-page": (lang) => t("fixit.card.remedy.openExtensions", lang) },
  }),
  "needs-config": keyed(["name", "key"], "fixit.card.bundleNeedsConfig.title", "fixit.card.bundleNeedsConfig.why", {
    remedyLabels: { "open-extensions-page": (lang) => t("fixit.card.remedy.openExtensions", lang) },
  }),
  "image-added": {
    values: ["name", "service", "from", "to"],
    title: (v, lang) => fill(t("fixit.card.bundleImageChange.title", lang), v),
    why: (v, lang) => fill(t("fixit.card.bundleImageChange.addedWhy", lang), { name: v.name, ...imageChangeValues(v, lang) }),
    remedyLabels: {
      "apply-bundle-compose-update": (lang) => t("fixit.card.remedy.applyUpdate", lang),
      "open-extensions-page": (lang) => t("fixit.card.remedy.openExtensions", lang),
    },
  },
  "image-removed": {
    values: ["name", "service", "from", "to"],
    title: (v, lang) => fill(t("fixit.card.bundleImageChange.title", lang), v),
    why: (v, lang) => fill(t("fixit.card.bundleImageChange.removedWhy", lang), { name: v.name, ...imageChangeValues(v, lang) }),
    remedyLabels: {
      "apply-bundle-compose-update": (lang) => t("fixit.card.remedy.applyUpdate", lang),
      "open-extensions-page": (lang) => t("fixit.card.remedy.openExtensions", lang),
    },
  },
  "image-swapped": {
    values: ["name", "service", "from", "to"],
    title: (v, lang) => fill(t("fixit.card.bundleImageChange.title", lang), v),
    why: (v, lang) => fill(t("fixit.card.bundleImageChange.swappedWhy", lang), { name: v.name, ...imageChangeValues(v, lang) }),
    remedyLabels: {
      "apply-bundle-compose-update": (lang) => t("fixit.card.remedy.applyUpdate", lang),
      "open-extensions-page": (lang) => t("fixit.card.remedy.openExtensions", lang),
    },
  },

  // ── the browser add-on's stale image (copy lives in its own approved table) ─
  "browser-image-stale": {
    values: ["running", "new"],
    title: (_v, lang) => BROWSER_COPY.title[lang],
    why: (v, lang) => {
      const sentence = browserVersionSentence(v.running, v.new, lang);
      return sentence ? `${BROWSER_COPY.body[lang]} ${sentence}` : BROWSER_COPY.body[lang];
    },
    remedyLabels: {
      "restart-browser-addon": (lang) => BROWSER_COPY.restartAction[lang],
      "open-extensions-page": (lang) => BROWSER_COPY.openExtensions[lang],
    },
  },

  "addon-keys-unreadable": {
    values: [],
    title: (_v, lang) => t("fixit.card.addonKeys.title", lang),
    why: (_v, lang) => t("fixit.card.addonKeys.why", lang),
  },
};

// The boot-guard's three reasons: one title, one whole sentence each.
for (const [code, whyKey] of Object.entries(BOOT_GUARD_WHY_KEYS)) {
  CARD_DEFS[code] = {
    values: [],
    title: (_v, lang) => t("fixit.card.bootGuard.title", lang),
    why: (_v, lang) => t(whyKey, lang),
  };
}

/** Every card code `cardText`/`renderStoredCard` knows. */
export const CARD_CODES = Object.freeze(Object.keys(CARD_DEFS));

/** The `code` piece of one image-change record, for a detector to store. */
export const imageChangeCardCode = imageChangeCode;

/**
 * The card kind `code` names, or undefined — an OWN property of the code-held
 * table only. `code` is a stored string, so "constructor" or "__proto__" must
 * miss every lookup instead of reaching Object.prototype.
 */
const cardDef = (code) => (typeof code === "string" && Object.hasOwn(CARD_DEFS, code) ? CARD_DEFS[code] : undefined);

/**
 * The `context.card` a detector stores beside its existing context keys:
 * `{ ...extra, card: { code, values } }`, with only the names this kind reads
 * and every value reduced to safe text.
 */
export function cardContext(code, values, extra = {}) {
  const def = cardDef(code);
  const safe = {};
  for (const name of def ? def.values : []) {
    const text = readValue(isPlainObject(values) ? values[name] : undefined);
    safe[name] = text ?? "";
  }
  return { ...(isPlainObject(extra) ? extra : {}), card: { code, values: safe } };
}

/**
 * `{ title, why }` for one card kind and value set, in `lang` — both strings,
 * NOT escaped (the renderers escape). Returns null for a code this module does
 * not know, or when `values` is not a plain object / carries a value of the
 * wrong type.
 */
export function cardText(code, values, lang = "en") {
  const def = cardDef(code);
  if (!def) return null;
  if (!isPlainObject(values)) return null;
  const safe = {};
  for (const name of def.values) {
    const text = readValue(values[name]);
    if (text === null) return null; // an object/array/boolean: treat the card as malformed
    safe[name] = text;
  }
  const language = langOf(lang);
  return { title: def.title(safe, language), why: def.why(safe, language) };
}

/**
 * The label (in `lang`) of one remedy button a card kind owns, or null when the
 * kind does not own that actionId (the stored label is then the right one).
 */
export function cardRemedyLabel(code, actionId, lang = "en") {
  const labels = cardDef(code)?.remedyLabels || {};
  if (typeof actionId !== "string" || !Object.hasOwn(labels, actionId)) return null;
  return labels[actionId](langOf(lang));
}

/**
 * A stored card row's copy in `lang`, or null when the row has no
 * `context.card`, names a code this module does not know, or carries malformed
 * values — the caller then renders the row's stored text exactly as before.
 *
 * `remedyLabel(r)` answers the label for a stored remedy whose actionId this
 * card kind owns, in `lang`; null means "use the stored label".
 */
export function renderStoredCard(item, lang = "en") {
  const card = item?.context?.card;
  if (!isPlainObject(card)) return null;
  const code = card.code;
  if (typeof code !== "string") return null;
  const text = cardText(code, card.values, lang);
  if (!text) return null;
  const labels = cardDef(code)?.remedyLabels || {};
  const language = langOf(lang);
  return {
    title: text.title,
    why: text.why,
    remedyLabel: (r) => {
      const actionId = r && typeof r.actionId === "string" ? r.actionId : null;
      const label = actionId && Object.hasOwn(labels, actionId) ? labels[actionId](language) : null;
      return typeof label === "string" && label ? label : null;
    },
  };
}

/**
 * The i18n key of each wall-failure reason sentence (scripts/addon-sandbox/
 * failures.mjs's codes). `null` keys are resolved from other values, not a key.
 */
const WALL_REASON_KEYS = Object.freeze({
  "refused": "fixit.wall.reason.refused",
  "installed-changed": "fixit.wall.reason.installedChanged",
  "warmup": "fixit.wall.reason.warmup",
  "not-ready": "fixit.wall.reason.notReady",
  "denied": "fixit.wall.reason.denied",
  "open": "fixit.wall.reason.openRel",
  "open-folder": "fixit.wall.reason.openFolder",
  "open-outside": "fixit.wall.reason.openOutside",
  "exit-code": "fixit.wall.reason.exitCode",
  "default": "fixit.wall.reason.default",
});

/**
 * One wall failure's reason line in `lang`, from the code + values the proxy
 * kept on the in-memory record (never from finished English text). Returns null
 * for an unknown code, so the caller can fall back to a stored reason string.
 */
export function renderWallReason(reasonCode, lang = "en") {
  if (!isPlainObject(reasonCode) || typeof reasonCode.code !== "string") return null;
  const language = langOf(lang);
  // A reason's one value may sit beside `code` or inside `values` (see
  // scripts/addon-sandbox/failures.mjs `wallFailureReasonCode`).
  const values = wallReasonValues(reasonCode);
  if (reasonCode.code === "warmup") {
    const warmup = t(WALL_REASON_KEYS.warmup, language);
    if (!isPlainObject(values.detail)) return warmup;
    const detail = renderWallReason(values.detail, language);
    return detail ? `${warmup}: ${detail}` : warmup;
  }
  const key = Object.hasOwn(WALL_REASON_KEYS, reasonCode.code) ? WALL_REASON_KEYS[reasonCode.code] : null;
  if (!key) return null;
  if (reasonCode.code === "denied") {
    const stored = readValue(values.target) || "";
    // The proxy stores the fixed HIDDEN_TARGET sentinel when a denial names
    // something that is not plain host:port text; that word is translated here.
    const target = !stored || stored === HIDDEN_TARGET
      ? t("fixit.wall.reason.hiddenTarget", language)
      : stored;
    return fill(t(key, language), { target });
  }
  if (reasonCode.code === "open") {
    const rel = readValue(values.rel) || "";
    return fill(t(key, language), { rel });
  }
  if (reasonCode.code === "exit-code") {
    return fill(t(key, language), { exitCode: readValue(values.exitCode) ?? "" });
  }
  return t(key, language);
}