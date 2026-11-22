/**
 * In-memory records of the add-ons that could not run inside their wall.
 *
 * A record is what makes the owner's "Run without the wall" click safe: the
 * Fix-it card stores only a random `ref`, and the remedy reads the add-on id
 * from the record that ref names, never from the card (crow.db is writable by
 * the eight add-ons that share it). Records live as long as this process, so a
 * card raised before a restart names nothing and unwalls nothing.
 *
 * A record also remembers the Fix-it item it became (`itemId`, `dedupKey`), so
 * the card the owner sees is bound to the record and the remedy can refuse a
 * copy of a genuine ref on a forged card.
 *
 * Pure: node built-ins, the dashboard's i18n table (the one copy of the
 * approved reason sentences the card renders too) and memory, no I/O.
 */
import { randomBytes } from "node:crypto";
import { relative as relativePath, resolve as resolvePath } from "node:path";
import { fill, t } from "../../servers/gateway/dashboard/shared/i18n.js";

/** A ref is 16 random bytes, hex. */
const REF_RE = /^[0-9a-f]{32}$/;
/** The most live records this map holds; the oldest is dropped first. */
export const MAX_WALL_FAILURES = 256;
/** A denial target a card may show: no spaces, nothing a card could reshape. */
const TARGET_RE = /^[A-Za-z0-9.:[\]_-]{1,255}$/;
/** An open(2) failure with its path in single quotes (the newest line wins). */
const OPEN_FAILURE_RE = /\b(EROFS|EACCES|ENOENT|EPERM)\b[^']*'([^']+)'/;
/** The dedupKey of one add-on's card: "addon-wall:<id>". */
export const CARD_DEDUP_PREFIX = "addon-wall:";
/** A relative path a card may show: no spaces, quotes, markup or "~". */
const PLAIN_RELATIVE_RE = /^[A-Za-z0-9._/-]{1,128}$/;

/**
 * The i18n key of each reason sentence. These are the SAME keys the Fix-it
 * card renders (servers/gateway/fix-it/card-copy.js `renderWallReason`), so the
 * English constants below and the card's English are one copy: `t(key, "en")`.
 */
const REASON_KEYS = Object.freeze({
  refused: "fixit.wall.reason.refused",
  installedChanged: "fixit.wall.reason.installedChanged",
  warmup: "fixit.wall.reason.warmup",
  notReady: "fixit.wall.reason.notReady",
  hiddenTarget: "fixit.wall.reason.hiddenTarget",
  denied: "fixit.wall.reason.denied",
  open: "fixit.wall.reason.openRel",
  openFolder: "fixit.wall.reason.openFolder",
  openOutside: "fixit.wall.reason.openOutside",
  exitCode: "fixit.wall.reason.exitCode",
  default: "fixit.wall.reason.default",
});

/** The wall itself could not be built here. */
export const REFUSED_REASON = t(REASON_KEYS.refused, "en");
/** The installed copy's policy differs from Crow's copy of the bundle. */
export const INSTALLED_CHANGED_REASON = t(REASON_KEYS.installedChanged, "en");
/** The prepare run inside the wall did not finish. */
export const WARMUP_REASON = t(REASON_KEYS.warmup, "en");
/** A child that went away without an exit code of its own. */
export const NOT_READY_REASON = t(REASON_KEYS.notReady, "en");
/** Shown when a denial target is not plain host:port text. */
export const HIDDEN_TARGET = t(REASON_KEYS.hiddenTarget, "en");
/** The add-on-wall card's fallback when an event carries no reason at all. */
export const DEFAULT_REASON = t(REASON_KEYS.default, "en");

const records = new Map(); // ref -> { id, reason, at, itemId, dedupKey }
const liveRef = new Map(); // id -> ref (at most one live record per add-on)
const liveItem = new Map(); // Fix-it item id -> ref

/** The copy of a record the callers see (never the live object). */
function recordView(record) {
  return {
    id: record.id,
    reason: record.reason,
    reasonCode: record.reasonCode,
    at: record.at,
    itemId: record.itemId,
    dedupKey: record.dedupKey,
  };
}

/** Drop one record and every index entry that points at it. */
function dropRecord(ref) {
  const record = records.get(ref);
  if (!record) return;
  records.delete(ref);
  if (record.itemId != null && liveItem.get(record.itemId) === ref) liveItem.delete(record.itemId);
  if (liveRef.get(record.id) === ref) liveRef.delete(record.id);
}

/**
 * Remember one failure for `id` and return its ref. A newer failure for an
 * add-on drops its older record, so only the latest cards can be answered.
 *
 * `reasonCode` is the machine-readable `{ code, values }` shape
 * (`wallFailureReasonCode`) — the reason is rendered from it at view time, in
 * the dashboard's language (fix-it/card-copy.js `renderWallReason`). `reason`
 * stays beside it as the English sentence the console and older cards use.
 */
export function recordWallFailure(id, reason, reasonCode = null) {
  if (typeof id !== "string" || !id) return null;
  const ref = randomBytes(16).toString("hex");
  const older = liveRef.get(id);
  if (older) dropRecord(older);
  records.set(ref, {
    id,
    reason: typeof reason === "string" ? reason : String(reason ?? ""),
    reasonCode: isReasonCode(reasonCode) ? reasonCode : null,
    at: Date.now(),
    itemId: null,
    dedupKey: null,
  });
  liveRef.set(id, ref);
  while (records.size > MAX_WALL_FAILURES) {
    const oldest = records.keys().next().value;
    dropRecord(oldest);
  }
  return ref;
}

/** True for a `{ code, values }` reason code this module can produce. */
function isReasonCode(value) {
  return Boolean(value) && typeof value === "object" && typeof value.code === "string" && value.code !== "";
}

/**
 * Bind a live record to the Fix-it item it became. Refused (false) for an
 * unknown ref, a non-integer item id, a dedupKey naming another add-on, an item
 * id another live record already owns, or a second, different item id for a
 * record that is already bound — so a writer that copies a ref onto its own
 * card cannot take the record over.
 */
export function bindWallFailureCard(ref, { itemId, dedupKey } = {}) {
  if (typeof ref !== "string" || !REF_RE.test(ref)) return false;
  const record = records.get(ref);
  if (!record) return false;
  if (!Number.isInteger(itemId)) return false;
  if (dedupKey !== CARD_DEDUP_PREFIX + record.id) return false;
  if (record.itemId != null) return record.itemId === itemId;
  const holder = liveItem.get(itemId);
  if (holder && holder !== ref && records.get(holder)?.itemId === itemId) return false;
  record.itemId = itemId;
  record.dedupKey = dedupKey;
  liveItem.set(itemId, ref);
  return true;
}

/** The record `ref` names, or null (a ref that is not one of ours names nothing). */
export function wallFailureByRef(ref) {
  if (typeof ref !== "string" || !REF_RE.test(ref)) return null;
  const record = records.get(ref);
  return record ? recordView(record) : null;
}

/** The live record bound to this Fix-it item id, or null. */
export function wallFailureByItemId(itemId) {
  if (!Number.isInteger(itemId)) return null;
  const ref = liveItem.get(itemId);
  if (!ref) return null;
  const record = records.get(ref);
  if (!record || record.itemId !== itemId) return null;
  return recordView(record);
}

/** Forget `id`'s live record (it connected walled, or the owner answered it). */
export function clearWallFailures(id) {
  const ref = liveRef.get(id);
  if (!ref) return;
  dropRecord(ref);
}

/**
 * `{ ref, reason }` for the add-on's live record, or null when it has none — the
 * pair a caller re-emits to reopen that failure's card. The record's ref never
 * leaves this module except through a read like this one.
 */
export function liveWallFailureFor(id) {
  if (typeof id !== "string" || !id) return null;
  const ref = liveRef.get(id);
  if (!ref) return null;
  const record = records.get(ref);
  if (!record) return null;
  return { ref, reason: record.reason, reasonCode: record.reasonCode };
}

/** Empty every map (tests, and a simulated restart). */
export function _resetWallFailuresForTest() {
  records.clear();
  liveRef.clear();
  liveItem.clear();
}

/** True when the resolved path `p` is `root` itself or under it. */
function isUnder(p, root) {
  const r = resolvePath(root);
  return p === r || p.startsWith(r.endsWith("/") ? r : r + "/");
}

/** True when a path relative to the add-on's folder is plain enough to show. */
function isPlainRelative(rel) {
  if (!PLAIN_RELATIVE_RE.test(rel)) return false;
  if (rel.startsWith("/")) return false;
  return !rel.split("/").includes("..");
}

/**
 * The card line for an open(2) path: the relative path only when it is plain
 * text inside the add-on's own folder, otherwise a fixed phrase. Nothing from
 * the add-on's stderr is ever copied into a card unchecked.
 *
 * Returns the machine-readable `{ code, values }` shape; the sentence is
 * rendered from it (English here, the dashboard's language in the card).
 */
function openFailureCode(resolved, roots) {
  for (const root of roots) {
    const r = resolvePath(root);
    if (!isUnder(resolved, r)) continue;
    const rel = relativePath(r, resolved);
    return isPlainRelative(rel)
      ? { code: "open", values: { rel } }
      : { code: "open-folder", values: {} };
  }
  return { code: "open-outside", values: {} };
}

/**
 * What one child's own evidence says, as `{ code, values }`, first match:
 *  1. the relay's last denial — a target only when it is plain host:port text;
 *  2. the newest stderr line naming an open failure — the path relative to the
 *     add-on's own install or data folder, and only when that relative path is
 *     plain text, so a card never echoes a secret path or foreign markup;
 *  3. the exit code;
 *  4. the not-ready text.
 */
function evidenceCode({ denials, stderrLines, exitCode, installDir, dataDir } = {}) {
  const denied = Array.isArray(denials) ? denials.filter((d) => typeof d === "string" && d) : [];
  const lastDenial = denied.length ? denied[denied.length - 1] : null;
  if (lastDenial) {
    const target = TARGET_RE.test(lastDenial) ? lastDenial : HIDDEN_TARGET;
    return { code: "denied", values: { target } };
  }

  const lines = Array.isArray(stderrLines) ? stderrLines : [];
  const roots = [installDir, dataDir].filter((r) => typeof r === "string" && r);
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    if (typeof line !== "string") continue;
    const match = OPEN_FAILURE_RE.exec(line);
    if (!match) continue;
    return openFailureCode(resolvePath(match[2]), roots);
  }

  if (Number.isInteger(exitCode)) return { code: "exit-code", values: { exitCode } };
  return { code: "not-ready", values: {} };
}

/**
 * The reason a card shows, as a CODE the card renders in the viewer's language.
 * The shape:
 *   - a reason with no value of its own: `{ code, values: {} }`;
 *   - a reason whose sentence names one value (denied → target, open → rel,
 *     exit-code → exitCode): that value sits beside `code`;
 *   - a prepare run with evidence of its own: `{ code: "warmup", values: {
 *     detail } }`, where `detail` is another reason code in either shape.
 * Values are strings or numbers only (the card escapes what it renders).
 */
export function wallFailureReasonCode({ denials, stderrLines, exitCode, installDir, dataDir, refused } = {}) {
  if (refused === "installed-changed") return { code: "installed-changed", values: {} };
  if (refused === "warmup") {
    const detail = evidenceCode({ denials, stderrLines, exitCode, installDir, dataDir });
    return detail.code === "not-ready" ? { code: "warmup", values: {} } : { code: "warmup", values: { detail } };
  }
  if (refused) return { code: "refused", values: {} };
  const evidence = evidenceCode({ denials, stderrLines, exitCode, installDir, dataDir });
  return Object.keys(evidence.values).length ? { code: evidence.code, ...evidence.values } : { code: evidence.code, values: {} };
}

/** One reason code's values, read from `values` and from beside `code`. */
export function wallReasonValues(reasonCode) {
  const source = reasonCode && typeof reasonCode === "object" ? reasonCode : {};
  const values = source.values && typeof source.values === "object" ? source.values : {};
  return { ...source, ...values };
}

/**
 * One reason code as the English sentence (the console and the stored card use
 * it). The wording comes from the SAME i18n keys the card renders, so the two
 * cannot drift; `wallFailureReason(args)` is exactly
 * `renderWallReason(wallFailureReasonCode(args), "en")` in the card.
 */
export function renderWallReasonEnglish(reasonCode) {
  const values = wallReasonValues(reasonCode);
  const code = values.code;
  if (code === "installed-changed") return INSTALLED_CHANGED_REASON;
  if (code === "refused") return REFUSED_REASON;
  if (code === "warmup") {
    if (!values.detail || typeof values.detail !== "object") return WARMUP_REASON;
    return `${WARMUP_REASON}: ${renderWallReasonEnglish(values.detail)}`;
  }
  if (code === "not-ready") return NOT_READY_REASON;
  if (code === "denied") return fill(t(REASON_KEYS.denied, "en"), { target: values.target ?? HIDDEN_TARGET });
  if (code === "open") return fill(t(REASON_KEYS.open, "en"), { rel: values.rel ?? "" });
  if (code === "open-folder") return t(REASON_KEYS.openFolder, "en");
  if (code === "open-outside") return t(REASON_KEYS.openOutside, "en");
  if (code === "exit-code") return fill(t(REASON_KEYS.exitCode, "en"), { exitCode: values.exitCode ?? "" });
  return DEFAULT_REASON;
}

/**
 * The one line a card shows for a failure, first match:
 *  1. the installed copy changed;
 *  2. the prepare run could not fill the add-on's cache, with the same evidence
 *     a stopped child gives, or alone when it left none;
 *  3. the wall could not be built;
 *  4. the evidence itself (see `evidenceCode`).
 *
 * Always the English sentence — the card renders `wallFailureReasonCode(args)`
 * in the viewer's language instead.
 */
export function wallFailureReason(args = {}) {
  return renderWallReasonEnglish(wallFailureReasonCode(args));
}