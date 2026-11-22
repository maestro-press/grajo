/**
 * Capability-id → plain-language label, used by Fix-it cards AND (bonus) the
 * remote-exposure settings panel. Unknown ids fall back to the catalog's human
 * name (an addon's manifest `name`), then the raw id.
 *
 * Fix-it round 2: the label is resolved at VIEW time in the dashboard's
 * language, so the map has an `es` column (the operator-approved R6-R13 names).
 * The third argument is optional: a caller that omits it (the Settings panel)
 * keeps exactly the English it showed before. An add-on's own catalog name and
 * a raw id are never translated — they are the name/word its author chose.
 */
const FRIENDLY_NAMES = {
  "funkwhale": "Music",
  "media": "News & Podcasts",
  "crow-memory": "Memory",
  "crow-blog": "Blog",
  "crow-projects": "Projects",
  "crow-sharing": "Sharing & Messages",
  "crow-storage": "Files",
};

/** The approved Spanish names, keyed like FRIENDLY_NAMES. */
const FRIENDLY_NAMES_ES = Object.freeze({
  "funkwhale": "Música",
  "media": "Noticias y pódcasts",
  "crow-memory": "Memoria",
  "crow-blog": "Blog",
  "crow-projects": "Proyectos",
  "crow-sharing": "Compartir y mensajes",
  "crow-storage": "Archivos",
});

export function resolveFriendlyName(capabilityId, catalogName, lang = "en") {
  // Own properties only: a capability id the map does not hold ("constructor",
  // "__proto__", a tool name) must fall through to its own name/id, never
  // resolve to a member of Object.prototype.
  if (capabilityId && Object.hasOwn(FRIENDLY_NAMES, capabilityId) && Object.hasOwn(FRIENDLY_NAMES_ES, capabilityId)) {
    return lang === "es" ? FRIENDLY_NAMES_ES[capabilityId] : FRIENDLY_NAMES[capabilityId];
  }
  if (catalogName && String(catalogName).trim()) return String(catalogName);
  if (capabilityId) return String(capabilityId);
  return lang === "es" ? "esta función" : "this feature";
}

export { FRIENDLY_NAMES, FRIENDLY_NAMES_ES };