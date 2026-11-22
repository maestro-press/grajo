/**
 * The browser add-on's stale-image card copy, in both languages.
 *
 * Copy approved by the operator 2026-11-19, plus the two version sentences
 * approved 2026-11-21. It lives in its own module so the view-time renderer
 * (fix-it/card-copy.js) can read it without importing the detector that writes
 * the card — the detector re-exports it under the same name, so every existing
 * reader of `COPY` keeps working.
 *
 * "Not now" is not here on purpose: it is the ONE dismissal button every Fix-it
 * card already renders (fix-it/index.js → store.dismiss, a 7-day snooze,
 * nothing changed), not a per-card string.
 */
export const COPY = Object.freeze({
  title: {
    en: "The browser add-on is still running the old version",
    es: "El complemento del navegador sigue ejecutando la versión anterior",
  },
  body: {
    en: "Crow updated the browser add-on, but the copy that is running is still the old one. "
      + "Restart it to load the update. A restart cannot be undone, and the pages that are open in the browser now will close. "
      + "Saved logins and cookies are kept.",
    es: "Crow actualizó el complemento del navegador, pero la copia que está en marcha sigue siendo la anterior. "
      + "Reinícialo para cargar la actualización. Un reinicio no se puede deshacer, y las páginas que están abiertas ahora en el navegador se cerrarán. "
      + "Los inicios de sesión y las cookies guardados se conservan.",
  },
  restartAction: {
    en: "Restart the browser add-on",
    es: "Reiniciar el complemento del navegador",
  },
  openExtensions: {
    en: "Open Extensions",
    es: "Abrir Extensiones",
  },
  // ONE extra sentence naming the version that is RUNNING and the one the update
  // would install. `{running}` and `{new}` are filled from the card's values
  // (fix-it/card-copy.js) — a placeholder is never shown.
  versionKnown: {
    en: "Running now: version {running}. The update would install version {new}.",
    es: "En marcha ahora: versión {running}. La actualización instalaría la versión {new}.",
  },
  versionUnknown: {
    en: "Running now: an earlier version that does not report its number. The update would install version {new}.",
    es: "En marcha ahora: una versión anterior que no indica su número. La actualización instalaría la versión {new}.",
  },
});