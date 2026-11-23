/**
 * The recipient-facing copy: every word a reader who was not the owner ever sees, in one place.
 *
 * WHY ONE TABLE: a recipient link is opened by somebody who has no Crow account, no dashboard and no
 * settings page, so the page cannot borrow the owner's i18n keys: the language is chosen from the mail
 * client's `Accept-Language` header alone (the link carries no session and no locale) and the wording is
 * fixed, not a translation the owner can change. Keeping the whole table here means a wording change is
 * one edit, and the view builder, the notice page and the comment door all read the same entries rather
 * than drifting apart.
 *
 * WHY `{bot}` STAYS A PLACEHOLDER: a bot's display name is data (the owner names it, a report's own title
 * can change it), so the copy cannot carry it. The caller substitutes it into `bot` and never rewrites
 * the rest of the line.
 *
 * NO EM DASHES: these lines are short, plain sentences a reader can act on. Em dashes are not part of the
 * house voice, and a test pins that for both languages.
 */

/**
 * The recipient copy, keyed by the id every caller uses. EN and ES carry the same keys.
 *
 * WHY THE WORDING IS FIXED AND KEPT VERBATIM: a test pins every line, so the table is a copy of the
 * wording, not a paraphrase of it. Accents, inverted marks, the `{bot}` placeholder, the 4,000 / 4.000
 * number spellings and the ASCII apostrophes are all part of it; `tests/reports-recipient-view.test.js`
 * hard-codes the same 21 strings per language and asserts deep equality, so any drift fails in CI
 * instead of shipping. The ids label each line by its role: expired, unknownLink and unavailable are
 * the three notice pages, chartTooLarge is the note a chart over the ceiling leaves behind,
 * commentsHeading / noComments / addComment / sendComment / sent / closed are the comment chrome,
 * you / sender / bot / anotherReader are the author labels, and errRate / errThreads /
 * errFormExpired / errEmpty / errTooLong / errViewOnly / errOther are the refusals a comment post
 * can answer with.
 */
export const RECIPIENT_COPY = Object.freeze({
  en: Object.freeze({
    expired: "This report link has expired. Ask the sender for a new one.",
    unknownLink: "This link doesn't open a report. Ask the sender for a new one.",
    unavailable: "This report is unavailable right now. Try again in a few minutes.",
    chartTooLarge: "This chart is too large to show here.",
    commentsHeading: "Comments",
    noComments: "No comments yet.",
    addComment: "Add a comment",
    sendComment: "Send comment",
    sent: "Thanks. Your comment was sent.",
    you: "You",
    sender: "The sender",
    bot: "{bot} (AI)",
    anotherReader: "Another reader",
    closed: "Closed",
    errRate: "You've sent a lot of comments recently. Try again later.",
    errThreads: "This report has too many open comments right now. The sender has been told.",
    errFormExpired: "This page was open too long. Reload it and try again.",
    errEmpty: "Write a comment first.",
    errTooLong: "That comment is too long. Keep it under 4,000 characters.",
    errViewOnly: "Comments aren't open on this link.",
    errOther: "Your comment didn't go through. Try again later.",
  }),
  es: Object.freeze({
    expired: "Este enlace del informe ha caducado. Pide uno nuevo a quien te lo envió.",
    unknownLink: "Este enlace no abre ningún informe. Pide uno nuevo a quien te lo envió.",
    unavailable: "Este informe no está disponible ahora. Inténtalo de nuevo en unos minutos.",
    chartTooLarge: "Este gráfico es demasiado grande para mostrarlo aquí.",
    commentsHeading: "Comentarios",
    noComments: "Aún no hay comentarios.",
    addComment: "Añade un comentario",
    sendComment: "Enviar comentario",
    sent: "Gracias. Tu comentario se envió.",
    you: "Tú",
    sender: "Quien lo envió",
    bot: "{bot} (IA)",
    anotherReader: "Otra persona",
    closed: "Cerrado",
    errRate: "Has enviado muchos comentarios hace poco. Inténtalo más tarde.",
    errThreads: "Este informe tiene demasiados comentarios abiertos ahora. Ya se le avisó a quien lo envió.",
    errFormExpired: "Esta página estuvo abierta demasiado tiempo. Vuelve a cargarla e inténtalo de nuevo.",
    errEmpty: "Escribe un comentario primero.",
    errTooLong: "Ese comentario es demasiado largo. Debe tener menos de 4.000 caracteres.",
    errViewOnly: "Este enlace no admite comentarios.",
    errOther: "Tu comentario no se envió. Inténtalo más tarde.",
  }),
});

/** The two languages this table knows, in the order a missing header falls back through. */
const LANGS = Object.freeze(["en", "es"]);

/** The language a header with nothing readable in it gets. */
const DEFAULT_LANG = "en";

/**
 * The `Accept-Language` entries in the order the header wrote them, with their q value.
 *
 * Only the tags a browser actually sends are read: a tag is one to eight letters (optionally followed by
 * `-` and more of them), an optional `;q=` weight is a decimal, and anything else in the header (an
 * empty field, `*`, a bare parameter, a junk token) is skipped rather than shifting the entry after it.
 * The first entry is kept even when it carries no weight, because the rule reads the first tag as much as
 * the strongest one.
 *
 * @param {*} header an Accept-Language header value
 * @returns {{tag: string, q: number}[]}
 */
function languageEntries(header) {
  if (typeof header !== "string") return [];
  const out = [];
  for (const part of header.split(",")) {
    const [rawTag, ...params] = part.split(";");
    const tag = String(rawTag == null ? "" : rawTag).trim().toLowerCase();
    if (!/^[a-z]{1,8}(?:-[a-z0-9]{1,8})*$/.test(tag)) continue;
    let q = 1;
    for (const param of params) {
      const m = /^\s*q\s*=\s*([0-9](?:\.[0-9]{0,5})?)\s*$/i.exec(param);
      if (m) {
        const value = Number(m[1]);
        if (Number.isFinite(value) && value >= 0 && value <= 1) q = value;
      }
    }
    out.push({ tag, q });
  }
  return out;
}

/**
 * The language a recipient page is written in: `es` or `en`.
 *
 * The header's first real tag decides when it is Spanish, because a client that puts Spanish first is
 * telling us that is the language the reader wants even if a later tag outranks it; otherwise the
 * highest-weighted tag decides. Anything unreadable (no header, a proxy that scrubbed it, a tag this
 * product does not speak) is English, never an error: a page always renders.
 *
 * @param {*} acceptLanguage the request's `Accept-Language` header
 * @returns {"en"|"es"}
 */
export function pickLang(acceptLanguage) {
  const entries = languageEntries(acceptLanguage);
  if (!entries.length) return DEFAULT_LANG;
  const first = entries[0];
  if (first && first.tag.startsWith("es") && first.q > 0) return "es";
  let best = null;
  for (const entry of entries) {
    if (entry.q <= 0) continue;
    if (best == null || entry.q > best.q) best = entry;
  }
  if (best && best.tag.startsWith("es")) return "es";
  return DEFAULT_LANG;
}

/**
 * The copy table for a language, English when the language is not one this table carries.
 *
 * @param {*} lang a language tag or whatever a caller holds
 * @returns {typeof RECIPIENT_COPY.en}
 */
export function copyFor(lang) {
  const key = typeof lang === "string" ? lang.trim().toLowerCase() : "";
  if (LANGS.includes(key)) return RECIPIENT_COPY[key];
  // A full tag (`es-MX`) uses the language it names, the same prefix rule `pickLang` applies.
  const base = key.split("-")[0];
  if (LANGS.includes(base)) return RECIPIENT_COPY[base];
  return RECIPIENT_COPY[DEFAULT_LANG];
}