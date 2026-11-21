/**
 * The ONE way a text is read before its links are judged, for the whole report mail path.
 *
 * A URL is not what a reader's mail client sees, it is what the client DRAWS. A browser and a mail client
 * draw the character a character reference stands for (`&#8203;`, `&#x0200B;`, `&#00008203;` and
 * `&ZeroWidthSpace;` all draw one zero-width space), and they draw nothing at all for a character in the
 * Unicode `Default_Ignorable_Code_Point` class or the `Cf` (format) class: the zero-width space and
 * joiners, the word joiner, a byte order mark, a soft hyphen, a variation selector, a tag character, a
 * left-to-right mark, U+180E. A control character is drawn as nothing either. So `ht<U+200B>tps://host` is
 * ONE link to the reader, while a judge that reads the text as written sees no link at all.
 *
 * `normalizeForLinkCheck` answers the text as it is judged: every character reference decoded, the whole
 * invisible class and every control character (except `\n`, `\r` and `\t`, which are whitespace and keep
 * the words around them apart) removed, and `&nbsp;` read as a plain space. This is applied BEFORE any
 * link matching in the html half of a report mail (sanitize-outgoing.js: the html's text nodes and the
 * joined block text), so there is no second, hand-listed set of characters to fall behind the reader's
 * own.
 *
 * THE PLAIN-TEXT HALF IS NOT DECODED. A plain-text client draws no character reference, so
 * `https&#x3A;//host` is the literal text its reader gets and no URL at all. What that half is judged
 * on is `stripInvisible`: the same control and invisible classes removed (again with `\n`, `\r` and `\t`
 * kept) and nothing decoded, so the text it returns is byte for byte the text that is sent.
 *
 * `normalizeView` is the same view together with where each of its characters sits in the text it was
 * given (`at` has one entry per code unit of the view, and each is the half-open `[from, to)` range of the
 * original it came from). A caller that rewrites a run keeps every character outside it exactly as it was
 * written: the invisible characters INSIDE a refused run go with it (they were part of what the reader
 * read), and a text with no URL in it is left byte for byte as it came. The map is the old offset-map
 * technique, widened from one offset to a range because a decoded reference is several characters of the
 * original for one character of the view.
 *
 * Named references are decoded only for the characters they are here to hide: the invisible and format
 * ones the table below names, plus the whitespace references (`&Tab;`, `&NewLine;`) and `&nbsp;`. A named
 * reference whose character is ordinary (`&amp;`) is left as it was written: it draws a character a judge
 * can read, so nothing hides behind it.
 */

/** The character class a reader does not see: the Unicode default-ignorables, and every format character. */
const INVISIBLE = /[\p{Default_Ignorable_Code_Point}\p{Cf}]/u;

/** A control character. */
const CONTROL = /\p{Cc}/u;

/** Anything a text drops before it is judged and sent as plain text: a control character or an invisible
 *  one. `\t`, `\n` and `\r` are kept (see KEPT_CONTROL). */
const UNSEEN = /[\p{Cc}\p{Default_Ignorable_Code_Point}\p{Cf}]/u;

/** The control characters that are whitespace, which a text keeps: a body is lines. */
const KEPT_CONTROL = /[\t\n\r]/;

/** A numerical character reference, any number of leading zeros, both bases, semicolon optional. */
const NUMERIC_REFERENCE = /&#(?:[xX]([0-9a-fA-F]{1,8})|([0-9]{1,10}));?/y;

/** A named character reference; the semicolon-less form is read too (see NAMED_REFERENCES). */
const NAMED_REFERENCE = /&([A-Za-z][A-Za-z0-9]{0,31})(;?)/y;

/**
 * The named references that write a character the reader does not see (or a space): the invisible and
 * format characters above, and the whitespace ones a text keeps. Lower-cased, because the lookup is.
 */
const NAMED_REFERENCES = Object.freeze({
  zerowidthspace: 0x200b,
  zwnj: 0x200c,
  zwj: 0x200d,
  lrm: 0x200e,
  rlm: 0x200f,
  shy: 0x00ad,
  nobreak: 0x2060,
  applyfunction: 0x2061,
  af: 0x2061,
  invisibletimes: 0x2062,
  it: 0x2062,
  invisiblecomma: 0x2063,
  ic: 0x2063,
  nbsp: 0x00a0,
  tab: 0x0009,
  newline: 0x000a,
});

/**
 * What a code point is in the view: the character itself (or a plain space for a no-break space), "" for
 * one the reader does not see, or null when the reference is to be left as it was written (an invalid
 * code point: a surrogate, past the last plane).
 */
function replacementOf(codePoint) {
  if (!Number.isInteger(codePoint) || codePoint < 0 || codePoint > 0x10ffff) return null;
  if (codePoint >= 0xd800 && codePoint <= 0xdfff) return null;
  if (codePoint === 0x00a0) return " ";
  const character = String.fromCodePoint(codePoint);
  if (KEPT_CONTROL.test(character)) return character;
  if (CONTROL.test(character) || INVISIBLE.test(character)) return "";
  return character;
}

/** A numerical reference at `index`, as `{ end, replacement }`, or null when there is none to decode. */
function numericAt(source, index) {
  NUMERIC_REFERENCE.lastIndex = index;
  const match = NUMERIC_REFERENCE.exec(source);
  if (!match) return null;
  const codePoint = match[1] != null
    ? Number.parseInt(match[1], 16)
    : Number.parseInt(match[2], 10);
  const replacement = replacementOf(codePoint);
  if (replacement === null) return null;
  return { end: NUMERIC_REFERENCE.lastIndex, replacement };
}

/** A named reference at `index`, read only when NAMED_REFERENCES names it. */
function namedAt(source, index) {
  NAMED_REFERENCE.lastIndex = index;
  const match = NAMED_REFERENCE.exec(source);
  if (!match) return null;
  const name = match[1].toLowerCase();
  if (!Object.hasOwn(NAMED_REFERENCES, name)) return null;
  const end = NAMED_REFERENCE.lastIndex;
  // A semicolon-less reference in an attribute-like form (`&shy=`) is not one: fail safe by leaving it.
  if (!match[2] && source[end] === "=") return null;
  const replacement = replacementOf(NAMED_REFERENCES[name]);
  if (replacement === null) return null;
  return { end, replacement };
}

/**
 * One text as it is judged, with where each character of that view was written.
 *
 * @param {*} value the text as it was written
 * @returns {{text: string, at: Array<{from: number, to: number}>}} the view, and for each code unit of
 *   it the half-open range of the original that unit came from
 */
export function normalizeView(value) {
  const source = typeof value === "string" ? value : "";
  let text = "";
  const at = [];
  /** One entry per CODE UNIT of the view, so a view offset is always an index into `at`. */
  const remember = (from, to, width) => {
    const range = { from, to };
    for (let unit = 0; unit < width; unit += 1) at.push(range);
  };
  let index = 0;
  while (index < source.length) {
    if (source[index] === "&") {
      const reference = numericAt(source, index) ?? namedAt(source, index);
      if (reference !== null) {
        if (reference.replacement !== "") {
          text += reference.replacement;
          remember(index, reference.end, reference.replacement.length);
        }
        index = reference.end;
        continue;
      }
    }
    const width = source.codePointAt(index) > 0xffff ? 2 : 1;
    const character = source.slice(index, index + width);
    if (KEPT_CONTROL.test(character) || (!CONTROL.test(character) && !INVISIBLE.test(character))) {
      text += character;
      remember(index, index + width, width);
    }
    index += width;
  }
  return { text, at };
}

/**
 * The text as it is judged: character references decoded, the invisible and format classes and every
 * control character removed (`\n`, `\r` and `\t` kept), `&nbsp;` read as a plain space.
 *
 * @param {*} value the text as it was written
 * @returns {string} the text a reader's mail client draws, which is what its autolink rule reads
 */
export function normalizeForLinkCheck(value) {
  return normalizeView(value).text;
}

/**
 * The plain-text half of a mail as it is judged and as it is sent: every control character (with `\n`,
 * `\r` and `\t` kept) and every character of the default-ignorable and format class removed, and NOTHING
 * decoded. A plain-text client does not draw a character reference, so a reference in a body is the
 * literal text its reader gets; only the characters nobody sees are dropped, and what this answers is
 * byte for byte the text that goes out.
 *
 * @param {*} value the text as it will be sent
 * @returns {string} the same text with nothing in it a plain-text reader cannot see
 */
export function stripInvisible(value) {
  const source = typeof value === "string" ? value : "";
  if (!source) return "";
  let text = "";
  for (const character of source) {
    if (KEPT_CONTROL.test(character)) text += character;
    else if (!UNSEEN.test(character)) text += character;
  }
  return text;
}