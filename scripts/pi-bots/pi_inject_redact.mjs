/**
 * The spellings a credential can come back as, and a sliding-window replacer
 * that finds them across chunk boundaries.
 *
 * A credentialed upstream may echo the credential it was given, deliberately or
 * because an error page quotes the request. The custom step that reads the
 * answer must never see it, so every spelling a server could plausibly produce
 * is a needle here: the bytes as they were sent, URL-encoded, base64 at every
 * byte alignment (inside a bigger blob, in both alphabetical variants, with and
 * without padding), JSON-escaped, as HTML numeric entities, and as hex.
 *
 * Needles are Buffers and matched byte-exactly, so a multi-byte secret is
 * matched as the bytes that were sent and a replacement never re-encodes the
 * stream around it.
 */

/** What a match is replaced with. Fixed, so nothing about the secret survives. */
export const REDACTED = "[redacted]";

/**
 * The taint window a spelling is judged with. Eight consecutive bytes of a random
 * text form is no coincidence, but a HEX form draws on sixteen symbols only, so a
 * short run of it says much less: the hex spellings are judged at 16 bytes instead.
 */
export const TAINT_WINDOW = 8;
export const HEX_TAINT_WINDOW = 16;

const RED_BYTES = Buffer.from(REDACTED, "utf8");

const isBuffer = (v) => Buffer.isBuffer(v);

const b64 = (buf) => buf.toString("base64");
const b64url = (buf) => buf.toString("base64").replace(/\+/g, "-").replace(/\//g, "_");

/**
 * Base64 needles for `secret` at every byte alignment.
 *
 * The secret may sit at any offset inside the text it was encoded with, so its
 * first base64 character can land at any of the three positions of a
 * 4-character group; and the last group the secret touches may be completed by
 * bytes that FOLLOW it, which make that group's trailing characters unknowable.
 * So for each alignment k in 0..2: encode k placeholder bytes plus the secret,
 * drop the leading characters the unknown prefix decided (ceil(k*8/6) of them:
 * no more than those can depend on it) and drop everything from the first
 * character after the last COMPLETE group of three bytes, then keep the rest.
 * What is left is a contiguous run of characters that depends only on the
 * secret's own bytes, so it is a substring of the base64 of any surrounding
 * text, whatever the prefix, the suffix or the padding.
 */
function base64Needles(secret) {
  const out = [];
  const len = secret.length;
  // The whole secret as one base64 value: a body or header that carries the
  // encoding by itself, padded and with the padding stripped.
  for (const enc of [b64, b64url]) {
    const whole = enc(secret);
    if (whole.length >= 4) out.push(Buffer.from(whole, "latin1"));
    const bare = whole.replace(/=+$/, "");
    if (bare !== whole && bare.length >= 4) out.push(Buffer.from(bare, "latin1"));
  }
  for (let k = 0; k < 3; k++) {
    const groups = Math.floor((k + len) / 3);
    if (groups < 1) continue;
    const head = Math.ceil((k * 8) / 6);
    const end = groups * 4;
    if (end - head < 4) continue;
    const bytes = Buffer.concat([Buffer.alloc(k), secret]);
    for (const enc of [b64, b64url]) {
      const text = enc(bytes);
      const needle = Buffer.from(text.slice(head, end), "latin1");
      if (needle.length >= 4) out.push(needle);
    }
  }
  return out;
}

/** A percent spelling of a string; a lone surrogate is simply left alone. */
const tryEncode = (fn, s) => {
  try { return fn(s); } catch { return null; }
};

/**
 * Every needle for one secret as `{needle, wide}`, where `wide` marks a spelling that
 * draws on a small alphabet (hex) and so needs the wider taint window. Takes a string
 * (a Buffer would be the bytes that were already sent, which is the raw form).
 * @returns {Array<{needle: Buffer, wide: boolean}>}
 */
export function secretFormEntries(secret) {
  const s = isBuffer(secret) ? secret.toString("utf8") : typeof secret === "string" ? secret : String(secret ?? "");
  if (!s) return [];
  const bytes = isBuffer(secret) ? secret : Buffer.from(s, "utf8");
  const out = [{ needle: bytes, wide: false }];
  const add = (text, wide = false) => {
    if (typeof text !== "string" || !text || text === s) return;
    out.push({ needle: Buffer.from(text, "utf8"), wide });
  };
  // URL encodings: the uppercase one every JS library produces, the looser one
  // that leaves separators alone, and the lowercase-hex spelling some encoders write.
  const component = tryEncode(encodeURIComponent, s);
  if (component !== null) {
    add(component);
    if (component !== s) add(component.replace(/%[0-9A-F]{2}/g, (m) => m.toLowerCase()));
  }
  add(tryEncode(encodeURI, s));
  // JSON escaping, without the quotes: an upstream that quotes the request in a
  // JSON error body escapes backslashes, quotes and control characters.
  try { add(JSON.stringify(s).slice(1, -1)); } catch { /* a lone surrogate cannot be stringified */ }
  // HTML numeric entities, one per character, decimal and hex in the spellings
  // a templating library emits.
  const cps = [...s].map((ch) => ch.codePointAt(0));
  if (cps.length) {
    add(cps.map((c) => `&#${c};`).join(""));
    add(cps.map((c) => `&#x${c.toString(16)};`).join(""));
    add(cps.map((c) => `&#x${c.toString(16).toUpperCase()};`).join(""));
    add(cps.map((c) => `&#X${c.toString(16)};`).join(""));
  }
  // Hex of the bytes, both cases: a sixteen-symbol alphabet, so judged wide.
  add(bytes.toString("hex"), true);
  add(bytes.toString("hex").toUpperCase(), true);
  for (const n of base64Needles(bytes)) out.push({ needle: n, wide: false });
  const seen = new Map();
  const unique = [];
  for (const entry of out) {
    const key = entry.needle.toString("hex");
    const prior = seen.get(key);
    if (prior) { prior.wide = prior.wide && entry.wide; continue; }
    const kept = { needle: entry.needle, wide: entry.wide };
    seen.set(key, kept);
    unique.push(kept);
  }
  return unique.sort((a, b) => b.needle.length - a.needle.length);
}

/** Every needle for one secret, unique, longest first. */
export function secretForms(secret) {
  return secretFormEntries(secret).map((entry) => entry.needle);
}

/** Every needle for every secret, unique, longest first, with the window it is judged at. */
function allEntries(secrets) {
  const list = Array.isArray(secrets) ? secrets : [secrets];
  const seen = new Map();
  const out = [];
  for (const s of list) {
    for (const entry of secretFormEntries(s)) {
      const key = entry.needle.toString("hex");
      const prior = seen.get(key);
      if (prior) { prior.wide = prior.wide && entry.wide; continue; }
      const kept = { needle: entry.needle, wide: entry.wide };
      seen.set(key, kept);
      out.push(kept);
    }
  }
  return out.sort((a, b) => b.needle.length - a.needle.length);
}

/** Every needle for every secret, unique, longest first. */
function allNeedles(secrets) {
  return allEntries(secrets).map((entry) => entry.needle);
}

/**
 * A replacer over a stream: `push(chunk)` returns the bytes that are safe to
 * hand on, `end()` returns the rest.
 *
 * The last (longest needle - 1) bytes are held back until the next chunk (or
 * `end()`), because a needle that starts inside them could still be completed
 * by bytes that have not arrived; every position that is decided has at least
 * one needle's worth of bytes behind it. That makes the result independent of
 * how the same input was chunked. At a position where several needles match,
 * the longest wins, so a secret that contains another is replaced whole.
 */
export function createStreamRedactor(secrets) {
  const needles = allNeedles(secrets);
  if (!needles.length) {
    return {
      push: (chunk) => (isBuffer(chunk) ? chunk : Buffer.from(chunk ?? "", "utf8")),
      end: () => Buffer.alloc(0),
    };
  }
  const maxLen = needles[0].length;
  // Which needles start with which byte (each list stays longest first), plus a
  // byte table so a position no needle can start at costs one lookup.
  const byFirst = new Map();
  const starts = new Uint8Array(256);
  for (const n of needles) {
    starts[n[0]] = 1;
    const bucket = byFirst.get(n[0]);
    if (bucket) bucket.push(n); else byFirst.set(n[0], [n]);
  }
  const matchAt = (buf, i) => {
    if (!starts[buf[i]]) return null;
    const bucket = byFirst.get(buf[i]);
    if (!bucket) return null;
    for (const n of bucket) {
      if (i + n.length > buf.length) continue;
      if (buf.compare(n, 0, n.length, i, i + n.length) === 0) return n;
    }
    return null;
  };
  let pending = Buffer.alloc(0);
  const scrub = (final) => {
    const parts = [];
    const stop = final ? pending.length : pending.length - (maxLen - 1);
    let i = 0;
    let runStart = 0;
    while (i < stop) {
      const needle = matchAt(pending, i);
      if (needle) {
        if (i > runStart) parts.push(pending.subarray(runStart, i));
        parts.push(RED_BYTES);
        i += needle.length;
        runStart = i;
        continue;
      }
      i++;
    }
    if (final) {
      parts.push(pending.subarray(runStart));
      pending = Buffer.alloc(0);
    } else if (runStart < stop) {
      parts.push(pending.subarray(runStart, stop));
      pending = pending.subarray(stop);
    } else {
      pending = pending.subarray(runStart);
    }
    return Buffer.concat(parts);
  };
  return {
    push(chunk) {
      const buf = isBuffer(chunk) ? chunk : Buffer.from(chunk ?? "", "utf8");
      if (!buf.length) return Buffer.alloc(0);
      pending = pending.length ? Buffer.concat([pending, buf]) : buf;
      return scrub(false);
    },
    end: () => scrub(true),
  };
}

/**
 * A detector for a PARTIAL echo: any `window` consecutive bytes of any spelling
 * of a credential.
 *
 * The redactor above removes a spelling only when the whole needle arrived. A
 * server that quotes a credential, or an error page that truncates one, hands
 * back a run of bytes that is too short to be a needle and still enough to be
 * the credential. Every `window`-byte substring (byte-exact, latin1) of every
 * form of every secret is the needle set here: a run of that many bytes of the
 * credential is not a coincidence.
 *
 * `scan(chunk)` carries the last `holdback` bytes across chunks, so the same bytes
 * are found however the stream was split. A hit is sticky: once a stream is tainted
 * every later scan says so. Windows are looked up by their first two bytes first, so
 * a stream that holds none of them costs two table reads a byte (a 16 MB body is
 * scanned in well under a second). A hex spelling is judged at a wider window than
 * the other forms (HEX_TAINT_WINDOW): sixteen symbols make a short run a coincidence.
 *
 * @param {Array<string|Buffer>|string|Buffer} secrets
 * @param {{window?: number}} [opts]
 * @returns {{window: number, holdback: number, windows: number, scan: (chunk: any) => boolean,
 *   reset: () => void}}
 */
export function createTaintDetector(secrets, opts = {}) {
  const width = Number(opts.window === undefined ? TAINT_WINDOW : opts.window);
  if (!Number.isInteger(width) || width < 1 || width > 64) throw new Error("a taint window is 1 to 64 bytes");
  const groups = new Map();
  const groupFor = (w) => {
    let g = groups.get(w);
    if (!g) {
      g = { width: w, windows: new Set(), starts: new Uint8Array(256), pairs: w > 1 ? new Uint8Array(65536) : null };
      groups.set(w, g);
    }
    return g;
  };
  for (const entry of allEntries(secrets)) {
    const w = entry.wide ? Math.max(width, HEX_TAINT_WINDOW) : width;
    if (entry.needle.length < w) continue;
    const g = groupFor(w);
    for (let i = 0; i + w <= entry.needle.length; i++) {
      const one = entry.needle.subarray(i, i + w).toString("latin1");
      if (g.windows.has(one)) continue;
      g.windows.add(one);
      g.starts[entry.needle[i]] = 1;
      if (g.pairs) g.pairs[(entry.needle[i] << 8) | entry.needle[i + 1]] = 1;
    }
  }
  const list = [...groups.values()];
  const total = list.reduce((n, g) => n + g.windows.size, 0);
  const maxWidth = list.reduce((n, g) => Math.max(n, g.width), width);
  const keep = maxWidth - 1;
  let carry = Buffer.alloc(0);
  let hot = false;
  return {
    window: width,
    holdback: keep,
    windows: total,
    scan(chunk) {
      if (hot) return true;
      if (!total) return false;
      const buf = isBuffer(chunk) ? chunk : Buffer.from(chunk ?? "", "utf8");
      const all = carry.length ? Buffer.concat([carry, buf]) : buf;
      for (const g of list) {
        const w = g.width;
        for (let i = 0, last = all.length - w; i <= last; i++) {
          const b = all[i];
          if (!g.starts[b]) continue;
          if (g.pairs && !g.pairs[(b << 8) | all[i + 1]]) continue;
          if (g.windows.has(all.subarray(i, i + w).toString("latin1"))) {
            hot = true;
            carry = Buffer.alloc(0);
            return true;
          }
        }
      }
      carry = Buffer.from(keep && all.length > keep ? all.subarray(all.length - keep) : all);
      return false;
    },
    reset() { carry = Buffer.alloc(0); hot = false; },
  };
}

/**
 * A copy of a node header bag with every value redacted (arrays element by
 * element). The names are left exactly as they are: they are not secret, and a
 * response that arrives with a renamed header would be a different response.
 */
export function redactHeaderValues(headers, secrets) {
  const out = {};
  const redactor = createStreamRedactor(secrets);
  const one = (value) => {
    if (typeof value !== "string") return value;
    return Buffer.concat([redactor.push(Buffer.from(value, "utf8")), redactor.end()]).toString("utf8");
  };
  for (const [k, v] of Object.entries(headers || {})) out[k] = Array.isArray(v) ? v.map(one) : one(v);
  return out;
}