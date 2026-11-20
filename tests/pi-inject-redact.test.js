// The credential spellings the reports egress relay redacts, and the sliding
// window that keeps a split credential from slipping through: needle forms,
// base64 alignment under arbitrary surrounding bytes, chunk invariance.
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { secretForms, createStreamRedactor, createTaintDetector, redactHeaderValues, REDACTED } from "../scripts/pi-bots/pi_inject_redact.mjs";

const SECRET = "rpt_7Qp2erT4uvWx9YzAkL";
const asText = (buf) => buf.toString("utf8");
const forms = (secret) => secretForms(secret).map(asText);

/** Every needle as a latin1 string, so a substring check is a byte check. */
function has(needles, text) {
  return needles.some((n) => text.includes(n));
}

test("secretForms: needles are Buffers, unique, longest first", () => {
  const needles = secretForms(SECRET);
  assert.ok(needles.length >= 8, "every form is listed: " + needles.length);
  for (const n of needles) assert.ok(Buffer.isBuffer(n), "a needle is bytes, not a string");
  const keys = needles.map((n) => n.toString("hex"));
  assert.equal(new Set(keys).size, keys.length, "no duplicate needle");
  for (let i = 1; i < needles.length; i++) assert.ok(needles[i - 1].length >= needles[i].length, "longest first");
  assert.deepEqual(secretForms(""), [], "no secret, no needle");
});

test("secretForms: the raw, URL, JSON, entity, hex and base64 spellings are all present", () => {
  const needles = forms(SECRET);
  const want = {
    raw: SECRET,
    "encodeURIComponent": encodeURIComponent(SECRET),
    "encodeURI": encodeURI(SECRET),
    "JSON escaped": JSON.stringify(SECRET).slice(1, -1),
    "html decimal": [...SECRET].map((c) => `&#${c.codePointAt(0)};`).join(""),
    "html hex": [...SECRET].map((c) => `&#x${c.codePointAt(0).toString(16)};`).join(""),
    "utf8 hex lower": Buffer.from(SECRET).toString("hex"),
    "utf8 hex upper": Buffer.from(SECRET).toString("hex").toUpperCase(),
    "base64 padded": Buffer.from(SECRET).toString("base64"),
    "base64 unpadded": Buffer.from(SECRET).toString("base64").replace(/=+$/, ""),
    "base64url padded": Buffer.from(SECRET).toString("base64url"),
  };
  for (const [label, text] of Object.entries(want)) assert.ok(needles.includes(text), label + " is a needle");
});

test("secretForms: a secret with characters that need escaping keeps every spelling", () => {
  const tricky = 'pa"ss\\wo rd+&=/%<>é';
  const needles = forms(tricky);
  assert.ok(needles.includes(tricky), "raw");
  assert.ok(needles.includes(encodeURIComponent(tricky)), "percent-encoded");
  assert.ok(needles.includes(JSON.stringify(tricky).slice(1, -1)), "JSON escaped");
  assert.ok(needles.includes(Buffer.from(tricky).toString("hex")), "hex");
});

test("base64: a needle appears in the encoding of the secret under random prefixes and suffixes", () => {
  const needles = forms(SECRET);
  const bytes = Buffer.from(SECRET);
  for (let self = 0; self < 3; self++) {
    for (let trial = 0; trial < 200; trial++) {
      const prefix = randomBytes(self + Math.floor(Math.random() * 12));
      const suffix = randomBytes(Math.floor(Math.random() * 12));
      const text = Buffer.concat([prefix, bytes, suffix]).toString("base64");
      const urlSafe = text.replace(/\+/g, "-").replace(/\//g, "_");
      assert.ok(has(needles, text), `standard base64, alignment ${self}, trial ${trial}`);
      assert.ok(has(needles, urlSafe), `url-safe base64, alignment ${self}, trial ${trial}`);
      assert.ok(has(needles, text.replace(/=+$/, "")), `unpadded standard base64, alignment ${self}, trial ${trial}`);
    }
  }
});

test("base64: the standalone value is redacted in both alphabets, padded and unpadded", () => {
  const std = Buffer.from(SECRET).toString("base64");
  for (const text of [std, std.replace(/=+$/, ""), std.replace(/\+/g, "-").replace(/\//g, "_")]) {
    const r = createStreamRedactor([SECRET]);
    const out = Buffer.concat([r.push(Buffer.from(`before ${text} after`)), r.end()]).toString();
    assert.equal(out, `before ${REDACTED} after`, text);
  }
});

test("the redactor replaces each spelling when it is the whole body", () => {
  const b64 = Buffer.from(SECRET).toString("base64");
  const spellings = {
    raw: SECRET,
    "percent-encoded": encodeURIComponent(SECRET),
    "json escaped": JSON.stringify(SECRET).slice(1, -1),
    "html entities": [...SECRET].map((c) => `&#${c.codePointAt(0)};`).join(""),
    "html hex entities": [...SECRET].map((c) => `&#x${c.codePointAt(0).toString(16)};`).join(""),
    hex: Buffer.from(SECRET).toString("hex"),
    "base64 whole": b64,
  };
  for (const [label, text] of Object.entries(spellings)) {
    const r = createStreamRedactor([SECRET]);
    const out = Buffer.concat([r.push(Buffer.from(text)), r.end()]).toString();
    assert.equal(out, REDACTED, label);
  }
  // All of them in one body: none survives.
  const body = Object.values(spellings).join("\n");
  const r = createStreamRedactor([SECRET]);
  const out = Buffer.concat([r.push(Buffer.from(body)), r.end()]).toString();
  for (const n of forms(SECRET)) assert.equal(out.includes(n), false, "no spelling survives");
  assert.equal(out, Object.keys(spellings).map(() => REDACTED).join("\n"));
});

test("a credential encoded inside a larger base64 blob loses the characters that belong to it", () => {
  const blob = Buffer.concat([Buffer.from("header-"), Buffer.from(SECRET), Buffer.from("-footer")]);
  const encoded = blob.toString("base64");
  const r = createStreamRedactor([SECRET]);
  const out = Buffer.concat([r.push(Buffer.from(encoded)), r.end()]).toString();
  assert.ok(out.includes(REDACTED), "the body of the encoding is replaced: " + out);
  assert.ok(out.length < encoded.length, "characters that belong to the credential are gone");
  // The same blob split across chunks gives the same answer.
  for (let cut = 0; cut <= encoded.length; cut++) {
    const rr = createStreamRedactor([SECRET]);
    const got = Buffer.concat([rr.push(Buffer.from(encoded.slice(0, cut))), rr.push(Buffer.from(encoded.slice(cut))), rr.end()]).toString();
    assert.equal(got, out, "split at " + cut);
  }
});

test("chunk invariance: the same body split at every offset gives the same output", () => {
  const body = Buffer.from(
    `head ${SECRET} mid ${Buffer.from(SECRET).toString("base64")} tail ${encodeURIComponent(SECRET)} end`,
  );
  const whole = (() => { const r = createStreamRedactor([SECRET]); return Buffer.concat([r.push(body), r.end()]).toString(); })();
  assert.ok(whole.includes(REDACTED));
  for (let cut = 0; cut <= body.length; cut++) {
    const r = createStreamRedactor([SECRET]);
    const out = Buffer.concat([r.push(body.subarray(0, cut)), r.push(body.subarray(cut)), r.end()]).toString();
    assert.equal(out, whole, "split at byte " + cut);
  }
  for (let trial = 0; trial < 200; trial++) {
    const r = createStreamRedactor([SECRET]);
    const parts = [];
    for (let at = 0; at < body.length;) {
      const take = 1 + Math.floor(Math.random() * 9);
      parts.push(r.push(body.subarray(at, at + take)));
      at += take;
    }
    parts.push(r.end());
    assert.equal(Buffer.concat(parts).toString(), whole, "random chunking, trial " + trial);
  }
});

test("chunk invariance: one byte at a time never lets a spelling through", () => {
  const body = Buffer.from(`A${SECRET}B${Buffer.from(SECRET).toString("base64")}C`);
  const r = createStreamRedactor([SECRET]);
  const parts = [];
  for (let i = 0; i < body.length; i++) parts.push(r.push(body.subarray(i, i + 1)));
  parts.push(r.end());
  const out = Buffer.concat(parts).toString();
  assert.equal(out, `A${REDACTED}B${REDACTED}C`);
});

test("longest first: a secret that contains another is replaced whole", () => {
  const short = "abcdefgh";
  const long = "abcdefghij";
  const r = createStreamRedactor([short, long]);
  const out = Buffer.concat([r.push(Buffer.from("x" + long + "y")), r.end()]).toString();
  assert.equal(out, `x${REDACTED}y`, "the longer needle wins, not two replacements");
});

test("several secrets: each one is redacted, and an injected header value counts as one", () => {
  const other = "second-secret-value-here";
  const injected = "Bearer " + SECRET;
  const r = createStreamRedactor([SECRET, injected]);
  const out = Buffer.concat([r.push(Buffer.from(`a ${injected} b ${other} c`)), r.end()]).toString();
  assert.equal(out, `a ${REDACTED} b ${other} c`, "the formatted value is redacted as one");
});

test("text without the secret is passed byte-identical, including a non-UTF-8 byte", () => {
  const body = Buffer.concat([Buffer.from("plain text, no credential here"), Buffer.from([0xff, 0x00, 0xfe])]);
  const r = createStreamRedactor([SECRET]);
  const out = Buffer.concat([r.push(body), r.end()]);
  assert.deepEqual([...out], [...body]);
  // And through every possible split, the bytes come back unchanged.
  for (let cut = 0; cut <= body.length; cut++) {
    const rr = createStreamRedactor([SECRET]);
    const got = Buffer.concat([rr.push(body.subarray(0, cut)), rr.push(body.subarray(cut)), rr.end()]);
    assert.deepEqual([...got], [...body], "split at " + cut);
  }
});

test("no secret at all: the stream is untouched", () => {
  const r = createStreamRedactor([]);
  assert.deepEqual([...Buffer.concat([r.push(Buffer.from("abc")), r.end()])], [...Buffer.from("abc")]);
});

test("redactHeaderValues: values and arrays are redacted, names are left exactly as they are", () => {
  const secret = SECRET;
  const headers = {
    location: `https://other.example.com/next?token=${secret}`, "set-cookie": [`a=1; token=${secret}`, "b=2"],
    "www-authenticate": `Bearer realm="x", error="${encodeURIComponent(secret)}"`, link: `<https://x.example.com/>`,
    "content-type": "text/plain",
  };
  const out = redactHeaderValues(headers, [secret]);
  assert.deepEqual(Object.keys(out), Object.keys(headers), "header names unchanged");
  assert.equal(out.location, `https://other.example.com/next?token=${REDACTED}`);
  assert.deepEqual(out["set-cookie"], [`a=1; token=${REDACTED}`, "b=2"]);
  assert.equal(out.link, "<https://x.example.com/>", "an unrelated value is byte-identical");
  assert.equal(out["content-type"], "text/plain");
  for (const [k, v] of Object.entries(out)) {
    for (const one of Array.isArray(v) ? v : [v]) assert.equal(String(one).includes(secret), false, k);
  }
});

test("redactHeaderValues: an empty header bag or no secrets changes nothing", () => {
  assert.deepEqual(redactHeaderValues({}, [SECRET]), {});
  assert.deepEqual(redactHeaderValues({ a: "plain" }, []), { a: "plain" });
});

test("createTaintDetector: a window of any spelling is found, whole or split across chunks", () => {
  const b64 = Buffer.from(SECRET).toString("base64");
  const hex = Buffer.from(SECRET).toString("hex");
  // A hex spelling is judged at 16 bytes (sixteen symbols), the other forms at 8.
  const cases = [
    { form: SECRET, from: 4, to: 16 },
    { form: b64, from: 4, to: 16 },
    { form: encodeURIComponent(SECRET), from: 4, to: 16 },
    { form: hex, from: 4, to: 20 },
    { form: JSON.stringify(SECRET).slice(1, -1), from: 4, to: 16 },
  ];
  for (const { form, from, to } of cases) {
    const piece = form.slice(from, to);
    assert.equal(piece.length, to - from, form);
    // One chunk, and every split of the same bytes.
    assert.equal(createTaintDetector([SECRET]).scan(Buffer.from(piece)), true, "one chunk: " + form);
    for (let cut = 0; cut <= piece.length; cut++) {
      const d = createTaintDetector([SECRET]);
      const seen = d.scan(Buffer.from(piece.slice(0, cut))) || d.scan(Buffer.from(piece.slice(cut)));
      assert.equal(seen, true, "split at " + cut + " of " + form);
    }
  }
  // A detector built from a different secret does not know this one.
  assert.equal(createTaintDetector(["another-secret-value"]).scan(Buffer.from(SECRET.slice(4, 16))), false);
});

test("createTaintDetector: a hex run is judged at 16 bytes, every other form at 8", () => {
  const hex = Buffer.from(SECRET).toString("hex");
  const detector = createTaintDetector([SECRET]);
  assert.equal(detector.window, 8, "the base window is 8");
  assert.equal(detector.holdback, 15, "the widest window decides how much is held back");
  for (const n of [8, 12, 15]) {
    assert.equal(createTaintDetector([SECRET]).scan(Buffer.from(hex.slice(4, 4 + n))), false,
      n + " hex characters are not a window");
  }
  assert.equal(createTaintDetector([SECRET]).scan(Buffer.from(hex.slice(4, 20))), true, "16 hex characters are");
  // The raw form still trips at 8.
  assert.equal(createTaintDetector([SECRET]).scan(Buffer.from(SECRET.slice(4, 12))), true);
  assert.equal(createTaintDetector([SECRET]).scan(Buffer.from(SECRET.slice(4, 11))), false, "seven bytes is not a window");
});

test("createTaintDetector: fewer bytes than the window never trip it, and a hit is sticky", () => {
  const d = createTaintDetector([SECRET], { window: 8 });
  assert.equal(d.window, 8);
  assert.equal(d.scan(Buffer.from(SECRET.slice(0, 7))), false, "seven bytes is not a window");
  assert.equal(d.scan(Buffer.from(SECRET.slice(7, 14))), true, "the window completed across the two chunks");
  assert.equal(d.scan(Buffer.from("plain text after the hit")), true, "a hit is sticky");
  d.reset();
  assert.equal(d.scan(Buffer.from("plain text")), false, "reset forgets the carry and the hit");
  assert.equal(createTaintDetector([]).windows, 0);
  assert.equal(createTaintDetector([]).scan(Buffer.from(SECRET)), false, "no secret, nothing to find");
});

test("createTaintDetector: the redactor's own output is clean (an exact echo is redacted, not tainted)", () => {
  // The response path redacts first and scans what would be forwarded: an exact
  // echo is replaced before the detector sees it, so the step gets a redacted
  // body rather than a cut connection, and a partial echo is still caught.
  const redactor = createStreamRedactor([SECRET]);
  const out = Buffer.concat([redactor.push(Buffer.from(`A${SECRET}B`)), redactor.end()]);
  assert.equal(out.toString(), `A${REDACTED}B`);
  assert.equal(createTaintDetector([SECRET]).scan(out), false, "the redacted output holds no window");
  const partial = Buffer.from(`A${SECRET.slice(4, 16)}B`);
  assert.equal(createTaintDetector([SECRET]).scan(partial), true, "a partial echo is caught");
});

test("createTaintDetector: a 16 MB benign body scans inside its budget", () => {
  const pattern = Buffer.from("the quick brown fox jumps over the lazy dog. rpt_0123456789 ");
  const block = Buffer.alloc(256 * 1024);
  for (let i = 0; i < block.length; i++) block[i] = pattern[i % pattern.length];
  const detector = createTaintDetector([SECRET]);
  const started = Date.now();
  let scanned = 0;
  while (scanned < 16 * 1024 * 1024) {
    assert.equal(detector.scan(block), false, "a clean body stays clean");
    scanned += block.length;
  }
  const elapsed = Date.now() - started;
  assert.ok(elapsed < 5000, "16 MB of a clean body is scanned well inside a few seconds: " + elapsed + " ms");
});