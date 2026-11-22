/**
 * The owner's approval MAC, as the engine checks it.
 *
 * A signed request carries three headers: an epoch-seconds stamp, a nonce of
 * 16-128 characters from the base64url alphabet, and a lowercase hex
 * HMAC-SHA256.  The signed text is five lines joined by a newline:
 *
 *     METHOD
 *     path_with_query
 *     ts
 *     nonce
 *     hex(sha256(body bytes))
 *
 * The body is the exact UTF-8 text sent, so the caller serialises it once and
 * signs that same text.
 */
import { createHash, createHmac, randomBytes as nodeRandomBytes } from "node:crypto";

const KEY_REQUIRED = "a signing key is required";
const NONCE_BYTES = 18;

/** Refuse a value that cannot key a MAC, without repeating it in the message. */
function requireKey(key) {
  if (typeof key !== "string" || key.length === 0) {
    throw new Error(KEY_REQUIRED);
  }
}

/** The lowercase hex SHA-256 of a body's UTF-8 bytes. */
export function bodySha256Hex(bodyText) {
  const text = bodyText === undefined || bodyText === null ? "" : String(bodyText);
  return createHash("sha256").update(text, "utf8").digest("hex");
}

/** The five-line text the MAC covers. */
export function stringToSign({ method, pathWithQuery, ts, nonce, body }) {
  return [
    String(method === undefined || method === null ? "" : method).toUpperCase(),
    pathWithQuery === undefined || pathWithQuery === null ? "" : String(pathWithQuery),
    ts === undefined || ts === null ? "" : String(ts),
    nonce === undefined || nonce === null ? "" : String(nonce),
    bodySha256Hex(body),
  ].join("\n");
}

/** Lowercase hex HMAC-SHA256 over `stringToSign`, keyed by the UTF-8 of `key`. */
export function macSignature({ key, method, pathWithQuery, ts, nonce, body }) {
  requireKey(key);
  const text = stringToSign({ method, pathWithQuery, ts, nonce, body });
  return createHmac("sha256", Buffer.from(key, "utf8")).update(text, "utf8").digest("hex");
}

/**
 * The three headers for one request.
 *
 * `ts` and `nonce` may be supplied by the caller instead of being generated, so a
 * vector can be reproduced exactly.
 */
export function macHeaders({
  key,
  method,
  pathWithQuery,
  body = "",
  now = () => Date.now(),
  randomBytes = nodeRandomBytes,
  ts,
  nonce,
} = {}) {
  requireKey(key);
  const stamp = ts === undefined || ts === null ? String(Math.floor(now() / 1000)) : String(ts);
  const used =
    nonce === undefined || nonce === null ? randomBytes(NONCE_BYTES).toString("base64url") : String(nonce);
  return {
    "X-Crow-Timestamp": stamp,
    "X-Crow-Nonce": used,
    "X-Crow-Signature": macSignature({ key, method, pathWithQuery, ts: stamp, nonce: used, body }),
  };
}