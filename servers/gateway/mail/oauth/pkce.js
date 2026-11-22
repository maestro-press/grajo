/**
 * PKCE (RFC 7636) for Crow Mail's OAuth flows: the per-flow verifier and the S256 challenge derived
 * from it.
 *
 * The verifier is the flow's secret. It never leaves this machine: it goes into the flow store
 * (oauth/state.js) and into the ONE token request that redeems the code (oauth/flow.js), and it is what
 * makes a stolen authorization code useless on its own. The challenge travels in the URL the person
 * approves, so the provider can hold the code until someone proves they had the verifier.
 *
 * Both strings are base64url without padding — the alphabet PKCE requires — and both are URLs and form
 * values, so no further encoding is needed at either end.
 *
 * https://www.rfc-editor.org/rfc/rfc7636 (S256, appendix A for the verifier alphabet, appendix B for
 * the worked example the tests pin).
 */
import { createHash, randomBytes } from "node:crypto";

/** 32 random bytes is 256 bits of entropy and base64url-encodes to 43 characters (RFC 7636 allows 43-128). */
const VERIFIER_BYTES = 32;

/** base64url without padding: `+` -> `-`, `/` -> `_`, and no `=`. */
function base64url(bytes) {
  return bytes.toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/**
 * A fresh code verifier: 43 characters of `[A-Za-z0-9-._~]`, from 256 bits of CSPRNG output.
 *
 * @returns {string}
 */
export function newVerifier() {
  return base64url(randomBytes(VERIFIER_BYTES));
}

/**
 * The S256 challenge for a verifier: base64url(SHA-256(verifier)), no padding. RFC 7636's appendix B
 * example is pinned by the tests.
 *
 * @param {string} verifier the value `newVerifier()` produced (never logged, never sent to the browser)
 * @returns {string} 43 characters, the `code_challenge` of the authorization URL
 */
export function challengeFor(verifier) {
  if (typeof verifier !== "string" || verifier.length === 0) {
    throw new TypeError("challengeFor needs the verifier string");
  }
  return base64url(createHash("sha256").update(verifier, "utf8").digest());
}