/**
 * G7: the CI gate's read of a self-hosted Gitea/Forgejo origin's commit statuses.
 *
 * A Gitea/Forgejo install reports CI as COMMIT STATUSES
 * (`GET /repos/{owner}/{repo}/commits/{sha}/statuses`), not as GitHub check-runs.
 * Both the gateway's auto-update and the satellite's follow-the-primary update
 * read them through here; classifyCommitStatuses (shared/ci-check-runs.js, which
 * itself imports nothing) turns a list into a verdict.
 *
 * Everything in this module FAILS CLOSED. The only successful answer is a parsed
 * list of statuses; a partial configuration, an unreadable or empty token file,
 * an unparseable origin, an unknown forge name, a non-2xx answer, a redirected
 * request (`redirect: "error"`), a thrown request, a body that is not an array,
 * and a paginated list that never ends all answer `{ ok: false, reason }`. The callers map that to "unavailable" (the
 * gateway) or "refused" (the satellite) — never to "green" and never to
 * "not-applicable".
 *
 * The token is read from a FILE (`CROW_UPDATE_FORGE_TOKEN_FILE`), sent as
 * `Authorization: token <contents>`, and never appears in a returned reason, a
 * log line or a message. Reasons are fixed short codes for exactly that reason:
 * they cannot carry anything read from the environment.
 *
 * Env is read at CALL time, not at import time, so a test (and a restart-less
 * operator change) sees the current values.
 */
import { readFileSync } from "node:fs";
import { parseRemoteOwnerRepo } from "./ci-check-runs.js";

/** Forge names that speak this API. Forgejo is a Gitea fork with the same API. */
const FORGE_NAMES = new Set(["gitea", "forgejo"]);

/** Page size and the hard page cap: a list that is still full at the cap is
 *  treated as unreadable rather than as the whole answer (it may be truncated).
 *  The cap is generous because a forge may serve FEWER entries per page than
 *  `limit` asks for, so the number of pages says nothing about the list size. */
const PAGE_LIMIT = 50;
const MAX_PAGES = 40;
const REQUEST_TIMEOUT_MS = 15000;

const FULL_SHA = /^[0-9a-f]{40}$/;

/**
 * Every variable that puts this instance in forge mode shares this prefix.
 * Matched CASE-SENSITIVELY on the key, so a misspelled `CROW_UPDATE_FORGE_URL`
 * is still forge mode — a typo has to fail CLOSED (unavailable), never fall
 * through to the GitHub path (which would read a non-GitHub origin as
 * "not-applicable" and deploy the unverified commit).
 */
const FORGE_ENV_PREFIX = "CROW_UPDATE_FORGE";

/**
 * Is this instance in "forge mode"? True when ANY environment key starts with
 * `CROW_UPDATE_FORGE` — the three documented variables, and any misspelling of
 * them — even when the value is an empty string. A partial or typo'd
 * configuration must be a loud "unavailable", never a silent fall-through to
 * the GitHub path.
 */
export function forgeConfigured(env = process.env) {
  const e = env || {};
  return Object.keys(e).some((key) => key.startsWith(FORGE_ENV_PREFIX));
}

/** The token, trimmed, or a reason why there is none. Never echoes the value. */
function readToken(env) {
  const file = String(env?.CROW_UPDATE_FORGE_TOKEN_FILE ?? "").trim();
  if (!file) return { ok: false, reason: "forge-token-file-unset" };
  let raw;
  try {
    raw = readFileSync(file, "utf8");
  } catch {
    return { ok: false, reason: "forge-token-file-unreadable" };
  }
  const token = String(raw).trim();
  if (!token) return { ok: false, reason: "forge-token-empty" };
  return { ok: true, token };
}

/**
 * The forge API base, or a reason. An http(s) URL is required: the token travels
 * in a header, so a bogus base must never be guessed at.
 */
function readApiBase(env) {
  const raw = String(env?.CROW_UPDATE_FORGE_API ?? "").trim();
  if (!raw) return { ok: false, reason: "forge-api-unset" };
  let parsed;
  try {
    parsed = new URL(raw);
  } catch {
    return { ok: false, reason: "forge-api-invalid" };
  }
  if (parsed.protocol !== "http:" && parsed.protocol !== "https:") return { ok: false, reason: "forge-api-invalid" };
  // The endpoints are appended to this base, so a trailing slash is dropped and
  // any query/fragment is ignored rather than glued onto the request path.
  return { ok: true, base: `${parsed.origin}${parsed.pathname.replace(/\/+$/, "")}` };
}

/**
 * Read every commit status for `sha` from the configured forge.
 *
 * @param {object} options
 * @param {string} options.remoteUrl output of `git remote get-url origin`
 * @param {string} options.sha the commit the update would land on
 * @param {object} [options.env] defaults to process.env, read at call time
 * @param {Function} [options.fetchImpl] injectable fetch (tests, seams)
 * @returns {Promise<{ok: true, statuses: object[]}|{ok: false, reason: string}>}
 */
export async function fetchForgeStatuses({ remoteUrl, sha, env = process.env, fetchImpl } = {}) {
  const e = env || {};
  const forge = String(e.CROW_UPDATE_FORGE ?? "").trim().toLowerCase();
  if (!FORGE_NAMES.has(forge)) return { ok: false, reason: "forge-unsupported" };

  const api = readApiBase(e);
  if (!api.ok) return api;

  // The sha goes into a URL path, so it must be a full lowercase sha first.
  const target = typeof sha === "string" ? sha.trim() : "";
  if (!FULL_SHA.test(target)) return { ok: false, reason: "bad-sha" };

  const remote = parseRemoteOwnerRepo(remoteUrl);
  if (!remote) return { ok: false, reason: "bad-remote" };

  const token = readToken(e);
  if (!token.ok) return token;

  const doFetch = typeof fetchImpl === "function" ? fetchImpl : globalThis.fetch;
  const owner = encodeURIComponent(remote.owner);
  const repo = encodeURIComponent(remote.repo);
  const statuses = [];

  for (let page = 1; page <= MAX_PAGES; page += 1) {
    const url = `${api.base}/repos/${owner}/${repo}/commits/${target}/statuses?limit=${PAGE_LIMIT}&page=${page}`;
    let resp;
    try {
      resp = await doFetch(url, {
        headers: {
          Accept: "application/json",
          Authorization: `token ${token.token}`,
          "User-Agent": "crow-auto-update",
        },
        // A redirect is never followed: the token travels in a header, and a 3xx
        // to another host would hand it over (or land on an HTML login page that
        // is not a status list). fetch REJECTS on a 3xx in this mode, which the
        // catch below reports as unavailable.
        redirect: "error",
        signal: AbortSignal.timeout(REQUEST_TIMEOUT_MS),
      });
    } catch {
      return { ok: false, reason: "request-failed" };
    }
    if (!resp || !resp.ok) return { ok: false, reason: "http-error" };
    let body;
    try {
      body = await resp.json();
    } catch {
      return { ok: false, reason: "bad-json" };
    }
    if (!Array.isArray(body)) return { ok: false, reason: "bad-json" };
    // ONLY an empty page ends the list. A short page does NOT: a forge is allowed
    // to serve fewer entries than `limit` asks for (some cap it, e.g. at 30), so
    // "fewer than PAGE_LIMIT" says nothing about the end — treating it as the end
    // truncated the list, and a newer failure on the next page was never seen.
    if (body.length === 0) return { ok: true, statuses };
    // A for loop, never `statuses.push(...body)`: spreading a huge page throws
    // RangeError (too many arguments) and would escape as an uncaught error.
    for (const entry of body) statuses.push(entry);
    // A non-empty page at the cap may be truncated — an incomplete list could
    // hide a failure, so it is unreadable rather than a verdict.
    if (page === MAX_PAGES) return { ok: false, reason: "too-many-pages" };
  }
  return { ok: false, reason: "too-many-pages" };
}