/**
 * The CI gate's pure classification of a GitHub check-runs payload (A5), shared by the gateway's
 * auto-update and the satellite's follow-the-primary update (SAT-6). No imports: the satellite
 * agent must not load the gateway's auto-update module (it reaches crow.db).
 */

// The three branch-protection context names (the A1 contract). Other runs
// (deploy-docs, build, image-freshness) never block updates.
export const CI_GATE_CONTEXTS = ["suite", "static-checks", "audit"];

// Hosts whose check-runs api.github.com can answer for. `ssh.github.com` is
// GitHub's documented SSH-over-443 endpoint, so it is the same repository.
const GITHUB_HOSTS = new Set(["github.com", "www.github.com", "ssh.github.com"]);

/**
 * A path segment usable as an owner or repo name. The forge/GitHub request URL
 * is built from these two, so a `.` or `..` segment (path traversal), a
 * percent-encoded segment (a second, already-decoded spelling of the same
 * traversal — `%2e%2e`), and anything carrying whitespace or a control
 * character (which can smuggle an extra path segment or a header) is refused:
 * such a remote is not a repository.
 *
 * Applied at the two call sites that act on the answer — parseRemoteOwnerRepo
 * (which builds a forge URL, so it answers null) and unsafeGithubRemote (which
 * tells the GitHub callers that the remote is GitHub but unaskable, so they
 * answer "unavailable"/refuse instead of "not GitHub"). NOT in the shared
 * segment split: a parse that refuses these makes the gateway read them as
 * not-applicable and deploy without the gate (review round 2).
 */
function isSafeOwnerOrRepo(segment) {
  if (segment === "." || segment === "..") return false;
  if (segment.includes("%")) return false;
  if (/[\s\u0000-\u001f\u007f]/.test(segment)) return false;
  return true;
}

/**
 * The first two path segments of a remote as `{ owner, repo }`, or null.
 *
 * Trailing slashes (git accepts `o/r/` and `o/r.git/`) and the `.git` suffix are
 * transport details, not part of the repository's name.
 *
 * There is NO safety check here (review round 2). A `.`/`..`, percent-encoded or
 * whitespace/control segment is a PATH problem, and each caller decides what it
 * means: parseRemoteOwnerRepo refuses it outright (it builds a forge URL), the
 * gateway and the satellite ask unsafeGithubRemote first (an unsafe GitHub
 * segment is "unavailable"/refused, never "not GitHub"), and parseGithubRemote
 * keeps its PRE-round-1 reading so that its safe-remote answers are unchanged.
 */
function splitOwnerRepo(path) {
  const parts = String(path || "").replace(/\/+$/, "").split("/").filter(Boolean);
  if (parts.length < 2) return null;
  const owner = parts[0];
  const repo = parts[1].replace(/\.git$/i, "");
  if (!owner || !repo) return null;
  return { owner, repo };
}

/**
 * A remote URL split into `{ scheme, host, path }`, or null when it is not a
 * remote at all. `scheme` is null for an scp-like `[user@]host:path` remote.
 *
 * The authority ends at the first slash, so `ssh://git@host:2222/o/r.git` keeps
 * the port OUT of the path; the user part and the port are dropped from `host`.
 * A local path, and a bare `host` with no path, carry no remote host and answer
 * null (git's own reading: the colon — not a leading path — decides scp-like).
 */
function parseRemoteParts(url) {
  const raw = typeof url === "string" ? url.trim() : "";
  if (!raw) return null;

  let scheme = null;
  let host;
  let path;
  const schemeMatch = /^([a-z][a-z0-9+.-]*):\/\/(.*)$/i.exec(raw);
  if (schemeMatch) {
    scheme = schemeMatch[1].toLowerCase();
    const rest = schemeMatch[2];
    const slash = rest.indexOf("/");
    const authority = slash === -1 ? rest : rest.slice(0, slash);
    path = slash === -1 ? "" : rest.slice(slash + 1);
    host = authority.slice(authority.lastIndexOf("@") + 1).replace(/:\d+$/, "");
  } else {
    const scp = /^(?:[^@/\s]+@)?([^:/\s]+):(.+)$/.exec(raw);
    if (!scp) return null;
    host = scp[1];
    path = scp[2];
  }
  return { scheme, host, path };
}

/**
 * Parse a git remote URL into `{ owner, repo }` — but only when it really points
 * at github.com.
 *
 * A substring match on "github.com" was what the gate and the satellite update
 * used before (review round 1, S1): it read a LOCAL path containing
 * `github.com/o/r` as GitHub, and it missed every form whose host carries a
 * user, a port or different case (`ssh://git@ssh.github.com:443/o/r.git`,
 * `https://GitHub.com/o/r`, a trailing slash, `.git/`). Misses fail OPEN in the
 * gateway — the origin reads as "not GitHub", the gate says not-applicable and
 * the unverified commit deploys — so the host is parsed, lowercased and compared
 * exactly.
 *
 * Accepted forms:
 *   https://github.com/o/r(.git)      http://…      ssh://git@github.com/o/r(.git)
 *   ssh://git@ssh.github.com:443/o/r(.git)         git@github.com:o/r(.git)   (scp-like)
 * A local path, a `file://` URL and any other host return null: there is no
 * GitHub API to ask. Without a user part, `host:path` is still read as scp-like
 * (git accepts it), which is why the colon — not a leading path — decides.
 *
 * A GitHub host with an UNSAFE owner/repo segment (`../crow`, `o/r%2Ex`,
 * `o%20/r`, `./r`) still answers `{ owner, repo }` here, exactly as it did before
 * review round 1: its caller then asks a URL that 404s, which the gate reads as
 * "unavailable". Moving the safety check into this parse once made those remotes
 * answer null, and the gateway read a null parse as "not GitHub" — not-applicable
 * — and deployed the unverified commit (fail open, review round 2). The safety
 * check therefore belongs to the callers that read null as "nothing to ask":
 * they consult unsafeGithubRemote FIRST.
 *
 * @param {string|null|undefined} url the output of `git remote get-url origin`
 * @returns {{owner: string, repo: string}|null}
 */
export function parseGithubRemote(url) {
  const parts = parseRemoteParts(url);
  if (!parts) return null;
  if (!parts.host || !GITHUB_HOSTS.has(parts.host.toLowerCase())) return null;
  return splitOwnerRepo(parts.path);
}

/**
 * Is this origin a GITHUB one whose owner or repo cannot be used as a URL path
 * segment — `.`/`..`, percent-encoded, or carrying whitespace/control
 * characters (see isSafeOwnerOrRepo)?
 *
 * parseGithubRemote deliberately keeps answering `{ owner, repo }` for such a
 * remote (its safe answers must not change, and the 404 that follows is
 * "unavailable"). But a caller for which a null parse means "not GitHub, there
 * is nothing to ask" — the gateway's not-applicable branch and `ciGateAppliesTo`,
 * the satellite's GitHub read — would then FAIL OPEN and deploy the unverified
 * commit. Those callers ask this first and answer "unavailable" (gateway) or
 * refuse (satellite) WITHOUT building a request: an unsafe segment is not a
 * repository, so there is nothing to ask about and no URL worth forming.
 *
 * Everything else answers false, so nothing else changes: a remote on another
 * host, and a GitHub remote with no owner/repo to speak of (`https://github.com/`,
 * one path segment), which was not-applicable before round 1 too.
 *
 * @param {string|null|undefined} url the output of `git remote get-url origin`
 * @returns {boolean}
 */
export function unsafeGithubRemote(url) {
  const parts = parseRemoteParts(url);
  if (!parts || !parts.host) return false;
  if (!GITHUB_HOSTS.has(parts.host.toLowerCase())) return false;
  const remote = splitOwnerRepo(parts.path);
  if (!remote) return false;
  return !isSafeOwnerOrRepo(remote.owner) || !isSafeOwnerOrRepo(remote.repo);
}

/** Schemes a self-hosted forge API can be reached over. `file://` and every
 *  other scheme name no forge to ask, so they answer null (fail closed). */
const FORGE_SCHEMES = new Set(["http", "https", "ssh"]);

/**
 * Parse a git remote URL into `{ owner, repo }` for ANY host — the generic
 * sibling of parseGithubRemote, used by the self-hosted (Gitea/Forgejo) CI
 * gate, where the host is configured separately (`CROW_UPDATE_FORGE_API`) and
 * must not be second-guessed here.
 *
 * Accepted forms: `https://…`, `http://…`, `ssh://[user@]host[:port]/…` and the
 * scp-like `[user@]host:owner/repo(.git)`. Trailing slashes and the `.git`
 * suffix are dropped, and a port in the authority never reaches the path (an
 * `ssh://git@host:2222/o/r.git` owner is `o`, not `2222`).
 *
 * A local path, a `file://` URL, any other scheme, an empty host, anything with
 * fewer than two path segments, and an owner or repo segment that is a `.`/`..`
 * traversal, percent-encoded or carries whitespace/control characters return
 * null: an unparseable origin must not be mistaken for a repository.
 *
 * @param {string|null|undefined} url the output of `git remote get-url origin`
 * @returns {{owner: string, repo: string}|null}
 */
export function parseRemoteOwnerRepo(url) {
  const parts = parseRemoteParts(url);
  if (!parts) return null;
  if (parts.scheme && !FORGE_SCHEMES.has(parts.scheme)) return null;
  if (!parts.host) return null;
  const remote = splitOwnerRepo(parts.path);
  if (!remote) return null;
  // This parse builds a forge request URL, so the safety check lives HERE and
  // only here: an unsafe segment is not a repository to ask about.
  if (!isSafeOwnerOrRepo(remote.owner) || !isSafeOwnerOrRepo(remote.repo)) return null;
  return remote;
}

/** The runs in this payload that carry one of the three required contexts. */
export function ciGateRuns(payload) {
  return (payload?.check_runs || []).filter((r) => CI_GATE_CONTEXTS.includes(r?.name));
}

/**
 * The required contexts this payload has NO run for.
 *
 * classifyCheckRuns answers "pending" for two very different shapes: a context
 * that has not reported YET (its run is queued or in progress) and a context
 * that will NEVER report on this origin (a fork carrying only some of our
 * workflows). The gateway needs the difference to word its skip, and to stop
 * calling a partial-CI fork "still running" forever (review round 2). The
 * classifier's own return values are untouched — this is a second read of the
 * same payload, not a sixth verdict.
 */
export function missingCiContexts(payload) {
  const present = new Set(ciGateRuns(payload).map((r) => r.name));
  return CI_GATE_CONTEXTS.filter((name) => !present.has(name));
}

/**
 * Pure classification of a GitHub check-runs payload for the target sha.
 * "unknown" (no named runs — a fork without our CI, or a push that raced the
 * workflow) is not a deployment decision: nothing here can verify the sha, so it
 * is never green. The gateway's auto-update maps it to "no-ci" (a fork without
 * this repo's CI) and the satellite accepts only "green".
 *
 * Green requires ALL THREE contexts to be present and successful (review round
 * 1, S3): a sha where only `audit` has reported so far used to read green and be
 * deployed before `suite` and `static-checks` ever ran. A present-and-finished
 * subset is "pending" (the rest has not reported yet), a red run is "red" even
 * when another context is still missing, and no run at all is "unknown".
 *
 * A finished subset with a context missing is "pending" HERE — the gateway
 * turns that shape into "no-ci" when nothing is still running (review round 2,
 * see missingCiContexts); the satellite keeps treating it as a refusal.
 */
export function classifyCheckRuns(payload) {
  const runs = ciGateRuns(payload);
  if (runs.length === 0) return "unknown";
  if (runs.some((r) => r.status !== "completed")) return "pending";
  const ok = ["success", "neutral", "skipped"];
  if (!runs.every((r) => ok.includes(r.conclusion))) return "red";
  const present = new Set(runs.map((r) => r.name));
  return CI_GATE_CONTEXTS.every((name) => present.has(name)) ? "green" : "pending";
}

// ---------------------------------------------------------------------------
// G7: the same gate for a self-hosted Gitea/Forgejo origin, whose CI reports
// COMMIT STATUSES instead of check-runs. A status context there has the shape
// `<workflow> / <jobkey> (push)` — e.g. `Tests / suite (push)`.
// ---------------------------------------------------------------------------

// Anchored at both ends: the workflow part is greedy, so a workflow name that
// itself contains " / " still yields the LAST segment as the job key, and a
// lookalike (`suite-extra`, a bare `x suite (push)` without the separator) can
// never match a required key by substring.
const PUSH_STATUS_CONTEXT = /^(.+) \/ ([^/]+) \(push\)$/;

const parsePushStatusContext = (context) => {
  if (typeof context !== "string") return null;
  const m = PUSH_STATUS_CONTEXT.exec(context);
  return m ? { workflow: m[1], key: m[2] } : null;
};

/**
 * Commit-status state → ok | pending | red. Fail closed: only `success` and
 * `skipped` count as ok, and anything unrecognised (or absent) is RED — an
 * unreadable answer is not a green one.
 *
 * Gitea/Forgejo report the field as `status`, the GitHub-compatible API as
 * `state`; both are read.
 */
function statusStateOf(entry) {
  const raw = entry?.state ?? entry?.status;
  const state = typeof raw === "string" ? raw.trim().toLowerCase() : "";
  if (state === "success" || state === "skipped") return "ok";
  if (state === "pending") return "pending";
  return "red"; // failure, error, warning — and anything unrecognised
}

const statusTime = (entry) => {
  const t = Date.parse(String(entry?.updated_at ?? entry?.created_at ?? ""));
  return Number.isFinite(t) ? t : null;
};

const statusId = (entry) => {
  const id = Number(entry?.id);
  return Number.isFinite(id) ? id : null;
};

/**
 * Is `candidate` a LATER event than `current`? The statuses endpoint is an
 * append-only event list: the highest numeric `id` wins, a missing id falls
 * back to `created_at`/`updated_at`, and when neither orders the two the later
 * entry of the list is taken as the newer one.
 */
function isLaterStatus(candidate, current) {
  const aId = statusId(candidate);
  const bId = statusId(current);
  if (aId !== null && bId !== null && aId !== bId) return aId > bId;
  if (aId !== null && bId === null) return true;
  if (aId === null && bId !== null) return false;
  const aAt = statusTime(candidate);
  const bAt = statusTime(current);
  if (aAt !== null && bAt !== null && aAt !== bAt) return aAt > bAt;
  return true;
}

/**
 * The latest status per PARSED CONTEXT STRING, restricted to the required job
 * keys. Keyed by the full context, never by the key alone: two workflows that
 * both report `suite` are two independent verdicts and both have to be read.
 * `(pull_request)` contexts, unparseable names and keys we do not require are
 * ignored here.
 */
function latestStatusContexts(statuses, requiredKeys) {
  const keys = Array.isArray(requiredKeys) ? requiredKeys : CI_GATE_CONTEXTS;
  const byContext = new Map();
  for (const entry of Array.isArray(statuses) ? statuses : []) {
    const parsed = parsePushStatusContext(entry?.context);
    if (!parsed) continue;
    if (!keys.includes(parsed.key)) continue;
    const prev = byContext.get(entry.context);
    if (!prev || isLaterStatus(entry, prev.status)) byContext.set(entry.context, { key: parsed.key, status: entry });
  }
  return [...byContext.values()];
}

/**
 * The required job keys this status list has NO `(push)` context for — the
 * forge-side twin of missingCiContexts, and what the gateway's "no CI" sentence
 * needs to name.
 */
export function missingStatusContexts(statuses, requiredKeys = CI_GATE_CONTEXTS) {
  const keys = Array.isArray(requiredKeys) ? requiredKeys : CI_GATE_CONTEXTS;
  const present = new Set(latestStatusContexts(statuses, keys).map((e) => e.key));
  return keys.filter((key) => !present.has(key));
}

/**
 * Pure classification of a Gitea/Forgejo commit-status list (G7) — the
 * forge-side twin of classifyCheckRuns, with the same verdicts and the same
 * green rule (ALL required keys, not a subset).
 *
 * - Only `<workflow> / <jobkey> (push)` contexts count, parsed and anchored both
 *   ends; `(pull_request)` ones and unparseable names are ignored.
 * - Only the LATEST event per context string counts (append-only list), and a
 *   required key is green only when EVERY context reporting it is ok — a second
 *   workflow failing the same key is red.
 * - `success`/`skipped` are ok, `pending` is pending, and everything else
 *   (failure/error/warning, an unknown state, a missing state) is red.
 *
 * No matching status at all is "unknown" (never green: nothing verified the
 * sha). Any red is red. Any pending is pending. All required keys ok is green,
 * and a finished subset with a key missing is "pending" HERE — the gateway
 * turns that shape into "no-ci" when nothing is still running, exactly as it
 * does for check-runs, and the satellite keeps refusing it.
 */
export function classifyCommitStatuses(statuses, requiredKeys = CI_GATE_CONTEXTS) {
  const keys = Array.isArray(requiredKeys) ? requiredKeys : CI_GATE_CONTEXTS;
  const latest = latestStatusContexts(statuses, keys);
  if (latest.length === 0) return "unknown";
  const states = latest.map((e) => statusStateOf(e.status));
  if (states.includes("red")) return "red";
  if (states.includes("pending")) return "pending";
  const present = new Set(latest.map((e) => e.key));
  return keys.every((key) => present.has(key)) ? "green" : "pending";
}