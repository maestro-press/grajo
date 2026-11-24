// G7: the CI gate against a self-hosted Gitea/Forgejo origin.
//
// A Gitea/Forgejo install reports CI as COMMIT STATUSES
// (`<workflow> / <jobkey> (push)`), not as GitHub check-runs. The gate must read
// them without ever asking GitHub, and it must FAIL CLOSED on every way the
// configuration or the answer can be broken: a partial config, an unreadable or
// empty token file, an unknown forge name, an unparseable origin, a non-2xx
// answer, a thrown request, a body that is not an array, a list that never ends.
// "Unavailable" is never green and — unlike the GitHub path's non-GitHub origin —
// never "not-applicable".
//
// The real GitHub path is pinned by auto-update-ci-gate.test.js and
// auto-update-ci-gate-unavailable.test.js. The forge fixtures carry the
// GitHub-compatible `state` field, so one section pins the classifier against
// the per-sha shape a real Gitea/Forgejo actually serves (`status`, no `state`); this file adds one assertion that all
// three forge variables unset leaves it unchanged, and otherwise only exercises
// forge mode — except review round 2's unsafe-segment section, which is about the
// GitHub path on purpose: it pins that a GitHub origin with a `.`/`..`/percent/
// whitespace owner-or-repo cannot read as "not-applicable" (that deployed without
// the gate) and that parseGithubRemote itself never changed.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  CI_GATE_CONTEXTS, classifyCommitStatuses, missingStatusContexts, parseGithubRemote,
  parseRemoteOwnerRepo, unsafeGithubRemote,
} from "../servers/shared/ci-check-runs.js";
import { fetchForgeStatuses, forgeConfigured } from "../servers/shared/ci-forge-status.js";
import {
  runLockedUpdate, _resolveCiVerdictForTest, _setAppRootForTest, _setCiFetchForTest,
  _setCiRemoteUrlForTest, _setDbForTest, CI_GATE_SETTING_KEY, CI_UNAVAILABLE_COUNT_KEY,
} from "../servers/gateway/auto-update.js";

// A successful update arms the gateway's restart chain; never inside a test.
delete process.env.INVOCATION_ID;
delete process.env.CROW_SUPERVISED;

// Static imports above are already evaluated, so the scratch home the satellite
// module resolves at ITS import time (a dynamic one, below) is set here.
const ROOT = mkdtempSync(join(tmpdir(), "au-forge-"));
process.env.CROW_HOME = join(ROOT, "crow-home");
process.env.CROW_DATA_DIR = join(ROOT, "crow-data");
process.env.CROW_DISABLE_INSTANCE_SYNC = "1";

const REAL_APP_ROOT = join(import.meta.dirname, "..");
const FORGE_VARS = ["CROW_UPDATE_FORGE", "CROW_UPDATE_FORGE_API", "CROW_UPDATE_FORGE_TOKEN_FILE"];
const TOKEN = "fake-forge-token-for-tests";
const FORGE_URL = "https://gitea.example.ts.net/api/v1";
const REMOTE = "https://gitea.example.ts.net/acme/crow.git";
const GH_URL = "https://github.com/acme/crow.git";
const SHA = "1a2b3c4d5e6f7890a1b2c3d4e5f60718293a4b5c";
const CUR = "1".repeat(40);
const TARGET = "2".repeat(40);

const TOKEN_FILE = join(ROOT, "forge-token");
writeFileSync(TOKEN_FILE, `${TOKEN}\n`);
const EMPTY_TOKEN_FILE = join(ROOT, "empty-token");
writeFileSync(EMPTY_TOKEN_FILE, "  \n\n");
const MISSING_TOKEN_FILE = join(ROOT, "no-such-token-file");

const closers = [];
after(() => {
  for (const close of closers) close();
  rmSync(ROOT, { recursive: true, force: true });
});

/** Run `fn` with exactly these forge variables in the env, then restore all three.
 *  Any OTHER key in `vars` (a misspelled `CROW_UPDATE_FORGE*` variable) is
 *  removed afterwards too, so a test cannot leak one into the next test. */
async function withForgeEnv(vars, fn) {
  const saved = {};
  for (const key of FORGE_VARS) saved[key] = process.env[key];
  const extra = Object.keys(vars).filter((key) => !FORGE_VARS.includes(key));
  const extraSaved = {};
  for (const key of extra) extraSaved[key] = process.env[key];
  try {
    for (const key of FORGE_VARS) delete process.env[key];
    for (const [key, value] of Object.entries(vars)) process.env[key] = String(value);
    return await fn();
  } finally {
    for (const key of FORGE_VARS) {
      if (saved[key] === undefined) delete process.env[key];
      else process.env[key] = saved[key];
    }
    for (const key of extra) {
      if (extraSaved[key] === undefined) delete process.env[key];
      else process.env[key] = extraSaved[key];
    }
  }
}

/** The three forge variables as a valid configuration. */
const FORGE_ENV = {
  CROW_UPDATE_FORGE: "gitea",
  CROW_UPDATE_FORGE_API: FORGE_URL,
  CROW_UPDATE_FORGE_TOKEN_FILE: TOKEN_FILE,
};

// ---------------------------------------------------------------- fixtures

/** One commit status as Gitea/Forgejo serve it. */
const status = (workflow, key, state, extra = {}) => ({
  context: `${workflow} / ${key} (push)`, state, ...extra,
});

const GREEN_STATUSES = CI_GATE_CONTEXTS.map((key, i) => status("Tests", key, "success", { id: i + 1 }));

// ------------------------------------------------------- the classifier

test("classifyCommitStatuses: the three (push) contexts green is green", () => {
  assert.equal(classifyCommitStatuses(GREEN_STATUSES), "green");
  assert.deepEqual(missingStatusContexts(GREEN_STATUSES), []);
});

test("classifyCommitStatuses: the LATEST event per context wins (id, then timestamp)", () => {
  // An older failure superseded by a newer success is green …
  assert.equal(classifyCommitStatuses([
    status("Tests", "suite", "failure", { id: 1 }),
    status("Tests", "suite", "success", { id: 2 }),
    status("Tests", "static-checks", "success", { id: 3 }),
    status("Tests", "audit", "success", { id: 4 }),
  ]), "green");
  // … and an older success superseded by a newer failure is red.
  assert.equal(classifyCommitStatuses([
    status("Tests", "suite", "success", { id: 1 }),
    status("Tests", "suite", "failure", { id: 2 }),
    status("Tests", "static-checks", "success", { id: 3 }),
    status("Tests", "audit", "success", { id: 4 }),
  ]), "red");
  // No ids: created_at/updated_at order the events instead.
  assert.equal(classifyCommitStatuses([
    status("Tests", "suite", "failure", { created_at: "2026-01-01T00:00:00Z" }),
    status("Tests", "suite", "success", { created_at: "2026-01-01T00:05:00Z" }),
    status("Tests", "static-checks", "success", { created_at: "2026-01-01T00:06:00Z" }),
    status("Tests", "audit", "success", { created_at: "2026-01-01T00:07:00Z" }),
  ]), "green");
  // `skipped` counts as ok for the last step.
  assert.equal(classifyCommitStatuses([
    status("Tests", "suite", "success", { id: 1 }),
    status("Tests", "static-checks", "success", { id: 2 }),
    status("Tests", "audit", "skipped", { id: 3 }),
  ]), "green");
});

test("classifyCommitStatuses: one pending context is pending", () => {
  assert.equal(classifyCommitStatuses([
    status("Tests", "suite", "success", { id: 1 }),
    status("Tests", "static-checks", "pending", { id: 2 }),
    status("Tests", "audit", "success", { id: 3 }),
  ]), "pending");
  // Pending beats nothing: a red context still wins over a pending one.
  assert.equal(classifyCommitStatuses([
    status("Tests", "suite", "pending", { id: 1 }),
    status("Tests", "static-checks", "failure", { id: 2 }),
    status("Tests", "audit", "success", { id: 3 }),
  ]), "red");
});

test("classifyCommitStatuses: a missing required key is pending, and missingStatusContexts names it", () => {
  const partial = [
    status("Tests", "suite", "success", { id: 1 }),
    status("Tests", "static-checks", "success", { id: 2 }),
  ];
  assert.equal(classifyCommitStatuses(partial), "pending");
  assert.deepEqual(missingStatusContexts(partial), ["audit"]);
  assert.deepEqual(missingStatusContexts([]), CI_GATE_CONTEXTS);
});

test("classifyCommitStatuses: only (pull_request) contexts is unknown, never green", () => {
  assert.equal(classifyCommitStatuses(CI_GATE_CONTEXTS.map((key) => ({
    context: `Tests / ${key} (pull_request)`, state: "success", id: 1,
  }))), "unknown");
  assert.equal(classifyCommitStatuses([]), "unknown");
  assert.equal(classifyCommitStatuses(null), "unknown");
  assert.equal(classifyCommitStatuses(undefined), "unknown");
  assert.equal(classifyCommitStatuses({ statuses: GREEN_STATUSES }), "unknown");
});

test("classifyCommitStatuses: error, warning and an unknown state all fail closed to red", () => {
  for (const state of ["error", "failure", "warning", "queued", "", undefined, null]) {
    assert.equal(classifyCommitStatuses([
      status("Tests", "suite", state, { id: 1 }),
      status("Tests", "static-checks", "success", { id: 2 }),
      status("Tests", "audit", "success", { id: 3 }),
    ]), "red", String(state));
  }
  // A missing state field entirely (the object has neither state nor status).
  assert.equal(classifyCommitStatuses([
    { context: "Tests / suite (push)", id: 1 },
    status("Tests", "static-checks", "success", { id: 2 }),
    status("Tests", "audit", "success", { id: 3 }),
  ]), "red");
});

test("classifyCommitStatuses: unparseable and lookalike contexts are ignored, never matched loosely", () => {
  const ignored = [
    { context: "suite", state: "failure", id: 90 },                    // bare name
    { context: "x suite (push)", state: "failure", id: 91 },           // no workflow separator
    { context: "Tests/suite (push)", state: "failure", id: 92 },       // missing separator spaces
    { context: "Tests / suite-extra (push)", state: "failure", id: 93 },
    { context: "Tests / suite (push) trailing", state: "failure", id: 94 },
    { context: "Tests / suite (pushes)", state: "failure", id: 95 },
    { context: "Tests / Suite (push)", state: "failure", id: 96 },     // exact case only
    { context: "Tests / suite (pull_request)", state: "failure", id: 97 },
    { context: "", state: "failure", id: 98 },
  ];
  assert.equal(classifyCommitStatuses([...GREEN_STATUSES, ...ignored]), "green",
    "a lookalike must never be read as one of the required contexts");
  // The bare lookalikes alone verify nothing at all.
  assert.equal(classifyCommitStatuses(ignored), "unknown");
  // `x suite (push)` is not the `suite` key even when it IS a push context.
  assert.equal(classifyCommitStatuses([{ context: "x suite (push)", state: "success" }]), "unknown");
});

test("classifyCommitStatuses: the same key from two workflows — one failing — is red", () => {
  assert.equal(classifyCommitStatuses([
    ...GREEN_STATUSES,
    status("Other CI", "suite", "failure", { id: 50 }),
  ]), "red");
  // Both green is fine: two workflows may both report the key.
  assert.equal(classifyCommitStatuses([
    ...GREEN_STATUSES,
    status("Other CI", "suite", "success", { id: 50 }),
  ]), "green");
  // Each context keeps its own latest event: a workflow's newer success does not
  // clear another workflow's failure.
  assert.equal(classifyCommitStatuses([
    status("Tests", "suite", "success", { id: 1 }),
    status("Tests", "static-checks", "success", { id: 2 }),
    status("Tests", "audit", "success", { id: 3 }),
    status("Other CI", "suite", "failure", { id: 4 }),
    status("Other CI", "suite", "success", { id: 5 }),
    status("Third CI", "suite", "failure", { id: 6 }),
  ]), "red");
});

// -------------------------------------- the REAL Gitea statuses shape
//
// The fixtures above carry the GitHub-compatible `state` field. A real
// Gitea/Forgejo per-sha `/statuses` answer does NOT: it sends `status` (and
// `statusStateOf` reads either). The forge-side verdicts are therefore pinned
// again here against the field the forge actually sends, with the field set
// itself asserted — a fixture that drifts back to `state` fails, so these
// cases cannot quietly stop testing the real wire shape.
//
// The four contexts are this repo's real `Tests` workflow push jobs. Note
// `phone-runner` is a real job but NOT one of the three required gate
// contexts: it must never stand in for a missing one.

/** The exact field set of one Gitea/Forgejo commit status as the per-sha
 *  `/statuses` endpoint serves it. No `state`, and no `workflow`/`name` pair —
 *  the job key comes out of `context`. */
const GITEA_STATUS_FIELDS = [
  "id", "status", "context", "target_url", "description", "created_at", "updated_at",
];

/** One status in the REAL Gitea shape. */
const giteaStatus = (key, status, id, at) => ({
  id,
  status,
  context: `Tests / ${key} (push)`,
  target_url: `https://gitea.example.ts.net/acme/crow/actions/runs/${id}`,
  description: `${status} — Tests / ${key}`,
  created_at: at,
  updated_at: at,
});

/** Every entry really is the wire shape: the exact field set, and no `state`. */
function assertRealGiteaShape(statuses) {
  for (const entry of statuses) {
    assert.deepEqual(Object.keys(entry).sort(), [...GITEA_STATUS_FIELDS].sort(), JSON.stringify(entry));
    assert.equal("state" in entry, false,
      `a real Gitea status carries no state field: ${JSON.stringify(entry)}`);
    assert.equal(typeof entry.status, "string", JSON.stringify(entry));
  }
}

test("classifyCommitStatuses: the REAL Gitea per-sha shape (status, no state) reaches the same verdicts", () => {
  const at = (minute) => `2026-05-01T10:${String(minute).padStart(2, "0")}:00Z`;

  // (a) a full green push: all four real push contexts report success.
  const green = [
    giteaStatus("suite", "success", 1, at(1)),
    giteaStatus("static-checks", "success", 2, at(2)),
    giteaStatus("audit", "success", 3, at(3)),
    giteaStatus("phone-runner", "success", 4, at(4)),
  ];
  assertRealGiteaShape(green);
  assert.equal(classifyCommitStatuses(green), "green");
  assert.deepEqual(missingStatusContexts(green), []);

  // (b) append-only re-run: the first attempt's four statuses are `pending`, the
  // re-run appends four `success` ones with HIGHER ids for the same contexts.
  // The endpoint is an event list, so the latest event per context wins: green.
  const rerun = [
    giteaStatus("suite", "pending", 1, at(1)),
    giteaStatus("static-checks", "pending", 2, at(2)),
    giteaStatus("audit", "pending", 3, at(3)),
    giteaStatus("phone-runner", "pending", 4, at(4)),
    giteaStatus("suite", "success", 5, at(5)),
    giteaStatus("static-checks", "success", 6, at(6)),
    giteaStatus("audit", "success", 7, at(7)),
    giteaStatus("phone-runner", "success", 8, at(8)),
  ];
  assertRealGiteaShape(rerun);
  assert.equal(classifyCommitStatuses(rerun), "green", "the highest id per context is the latest event");
  // The id decides, not the position in the list (some forge versions serve the
  // list newest-first): the same events reversed are still green.
  assert.equal(classifyCommitStatuses([...rerun].reverse()), "green");
  // …and the mirror image — success first, a HIGHER-id pending for the same
  // context later — is not green: the re-run is still running.
  assert.equal(classifyCommitStatuses([
    giteaStatus("suite", "success", 1, at(1)),
    giteaStatus("static-checks", "success", 2, at(2)),
    giteaStatus("audit", "success", 3, at(3)),
    giteaStatus("phone-runner", "success", 4, at(4)),
    giteaStatus("suite", "pending", 5, at(5)),
  ]), "pending");

  // (c) the LATEST suite status is a failure: red, whatever the run before said.
  const latestFailure = [
    giteaStatus("suite", "success", 1, at(1)),
    giteaStatus("static-checks", "success", 2, at(2)),
    giteaStatus("audit", "success", 3, at(3)),
    giteaStatus("phone-runner", "success", 4, at(4)),
    giteaStatus("suite", "failure", 9, at(9)),
  ];
  assertRealGiteaShape(latestFailure);
  assert.equal(classifyCommitStatuses(latestFailure), "red");
  // The superseded shape (an older failure, a newer success for the same
  // context) stays green: only the latest event counts.
  const supersededFailure = [
    giteaStatus("suite", "failure", 1, at(1)),
    giteaStatus("static-checks", "success", 2, at(2)),
    giteaStatus("audit", "success", 3, at(3)),
    giteaStatus("phone-runner", "success", 4, at(4)),
    giteaStatus("suite", "success", 5, at(5)),
  ];
  assertRealGiteaShape(supersededFailure);
  assert.equal(classifyCommitStatuses(supersededFailure), "green");

  // (d) one required context missing (`audit`), everything else finished and
  // green, `phone-runner` present: never green. The classifier's name for a
  // finished-but-partial set is "pending" (the gateway reads that shape as
  // "no-ci" when nothing is still running).
  const partial = [
    giteaStatus("suite", "success", 1, at(1)),
    giteaStatus("static-checks", "success", 2, at(2)),
    giteaStatus("phone-runner", "success", 4, at(4)),
  ];
  assertRealGiteaShape(partial);
  assert.equal(classifyCommitStatuses(partial), "pending");
  assert.deepEqual(missingStatusContexts(partial), ["audit"],
    "phone-runner is a real job but not a gate context, so it cannot stand in for audit");
});

// -------------------------------------------------------- the origin parse

test("parseRemoteOwnerRepo: every remote form of a self-hosted forge", () => {
  const forms = [
    "https://gitea.example.ts.net/acme/crow.git",
    "https://gitea.example.ts.net/acme/crow",
    "https://gitea.example.ts.net/acme/crow/",
    "https://gitea.example.ts.net/acme/crow.git/",
    "http://gitea.example.ts.net:3000/acme/crow.git",
    "ssh://git@gitea.example.ts.net/acme/crow.git",
    "ssh://git@gitea.example.ts.net:2222/acme/crow.git",
    "git@gitea.example.ts.net:acme/crow.git",
    "git@gitea.example.ts.net:acme/crow",
    "https://Gitea.Example.TS.Net/acme/crow.git", // uppercase host untouched
    "https://github.com/acme/crow.git",           // the host is not checked
  ];
  for (const url of forms) assert.deepEqual(parseRemoteOwnerRepo(url), { owner: "acme", repo: "crow" }, url);
  // A port in the authority never leaks into the path.
  assert.deepEqual(parseRemoteOwnerRepo("ssh://git@gitea.example.ts.net:2222/acme/crow.git"),
    { owner: "acme", repo: "crow" });
});

test("parseRemoteOwnerRepo: a local path, file:// and a too-short path are null", () => {
  const forms = [
    "/srv/git/crow.git",
    "/srv/git/acme/crow.git",
    "./acme/crow.git",
    "file:///srv/git/acme/crow.git",
    "https://gitea.example.ts.net/acme",
    "https://gitea.example.ts.net/",
    "gitea.example.ts.net/acme/crow.git", // no scheme, no colon
    "",
    null,
    undefined,
  ];
  for (const url of forms) assert.equal(parseRemoteOwnerRepo(url), null, String(url));
});

test("parseRemoteOwnerRepo: a traversal, percent-encoded or space/control segment is null", () => {
  // The owner and repo become URL path segments, so a traversal segment must
  // never be read as a repository name.
  const forms = [
    "https://h/../b",
    "https://h/./b",
    "https://h/o/%2e%2e",
    "https://h/%2e%2e/b",
    "https://h/o/%2E%2E/b",
    "https://h/o/crow%2F..%2Fb",
    "git@h:../b",
    "git@h:./b",
    "https://h/o%20a/b",
    "https://h/o/a b",
    "https://h/o/a\tb",
    "https://h/o/a\u0000b",
    "ssh://git@h/../b",
  ];
  for (const url of forms) assert.equal(parseRemoteOwnerRepo(url), null, JSON.stringify(url));
  // Ordinary names still parse, dots and dashes included.
  assert.deepEqual(parseRemoteOwnerRepo("https://h/acme.co/crow-docs.git"), { owner: "acme.co", repo: "crow-docs" });
  assert.deepEqual(parseRemoteOwnerRepo("git@h:a_b/c.d"), { owner: "a_b", repo: "c.d" });
});

// ------------------------------------ round 2: the unsafe GitHub segment
//
// Round 1 moved the safety check into the shared segment split, so a GitHub
// origin with an unsafe segment stopped parsing at all: the gateway read the
// null as "not GitHub", recorded not-applicable and DEPLOYED WITHOUT THE GATE.
// parseGithubRemote must keep its pre-round-1 answers (the API then 404s, which
// reads as "unavailable"); the safety check belongs to parseRemoteOwnerRepo —
// which builds a forge URL — and to the callers that would otherwise turn such
// an origin into "not GitHub".

/** The four probe forms: each is a GitHub host with one unsafe path segment. */
const UNSAFE_GITHUB_REMOTES = [
  "https://github.com/../crow",
  "https://github.com/o/r%2Ex",
  "https://github.com/o%20/r",
  "git@github.com:./r.git",
];

test("parseGithubRemote: an unsafe segment still parses exactly as it did before round 1", () => {
  const expected = [
    { owner: "..", repo: "crow" },
    { owner: "o", repo: "r%2Ex" },
    { owner: "o%20", repo: "r" },
    { owner: ".", repo: "r" },
  ];
  UNSAFE_GITHUB_REMOTES.forEach((url, i) => {
    assert.deepEqual(parseGithubRemote(url), expected[i], url);
    assert.equal(unsafeGithubRemote(url), true, url);
  });
  // Everything else is not "unsafe": a safe GitHub remote, another host, and a
  // GitHub remote with no owner/repo to speak of (not-applicable before round 1
  // too, so its reading must not change either).
  assert.equal(unsafeGithubRemote(GH_URL), false);
  assert.equal(unsafeGithubRemote("git@example.com:../crow"), false);
  assert.equal(unsafeGithubRemote("/srv/git/../crow"), false);
  assert.equal(unsafeGithubRemote("https://github.com/acme"), false);
  assert.equal(unsafeGithubRemote(""), false);
  assert.equal(unsafeGithubRemote(null), false);
});

test("parseRemoteOwnerRepo: the same four (GitHub) forms are null — the forge parser refuses them", () => {
  for (const url of UNSAFE_GITHUB_REMOTES) assert.equal(parseRemoteOwnerRepo(url), null, url);
});

test("gateway: an unsafe GitHub segment is 'unavailable' and no request is made", async () => {
  const calls = [];
  try {
    await withForgeEnv({}, async () => {
      _setCiFetchForTest(async (url) => {
        calls.push(url);
        throw new Error("an unsafe owner/repo must never be sent to GitHub");
      });
      for (const remote of UNSAFE_GITHUB_REMOTES) {
        assert.equal(await _resolveCiVerdictForTest(remote, SHA), "unavailable", remote);
      }
      assert.deepEqual(calls, [], "no GitHub request may be made for any of them");
      // The unchanged neighbours: a non-GitHub origin still has no CI to ask …
      assert.equal(await _resolveCiVerdictForTest("/srv/git/crow.git", SHA), "not-applicable");
      // …and a safe GitHub origin still goes through the classifier.
      assert.equal(await _resolveCiVerdictForTest(GH_URL, SHA), "unavailable", "the seam threw");
    });
  } finally {
    _setCiFetchForTest(null);
  }
});

// -------------------------------------------------- the fetch and the verdict

/** A fetch that answers page 1 with `body` and every later page with an empty
 *  list (what a real forge does for a short list), recording the requests it saw. */
function forgeFetch(body, { status: httpStatus = 200, ok = true } = {}) {
  const calls = [];
  const impl = async (url, init = {}) => {
    calls.push({ url, headers: init.headers, signal: init.signal, redirect: init.redirect });
    let page = 1;
    try { page = Number(new URL(url).searchParams.get("page")) || 1; } catch { /* not a URL: page 1 */ }
    return { ok, status: httpStatus, json: async () => (page === 1 ? body : []) };
  };
  impl.calls = calls;
  return impl;
}

test("forgeConfigured: any of the three variables set — even empty — is forge mode", async () => {
  await withForgeEnv({}, () => {
    assert.equal(forgeConfigured(), false);
    assert.equal(forgeConfigured({}), false);
  });
  for (const key of FORGE_VARS) {
    await withForgeEnv({ [key]: "" }, () => assert.equal(forgeConfigured(), true, `${key}=""`));
  }
  await withForgeEnv(FORGE_ENV, () => assert.equal(forgeConfigured(), true));
});

test("forgeConfigured: a misspelled CROW_UPDATE_FORGE* key is forge mode too (fails closed)", async () => {
  // A typo must never fall through to the GitHub path, where a non-GitHub origin
  // reads as not-applicable and the unverified commit deploys.
  await withForgeEnv({ CROW_UPDATE_FORGE_URL: FORGE_URL }, async () => {
    assert.equal(forgeConfigured(), true);
    const fetchImpl = forgeFetch(GREEN_STATUSES);
    _setCiFetchForTest(fetchImpl);
    assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "unavailable");
    assert.equal(fetchImpl.calls.length, 0, "a typo'd config must not be sent anywhere");
    // …and it does not fall back to GitHub for an origin that would be GitHub.
    assert.equal(await _resolveCiVerdictForTest(GH_URL, SHA), "unavailable");
    assert.equal(fetchImpl.calls.length, 0);
  });
  // The prefix match is case-sensitive: a lowercase lookalike is not forge mode.
  await withForgeEnv({ crow_update_forge: "gitea" }, () => assert.equal(forgeConfigured(), false));
  await withForgeEnv({}, () => assert.equal(forgeConfigured(), false));
});

test("forge mode: a broken configuration is 'unavailable', never 'not-applicable'", async () => {
  const cases = [
    ["token file missing", { ...FORGE_ENV, CROW_UPDATE_FORGE_TOKEN_FILE: MISSING_TOKEN_FILE }],
    ["token file empty", { ...FORGE_ENV, CROW_UPDATE_FORGE_TOKEN_FILE: EMPTY_TOKEN_FILE }],
    ["token file unset", { CROW_UPDATE_FORGE: "gitea", CROW_UPDATE_FORGE_API: FORGE_URL }],
    ["forge name github", { ...FORGE_ENV, CROW_UPDATE_FORGE: "github" }],
    ["forge name unknown", { ...FORGE_ENV, CROW_UPDATE_FORGE: "gitlab" }],
    ["forge name empty", { ...FORGE_ENV, CROW_UPDATE_FORGE: "" }],
    ["api unset", { CROW_UPDATE_FORGE: "gitea", CROW_UPDATE_FORGE_TOKEN_FILE: TOKEN_FILE }],
    ["api not a url", { ...FORGE_ENV, CROW_UPDATE_FORGE_API: "gitea.example.ts.net/api/v1" }],
    ["api not http(s)", { ...FORGE_ENV, CROW_UPDATE_FORGE_API: "ftp://gitea.example.ts.net/api/v1" }],
  ];
  try {
    for (const [name, env] of cases) {
      await withForgeEnv(env, async () => {
        const fetchImpl = forgeFetch(GREEN_STATUSES);
        _setCiFetchForTest(fetchImpl);
        assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "unavailable", name);
        assert.equal(fetchImpl.calls.length, 0, `${name}: an invalid config must not be sent anywhere`);
      });
    }
    // Forgejo speaks the same API and is accepted.
    await withForgeEnv({ ...FORGE_ENV, CROW_UPDATE_FORGE: "Forgejo" }, async () => {
      _setCiFetchForTest(forgeFetch(GREEN_STATUSES));
      assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "green");
    });
  } finally {
    _setCiFetchForTest(null);
  }
});

test("forge mode: every failure to read the forge is 'unavailable'", async () => {
  const failures = [
    ["401", { status: 401, ok: false }],
    ["403", { status: 403, ok: false }],
    ["404", { status: 404, ok: false }],
    ["500", { status: 500, ok: false }],
  ];
  try {
    await withForgeEnv(FORGE_ENV, async () => {
      for (const [name, answer] of failures) {
        _setCiFetchForTest(forgeFetch({}, answer));
        assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "unavailable", name);
      }
      // A thrown request (timeout, DNS, refused connection).
      _setCiFetchForTest(async () => { throw Object.assign(new Error("aborted"), { name: "TimeoutError" }); });
      assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "unavailable", "thrown fetch");
      // A body that is not an array, and a body that is not JSON at all.
      _setCiFetchForTest(forgeFetch({ message: "not a list" }));
      assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "unavailable", "non-array JSON");
      _setCiFetchForTest(async () => ({ ok: true, status: 200, json: async () => { throw new SyntaxError("Unexpected token <"); } }));
      assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "unavailable", "bad JSON");
      // An origin the forge could not be asked about at all.
      _setCiFetchForTest(forgeFetch(GREEN_STATUSES));
      assert.equal(await _resolveCiVerdictForTest("/srv/git/acme/crow.git", SHA), "unavailable", "local path origin");
      assert.equal(await _resolveCiVerdictForTest(REMOTE, "zzz"), "unavailable", "malformed sha");
    });
  } finally {
    _setCiFetchForTest(null);
  }
});

test("forge mode: a malformed sha is unavailable before any request", async () => {
  try {
    await withForgeEnv(FORGE_ENV, async () => {
      for (const sha of ["zzz", "1a2b3c4d5e6f7890a1b2c3d4e5f60718293a4b5c0", "1A2B3C4D5E6F7890A1B2C3D4E5F60718293A4B5C"]) {
        const fetchImpl = forgeFetch(GREEN_STATUSES);
        const res = await fetchForgeStatuses({ remoteUrl: REMOTE, sha, env: process.env, fetchImpl });
        assert.deepEqual(res, { ok: false, reason: "bad-sha" }, sha);
        assert.equal(fetchImpl.calls.length, 0, `${sha}: no request may be made`);
      }
    });
  } finally {
    _setCiFetchForTest(null);
  }
});

test("forge mode: the request carries the token header and the /repos/<owner>/<repo>/commits/<sha>/statuses path", async () => {
  try {
    await withForgeEnv(FORGE_ENV, async () => {
      const fetchImpl = forgeFetch(GREEN_STATUSES);
      _setCiFetchForTest(fetchImpl);
      assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "green");
      // Page 1 carries the request below; page 2 is the EMPTY page that ends the
      // list (a short page is not the end).
      assert.equal(fetchImpl.calls.length, 2);
      assert.equal(new URL(fetchImpl.calls[1].url).searchParams.get("page"), "2");
      const { url, headers, signal, redirect } = fetchImpl.calls[0];
      assert.equal(
        url,
        `${FORGE_URL}/repos/acme/crow/commits/${SHA}/statuses?limit=50&page=1`,
      );
      assert.equal(headers.Authorization, `token ${TOKEN}`);
      assert.ok(signal, "every request carries a timeout signal");
      assert.equal(redirect, "error",
        "a redirect is refused, never followed with the token attached");

      // A remote whose owner/repo need encoding is encoded, never interpolated raw.
      const odd = forgeFetch(GREEN_STATUSES);
      const res = await fetchForgeStatuses({ remoteUrl: "git@gitea.example.ts.net:acme/crow+docs.git", sha: SHA, env: process.env, fetchImpl: odd });
      assert.equal(res.ok, true);
      assert.match(odd.calls[0].url, /\/repos\/acme\/crow%2Bdocs\/commits\//);
    });
  } finally {
    _setCiFetchForTest(null);
  }
});

test("forge mode: an empty list is no-ci (never green)", async () => {
  try {
    await withForgeEnv(FORGE_ENV, async () => {
      _setCiFetchForTest(forgeFetch([]));
      assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "no-ci");
      // Only (pull_request) contexts verify nothing either.
      _setCiFetchForTest(forgeFetch(CI_GATE_CONTEXTS.map((key) => ({
        context: `Tests / ${key} (pull_request)`, state: "success", id: 1,
      }))));
      assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "no-ci");
    });
  } finally {
    _setCiFetchForTest(null);
  }
});

test("forge mode: green, red and pending reach the tick as themselves", async () => {
  try {
    await withForgeEnv(FORGE_ENV, async () => {
      _setCiFetchForTest(forgeFetch(GREEN_STATUSES));
      assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "green");

      _setCiFetchForTest(forgeFetch([
        status("Tests", "suite", "failure", { id: 1 }),
        status("Tests", "static-checks", "success", { id: 2 }),
        status("Tests", "audit", "success", { id: 3 }),
      ]));
      assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "red");

      _setCiFetchForTest(forgeFetch([
        status("Tests", "suite", "pending", { id: 1 }),
        status("Tests", "static-checks", "success", { id: 2 }),
        status("Tests", "audit", "success", { id: 3 }),
      ]));
      assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "pending");

      // A finished subset with a key missing is the no-ci shape, exactly like the
      // GitHub branch: nothing is still running, so nothing more is coming.
      _setCiFetchForTest(forgeFetch([
        status("Tests", "suite", "success", { id: 1 }),
        status("Tests", "static-checks", "success", { id: 2 }),
      ]));
      assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "no-ci");
    });
  } finally {
    _setCiFetchForTest(null);
  }
});

test("forge mode: a 3xx answer is unavailable (redirects are refused, not followed)", async () => {
  // Real fetch REJECTS on a 3xx when `redirect: "error"`, so the seam is modelled
  // that way: it only hands back the 302 if the option was NOT passed.
  const redirects = [];
  const redirecting = async (url, init = {}) => {
    redirects.push(init.redirect);
    if (init.redirect === "error") throw new TypeError("Failed to fetch: unexpected redirect");
    return { ok: true, status: 302, json: async () => GREEN_STATUSES };
  };
  try {
    await withForgeEnv(FORGE_ENV, async () => {
      _setCiFetchForTest(redirecting);
      assert.deepEqual(await _resolveCiVerdictForTest(REMOTE, SHA), "unavailable");
      assert.deepEqual(redirects, ["error"], "every request must refuse redirects");
      // The same answer through the seam directly, never a green one.
      const res = await fetchForgeStatuses({ remoteUrl: REMOTE, sha: SHA, env: process.env, fetchImpl: redirecting });
      assert.deepEqual(res, { ok: false, reason: "request-failed" });
    });
  } finally {
    _setCiFetchForTest(null);
  }
});

test("forge mode: the statuses are paged until an EMPTY page, and the cap is unavailable", async () => {
  const filler = (page) => Array.from({ length: 50 }, (_, i) => ({
    context: `Other / job${page}-${i} (push)`, state: "success", id: page * 1000 + i,
  }));
  try {
    await withForgeEnv(FORGE_ENV, async () => {
      // Page 1 is non-empty, so page 2 is asked for; page 2 is empty, so it ends there.
      const pages = [filler(1), []];
      const paged = async (url) => {
        const page = Number(new URL(url).searchParams.get("page"));
        paged.calls.push(url);
        return { ok: true, status: 200, json: async () => pages[page - 1] ?? [] };
      };
      paged.calls = [];
      const res = await fetchForgeStatuses({ remoteUrl: REMOTE, sha: SHA, env: process.env, fetchImpl: paged });
      assert.equal(res.ok, true);
      assert.equal(res.statuses.length, 50);
      assert.deepEqual(paged.calls.map((u) => new URL(u).searchParams.get("page")), ["1", "2"]);
      // A SHORT page is not the end: only an empty one is.
      const shortThenRest = async (url) => {
        const page = Number(new URL(url).searchParams.get("page"));
        shortThenRest.calls.push(page);
        return { ok: true, status: 200, json: async () => (page === 1 ? GREEN_STATUSES : page === 2 ? [status("Other", "job", "failure", { id: 9 })] : []) };
      };
      shortThenRest.calls = [];
      const three = await fetchForgeStatuses({ remoteUrl: REMOTE, sha: SHA, env: process.env, fetchImpl: shortThenRest });
      assert.equal(three.ok, true);
      assert.equal(three.statuses.length, 4, "a short page must not stop the paging");
      assert.deepEqual(shortThenRest.calls, [1, 2, 3]);

      // Forty full pages: the list may be truncated, so it is unreadable.
      const endless = async (url) => {
        endless.calls.push(url);
        return { ok: true, status: 200, json: async () => filler(Number(new URL(url).searchParams.get("page"))) };
      };
      endless.calls = [];
      const capped = await fetchForgeStatuses({ remoteUrl: REMOTE, sha: SHA, env: process.env, fetchImpl: endless });
      assert.equal(capped.ok, false);
      assert.equal(capped.reason, "too-many-pages");
      assert.equal(endless.calls.length, 40);
      _setCiFetchForTest(endless);
      assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "unavailable");
    });
  } finally {
    _setCiFetchForTest(null);
  }
});

test("forge mode: a server that caps pages at 30 cannot hide a newer failure (F1)", async () => {
  // 27 filler statuses of other contexts + the three required contexts green =
  // exactly the 30 this server serves, and a NEWER failure of a required context
  // sits at position 31. Stopping on "fewer than PAGE_LIMIT" truncated the list
  // and read it green.
  const all = [
    ...Array.from({ length: 27 }, (_, i) => ({ context: `Other / job${i} (push)`, state: "success", id: 1000 + i })),
    ...GREEN_STATUSES,
    status("Tests", "suite", "failure", { id: 9000 }),
  ];
  assert.equal(all.length, 31);
  const pageCap = 30;
  const capped = async (url) => {
    const u = new URL(url);
    const page = Number(u.searchParams.get("page"));
    capped.calls.push(page);
    // At most `pageCap` per request, whatever `limit` asks for.
    const size = Math.min(Number(u.searchParams.get("limit")) || pageCap, pageCap);
    return { ok: true, status: 200, json: async () => all.slice((page - 1) * size, page * size) };
  };
  capped.calls = [];
  try {
    await withForgeEnv(FORGE_ENV, async () => {
      const res = await fetchForgeStatuses({ remoteUrl: REMOTE, sha: SHA, env: process.env, fetchImpl: capped });
      assert.equal(res.ok, true);
      assert.equal(res.statuses.length, 31, "every status must be read, not just the first page");
      assert.deepEqual(capped.calls, [1, 2, 3], "paging ends on the empty page");
      assert.equal(classifyCommitStatuses(res.statuses), "red");
      _setCiFetchForTest(capped);
      assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "red",
        "the truncated-list regression: this used to read green");
    });
  } finally {
    _setCiFetchForTest(null);
  }
});

test("forge mode: a huge page is read without RangeError, and a body that cannot be iterated is unavailable", async () => {
  // `statuses.push(...body)` threw RangeError past ~100k arguments; the for loop
  // does not, so a page this size is read in full.
  const huge = Array.from({ length: 130000 }, (_, i) => ({ context: `Other / job${i} (push)`, state: "success", id: i + 1 }));
  const hugeFetch = async (url) => {
    const page = Number(new URL(url).searchParams.get("page"));
    return { ok: true, status: 200, json: async () => (page === 1 ? huge : []) };
  };
  try {
    await withForgeEnv(FORGE_ENV, async () => {
      const res = await fetchForgeStatuses({ remoteUrl: REMOTE, sha: SHA, env: process.env, fetchImpl: hugeFetch });
      assert.equal(res.ok, true);
      assert.equal(res.statuses.length, huge.length);

      // A non-network throw from the read (here: a body whose iteration throws)
      // is an unreadable answer, never a crash and never green.
      const uncallable = [...GREEN_STATUSES];
      uncallable[Symbol.iterator] = () => { throw new Error("statuses could not be read"); };
      _setCiFetchForTest(async () => ({ ok: true, status: 200, json: async () => uncallable }));
      assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "unavailable");
      // …and the same for a seam that throws a plain, non-network error itself.
      _setCiFetchForTest(async () => { throw new Error("seam exploded"); });
      assert.equal(await _resolveCiVerdictForTest(REMOTE, SHA), "unavailable");
    });
  } finally {
    _setCiFetchForTest(null);
  }
});

test("not forge mode: the GitHub path is unchanged (all three variables unset)", async () => {
  try {
    await withForgeEnv({}, async () => {
      // A non-GitHub origin still has no CI to ask.
      assert.equal(await _resolveCiVerdictForTest("/srv/git/crow.git", SHA), "not-applicable");
      assert.equal(await _resolveCiVerdictForTest("git@example.com:acme/crow.git", SHA), "not-applicable");
      // …and a GitHub origin still goes through the check-runs classifier.
      const fetchImpl = async () => ({
        ok: true,
        status: 200,
        json: async () => ({ check_runs: CI_GATE_CONTEXTS.map((name) => ({ name, status: "completed", conclusion: "success" })) }),
      });
      _setCiFetchForTest(fetchImpl);
      assert.equal(await _resolveCiVerdictForTest(GH_URL, SHA), "green");
    });
  } finally {
    _setCiFetchForTest(null);
  }
});

// ------------------------------------------------------------- tick level

const g = (cwd, ...args) => execFileSync("git", args, { cwd, stdio: "pipe" }).toString().trim();

/** dashboard_settings behind a Map, so a test can read what the tick recorded. */
function stubDb(initial = {}) {
  const settings = new Map(Object.entries(initial));
  return {
    settings,
    async execute({ sql, args = [] } = {}) {
      if (/^\s*SELECT value FROM dashboard_settings WHERE key = \?/.test(sql || "")) {
        return { rows: settings.has(args[0]) ? [{ value: settings.get(args[0]) }] : [] };
      }
      if (/SELECT key, value FROM dashboard_settings WHERE key IN \(\?, \?\)/.test(sql || "")) {
        return { rows: args.filter((k) => settings.has(k)).map((k) => ({ key: k, value: settings.get(k) })) };
      }
      if (/SELECT key, value FROM dashboard_settings WHERE key LIKE 'auto_update_%'/.test(sql || "")) {
        return { rows: [...settings].filter(([k]) => k.startsWith("auto_update_"))
          .map(([key, value]) => ({ key, value })) };
      }
      if (/INSERT INTO dashboard_settings/.test(sql || "")) {
        settings.set(args[0], args[1]);
        return { rows: [], lastInsertRowid: 0 };
      }
      return { rows: [] };
    },
  };
}

/** A bare origin plus a clone — one commit behind unless `behind` is false. */
function fixture({ behind = true } = {}) {
  const root = mkdtempSync(join(ROOT, "tick-"));
  const origin = join(root, "origin.git");
  const work = join(root, "work");
  execFileSync("git", ["init", "--bare", "-b", "main", origin], { stdio: "pipe" });
  execFileSync("git", ["clone", origin, work], { stdio: "pipe" });
  g(work, "config", "user.email", "t@t");
  g(work, "config", "user.name", "t");
  writeFileSync(join(work, "a.txt"), "one\n");
  mkdirSync(join(work, "scripts"), { recursive: true });
  writeFileSync(join(work, "scripts", "init-db.js"), "process.exit(0);\n");
  g(work, "add", "a.txt", "scripts/init-db.js");
  g(work, "commit", "-m", "c1");
  g(work, "push", "origin", "main");
  if (behind) {
    const pusher = join(root, "pusher");
    execFileSync("git", ["clone", origin, pusher], { stdio: "pipe" });
    g(pusher, "config", "user.email", "t@t");
    g(pusher, "config", "user.name", "t");
    writeFileSync(join(pusher, "b.txt"), "two\n");
    g(pusher, "add", "b.txt");
    g(pusher, "commit", "-m", "c2");
    g(pusher, "push", "origin", "main");
  }
  return { root, work };
}

/** Restore every module seam the tick tests touch. */
function resetSeams(appRoot = REAL_APP_ROOT) {
  _setCiFetchForTest(null);
  _setCiRemoteUrlForTest(null);
  _setDbForTest(null);
  _setAppRootForTest(appRoot);
}

/** Neither the forge token nor the token file's path may appear in any captured
 *  log line, in the recorded result, or in any saved setting. */
function assertNoForgeSecret(logs, db, where) {
  for (const line of logs) {
    assert.equal(line.includes(TOKEN), false, `${where}: the token leaked into a log line: ${line}`);
    assert.equal(line.includes(TOKEN_FILE), false, `${where}: the token file path leaked into a log line: ${line}`);
  }
  const lastResult = String(db.settings.get("auto_update_last_result") ?? "");
  assert.equal(lastResult.includes(TOKEN), false, `${where}: the token leaked into last_result`);
  assert.equal(lastResult.includes(TOKEN_FILE), false, `${where}: the token file path leaked into last_result`);
  for (const [key, value] of db.settings) {
    assert.equal(String(key).includes(TOKEN), false, `${where}: the token leaked into setting ${key}`);
    assert.equal(String(value).includes(TOKEN), false, `${where}: the token leaked into setting ${key}`);
    assert.equal(String(key).includes(TOKEN_FILE), false, `${where}: the token file path leaked into setting ${key}`);
    assert.equal(String(value).includes(TOKEN_FILE), false, `${where}: the token file path leaked into setting ${key}`);
  }
}

test("tick: forge mode skips the pull on red, pending and unavailable", async () => {
  const fx = fixture();
  const db = stubDb();
  const logs = [];
  const realLog = console.log;
  const realWarn = console.warn;
  const realError = console.error;
  // The tick's own log, captured (not discarded): the token and the token file
  // path must never reach a line the updater writes.
  const tickLog = (msg) => logs.push(String(msg));
  try {
    _setAppRootForTest(fx.work);
    _setDbForTest(db);
    // A fixture origin has to stay a local bare repo for git to fetch it; the
    // seam is what the tick reads as `git remote get-url origin`.
    _setCiRemoteUrlForTest(REMOTE);
    const recorded = () => db.settings.get("auto_update_last_result");
    console.log = (...a) => { logs.push(a.join(" ")); };
    console.warn = (...a) => { logs.push(a.join(" ")); };
    console.error = (...a) => { logs.push(a.join(" ")); };

    await withForgeEnv(FORGE_ENV, async () => {
      const before = g(fx.work, "rev-parse", "HEAD");

      _setCiFetchForTest(forgeFetch([status("Tests", "suite", "failure", { id: 1 })]));
      const red = await runLockedUpdate(tickLog);
      assert.equal(red.updated, false);
      assert.equal(red.skipped, "ci-red");
      assert.equal(g(fx.work, "rev-parse", "HEAD"), before, "red CI must not pull");
      assert.match(recorded(), /^Skipped: CI is RED on origin\/main \([0-9a-f]{9}\)/);

      _setCiFetchForTest(forgeFetch([status("Tests", "suite", "pending", { id: 1 })]));
      const pending = await runLockedUpdate(tickLog);
      assert.equal(pending.skipped, "ci-pending");
      assert.equal(g(fx.work, "rev-parse", "HEAD"), before, "pending CI must not pull");

      _setCiFetchForTest(forgeFetch({}, { status: 503, ok: false }));
      const down = await runLockedUpdate(tickLog);
      assert.equal(down.skipped, "ci-unavailable");
      assert.equal(g(fx.work, "rev-parse", "HEAD"), before, "an unreadable answer must not pull");
      assert.equal(db.settings.get(CI_GATE_SETTING_KEY), "unavailable");
      assert.equal(db.settings.get(CI_UNAVAILABLE_COUNT_KEY), "1");

      // The no-ci shapes read identically in forge mode.
      _setCiFetchForTest(forgeFetch([]));
      const none = await runLockedUpdate(tickLog);
      assert.equal(none.skipped, "no-ci");
      assert.deepEqual(none.missingCi, CI_GATE_CONTEXTS);

      // …and a full green set finally pulls.
      _setCiFetchForTest(forgeFetch(GREEN_STATUSES));
      const green = await runLockedUpdate(tickLog);
      assert.equal(green.updated, true, JSON.stringify(green));
      assert.notEqual(g(fx.work, "rev-parse", "HEAD"), before, "a green answer pulls");
    });
  } finally {
    console.log = realLog;
    console.warn = realWarn;
    console.error = realError;
    resetSeams();
    rmSync(fx.root, { recursive: true, force: true });
  }

  assertNoForgeSecret(logs, db, "tick: red/pending/unavailable");
});

test("tick: forge mode names the code host in the unavailable pause sentence", async () => {
  const fx = fixture();
  const db = stubDb({ [CI_UNAVAILABLE_COUNT_KEY]: "2" });
  const logs = [];
  const tickLog = (msg) => logs.push(String(msg));
  try {
    _setAppRootForTest(fx.work);
    _setDbForTest(db);
    _setCiRemoteUrlForTest(REMOTE);
    _setCiFetchForTest(forgeFetch({}, { status: 503, ok: false }));
    await withForgeEnv(FORGE_ENV, async () => {
      const res = await runLockedUpdate(tickLog);
      assert.equal(res.skipped, "ci-unavailable");
      assert.equal(
        res.message,
        "Skipped: CI status unreadable for 3 checks in a row — updates are paused until the code host answers (or set CROW_UPDATE_CI_GATE=0)",
      );
    });
  } finally {
    resetSeams();
    rmSync(fx.root, { recursive: true, force: true });
  }
  assertNoForgeSecret(logs, db, "tick: pause sentence");
});

test("tick: an up-to-date checkout in forge mode records '' (the gate applies), not not-applicable", async () => {
  const fx = fixture({ behind: false });
  const db = stubDb({ [CI_GATE_SETTING_KEY]: "not-applicable", [CI_UNAVAILABLE_COUNT_KEY]: "2" });
  const logs = [];
  const tickLog = (msg) => logs.push(String(msg));
  try {
    _setAppRootForTest(fx.work);
    _setDbForTest(db);
    // No fetch at all: an up-to-date tick never asks the forge.
    _setCiFetchForTest(() => { throw new Error("an up-to-date tick must not ask the forge"); });
    await withForgeEnv(FORGE_ENV, async () => {
      const res = await runLockedUpdate(tickLog);
      assert.equal(res.updated, false, JSON.stringify(res));
      assert.equal(res.skipped, undefined, "plain up-to-date, not a CI skip");
      assert.equal(db.settings.get("auto_update_last_result"), "Up to date");
      assert.equal(db.settings.get(CI_GATE_SETTING_KEY), "",
        "forge mode applies the gate whatever the origin looks like");
      assert.equal(db.settings.get(CI_UNAVAILABLE_COUNT_KEY), "0");
    });
  } finally {
    resetSeams();
    rmSync(fx.root, { recursive: true, force: true });
  }
  assertNoForgeSecret(logs, db, "tick: up-to-date");
});

test("tick: an up-to-date checkout on an unsafe GitHub origin records '' (never not-applicable)", async () => {
  // The round-2 regression: this origin used to parse to null, so the up-to-date
  // branch recorded "not-applicable" — the gate's "nothing to ask here, keep
  // updating" reading — for an origin that IS GitHub.
  const fx = fixture({ behind: false });
  const logs = [];
  const tickLog = (msg) => logs.push(String(msg));
  try {
    _setAppRootForTest(fx.work);
    // An up-to-date tick asks nothing at all; a request here would be a regression.
    _setCiFetchForTest((url) => { throw new Error(`an up-to-date tick must not ask GitHub: ${url}`); });
    await withForgeEnv({}, async () => {
      for (const remote of UNSAFE_GITHUB_REMOTES) {
        const db = stubDb({ [CI_GATE_SETTING_KEY]: "not-applicable", [CI_UNAVAILABLE_COUNT_KEY]: "2" });
        _setDbForTest(db);
        _setCiRemoteUrlForTest(remote);
        const res = await runLockedUpdate(tickLog);
        assert.equal(res.updated, false, `${remote}: ${JSON.stringify(res)}`);
        assert.equal(res.skipped, undefined, `${remote}: plain up-to-date, not a CI skip`);
        assert.equal(db.settings.get("auto_update_last_result"), "Up to date", remote);
        assert.equal(db.settings.get(CI_GATE_SETTING_KEY), "",
          `${remote}: the gate applies to an unsafe GitHub origin, so the reading is cleared`);
        assert.equal(db.settings.get(CI_UNAVAILABLE_COUNT_KEY), "0", remote);
      }
    });
  } finally {
    resetSeams();
    rmSync(fx.root, { recursive: true, force: true });
  }
});

// --------------------------------------------------------------- satellite

/** A scripted git runner for the satellite updater: only the reads `check()` needs. */
function satelliteRunner(remote = REMOTE) {
  const lines = [];
  const runner = async (cmd, args = []) => {
    const line = [cmd, ...args].join(" ");
    lines.push(line);
    if (line === "git rev-parse HEAD") return { stdout: `${CUR}\n`, stderr: "" };
    if (line === "git remote get-url origin") return { stdout: `${remote}\n`, stderr: "" };
    return { stdout: "", stderr: "" };
  };
  runner.lines = lines;
  return runner;
}

test("satellite: forge mode accepts only green, and never touches the GitHub seam", async () => {
  const { openSatelliteDb } = await import("../servers/satellite/db.js");
  const U = await import("../servers/satellite/update.js");
  const satHome = mkdtempSync(join(ROOT, "sat-home-"));
  const appRoot = mkdtempSync(join(ROOT, "sat-app-"));
  const db = openSatelliteDb(satHome);
  closers.push(() => db.close());

  const world = (statuses) => {
    const runner = satelliteRunner();
    const seen = [];
    const updater = U.createUpdater({
      db, satHome, appRoot, runner, exit: () => {}, log: () => {},
      fetchCheckRuns: async () => { throw new Error("the GitHub check-runs seam must not be used in forge mode"); },
      fetchStatuses: async (sha) => { seen.push(sha); return statuses; },
    });
    return { runner, updater, seen };
  };

  try {
    await withForgeEnv(FORGE_ENV, async () => {
      const ok = world(GREEN_STATUSES);
      const accepted = await ok.updater.check(TARGET);
      assert.equal(accepted.ok, true, JSON.stringify(accepted));
      assert.deepEqual(ok.seen, [TARGET]);

      const refusals = [
        ["red", [status("Tests", "suite", "failure", { id: 1 })]],
        ["pending", [status("Tests", "suite", "pending", { id: 1 })]],
        ["unknown", []],
        ["unknown", null],  // an unreadable answer: null → nothing matched
      ];
      for (const [verdict, statuses] of refusals) {
        const w = world(statuses);
        const r = await w.updater.check(TARGET);
        assert.equal(r.ok, false, JSON.stringify(statuses));
        assert.equal(r.code, "ci_not_green");
        assert.equal(r.ci, verdict);
        assert.ok(!w.runner.lines.includes(`git merge --ff-only ${TARGET}`));
      }
      // A finished subset with a key missing is still a refusal here (the
      // satellite is green-only; the gateway is the one that reads it as no-ci).
      const partial = world([status("Tests", "suite", "success", { id: 1 })]);
      assert.deepEqual(await partial.updater.check(TARGET), { ok: false, status: 409, code: "ci_not_green", ci: "pending" });
    });

    // The satellite's own forge read: a broken config is null (→ unknown → refused).
    const broken = await U.forgeCommitStatuses({
      runner: satelliteRunner(), appRoot, sha: TARGET,
      env: { ...FORGE_ENV, CROW_UPDATE_FORGE_TOKEN_FILE: MISSING_TOKEN_FILE },
      fetchImpl: async () => ({ ok: true, json: async () => GREEN_STATUSES }),
    });
    assert.equal(broken, null);
    // …and a valid one returns the list, never the token.
    const fetched = await U.forgeCommitStatuses({
      runner: satelliteRunner(), appRoot, sha: TARGET, env: FORGE_ENV,
      fetchImpl: forgeFetch(GREEN_STATUSES),
    });
    assert.deepEqual(fetched, GREEN_STATUSES);
    assert.equal(JSON.stringify(fetched).includes(TOKEN), false);

    // Not forge mode: the GitHub seam still decides, exactly as before.
    await withForgeEnv({}, async () => {
      const runner = satelliteRunner();
      const updater = U.createUpdater({
        db, satHome, appRoot, runner, exit: () => {}, log: () => {},
        fetchCheckRuns: async () => ({ check_runs: [] }),
        fetchStatuses: async () => GREEN_STATUSES,
      });
      const r = await updater.check(TARGET);
      assert.equal(r.code, "ci_not_green");
      assert.equal(r.ci, "unknown");
    });
  } finally {
    rmSync(satHome, { recursive: true, force: true });
    rmSync(appRoot, { recursive: true, force: true });
  }
});

test("satellite: a misspelled forge variable refuses instead of falling back to GitHub", async () => {
  const { openSatelliteDb } = await import("../servers/satellite/db.js");
  const U = await import("../servers/satellite/update.js");
  const satHome = mkdtempSync(join(ROOT, "sat-typo-home-"));
  const appRoot = mkdtempSync(join(ROOT, "sat-typo-app-"));
  const db = openSatelliteDb(satHome);
  closers.push(() => db.close());
  try {
    // Only a typo'd name is set: still forge mode, so the satellite's forge read
    // answers null and the check refuses. Falling back to GitHub would have
    // deployed an unverified sha.
    await withForgeEnv({ CROW_UPDATE_FORGE_URL: FORGE_URL }, async () => {
      assert.equal(forgeConfigured(), true);
      let githubAsked = false;
      const runner = satelliteRunner();
      const updater = U.createUpdater({
        db, satHome, appRoot, runner, exit: () => {}, log: () => {},
        fetchCheckRuns: async () => {
          githubAsked = true;
          return { check_runs: CI_GATE_CONTEXTS.map((name) => ({ name, status: "completed", conclusion: "success" })) };
        },
      });
      const r = await updater.check(TARGET);
      assert.equal(r.ok, false, JSON.stringify(r));
      assert.equal(r.code, "ci_not_green");
      assert.equal(r.ci, "unknown", "a typo'd config is an unreadable answer, never green");
      assert.equal(githubAsked, false, "a typo must not fall through to the GitHub path");
      assert.ok(!runner.lines.includes(`git merge --ff-only ${TARGET}`));
    });
  } finally {
    rmSync(satHome, { recursive: true, force: true });
    rmSync(appRoot, { recursive: true, force: true });
  }
});

test("satellite: an unsafe GitHub segment is refused, and no request is made", async () => {
  const { openSatelliteDb } = await import("../servers/satellite/db.js");
  const U = await import("../servers/satellite/update.js");
  const satHome = mkdtempSync(join(ROOT, "sat-unsafe-home-"));
  const appRoot = mkdtempSync(join(ROOT, "sat-unsafe-app-"));
  const db = openSatelliteDb(satHome);
  closers.push(() => db.close());
  try {
    await withForgeEnv({}, async () => {
      for (const remote of UNSAFE_GITHUB_REMOTES) {
        // The GitHub read answers null (unreadable) WITHOUT building a URL: the
        // owner `..`/`o%20` or the repo `r%2Ex`/`.` is not a repository.
        const asked = [];
        const runner = satelliteRunner(remote);
        const checked = await U.githubCheckRuns({
          runner, appRoot, sha: TARGET,
          fetchImpl: async (url) => { asked.push(url); throw new Error("no request may be made"); },
        });
        assert.equal(checked, null, remote);
        assert.deepEqual(asked, [], `${remote}: no GitHub request may be made`);

        // …and the updater refuses it: unknown is never green, nothing is merged.
        const updater = U.createUpdater({
          db, satHome, appRoot, runner, exit: () => {}, log: () => {},
          fetchStatuses: async () => null,
        });
        const res = await updater.check(TARGET);
        assert.equal(res.ok, false, `${remote}: ${JSON.stringify(res)}`);
        assert.equal(res.code, "ci_not_green", remote);
        assert.equal(res.ci, "unknown", remote);
        assert.ok(!runner.lines.includes(`git merge --ff-only ${TARGET}`), `${remote}: refused, never merged`);
      }
    });
  } finally {
    rmSync(satHome, { recursive: true, force: true });
    rmSync(appRoot, { recursive: true, force: true });
  }
});

test("the token never appears in a returned reason (every failure shape)", async () => {
  const tokenEnv = { ...FORGE_ENV, CROW_UPDATE_FORGE_TOKEN_FILE: EMPTY_TOKEN_FILE };
  const probes = [
    FORGE_ENV,
    tokenEnv,
    { ...FORGE_ENV, CROW_UPDATE_FORGE_TOKEN_FILE: MISSING_TOKEN_FILE },
    { ...FORGE_ENV, CROW_UPDATE_FORGE: "bitbucket" },
    { ...FORGE_ENV, CROW_UPDATE_FORGE_API: "not a url" },
  ];
  const answers = [
    forgeFetch(GREEN_STATUSES),
    { ok: false, status: 403, json: async () => ({}) },
    { ok: true, status: 200, json: async () => ({ message: "nope" }) },
  ];
  for (const env of probes) {
    await withForgeEnv(env, async () => {
      for (const answer of answers) {
        const impl = typeof answer === "function" ? answer : async () => answer;
        const res = await fetchForgeStatuses({
          remoteUrl: REMOTE, sha: SHA, env: process.env, fetchImpl: impl,
        });
        assert.equal(JSON.stringify(res).includes(TOKEN), false, JSON.stringify(res));
      }
      // A thrown error from the transport must not carry it either.
      const thrown = await fetchForgeStatuses({
        remoteUrl: REMOTE, sha: SHA, env: process.env,
        fetchImpl: async () => { throw new Error(`request failed for token ${TOKEN}`); },
      });
      assert.equal(JSON.stringify(thrown).includes(TOKEN), false);
      if (env.CROW_UPDATE_FORGE_TOKEN_FILE === TOKEN_FILE && env.CROW_UPDATE_FORGE === FORGE_ENV.CROW_UPDATE_FORGE
        && env.CROW_UPDATE_FORGE_API === FORGE_ENV.CROW_UPDATE_FORGE_API) {
        assert.deepEqual(thrown, { ok: false, reason: "request-failed" });
      }
      // And an unparseable origin, which is the other early return.
      const badRemote = await fetchForgeStatuses({
        remoteUrl: "/srv/git/acme/crow.git", sha: SHA, env: process.env, fetchImpl: async () => answers[0],
      });
      assert.equal(JSON.stringify(badRemote).includes(TOKEN), false);
    });
  }
});