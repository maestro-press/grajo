/**
 * Fix-it card: the browser add-on's RUNNING container holds files that differ from the
 * ones Crow installed — tests/fix-it-browser-image-stale.test.js
 *
 * bundles/browser/cdp-relay.mjs runs INSIDE the browser container image, and a bundle
 * refresh copies new files into ~/.crow/bundles/browser/ without rebuilding or
 * restarting a running container (routes/bundles.js: "No automatic rebuild:
 * Extensions Restart/Start runs `up -d --build`"). So an existing install keeps
 * answering with the old relay until someone restarts the add-on.
 *
 * The rule these tests pin is CONTENT, not time. An earlier rule compared the running
 * image's `Created` time with the newest mtime among the installed build inputs, which
 * raised the card again straight after the restart it just performed: a bundle refresh
 * copies files with fresh mtimes, and a cached rebuild (BuildKit reuses layers by
 * content) leaves the image's Created time old. So the detector must instead compare
 * the bytes inside the running container:
 *
 *   docker exec <container> sha256sum <dest paths...>
 *
 * with each dest path being where the Dockerfile COPYs that file to (resolved against
 * WORKDIR; a dest ending in "/" or "." takes the source's basename), compared with the
 * sha256 of the installed source file. Stale iff any hash differs or a file the image
 * is built from is missing inside the container. The Dockerfile itself is not in the
 * image and is not compared. A failed exec (non-zero/timeout/garbage) is QUIET, like
 * the existing docker-unreachable rule: no card, and a pending card is left as it is.
 *
 * And a stale container does NOT get the card when the restart would go BACKWARDS: the
 * remedy REBUILDS the image (Chromium 145, from the installed lock) and a profile the
 * running container's newer Chromium wrote (159) crash-loops on it. The detector asks
 * browser-chromium-guard.js, and fails closed: an unknown lock, an unreadable profile or
 * no running container hides the card too (tests/fix-it-browser-chromium-guard.test.js
 * pins the guard itself). The docker stub answers that read from `profileVersion`.
 *
 * And the card names the VERSIONS. The image also carries the bundle's own manifest.json
 * (`COPY manifest.json ./`): a version MARKER, not a compared file. It is read out of the
 * running container (`docker exec <id> cat /app/manifest.json` → `.version`) to say what
 * is running beside what an update would install, and it is EXCLUDED from the sha256
 * comparison — a manifest version bump on its own restarts and rebuilds nothing, so it
 * must never be able to raise the card. A read that fails (an image built before the
 * marker has no such file, garbage JSON, no version string) is the approved UNKNOWN
 * sentence, never a throw and never a hidden card.
 *
 * Docker is never real here (every call goes through the injected runner), the
 * restart is injected, and CROW_HOME is a scratch dir set BEFORE the dynamic imports,
 * so nothing reads the real ~/.crow or touches a container.
 */
import { test, describe, before, after, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, utimesSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, dirname, basename } from "node:path";

/**
 * The image's `Created` stamp the stub reports. Deliberately OLD: any surviving
 * mtime/Created rule would raise the card on the fixtures below, so "no card" here
 * means the decision really came from the content comparison.
 */
const IMAGE_OLD = "2026-01-01T00:00:00.000000000Z";
/** An image built AFTER a refresh: the Created time must not be able to hide a differing file either. */
const IMAGE_NEW = "2027-01-01T00:00:00.000000000Z";
/** Before IMAGE_OLD (an install whose image already carries these files). */
const FILES_OLD = "2025-06-01T00:00:00Z";
/** After IMAGE_OLD — what a bundle refresh makes with its fresh copy. */
const FILES_NEW = "2026-06-01T00:00:00Z";

let home;
let dataDir;
let db;
let idx;
let detector;
let SOURCE;
let DEDUP_KEY;
let COPY;
let dockerfileCopies;
let remedy;
let ACTION_ID;
let OWNER_ONLY_FLASH;
let setDeps;
let store;
const silent = { warn() {}, log() {} };

const COMPOSE = [
  "name: ${CROW_BROWSER_CONTAINER_NAME:-browser}",
  "services:",
  "  crow-browser:",
  "    build:",
  "      context: .",
  "      dockerfile: Dockerfile",
  "    container_name: crow-browser",
  "",
].join("\n");

const DOCKERFILE = [
  "FROM ubuntu:22.04",
  "WORKDIR /app",
  "COPY package.json ./",
  "RUN npm install",
  "COPY entrypoint.sh ./",
  "COPY cdp-relay.mjs ./",
  "",
].join("\n");

/** The bundle's real Dockerfile — the one whose COPY destinations test (c) pins. */
const REAL_DOCKERFILE = readFileSync(join(import.meta.dirname, "..", "bundles", "browser", "Dockerfile"), "utf8");

/** A Dockerfile whose destinations are spelled all three ways (`./`, `.`, a full name). */
const DOCKERFILE_DESTS = [
  "FROM ubuntu:22.04",
  "WORKDIR /srv/app",
  "COPY package.json .",
  "COPY entrypoint.sh ./",
  "COPY cdp-relay.mjs /srv/app/relay.mjs",
  "",
].join("\n");

/**
 * A Dockerfile naming a COPY source the installed bundle does not have (yet, or any more).
 * The image cannot carry what is not in the build context, so it is not a destination this
 * detector may compare: the absent source contributes nothing (and never a card by itself).
 */
const DOCKERFILE_ABSENT_SOURCE = [
  "FROM ubuntu:22.04",
  "WORKDIR /app",
  "COPY package.json ./",
  "COPY entrypoint.sh ./",
  "COPY cdp-relay.mjs ./",
  "COPY extra.mjs ./",
  "",
].join("\n");

/** The relay as Crow just installed it (the new one). */
const RELAY_INSTALLED = "// the relay: the WebRTC launch flag, and no Target.createTarget\n";
/** The relay the container is still running (the old one it was built with). */
const RELAY_OLD = "// the relay: no WebRTC flag yet\n";
const ENTRYPOINT = "#!/bin/sh\nexec node /app/cdp-relay.mjs\n";
const PACKAGE_JSON = '{"name":"crow-browser","version":"1.8.0"}\n';
/**
 * The committed lockfile the real Dockerfile COPYs alongside package.json (`npm ci`).
 * It pins playwright-core 1.58.2 — what the rebuilt image's Chromium (145) comes from,
 * which is what the Chromium-downgrade guard reads (browser-chromium-guard.js).
 */
const LOCKFILE = `${JSON.stringify({
  name: "crow-browser",
  version: "0.1.3",
  lockfileVersion: 3,
  packages: {
    "": { name: "crow-browser", version: "0.1.3", dependencies: { playwright: "^1.49.0" } },
    "node_modules/playwright": { version: "1.58.2", dependencies: { "playwright-core": "1.58.2" } },
    "node_modules/playwright-core": { version: "1.58.2" },
  },
}, null, 2)}\n`;
/** The Chromium major fast-path stands for: what a container profile written by it says. */
const PROFILE_145 = "145.0.7632.6";
/** A profile written by a NEWER Chromium than the rebuild installs. */
const PROFILE_159 = "159.0.8154.6";
/** `profileVersion` for a container whose profile cannot be read at all (the exec fails). */
const PROFILE_UNREADABLE = Symbol("profile-unreadable");
/**
 * The running container has no /app/manifest.json at all — every image built before the
 * version marker existed, which is exactly the install this card is for.
 */
const RUNNING_MANIFEST_MISSING = Symbol("running-manifest-missing");
/** The version read does not answer at all (a cold exec that runs into its bound). */
const RUNNING_MANIFEST_TIMEOUT = Symbol("running-manifest-timeout");

/** What the installed bundle holds on disk. */
const INSTALLED_FILES = {
  Dockerfile: DOCKERFILE,
  "entrypoint.sh": ENTRYPOINT,
  "cdp-relay.mjs": RELAY_INSTALLED,
  "package.json": PACKAGE_JSON,
  "package-lock.json": LOCKFILE,
};
const BUNDLE_FILES = ["Dockerfile", "entrypoint.sh", "cdp-relay.mjs", "package.json", "package-lock.json"];

before(async () => {
  home = mkdtempSync(join(tmpdir(), "crowhome-browserstale-"));
  process.env.CROW_HOME = home;
  dataDir = mkdtempSync(join(tmpdir(), "crowdata-browserstale-"));
  execFileSync(process.execPath, ["scripts/init-db.js"], {
    env: { ...process.env, CROW_DATA_DIR: dataDir }, stdio: "pipe", cwd: join(import.meta.dirname, ".."),
  });
  process.env.CROW_DATA_DIR = dataDir;

  const mod = await import("../servers/gateway/fix-it/detectors/browser-image-stale.js");
  detector = mod.default;
  SOURCE = mod.SOURCE;
  DEDUP_KEY = mod.DEDUP_KEY;
  COPY = mod.COPY;
  dockerfileCopies = mod.dockerfileCopies;
  remedy = await import("../servers/gateway/fix-it/remedies/restart-browser-addon.js");
  ACTION_ID = remedy.ACTION_ID;
  OWNER_ONLY_FLASH = (await import("../servers/gateway/fix-it/remedies/restore-bundle-compose.js")).OWNER_ONLY_FLASH;
  setDeps = remedy._setRestartDepsForTest;
  idx = await import("../servers/gateway/fix-it/index.js");
  store = await import("../servers/shared/fix-it/store.js");
  const { createDbClient } = await import("../servers/db.js");
  db = createDbClient();
});

after(() => {
  delete process.env.CROW_HOME;
  delete process.env.CROW_DATA_DIR;
  try { db?.close(); } catch { /* already closed */ }
  for (const d of [home, dataDir]) { try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
});

beforeEach(() => {
  rmSync(join(home, "bundles"), { recursive: true, force: true });
  rmSync(join(home, "installed.json"), { force: true });
  setDeps(null);
});

function put(relPath, content) {
  const p = join(home, relPath);
  mkdirSync(dirname(p), { recursive: true });
  writeFileSync(p, content);
}

/**
 * The version sentences, approved 2026-11-21 (with the placeholders the detector fills).
 * The card shows the EN known/unknown form; the ES twins are pinned here too.
 */
const APPROVED_VERSION_KNOWN = {
  en: "Running now: version {running}. The update would install version {new}.",
  es: "En marcha ahora: versión {running}. La actualización instalaría la versión {new}.",
};
const APPROVED_VERSION_UNKNOWN = {
  en: "Running now: an earlier version that does not report its number. The update would install version {new}.",
  es: "En marcha ahora: una versión anterior que no indica su número. La actualización instalaría la versión {new}.",
};

/** An approved sentence with its placeholders filled, as the card renders it. */
const fill = (text, values) => Object.entries(values).reduce((out, [key, value]) => out.split(`{${key}}`).join(value), text);

/**
 * The installed browser bundle; `files` overrides the content of a build input, `lock`
 * the lockfile (`null` omits it — an install whose lock cannot be read), and `version`
 * the version its manifest.json declares.
 */
function installBrowser({ whenIso = FILES_OLD, files = {}, lock = LOCKFILE, version = "1.9.4", installed = [{ id: "browser", version }] } = {}) {
  put("bundles/browser/manifest.json", JSON.stringify({
    id: "browser", name: "Browser Automation", version, type: "bundle",
    docker: { composefile: "docker-compose.yml" },
  }));
  put("bundles/browser/docker-compose.yml", COMPOSE);
  const onDisk = { ...INSTALLED_FILES, ...files };
  if (lock === null) delete onDisk["package-lock.json"];
  else onDisk["package-lock.json"] = lock;
  for (const [rel, content] of Object.entries(onDisk)) put(`bundles/browser/${rel}`, content);
  if (installed) put("installed.json", JSON.stringify(installed));
  touch(whenIso);
}

/** Set the mtime of every build input (and of the compose, which is not one). */
function touch(whenIso) {
  const when = new Date(whenIso);
  for (const rel of [...BUNDLE_FILES, "docker-compose.yml"]) {
    try { utimesSync(join(home, "bundles/browser", rel), when, when); } catch { /* not written */ }
  }
}

const sha256 = (text) => createHash("sha256").update(String(text), "utf8").digest("hex");

/**
 * What the RUNNING container holds, at the destinations the browser Dockerfile copies to.
 * A dest the installed Dockerfile does not COPY (package-lock.json, for the fixtures that
 * build from the shorter DOCKERFILE) is never asked for, so carrying it is harmless.
 */
function inContainer({ relay = RELAY_INSTALLED, entrypoint = ENTRYPOINT, pkg = PACKAGE_JSON, lock = LOCKFILE } = {}) {
  return {
    "/app/cdp-relay.mjs": relay,
    "/app/entrypoint.sh": entrypoint,
    "/app/package-lock.json": lock,
    "/app/package.json": pkg,
  };
}

/**
 * `sha256sum <dest…>` as a real container answers it: one `hash  path` line per file it
 * has, and a `No such file or directory` line on stderr (exit 1) for each one it does
 * not — which is what makes a missing file different from an unreachable docker.
 */
function sha256sumOutput(files, lookup, dests) {
  const lines = [];
  const missing = [];
  for (const dest of dests) {
    const content = lookup(files, dest);
    if (content === undefined) { missing.push(dest); continue; }
    lines.push(`${sha256(content)}  ${dest}`);
  }
  return {
    stdout: lines.length > 0 ? `${lines.join("\n")}\n` : "",
    stderr: missing.map((d) => `sha256sum: ${d}: No such file or directory`).join("\n"),
  };
}

/** Every absolute path a sha256sum exec call names — the dest paths, however the command is spelled. */
function execDestPaths(args) {
  const out = [];
  for (const arg of args.slice(2)) {
    for (const tok of String(arg).split(/\s+/)) if (tok.startsWith("/")) out.push(tok);
  }
  return out;
}

/** The content-check exec calls (`sha256sum <dests…>`); the guard's profile reads are apart. */
const execCalls = (runner) => runner.calls.filter((c) => c.args[0] === "exec" && c.args[2] === "sha256sum");
/** The version read's `cat <…/manifest.json>` exec calls (the card's version marker). */
const manifestCalls = (runner) => runner.calls.filter((c) => c.args[0] === "exec" && c.args[2] === "cat" && basename(String(c.args[3] ?? "")) === "manifest.json");
/** The Chromium-downgrade guard's `cat …/Last Version` exec calls. */
const profileCalls = (runner) => runner.calls.filter((c) => c.args[0] === "exec" && c.args[2] === "cat" && basename(String(c.args[3] ?? "")) === "Last Version");
const execDests = (runner) => new Set(execCalls(runner).flatMap((c) => execDestPaths(c.args)));
/** The container an exec call names (the first argument that is one of the running ids). */
const execContainer = (args, ids) => args.slice(1).find((a) => ids.includes(a)) || args[1];

/**
 * A `docker` CLI stand-in: `ps` answers the running ids, `inspect` answers the image
 * fixture, `exec <id> sha256sum <dests>` answers from the container's files, and
 * `exec <id> cat …/Last Version` answers the Chromium profile fixture.
 *
 * `containerFiles`: container id (or "*") → { destPath: content }. With `basenameFiles`
 * a dest that has no exact entry falls back to its basename — used only where the
 * detector must pick the destination itself (the unreadable-Dockerfile fallback).
 * `execAnswer` forces one answer for every exec call (a throw, garbage, …).
 * `profileVersion` is what `Last Version` holds; PROFILE_UNREADABLE makes that read
 * fail (a container whose profile cannot be read). `runningManifest` is what the
 * container's own `/app/manifest.json` answers to `cat` — the version marker the card
 * names; RUNNING_MANIFEST_MISSING (the default) is an image built before it existed.
 */
function dockerStub({ ids = ["container1"], imageIds = ["sha256:cafe"], created = IMAGE_OLD, containerFiles = {}, basenameFiles = null, execAnswer = null, profileVersion = PROFILE_145, runningManifest = RUNNING_MANIFEST_MISSING } = {}) {
  const lookup = (files, dest) => {
    if (dest in files) return files[dest];
    if (basenameFiles && basename(dest) in basenameFiles) return basenameFiles[basename(dest)];
    return undefined;
  };
  const calls = [];
  const runner = async (cmd, args, opts) => {
    calls.push({ cmd, args: [...args], opts });
    if (cmd !== "docker") throw new Error(`unexpected command ${cmd}`);
    if (args[0] === "ps") return { stdout: ids.join("\n"), stderr: "" };
    if (args[0] === "exec") {
      if (execAnswer) return execAnswer({ args: [...args], opts });
      if (args[2] === "cat") {
        // The version marker: the card's `cat <…/manifest.json>`, answered from a knob.
        const target = String(args[3] ?? "");
        if (basename(target) === "manifest.json") {
          if (runningManifest === RUNNING_MANIFEST_TIMEOUT) {
            throw Object.assign(new Error("docker exec timed out after 20000ms"), { killed: true, signal: "SIGTERM" });
          }
          if (runningManifest === RUNNING_MANIFEST_MISSING) {
            throw Object.assign(new Error("docker exec exited 1"), { code: 1, stdout: "", stderr: `cat: ${target}: No such file or directory` });
          }
          return { stdout: runningManifest, stderr: "" };
        }
        if (profileVersion === PROFILE_UNREADABLE) {
          throw Object.assign(new Error("docker exec exited 1"), { code: 1, stdout: "", stderr: "cat: /root/.config/chromium-crow/Last Version: No such file or directory" });
        }
        return { stdout: `${profileVersion}\n`, stderr: "" };
      }
      const container = execContainer(args, ids);
      const files = containerFiles[container] ?? containerFiles["*"] ?? {};
      const out = sha256sumOutput(files, lookup, execDestPaths(args));
      if (out.stderr) throw Object.assign(new Error("docker exec exited 1"), { code: 1, stdout: out.stdout, stderr: out.stderr });
      return out;
    }
    if (args[0] === "inspect" && args[1] === "--format" && args[2] === "{{.Image}}") return { stdout: imageIds.join("\n"), stderr: "" };
    if (args[0] === "inspect" && args[1] === "--format" && args[2] === "{{.Created}}") return { stdout: created, stderr: "" };
    // bind-drift reads plain `docker inspect` rows; nothing runs wide here.
    if (args[0] === "inspect") return { stdout: "[]", stderr: "" };
    return { stdout: "", stderr: "" };
  };
  runner.calls = calls;
  return runner;
}

/** A store that records what the detector did, instead of a database. */
function fakeStore() {
  const upserts = [];
  const resolved = [];
  return {
    upserts,
    resolved,
    async upsertItem(item) { upserts.push(item); return { id: upserts.length, notify: false }; },
    async resolveByKey(source, key) { resolved.push(`${source}|${key}`); },
    async listBySource() { return []; },
    async recordDuplicate() {},
    async recordSuppressed() {},
    async markResolved() {},
  };
}

const runCheck = (storeStub, opts = {}) => detector.check(storeStub, { crowHome: home, log: silent, ...opts });
/** The key the detector resolves its one card by (read after the imports in before()). */
const resolvedKey = () => `${SOURCE}|${DEDUP_KEY}`;

describe("the signal: the CONTENT inside the running container differs from the installed files", () => {
  test("(a) the container runs an older relay than the installed one → one card", async () => {
    installBrowser();
    const s = fakeStore();
    const runner = dockerStub({ containerFiles: { container1: inContainer({ relay: RELAY_OLD }) } });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1);
    const card = s.upserts[0];
    assert.equal(card.source, SOURCE);
    assert.equal(card.source, "browser-image-stale");
    assert.equal(card.dedupKey, DEDUP_KEY);
    assert.equal(card.title, COPY.title.en);
    // The approved body, then the approved version sentence. This fixture's container is
    // from before the version marker, so it cannot report its number.
    assert.equal(card.why, `${COPY.body.en} ${fill(APPROVED_VERSION_UNKNOWN.en, { new: "1.9.4" })}`);
    assert.equal(card.severity, "warn");
    // The restart is owner-gated inside the remedy, never by the stored card.
    assert.deepEqual(card.remedies, [
      { actionId: ACTION_ID, kind: "instant", label: "Restart the browser add-on", args: { bundle: "browser" } },
      { actionId: "open-extensions-page", kind: "link", label: "Open Extensions" },
    ]);
    assert.equal(card.context?.bundle, "browser");
    // The containers are looked up by the bundle's compose project, `${VAR:-browser}` resolved.
    assert.match(runner.calls[0].args.join(" "), /com\.docker\.compose\.project=browser/);
    assert.equal(typeof runner.calls[0].opts?.timeout, "number", "every docker call is time-bounded");
    for (const call of execCalls(runner)) {
      assert.equal(typeof call.opts?.timeout, "number", "the content check is bounded too");
    }
    assert.ok(execDests(runner).has("/app/cdp-relay.mjs"), "the differing file was hashed inside the container");
  });

  test("(a) CONTROL: identical content → no card, and a pending card resolves", async () => {
    installBrowser();
    const s = fakeStore();
    const runner = dockerStub({ containerFiles: { container1: inContainer() } });

    await runCheck(s, { runner });

    assert.deepEqual(s.upserts, [], "the container already holds exactly these bytes");
    assert.ok(s.resolved.includes(resolvedKey()), "the card resolves itself once the restart loaded the new files");
    assert.ok(execCalls(runner).length > 0, "it decided from the content, not from a timestamp");
  });

  test("(b) REGRESSION: fresh mtimes + an old image `Created` + equal content (a cached rebuild) → NO card", async () => {
    // A bundle refresh rewrites the files with NOW as their mtime; BuildKit reuses the
    // layers by content, so the rebuilt image's Created time stays old. The old rule
    // raised the card again immediately after the restart it had just performed.
    installBrowser({ whenIso: FILES_NEW });
    const s = fakeStore();
    const runner = dockerStub({ created: IMAGE_OLD, containerFiles: { container1: inContainer() } });

    await runCheck(s, { runner });

    assert.deepEqual(s.upserts, [], "the false positive is gone: content decides, not mtime vs Created");
    assert.ok(s.resolved.includes(resolvedKey()));
    // …and it really did ask the container for its content.
    assert.ok(execCalls(runner).length > 0, "the fake runner was asked for sha256sum");
    assert.ok(execDests(runner).has("/app/cdp-relay.mjs"));
    // The old rule would have fired here: the stub answered `Created` with IMAGE_OLD,
    // which is older than every input mtime. No card ⇒ Created played no part.
    assert.ok(runner.calls.some((c) => c.args[0] === "ps"), "the running containers were looked up");
  });

  test("(b) CONTROL: same mtimes and same `Created`, but one differing hash → card", async () => {
    installBrowser({ whenIso: FILES_NEW });
    const s = fakeStore();
    const runner = dockerStub({
      created: IMAGE_OLD,
      containerFiles: { container1: inContainer({ relay: RELAY_OLD }) },
    });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1);
    assert.deepEqual(s.resolved, []);
  });

  test("(b) an image created AFTER the files cannot hide a differing file (Created is not the decision)", async () => {
    installBrowser({ whenIso: FILES_OLD });
    const s = fakeStore();
    const runner = dockerStub({
      created: IMAGE_NEW,
      containerFiles: { container1: inContainer({ relay: RELAY_OLD }) },
    });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1, "content differs, so the card is raised whatever the timestamps say");
  });

  test("(c) the dest paths are the real Dockerfile's COPY destinations under WORKDIR", async () => {
    // The real Dockerfile is `COPY package.json package-lock.json ./`, so the build context
    // it is compared against holds both — a source absent on disk is skipped, not compared.
    installBrowser({ files: { Dockerfile: REAL_DOCKERFILE, "package-lock.json": LOCKFILE } });
    const s = fakeStore();
    const runner = dockerStub({ containerFiles: { container1: inContainer() } });

    await runCheck(s, { runner });

    assert.deepEqual(s.upserts, [], "identical content: nothing to say");
    assert.deepEqual([...execDests(runner)].sort(), ["/app/cdp-relay.mjs", "/app/entrypoint.sh", "/app/package-lock.json", "/app/package.json"]);
    // The Dockerfile itself is not in the image and is not hashed.
    assert.ok(!execDests(runner).has("/app/Dockerfile"));
    // …and neither is the manifest.json version MARKER the image does carry: it is read,
    // never compared (see the version-sentence tests below).
    assert.ok(!execDests(runner).has("/app/manifest.json"), "the version marker is never hashed");
  });

  test("(c) CONTROL: the lockfile inside the container differs from the installed one → card", async () => {
    installBrowser({ files: { Dockerfile: REAL_DOCKERFILE, "package-lock.json": LOCKFILE } });
    const s = fakeStore();
    const runner = dockerStub({
      containerFiles: { container1: inContainer({ lock: '{"lockfileVersion":2}\n' }) },
    });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1, "the lockfile is a file the image is built from, so a differing one is stale");
    assert.ok(execDests(runner).has("/app/package-lock.json"), "the lockfile was hashed inside the container");
    assert.deepEqual(s.resolved, [], "a raised card is not resolved in the same pass");
  });

  test("(c) a dest spelled `./`, `.` or as a full path all resolve against WORKDIR", async () => {
    installBrowser({ files: { Dockerfile: DOCKERFILE_DESTS } });
    const s = fakeStore();
    const runner = dockerStub({
      containerFiles: {
        container1: {
          "/srv/app/package.json": PACKAGE_JSON,
          "/srv/app/entrypoint.sh": ENTRYPOINT,
          "/srv/app/relay.mjs": RELAY_INSTALLED,
        },
      },
    });

    await runCheck(s, { runner });

    assert.deepEqual(s.upserts, []);
    assert.deepEqual([...execDests(runner)].sort(), ["/srv/app/entrypoint.sh", "/srv/app/package.json", "/srv/app/relay.mjs"]);
  });

  test("(c) a file the image is built from is MISSING inside the container → stale", async () => {
    installBrowser();
    const s = fakeStore();
    // No entrypoint.sh at all: sha256sum says "No such file or directory" and exits 1.
    const runner = dockerStub({
      containerFiles: {
        container1: {
          "/app/cdp-relay.mjs": RELAY_INSTALLED,
          "/app/package.json": PACKAGE_JSON,
        },
      },
    });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1, "a file the image is built from is not in the running container");
  });
  test("(e) two running containers: stale if ANY of them differs", async () => {
    installBrowser();
    const s = fakeStore();
    const runner = dockerStub({
      ids: ["container1", "container2"],
      containerFiles: {
        container1: inContainer(),
        container2: inContainer({ relay: RELAY_OLD }),
      },
    });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1);
    assert.deepEqual(execCalls(runner).map((c) => execContainer(c.args, ["container1", "container2"])).sort(), ["container1", "container2"], "every running container is asked");
  });

  test("(e) CONTROL: two containers that both match → no card", async () => {
    installBrowser();
    const s = fakeStore();
    const runner = dockerStub({
      ids: ["container1", "container2"],
      containerFiles: { container1: inContainer(), container2: inContainer() },
    });

    await runCheck(s, { runner });

    assert.deepEqual(s.upserts, []);
    assert.ok(s.resolved.includes(resolvedKey()));
  });

  test("the fallback list is used when the Dockerfile cannot be read", async () => {
    installBrowser();
    rmSync(join(home, "bundles/browser/Dockerfile"), { force: true });
    const s = fakeStore();
    // No Dockerfile ⇒ no destinations to read: the stub answers by basename, so this
    // test says nothing about where the fallback puts them, only that they are compared.
    const runner = dockerStub({
      basenameFiles: { "cdp-relay.mjs": RELAY_OLD, "entrypoint.sh": ENTRYPOINT },
      containerFiles: { "*": {} },
    });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1, "cdp-relay.mjs and entrypoint.sh are still compared");
    const dests = [...execDests(runner)].map((d) => basename(d)).sort();
    assert.deepEqual([...new Set(dests)], ["cdp-relay.mjs", "entrypoint.sh"], "the Dockerfile itself is not in the image");
  });

  test("a compose with no build context has nothing an image could be older than", async () => {
    installBrowser();
    put("bundles/browser/docker-compose.yml", "services:\n  crow-browser:\n    image: someone/else:1\n");
    const s = fakeStore();
    const runner = dockerStub({ containerFiles: { container1: inContainer({ relay: RELAY_OLD }) } });

    await runCheck(s, { runner });

    assert.deepEqual(s.upserts, []);
    assert.equal(runner.calls.length, 0, "no docker call for a compose that builds nothing");
  });
});

describe("a COPY whose source the installed bundle does not have", () => {
  /** A build context on disk: the Dockerfile plus the named files that really exist. */
  function context(dockerfileText, files) {
    const dir = mkdtempSync(join(tmpdir(), "crowcopyctx-"));
    writeFileSync(join(dir, "Dockerfile"), dockerfileText);
    for (const [name, content] of Object.entries(files)) writeFileSync(join(dir, name), content);
    return dir;
  }
  const EXISTING = { "package.json": PACKAGE_JSON, "entrypoint.sh": ENTRYPOINT, "cdp-relay.mjs": RELAY_INSTALLED };

  // The copy list is where an absent source is visible: the detector's own imageCopies()
  // filter would hide it one step later, so the control that it was ever considered lives
  // here, on the list dockerfileCopies() returns.
  test("the copy list leaves an absent source out, and keeps the sources that are there", () => {
    const dir = context(DOCKERFILE_ABSENT_SOURCE, EXISTING);
    try {
      const copies = dockerfileCopies(join(dir, "Dockerfile"), dir);
      assert.deepEqual(copies.map((c) => c.dest).sort(), ["/app/cdp-relay.mjs", "/app/entrypoint.sh", "/app/package.json"]);
      assert.equal(copies.some((c) => c.source.endsWith("extra.mjs")), false, "the absent source is not in the list at all");
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  // CONTROL: so the test above is not passing because COPY lines are skipped wholesale.
  test("CONTROL: the same Dockerfile with the source present lists it", () => {
    const dir = context(DOCKERFILE_ABSENT_SOURCE, { ...EXISTING, "extra.mjs": "// extra\n" });
    try {
      const copies = dockerfileCopies(join(dir, "Dockerfile"), dir);
      assert.deepEqual(copies.map((c) => c.dest).sort(), ["/app/cdp-relay.mjs", "/app/entrypoint.sh", "/app/extra.mjs", "/app/package.json"]);
    } finally { rmSync(dir, { recursive: true, force: true }); }
  });

  test("an absent source is not compared, and does not raise a card by itself", async () => {
    installBrowser({ files: { Dockerfile: DOCKERFILE_ABSENT_SOURCE } });
    const s = fakeStore();
    // The container holds SOMETHING at that destination, and it differs from nothing the
    // bundle has — there is no installed file to compare it with, so it says nothing.
    const runner = dockerStub({ containerFiles: { container1: { ...inContainer(), "/app/extra.mjs": "whatever the running image has\n" } } });

    await runCheck(s, { runner });

    assert.deepEqual(s.upserts, [], "an absent source is not evidence of a stale image");
    assert.ok(s.resolved.includes(resolvedKey()));
    assert.equal(execDests(runner).has("/app/extra.mjs"), false, "…and it was never hashed inside the container");
    assert.ok(execDests(runner).has("/app/cdp-relay.mjs"), "the sources that ARE installed were compared");
  });

  // CONTROL: with the source present, a differing container is exactly what the card is for.
  test("CONTROL: the source present and differing in the container → card", async () => {
    installBrowser({ files: { Dockerfile: DOCKERFILE_ABSENT_SOURCE, "extra.mjs": "// the installed one\n" } });
    const s = fakeStore();
    const runner = dockerStub({ containerFiles: { container1: { ...inContainer(), "/app/extra.mjs": "// the old one\n" } } });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1, "a source that IS installed and differs inside the container is stale");
    assert.ok(execDests(runner).has("/app/extra.mjs"));
  });
});

describe("the version sentence: what is running, and what the update would install", () => {
  test("the two sentences are the approved text, EN and ES, with their placeholders", () => {
    assert.deepEqual(COPY.versionKnown, APPROVED_VERSION_KNOWN);
    assert.deepEqual(COPY.versionUnknown, APPROVED_VERSION_UNKNOWN);
    assert.equal(COPY.versionKnown.es, "En marcha ahora: versión {running}. La actualización instalaría la versión {new}.");
    assert.equal(COPY.versionUnknown.es, "En marcha ahora: una versión anterior que no indica su número. La actualización instalaría la versión {new}.");
  });

  test("known: the container reports 1.9.2 and the installed bundle is 1.9.4 → the approved EN sentence, filled in", async () => {
    installBrowser({ version: "1.9.4" });
    const s = fakeStore();
    const runner = dockerStub({
      containerFiles: { container1: inContainer({ relay: RELAY_OLD }) },
      runningManifest: '{"id":"browser","name":"Browser Automation","version":"1.9.2"}\n',
    });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1);
    const card = s.upserts[0];
    assert.equal(
      card.why,
      `${COPY.body.en} ${fill(APPROVED_VERSION_KNOWN.en, { running: "1.9.2", new: "1.9.4" })}`,
      "the body, then ONE approved sentence with the real versions in it",
    );
    assert.ok(!card.why.includes("{"), "no placeholder is ever shown");
    assert.equal(card.context?.runningVersion, "1.9.2");
    assert.equal(card.context?.newVersion, "1.9.4");
    // The version really was read out of the running container, bounded like every exec.
    assert.equal(manifestCalls(runner).length, 1, "one version read, from the first differing container");
    assert.equal(typeof manifestCalls(runner)[0].opts?.timeout, "number", "the version read is time-bounded");
    assert.match(String(manifestCalls(runner)[0].args[3]), /^\/app\/manifest\.json$/, "from the image's own marker path");
  });

  for (const [what, runningManifest] of [
    ["the file is missing (an image built before the marker)", RUNNING_MANIFEST_MISSING],
    ["the answer is garbage", "{ not json at all\n"],
    ["the manifest has no version", '{"id":"browser","name":"Browser Automation"}\n'],
    ["the version is not a string", '{"id":"browser","version":19}\n'],
    ["the version is empty", '{"id":"browser","version":""}\n'],
  ]) {
    test(`unknown: ${what} → the approved unknown sentence, and the card is still raised`, async () => {
      installBrowser({ version: "1.9.4" });
      const s = fakeStore();
      const runner = dockerStub({ containerFiles: { container1: inContainer({ relay: RELAY_OLD }) }, runningManifest });

      await runCheck(s, { runner });

      assert.equal(s.upserts.length, 1, "the content evidence stands on its own: the card is not hidden");
      const card = s.upserts[0];
      assert.equal(card.why, `${COPY.body.en} ${fill(APPROVED_VERSION_UNKNOWN.en, { new: "1.9.4" })}`);
      assert.ok(!card.why.includes("{"), "no placeholder is ever shown");
      assert.equal(card.context?.runningVersion, null);
      assert.equal(card.context?.newVersion, "1.9.4");
    });
  }

  test("unknown: the version read TIMES OUT → no throw, the unknown sentence", async () => {
    installBrowser({ version: "1.9.4" });
    const s = fakeStore();
    const runner = dockerStub({
      containerFiles: { container1: inContainer({ relay: RELAY_OLD }) },
      runningManifest: RUNNING_MANIFEST_TIMEOUT,
    });

    await assert.doesNotReject(runCheck(s, { runner }));

    assert.equal(s.upserts.length, 1);
    assert.equal(s.upserts[0].why, `${COPY.body.en} ${fill(APPROVED_VERSION_UNKNOWN.en, { new: "1.9.4" })}`);
    assert.equal(s.upserts[0].context?.runningVersion, null);
  });

  // The running version is a `docker exec`'s stdout, so it is UNTRUSTED text that ends
  // up inside the approved sentence. Only a short, version-shaped string may be named;
  // anything else — a value that would inject the other placeholder, a newline, a
  // space, an over-long string, other characters — is UNKNOWN, exactly like a failed
  // read. Otherwise a container could write the card's copy.
  for (const [what, raw] of [
    ["the very placeholder {new}", "{new}"],
    ["a newline in the middle", "1.9.2\nThe update would install version 9.9.9."],
    ["40 characters", `1.9.2${"0".repeat(35)}`],
    ["33 characters", `1.9.2${"0".repeat(28)}`],
    ["a space", "1.9.2 beta"],
    ["the other placeholder {running}", "{running}"],
    ["a brace and a space", "{ new }"],
  ]) {
    test(`sanitised: ${what} is never named — it is UNKNOWN, like a failed read`, async () => {
      installBrowser({ version: "1.9.4" });
      const s = fakeStore();
      const runner = dockerStub({
        containerFiles: { container1: inContainer({ relay: RELAY_OLD }) },
        runningManifest: JSON.stringify({ id: "browser", name: "Browser Automation", version: raw }),
      });

      await runCheck(s, { runner });

      assert.equal(s.upserts.length, 1, "the content evidence stands on its own: the card is still raised");
      const card = s.upserts[0];
      assert.equal(
        card.why,
        `${COPY.body.en} ${fill(APPROVED_VERSION_UNKNOWN.en, { new: "1.9.4" })}`,
        "the approved UNKNOWN sentence, byte for byte",
      );
      assert.equal(card.context?.runningVersion, null, "the untrusted value is not even stored");
      assert.equal(card.context?.newVersion, "1.9.4");
      // The container's text reached neither the sentence nor the context: in particular
      // `{new}` could not fill itself in and pretend a version was known.
      assert.ok(!card.why.includes("9.9.9"), "nothing the container wrote lands in the card text");
      assert.ok(!card.why.includes("{running}"));
      assert.ok(!card.why.includes("beta"));
      // The version WAS read, so this is the sanitiser's doing and not a skipped read.
      assert.equal(manifestCalls(runner).length, 1);
    });
  }

  // CONTROL: a real version string with the pattern's own characters is still named.
  test("CONTROL: a normal 1.9.2, and a 32-character build string, are still named", async () => {
    for (const version of ["1.9.2", `1.9.2${"0".repeat(27)}`, "1.9.2-rc.1+build.5"]) {
      installBrowser({ version: "1.9.4" });
      const s = fakeStore();
      const runner = dockerStub({
        containerFiles: { container1: inContainer({ relay: RELAY_OLD }) },
        runningManifest: JSON.stringify({ id: "browser", version }),
      });

      await runCheck(s, { runner });

      assert.equal(s.upserts.length, 1);
      const card = s.upserts[0];
      assert.equal(card.context?.runningVersion, version, `${version} is version-shaped, so it is shown`);
      assert.equal(card.why, `${COPY.body.en} ${fill(APPROVED_VERSION_KNOWN.en, { running: version, new: "1.9.4" })}`);
    }
  });

  test("the installed version is not version-shaped either → the sentence is LEFT OUT, never substituted", async () => {
    // The INSTALLED version is read from the bundle's manifest, and it is filled into the
    // same sentence: a value holding `{running}` would inject the other placeholder.
    installBrowser({ version: "1.9.4 {running}" });
    const s = fakeStore();
    const runner = dockerStub({
      containerFiles: { container1: inContainer({ relay: RELAY_OLD }) },
      runningManifest: '{"id":"browser","version":"1.9.2"}\n',
    });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1, "the card is still offered: the files differ");
    assert.equal(s.upserts[0].why, COPY.body.en, "the approved body only — never a sentence with a placeholder in it");
    assert.equal(s.upserts[0].context?.newVersion, null);
  });

  test("VERSION ONLY: the running marker says 1.9.3, the installed bundle 1.9.4, every compared file identical → NO card, and a pending one resolves", async () => {
    // The real Dockerfile copies manifest.json in, so the image really does carry it.
    installBrowser({ version: "1.9.4", files: { Dockerfile: REAL_DOCKERFILE } });
    const s = fakeStore();
    const runner = dockerStub({
      containerFiles: { container1: { ...inContainer(), "/app/manifest.json": '{"id":"browser","version":"1.9.3"}\n' } },
      runningManifest: '{"id":"browser","version":"1.9.3"}\n',
    });

    await runCheck(s, { runner });

    assert.deepEqual(s.upserts, [], "a manifest version difference on its own is not a stale image: nothing restarts for it");
    assert.ok(s.resolved.includes(resolvedKey()), "and a pending card resolves");
    assert.equal(execDests(runner).has("/app/manifest.json"), false, "manifest.json is never hashed: it is a marker, not a compared file");
    assert.deepEqual(manifestCalls(runner), [], "no card is going up, so nothing is read to name it");
    assert.ok(execDests(runner).has("/app/cdp-relay.mjs"), "the files that DO run were still compared");
  });

  test("two running containers: the version is read from the FIRST one that differs", async () => {
    installBrowser({ version: "1.9.4" });
    const s = fakeStore();
    const runner = dockerStub({
      ids: ["container1", "container2"],
      containerFiles: { container1: inContainer(), container2: inContainer({ relay: RELAY_OLD }) },
      runningManifest: '{"id":"browser","version":"1.9.0"}\n',
    });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1);
    assert.deepEqual(
      manifestCalls(runner).map((c) => execContainer(c.args, ["container1", "container2"])),
      ["container2"],
      "container1 matches, so the version comes from the one that differs",
    );
    assert.equal(s.upserts[0].context?.runningVersion, "1.9.0");
  });

  test("two running containers, BOTH differing: the version still comes from the first", async () => {
    installBrowser({ version: "1.9.4" });
    const s = fakeStore();
    const runner = dockerStub({
      ids: ["container1", "container2"],
      containerFiles: {
        container1: inContainer({ relay: RELAY_OLD }),
        container2: inContainer({ entrypoint: "#!/bin/sh\n" }),
      },
      runningManifest: '{"id":"browser","version":"1.9.0"}\n',
    });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1);
    assert.equal(s.upserts[0].context?.runningVersion, "1.9.0", "the FIRST differing container is the one asked");
  });

  test("CONTROL: the same manifest difference WITH a stale relay → card (the marker is added, not compared instead)", async () => {
    installBrowser({ version: "1.9.4", files: { Dockerfile: REAL_DOCKERFILE } });
    const s = fakeStore();
    const runner = dockerStub({
      containerFiles: { container1: { ...inContainer({ relay: RELAY_OLD }), "/app/manifest.json": '{"id":"browser","version":"1.9.3"}\n' } },
      runningManifest: '{"id":"browser","version":"1.9.3"}\n',
    });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1);
    assert.equal(s.upserts[0].context?.runningVersion, "1.9.3");
    assert.equal(s.upserts[0].context?.newVersion, "1.9.4");
    assert.equal(s.upserts[0].why, `${COPY.body.en} ${fill(APPROVED_VERSION_KNOWN.en, { running: "1.9.3", new: "1.9.4" })}`);
  });

  test("the installed manifest's version is unreadable → the version sentence is LEFT OUT (never a placeholder)", async () => {
    installBrowser({ version: "1.9.4" });
    put("bundles/browser/manifest.json", "{ not a manifest at all\n");
    const s = fakeStore();
    const runner = dockerStub({
      containerFiles: { container1: inContainer({ relay: RELAY_OLD }) },
      runningManifest: '{"id":"browser","version":"1.9.2"}\n',
    });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1, "the card is still offered: the files differ");
    assert.equal(s.upserts[0].why, COPY.body.en, "the approved body only — no sentence that would need a placeholder");
    assert.equal(s.upserts[0].context?.newVersion, null);
  });
});

describe("quiet: docker exec / sha256sum failing is no evidence either way", () => {
  test("(d) the exec times out → no card, no throw, and a pending card is left as it is", async () => {
    installBrowser();
    const s = fakeStore();
    const lines = [];
    const runner = dockerStub({
      execAnswer: () => {
        throw Object.assign(new Error("docker exec timed out after 20000ms"), { killed: true, signal: "SIGTERM" });
      },
    });

    await assert.doesNotReject(runCheck(s, { runner, log: { warn: (m) => lines.push(m) } }));

    assert.deepEqual(s.upserts, [], "a timeout is not evidence of a stale image");
    assert.deepEqual(s.resolved, [], "a pending card is left exactly as it is");
  });

  test("(d) the exec answers garbage → quiet, the pending card untouched", async () => {
    installBrowser();
    const s = fakeStore();
    const runner = dockerStub({
      execAnswer: () => ({ stdout: "Error response from daemon: container abc is not running\n", stderr: "" }),
    });

    await assert.doesNotReject(runCheck(s, { runner }));

    assert.deepEqual(s.upserts, []);
    assert.deepEqual(s.resolved, []);
  });

  test("(d) a non-zero exit with nothing parseable → quiet", async () => {
    installBrowser();
    const s = fakeStore();
    const runner = dockerStub({
      execAnswer: () => { throw Object.assign(new Error("OCI runtime exec failed"), { code: 126, stdout: "", stderr: "OCI runtime exec failed: exec failed: unable to start container process" }); },
    });

    await assert.doesNotReject(runCheck(s, { runner }));

    assert.deepEqual(s.upserts, []);
    assert.deepEqual(s.resolved, []);
  });

  test("(d) CONTROL: the same setup with good output makes a card", async () => {
    installBrowser();
    const s = fakeStore();
    const runner = dockerStub({ containerFiles: { container1: inContainer({ relay: RELAY_OLD }) } });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1, "so the quiet cases above were quiet for the right reason");
  });
});

describe("nothing to say", () => {
  test("the container is not running → no card, and the card resolves", async () => {
    installBrowser();
    const s = fakeStore();

    await runCheck(s, { runner: dockerStub({ ids: [], containerFiles: { container1: inContainer({ relay: RELAY_OLD }) } }) });

    assert.deepEqual(s.upserts, []);
    assert.ok(s.resolved.includes(resolvedKey()));
  });

  test("docker errors → no card, no throw, one log line", async () => {
    installBrowser();
    const s = fakeStore();
    const lines = [];
    const runner = async () => { throw new Error("docker: not found"); };

    await assert.doesNotReject(runCheck(s, { runner, log: { warn: (m) => lines.push(m) } }));

    assert.deepEqual(s.upserts, []);
    assert.deepEqual(s.resolved, [], "an unreachable docker is no evidence either way: the card is left as it is");
    assert.equal(lines.length, 1);
    assert.match(lines[0], /docker is not reachable/);
  });

  test("the bundle is not installed → no card", async () => {
    installBrowser({ installed: [] });
    const s = fakeStore();
    const runner = dockerStub({ containerFiles: { container1: inContainer({ relay: RELAY_OLD }) } });

    await runCheck(s, { runner });

    assert.deepEqual(s.upserts, []);
    assert.equal(runner.calls.length, 0);
  });

  test("another bundle's container change is not this pass's business", async () => {
    installBrowser();
    const s = fakeStore();
    const runner = dockerStub({ containerFiles: { container1: inContainer({ relay: RELAY_OLD }) } });

    await runCheck(s, { runner, only: ["browser-other"] });

    assert.deepEqual(s.upserts, []);
    assert.deepEqual(s.resolved, []);
    assert.equal(runner.calls.length, 0);
  });
});

describe("the Chromium-downgrade guard: no restart while the rebuild would go backwards", () => {
  // The restart this card offers runs `up -d --build --force-recreate`, which installs
  // the Chromium the installed lock pins (145). A container profile written by a NEWER
  // Chromium (159) makes Chromium crash-loop, so the card must not be offered at all.
  // Fail closed: an unknown lock, an unreadable profile or no container at all is a
  // refusal too — the card is HIDDEN, and no new copy is written for it.

  test("a stale relay and a profile written by Chromium 159 → NO card, and the pending card resolves", async () => {
    installBrowser();
    const s = fakeStore();
    const runner = dockerStub({ containerFiles: { container1: inContainer({ relay: RELAY_OLD }) }, profileVersion: PROFILE_159 });
    const lines = [];

    await runCheck(s, { runner, log: { warn: (m) => lines.push(m) } });

    assert.deepEqual(s.upserts, [], "the rebuild would install an older Chromium than the profile holds");
    assert.ok(s.resolved.includes(resolvedKey()), "the card is hidden, not left dangling");
    assert.equal(lines.length, 1, "one log line for the operator, and no user-facing copy");
    assert.match(lines[0], /older Chromium than the profile holds/);
    // It really read the profile before deciding.
    assert.ok(profileCalls(runner).length > 0, "the profile was read inside the container");
  });

  test("CONTROL: the same stale relay with a profile written by Chromium 145 → card", async () => {
    installBrowser();
    const s = fakeStore();
    const runner = dockerStub({ containerFiles: { container1: inContainer({ relay: RELAY_OLD }) }, profileVersion: PROFILE_145 });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1, "a rebuild that keeps the same Chromium is safe");
    assert.deepEqual(s.resolved, []);
  });

  test("an OLDER profile (Chromium 140) → card (that rebuild is an upgrade)", async () => {
    installBrowser();
    const s = fakeStore();
    const runner = dockerStub({ containerFiles: { container1: inContainer({ relay: RELAY_OLD }) }, profileVersion: "140.0.7000.1" });

    await runCheck(s, { runner });

    assert.equal(s.upserts.length, 1);
  });

  test("an unreadable profile → NO card and no upsert (fail closed)", async () => {
    installBrowser();
    const s = fakeStore();
    const runner = dockerStub({ containerFiles: { container1: inContainer({ relay: RELAY_OLD }) }, profileVersion: PROFILE_UNREADABLE });

    await assert.doesNotReject(runCheck(s, { runner }));

    assert.deepEqual(s.upserts, [], "we cannot tell what the profile holds, so the restart is not offered");
    assert.ok(s.resolved.includes(resolvedKey()));
  });

  test("the installed bundle has no lockfile → NO card (an unknown rebuild is never offered)", async () => {
    installBrowser({ lock: null });
    const s = fakeStore();
    const runner = dockerStub({ containerFiles: { container1: inContainer({ relay: RELAY_OLD }) } });

    await runCheck(s, { runner });

    assert.deepEqual(s.upserts, [], "what Chromium the rebuild installs is unknown");
    assert.ok(s.resolved.includes(resolvedKey()));
  });

  test("an unparseable lockfile → NO card either", async () => {
    installBrowser({ lock: "{ not a lock at all" });
    const s = fakeStore();
    const runner = dockerStub({ containerFiles: { container1: inContainer({ relay: RELAY_OLD }) } });

    await runCheck(s, { runner });

    assert.deepEqual(s.upserts, []);
    assert.ok(s.resolved.includes(resolvedKey()));
  });

  test("a lock pinning a playwright the table does not know → NO card", async () => {
    installBrowser({ lock: LOCKFILE.replaceAll("1.58.2", "1.99.0") });
    const s = fakeStore();
    const runner = dockerStub({ containerFiles: { container1: inContainer({ relay: RELAY_OLD }) } });

    await runCheck(s, { runner });

    assert.deepEqual(s.upserts, []);
    assert.ok(s.resolved.includes(resolvedKey()));
  });

  test("the guard is NOT consulted when the container already matches (nothing to offer)", async () => {
    installBrowser();
    const s = fakeStore();
    const runner = dockerStub({ containerFiles: { container1: inContainer() }, profileVersion: PROFILE_159 });

    await runCheck(s, { runner });

    assert.deepEqual(s.upserts, []);
    assert.ok(s.resolved.includes(resolvedKey()));
    assert.deepEqual(profileCalls(runner), [], "no restart is offered, so the profile need not be read");
  });
});

describe("the copy object", () => {
  test("every user-facing string is there in EN and ES, and none is empty", () => {
    for (const [key, value] of Object.entries(COPY)) {
      assert.equal(typeof value?.en, "string", `${key}.en exists`);
      assert.equal(typeof value?.es, "string", `${key}.es exists`);
      assert.ok(value.en.trim().length > 0, `${key}.en is not empty`);
      assert.ok(value.es.trim().length > 0, `${key}.es is not empty`);
      assert.notEqual(value.en, value.es, `${key} is really translated`);
    }
    assert.equal(COPY.restartAction.en, "Restart the browser add-on");
    // The card says plainly that a restart cannot be undone.
    assert.match(COPY.body.en, /cannot be undone/);
    assert.match(COPY.body.es, /no se puede deshacer/);
  });
});

describe("boot checks and the container-change re-check", () => {
  test("it runs through the gateway's boot checks", () => {
    assert.ok(idx.BOOT_CHECK_DETECTORS.some((d) => d.source === SOURCE));
  });

  test("the re-check after a Start/stop runs it, and it then clears the card", async () => {
    installBrowser();
    await db.execute("DELETE FROM fix_it_items");
    const staleRunner = dockerStub({ containerFiles: { container1: inContainer({ relay: RELAY_OLD }) } });

    // The bundle routes' own re-check (routes/bundles.js → runBootCheck("bundle-bind-drift"))
    // is the moment a container was just rebuilt: this detector rides it.
    await idx.runBootCheck(db, "bundle-bind-drift", { only: ["browser"], crowHome: home, runner: staleRunner, log: silent });
    let pending = await store.listPending(db);
    assert.equal(pending.filter((p) => p.source === SOURCE).length, 1, "the card is raised by the bundle routes' own re-check");

    // Same re-check, after the rebuild: the container holds the installed bytes now.
    const freshRunner = dockerStub({ containerFiles: { container1: inContainer() } });
    await idx.runBootCheck(db, "bundle-bind-drift", { only: ["browser"], crowHome: home, runner: freshRunner, log: silent });
    pending = await store.listPending(db);
    assert.equal(pending.filter((p) => p.source === SOURCE).length, 0, "the card clears once the new image is running");
  });

  test("a re-check for ANOTHER bundle leaves this card alone", async () => {
    installBrowser();
    await db.execute("DELETE FROM fix_it_items");
    await idx.runBootCheck(db, "bundle-bind-drift", {
      only: ["browser"], crowHome: home, log: silent,
      runner: dockerStub({ containerFiles: { container1: inContainer({ relay: RELAY_OLD }) } }),
    });
    assert.equal((await store.listPending(db)).filter((p) => p.source === SOURCE).length, 1);

    await idx.runBootCheck(db, "bundle-bind-drift", {
      only: ["something-else"], crowHome: home, log: silent,
      runner: dockerStub({ containerFiles: { container1: inContainer() } }),
    });
    assert.equal((await store.listPending(db)).filter((p) => p.source === SOURCE).length, 1, "still pending");
  });
});

describe("the restart action", () => {
  /** Put one real card in the real DB, through the boot-check path. */
  async function raiseCard() {
    installBrowser();
    await db.execute("DELETE FROM fix_it_items");
    await idx.runBootCheck(db, SOURCE, {
      crowHome: home, log: silent,
      runner: dockerStub({ containerFiles: { container1: inContainer({ relay: RELAY_OLD }) } }),
    });
    const pending = (await store.listPending(db)).filter((p) => p.source === SOURCE);
    assert.equal(pending.length, 1, "precondition: one card");
    return pending[0];
  }

  function click(item, props = {}) {
    let redirected = null;
    return idx.handleFixItAction(
      { body: { action: "remedy", item_id: String(item.id), action_id: ACTION_ID }, ...props },
      { redirectAfterPost: (u) => { redirected = u; } },
      { db },
    ).then(() => redirected);
  }

  test("the owner's click restarts the add-on exactly once, through the Extensions path, and resolves the card", async () => {
    const item = await raiseCard();
    const calls = [];
    setDeps({ owner: async () => true, guard: async () => ({ blocked: false }), restart: async (id) => { calls.push(id); return { ok: true }; } });

    const redirected = await click(item, { headers: { cookie: "crow_session=x" }, csrfToken: "t" });

    assert.deepEqual(calls, ["browser"], "one restart, for the browser bundle");
    assert.match(redirected, /flash=fixit_done/);
    assert.equal((await store.getItem(db, item.id)).status, "resolved");
  });

  test("a restart that did not run leaves the card open", async () => {
    const item = await raiseCard();
    setDeps({ owner: async () => true, guard: async () => ({ blocked: false }), restart: async () => ({ ok: false, reason: "docker compose up failed" }) });

    const redirected = await click(item);

    assert.match(redirected, /flash=fixit_error/);
    assert.equal((await store.getItem(db, item.id)).status, "pending", "the owner can try again");
  });

  test("refuses anyone but the owner, and restarts nothing", async () => {
    let called = 0;
    setDeps({ owner: async () => false, guard: async () => ({ blocked: false }), restart: async () => { called += 1; return { ok: true }; } });

    const out = await remedy.default({ bundle: "browser" }, { db: null, item: null, req: { headers: { cookie: "crow_session=x" } } });

    assert.equal(out.resolved, false);
    assert.equal(out.flash, OWNER_ONLY_FLASH, "the refusal is a flash the Nest can render");
    assert.equal(out.message, "Only the owner, signed in on this Crow, can do that.");
    assert.equal(called, 0);
    assert.ok(idx.REMEDY_FLASHES.includes(OWNER_ONLY_FLASH));
  });

  test("the action is registered, and a stored card cannot pick another bundle", async () => {
    const item = await raiseCard();
    const calls = [];
    setDeps({ owner: async () => true, guard: async () => ({ blocked: false }), restart: async (id) => { calls.push(id); return { ok: true }; } });
    // `args` is crow.db data: the remedy ignores it and restarts the bundle it holds.
    await db.execute({
      sql: "UPDATE fix_it_items SET remedies = ? WHERE id = ?",
      args: [JSON.stringify([{ actionId: ACTION_ID, kind: "instant", label: "x", args: { bundle: "../../etc" } }]), item.id],
    });

    await click(item);

    assert.deepEqual(calls, ["browser"]);
  });

  test("the default path never dials the Extensions route without a session to carry", async () => {
    // No injected restart: the real one runs, which refuses before any network call
    // when the request carries no dashboard session cookie (nothing to send).
    setDeps({ owner: async () => true, guard: async () => ({ blocked: false }) });

    const out = await remedy.default({}, { db: null, item: null, req: { headers: {} } });

    assert.equal(out.resolved, false);
    assert.equal(out.flash, undefined, "the Nest's generic failure line, not a made-up sentence");
  });

  test('"Not now" changes nothing: the card is answered and nothing is restarted', async () => {
    const item = await raiseCard();
    let called = 0;
    setDeps({ owner: async () => true, guard: async () => ({ blocked: false }), restart: async () => { called += 1; return { ok: true }; } });

    let redirected = null;
    await idx.handleFixItAction(
      { body: { action: "dismiss", item_id: String(item.id) } },
      { redirectAfterPost: (u) => { redirected = u; } },
      { db },
    );

    assert.match(redirected, /flash=fixit_dismissed/);
    assert.equal(called, 0, "dismissing never restarts anything");
    const row = await store.getItem(db, item.id);
    assert.equal(row.status, "dismissed");
    assert.equal((await store.listPending(db)).filter((p) => p.source === SOURCE).length, 0);
  });
});