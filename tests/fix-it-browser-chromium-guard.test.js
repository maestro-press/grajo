/**
 * The Chromium-downgrade guard — tests/fix-it-browser-chromium-guard.test.js
 *
 * The Fix-it card "Restart the browser add-on" runs `up -d --build --force-recreate`
 * (remedies/restart-browser-addon.js). The rebuild installs whatever
 * bundles/browser/package-lock.json pins — playwright-core 1.58.2, whose Chromium is
 * 145 — while the RUNNING container's persistent profile may have been written by a
 * NEWER Chromium (159). Chromium refuses, and crash-loops on, a profile written by a
 * newer version, so offering that restart would take the add-on down for good.
 *
 * browsers.js of an installed bundle is not here: the installed bundle dir holds only
 * package-lock.json, and a host node_modules/playwright-core may be anything at all —
 * it is NOT what the image's `npm ci` installs. The lock is the authority, and
 * PLAYWRIGHT_CHROMIUM_MAJOR maps that pin to the Chromium it downloads. An unknown
 * playwright version is unknown, so it fails closed (no card, no restart), and the
 * table-drift test at the bottom makes a lock bump that forgets the table fail CI.
 *
 * No docker here: every call goes through the injected runner.
 */
import { test, describe, before, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const REPO_BUNDLE = join(import.meta.dirname, "..", "bundles", "browser");
const PROFILE_PATH = "/root/.config/chromium-crow/Last Version";

let guard;
let home;
let scratch;

before(async () => {
  // CROW_HOME before the import: the module reads bundles-config at load time.
  home = mkdtempSync(join(tmpdir(), "crowhome-chromeguard-"));
  process.env.CROW_HOME = home;
  guard = await import("../servers/gateway/fix-it/browser-chromium-guard.js");
  scratch = mkdtempSync(join(tmpdir(), "crowchromeguard-"));
});

after(() => {
  delete process.env.CROW_HOME;
  for (const d of [home, scratch]) { try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
});

/** A lockfile body pinning playwright-core to `version`. */
function lockWith(version) {
  return `${JSON.stringify({
    name: "crow-browser",
    lockfileVersion: 3,
    packages: {
      "": { name: "crow-browser", dependencies: { playwright: "^1.49.0" } },
      "node_modules/playwright": { version, dependencies: { "playwright-core": version } },
      "node_modules/playwright-core": { version },
    },
  }, null, 2)}\n`;
}

/** A bundle dir holding `package-lock.json` (or nothing, with `lock: null`). */
function bundleDir(lock) {
  const dir = mkdtempSync(join(scratch, "bundle-"));
  if (lock !== null) writeFileSync(join(dir, "package-lock.json"), lock);
  return dir;
}

/** A runner that answers the profile read with `stdout` (or throws `error`). */
function runner(answer) {
  const calls = [];
  const run = async (cmd, args, opts) => {
    calls.push({ cmd, args: [...args], opts });
    if (answer instanceof Error) throw answer;
    if (typeof answer === "function") return answer({ cmd, args, opts });
    if (answer && typeof answer === "object") return answer;
    return { stdout: answer, stderr: "" };
  };
  run.calls = calls;
  return run;
}

describe("bundledChromiumMajor: what the image's `npm ci` actually installs", () => {
  test("the repo bundle's own lock → the Chromium its playwright-core downloads", () => {
    assert.equal(guard.bundledChromiumMajor(REPO_BUNDLE), 145);
  });

  test("no package-lock.json in the installed bundle dir → null (unknown)", () => {
    assert.equal(guard.bundledChromiumMajor(bundleDir(null)), null);
  });

  test("a directory that does not exist → null", () => {
    assert.equal(guard.bundledChromiumMajor(join(scratch, "no-such-bundle")), null);
  });

  test("a playwright-core version the table does not know → null (fail closed)", () => {
    assert.equal(guard.bundledChromiumMajor(bundleDir(lockWith("1.99.0"))), null);
  });

  test("a lock with no playwright-core entry at all → null", () => {
    const lock = JSON.stringify({ lockfileVersion: 3, packages: { "node_modules/playwright": { version: "1.58.2" } } });
    assert.equal(guard.bundledChromiumMajor(bundleDir(lock)), null);
  });

  test("an unparseable lock → null", () => {
    assert.equal(guard.bundledChromiumMajor(bundleDir("{ not json")), null);
  });
});

describe("profileChromiumMajor: the major Chromium last wrote this profile", () => {
  test("`Last Version` 159.0.8154.6 → 159, read through the bounded docker exec", async () => {
    const run = runner("159.0.8154.6\n");

    assert.equal(await guard.profileChromiumMajor("container1", run), 159);

    assert.equal(run.calls.length, 1);
    assert.equal(run.calls[0].cmd, "docker");
    assert.deepEqual(run.calls[0].args, ["exec", "container1", "cat", PROFILE_PATH]);
    assert.equal(typeof run.calls[0].opts?.timeout, "number", "the read is time-bounded");
  });

  test("a trailing newline and surrounding spaces are trimmed", async () => {
    assert.equal(await guard.profileChromiumMajor("container1", runner("  145.0.7632.6 \n")), 145);
  });

  test("no version component → null", async () => {
    assert.equal(await guard.profileChromiumMajor("container1", runner("145\n")), null);
  });

  test("garbage → null", async () => {
    assert.equal(await guard.profileChromiumMajor("container1", runner("cat: No such file or directory\n")), null);
  });

  test("empty output → null", async () => {
    assert.equal(await guard.profileChromiumMajor("container1", runner("")), null);
  });

  test("a throwing / timed-out exec → null", async () => {
    assert.equal(await guard.profileChromiumMajor("container1", runner(Object.assign(new Error("timed out"), { killed: true }))), null);
  });
});

describe("restartWouldDowngrade: the restart is offered only when it cannot go backwards", () => {
  const downgrade = (ids, answer, lock = lockWith("1.58.2")) =>
    guard.restartWouldDowngrade({ bundleDir: bundleDir(lock), ids, runner: runner(answer) });

  test("bundled 145, profile 159 → BLOCKED (this is the bug the guard exists for)", async () => {
    const out = await downgrade(["container1"], "159.0.8154.6\n");

    assert.equal(out.blocked, true);
    assert.equal(out.bundled, 145);
    assert.deepEqual(out.profiles, [159]);
  });

  test("bundled 145, profile 145 → allowed (the same browser, a rebuild is safe)", async () => {
    const out = await downgrade(["container1"], "145.0.7632.6\n");

    assert.equal(out.blocked, false);
    assert.equal(out.bundled, 145);
    assert.deepEqual(out.profiles, [145]);
  });

  test("bundled 145, profile 140 → allowed (an upgrade)", async () => {
    const out = await downgrade(["container1"], "140.0.7000.1\n");

    assert.equal(out.blocked, false);
    assert.deepEqual(out.profiles, [140]);
  });

  test("two containers, one behind → BLOCKED (any of them is enough)", async () => {
    const dir = bundleDir(lockWith("1.58.2"));
    const run = runner(({ args }) => ({ stdout: args[1] === "container2" ? "159.1.0.0\n" : "145.0.7632.6\n", stderr: "" }));

    const out = await guard.restartWouldDowngrade({ bundleDir: dir, ids: ["container1", "container2"], runner: run });

    assert.equal(out.blocked, true);
    assert.deepEqual(out.profiles, [145, 159]);
  });

  test("an unreadable profile → BLOCKED (fail closed)", async () => {
    const out = await downgrade(["container1"], new Error("docker exec exited 1"));

    assert.equal(out.blocked, true);
    assert.deepEqual(out.profiles, [null]);
  });

  test("an unreadable lock → BLOCKED (we cannot know what the rebuild installs)", async () => {
    const out = await downgrade(["container1"], "145.0.7632.6\n", null);

    assert.equal(out.blocked, true);
    assert.equal(out.bundled, null);
  });

  test("a lock pinning a playwright nobody mapped → BLOCKED", async () => {
    const out = await downgrade(["container1"], "145.0.7632.6\n", lockWith("1.99.0"));

    assert.equal(out.blocked, true);
    assert.equal(out.bundled, null);
  });

  test("no running container → BLOCKED (nothing to allow the restart for)", async () => {
    const out = await guard.restartWouldDowngrade({ bundleDir: bundleDir(lockWith("1.58.2")), ids: [], runner: runner("145.0.7632.6\n") });

    assert.equal(out.blocked, true);
    assert.deepEqual(out.profiles, []);
  });

  test("never throws: a synchronous runner explosion is BLOCKED, not an exception", async () => {
    const run = () => { throw new Error("boom"); };

    const out = await guard.restartWouldDowngrade({ bundleDir: bundleDir(lockWith("1.58.2")), ids: ["container1"], runner: run });

    assert.equal(out.blocked, true);
  });

  test("a missing bundleDir/runner argument is BLOCKED, not an exception", async () => {
    await assert.doesNotReject(async () => {
      const out = await guard.restartWouldDowngrade({});
      assert.equal(out.blocked, true);
    });
  });
});

describe("runningBrowserContainerIds: the bundle's own compose project", () => {
  /**
   * An installed browser bundle; `composeBody === null` leaves the compose file out, and
   * `dotEnv` (a string) is written as the bundle's .env — the file Compose reads itself.
   */
  function installedBundle(composeBody, dotEnv = null) {
    const dir = mkdtempSync(join(scratch, "installed-"));
    writeFileSync(join(dir, "manifest.json"), JSON.stringify({ id: "browser", version: "1.8.0", docker: { composefile: "docker-compose.yml" } }));
    if (composeBody !== null) writeFileSync(join(dir, "docker-compose.yml"), composeBody);
    if (dotEnv !== null) writeFileSync(join(dir, ".env"), dotEnv);
    return dir;
  }

  test("asks docker for the running containers of the compose project", async () => {
    const dir = installedBundle("name: crow-browser\nservices:\n  crow-browser:\n    image: x:1\n");
    const run = runner({ stdout: "container1\ncontainer2\n", stderr: "" });

    const ids = await guard.runningBrowserContainerIds({ bundleDir: dir, runner: run });

    assert.deepEqual(ids, ["container1", "container2"]);
    assert.equal(run.calls.length, 1);
    assert.equal(run.calls[0].args[0], "ps");
    assert.ok(run.calls[0].args.includes("label=com.docker.compose.project=crow-browser"), run.calls[0].args.join(" "));
    assert.ok(run.calls[0].args.includes("status=running"));
    assert.equal(run.calls[0].opts?.timeout, 15_000);
  });

  test("docker failing → [] (never a throw)", async () => {
    const dir = installedBundle("name: crow-browser\nservices:\n  crow-browser:\n    image: x:1\n");

    assert.deepEqual(await guard.runningBrowserContainerIds({ bundleDir: dir, runner: runner(new Error("docker: not found")) }), []);
  });

  test("a bundle with no compose file → []", async () => {
    const dir = installedBundle(null);

    assert.deepEqual(await guard.runningBrowserContainerIds({ bundleDir: dir, runner: runner("container1\n") }), []);
  });

  // The browser bundle's compose names its project via a ${VAR:-default} that the
  // operator's bundle .env fills in (the same file Compose reads), so the lookup must
  // resolve it against that .env — normally, and to the default when the (.env) leaves
  // it unset. Only the gateway's OWN allowlisted variables are in the env passed here
  // (compose-guard's COMPOSE_ENV_KEYS), so process.env cannot stand in for the file.
  test("a ${VAR:-default} project name is resolved from the bundle .env, then from the default", async () => {
    const COMPOSE = "name: ${CROW_BROWSER_CONTAINER_NAME:-browser}\nservices:\n  browser:\n    image: x:1\n";

    const withEnv = runner("container1\n");
    const ids = await guard.runningBrowserContainerIds({
      bundleDir: installedBundle(COMPOSE, "CROW_BROWSER_CONTAINER_NAME=crow-browser-r4\n"),
      runner: withEnv,
    });

    assert.deepEqual(ids, ["container1"]);
    assert.equal(withEnv.calls.length, 1);
    assert.ok(
      withEnv.calls[0].args.includes("label=com.docker.compose.project=crow-browser-r4"),
      `the .env value names the project (got: ${withEnv.calls[0].args.join(" ")})`,
    );

    // CONTROL: the same compose with no .env value → the file's own default, not the
    // operator's container name (so the label came from that one file, not from luck).
    const bare = runner("container1\n");
    await guard.runningBrowserContainerIds({ bundleDir: installedBundle(COMPOSE), runner: bare });

    assert.equal(bare.calls.length, 1);
    assert.ok(
      bare.calls[0].args.includes("label=com.docker.compose.project=browser"),
      `the default applies without the .env value (got: ${bare.calls[0].args.join(" ")})`,
    );
    assert.ok(!bare.calls[0].args.includes("label=com.docker.compose.project=crow-browser-r4"));
  });
});

describe("the version table", () => {
  test("it is frozen", () => {
    assert.ok(Object.isFrozen(guard.PLAYWRIGHT_CHROMIUM_MAJOR));
  });

  // The drift guard: a lock bump that forgets the table would silently make the
  // restart card disappear (unknown → fail closed) instead of failing CI. This test
  // is what turns that silence into a red build.
  test("the repo bundle's playwright-core version is a key of PLAYWRIGHT_CHROMIUM_MAJOR", () => {
    const lock = JSON.parse(readFileSync(join(REPO_BUNDLE, "package-lock.json"), "utf8"));
    const version = lock?.packages?.["node_modules/playwright-core"]?.version;

    assert.equal(typeof version, "string", "bundles/browser/package-lock.json pins playwright-core");
    assert.ok(
      Object.prototype.hasOwnProperty.call(guard.PLAYWRIGHT_CHROMIUM_MAJOR, version),
      `PLAYWRIGHT_CHROMIUM_MAJOR has no entry for playwright-core ${version}: add the Chromium major its browsers.json downloads (bundles/browser/package-lock.json changed)`,
    );
  });
});