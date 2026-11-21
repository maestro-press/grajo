/**
 * The browser image's Chromium DOWNGRADE GUARD, run for real — shell-level behaviour.
 *
 * Chromium cannot open a profile written by a NEWER major: it refuses, then crash-loops.
 * bundles/browser/entrypoint.sh therefore compares the image's recorded Chromium
 * (/opt/crow-chromium-version, written at build time) with the version that last wrote the
 * profile ("Last Version"), and stops the container loudly when the profile is ahead. Until
 * now only its SHAPE was tested (tests/browser-chromium-floor.test.js (e)): a comparison that
 * reads the wrong file, compares the wrong way or forgets `10#` would still have passed.
 *
 * So this file RUNS it. The guard block and its `die_after_sleep` helper are extracted from
 * the real entrypoint text at test time (by their own markers — a marker that went missing
 * fails every test here, loudly), dropped into a small bash harness with `log()`,
 * PROFILE_DIR, CROW_CHROMIUM_VERSION_FILE and CROW_DOWNGRADE_REFUSE_SLEEP stubbed, and run
 * under the same `set` line the real script uses. Nothing is mocked beyond the harness: the
 * assertions are the exit status, the log lines and the marker file.
 *
 * The refusal's SLEEP is the one case that cannot be run to completion — a non-numeric
 * CROW_DOWNGRADE_REFUSE_SLEEP falls back to 30 s — so it is checked statically on the
 * extracted text AND behaviourally by killing the child at 3 s.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

const ENTRYPOINT = fileURLToPath(new URL("../bundles/browser/entrypoint.sh", import.meta.url));
const SOURCE = readFileSync(ENTRYPOINT, "utf8");

/** The version this image records (Chromium 159.0.8154.6, the 1.9.1 lock). */
const IMAGE = "159.0.8154.6";

/**
 * The guard block: from its own banner to the `fi` that closes its if/elif chain. The end
 * marker is the block's own "ok" log line plus that `fi` — the block contains inner `if`s,
 * so the first bare `fi` is NOT the end.
 */
const GUARD_START = "# --- Chromium downgrade guard ---";
const GUARD_END = 'log "profile last opened by Chromium ${PROFILE_CHROMIUM}; image has ${IMAGE_CHROMIUM}: ok"\nfi';

/** The helper the guard calls: its definition, opening brace to the closing one. */
const HELPER_START = "die_after_sleep() {";
const HELPER_END = "\n}\n";

/** The exact fatal the guard prints on a downgrade — the sentence an operator reads at 3 a.m. */
const FATAL_999 =
  "[crow-browser] FATAL: this profile was last opened by Chromium 999.0.0.1, newer than this " +
  "image's 159.0.8154.6; Chromium cannot open a newer profile. Rebuild with the current add-on " +
  "or restore the previous image.";

/** A marker missing from the real file fails loudly instead of extracting nothing. */
function sliceBetween(text, startMarker, endMarker, what) {
  const start = text.indexOf(startMarker);
  assert.ok(start >= 0, `${ENTRYPOINT} no longer contains the ${what} start marker ${JSON.stringify(startMarker)}`);
  const end = text.indexOf(endMarker, start);
  assert.ok(end >= 0, `${ENTRYPOINT} no longer contains the ${what} end marker after it: ${JSON.stringify(endMarker)}`);
  return text.slice(start, end + endMarker.length);
}

let pieces = null;
/** The two extracted pieces plus the strict-mode line, read once from the real script. */
function extracted() {
  if (pieces) return pieces;
  const helper = sliceBetween(SOURCE, HELPER_START, HELPER_END, "die_after_sleep helper");
  // `set -uo pipefail` in the real script: the harness must keep its strictness (-u would
  // have caught a guard that reads an unset name), so the line is copied, not restated.
  const setLine = SOURCE.split("\n").map((line) => line.trim()).find((line) => /^set\s+-/.test(line));
  assert.ok(setLine, `${ENTRYPOINT} has no \`set\` line for the harness to mirror`);
  pieces = {
    guard: sliceBetween(SOURCE, GUARD_START, GUARD_END, "downgrade guard"),
    helper,
    setLine,
  };
  return pieces;
}

/** Single-quote a value for the harness (temp paths, and nothing else, ever go in here). */
const shQuote = (value) => `'${String(value).replace(/'/g, `'\\''`)}'`;

/**
 * One harness run in its own temp dir: a profile dir (with an optional "Last Version" and an
 * optional stale marker) and the image's version file (or none). Returns what the guard did.
 */
function runGuard(t, { profileVersion = null, imageVersion = IMAGE, refuseSleep = "0", staleMarker = false, timeout = 30_000 } = {}) {
  const { guard, helper, setLine } = extracted();
  const dir = mkdtempSync(join(tmpdir(), "crow-downgrade-guard-"));
  t.after(() => rmSync(dir, { recursive: true, force: true }));

  const profileDir = join(dir, "profile");
  mkdirSync(profileDir, { recursive: true });
  const lastVersion = join(profileDir, "Last Version");
  // Chromium writes "Last Version" with NO trailing newline; the guard reads it with `read -r`,
  // whose status is non-zero at EOF without one — the cases below cover both shapes.
  if (profileVersion !== null) writeFileSync(lastVersion, profileVersion);
  const marker = join(profileDir, ".crow-downgrade-refused");
  if (staleMarker) writeFileSync(marker, "profile=158.0.7000.1 image=159.0.8154.6 at=2020-01-01T00:00:00Z\n");

  const imageFile = join(dir, "crow-chromium-version");
  if (imageVersion !== null) writeFileSync(imageFile, `${imageVersion}\n`);

  const helperPath = join(dir, "die_after_sleep.sh");
  const guardPath = join(dir, "downgrade-guard.sh");
  writeFileSync(helperPath, `${helper}\n`);
  writeFileSync(guardPath, `${guard}\n`);

  const harnessPath = join(dir, "harness.sh");
  writeFileSync(
    harnessPath,
    [
      "#!/bin/bash",
      setLine,
      'log() { echo "[crow-browser] $*"; }',
      `PROFILE_DIR=${shQuote(profileDir)}`,
      `CROW_CHROMIUM_VERSION_FILE=${shQuote(imageFile)}`,
      `CROW_DOWNGRADE_REFUSE_SLEEP=${shQuote(refuseSleep)}`,
      `source ${shQuote(helperPath)}`,
      `source ${shQuote(guardPath)}`,
      "",
    ].join("\n"),
  );

  const started = Date.now();
  const result = spawnSync("bash", [harnessPath], {
    encoding: "utf8",
    timeout,
    // A hermetic environment: nothing from the test runner's own env may reach the guard.
    env: { PATH: process.env.PATH || "/usr/local/bin:/usr/bin:/bin", HOME: dir, LC_ALL: "C" },
  });
  const elapsedMs = Date.now() - started;

  return {
    dir,
    result,
    elapsedMs,
    status: result.status,
    signal: result.signal,
    stdout: result.stdout ?? "",
    stderr: result.stderr ?? "",
    logs: `${result.stdout ?? ""}${result.stderr ?? ""}`,
    marker,
    markerExists: () => existsSync(marker),
    markerText: () => (existsSync(marker) ? readFileSync(marker, "utf8") : ""),
    imageFile,
  };
}

// ---------------------------------------------------------------------------------------
// the extracted pieces are the right ones
// ---------------------------------------------------------------------------------------

test("the extracted block IS the guard and its helper (markers found, shapes intact)", () => {
  const { guard, helper, setLine } = extracted();

  assert.ok(guard.startsWith(GUARD_START), "the guard starts at its banner");
  assert.ok(guard.endsWith("\nfi"), "the guard ends at its closing fi");
  assert.match(guard, /PROFILE_LAST_VERSION="\$PROFILE_DIR\/Last Version"/, "the guard reads the profile's Last Version");
  assert.match(guard, /REFUSED_MARKER="\$PROFILE_DIR\/\.crow-downgrade-refused"/, "the guard writes its marker in the profile");
  assert.match(guard, /CROW_DOWNGRADE_REFUSE_SLEEP:-30/, "the delay defaults to 30 s and is overridable");
  assert.match(guard, /die_after_sleep "\$REFUSE_SLEEP" "this profile was last opened by Chromium \$\{PROFILE_CHROMIUM\}, newer than this image's \$\{IMAGE_CHROMIUM\}/, "the guard refuses through the delayed fatal");
  // The inner `if`s are inside the block: the extraction must not stop at their `fi`.
  assert.equal(guard.split("\n").filter((line) => line === "fi").length, 3, "the block carries all three of its `fi` lines (read file, read profile, the chain's)");

  // Helper order: the line is printed at once, the sleep delays only the exit.
  const printAt = helper.indexOf("FATAL:");
  const sleepAt = helper.search(/\bsleep\s+"\$seconds"/);
  const exitAt = helper.indexOf("exit 1");
  assert.ok(printAt >= 0 && sleepAt > printAt, "die_after_sleep prints the FATAL line before it sleeps");
  assert.ok(exitAt > sleepAt, "die_after_sleep sleeps before it exits");

  assert.match(setLine, /^set -/, "the harness mirrors the script's own `set` line");
});

// ---------------------------------------------------------------------------------------
// no downgrade: the guard stays out of the way
// ---------------------------------------------------------------------------------------

test("profile 159.0.8154.6 (no trailing newline, as Chromium writes it) with a 159 image: ok, no marker", (t) => {
  const run = runGuard(t, { profileVersion: "159.0.8154.6" });

  assert.equal(run.status, 0, `the guard must not refuse an equal profile:\n${run.logs}`);
  assert.match(run.stdout, /: ok/, "the guard logs the comparison as ok");
  assert.doesNotMatch(run.logs, /FATAL/, "no fatal on an equal profile");
  assert.equal(run.markerExists(), false, "an equal profile leaves no refusal marker");
});

test("profile 158.x with a 159 image: ok, no marker (an upgrade is Chromium's own business)", (t) => {
  const run = runGuard(t, { profileVersion: "158.0.7300.0" });

  assert.equal(run.status, 0, `an older profile must start:\n${run.logs}`);
  assert.match(run.stdout, /profile last opened by Chromium 158\.0\.7300\.0; image has 159\.0\.8154\.6: ok/);
  assert.equal(run.markerExists(), false, "an older profile leaves no refusal marker");
});

test("profile major 0159 is 159, not newer than the image (leading zeros are decimal, not octal)", (t) => {
  const run = runGuard(t, { profileVersion: "0159.0.0.1" });

  assert.equal(run.status, 0, `a leading-zero major must compare as 159:\n${run.logs}`);
  assert.match(run.stdout, /: ok/, "0159.0.0.1 vs a 159 image compares as equal");
  assert.equal(run.markerExists(), false, "a non-newer profile leaves no refusal marker");
});

test("a stale refusal marker is removed once the profile is not newer", (t) => {
  const run = runGuard(t, { profileVersion: "158.0.7300.0", staleMarker: true });

  assert.equal(run.status, 0, `an older profile must start:\n${run.logs}`);
  assert.equal(run.markerExists(), false, "the leftover marker from an earlier refusal is gone");
});

// ---------------------------------------------------------------------------------------
// the refusal
// ---------------------------------------------------------------------------------------

test("profile 999.0.0.1 with a 159 image: the exact fatal, exit 1, and the marker records both versions", (t) => {
  const run = runGuard(t, { profileVersion: "999.0.0.1" });

  assert.equal(run.status, 1, `a newer profile must stop the container:\n${run.logs}`);
  // The sentence, exactly: it is what an operator reads at 3 a.m.
  assert.ok(run.stderr.includes(FATAL_999), `stderr carries the exact fatal sentence.\n--- stderr ---\n${run.stderr}`);

  assert.equal(run.markerExists(), true, "the refusal leaves .crow-downgrade-refused in the profile");
  assert.ok(
    run.markerText().startsWith("profile=999.0.0.1 image=159.0.8154.6"),
    `the marker records both versions (got ${JSON.stringify(run.markerText())})`,
  );
});

test("the refusal sleeps CROW_DOWNGRADE_REFUSE_SLEEP seconds, not 0 and not 30", (t) => {
  const run = runGuard(t, { profileVersion: "999.0.0.1", refuseSleep: "1" });

  assert.equal(run.status, 1, `the refusal still exits 1 after its sleep:\n${run.logs}`);
  assert.ok(run.elapsedMs >= 900, `the refusal waited ~1 s before exiting (waited ${run.elapsedMs} ms)`);
  assert.ok(run.elapsedMs < 10_000, `the refusal did not fall back to the 30 s default (waited ${run.elapsedMs} ms)`);
});

test("a non-numeric CROW_DOWNGRADE_REFUSE_SLEEP falls back to 30 s", (t) => {
  // Static first: the fallback line is in the extracted guard text, so the behaviour below is
  // explained by the source and not by a stray default.
  assert.match(extracted().guard, /\[\[ "\$REFUSE_SLEEP" =~ \^\[0-9\]\+\$ \]\] \|\| REFUSE_SLEEP=30/, "the guard rejects a non-numeric delay and falls back to 30");

  // Behavioural: "abc" must become 30 s, so the child is still asleep when killed at 3 s. It is
  // never run to completion — a 30 s wait per test run is not worth it.
  const run = runGuard(t, { profileVersion: "999.0.0.1", refuseSleep: "abc", timeout: 3_000 });

  assert.equal(run.signal, "SIGTERM", `the refusal was still sleeping at 3 s and was killed by the timeout (signal ${run.signal}, status ${run.status})`);
  assert.equal(run.status, null, "the killed child has no exit status of its own");
  assert.ok(run.elapsedMs >= 2_500, `the child ran until the 3 s timeout (ran ${run.elapsedMs} ms)`);
  // The FATAL line is printed BEFORE the sleep, so a killed refusal still left it in the log.
  assert.ok(run.stderr.includes(FATAL_999), `the fatal was printed before the sleep, so the timeout did not lose it:\n${run.stderr}`);
});

// ---------------------------------------------------------------------------------------
// nothing to compare: skip, never guess
// ---------------------------------------------------------------------------------------

test("no Last Version in the profile: skip, exit 0 (a fresh profile is Chromium's call)", (t) => {
  const run = runGuard(t, { profileVersion: null });

  assert.equal(run.status, 0, `a fresh profile must start:\n${run.logs}`);
  assert.match(run.stdout, /no Chromium version in the profile .*nothing to compare, Chromium decides/, "the guard says why it skipped");
  assert.doesNotMatch(run.logs, /FATAL/, "a skipped comparison is not a fatal");
  assert.equal(run.markerExists(), false, "a skipped comparison leaves no marker");
});

test("a garbage Last Version: skip, exit 0", (t) => {
  const run = runGuard(t, { profileVersion: "abc" });

  assert.equal(run.status, 0, `an unparseable profile version must not stop the container:\n${run.logs}`);
  assert.match(run.stdout, /no Chromium version in the profile \('abc'/, "the skip names the value it could not read");
  assert.doesNotMatch(run.logs, /FATAL/, "an unparseable profile version is not a fatal");
  assert.equal(run.markerExists(), false, "a skipped comparison leaves no marker");
});

test("no image version file: skip with a warning, exit 0", (t) => {
  const run = runGuard(t, { profileVersion: "999.0.0.1", imageVersion: null });

  assert.equal(run.status, 0, `an image without a recorded version must still start:\n${run.logs}`);
  assert.match(run.stdout, /warning: this image's Chromium version \(''\) is unreadable from /, "the skip is a warning, not silence");
  assert.match(run.stdout, /skipping the downgrade guard/, "the warning names the guard it skipped");
  assert.doesNotMatch(run.logs, /FATAL/, "a missing image version is not a fatal");
  assert.equal(run.markerExists(), false, "a skipped comparison leaves no marker");
});