/**
 * The browser image installs the committed dependency tree.
 *
 * `COPY package.json ./` plus `RUN npm install` re-resolves `^` ranges at build
 * time, so the image could carry a newer Playwright than package-lock.json pins.
 * The Dockerfile must copy the lockfile and install with `npm ci`.
 *
 * Static only: the Dockerfile text, package-lock.json's presence and the build
 * context's .dockerignore.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { existsSync, readFileSync } from "node:fs";
import { join, resolve } from "node:path";

const BUNDLE = resolve(import.meta.dirname, "..", "bundles", "browser");
const read = (file) => readFileSync(join(BUNDLE, file), "utf-8");

/** Lines that are not comments and not blank, trimmed. */
const codeLines = (text) => text
  .split("\n")
  .map((line) => line.trim())
  .filter((line) => line !== "" && !line.startsWith("#"));

/** The source operands of a COPY line (the last operand is the destination). */
function copySources(line) {
  const rest = line.replace(/^COPY\s+/i, "");
  const operands = rest.startsWith("[") ? JSON.parse(rest) : rest.split(/\s+/);
  return operands.slice(0, -1);
}

function copiesLockfile(text) {
  return codeLines(text)
    .filter((line) => /^COPY\s/i.test(line))
    .some((line) => copySources(line).includes("package-lock.json"));
}

function runsNpmCi(text) {
  return codeLines(text)
    .filter((line) => /^RUN\s/i.test(line))
    .some((line) => /\bnpm\s+ci\b/.test(line));
}

function runsNpmInstall(text) {
  return codeLines(text)
    .filter((line) => /^RUN\s/i.test(line))
    .some((line) => /\bnpm\s+install\b/.test(line));
}

test("the image copies the lockfile and installs with npm ci", () => {
  assert.ok(existsSync(join(BUNDLE, "package-lock.json")), "bundles/browser/package-lock.json must be committed");
  const df = read("Dockerfile");
  assert.ok(copiesLockfile(df), "the Dockerfile must COPY package-lock.json into the image");
  assert.ok(runsNpmCi(df), "the dependency layer must run `npm ci`");
  assert.equal(runsNpmInstall(df), false, "`npm install` re-resolves the lockfile's ranges at build time");
});

// CONTROL: the checks above are not vacuous — the pre-fix shape is rejected.
test("CONTROL: the same checks reject a Dockerfile that copies no lockfile and runs npm install", () => {
  const stale = [
    "FROM ubuntu:22.04",
    "WORKDIR /app",
    "COPY package.json ./",
    "RUN npm install",
    "",
  ].join("\n");
  assert.equal(copiesLockfile(stale), false, "no package-lock.json in any COPY");
  assert.equal(runsNpmCi(stale), false, "no `npm ci`");
  assert.equal(runsNpmInstall(stale), true, "the control still sees `npm install`");

  const fixed = [
    "FROM ubuntu:22.04",
    "COPY package.json package-lock.json ./",
    "RUN npm ci",
    "",
  ].join("\n");
  assert.equal(copiesLockfile(fixed), true);
  assert.equal(runsNpmCi(fixed), true);
  assert.equal(runsNpmInstall(fixed), false);
});

// ─── the lockfile survives the build context ────────────────────────────────

/** One .dockerignore pattern → an anchored RegExp over a context-relative path. */
function patternToRegExp(pattern) {
  const segments = pattern.split("/").map((segment) => {
    if (segment === "**") return null;
    return segment
      .replace(/[.+^${}()|[\]\\]/g, "\\$&")
      .replace(/\*/g, "[^/]*")
      .replace(/\?/g, "[^/]");
  });
  let source = "";
  segments.forEach((segment, i) => {
    const last = i === segments.length - 1;
    if (segment === null) source += last ? ".*" : "(?:[^/]+/)*";
    else source += segment + (last ? "" : "/");
  });
  return new RegExp(`^${source}$`);
}

/** Docker's semantics: last matching line wins, and an excluded parent keeps children out. */
function dockerIgnoreMatcher(text) {
  const patterns = codeLines(text).map((line) => {
    const negated = line.startsWith("!");
    const body = (negated ? line.slice(1) : line).replace(/^\.?\//, "").replace(/\/+$/, "");
    return { negated, re: patternToRegExp(body) };
  });
  const lastMatch = (path) => {
    let hit;
    for (const pattern of patterns) if (pattern.re.test(path)) hit = pattern;
    return hit;
  };
  return (path) => {
    const parts = path.replace(/^\.?\//, "").replace(/\/+$/, "").split("/").filter(Boolean);
    let excluded = false;
    for (let i = 1; i <= parts.length; i++) {
      const hit = lastMatch(parts.slice(0, i).join("/"));
      if (hit) excluded = !hit.negated;
    }
    return excluded;
  };
}

test("the build context's .dockerignore does not exclude the lockfile", () => {
  // `docker-compose.yml` builds with `context: .`, i.e. bundles/browser itself.
  assert.match(read("docker-compose.yml"), /^\s+context: \.$/m, "the build context is this bundle directory");
  const ignorePath = join(BUNDLE, ".dockerignore");
  if (!existsSync(ignorePath)) return;
  const excludedBy = dockerIgnoreMatcher(readFileSync(ignorePath, "utf-8"));
  assert.equal(excludedBy("package-lock.json"), false, ".dockerignore must let the lockfile into the context");
  // CONTROL: the matcher is not vacuous — this context really does exclude node_modules.
  assert.equal(excludedBy("node_modules"), true, "the control pattern is excluded");
});