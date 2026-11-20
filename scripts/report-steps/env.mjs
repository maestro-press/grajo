/**
 * One report's dependency env, per language, cached by the hash of its requirements.
 *
 * Layout, below this instance's home:
 *
 *   <crowHome>/reports/<reportId>/env/<language>/            the env a run mounts read-only at /env
 *   <crowHome>/reports/<reportId>/env/<language>.marker      {"hash": ..., "language": ..., "builtAt": ...}
 *   <crowHome>/reports/<reportId>/env/.cache/                the resolvers' cache (uv, npm), writable in the wall
 *
 * The marker records the sha256 of the requirements text the env was built from. The same hash is
 * the same env and nothing is installed again; a different hash builds into a FRESH sibling folder and
 * then swaps it into place, so a run either sees the whole old env or the whole new one, never a
 * half-installed one. A leftover build folder from a crash is removed before the next build.
 *
 * One build at a time per report and language: in this process a promise map hands every waiter the
 * winner's result, and across processes `<env dir>.lock` (holding the owner's pid and the time it was
 * taken) makes a second build wait for the live holder. A lock whose process is gone is stale and is
 * taken over, so a build that died leaves the next one unblocked; a waiter that sees the marker appear
 * reuses the env instead of building it again.
 *
 * The requirements text, per language (this is the format, and nothing else is accepted):
 *
 *   python   A pip requirements FILE as text: one requirement per line, `#` comments and blank lines
 *            ignored. A line is a distribution name, an optional `[extras]` list, and optional version
 *            specifiers (`==`, `!=`, `<=`, `>=`, `<`, `>`, `~=`, `===`), optionally followed by a
 *            `; environment marker`. The marker may use the allowed variables and the operators `==`,
 *            `!=`, `<=`, `>=`, `<`, `>`, `~=`, `===`, `in` and `not in`, joined by `and`/`or` and
 *            parentheses, and nothing else. No URLs, no paths, no `@` references, no options
 *            (`-r`, `-e`, `--index-url`, `--find-links`, `--hash`, ...): the warm-up reaches three
 *            package hosts and installs from them only.
 *
 *   node     A JSON object with exactly two keys, each holding the TEXT of that file:
 *              {"package.json": "<file text>", "package-lock.json": "<file text>"}
 *            Both texts must themselves parse as JSON objects, and both are rebuilt from what is
 *            parsed, never handed on as written.
 *
 *            package.json keeps its name (a lower-case npm name, optionally `@scope/`), its version
 *            (a plain semver version) and its dependency maps (`dependencies`, `devDependencies`,
 *            `optionalDependencies`), and only those. A dependency spec is a semver range (digits,
 *            `x`/`X`/`*`, `^`, `~`, `>=`, `<=`, `>`, `<`, `=`, a hyphen range, `||`, and spaces
 *            between comparators) or a dist-tag word such as `latest`, and nothing else: a spec with a
 *            `/`, `:`, `\` or `@` in it, or one that starts with `.`, is a git, http(s), file, link,
 *            workspace, alias or path reference (`git+https:`, `github:`, `npm:other@1`, `user/repo`,
 *            `../x`, `~/x`), and is refused; so is any lifecycle script (`preinstall`, `install`,
 *            `postinstall`, `prepare`, `prepublish`, `dependencies`).
 *
 *            The lock is rebuilt from an allowlist. `lockfileVersion` 3 is accepted, and so is 2 with
 *            its parallel `dependencies` tree dropped (every entry in that tree is still checked, so a
 *            tree holding a link or a foreign tarball refuses the lock rather than vanishing). Only the
 *            `packages` map survives: the root entry `""` is rebuilt from package.json (its dependency
 *            names must be package.json's own), and every other key must be a nested `node_modules/...`
 *            path. A non-root entry must hold a plain semver `version`, a `resolved` that is an https
 *            URL on exactly `registry.npmjs.org`, and an `integrity` digest; an entry with `link`,
 *            `from`, `inBundle`, a missing or foreign `resolved`, or a version that is a range or a tag
 *            refuses the whole lock. Every other field is dropped, and `bin`/`hasInstallScript` are kept
 *            as data only: `npm ci` runs with `--ignore-scripts`, so no package's install script runs.
 *
 * A text is never handed on as written. Both formats are parsed into records and the bytes a resolver
 * reads are REBUILT from those records, so a resolver can only ever see what this module accepted, and
 * the cache key is the sha256 of the REBUILT text. That canonicalisation is what the key means:
 *
 *   - a comment, a blank line, trailing whitespace, the whitespace inside a line (around `==`, around a
 *     comma, inside `[extras]`, around the tokens of a marker) and the key order inside the node JSON
 *     change nothing;
 *   - the ORDER of requirements does: `a` then `b` is a different text, and a different env, from `b`
 *     then `a`; the order of the specifiers within one line, and the spelling of a name, are kept as
 *     written;
 *   - the python text is `name[extras]specs; marker` per line, `\n`-joined, with one trailing newline;
 *     the node text is the two rebuilt file texts, framed as the JSON object above.
 *
 * The bytes themselves are checked before any of that: a `\r`, any other control byte but tab and
 * `\n`, and any non-ASCII byte is refused (`bad_requirements`), so no second line ending and no
 * character the two readers could disagree about ever reaches a resolver. For python the text is split
 * on `/\r\n|\r|\n/` exactly as a resolver splits it, and a `#` starts a comment only at the start of a
 * line or after whitespace (so `foo==1.0#--index-url x` is one bad token, not a requirement and an
 * option).
 *
 * The build runs in the wall (`warmup.mjs`): no uv on this computer is `uv_missing`, a failed install is
 * `env_failed`, and no sandbox at all is `no_wall` (nothing is built unwalled).
 */
import { createHash } from "node:crypto";
import {
  chmodSync, existsSync, mkdirSync, mkdtempSync, readFileSync, readdirSync, renameSync, rmSync, statSync, writeFileSync,
} from "node:fs";
import { dirname, join } from "node:path";
import { resolveCrowHome } from "../../servers/shared/crow-home.js";
import { resolveAddonCommand } from "../../servers/shared/resolve-command.js";
import { runWarmup } from "./warmup.mjs";

/** A report id as it may appear as a path segment. */
const PATH_ID_RE = /^[A-Za-z0-9._-]{1,64}$/;
/** The two languages an env may be built for. */
const LANGUAGES = Object.freeze(["python", "node"]);
/** The marker file's name, beside the env folder. */
const MARKER_SUFFIX = ".marker";
/** The largest requirements text this module will parse. */
export const REQUIREMENTS_MAX_BYTES = 64 * 1024;

const fail = (code, detail = "") => {
  const err = new Error(detail ? `${code}: ${detail}` : code);
  err.code = code;
  if (detail) err.detail = detail;
  return err;
};

/** A requirement name: a distribution name as PyPI writes one. */
const PY_NAME_RE = /^[A-Za-z0-9][A-Za-z0-9._-]*$/;
/** One version specifier, and a run of them separated by commas. */
const PY_SPEC_RE = /^(===|==|!=|<=|>=|~=|<|>)[A-Za-z0-9.*+_!-]+$/;
/** The characters an extras list may hold. */
const PY_EXTRAS_RE = /^[A-Za-z0-9._,-]+$/;
/** The comparison operators an environment marker may use (`in` and `not in` are handled as words). */
const MARKER_OPS = Object.freeze(["===", "==", "!=", "<=", ">=", "~=", "<", ">"]);
/** The environment-marker variables a requirement may test, and nothing else. */
const MARKER_VARS = new Set([
  "python_version", "python_full_version", "os_name", "sys_platform", "platform_machine",
  "platform_python_implementation", "platform_release", "platform_system", "platform_version",
  "implementation_name", "implementation_version", "extra",
]);
/** The quotes a marker value may be written in, and the characters inside one. */
const MARKER_VALUE_RE = /^[A-Za-z0-9._*+-]*$/;

/** The npm scripts that run during an install: never part of an env this module builds. */
const LIFECYCLE_SCRIPTS = Object.freeze(["preinstall", "install", "postinstall", "prepare", "prepublish", "dependencies"]);
/** The dependency maps a package.json keeps, and nothing else of the file. */
const NODE_DEP_MAPS = Object.freeze(["dependencies", "devDependencies", "optionalDependencies"]);
/** The longest npm package name npm itself accepts. */
const NODE_NAME_MAX = 214;
/** The body of a lower-case npm name, as npm writes one. */
const NODE_NAME_BODY = "[a-z0-9][a-z0-9._-]*";
/** A package name: lower case, optionally scoped (`@scope/name`). */
const NODE_NAME_RE = new RegExp(`^(?:@${NODE_NAME_BODY}/)?${NODE_NAME_BODY}$`);
/** A dist-tag word: `latest`, `next-2`, `beta.1`. */
const NODE_TAG_RE = /^[a-z][a-z0-9._-]{0,63}$/;
/** One version or partial version: a number or a wildcard, at most three parts, then prerelease and
 *  build metadata. `1`, `1.2`, `1.2.3`, `1.x`, `*`, `1.2.3-beta.1` all match. */
const NODE_PARTIAL_RE = /^(?:0|[1-9]\d*|[xX*])(?:\.(?:0|[1-9]\d*|[xX*])){0,2}(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
/** A plain version, with no range and no tag: a package's own `version` and a lock entry's `version`. */
const NODE_VERSION_RE = /^(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)\.(?:0|[1-9]\d*)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$/;
/** The operators a range may put in front of a version, longest first. */
const NODE_COMPARATORS = Object.freeze([">=", "<=", ">", "<", "=", "^", "~"]);
/** The dependency maps a lock entry may carry, beside the ones package.json keeps. */
const NODE_LOCK_ENTRY_MAPS = Object.freeze(["dependencies", "optionalDependencies", "peerDependencies"]);
/** A lock key: one or more nested `node_modules/<name>` segments, and nothing else. */
const LOCK_KEY_RE = /^node_modules\/(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+(?:\/node_modules\/(?:@[a-z0-9._-]+\/)?[a-z0-9._-]+)*$/;
/** What a lock entry may resolve to: the public registry over https, on exactly that host. */
const LOCK_RESOLVED_RE = /^https:\/\/registry\.npmjs\.org(\/[A-Za-z0-9._~%+!*'()@/=-]*)?$/;
/** A subresource integrity digest, as the registry writes one. */
const LOCK_INTEGRITY_RE = /^sha(256|384|512)-[A-Za-z0-9+/]+={0,2}$/;
/** A relative path inside a package, as a `bin` entry is written. */
const LOCK_BIN_PATH_RE = /^[A-Za-z0-9._-]+(\/[A-Za-z0-9._-]+)*$/;
/** An `os`/`cpu` list item: a platform name, optionally negated. */
const LOCK_PLATFORM_RE = /^!?[A-Za-z0-9._-]+$/;
/** A license string as a lock writes one. */
const LOCK_LICENSE_RE = /^[A-Za-z0-9. +()/-]+$/;
/** The fields a lock entry may never carry: each one means a package that is not the registry's tarball. */
const LOCK_REFUSED_FIELDS = Object.freeze(["link", "from", "inBundle"]);
/** The boolean fields a lock entry may carry. */
const LOCK_FLAG_FIELDS = Object.freeze(["dev", "optional", "peer", "hasInstallScript"]);

/**
 * The bytes a requirements text may hold: printable ASCII, with tab and newline. A `\r` would be a
 * second line ending, a NUL or another control byte a reader might skip, and a non-ASCII byte a code
 * point two readers can disagree about; all of them are refused before anything is parsed.
 */
function checkBytes(text, label) {
  if (typeof text !== "string") throw fail("bad_requirements", label);
  if (Buffer.byteLength(text, "utf8") > REQUIREMENTS_MAX_BYTES) throw fail("bad_requirements", "too large");
  for (let i = 0; i < text.length; i += 1) {
    const code = text.charCodeAt(i);
    if (code === 0x0a || code === 0x09) continue;
    if (code < 0x20 || code > 0x7e) throw fail("bad_requirements", "non-printable byte");
  }
}

/** The text of one requirement line with its comment cut: a `#` starts a comment only at the line
 *  start or after whitespace, so a `#` inside a specifier token stays part of that token. */
function withoutComment(line) {
  for (let i = 0; i < line.length; i += 1) {
    if (line[i] !== "#") continue;
    if (i === 0 || line[i - 1] === " " || line[i - 1] === "\t") return line.slice(0, i);
  }
  return line;
}

/**
 * One environment marker, normalised to single spaces between its tokens, or null when it is not one:
 * a boolean expression of the allowed variables and quoted values over the allowed operators.
 * @param {string} text
 * @returns {string|null}
 */
function normalizeMarker(text) {
  const tokens = [];
  let i = 0;
  while (i < text.length) {
    const ch = text[i];
    if (ch === " " || ch === "\t") { i += 1; continue; }
    if (ch === "(" || ch === ")") { tokens.push(ch); i += 1; continue; }
    if (ch === '"' || ch === "'") {
      const end = text.indexOf(ch, i + 1);
      if (end < 0) return null;
      const value = text.slice(i + 1, end);
      if (!MARKER_VALUE_RE.test(value)) return null;
      tokens.push(ch + value + ch);
      i = end + 1;
      continue;
    }
    const op = MARKER_OPS.find((candidate) => text.startsWith(candidate, i));
    if (op) { tokens.push(op); i += op.length; continue; }
    const word = /^[A-Za-z_][A-Za-z0-9_.]*/.exec(text.slice(i));
    if (!word) return null;
    let value = word[0];
    i += value.length;
    if (value === "not") {
      // `not in` is the only two-word operator this accepts.
      const rest = /^\s+in\b/.exec(text.slice(i));
      if (!rest) return null;
      i += rest[0].length;
      value = "not in";
    }
    if (value === "and" || value === "or" || value === "in" || value === "not in") tokens.push(value);
    else if (MARKER_VARS.has(value)) tokens.push(value);
    else return null;
  }
  return markerIsWellFormed(tokens) ? tokens.join(" ").replace(/\(\s+/g, "(").replace(/\s+\)/g, ")") : null;
}

/** A marker token list as the small boolean grammar this module allows: `term (and|or term)*`, where a
 *  term is `(term)`, a variable or a quoted value on each side of one allowed operator. */
function markerIsWellFormed(tokens) {
  const isValue = (t) => t !== undefined && (MARKER_VARS.has(t) || t.startsWith('"') || t.startsWith("'"));
  const isOp = (t) => t !== undefined && (MARKER_OPS.includes(t) || t === "in" || t === "not in");
  let at = 0;
  const peek = () => tokens[at];
  const term = () => {
    if (peek() === "(") {
      at += 1;
      if (!expression()) return false;
      if (peek() !== ")") return false;
      at += 1;
      return true;
    }
    if (!isValue(peek())) return false;
    at += 1;
    if (!isOp(peek())) return false;
    at += 1;
    if (!isValue(peek())) return false;
    at += 1;
    return true;
  };
  function expression() {
    if (!term()) return false;
    while (peek() === "and" || peek() === "or") {
      at += 1;
      if (!term()) return false;
    }
    return true;
  }
  return tokens.length > 0 && expression() && at === tokens.length;
}

/**
 * One line of a pip requirements file as this module reads it, or null when it is not one: a
 * distribution name, an optional `[extras]` list, version specifiers, and an optional marker. A name
 * that holds a path, a URL, an `@` reference or a leading `-` (an option line) never matches.
 * @param {string} line
 * @returns {{name: string, extras: string|null, specs: string[], marker: string|null}|null}
 */
function parseRequirementLine(line) {
  let rest = line;
  let marker = null;
  const semi = rest.indexOf(";");
  if (semi >= 0) {
    marker = normalizeMarker(rest.slice(semi + 1));
    if (!marker) return null;
    rest = rest.slice(0, semi).trim();
  }
  if (!rest) return null;
  let extras = null;
  const bracket = rest.indexOf("[");
  if (bracket >= 0) {
    const close = rest.indexOf("]", bracket);
    if (close < 0) return null;
    extras = rest.slice(bracket + 1, close).replace(/\s+/g, "");
    if (!PY_EXTRAS_RE.test(extras)) return null;
    rest = (rest.slice(0, bracket) + rest.slice(close + 1)).trim();
  }
  let name = rest;
  let specText = "";
  const at = rest.search(/[<>=!~]/);
  if (at >= 0) {
    name = rest.slice(0, at).trim();
    specText = rest.slice(at);
  }
  if (!name || !PY_NAME_RE.test(name)) return null;
  const specs = [];
  if (specText) {
    for (const part of specText.split(",")) {
      const spec = part.replace(/\s+/g, "");
      if (!spec || !PY_SPEC_RE.test(spec)) return null;
      specs.push(spec);
    }
  }
  return { name, extras, specs, marker };
}

/**
 * A python requirements text as its parsed records (at least one), or a `bad_requirements` refusal.
 * A comment line, a blank line, and a `#` comment after whitespace are allowed; nothing else is.
 * @param {string} text
 * @returns {{name: string, extras: string|null, specs: string[], marker: string|null}[]}
 */
export function parsePythonRequirements(text) {
  checkBytes(text, "python");
  const out = [];
  for (const raw of text.split(/\r\n|\r|\n/)) {
    const line = withoutComment(raw).trim();
    if (!line) continue;
    const parsed = parseRequirementLine(line);
    if (!parsed) throw fail("bad_requirements", "line");
    out.push(parsed);
  }
  if (!out.length) throw fail("bad_requirements", "empty");
  return out;
}

/** The canonical text a list of parsed requirement records rebuilds to: that is what a resolver
 *  reads, and what the cache key hashes. */
function canonicalPythonText(records) {
  const lines = records.map((record) => {
    let line = record.name;
    if (record.extras !== null) line += "[" + record.extras + "]";
    line += record.specs.join(",");
    if (record.marker !== null) line += "; " + record.marker;
    return line;
  });
  return lines.join("\n") + "\n";
}

/** Is `name` a package name: lower case, optionally `@scope/`, and no longer than npm allows? */
function isNodeName(name) {
  return typeof name === "string" && name.length > 0 && name.length <= NODE_NAME_MAX && NODE_NAME_RE.test(name);
}

/** One comparator of a range: an optional operator, then a version or partial version. */
function isNodeComparator(token) {
  let rest = token;
  const op = NODE_COMPARATORS.find((candidate) => rest.startsWith(candidate));
  if (op) rest = rest.slice(op.length);
  return rest.length > 0 && NODE_PARTIAL_RE.test(rest);
}

/** One comparator set: comparators separated by spaces (an operator may stand apart from its version),
 *  or a single hyphen range `1.2.3 - 2.3.4`. */
function isNodeComparatorSet(text) {
  const trimmed = text.trim();
  if (!trimmed) return false;
  const hyphen = trimmed.split(/\s+-\s+/);
  if (hyphen.length === 2) return NODE_PARTIAL_RE.test(hyphen[0]) && NODE_PARTIAL_RE.test(hyphen[1]);
  if (hyphen.length > 2) return false;
  const parts = trimmed.split(/\s+/);
  for (let i = 0; i < parts.length; i += 1) {
    let token = parts[i];
    if (NODE_COMPARATORS.includes(token)) {
      i += 1;
      if (i >= parts.length) return false;
      token += parts[i];
    }
    if (!isNodeComparator(token)) return false;
  }
  return true;
}

/** Is `text` a semver range: comparator sets joined by `||`? */
function isNodeRange(text) {
  const sets = text.split("||");
  return sets.length > 0 && sets.every((set) => isNodeComparatorSet(set));
}

/**
 * Is `spec` a dependency spec this module accepts: a semver range or a dist-tag word, and nothing else?
 * A `/`, `:`, `\` or `@` anywhere in it makes it a git, http(s), file, link, workspace or alias spec,
 * and a leading `.` makes it a path; both are refused before the grammar is even consulted.
 */
function isNodeSpec(spec) {
  if (typeof spec !== "string" || !spec) return false;
  if (/[/\\:@]/.test(spec)) return false;
  if (spec.startsWith(".")) return false;
  if (NODE_TAG_RE.test(spec)) return true;
  return isNodeRange(spec);
}

/** A node dependency map as this module reads it: every name a package name and every version a semver
 *  range or a dist-tag, in the order given. A git, http, file, link, workspace, alias or path spec is
 *  refused. */
function normalizeNodeDeps(value, label) {
  if (value === undefined) return null;
  if (!value || typeof value !== "object" || Array.isArray(value)) throw fail("bad_requirements", label);
  const out = {};
  for (const [name, spec] of Object.entries(value)) {
    if (!isNodeName(name)) throw fail("bad_requirements", "package name");
    if (!isNodeSpec(spec)) throw fail("bad_requirements", "version spec");
    out[name] = spec;
  }
  return out;
}

/** Refuse a lock entry that carries a field meaning "this package is not the registry's tarball". */
function checkLockEntryShape(entry) {
  if (!entry || typeof entry !== "object" || Array.isArray(entry)) throw fail("bad_requirements", "lock entry");
  for (const field of LOCK_REFUSED_FIELDS) {
    if (Object.prototype.hasOwnProperty.call(entry, field)) throw fail("bad_requirements", "lock " + field);
  }
}

/** A lock entry's `resolved`: an https URL on exactly `registry.npmjs.org`, with no credentials and no
 *  port, returned as written. Anything else refuses the lock. */
function checkLockResolved(entry) {
  const resolved = entry.resolved;
  if (typeof resolved !== "string" || !LOCK_RESOLVED_RE.test(resolved)) throw fail("bad_requirements", "lock resolved");
  let url;
  try {
    url = new URL(resolved);
  } catch {
    throw fail("bad_requirements", "lock resolved");
  }
  if (url.protocol !== "https:" || url.hostname !== "registry.npmjs.org" || url.port !== ""
    || url.username !== "" || url.password !== "") {
    throw fail("bad_requirements", "lock resolved");
  }
  return resolved;
}

/** A lock entry's `integrity`: a sha256, sha384 or sha512 digest, and nothing else. */
function checkLockIntegrity(entry) {
  if (typeof entry.integrity !== "string" || !LOCK_INTEGRITY_RE.test(entry.integrity)) {
    throw fail("bad_requirements", "lock integrity");
  }
  return entry.integrity;
}

/** A `bin` path: relative, inside the package, and with no `..` segment that could leave it. */
function isLockBinPath(value) {
  return typeof value === "string" && LOCK_BIN_PATH_RE.test(value)
    && value.split("/").every((segment) => segment !== "." && segment !== "..");
}

/** A lock entry's `bin`, kept as data: a string, or a name-to-relative-path map. */
function normalizeLockBin(bin) {
  if (typeof bin === "string") {
    if (!isLockBinPath(bin)) throw fail("bad_requirements", "lock bin");
    return bin;
  }
  if (!bin || typeof bin !== "object" || Array.isArray(bin)) throw fail("bad_requirements", "lock bin");
  const out = {};
  for (const [name, path] of Object.entries(bin)) {
    if (!isNodeName(name) || !isLockBinPath(path)) throw fail("bad_requirements", "lock bin");
    out[name] = path;
  }
  return out;
}

/**
 * One non-root lock entry as the allowlist rebuilds it: a registry tarball at a pinned plain version,
 * with an integrity digest and only the fields the resolver reads. Every other field the raw entry held
 * is dropped, and `bin`/`hasInstallScript` survive as data only because the install runs with
 * `--ignore-scripts`.
 */
function rebuildLockEntry(entry) {
  checkLockEntryShape(entry);
  if (typeof entry.version !== "string" || !NODE_VERSION_RE.test(entry.version)) {
    throw fail("bad_requirements", "lock version");
  }
  const out = { version: entry.version, resolved: checkLockResolved(entry), integrity: checkLockIntegrity(entry) };
  for (const flag of LOCK_FLAG_FIELDS) {
    if (entry[flag] === undefined) continue;
    if (typeof entry[flag] !== "boolean") throw fail("bad_requirements", "lock " + flag);
    out[flag] = entry[flag];
  }
  for (const map of NODE_LOCK_ENTRY_MAPS) {
    const deps = normalizeNodeDeps(entry[map], "lock " + map);
    if (deps) out[map] = deps;
  }
  if (entry.engines !== undefined) {
    if (!entry.engines || typeof entry.engines !== "object" || Array.isArray(entry.engines)) {
      throw fail("bad_requirements", "lock engines");
    }
    out.engines = {};
    for (const [name, spec] of Object.entries(entry.engines)) {
      if (!isNodeName(name) || !isNodeSpec(spec)) throw fail("bad_requirements", "lock engines");
      out.engines[name] = spec;
    }
  }
  for (const field of ["os", "cpu"]) {
    if (entry[field] === undefined) continue;
    const list = entry[field];
    if (!Array.isArray(list) || !list.every((item) => typeof item === "string" && LOCK_PLATFORM_RE.test(item))) {
      throw fail("bad_requirements", "lock " + field);
    }
    out[field] = [...list];
  }
  if (entry.license !== undefined) {
    if (typeof entry.license !== "string" || !LOCK_LICENSE_RE.test(entry.license)) {
      throw fail("bad_requirements", "lock license");
    }
    out.license = entry.license;
  }
  if (entry.bin !== undefined) out.bin = normalizeLockBin(entry.bin);
  return out;
}

/**
 * The lock's root entry `""`, checked against the rebuilt package.json: it may carry no refused field,
 * and its dependency names must be exactly package.json's own, map for map. The root this module writes
 * is rebuilt from package.json either way, so a lock with no root entry at all is the same env as one
 * with a matching root.
 */
function checkLockRoot(entry, packageJson) {
  checkLockEntryShape(entry);
  for (const map of NODE_DEP_MAPS) {
    const fromLock = normalizeNodeDeps(entry[map], "lock " + map);
    const fromPackage = packageJson[map] || null;
    const lockNames = fromLock === null ? [] : Object.keys(fromLock).sort();
    const packageNames = fromPackage === null ? [] : Object.keys(fromPackage).sort();
    if (lockNames.join("\n") !== packageNames.join("\n")) {
      throw fail("bad_requirements", "lock root dependencies");
    }
  }
}

/**
 * A v2 lock's parallel `dependencies` tree. It is never written, but every entry in it is checked the
 * same way a `packages` entry is, so a tree carrying a link, a foreign tarball or a range where a
 * version belongs refuses the lock instead of being dropped.
 */
function checkLegacyTree(tree) {
  if (tree === undefined) return;
  if (!tree || typeof tree !== "object" || Array.isArray(tree)) {
    throw fail("bad_requirements", "lock dependencies");
  }
  for (const [name, entry] of Object.entries(tree)) {
    if (!isNodeName(name) || !entry || typeof entry !== "object" || Array.isArray(entry)) {
      throw fail("bad_requirements", "lock dependencies");
    }
    checkLockEntryShape(entry);
    if (typeof entry.version !== "string" || !NODE_VERSION_RE.test(entry.version)) {
      throw fail("bad_requirements", "lock version");
    }
    checkLockResolved(entry);
    checkLockIntegrity(entry);
    checkLegacyTree(entry.dependencies);
  }
}

/** A lock key: one or more nested `node_modules/<name>` segments, with no segment that starts with a
 *  dot (so `.` and `..` are never a path step), and nothing else. */
function isLockKey(key) {
  return typeof key === "string" && LOCK_KEY_RE.test(key)
    && key.split("/").every((segment) => !segment.startsWith("."));
}

/**
 * A lock as the allowlist rebuilds it: `lockfileVersion` 3, the root entry from package.json, and one
 * entry per nested `node_modules/...` key, each rebuilt from its own fields. A key that is not one of
 * those paths, a bad entry, a lockfile version other than 3 or 2, or a missing `packages` map refuses
 * the whole lock; every top-level field the raw lock held is dropped.
 */
function rebuildLock(rawLock, packageJson) {
  if (rawLock.lockfileVersion !== 3 && rawLock.lockfileVersion !== 2) {
    throw fail("bad_requirements", "lockfile version");
  }
  const rawPackages = rawLock.packages;
  if (!rawPackages || typeof rawPackages !== "object" || Array.isArray(rawPackages)) {
    throw fail("bad_requirements", "lock packages");
  }
  checkLegacyTree(rawLock.dependencies);
  const packages = {};
  for (const [key, entry] of Object.entries(rawPackages)) {
    if (key === "") { checkLockRoot(entry, packageJson); continue; }
    if (!isLockKey(key)) throw fail("bad_requirements", "lock key");
    packages[key] = rebuildLockEntry(entry);
  }
  const root = { name: packageJson.name, version: packageJson.version };
  for (const map of NODE_DEP_MAPS) if (packageJson[map]) root[map] = packageJson[map];
  const rebuilt = { lockfileVersion: 3, packages: { "": root } };
  for (const key of Object.keys(packages).sort()) rebuilt.packages[key] = packages[key];
  return rebuilt;
}

/**
 * A node requirements text as the two file texts it is rebuilt to, plus the canonical envelope text
 * the cache key hashes, or a `bad_requirements` refusal.
 * @param {string} text
 * @returns {{text: string, packageJson: string, lock: string}}
 */
export function canonicalNodeRequirements(text) {
  checkBytes(text, "node");
  let parsed;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw fail("bad_requirements", "not json");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) throw fail("bad_requirements", "not an object");
  const keys = Object.keys(parsed).sort();
  if (keys.length !== 2 || keys[0] !== "package-lock.json" || keys[1] !== "package.json") {
    throw fail("bad_requirements", "keys");
  }
  const packageJsonText = parsed["package.json"];
  const lockText = parsed["package-lock.json"];
  for (const value of [packageJsonText, lockText]) {
    if (typeof value !== "string" || !value || Buffer.byteLength(value, "utf8") > REQUIREMENTS_MAX_BYTES) {
      throw fail("bad_requirements", "file text");
    }
  }
  checkBytes(packageJsonText, "package.json");
  checkBytes(lockText, "package-lock.json");
  let rawPackage;
  let rawLock;
  try {
    rawPackage = JSON.parse(packageJsonText);
    rawLock = JSON.parse(lockText);
  } catch {
    throw fail("bad_requirements", "file text is not json");
  }
  for (const inner of [rawPackage, rawLock]) {
    if (!inner || typeof inner !== "object" || Array.isArray(inner)) throw fail("bad_requirements", "file text");
  }

  // package.json: name, version and the dependency maps, rebuilt; a lifecycle script is refused
  // rather than dropped, because an install that ran one would be a different env than the hash says.
  if (!isNodeName(rawPackage.name)) throw fail("bad_requirements", "name");
  if (typeof rawPackage.version !== "string" || !NODE_VERSION_RE.test(rawPackage.version)) {
    throw fail("bad_requirements", "version");
  }
  const scripts = rawPackage.scripts;
  if (scripts !== undefined) {
    if (!scripts || typeof scripts !== "object" || Array.isArray(scripts)) throw fail("bad_requirements", "scripts");
    for (const name of LIFECYCLE_SCRIPTS) {
      if (Object.prototype.hasOwnProperty.call(scripts, name)) throw fail("bad_requirements", "lifecycle script");
    }
  }
  const rebuilt = { name: rawPackage.name, version: rawPackage.version };
  for (const map of NODE_DEP_MAPS) {
    const deps = normalizeNodeDeps(rawPackage[map], map);
    if (deps) rebuilt[map] = deps;
  }

  const packageJson = JSON.stringify(rebuilt, null, 2) + "\n";
  const lock = JSON.stringify(rebuildLock(rawLock, rebuilt), null, 2) + "\n";
  const canonical = JSON.stringify({ "package.json": packageJson, "package-lock.json": lock }, null, 2) + "\n";
  return { text: canonical, packageJson, lock };
}

/**
 * A node requirements text as the two file texts it is rebuilt to, or a `bad_requirements` refusal.
 * @param {string} text
 * @returns {{packageJson: string, lock: string}}
 */
export function parseNodeRequirements(text) {
  const { packageJson, lock } = canonicalNodeRequirements(text);
  return { packageJson, lock };
}

/**
 * The canonical requirements for one language: the text the cache key hashes, and the exact bytes the
 * resolver reads, rebuilt from the parsed records and from nothing else.
 * @param {"python"|"node"} language
 * @param {string} text
 * @returns {{text: string, files: {name: string, text: string}[]}}
 */
export function canonicalRequirements(language, text) {
  if (language === "python") {
    const canonical = canonicalPythonText(parsePythonRequirements(text));
    return { text: canonical, files: [{ name: "requirements.txt", text: canonical }] };
  }
  if (language !== "node") throw fail("bad_input", "language");
  const node = canonicalNodeRequirements(text);
  return {
    text: node.text,
    files: [
      { name: "package.json", text: node.packageJson },
      { name: "package-lock.json", text: node.lock },
    ],
  };
}

/** The env dir a language's dependencies live in. */
export function envDirFor({ crowHome, reportId, language }) {
  if (typeof reportId !== "string" || !PATH_ID_RE.test(reportId) || reportId === "." || reportId === "..") {
    throw fail("bad_input", "reportId");
  }
  if (!LANGUAGES.includes(language)) throw fail("bad_input", "language");
  return join(crowHome, "reports", reportId, "env", language);
}

/** The resolvers' cache folder for one report (writable inside the wall, never inside the env). */
export function envCacheDirFor({ crowHome, reportId }) {
  if (typeof reportId !== "string" || !PATH_ID_RE.test(reportId) || reportId === "." || reportId === "..") {
    throw fail("bad_input", "reportId");
  }
  return join(crowHome, "reports", reportId, "env", ".cache");
}

/** The sha256 of a canonical requirements text: the env's cache key. */
export function requirementsHash(requirements) {
  const text = requirements == null ? "" : String(requirements);
  return createHash("sha256")
    .update("crow-reports-env-v1\n", "utf8")
    .update(Buffer.from(text, "utf8"))
    .digest("hex");
}

/** The marker file a built env is remembered by, or null. */
function readMarker(markerPath) {
  try {
    const parsed = JSON.parse(readFileSync(markerPath, "utf8"));
    if (!parsed || typeof parsed !== "object") return null;
    if (typeof parsed.hash !== "string" || !/^[0-9a-f]{64}$/.test(parsed.hash)) return null;
    return parsed;
  } catch {
    return null;
  }
}

/** Write the marker atomically: a half-written marker is no marker at all. */
function writeMarker(markerPath, value) {
  const temp = markerPath + ".tmp-" + process.pid;
  writeFileSync(temp, JSON.stringify(value), { mode: 0o600 });
  renameSync(temp, markerPath);
}

/** The entries of a folder, or an empty list when it cannot be read. */
function readdirSafe(dir) {
  try {
    return readdirSync(dir);
  } catch {
    return [];
  }
}

/**
 * One build per env at a time, in this process AND across processes.
 *
 * In this process the map is the lock: a second caller for the same report and language waits on the
 * promise the first one made and gets its result (one build, one answer, no half-installed env
 * swapped twice). Across processes the exclusive lock file `<env dir>.lock` is, with the pid that owns
 * it and the time it was taken; a lock whose process is gone (or that is hours old) is stale and is
 * taken over, so a build that died leaves the next one unblocked.
 */
const inflight = new Map();   // `${home}|${reportId}|${language}` -> Promise
const LOCK_STALE_MS = 6 * 60 * 60 * 1000;
const LOCK_WAIT_MS = 10 * 60 * 1000;
const LOCK_POLL_MS = 100;

/** The lock file beside one env dir. */
const lockPathFor = (dir) => dir + ".lock";

/**
 * Take the env's lock file, or answer why not: `true` when this process took it, `false` when another
 * LIVE process holds it, `null` when the file could not be written at all (no lock is not a refusal:
 * the in-process map still holds).
 */
function takeEnvLock(lockPath, now = Date.now()) {
  try {
    writeFileSync(lockPath, JSON.stringify({ pid: process.pid, at: now }), { flag: "wx", mode: 0o600 });
    return true;
  } catch (err) {
    if (!err || err.code !== "EEXIST") return null;   // no lock file is no lock, not a refusal
    let held = null;
    try { held = JSON.parse(readFileSync(lockPath, "utf8")); } catch { held = null; }
    const pid = held && Number.isInteger(held.pid) ? held.pid : null;
    const at = held && Number.isFinite(held.at) ? held.at : 0;
    let alive = false;
    if (pid !== null) {
      try { process.kill(pid, 0); alive = true; } catch (e) { alive = Boolean(e && e.code === "EPERM"); }
    }
    if (alive && now - at < LOCK_STALE_MS) return false;
    // Stale: the process that took it is gone (or the file is hours old). Replace it.
    try { rmSync(lockPath, { force: true }); } catch { /* raced */ }
    try {
      writeFileSync(lockPath, JSON.stringify({ pid: process.pid, at: now }), { flag: "wx", mode: 0o600 });
      return true;
    } catch {
      return false;
    }
  }
}

/** Release the env's lock file, if this process still owns it. */
function releaseEnvLock(lockPath) {
  try {
    const held = JSON.parse(readFileSync(lockPath, "utf8"));
    if (held && held.pid !== process.pid) return;
  } catch {
    return;
  }
  try { rmSync(lockPath, { force: true }); } catch { /* already gone */ }
}

/** Poll for a condition, up to `ms`, and answer whether it became true. */
async function waitFor(check, ms, step = LOCK_POLL_MS) {
  const until = Date.now() + ms;
  for (;;) {
    if (check()) return true;
    if (Date.now() >= until) return false;
    await new Promise((r) => setTimeout(r, step));
  }
}

/** Is there a directory (not a symlink) at `p`? */
function isRealDir(p) {
  try {
    return !statSync(p).isSymbolicLink() && statSync(p).isDirectory();
  } catch {
    return false;
  }
}

/** The requirements files the build writes into the fresh folder: the canonical bytes, and nothing
 *  else, so the resolver reads exactly what the validator accepted. */
function writeRequirementsFiles(buildDir, files) {
  for (const file of files) writeFileSync(join(buildDir, file.name), file.text, { mode: 0o600 });
}

/** The uv on this computer, or null when there is none this instance may run. */
function defaultResolveUv() {
  try {
    const rc = resolveAddonCommand("uv");
    return rc && rc.missing !== true && typeof rc.command === "string" ? rc.command : null;
  } catch {
    return null;
  }
}

/** The npm beside the gateway's node, or null. */
function defaultResolveNpm(nodeBin) {
  const candidate = join(dirname(nodeBin), "npm");
  try {
    return existsSync(candidate) ? candidate : null;
  } catch {
    return null;
  }
}

/**
 * The env for one step, built if it is not already there.
 *
 * `deps` is the seam: `crowHome` (or `crowHome()`), `now()`, `probe` (the wall probe `runWarmup` takes),
 * `spawn`/`createRelay`/`seccompSupported`/`buildSeccompProgram` (the warm-up's own seams), `resolveUv`,
 * `npmBin`, `nodeBin`.
 *
 * @param {object} o
 * @param {string} o.reportId
 * @param {"python"|"node"} o.language
 * @param {string} [o.requirements]
 * @param {string} [o.crowHome]
 * @param {object} [o.deps]
 * @returns {Promise<{ok: true, dir: string, hash: string, cacheDir: string, built: boolean}|
 *   {ok: false, code: string, error: string}>}
 */
export async function ensureEnv(o = {}) {
  const { reportId, language, requirements = "", crowHome, deps = {} } = o;
  const seam = deps && typeof deps === "object" ? deps : {};
  const home = typeof crowHome === "string" && crowHome ? crowHome : typeof seam.crowHome === "string" && seam.crowHome
    ? seam.crowHome
    : typeof seam.crowHome === "function"
      ? seam.crowHome()
      : resolveCrowHome();
  let dir;
  let cacheDir;
  try {
    dir = envDirFor({ crowHome: home, reportId, language });
    cacheDir = envCacheDirFor({ crowHome: home, reportId });
  } catch (err) {
    return { ok: false, code: err.code || "bad_input", error: err.code || "bad_input" };
  }
  const text = requirements == null ? "" : String(requirements);

  // The requirements are parsed and REBUILT before anything is built or hashed: a text this module
  // cannot read is refused here, and a resolver only ever reads the rebuilt text, so it cannot read
  // something this module did not accept. The cache key is the sha256 of that same rebuilt text.
  let canonical = null;
  try {
    canonical = canonicalRequirements(language, text);
  } catch (err) {
    return { ok: false, code: err.code || "bad_requirements", error: err.code || "bad_requirements" };
  }
  const hash = requirementsHash(canonical.text);
  const markerPath = dir + MARKER_SUFFIX;

  // One build per (report, language) in this process: a second caller waits on the first one's promise
  // and gets its result, so two concurrent runs never swap two half-installed envs.
  const key = home + "|" + reportId + "|" + language;
  const prior = inflight.get(key);
  if (prior) return prior;
  const running = buildEnv({ seam, home, reportId, language, dir, cacheDir, markerPath, hash, canonical });
  inflight.set(key, running);
  try {
    return await running;
  } finally {
    inflight.delete(key);
  }
}

/** Does the env's marker say this exact env is here? One answer for every caller. */
function envReady(markerPath, hash, language, dir) {
  const marker = readMarker(markerPath);
  return Boolean(marker && marker.hash === hash && marker.language === language && isRealDir(dir));
}

/**
 * The build half of `ensureEnv`, run once per (report, language) at a time: the lock file makes a
 * build in ANOTHER process wait for the live holder (or take over a stale one), and the marker check
 * after the wait means a waiter reuses the winner's env instead of installing it again.
 */
async function buildEnv({ seam, home, reportId, language, dir, cacheDir, markerPath, hash, canonical }) {
  if (envReady(markerPath, hash, language, dir)) {
    return { ok: true, dir, hash, cacheDir, built: false };
  }

  const resolveUv = typeof seam.resolveUv === "function" ? seam.resolveUv : () => defaultResolveUv();
  const nodeBin = typeof seam.nodeBin === "string" && seam.nodeBin ? seam.nodeBin : process.execPath;
  const npmBin = typeof seam.npmBin === "string" && seam.npmBin ? seam.npmBin : defaultResolveNpm(nodeBin);
  const uvBin = language === "python" ? resolveUv() : null;
  if (language === "python" && !uvBin) return { ok: false, code: "uv_missing", error: "uv_missing" };
  if (language === "node" && !npmBin) return { ok: false, code: "env_failed", error: "env_failed" };

  let buildDir = null;
  let lockHeld = false;
  const lockPath = lockPathFor(dir);
  try {
    mkdirSync(dirname(dir), { recursive: true, mode: 0o700 });
    mkdirSync(cacheDir, { recursive: true, mode: 0o700 });
    try { chmodSync(dirname(dir), 0o700); } catch { /* a folder this process does not own */ }
    // The lock file first: a build in another process either waits here or takes over a stale lock.
    const took = takeEnvLock(lockPath);
    if (took === true) {
      lockHeld = true;
    } else if (took === false) {
      await waitFor(() => envReady(markerPath, hash, language, dir) || !existsSync(lockPath), LOCK_WAIT_MS);
      if (envReady(markerPath, hash, language, dir)) {
        return { ok: true, dir, hash, cacheDir, built: false };
      }
      lockHeld = takeEnvLock(lockPath) === true;
      if (!lockHeld) return { ok: false, code: "env_busy", error: "env_busy" };
    }
    // A leftover build folder from a crashed run is removed before a new one is made.
    for (const name of readdirSafe(dirname(dir))) {
      if (!name.startsWith(language + ".build-")) continue;
      try { rmSync(join(dirname(dir), name), { recursive: true, force: true }); } catch { /* in use */ }
    }
    buildDir = mkdtempSync(join(dirname(dir), language + ".build-"));
    chmodSync(buildDir, 0o700);
    writeRequirementsFiles(buildDir, canonical.files);
    const outcome = await runWarmup({
      reportId,
      language,
      buildDir,
      cacheDir,
      nodeBin,
      npmBin,
      uvBin,
      // The wall's home path is this instance's, so the empty tmpfs the build's HOME points at and the
      // one `rootArgs` makes are the same path.
      deps: { ...seam, home },
    });
    if (!outcome.ok) return { ok: false, code: outcome.code || "env_failed", error: outcome.code || "env_failed" };
    // The swap: the old env goes, the fresh one takes its place, and only then does the marker say so.
    try { rmSync(dir, { recursive: true, force: true }); } catch { /* nothing to replace */ }
    try { rmSync(markerPath, { force: true }); } catch { /* no marker yet */ }
    renameSync(buildDir, dir);
    buildDir = null;
    writeMarker(markerPath, { hash, language, builtAt: Number(seam.now ? seam.now() : Date.now()) || 0 });
    return { ok: true, dir, hash, cacheDir, built: true };
  } catch (err) {
    return { ok: false, code: err.code || "env_failed", error: err.code || "env_failed" };
  } finally {
    if (buildDir) { try { rmSync(buildDir, { recursive: true, force: true }); } catch { /* already gone */ } }
    if (lockHeld) releaseEnvLock(lockPath);
  }
}