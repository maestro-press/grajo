/**
 * The `workspace_file` block: a CSV or JSON file inside the report's project workspace.
 *
 * Settings: `{path}`, relative to `ctx.workspaceDir`, which the executor resolves for the report from
 * its PROJECT's `workspace_dir` (run-recipe.js). A report whose project has no workspace answers
 * `workspace_not_available`.
 *
 * CONFINED, in this order, and refused whole at the first step that fails:
 *   1. the path as written: not absolute, no drive letter, no backslash, no NUL or other control
 *      character, no `..` segment, no empty or `.` segment, not empty, not too long;
 *   2. the real path: `realpath` of the file must stay inside `realpath` of the workspace directory, so a
 *      SYMLINK that points out of the workspace is refused (`path_refused`) even though its own name is
 *      innocent;
 *   3. the open: `O_RDONLY | O_NOFOLLOW | O_NONBLOCK`, so nothing is followed and nothing waits on a
 *      pipe. A file swapped for a symlink between steps 2 and 3 is `path_refused`;
 *   4. the open handle: `fstat` must say it is a REGULAR file, and its device and inode must be the ones
 *      a fresh `stat` of the real path named (where the platform reports them). A FIFO, a socket, a
 *      device or a directory is `not_a_file`, refused BEFORE any read, and a FIFO cannot block one;
 *   5. where the handle really points: `readlink` of `/proc/self/fd/<fd>` must still resolve inside
 *      `realpath(workspaceDir)` (`path_refused` otherwise; a host without `/proc` has no readlink and
 *      steps 2 and 4 stand);
 *   6. the bytes: at most `MAX_FILE_BYTES` of them, read with `readSync` in a loop and stopped one byte
 *      past the cap, so a file that GROWS after the fstat is still refused (`too_large`). The handle is
 *      closed whatever happens.
 * No filesystem error ever reaches the answer: every failure is one of the code words below.
 *
 * `.csv` is read with the first row as headers. The parser is the small one at the bottom of this file:
 * the repository has no CSV parser that keeps a quoted field together (`dashboard/panels/contacts`
 * splits on every comma), and quoted fields are exactly what a spreadsheet export is full of. It reads
 * quoted fields (with `""` for a quote), commas and newlines inside quotes, CRLF or LF line ends, and a
 * last line with no line end. A row with fewer cells than headers leaves the missing values out; a row
 * with more is refused (`bad_csv`).
 *
 * `.json` is an array of items, or an object with an `items` array. A plain object is an item; anything
 * else becomes `{value: <it>}`, the same rule `http_json` applies, so every item is an object the shape
 * blocks can read. At most `MAX_ITEMS` items are kept from either format.
 *
 * This block stores no state: nothing here calls `ctx.setState`.
 */
import {
  closeSync, constants, fstatSync, openSync, readSync, readlinkSync, realpathSync, statSync,
} from "node:fs";
import { isAbsolute, join, sep } from "node:path";
import { isPlainObject, redactWith } from "./http-json.js";

/** How many items one file may contribute. */
export const MAX_ITEMS = 5000;

/** The bytes one file may hold. */
export const MAX_FILE_BYTES = 5 * 1024 * 1024;

/** The longest path this block reads. */
const PATH_MAX = 400;

/** C0 controls, DEL, C1 controls and the Unicode line and paragraph separators. */
const CONTROL_CHARS = /[\u0000-\u001f\u007f\u0080-\u009f\u2028\u2029]/;

/** A Windows drive prefix and a backslash separators are both refused: this path is POSIX and relative. */
const DRIVE_RE = /^[A-Za-z]:/;

function validate(settings) {
  if (!isPlainObject(settings)) return ["settings"];
  const errors = [];
  for (const key of Object.keys(settings)) {
    if (key !== "path") errors.push(key);
  }
  for (const token of pathTokens(settings.path)) errors.push(token);
  return errors;
}

/**
 * What is wrong with a path as written, as field tokens. The same checks the run applies before it
 * touches the filesystem, so a store that saved an older recipe cannot smuggle one in.
 */
function pathTokens(value) {
  if (typeof value !== "string" || !value.trim()) return ["path"];
  const path = value;
  if (path.length > PATH_MAX) return ["path"];
  if (CONTROL_CHARS.test(path)) return ["path"];
  if (path.includes("\\")) return ["path"];
  if (DRIVE_RE.test(path)) return ["path"];
  if (isAbsolute(path) || path.startsWith("/")) return ["path"];
  if (/^\.\.(\/|$)/.test(path)) return ["path"];
  for (const segment of path.split("/")) {
    if (!segment || segment === "." || segment === "..") return ["path"];
  }
  return [];
}

/** The extension this block reads, lower-cased, or "". */
function extensionOf(path) {
  const name = path.slice(path.lastIndexOf("/") + 1);
  const dot = name.lastIndexOf(".");
  return dot > 0 ? name.slice(dot).toLowerCase() : "";
}

/**
 * Read the file the settings name, answering its bytes or throwing a code word. Every refusal is a code,
 * and the filesystem's own message never leaves this function.
 */
function readConfinedFile(workspaceDir, path) {
  if (typeof workspaceDir !== "string" || !workspaceDir) throw fail("workspace_not_available");
  let base;
  try {
    base = realpathSync(workspaceDir);
  } catch {
    throw fail("workspace_not_available");
  }
  const inside = (candidate) => candidate === base
    || candidate.startsWith(base.endsWith(sep) ? base : base + sep);

  const target = join(base, path);
  let real;
  try {
    real = realpathSync(target);
  } catch {
    throw fail("file_not_found");
  }
  if (!inside(real)) throw fail("path_refused");

  // The identity of the file this run meant to read, for the fstat below where the platform has one.
  let named = null;
  try {
    named = statSync(real);
  } catch {
    throw fail("file_not_found");
  }

  let fd;
  try {
    fd = openSync(
      real,
      constants.O_RDONLY | (constants.O_NOFOLLOW ?? 0) | (constants.O_NONBLOCK ?? 0),
    );
  } catch (err) {
    throw fail(err && err.code === "ELOOP" ? "path_refused" : "file_not_found");
  }

  try {
    // The handle, before a byte is read: a regular file, and the file the stat above named.
    let opened;
    try {
      opened = fstatSync(fd);
    } catch {
      throw fail("read_failed");
    }
    if (!opened.isFile()) throw fail("not_a_file");
    if (named && Number(named.dev) > 0 && Number(named.ino) > 0
      && (Number(opened.dev) !== Number(named.dev) || Number(opened.ino) !== Number(named.ino))) {
      throw fail("path_refused");
    }

    // Where the handle really points, where this host can say: still the workspace it named.
    let link = null;
    try {
      link = readlinkSync("/proc/self/fd/" + fd);
    } catch {
      // No /proc on this host: steps 2 and 4 are the whole check there.
    }
    if (link && !inside(link)) throw fail("path_refused");

    if (Number(opened.size) > MAX_FILE_BYTES) throw fail("too_large");

    // Read at most one byte past the cap, so a file that grew after the fstat is refused as well.
    const bytes = Buffer.allocUnsafe(MAX_FILE_BYTES + 1);
    let total = 0;
    while (total < bytes.length) {
      let read;
      try {
        read = readSync(fd, bytes, total, bytes.length - total, null);
      } catch {
        throw fail("read_failed");
      }
      if (read <= 0) break;
      total += read;
    }
    if (total > MAX_FILE_BYTES) throw fail("too_large");
    return bytes.subarray(0, total);
  } finally {
    try {
      closeSync(fd);
    } catch {
      // The read is over either way; a handle that will not close is not this block's answer.
    }
  }
}

function fail(code) {
  const err = new Error(code);
  err.code = code;
  return err;
}

/**
 * One CSV document as rows of cells. Quoted fields keep their commas and newlines (a doubled quote
 * inside a quoted field is one quote), CRLF and LF both end a record, a last record with no line end is
 * still a record, and an empty line is no record at all.
 */
export function parseCsv(input) {
  const rows = [];
  let row = [];
  let cell = "";
  let quoted = false;
  let cellStarted = false;
  let i = 0;
  while (i < input.length) {
    const ch = input[i];
    if (quoted) {
      if (ch === "\"") {
        if (input[i + 1] === "\"") {
          cell += "\"";
          i += 2;
          continue;
        }
        quoted = false;
        i += 1;
        continue;
      }
      cell += ch;
      i += 1;
      continue;
    }
    if (ch === "\"" && !cellStarted) {
      quoted = true;
      cellStarted = true;
      i += 1;
      continue;
    }
    if (ch === ",") {
      row.push(cell);
      cell = "";
      cellStarted = false;
      i += 1;
      continue;
    }
    if (ch === "\r" || ch === "\n") {
      row.push(cell);
      rows.push(row);
      row = [];
      cell = "";
      cellStarted = false;
      i += ch === "\r" && input[i + 1] === "\n" ? 2 : 1;
      continue;
    }
    cell += ch;
    cellStarted = true;
    i += 1;
  }
  if (cellStarted || cell !== "" || row.length > 0) {
    row.push(cell);
    rows.push(row);
  }
  return rows.filter((cells) => !(cells.length === 1 && cells[0] === ""));
}

/** A CSV document as items, the first row naming the fields. */
function itemsOfCsv(textValue) {
  const rows = parseCsv(textValue);
  if (rows.length === 0) throw fail("empty_file");
  const headers = rows[0].map((name) => name.trim());
  if (!headers.length || headers.every((name) => !name)) throw fail("bad_csv");
  const items = [];
  for (const row of rows.slice(1)) {
    if (row.length > headers.length) throw fail("bad_csv");
    const item = {};
    headers.forEach((name, index) => {
      if (!name) return;
      item[name] = index < row.length ? row[index] : "";
    });
    items.push(item);
    if (items.length >= MAX_ITEMS) break;
  }
  return items;
}

/** A JSON document as items: an array, or an object holding an `items` array. */
function itemsOfJson(textValue) {
  let document;
  try {
    document = JSON.parse(textValue);
  } catch {
    throw fail("bad_json");
  }
  const found = Array.isArray(document) ? document : (isPlainObject(document) ? document.items : undefined);
  if (!Array.isArray(found)) throw fail("bad_shape");
  return found.slice(0, MAX_ITEMS).map((entry) => (isPlainObject(entry) ? entry : { value: entry }));
}

async function run(ctx, input) {
  const settings = isPlainObject(ctx.block?.settings) ? ctx.block.settings : {};
  const refuse = (code) => ({ sourceError: { message: redactWith(code, []) } });

  const tokens = pathTokens(settings.path);
  if (tokens.length) return refuse("bad_settings");
  const path = settings.path;
  const extension = extensionOf(path);
  if (extension !== ".csv" && extension !== ".json") return refuse("unsupported_file_type");

  let bytes;
  try {
    bytes = readConfinedFile(ctx?.workspaceDir, path);
  } catch (err) {
    const code = err && typeof err.code === "string" ? err.code : "read_failed";
    return refuse(code);
  }

  const decoded = new TextDecoder("utf-8", { fatal: false }).decode(bytes);
  try {
    const items = extension === ".csv" ? itemsOfCsv(decoded) : itemsOfJson(decoded);
    return { items };
  } catch (err) {
    const code = err && typeof err.code === "string" ? err.code : "bad_file";
    return refuse(code);
  }
}

export const workspaceFileBlock = Object.freeze({
  type: "workspace_file",
  kind: "source",
  sourceBearing: true,
  validate,
  run,
});