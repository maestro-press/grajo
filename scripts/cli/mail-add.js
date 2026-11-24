#!/usr/bin/env node
/**
 * `crow mail add` — connect a password mail account from a terminal, without the dashboard.
 *
 * The same seven steps the dashboard's Connect runs (`POST /dashboard/mail/api/accounts`,
 * servers/gateway/routes/mail-api.js), in the same order, so the two can never disagree about what
 * "connected" means:
 *
 *   1. the duplicate check, case-insensitive: one mailbox is one account here;
 *   2. the password joins this instance's masking set (`recordServiceSecretValues`) before any path
 *      can write it to a log — a recorder that fails is logged by code and never fails the add;
 *   3. the claim check: an address connected on another paired Crow is refused, never dialled;
 *   4. the probe: a real IMAP connect and a folder listing (`probeAccount`), so a password is only
 *      believed once a mail server has accepted it. IMAP only: the SMTP endpoint is stored for
 *      sending and an add never dials it, so no text here claims an SMTP sign-in;
 *   5. `createAccount` with `authKind: "password"`;
 *   6. the password sealed in the keychain (`credentials.saveSecret(id, "MAIL_PASSWORD", …)`) and this
 *      instance's claim written;
 *   7. the claim re-checked, because a claim written a moment ago can still lose to another instance's.
 *
 * Nothing is stored before step 4 passes, and ANY failure after step 5 undoes the whole thing — the
 * sealed secret, the account rows, the claim — so an address is never half-connected.
 *
 * The instance: this script must write to the SAME crow.db the gateway reads, or the account it adds
 * is invisible to Mail and its password is sealed under a key the gateway does not have. So before
 * anything else — first import, before any module that fixes a path at load time — `./lib/instance-env.js`
 * does what the gateway's boot does: it applies the checkout `.env` (an already-set variable wins,
 * CROW_APP_ENV_PATH honoured) and runs the gateway's own `runInstancePathsGate`. Then this script
 * refuses (exit 2) when that instance has no crow.db yet or no USABLE keychain key (the keychain's own
 * state check: missing, empty, damaged or not a file all count as unusable), instead of letting a
 * client or `ensureWriteKey` create either — a key minted here would differ from the gateway's and
 * every password it sealed would become unreadable. It prints the one instance it
 * writes to: the CROW_HOME and the db path, nothing more.
 *
 * Usage:
 *   node scripts/cli/mail-add.js --label <name> --address <address> \
 *     --imap host:port:security --smtp host:port:security \
 *     --password-env-file <path> --password-key <VAR> [--username <login>] [--dry-run]
 *
 *   node scripts/cli/mail-add.js --label <name> --address-key <VAR> \
 *     --imap host:port:security --smtp host:port:security \
 *     --password-stdin
 *
 *   security is one of ssl | starttls | none (none only for a server on this machine; the account
 *   store refuses it for any other host). `--username` is the IMAP/SMTP login when it differs from the
 *   address. `--dry-run` stops after the probe and stores nothing: no account, no secret, no claim.
 *
 * Security rules — this script is the one path to a mailbox password that is not a browser form:
 *
 *   - The password is NEVER accepted on argv (`--password` is refused outright): an argument is in the
 *     shell history, in `ps` for every user on the box and in the process's own environ dump.
 *   - Two sources only: `--password-env-file <path> --password-key <VAR>` reads the file in this
 *     process, or `--password-stdin` reads one line from standard input — refused outright when
 *     standard input is a terminal, where it would echo the password as it is typed.
 *     `--address-key <VAR>` reads the address from the same file. The file's rules, in full:
 *     `KEY=VALUE` per line; `export` and any whitespace may precede the key; `#` starts a line; an
 *     inline `#` is part of an UNQUOTED value (a password may contain one); a value inside matching
 *     `'…'` or `"…"` quotes is taken exactly as written, so `' lead '` keeps its spaces; anything after
 *     a closing quote that starts with `#`, with or without spaces, is a comment and is dropped; an
 *     unquoted value is trimmed of leading and trailing whitespace; and NOTHING is escaped — `\n` in
 *     that file is a backslash and an `n`.
 *   - That file must be readable by this user only (mode 0600). One that is group- or world-readable
 *     gets a warning (the flag name, never the path), and the docs create it under `umask 077` and
 *     say to delete it once the account is added.
 *   - No operator-supplied value is ever echoed by a failure: an unexpected argument is reported by
 *     its position, a `--password-key` that is not in the file without naming the variable, and any
 *     other failure by its MailError code.
 *   - The password is never printed, never logged and never put in a message: every failure this
 *     script reports is a MailError code (`AUTH_FAILED`, `NETWORK`, `TLS`, …), because a library's own
 *     text quotes the server, the command and the login.
 *   - `--dry-run` writes nothing at all, so a wrong password costs nothing but a failed sign-in.
 *
 * Exit codes: 0 added (or a dry run that signed in); 2 usage — a bad argument, the CROW_MAIL flag is
 * off and `--force-flag-off` was not passed, or this shell does not resolve the gateway's instance
 * (no crow.db, or no usable keychain key); 3 refused (the address is already connected here, or on
 * another instance); 4 failed and undone (nothing of the attempt remains); 5 the server refused the
 * sign-in (the probe failed; nothing was stored); 78 the instance-path gate refused this shell's
 * layout — the same refusal, and the same code, the gateway boots with.
 *
 * The flag: with `CROW_MAIL` unset the gateway reaches no mail route at all, so this script refuses
 * too — but the flag usually lives in the gateway's unit, not in the operator's shell, so the refusal
 * says which of the two it can see. `--force-flag-off` adds the account anyway, and says plainly that
 * the gateway will not sync it. The sync supervisor loads accounts when it starts, so after a
 * successful add it first pings the running gateway's loopback sync hook
 * (servers/gateway/routes/mail-sync-hook.js) with this boot's path-scoped `MAIL_HOOK_TOKEN`, which
 * starts the new account without a restart when a gateway is up. The hook decides the closing line:
 * when it reports `notified === true` the add ends with "The running gateway started syncing this
 * account."; otherwise (no token file, no gateway, a refusal, a timeout, or a hook that throws) it
 * ends by asking for a gateway restart, exactly as before. The hook is best effort in every case: the
 * exit code is `0` either way.
 */
// FIRST: the gateway's .env + instance-path gate, before any module below resolves a path.
import "./lib/instance-env.js";
import { existsSync, readFileSync, realpathSync, statSync } from "node:fs";
import { resolve as resolvePath } from "node:path";
import { fileURLToPath } from "node:url";
import { createInterface } from "node:readline";
import { createDbClient, resolveDataDir } from "../../servers/db.js";
import { resolveCrowHome } from "../../servers/shared/crow-home.js";
import { keychainKeyState } from "../../servers/gateway/keychain/key.js";
import { cleanPeerName } from "../../servers/shared/peer-label.js";
import { recordServiceSecretValues } from "../../servers/shared/secret-values.js";
import { getInstance, getOrCreateLocalInstanceId } from "../../servers/gateway/instance-registry.js";
import { createImapSmtpAdapter } from "../../servers/gateway/mail/adapter/imap-smtp.js";
import { checkClaim, claimedElsewhereSentence, releaseClaim, writeClaim } from "../../servers/gateway/mail/claims.js";
import { createMailCredentials } from "../../servers/gateway/mail/credentials.js";
import { toMailError } from "../../servers/gateway/mail/errors.js";
import { mailEnabled } from "../../servers/gateway/mail/flag.js";
import { probeAccount } from "../../servers/gateway/mail/probe.js";
import { createAccount, deleteAccount, listAccounts } from "../../servers/gateway/mail/store/accounts.js";
import { MAIL_HOOK_TOKEN } from "../../servers/gateway/local-token.js";
import { gatewayPort } from "../../servers/gateway/models/door.js";
import { notifyMailSyncHook } from "./lib/mail-sync-hook-client.js";

/** The exit codes the header documents, in one place so a caller never hard-codes a number. */
export const EXIT = Object.freeze({
  ok: 0,
  usage: 2,
  refused: 3,
  failed: 4,
  probeRefused: 5,
  // The instance-path gate (./lib/instance-env.js) exits by itself with the gateway's own code.
  instancePaths: 78,
});

/** The limits the mail API's own body reader applies; the account store validates the rest. */
const SECURITIES = new Set(["ssl", "starttls", "none"]);
const PASSWORD_MAX = 1024;
const LABEL_MAX = 120;
const USERNAME_MAX = 254;
const HOST_MAX = 253;
const ADDRESS_MAX = 254;
const CONTROL_CHARS_RE = /[\u0000-\u001f\u007f]/;

/** A refusal this script makes itself: its message is its own fixed text, never a value. */
export class MailCliError extends Error {
  constructor(exitCode, message) {
    super(message);
    this.name = "MailCliError";
    this.exitCode = exitCode;
  }
}

const usage = (message) => new MailCliError(EXIT.usage, message);

/* ------------------------------------------------------------------ arguments */

/** Flags that take a value: `--flag value`. */
const VALUE_FLAGS = new Map([
  ["--address", "address"],
  ["--address-key", "addressKey"],
  ["--label", "label"],
  ["--username", "username"],
  ["--password-env-file", "passwordEnvFile"],
  ["--password-key", "passwordKey"],
  ["--imap", "imap"],
  ["--smtp", "smtp"],
]);

/** Flags that stand alone. */
const BOOLEAN_FLAGS = new Map([
  ["--password-stdin", "passwordStdin"],
  ["--dry-run", "dryRun"],
  ["--force-flag-off", "forceFlagOff"],
  ["--help", "help"],
  ["-h", "help"],
]);

/**
 * Parse argv into the flags above. An unknown flag, a flag without its value, or `--password` is a
 * usage refusal — the password case gets its own sentence, so the operator learns why rather than
 * guessing at a typo.
 *
 * @param {string[]} argv
 * @returns {object}
 */
export function parseArgs(argv = []) {
  const out = {};
  for (let i = 0; i < argv.length; i++) {
    const arg = String(argv[i]);
    if (arg === "--password" || arg.startsWith("--password=")) {
      throw usage("the password is never accepted on the command line; use --password-env-file with --password-key, or --password-stdin");
    }
    const valueKey = VALUE_FLAGS.get(arg);
    if (valueKey) {
      const value = argv[i + 1];
      if (value === undefined || String(value).startsWith("--")) throw usage(`${arg} needs a value`);
      out[valueKey] = String(value);
      i++;
      continue;
    }
    const booleanKey = BOOLEAN_FLAGS.get(arg);
    if (booleanKey) {
      out[booleanKey] = true;
      continue;
    }
    // A token that is not one of the flags above is reported by its POSITION only: it may be the
    // password somebody typed from muscle memory, and nothing operator-supplied is ever echoed.
    if (arg.startsWith("-")) {
      throw usage(`unknown flag at argument ${i + 1} (run with --help)`);
    }
    throw usage(`an unexpected positional argument at argument ${i + 1} (run with --help)`);
  }
  return out;
}

function printUsage(stream = process.stdout) {
  stream.write(`Crow mail add — connect a password mail account from the terminal.

Usage:
  node scripts/cli/mail-add.js --label <name> --address <address> \\
    --imap host:port:ssl|starttls|none --smtp host:port:ssl|starttls|none \\
    --password-env-file <path> --password-key <VAR> [--username <login>] [--dry-run]
  node scripts/cli/mail-add.js --label <name> --address-key <VAR> \\
    --imap host:port:ssl|starttls|none --smtp host:port:ssl|starttls|none --password-stdin

The password is never accepted on the command line. Put it in a file only this user can read, and
remove the file once the account is added — the heredoc lines below go at column 0:

(umask 077 && cat > ~/.crow-mail.env <<'EOF'
IMAP_PASSWORD='the app password'
MAIL_ADDRESS='alex@example.com'
EOF
)

  node scripts/cli/mail-add.js --label Personal --address-key MAIL_ADDRESS \\
    --password-env-file ~/.crow-mail.env --password-key IMAP_PASSWORD \\
    --imap imap.example.com:993:ssl --smtp smtp.example.com:465:ssl

  rm ~/.crow-mail.env

The file is 'KEY=VALUE' per line: '#' starts a line, an inline '#' is part of an unquoted value, a
value inside matching quotes is taken exactly as written, anything after a closing quote that starts
with '#' is a comment, an unquoted value is trimmed, and nothing is escaped.

--password-stdin reads one line from a pipe; on a terminal it refuses, because it would echo.

This command writes to the instance this shell resolves — it prints that instance's CROW_HOME and db
path first — and refuses (exit 2) when that instance has no crow.db or no usable keychain key yet. Run
it as the user whose CROW_HOME the gateway uses.

Options:
  --dry-run         sign in and stop; nothing is stored
  --force-flag-off  add the account even though CROW_MAIL is not 1
  --help            this text

Exit codes: 0 added, 2 usage, 3 refused (already connected), 4 failed and undone, 5 sign-in refused,
78 the instance-path gate refused this shell's CROW_HOME layout.
`);
}

/* ------------------------------------------------------- arguments → input */

function cleanText(value, max) {
  if (typeof value !== "string") return null;
  const trimmed = value.trim();
  if (!trimmed || trimmed.length > max || CONTROL_CHARS_RE.test(trimmed)) return null;
  return trimmed;
}

/** One plain mailbox address: one `@`, no whitespace, no control characters, no angle brackets. */
function readAddress(value) {
  if (typeof value !== "string") return null;
  const address = value.trim().toLowerCase();
  if (!address || address.length > ADDRESS_MAX) return null;
  if (/[\s\u0000-\u001f\u007f<>]/.test(address)) return null;
  const at = address.indexOf("@");
  if (at <= 0 || at !== address.lastIndexOf("@") || at === address.length - 1) return null;
  return address;
}

/** `host:port:security`, the same shape and the same limits as the mail API's `readEndpoint`. */
function readEndpointSpec(flag, value) {
  const parts = String(value ?? "").split(":");
  if (parts.length !== 3) throw usage(`${flag} needs host:port:security (security is ssl, starttls or none)`);
  const host = parts[0].trim().toLowerCase();
  if (!host || host.length > HOST_MAX || /[\s\u0000-\u001f\u007f<>]/.test(host)) {
    throw usage(`${flag} has no usable host`);
  }
  if (!/^\d+$/.test(parts[1].trim())) throw usage(`${flag} needs a whole-number port`);
  const port = Number(parts[1].trim());
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw usage(`${flag} needs a port between 1 and 65535`);
  const security = parts[2].trim().toLowerCase();
  if (!SECURITIES.has(security)) throw usage(`${flag} needs security ssl, starttls or none`);
  return { host, port, security };
}

/**
 * The flags checked before anything is read from a file or from stdin: a bad label, endpoint or
 * source combination is refused with a usage error and no secret ever leaves its file.
 */
function validateFlags(args) {
  const label = cleanText(args.label, LABEL_MAX);
  if (!label) throw usage(`--label is required (at most ${LABEL_MAX} characters)`);
  if (!args.imap) throw usage("--imap host:port:security is required");
  if (!args.smtp) throw usage("--smtp host:port:security is required");
  const imap = readEndpointSpec("--imap", args.imap);
  const smtp = readEndpointSpec("--smtp", args.smtp);

  if (Boolean(args.address) === Boolean(args.addressKey)) {
    throw usage("one of --address or --address-key is required (and not both)");
  }
  const fromFile = Boolean(args.passwordEnvFile) || Boolean(args.passwordKey) || Boolean(args.addressKey);
  if (Boolean(args.passwordEnvFile) !== Boolean(args.passwordKey)) {
    throw usage("--password-env-file and --password-key go together");
  }
  if (args.passwordStdin && args.passwordEnvFile) {
    throw usage("one password source: --password-env-file with --password-key, or --password-stdin");
  }
  if (!args.passwordStdin && !args.passwordEnvFile) {
    throw usage("no password source: use --password-env-file with --password-key, or --password-stdin");
  }
  if (fromFile && !args.passwordEnvFile) {
    throw usage("--address-key reads the address from the file named by --password-env-file");
  }
  let username = null;
  if (args.username !== undefined) {
    username = cleanText(args.username, USERNAME_MAX);
    if (!username || /[\s\u0000-\u001f\u007f<>]/.test(username)) throw usage("--username is not a usable login");
  }
  return { label, address: args.address ?? null, username, imap, smtp };
}

/**
 * The `KEY=VALUE` lines of an env file, as a Map. Nothing here is echoed: a file that cannot be read
 * reports the errno code only, because the message of a read failure names the path — and the path may
 * be a script the operator wrote.
 *
 * @param {string} path
 * @returns {Map<string, string>}
 */
export function readEnvFile(path) {
  let text;
  try {
    text = readFileSync(path, "utf8");
  } catch (err) {
    throw usage(`cannot read the env file (${(err && err.code) || "read failed"})`);
  }
  warnIfGroupOrWorldReadable(path);
  const values = new Map();
  for (const raw of text.split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    // `export` plus ANY whitespace (a tab too) may precede the key; `export KEY` is not an assignment.
    const exported = /^export[ \t]+/.exec(line);
    const body = exported ? line.slice(exported[0].length) : line;
    const eq = body.indexOf("=");
    if (eq <= 0) continue;
    const key = body.slice(0, eq).trim();
    if (!key) continue;
    values.set(key, parseEnvValue(body.slice(eq + 1)));
  }
  return values;
}

/**
 * One value, by the rules the header and the docs state.
 *
 * - `"…"` or `'…'`: the text between the quotes is the value EXACTLY — no trimming, no escape
 *   processing. After the closing quote only a `#` comment may follow, with or without whitespace
 *   before the `#` (`"pw"#c` is `pw`); that comment is dropped.
 * - anything else: the text after `=` with leading and trailing whitespace trimmed. A `#` inside it
 *   is part of the value (`P=a#b` is `a#b`); nothing is escaped.
 *
 * A quote with no closing quote, or a closing quote followed by something that is not whitespace or a
 * comment, does not match the quoted form and is read as an ordinary unquoted value — never silently
 * truncated.
 *
 * @param {string} raw the text after `=`
 * @returns {string}
 */
export function parseEnvValue(raw) {
  const text = String(raw ?? "");
  const lead = text.replace(/^[ \t]+/, "");
  const quote = lead[0];
  if (quote === '"' || quote === "'") {
    const close = lead.indexOf(quote, 1);
    if (close > 0) {
      const rest = lead.slice(close + 1);
      if (/^[ \t]*(#.*)?$/.test(rest)) return lead.slice(1, close);
    }
  }
  // Unquoted: leading whitespace too (`KEY= pw` and `KEY = pw` are both `pw`).
  return text.trim();
}

/**
 * One warning when the password file is readable by group or others (mode & 0o077). It names the flag
 * and never the path: the warning goes to the terminal and into whatever scrollback or log that has.
 */
function warnIfGroupOrWorldReadable(path) {
  let mode;
  try {
    mode = statSync(path).mode;
  } catch {
    return; // a file that was just read but cannot be stat'd is not worth a second message
  }
  if ((mode & 0o077) === 0) return;
  console.warn("warning: the env file named by --password-env-file is readable by group or others; chmod 600 it (and delete it once the account is added)");
}

/**
 * Exactly one line from stdin: `--password-stdin`. A terminal is refused before anything is read: with
 * `terminal: false` readline still lets the tty echo what is typed, so the password would appear on
 * the screen (and in the scrollback) — a pipe is the only way it never does.
 */
export function readLineFromStdin(stream = process.stdin) {
  if (stream && stream.isTTY) {
    return Promise.reject(usage("--password-stdin would echo the password on a terminal: pipe it in or use --password-env-file with --password-key"));
  }
  return new Promise((resolve, reject) => {
    const rl = createInterface({ input: stream, terminal: false });
    let answered = false;
    rl.once("line", (line) => {
      answered = true;
      rl.close();
      resolve(String(line));
    });
    rl.once("close", () => {
      if (!answered) reject(usage("--password-stdin got no line on standard input"));
    });
  });
}

/** The address and the password from their two allowed sources. */
async function readSources(args) {
  let address = args.address ?? null;
  let password = null;
  if (args.passwordEnvFile) {
    const values = readEnvFile(args.passwordEnvFile);
    if (address === null) {
      address = values.get(args.addressKey);
      // The variable NAME is operator-supplied text and is never echoed, only the flag is named.
      if (address === undefined) throw usage("the --address-key variable is not set in the env file");
    }
    password = values.get(args.passwordKey);
    if (password === undefined) throw usage("the --password-key variable is not set in the env file");
  } else {
    password = await readLineFromStdin();
  }
  return { address, password: String(password ?? "") };
}

/** The account input the store and the probe take, or a usage refusal. Never carries the password. */
function readMailInput({ label, address, username, imap, smtp }) {
  const normalized = readAddress(address);
  if (!normalized) throw usage("--address is not one plain mailbox address");
  return { label, address: normalized, username, imap, smtp };
}

function readPassword(value) {
  const password = String(value ?? "");
  if (!password) throw usage("the password read from its source is empty");
  if (password.length > PASSWORD_MAX) throw usage(`the password is longer than ${PASSWORD_MAX} characters`);
  return password;
}

/* ------------------------------------------------------------------ the work */

/** The code a failure is reported by. Never the failure's own text, which may quote a value. */
function codeOf(error) {
  // The keychain's key-missing fault is not a mail error and must not read as a bad password.
  if (error && error.code === "KEYCHAIN_KEY_MISSING") return "KEYCHAIN_KEY_MISSING";
  try {
    return toMailError(error).code;
  } catch {
    return "PROTOCOL";
  }
}

/** A route's failure in the log: the code only, so no value can travel with it. */
function logCode(where, error) {
  try {
    console.warn(`[mail-add] ${where}: ${codeOf(error)}`);
  } catch {
    // A log line is never worth failing an add over.
  }
}

/** This instance's id and the name its own registry row carries — never an address or a mail host. */
async function defaultLocalInstance(db) {
  const instanceId = getOrCreateLocalInstanceId();
  let instanceName = "";
  try {
    const row = await getInstance(db, instanceId);
    instanceName = cleanPeerName(row?.name);
  } catch {
    instanceName = "";
  }
  return { instanceId, instanceName };
}

/**
 * Is this address already connected here? The store's own UNIQUE COLLATE NOCASE identity, checked
 * before anything dials: a second account for one mailbox is the operator's input, not a server's
 * verdict, so the far end need not be asked at all.
 */
async function addressTaken(db, address) {
  const wanted = String(address).trim().toLowerCase();
  for (const account of await listAccounts(db)) {
    if (String(account.address).trim().toLowerCase() === wanted) return true;
  }
  return false;
}

function isDuplicateAddress(error) {
  return Boolean(error && error.code === "BAD_INPUT" && error.detail === "address");
}

/** The account row a probe connects: the values just typed, with no stored id behind them. */
function probeRow(input) {
  return {
    id: "probe",
    label: input.label,
    address: input.address,
    username: input.username,
    authKind: "password",
    imap: input.imap,
    smtp: input.smtp,
  };
}

/** The credentials reader a probe is handed: the password just read, for that one sign-in. */
function probeCredentials(password) {
  return { getSecrets: async () => ({ MAIL_PASSWORD: password }) };
}

/** Undo an add that could not be finished: the secret, then the account. Best effort, code-logged. */
async function undoAdd(db, credentials, accountId) {
  try {
    await credentials.deleteSecrets(accountId);
  } catch (error) {
    logCode("undo_secret", error);
  }
  try {
    await deleteAccount(db, accountId);
  } catch (error) {
    logCode("undo_account", error);
  }
}

async function releaseClaimQuietly(claims, db, address, localInstanceId) {
  try {
    await claims.releaseClaim(db, address, { localInstanceId });
  } catch (error) {
    logCode("undo_claim", error);
  }
}

/**
 * Add one password mail account: the seven steps, in order, with every failure after the account row
 * exists undone. Pure with respect to its dependencies — `db`, `adapterFactory`, `credentials`,
 * `localInstance`, `recordSecrets` and `claims` all arrive as arguments — so a test can drive it
 * without a socket, a keychain or a host, and `main()` is what supplies the real ones. The claim
 * functions are one dependency because a test that needs a failure AFTER the claim was written (the
 * re-check that throws) must not have to stage a real race to get one.
 *
 * @param {object} options
 * @param {object} options.db           a crow.db client (the account store's own)
 * @param {{label: string, address: string, username?: string|null, imap: object, smtp: object}} options.input
 * @param {string} options.password     the plaintext password, already read from its one source
 * @param {Function} [options.adapterFactory] `({account, credentials}) => adapter`; the real IMAP/SMTP one
 * @param {object} [options.credentials]  `{saveSecret, deleteSecrets, getSecrets}`; the mail keychain
 * @param {{instanceId: string, instanceName: string}} [options.localInstance]
 * @param {Function} [options.recordSecrets] `(values) => …`; `recordServiceSecretValues` by default
 * @param {{checkClaim: Function, writeClaim: Function, releaseClaim: Function}} [options.claims]
 *   the claim functions; the real ones by default
 * @param {boolean} [options.dryRun]    stop after the probe and store nothing
 * @returns {Promise<{outcome: string, account?: object, code?: string, instanceName?: string,
 *   sentence?: string, undone?: boolean}>}
 *   outcome is one of `added`, `dry_run`, `duplicate`, `claimed`, `probe_failed`, `failed`.
 */
export async function addMailAccount({
  db,
  input,
  password,
  adapterFactory = null,
  credentials = null,
  localInstance = null,
  recordSecrets = recordServiceSecretValues,
  claims = { checkClaim, writeClaim, releaseClaim },
  dryRun = false,
} = {}) {
  const local = localInstance ?? await defaultLocalInstance(db);
  const creds = credentials ?? createMailCredentials({ db });
  const factory = typeof adapterFactory === "function"
    ? adapterFactory
    : ({ account, credentials: reader }) => createImapSmtpAdapter({ account, credentials: reader });

  // 1. One mailbox is one account: refused before anything dials, and before the password is even
  //    masked, so a duplicate leaves no trace of this attempt at all.
  if (await addressTaken(db, input.address)) return { outcome: "duplicate" };

  // 2. The password joins the masking set before any path can write it to a log — a dry run stores
  //    nothing, so it records nothing either.
  if (!dryRun) {
    try {
      await recordSecrets([password]);
    } catch (error) {
      logCode("record_secret", error);
    }
  }

  // 3. An address another live instance holds is refused, not dialled.
  const claim = await claims.checkClaim(db, input.address, { localInstanceId: local.instanceId });
  if (!claim.ok) {
    return { outcome: "claimed", instanceName: claim.instanceName, sentence: claimedElsewhereSentence(claim.instanceName) };
  }

  // 4. Before anything is stored: a refused sign-in leaves no account, no secret and no claim behind.
  try {
    await probeAccount({ adapterFactory: factory, account: probeRow(input), credentials: probeCredentials(password) });
  } catch (error) {
    return { outcome: "probe_failed", code: codeOf(error) };
  }
  if (dryRun) return { outcome: "dry_run" };

  // 5. The row itself.
  let account;
  try {
    account = await createAccount(db, {
      label: input.label,
      address: input.address,
      username: input.username,
      authKind: "password",
      imap: input.imap,
      smtp: input.smtp,
    });
  } catch (error) {
    // The store's own uniqueness rule can still answer a duplicate a race slipped past step 1.
    if (isDuplicateAddress(error)) return { outcome: "duplicate" };
    return { outcome: "failed", code: codeOf(error), undone: false };
  }

  // 6. The sealed secret and this instance's claim, and 7. the claim re-check: a claim written a
  //    moment ago can still lose to one another instance wrote concurrently, and then nothing of this
  //    add may remain. So every failure from the claim write onwards releases the claim too — a
  //    claim nobody releases would hold the address against this very instance.
  // The flag is set BEFORE the claim write is awaited, not after: a write that was attempted and then
  // threw must still get its release. A release tombstone holds nothing, so a claim that never landed
  // (or landed half-way) leaves no phantom holder behind.
  let claimAttempted = false;
  try {
    await creds.saveSecret(account.id, "MAIL_PASSWORD", password);
    claimAttempted = true;
    await claims.writeClaim(db, input.address, { localInstanceId: local.instanceId, instanceName: local.instanceName });
    const after = await claims.checkClaim(db, input.address, { localInstanceId: local.instanceId });
    if (!after.ok) {
      await undoAdd(db, creds, account.id);
      await releaseClaimQuietly(claims, db, input.address, local.instanceId);
      return {
        outcome: "claimed",
        instanceName: after.instanceName,
        sentence: claimedElsewhereSentence(after.instanceName),
        undone: true,
      };
    }
  } catch (error) {
    await undoAdd(db, creds, account.id);
    // Only when the claim write was attempted: a saveSecret that failed before it never touched the
    // claim rows, so there is nothing to release.
    if (claimAttempted) await releaseClaimQuietly(claims, db, input.address, local.instanceId);
    return { outcome: "failed", code: codeOf(error), undone: true };
  }

  return { outcome: "added", account };
}

/* -------------------------------------------------------------------- main */

/**
 * Report one outcome the way the header documents: a line and an exit code, never a value.
 *
 * `hook` is the sync hook's outcome (`{ notified }`), which only changes the second line of the
 * "added" case: a running gateway that started syncing this account needs no restart sentence.
 */
function report(result, hook = { notified: false }) {
  switch (result.outcome) {
    case "added":
      console.log(`added account ${result.account.id} (${result.account.label}, ${result.account.address})`);
      console.log(hook?.notified === true
        ? "The running gateway started syncing this account."
        : "restart the gateway so the sync supervisor starts this account");
      return EXIT.ok;
    case "dry_run":
      console.log("dry run: the mail server accepted the sign-in and listed a folder; nothing was stored");
      return EXIT.ok;
    case "duplicate":
      console.error("refused: that address is already connected on this Crow");
      return EXIT.refused;
    case "claimed":
      console.error(`refused: ${result.sentence}`);
      return EXIT.refused;
    case "probe_failed":
      console.error(`sign-in failed: ${result.code}`);
      return EXIT.probeRefused;
    default:
      console.error(result.undone === false
        ? `failed (nothing was stored): ${result.code}`
        : `failed (undone): ${result.code}`);
      return EXIT.failed;
  }
}

/**
 * The crow.db this instance uses — the same expression `createDbClient()` falls back to, resolved
 * once here so the existence check and the printed line name the file that will really be opened.
 */
function instanceDbPath() {
  return process.env.CROW_DB_PATH || resolvePath(resolveDataDir(), "crow.db");
}

/**
 * The instance this run writes to: announce it, then check it is the gateway's own.
 *
 * One line, paths only, before anything else is reported: an add on the wrong instance is invisible
 * to Mail, and the operator has to be able to see which one this shell resolved. Then two refusals,
 * both exit 2 and both before a client or a key is created here:
 *
 *   - no crow.db at that path — `createDbClient` would create an empty database the gateway never
 *     reads, and the add would "succeed" into it;
 *   - no USABLE keychain key — `ensureWriteKey` would mint a key of its own, and every password the
 *     gateway sealed under the real one would become unreadable. A CLI never mints that key. The
 *     test is the keychain's own `keychainKeyState`, not a bare existence check: a key path that is a
 *     directory, an empty file or damaged JSON is exactly as unusable as a missing file, and sealing
 *     under it would fail — or, worse, succeed under a key the gateway does not have.
 *
 * @returns {{crowHome: string, dbPath: string}}
 */
function enterInstance() {
  const crowHome = resolveCrowHome();
  const dbPath = instanceDbPath();
  console.log(`mail add: writing to instance CROW_HOME=${crowHome} db=${dbPath}`);
  if (!existsSync(dbPath)) {
    throw usage("this instance has no crow.db yet, so there is nothing to add the account to; start the gateway once (it creates the database), then re-run");
  }
  if (keychainKeyState({ crowHome }).state !== "ok") {
    throw usage("the keychain key at this instance is missing or unreadable, and this script never creates one (the gateway owns that key); seal one secret in Crow's Nest, or restore the key file, then re-run");
  }
  return { crowHome, dbPath };
}

/**
 * `crow mail add`, end to end: parse and check the arguments, honour the flag, confirm the instance,
 * read the password from its one source, then run `addMailAccount` against that instance's database.
 *
 * @param {string[]} [argv]
 * @returns {Promise<number>} the process exit code
 */
export async function main(argv = process.argv.slice(2)) {
  let db = null;
  try {
    const args = parseArgs(argv);
    if (args.help) {
      printUsage();
      return EXIT.ok;
    }
    // Everything that can be refused without reading a secret or opening the database goes first.
    let input = validateFlags(args);

    // The flag, before a password is read: with CROW_MAIL unset the gateway reaches no mail route, so
    // an add would be invisible to it. --force-flag-off says "store it anyway, I know". The flag
    // normally lives in the gateway's unit, so the refusal says what this shell can see rather than
    // presuming it is unset everywhere.
    if (!mailEnabled()) {
      if (!args.forceFlagOff) {
        throw usage("CROW_MAIL=1 is not set in this shell. If the gateway runs with CROW_MAIL=1 (e.g. in its systemd unit), re-run with CROW_MAIL=1 set; otherwise the gateway will not sync this account.");
      }
      console.error("warning: CROW_MAIL=1 is not set in this shell — the gateway will not sync this account unless its own environment sets CROW_MAIL=1");
    }

    const instance = enterInstance();
    const sources = await readSources(args);
    input = readMailInput({ ...input, address: sources.address });
    const password = readPassword(sources.password);

    db = createDbClient(instance.dbPath);
    const result = await addMailAccount({ db, input, password, dryRun: args.dryRun === true });
    // A successful add is worth telling the running gateway about: its supervisor loaded its accounts
    // at boot, so it would otherwise leave this one alone until the next restart. Best effort in every
    // direction — a hook that does not get through is never the add's failure, and only the closing
    // line report() prints below depends on it; the exit code is the same either way.
    let hook = { notified: false };
    if (result.outcome === "added") {
      try {
        hook = await notifyMailSyncHook({
          accountId: result.account.id,
          tokenPath: MAIL_HOOK_TOKEN.path(),
          port: gatewayPort(),
        });
      } catch {
        // A hook failure is never the add's failure, and counts as not notified.
        hook = { notified: false };
      }
    }
    return report(result, hook);
  } catch (error) {
    if (error instanceof MailCliError) {
      console.error(error.message);
      if (error.exitCode === EXIT.usage) console.error("run with --help for the flags this needs");
      return error.exitCode;
    }
    // Anything else that reached here is this instance's own fault (a database that will not open, a
    // keychain write that failed outside the add): its own text may quote a path or a value, so only
    // the code is reported.
    console.error(`failed (nothing was stored): ${codeOf(error)}`);
    return EXIT.failed;
  } finally {
    try {
      db?.close?.();
    } catch {
      // A client that is already closed is the only failure a close has here.
    }
  }
}

/** Is this file the one node was asked to run? (A test imports it and gets no main.) */
function isMain() {
  const invoked = process.argv[1];
  if (!invoked) return false;
  const self = fileURLToPath(import.meta.url);
  try {
    return realpathSync(invoked) === realpathSync(self);
  } catch {
    return resolvePath(invoked) === resolvePath(self);
  }
}

if (isMain()) {
  const code = await main();
  // The exit code, not process.exit(): every line is already flushed and no promise is left hanging.
  process.exitCode = code;
}

export default main;

/** The reporter itself, for tests: `main` owns it, and only the closing line depends on the hook. */
export { report as _reportForTest };