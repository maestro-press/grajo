/**
 * local-model-servers — "is the own-host address this provider row names really a
 * model server this instance already knows about?"
 *
 * THE THREAT. A contained bot shares the host network (CROW_PI_CONTAIN_NET=off)
 * and has crow.db bound read-write, so it writes its OWN `providers` row:
 * `gpu_policy.door_forward = true`, `base_url = http://127.0.0.1:<free port>/v1`.
 * It then starts its own listener on that port — a relay to a cloud API — and
 * waits. Every earlier check judges the ADDRESS CLASS (isLocalClassTarget,
 * door-resolve.js): loopback is loopback, so the row passed, the door forwarded a
 * turn (and, on some paths, a provider api_key) to whatever was listening. Nothing
 * in the row may vouch for the row, so the answer has to come from OUTSIDE
 * crow.db, and it has to be about the port and about the process actually holding
 * the listening socket.
 *
 * THE RULE (two independent halves; both must hold for an own-host target):
 *
 *   (1) VOUCHED, by a source that lives outside crow.db, matching ADDRESS and
 *       PORT (`isKnownLocalModelTarget`):
 *         a. a MODEL-SERVER Docker container — running OR stopped — publishing the
 *            port on the address (`HostConfig.PortBindings`, read through the
 *            docker CLI the gateway already uses). A stopped container's binding
 *            still vouches the port; that is exactly why the squat test works.
 *            NOT every container counts (S3, security review): a container
 *            vouches only when its compose project directory — the
 *            `com.docker.compose.project.working_dir` label Docker COMPOSE
 *            writes, never something this module invents — is
 *              (i) a Crow bundle directory, the repo's `bundles/<id>` or
 *                  `<CROW_HOME>/bundles/<id>`, whose `manifest.json` declares
 *                  `"category": "ai"`, or
 *              (ii) a compose directory the operator PINNED (a `composeDir`
 *                  entry in the pin file, written only by
 *                  `scripts/cli/local-model-pin.js add-compose`).
 *            A container with no compose label, or one whose bundle is not an AI
 *            bundle (search, Nextcloud, Home Assistant, a household Crow
 *            container…), publishes nothing Crow will forward to. Cached ~30 s;
 *            an unreachable Docker falls back to the last GOOD snapshot, and with
 *            no snapshot at all the source vouches nothing (fail closed). A
 *            container CREATED at acquire time is not in that snapshot, so a
 *            not-vouched own-host result LAST re-reads Docker ONCE (`force`)
 *            before it is refused, rate-limited process-wide (S2/H2).
 *         b. an installed bundle's compose file under <CROW_HOME>/bundles/<id>/
 *            publishing the port (published host port, optional host IP) — and
 *            only for a bundle whose `manifest.json` declares `"category": "ai"`,
 *            the same category rule vouch (a) applies.
 *         c. a native-runtime reservation in <data dir>/models/state.json
 *            (servers/gateway/models/state.js) with that port and a recorded pid
 *            that is alive — NOT "the port is in 18100-18199", which a bot can
 *            pick too.
 *         d. an operator pin, <CROW_HOME>/secrets/local-model-endpoints.json:
 *            `[{ "address": "...", "port": N, "exe": "/abs/path/of/binary" }]`,
 *            mode 0600, written only by `scripts/cli/local-model-pin.js` (read
 *            fresh; the secrets directory is not bound into a bot sandbox). The
 *            SAME file carries the COMPOSE-DIRECTORY pins —
 *            `[{ "composeDir": "/abs/compose/project/dir" }]`, written by
 *            `add-compose` / `rm-compose`, realpath'd, an existing directory —
 *            and those do not vouch a port themselves: they make a Docker
 *            container's compose working directory an allowed one (vouch (a) ii),
 *            which is how a model the owner runs from their own `docker compose`
 *            directory becomes a known model server. The SAME file carries the
 *            CONTAINER-NAME pins — `[{ "container": "flash-next-gufo" }]`, from
 *            `add-container` / `rm-container` — for a model container started by
 *            a systemd unit's plain `docker run` (no compose label at all): a
 *            pinned NAME vouches its published bindings exactly like an
 *            AI-bundle container (exact match against Docker's name without the
 *            leading "/"), and nothing else does.
 *         e. this gateway's OWN listen port (`gatewayListenPorts`), and — at
 *            forward time only — a listening socket owned by this very process:
 *            a `providers` row is bot-writable, but nothing a bot writes can make
 *            the gateway open a listening socket, so the socket itself is proof.
 *       A bind on 0.0.0.0/:: covers every own address, and "localhost" means
 *       loopback; anything else must name the address itself, so a vouch on
 *       100.64.20.5:8004 never vouches 127.0.0.1:8004.
 *
 *   (2) THE CURRENT LISTENER IS NOT A BOT (`isKnownLocalModelTarget`, checked at
 *       forward time, AFTER any on-demand start, so a cold native model that the
 *       acquire just started is already listening). Two judgements:
 *
 *       (2a) THE ACCEPTED CONNECTION, before any request byte is written
 *            (`verifyAcceptedConnection`, H1). llama.cpp's server sets
 *            SO_REUSEPORT and a contained bot shares the host network, so a bot
 *            can open its own reuseport listener on the model's port BETWEEN this
 *            check and the connect and be handed the connection; a pooled
 *            keep-alive socket would stretch one win over many requests. The
 *            forward therefore opens the TCP socket itself, finds the SERVER side
 *            of THAT connection in /proc/net/tcp{,6} (local = the server
 *            address:port, remote = our socket's localAddress:localPort, in ANY
 *            live state: a socket a peer already half-closed is visible as
 *            FIN_WAIT1/2, never as 01) and accepts it only when its uid is not
 *            ours (docker-proxy) or its accepted inode is held by a trusted
 *            candidate pid — the same candidate set (2b) uses. A same-uid row in
 *            any state but ESTABLISHED is a REFUSAL — EXCEPT SYN_RECV, which is
 *            PENDING (N1): under load our connect completes before the server has
 *            processed the final ACK, so a row in 03 is waited on within the
 *            accept budget, never refused. Every other state is a refusal: our
 *            connection IS in this namespace, and the socket that held the other
 *            end is closing — exactly what a bot's half-close looks like. A
 *            connection with NO
 *            server-side row in this network namespace at all is trusted as
 *            "nat-to-container" when a RUNNING Docker container's binding vouches
 *            the address:port (`running === true`; an entry that does not say so
 *            is not evidence of NAT rules) AND no same-uid listener exists there
 *            (`noLocalRowIsDockerNat`): Docker DNATs host-originated traffic to
 *            the host's own non-loopback address straight into the container's
 *            namespace, so such a peer legitimately has no socket here — a peer a
 *            bot could control would have one. Otherwise the socket is destroyed
 *            and the forward refused as "connection-not-trusted". Own-host forwards
 *            are never pooled (`agent: false`, `Connection: close`).
 *
 *       (2b) THE LISTENER:
 *         - find EVERY LISTEN socket (state 0A) for that address and port in
 *           /proc/net/tcp and /proc/net/tcp6 (little-endian addresses, v4-mapped
 *           unwrapped), and read its uid and inode;
 *         - no listener -> "no-listener" (an on-demand start that never came up
 *           is not a model server);
 *         - a uid OTHER than the gateway's own -> OK. A bot cannot run as another
 *           uid (contain = no_new_privs plus a user namespace that maps only the
 *           gateway uid), so this is docker-proxy (root) and other services;
 *         - EVERY same-uid listener row must be trusted — not merely one of them.
 *           A name can stand for several addresses (localhost is 127.0.0.1 AND
 *           ::1) and SO_REUSEPORT lets two sockets share one address and port, so
 *           "one trusted row" would let a bot's socket answer the forward that a
 *           model's socket vouched for. One untrusted same-uid row, or a row whose
 *           owning pid cannot be found, is "listener-not-trusted";
 *         - a same-uid row is trusted only if the pid holding its socket (found by a
 *           CANDIDATE-ONLY search — this process, a live native handle for that
 *           port, a pinned/managed-binary holder found by exe, or a docker-cgroup
 *           pid found via /proc/<pid>/cgroup for same-uid pids; never a scan of
 *           every process's fd table, H4) is
 *             (i) this very process (the gateway's own code — nothing a bot
 *                 writes into crow.db can make the gateway open a listener),
 *                 or a pid in a Docker container cgroup (`docker-<64hex>.scope` /
 *                 `/docker/<64hex>`), or
 *             (ii) THE NATIVE RUNTIME'S OWN CHILD, matched by PID — never by
 *                 ancestry. In the gateway process (`deps.nativeHandles`, default:
 *                 `runtime.js` `getStatusSnapshot()`) the pid must equal the pid of
 *                 a LIVE handle for THIS port AND for the address that handle
 *                 binds (`--host`, default 127.0.0.1, `buildLlamaServerArgs`). In
 *                 a process with no native handles at all (the memory MCP child, a
 *                 pi-bots host process — this fallback exists for those, because no
 *                 handle of ours can name their children) the pid must
 *                   - hold a LIVE reservation for this port in
 *                     `<data dir>/models/state.json` that RECORDS a pid which is
 *                     alive (a reservation with no recorded pid is not live), and
 *                   - run in THIS process's user namespace — the same check the pin
 *                     rule makes, because a bot sandbox has a namespace of its own,
 *                     and
 *                   - execute, by dev+inode of `/proc/<pid>/exe`, one of the
 *                     runtime's own managed llama-server binaries — and those are
 *                     identified BY CONTENT, never by path: the file's sha256 must
 *                     equal the checksum `ensureRuntime` recorded when it verified
 *                     that binary (`binSha256` in the release's
 *                     `.crow-runtime-installed.json`), and no recorded checksum for
 *                     that binary means that binary never counts
 *                     (`managedLlamaServerCandidates`). A candidate must lstat as a
 *                     REGULAR file (a symlink is never one) that stays inside its
 *                     own release dir; a `relBinPath` from the manifest that is
 *                     absolute or carries a `..` segment is ignored. Hash results are
 *                     cached by dev+inode+size+mtime, so a forward never re-hashes an
 *                     unchanged binary. A real llama-server cannot relay to a cloud.
 *                 The OLD "recorded pid or a descendant of it in the gateway's user
 *                 namespace" rule is GONE: an uncontained bot (sandbox off, the
 *                 setpriv fallback, a bot in a container instance) is exactly such a
 *                 descendant, so ancestry proved nothing;
 *             or (iii) a pinned executable: realpath(/proc/<pid>/exe) === the pin's
 *                 `exe` AND the process's user namespace is the gateway's own
 *                 (a bot sandbox runs in its own user namespace, so a pinned path
 *                 alone is never enough).
 *
 * LIMITS, stated plainly. These rules are only as good as the tier a bot runs in. A
 * sandboxed bot (bwrap, its own user namespace) is separated from the gateway by the
 * namespace and cgroup rules; a tier WITHOUT a sandbox (`CROW_PI_SANDBOX=off`, no
 * bwrap on the host, the setpriv fallback) shares the gateway's uid AND its network
 * namespace, so it is covered only by the vouch plus the uid/exe/cgroup rules. The
 * sharp edge: an uncontained bot can bind the vouched port of a STOPPED docker model
 * and is then refused only because it is not root, not in a container cgroup, not a
 * live native handle and not the runtime's own binary — the rule holds, but nothing
 * sandbox-side backs it up.
 *
 * FIVE MORE LIMITS, stated so nobody reads a guarantee into them:
 *
 *   (a) "other-host" is an ADDRESS CLASS, not a statement of trust. A target that is
 *       not this machine is allowed here (a bot cannot listen on another machine), and
 *       the class does NOT say who runs it: a tailnet peer can be a cloud VM the owner
 *       added — a `100.64.x.x` host serving a cloud model behind a proxy is
 *       indistinguishable, by address, from a paired gateway. Only own-host targets
 *       are vouched; an other-host row is the owner's own statement of where that
 *       model lives.
 *
 *   (b) THE DOCKER VOUCH IS ONLY AS STRONG AS DOCKER ACCESS. Vouch (a) trusts a
 *       compose label and the bundle/pin directory it names, and an UNCONTAINED bot
 *       that is in the docker group can `docker run -p 127.0.0.1:P:…` a container of
 *       its own. With the model-container rule such a container must ALSO name an
 *       AI-bundle working directory or a directory the owner pinned, so a bare
 *       publish no longer opens the box — but that bot can still WRITE in a bundle
 *       directory it can reach in this tier (it runs as the gateway's own uid),
 *       create a manifest saying `"category": "ai"`, and label a container with that
 *       path. The residual is therefore stated: a docker-group bot in an uncontained
 *       tier can mint the vouch it needs. A contained tier (its own user namespace,
 *       no host docker socket) or a host where the gateway's uid is not in the docker
 *       group closes it. The pin file's compose entries have the same shape of
 *       residual, narrower: a sandbox cannot write `<CROW_HOME>/secrets`, an
 *       uncontained bot can.
 *
 *   (c) THE FORCED-REFRESH WINDOW IS PROCESS-WIDE AND SHARED. At most ONE forced
 *       Docker re-read is allowed per `DOCKER_REFRESH_MIN_MS` for the WHOLE process
 *       (H2 chose that over a per-target window, which a bot's own port choice made
 *       worthless). The trade is availability, never trust: a bot that keeps asking
 *       for unvouched own-host targets inside the window consumes it, so a container
 *       CREATED a moment ago can take up to one vouch-snapshot TTL (`VOUCH_TTL_MS`,
 *       30 s) before the first forward to it is admitted. Nothing is vouched that
 *       Docker did not publish; a forward is only DELAYED.
 *
 *   (d) THE COMPOSE-LABEL RULE NAMES THIS CHECKOUT. `repoBundlesDir()` is
 *       `<this module's checkout>/bundles`, so a gateway running from checkout A
 *       vouches no container whose compose working directory is checkout B's
 *       `bundles/<id>` — until those containers are recreated by compose run from A.
 *       (A dev tree has always had that shape; `<CROW_HOME>/bundles/<id>` is the
 *       other, path-stable parent and an installed instance uses it.) The operator is
 *       not left guessing: `logUnvouchedProviderRows` prints the boot line naming
 *       every enabled row whose target nothing vouches for at rest.
 *
 *   (e) `"category": "ai"` IS WIDER THAN "SERVES A MODEL API". It is the bundle
 *       manifest's existing category, so an AI bundle that publishes no model API at
 *       all (an image generator's UI, a transcription console) vouches its published
 *       ports just like a model server. That is deliberate for now — the alternative
 *       would be a second vouch allowlist nobody maintains — and a dedicated manifest
 *       flag ("publishes a model API") is the documented follow-up. The LISTENER half
 *       is unchanged either way: whoever holds the socket must still be Crow's.
 *
 * THE MANAGED-BINARY FALLBACK'S OWN LIMIT (ii), spelled out. It is the path for
 * processes that hold NO native handles of their own — the memory MCP child and a
 * pi-bots host process — and it stands on files under `<CROW_HOME>`: the release
 * manifest that records the binary's checksum, and the binary itself. Those files
 * are never BOUND into a bot sandbox, which is what makes them usable as a vouch
 * from outside crow.db. That is a containment fact, not a permission one: an
 * UNCONTAINED bot runs as the gateway's own uid and can therefore rewrite the
 * manifest or replace a release binary exactly as the gateway can, and then the map
 * back to `ensureRuntime`'s install means nothing. That is the stated residual of
 * this tier — the tier in which the uid/cgroup/user-namespace rules are the only
 * thing standing between a bot and the vouch.
 *
 * `isKnownLocalModelTargetCached` is the SYNC, vouch-only half, for LISTING and
 * CLASSIFICATION only (never to authorize a forward): it uses the cached Docker
 * snapshot plus the sync-readable sources, so a listing never dials anything. An
 * own-host target no source vouches for is the "unverified-local" class: neither
 * local (never offered as a local model, never forwarded) nor cloud (never in the
 * cloud allowlist, never through the cloud door).
 *
 * A DOOR URL FROM A CHILD (M1). A Crow gateway door URL (`isDoorUrl`: `/llm/v1`,
 * `/llm/p/<id>/v1`) on this host is refused with the reason "door-url-from-child"
 * unless THIS PROCESS is the gateway (`markGatewayProcess`, called by
 * `servers/gateway/index.js`). The memory MCP child and a pi-bots host process
 * import this module too, and from there a door URL is not a model server at all:
 * the answer used to be the accidental "listener-not-trusted" (the socket belongs
 * to the gateway, not to the child), which reads like a squat rather than like "a
 * child may not drive the door". Fail closed, with the real reason.
 *
 * S1 (the boot line). `logUnvouchedProviderRows` prints ONE line per ENABLED
 * provider row whose own-host target nothing vouches for AT REST, right after the
 * gateway's first vouch snapshot (`boot/admin-api.js`, beside
 * `primeLocalModelVouch`). Logs only: it changes no decision, it tells the
 * operator which rows will be refused at forward time (the row may be fine — the
 * container simply is not running yet).
 *
 * Every host read is injectable (`deps`): the resolver, own addresses, the clock,
 * the fs functions, the /proc root, the uid, this process's pid and user namespace,
 * the native handles (`nativeHandles`), the docker runner, a prebuilt vouch
 * snapshot, and the candidate addresses the caller may dial (`dialAddresses` — the
 * ordered answer list from `pinnedTargetOf`'s `dialAnswers` — or a `pinned`
 * result). `deps.dockerEntries` is a snapshot the caller states Docker already
 * FILTERED (it bypasses `readDockerEntries`, so it skips S3's compose-directory
 * rule); `deps.isGatewayProcess` states whether this is the gateway process (M1's
 * door-URL rule). Tests never need to own a real /proc or a real Docker.
 *
 * IMPORT NOTE. This module is reachable from scripts/pi-bots/bridge.mjs (the bot
 * engine), so its static import closure must never reach servers/sharing/identity.js
 * or secret-box.js (tests/bot-seed-import-guard.test.js). It imports the address
 * predicates, node builtins, and `runtime.js`'s `getStatusSnapshot` (the native
 * handles THIS process supervises — the same module instance the gateway's
 * gpu-orchestrator registers into); none of that reaches the seed. The door-resolve
 * <-> self-target import cycle is deliberate and safe: both sides only call each
 * other's functions at call time, never while a module is being evaluated.
 */
import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import dns from "node:dns";
import * as nodeFs from "node:fs";
import { dirname, isAbsolute, join, relative } from "node:path";
import { fileURLToPath } from "node:url";

import { resolveCrowHome, resolveInstanceDataDir } from "../../shared/crow-home.js";
import { isDoorUrl, isForbiddenTarget, isLocalClassTarget } from "./door-resolve.js";
import { getStatusSnapshot } from "./runtime.js";
import { isOwnHostAddress, gatewayListenPorts, targetAddresses, targetHost, targetPort } from "./self-target.js";

/** How long a vouch snapshot (this module's own cache) stays usable. */
export const VOUCH_TTL_MS = 30_000;
/** A snapshot younger than this is not re-read on a vouch miss (thrash guard). */
export const VOUCH_MISS_REFRESH_MIN_AGE_MS = 2_000;
/** The pin file: `<CROW_HOME>/secrets/local-model-endpoints.json`. */
export const PIN_FILE = "local-model-endpoints.json";
/**
 * The label Docker COMPOSE writes on every container of a project: the project's
 * working directory. It is the ONLY thing that says which compose file (and so
 * which bundle or pinned directory) a container belongs to — a port number says
 * nothing about what is published on it.
 */
export const COMPOSE_WORKING_DIR_LABEL = "com.docker.compose.project.working_dir";
/** The bundle manifest category whose published ports vouch (S3). */
export const MODEL_BUNDLE_CATEGORY = "ai";
/**
 * At most ONE forced Docker re-read inside this window — for the WHOLE process,
 * across every target, not one window per address:port (S2: a container created
 * by the acquire is not in the <=30 s snapshot, so a not-vouched forward re-reads
 * once before refusing — but a bot retrying in a loop must not turn that into one
 * `docker inspect` per request).
 *
 * H2 (security review): the window key used to be the target's address:port, and
 * that key is ATTACKER-CHOSEN — a contained bot writes its own `providers` row, so
 * cycling ports made every forward start its own `docker` subprocess (and grew the
 * key map without bound). One global window per process closes that: N forwards to
 * N different unvouched ports are ONE Docker read.
 */
export const DOCKER_REFRESH_MIN_MS = 10_000;
/** Names a bundle's published-port declaration may use. */
const BUNDLE_COMPOSE_FILES = Object.freeze(["docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"]);
/** Names that always mean this host, before any resolver is asked (RFC 6761). */
const LOOPBACK_NAMES = new Set(["localhost", "ip6-localhost", "ip6-loopback", "localhost.localdomain"]);
/** The addresses a LOOPBACK NAME stands for. A listing is sync (it can never ask
 * a resolver), so `localhost` is judged as BOTH loopback addresses rather than as
 * the literal string "localhost" — which matched no binding at all and made every
 * `localhost:<port>` row (the Ollama bundle's 11434, a Kokoro on 8880) drop out of
 * the listings as "unverified-local". */
const LOOPBACK_NAME_ADDRESSES = Object.freeze(["127.0.0.1", "::1"]);
/** A bind on one of these covers every own address. */
const WILDCARD_ADDRS = new Set(["", "0.0.0.0", "::", "[::]", "*"]);
/** The release manifest `ensureRuntime` writes (runtime.js) — the one place the
 * checksum it verified an installed BINARY against is recorded. */
const RUNTIME_MANIFEST_FILE = ".crow-runtime-installed.json";
/** The two archive-internal shapes llama.cpp's release tarballs extract the binary
 * to, so an install whose manifest was replaced by a newer release still matches
 * the binary it is actually running. */
const LLAMA_SERVER_SHAPES = Object.freeze(["llama-server", "build/bin/llama-server"]);
const SHA256_RE = /^[0-9a-f]{64}$/;
/** Chunk size for a managed binary's sha256 (a llama-server binary is hundreds of
 * MB: never read whole). */
const HASH_CHUNK_BYTES = 1 << 20;
/** A Docker container's cgroup: `docker-<64hex>.scope` (systemd) or `/docker/<64hex>`. */
const DOCKER_CGROUP_RE = /(?:docker-[0-9a-f]{64}\.scope)|\/docker\/[0-9a-f]{64}/;
const LISTEN_STATE = "0A";
/** A live TCP connection (`ESTABLISHED`) — what an ACCEPTED socket looks like in
 * /proc/net/tcp once the handshake is done (see `verifyAcceptedConnection`). */
const ESTABLISHED_STATE = "01";
/** A row left over by a CLOSED connection (`TIME_WAIT`). It is not this
 * connection: a client port can be reused, and a TIME_WAIT row's owner is
 * nobody's live socket, so it never counts as "the server end is here". */
const TIME_WAIT_STATE = "06";
/** A server-side row whose handshake is not finished yet (`SYN_RECV`). It is THIS
 * connection, in our own namespace, in the moment before the server processed the
 * final ACK — a row to WAIT on, never one to refuse on (N1: on a loaded box the
 * client's connect completes before the server's row leaves SYN_RECV, and refusing
 * there refused a healthy model server exactly while it was busy serving).
 * FIN_WAIT1/2, CLOSE_WAIT, LAST_ACK, CLOSING and the rest stay REFUSALS: there the
 * peer has already hung up on a connection that IS in this namespace. */
const SYN_RECV_STATE = "03";
/** The accept wait's poll schedule. The kernel hands an accepted connection to a
 * socket within a millisecond or two, so the first window is polled at ~2 ms — a
 * fixed 10 ms poll was most of a loopback forward's added latency. After that window
 * the interval backs off, so a listener that never accepts costs a handful of reads
 * over the whole accept budget instead of a spin. `pollMs` is a caller's own base.
 * None of this decides ANYTHING: only how often the same question is asked. */
export const ACCEPT_POLL_FAST_MS = 2;
export const ACCEPT_POLL_FAST_WINDOW_MS = 20;
export const ACCEPT_POLL_BASE_MS = 5;
export const ACCEPT_POLL_MAX_MS = 50;
/** How long a verified connect waits for a LOCAL server-side row before it accepts
 * the "Docker NATed this into a container" explanation (see
 * `noLocalRowIsDockerNat`). A local listener's established child — even one no
 * application has accepted yet, whose inode is still 0 — is visible in this
 * network namespace THE MOMENT `connect()` completes, so one short re-read is all
 * this needs; it is never the 2 s accept budget. (Matching ANY state, not only
 * ESTABLISHED, is what makes it short: a squatter that half-closes leaves a
 * FIN_WAIT row, so the second look at 10 ms already knows this is local.) */
export const NAT_ROW_WAIT_MS = 10;

// ---------------------------------------------------------------------------
// Address helpers
// ---------------------------------------------------------------------------

/** An address in one comparable spelling: no brackets, no zone, lower case, and
 * an IPv4-mapped IPv6 unwrapped to the IPv4 it carries — in BOTH spellings. A
 * target URL may name `[::ffff:127.0.0.1]` or `[::ffff:7f00:1]`, and a dual-stack
 * socket's `localAddress` comes back hex-mapped, while the kernel row in
 * /proc/net/tcp{,6} decodes to `127.0.0.1`: without the hex unwrap those two never
 * compared equal and a verified connect to a mapped loopback/own address was
 * refused as `connection-not-trusted`. */
export function normalizeAddress(addr) {
  return String(addr ?? "")
    .replace(/^\[|\]$/g, "")
    .replace(/%.*$/, "")
    .trim()
    .toLowerCase()
    .replace(/^::ffff:(\d{1,3}(?:\.\d{1,3}){3})$/, "$1")
    .replace(/^(?:::ffff:|(?:0:){5}ffff:)([0-9a-f]{1,4}):([0-9a-f]{1,4})$/, (_m, hi, lo) => {
      const h = Number.parseInt(hi, 16);
      const l = Number.parseInt(lo, 16);
      return `${h >> 8}.${h & 0xff}.${l >> 8}.${l & 0xff}`;
    });
}

/** An IPv6 address in its eight-group spelling (`::1` -> `0:0:0:0:0:0:0:1`), so the
 * compressed and expanded spellings of ONE address compare equal. The kernel's
 * `/proc/net/tcp6` rows are always the expanded form; a target URL may be either.
 * Anything that is not IPv6 is returned unchanged. */
function expandIpv6(addr) {
  const a = String(addr ?? "");
  if (a.split(":").length < 3) return a;
  const [head, tail] = a.split("::");
  const left = head ? head.split(":") : [];
  const right = tail ? tail.split(":") : [];
  if (tail !== undefined && left.length + right.length > 7) return a;
  if (tail === undefined && left.length !== 8) return a;
  const fill = tail === undefined ? 0 : 8 - left.length - right.length;
  return [...left, ...Array(Math.max(0, fill)).fill("0"), ...right]
    .map((g) => (/^[0-9a-f]{1,4}$/.test(g) ? g.replace(/^0+(?=.)/, "") : g))
    .join(":");
}

/** The spelling every address COMPARISON uses: `normalizeAddress`, plus the
 * expanded IPv6 form so `::1` and `0:0:0:0:0:0:0:1` are one address. */
function compareAddress(addr) {
  return expandIpv6(normalizeAddress(addr));
}

const isLoopbackAddress = (addr) => {
  const a = compareAddress(addr);
  return a === "::1" || a === "0:0:0:0:0:0:0:1" || /^127\./.test(a);
};

/**
 * Does a vouch/bind on `binding` cover the target addresses? A wildcard covers
 * every own address; "localhost" means loopback; anything else must name one of
 * the addresses the target URL resolves to (so a vouch on 100.64.20.5:8004 never
 * vouches 127.0.0.1:8004).
 */
export function bindingCovers(binding, targetAddrs = []) {
  const b = normalizeAddress(binding);
  if (WILDCARD_ADDRS.has(b)) return true;
  if (b === "localhost" || LOOPBACK_NAMES.has(b)) return targetAddrs.some((a) => isLoopbackAddress(a));
  return targetAddrs.some((a) => compareAddress(a) === compareAddress(b));
}

// ---------------------------------------------------------------------------
// deps
// ---------------------------------------------------------------------------

function readCrowHome(deps) {
  if (typeof deps.crowHome === "string" && deps.crowHome) return deps.crowHome;
  try { return resolveCrowHome(); } catch { return null; }
}

/** Every host read this module makes, resolved once per call. */
function resolveDeps(deps = {}) {
  const fs = deps.fs || nodeFs;
  return {
    ...deps,
    fs,
    now: deps.now || Date.now,
    lookupFn: deps.lookupFn || dns.lookup,
    ownAddrs: deps.ownAddrs || undefined,
    uid: typeof deps.uid === "number" ? deps.uid : (typeof process.getuid === "function" ? process.getuid() : 0),
    selfPid: Number.isInteger(deps.selfPid) ? deps.selfPid : process.pid,
    procRoot: deps.procRoot || "/proc",
    crowHome: readCrowHome(deps),
    isProcessAlive: deps.isProcessAlive || defaultIsProcessAlive,
    dockerRunner: deps.dockerRunner || defaultDockerRunner,
  };
}

/** True if a pid looks alive: kill(pid, 0) succeeds, or fails EPERM (exists, not
 * ours). Only ESRCH means gone. */
function defaultIsProcessAlive(pid) {
  const n = Number(pid);
  if (!Number.isInteger(n) || n <= 0) return false;
  try { process.kill(n, 0); return true; } catch (err) { return err?.code === "EPERM"; }
}

/** The docker CLI runner: `(cmd, args, opts) => Promise<{stdout, stderr}>`. */
function defaultDockerRunner(cmd, args, { timeout = 15_000 } = {}) {
  return new Promise((resolveP, reject) => {
    execFile(cmd, args, { timeout, maxBuffer: 8 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) reject(Object.assign(err, { stdout, stderr }));
      else resolveP({ stdout, stderr });
    });
  });
}

function readText(path, d, encoding = "utf8") {
  try { return d.fs.readFileSync(path, encoding); } catch { return null; }
}

// ---------------------------------------------------------------------------
// Which process is asking (M1)
// ---------------------------------------------------------------------------

/** Set by the gateway's own entry point: THIS process is the gateway. */
let _gatewayProcess = false;

/**
 * `servers/gateway/index.js` calls this once at startup, so the ONE process that
 * owns the model door is the one allowed to forward to a door URL on this host.
 * Every other importer (the memory MCP child, a pi-bots host process, a bundle
 * server) leaves the mark unset — fail closed — and a door URL from there is
 * refused with the reason "door-url-from-child" (`isKnownLocalModelTarget`).
 */
export function markGatewayProcess() { _gatewayProcess = true; }

/** Undo the mark (tests; a process does not stop being the gateway). */
export function resetGatewayProcessMark() { _gatewayProcess = false; }

/** Is this the gateway process? `deps.isGatewayProcess` overrides both ways (the
 * seam a test states the answer with). */
function gatewayProcessHere(d) {
  if (typeof d.isGatewayProcess === "boolean") return d.isGatewayProcess;
  return _gatewayProcess;
}

// ---------------------------------------------------------------------------
// Vouch source (b): an installed bundle's compose file
// ---------------------------------------------------------------------------

/** `${VAR}`, `${VAR:-def}`, `${VAR-def}`, `$VAR` against a compose environment. */
function expandVars(text, env) {
  return String(text ?? "")
    .replace(/\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}/g, (_m, name, def) => {
      if (Object.prototype.hasOwnProperty.call(env, name)) return String(env[name]);
      return def === undefined ? "" : def;
    })
    .replace(/\$([A-Za-z_][A-Za-z0-9_]*)/g, (m, name) => (Object.prototype.hasOwnProperty.call(env, name) ? String(env[name]) : m));
}

/** A bundle's `.env` as an object (KEY=VALUE, `#` comments, simple quotes). */
function parseDotEnv(text) {
  const out = {};
  for (const raw of String(text ?? "").split(/\r?\n/)) {
    const line = raw.trim();
    if (!line || line.startsWith("#")) continue;
    const at = line.indexOf("=");
    if (at <= 0) continue;
    const key = line.slice(0, at).trim();
    let value = line.slice(at + 1).trim();
    if ((value.startsWith('"') && value.endsWith('"')) || (value.startsWith("'") && value.endsWith("'"))) value = value.slice(1, -1);
    out[key] = value;
  }
  return out;
}

const composeScalar = (raw) => String(raw ?? "").replace(/\s+#.*$/, "").trim().replace(/^["']|["']$/g, "").trim();

/** `8000` or `8000-8002` → [8000] / [8000,8001,8002]; null when it is not a port
 * range (an unresolved variable, a random publish). Capped so a nonsense range
 * cannot allocate an enormous list. */
function expandPortRange(text) {
  const m = /^(\d{1,5})(?:-(\d{1,5}))?$/.exec(String(text ?? "").trim());
  if (!m) return null;
  const lo = Number(m[1]);
  const hi = m[2] === undefined ? lo : Number(m[2]);
  if (!(lo >= 1 && hi <= 65535 && hi >= lo && hi - lo <= 256)) return null;
  const out = [];
  for (let p = lo; p <= hi; p++) out.push(p);
  return out;
}

/** One short-syntax port spec (`[ip:][host:]container[/proto]`) → published host
 * ports. A single value is a container port with a RANDOM host port, which
 * vouches nothing. */
function parseShortPort(spec, env, out) {
  let text = composeScalar(expandVars(String(spec ?? ""), env));
  if (!text) return;
  const slash = text.lastIndexOf("/");
  if (slash >= 0) {
    // Only a tcp publish can be a model server.
    if (composeScalar(text.slice(slash + 1)).toLowerCase() !== "tcp") return;
    text = text.slice(0, slash);
  }
  const parts = text.split(":");
  let address = null;
  let hostPortText = null;
  if (parts.length === 1) return; // container port only: the host port is chosen by docker
  if (parts.length === 2) hostPortText = parts[0];
  else { address = parts.slice(0, -2).join(":") || null; hostPortText = parts.at(-2); }
  const ports = expandPortRange(hostPortText);
  if (!ports) return;
  for (const port of ports) out.push({ address: address ? normalizeAddress(address) : null, port });
}

/** The published HOST ports a compose text declares, as `[{address, port}]`
 * (`address: null` = every interface). Both the short and the long syntax, and
 * `${VAR}` resolved exactly as compose resolves it. */
export function publishedPortsOf(text, env = {}) {
  const out = [];
  const lines = String(text ?? "").split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    const key = /^(\s*)ports:\s*(.*)$/.exec(lines[i]);
    if (!key) continue;
    const indent = key[1].length;
    const inline = composeScalar(key[2]);
    if (inline.startsWith("[")) {
      for (const item of inline.slice(1).replace(/\]\s*$/, "").split(",")) parseShortPort(item, env, out);
      continue;
    }
    // A block list: `- "127.0.0.1:8004:8004"`, or the long `target:`/`published:`
    // mapping form (whose `published:` is the host port).
    let long = null;
    const flush = () => {
      if (long && long.published !== undefined && long.target !== undefined) {
        const protocol = long.protocol === undefined ? "tcp" : composeScalar(expandVars(String(long.protocol), env)).toLowerCase();
        const ports = protocol === "tcp" ? expandPortRange(composeScalar(expandVars(String(long.published), env))) : null;
        const address = long.host_ip === undefined ? null : normalizeAddress(composeScalar(expandVars(String(long.host_ip), env)));
        if (ports) for (const port of ports) out.push({ address: address || null, port });
      }
      long = null;
    };
    for (let j = i + 1; j < lines.length; j++) {
      const line = lines[j];
      if (!line.trim() || /^\s*#/.test(line)) continue;
      const ind = /^(\s*)/.exec(line)[1].length;
      if (ind <= indent) break;
      const item = /^\s*-\s*(.*)$/.exec(line);
      if (item) {
        flush();
        const val = composeScalar(item[1]);
        const kv = /^([A-Za-z_]+)\s*:\s*(.*)$/.exec(val);
        if (kv) long = { [kv[1]]: composeScalar(kv[2]) };
        else parseShortPort(val, env, out);
        continue;
      }
      const kv = /^\s+([A-Za-z_]+)\s*:\s*(.*)$/.exec(line);
      if (kv && long) { long[kv[1]] = composeScalar(kv[2]); continue; }
      flush();
    }
    flush();
  }
  return out;
}

// ---------------------------------------------------------------------------
// Which compose directories may vouch (S3)
// ---------------------------------------------------------------------------

/** The repo's own `bundles/` directory (this module lives in servers/gateway/models). */
function repoBundlesDir() {
  return join(dirname(fileURLToPath(import.meta.url)), "..", "..", "..", "bundles");
}

/** `path` with symlinks resolved, or `path` itself when it cannot be resolved. */
function realPathOrSelf(path, d) {
  const p = String(path ?? "");
  if (!p) return p;
  try { return d.fs.realpathSync ? d.fs.realpathSync(p) : p; } catch { return p; }
}

/** A manifest.json's `category`, lower-cased, or null (missing / unreadable / not JSON). */
function bundleCategoryOf(bundleDir, d) {
  const raw = readText(join(bundleDir, "manifest.json"), d);
  if (raw == null) return null;
  let manifest;
  try { manifest = JSON.parse(raw); } catch { return null; }
  const category = manifest && typeof manifest.category === "string" ? manifest.category.trim().toLowerCase() : "";
  return category || null;
}

/**
 * Is `dir` a Crow bundle directory whose `manifest.json` declares `"category": "ai"`?
 *
 * Both places a bundle lives count: the repo's own `bundles/<id>` (a dev install
 * runs compose from the checkout) and `<CROW_HOME>/bundles/<id>` (an installed
 * copy). `dir` must be EXACTLY that directory, not a parent or a child: compose's
 * working dir label is the project dir the compose file sits in.
 */
export function isModelBundleDir(dir, deps = {}) {
  const d = resolveDeps(deps);
  const given = String(dir ?? "").trim();
  if (!given) return false;
  const real = realPathOrSelf(given, d);
  const parents = [repoBundlesDir()];
  if (d.crowHome) parents.push(join(d.crowHome, "bundles"));
  for (const parent of parents) {
    if (dirname(real) !== realPathOrSelf(parent, d)) continue;
    if (bundleCategoryOf(real, d) === MODEL_BUNDLE_CATEGORY) return true;
  }
  return false;
}

/**
 * The pin file's COMPOSE-DIRECTORY entries: absolute, realpath'd compose project
 * dirs the owner pinned with `scripts/cli/local-model-pin.js add-compose`.
 *
 * They are the second way a container that belongs to no Crow bundle may vouch
 * (`docker compose up` in `~/my-own-vllm`), and they are read FRESH on every
 * call: the secrets directory is not bound into a bot sandbox, so the file is a
 * statement that comes from outside crow.db. A malformed entry is dropped, never
 * guessed at, and the endpoint pins (`{address, port, exe}`) are untouched by
 * this reader — `readPins` still reads only those.
 */
export function readComposePins(deps = {}) {
  const d = resolveDeps(deps);
  if (!d.crowHome) return [];
  const raw = readText(pinFilePath(d.crowHome), d);
  if (raw == null) return [];
  let parsed;
  try { parsed = JSON.parse(raw); } catch { return []; }
  const list = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.endpoints) ? parsed.endpoints : [];
  const out = [];
  for (const e of list) {
    if (!e || typeof e !== "object") continue;
    const dir = typeof e.composeDir === "string" ? e.composeDir.trim() : "";
    if (!dir.startsWith("/")) continue;
    const real = realPathOrSelf(dir, d);
    if (!out.includes(real)) out.push(real);
  }
  return out;
}

/** A Docker container name as the CLI prints it (`/flash-next-gufo` for `docker
 * run --name flash-next-gufo`): the leading slash off, trimmed. Exact match only —
 * a pin names ONE container, never a prefix or a pattern. */
export function normalizeContainerName(raw) {
  const name = String(raw ?? "").trim().replace(/^\/+/, "");
  return name && !/[\s/]/.test(name) ? name : null;
}

/**
 * The pin file's CONTAINER-NAME entries: `[{ "container": "flash-next-gufo" }]`,
 * written by `scripts/cli/local-model-pin.js add-container`.
 *
 * They exist for a model container that carries NO compose label at all — a
 * systemd unit that runs plain `docker run --name <name> -p 0.0.0.0:8030:8000`.
 * Such a container used to vouch nothing after S3 (the compose-directory rule),
 * so the model became unreachable. The name is the one thing the owner can pin
 * outside Docker: container names are not bot-controllable in the contain tier (a
 * contained bot has no Docker API), and the listener half is unchanged — the
 * publish is what vouches the port, and docker-proxy is another uid. A pinned
 * container's bindings vouch exactly like an AI-bundle container's.
 *
 * Read FRESH on every call, like every other pin (the secrets directory is not
 * bound into a bot sandbox). A malformed entry is dropped, never guessed at.
 */
export function readContainerPins(deps = {}) {
  const d = resolveDeps(deps);
  if (!d.crowHome) return [];
  const raw = readText(pinFilePath(d.crowHome), d);
  if (raw == null) return [];
  let parsed;
  try { parsed = JSON.parse(raw); } catch { return []; }
  const list = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.endpoints) ? parsed.endpoints : [];
  const out = [];
  for (const e of list) {
    if (!e || typeof e !== "object") continue;
    const name = normalizeContainerName(e.container);
    if (name && !out.includes(name)) out.push(name);
  }
  return out;
}

/** Does one compose project directory vouch a model server? An operator pin, or
 * an AI-category Crow bundle. `pins` is `readComposePins(d)` when the caller
 * already read the file once for a batch of containers. */
function composeDirAllowed(dir, d, pins) {
  const given = String(dir ?? "").trim();
  if (!given) return false;
  const real = realPathOrSelf(given, d);
  if ((pins || []).includes(real)) return true;
  return isModelBundleDir(real, d);
}

/** Does `dir` vouch? (The exported form, reading the pin file itself.) */
export function composeDirVouches(dir, deps = {}) {
  const d = resolveDeps(deps);
  return composeDirAllowed(dir, d, readComposePins(d));
}

/** Parsed compose publishes, cached by FILE + mtime + size (H4): a listing that
 * runs every few seconds must not re-parse every bundle's YAML each time. A file
 * that changed in either value is re-parsed; anything unreadable is not cached. */
const _composeCache = new Map();

function publishedPortsOfFile(path, text, env, d) {
  let key = path;
  try {
    const st = d.fs.statSync(path);
    key = `${path}|${st.mtimeMs ?? 0}|${st.size ?? 0}`;
  } catch { key = `${path}|${String(text ?? "").length}`; }
  const hit = _composeCache.get(key);
  if (hit) return hit;
  const parsed = publishedPortsOf(text, env);
  _composeCache.set(key, parsed);
  return parsed;
}

/** (b) every installed AI-bundle's declared published ports. */
function bundleComposeEntries(d) {
  const out = [];
  if (!d.crowHome) return out;
  const dir = join(d.crowHome, "bundles");
  let ids;
  try { ids = d.fs.readdirSync(dir); } catch { return out; }
  const baseEnv = { ...process.env };
  for (const id of (ids || []).map(String).sort()) {
    const bundleDir = join(dir, id);
    // S3: the SAME category rule vouch (a) applies. A search / Nextcloud / Home
    // Assistant bundle publishes ports too, and none of them is a model server.
    if (bundleCategoryOf(bundleDir, d) !== MODEL_BUNDLE_CATEGORY) continue;
    const dotEnv = parseDotEnv(readText(join(bundleDir, ".env"), d));
    const env = { ...baseEnv, ...dotEnv };
    for (const name of BUNDLE_COMPOSE_FILES) {
      const composePath = join(bundleDir, name);
      const text = readText(composePath, d);
      if (text == null) continue;
      for (const entry of publishedPortsOfFile(composePath, text, env, d)) out.push({ ...entry, bundleId: id });
      break; // one compose file per bundle is what compose itself reads
    }
  }
  return out;
}

// ---------------------------------------------------------------------------
// Vouch source (c): the native-runtime state file
// ---------------------------------------------------------------------------

/** The directories the native runtime uses for one instance, in the order its own
 * callers resolve them: the instance DATA dir (`resolveDataDir()`, where
 * `ensureRuntime` installs binaries and `state.js` keeps `models/state.json`),
 * then `<CROW_HOME>` (an install whose data dir is the home itself). */
function nativeDirCandidates(d) {
  const out = [];
  try { out.push(resolveInstanceDataDir()); } catch { /* no instance data dir */ }
  if (d.crowHome) out.push(d.crowHome);
  return [...new Set(out)];
}

/** The state file candidates, in the order state.js's own callers would use it:
 * `<data dir>/models/state.json` (resolveDataDir), then `<CROW_HOME>/models/state.json`. */
function nativeStateCandidates(d) {
  return nativeDirCandidates(d).map((dir) => join(dir, "models", "state.json"));
}

/** (c) `[{port, pid}]` for every native reservation that records a port. It is the
 * RESERVATION (outside crow.db) that vouches — never the 18100-18199 range, which
 * a bot can pick as easily as Crow can. Both state-file candidates are read: this
 * host's data dir and the instance home may resolve differently (CROW_DB_PATH). */
function nativeReservationEntries(d) {
  const out = [];
  const seen = new Set();
  for (const path of nativeStateCandidates(d)) {
    if (seen.has(path)) continue;
    seen.add(path);
    const raw = readText(path, d);
    if (raw == null) continue;
    let parsed;
    try { parsed = JSON.parse(raw); } catch { continue; }
    const reservations = parsed && typeof parsed.reservations === "object" && parsed.reservations ? parsed.reservations : {};
    for (const value of Object.values(reservations)) {
      const port = Number(value?.port);
      const pid = Number(value?.owner?.pid);
      if (!Number.isInteger(port) || port <= 0) continue;
      // H5: a reservation vouches only for a REAL process of OUR uid. pid 0/1 is
      // never a model server (1 is init; 0 is "no pid"), and a cell naming another
      // uid's process names something this instance did not start. The state file
      // lives under the data dir, which a contained bot can write, so "a pid is
      // alive" alone was too little: it must be OUR pid.
      if (!Number.isInteger(pid) || pid <= 1) continue;
      const ownerUid = procOwnerUid(pid, d);
      if (ownerUid != null && ownerUid !== d.uid) continue;
      out.push({ port, pid });
    }
  }
  return out;
}

/** The owning uid of `/proc/<pid>`, or null when it cannot be read. */
function procOwnerUid(pid, d) {
  try {
    const st = d.fs.statSync(procPath(d, pid));
    const uid = Number(st && st.uid);
    return Number.isFinite(uid) ? uid : null;
  } catch { return null; }
}

/**
 * Every llama-server binary `ensureRuntime(<dir>, …)` can have installed for one
 * directory, as VERIFIED CANDIDATES: `{ path, releaseDir, sha256 }`, where
 * `sha256` is the checksum that release's own `.crow-runtime-installed.json`
 * recorded for the BINARY when `ensureRuntime` verified and made it executable
 * (`binSha256`; the same manifest's `sha256` is the downloaded archive's). PURE —
 * it reads those manifests and lstats the candidates, nothing else (no oracle, no
 * network, no clock).
 *
 * Hardening, all of it fail-closed:
 *   - a `relBinPath` that is absolute or carries a ".." segment is IGNORED (a
 *     manifest is a file under CROW_HOME; it never points itself out of its own
 *     release dir);
 *   - a candidate must lstat as a REGULAR file — a symlink is not one, because
 *     lstat does not follow it, so a link planted at the path cannot stand in for
 *     the runtime's binary;
 *   - the candidate's path must stay inside its release dir;
 *   - a release that recorded NO checksum for its binary contributes nothing: an
 *     install made before `binSha256` existed, or a manifest that lost it, is not
 *     "trusted by default".
 *
 * The two archive-internal shapes llama.cpp's release tarballs extract the binary
 * to are listed as well, so an install whose manifest was replaced by a newer
 * release still matches the binary it is actually running (its content is what
 * identifies it — see `verifiedCandidateIdentity`).
 */
export function managedLlamaServerCandidates(dir, { fs = nodeFs } = {}) {
  const out = [];
  const root = join(dir, "runtimes", "llamacpp");
  let releases;
  try { releases = fs.readdirSync(root); } catch { return out; }
  for (const release of (releases || []).map(String).sort()) {
    const releaseDir = join(root, release);
    let manifest = null;
    try { manifest = JSON.parse(String(fs.readFileSync(join(releaseDir, RUNTIME_MANIFEST_FILE), "utf8"))); } catch { manifest = null; }
    const recorded = manifest && typeof manifest.binSha256 === "string" ? manifest.binSha256.trim().toLowerCase() : "";
    // No recorded checksum for this binary: nothing in this release counts.
    if (!SHA256_RE.test(recorded)) continue;
    const rel = safeRelBinPath(manifest.relBinPath);
    const paths = [
      ...new Set([
        rel ? join(releaseDir, rel) : null,
        ...LLAMA_SERVER_SHAPES.map((shape) => join(releaseDir, shape)),
      ].filter(Boolean)),
    ];
    for (const path of paths) {
      if (!regularFileInside(releaseDir, path, fs)) continue;
      out.push({ path, releaseDir, sha256: recorded });
    }
  }
  return out;
}

/** The managed llama-server binary paths for one directory — `managedLlamaServerCandidates`
 * with the same hardening, paths only. */
export function managedLlamaServerBinPaths(dir, { fs = nodeFs } = {}) {
  return managedLlamaServerCandidates(dir, { fs }).map((c) => c.path);
}

/** The managed llama-server candidates for every directory this instance's native
 * runtime installs into (see `nativeDirCandidates`). */
function managedRuntimeBinCandidates(d) {
  const out = [];
  for (const dir of nativeDirCandidates(d)) out.push(...managedLlamaServerCandidates(dir, { fs: d.fs }));
  return out;
}

/** Does `port` hold a LIVE native reservation in the state file? The reservation
 * must NAME a pid, and that pid must be alive: a cell with no recorded pid names
 * nobody, so it is never live (state.js records `owner.pid` for every port it
 * allocates — one without it is a hand-edit or a fixture, not an allocation). */
function portReservedLive(port, snapshot, d) {
  for (const e of snapshot.native || []) {
    if (Number(e.port) !== port) continue;
    const pid = Number(e.pid);
    if (!Number.isInteger(pid) || pid <= 0) continue;
    if (d.isProcessAlive(pid)) return true;
  }
  return false;
}

/** The pin file path for a Crow home. */
export function pinFilePath(crowHome) { return join(crowHome, "secrets", PIN_FILE); }

/** (d) the operator's pins, validated: `[{address, port, exe}]`. A malformed entry
 * is dropped (never guessed at), and the file is read fresh on every call. */
export function readPins(deps = {}) {
  const d = resolveDeps(deps);
  if (!d.crowHome) return [];
  const raw = readText(pinFilePath(d.crowHome), d);
  if (raw == null) return [];
  let parsed;
  try { parsed = JSON.parse(raw); } catch { return []; }
  const list = Array.isArray(parsed) ? parsed : Array.isArray(parsed?.endpoints) ? parsed.endpoints : [];
  const out = [];
  for (const e of list) {
    if (!e || typeof e !== "object") continue;
    const port = Number(e.port);
    const address = normalizeAddress(e.address);
    const exe = typeof e.exe === "string" ? e.exe.trim() : "";
    if (!address || !Number.isInteger(port) || port <= 0 || port > 65535) continue;
    if (!exe.startsWith("/")) continue;
    out.push({ address, port, exe });
  }
  return out;
}

// ---------------------------------------------------------------------------
// Vouch source (a): Docker's published bindings (cached ~30 s)
// ---------------------------------------------------------------------------

let _dockerCache = { at: 0, ok: false, entries: [] };
let _dockerFlight = null;
/** When the last FORCED Docker re-read started — ONE stamp for the whole process
 * (S2's rate limit, H2: never per address:port, which the caller chooses). */
let _dockerRefreshAt = null;
/** The ONE in-flight forced re-read: every concurrent caller awaits this same
 * promise instead of starting its own (`refreshVouchFor`). */
let _refreshFlight = null;
/** Exponential backoff after a FAILED Docker read (H4): a hung/unavailable docker
 * must not be re-run once per forward. Never blocks a listing. */
let _dockerFailures = 0;
let _dockerBackoffUntil = 0;
/** The backoff ceiling: a recovered Docker is picked up within a minute. */
const DOCKER_BACKOFF_MAX_MS = 60_000;

/** Reset every module-level cache (tests: after writing a vouch fixture). */
export function resetLocalModelVouchCache() {
  _dockerCache = { at: 0, ok: false, entries: [] };
  _dockerFlight = null;
  _dockerRefreshAt = null;
  _refreshFlight = null;
  _dockerFailures = 0;
  _dockerBackoffUntil = 0;
  _composeCache.clear();
  _scanCache = { key: "", at: 0, pids: [] };
  _fdLookups.clear();
  _nameAddrs.clear();
  _binHashes.clear();
}

/** `{ "8004/tcp": [{ HostIp, HostPort }] }` (docker inspect shape) → `[{address, port}]`. */
export function publishedPortsOfBindings(bindings) {
  const out = [];
  if (!bindings || typeof bindings !== "object") return out;
  for (const [key, values] of Object.entries(bindings)) {
    const proto = key.includes("/") ? key.slice(key.indexOf("/") + 1).toLowerCase() : "tcp";
    if (proto !== "tcp") continue;
    for (const v of Array.isArray(values) ? values : []) {
      const port = Number(v?.HostPort);
      if (!Number.isInteger(port) || port <= 0) continue;
      const address = typeof v?.HostIp === "string" && v.HostIp ? normalizeAddress(v.HostIp) : null;
      out.push({ address, port });
    }
  }
  return out;
}

/**
 * THE ONE `docker inspect` READ (J4): the container id, its name, its labels and its
 * published bindings — ONE JSON object per container on ONE line.
 *
 * It used to be three inspect passes — `{{json .HostConfig.PortBindings}}`,
 * `{{json .Config.Labels}}`, `{{.Name}}` — zipped back together BY LINE POSITION,
 * which is only correct while every pass prints exactly one line per container in
 * the same order; a failed or short output in ONE pass silently shifted every field
 * under it onto the wrong container (a container vouching a port it does not
 * publish, or a model losing its vouch). One pass cannot shift: a container's
 * fields are one line, written by one traversal. The line is JSON rather than
 * fields joined by a separator, so no value can ever split it — `{{json …}}` has
 * already escaped newlines and tabs inside a string — and the same shape is what
 * `scripts/fence/crow-publish-snapshot` asks Docker for.
 */
export const DOCKER_INSPECT_FORMAT = '{"id":{{json .Id}},"name":{{json .Name}},"running":{{json .State.Running}},"labels":{{json .Config.Labels}},"ports":{{json .HostConfig.PortBindings}}}';

/** One JSON line, parsed; `null` for anything that is not JSON. */
function jsonField(text) {
  try { return JSON.parse(text); } catch { return null; }
}

/**
 * Ask docker for every container's configured publishes — running OR stopped: a
 * stopped container keeps its PortBindings, which is what makes "the model's
 * container is stopped, the port is free to squat" a refused forward.
 *
 * S3: a container is a vouch only when its compose project directory is one Crow
 * trusts — an AI-category bundle dir or an operator-pinned compose dir
 * (`composeDirAllowed`). The directory comes from Docker's own
 * `com.docker.compose.project.working_dir` label, read from the same inspect pass
 * as the bindings (`DOCKER_INSPECT_FORMAT`). A container with no label, or with a
 * directory nobody vouches for, contributes NOTHING: a published port alone never
 * says what is published on it (search, Nextcloud, Home Assistant and a household
 * Crow container all publish ports).
 */
async function readDockerEntries(d) {
  const ids = (await d.dockerRunner("docker", ["ps", "-aq", "--no-trunc"], { timeout: 8_000 })).stdout || "";
  const list = String(ids).split(/\s+/).map((s) => s.trim()).filter(Boolean);
  if (!list.length) return [];
  const { stdout } = await d.dockerRunner("docker", ["inspect", "--format", DOCKER_INSPECT_FORMAT, ...list], { timeout: 10_000 });
  const out = [];
  const pins = readComposePins(d);
  const containerPins = new Set(readContainerPins(d));
  for (const line of String(stdout || "").split(/\r?\n/)) {
    if (!line.trim()) continue;
    const record = jsonField(line);
    // The id is the record's own proof that this is a container, not a warning
    // docker printed on stdout: anything else is skipped, never guessed at.
    if (!record || typeof record !== "object" || typeof record.id !== "string" || !record.id) continue;
    const container = normalizeContainerName(record.name);
    const labels = record.labels;
    const bindings = record.ports;
    const labelValue = labels && typeof labels === "object" ? labels[COMPOSE_WORKING_DIR_LABEL] : null;
    const composeDir = typeof labelValue === "string" && labelValue.trim() ? labelValue.trim() : null;
    // A pinned CONTAINER NAME is the owner's own statement about a container that
    // carries no compose label at all (a systemd unit's plain `docker run`).
    const pinnedContainer = Boolean(container) && containerPins.has(container);
    // No compose label at all (and no name pin), or a directory nobody vouches
    // for: not a model server.
    if (!pinnedContainer && !composeDirAllowed(composeDir, d, pins)) continue;
    // `running` is carried because the NAT branch needs it: a STOPPED container
    // keeps its published bindings but has no NAT rules, so its port is a free
    // one to squat (see `noLocalRowIsDockerNat`).
    out.push(...publishedPortsOfBindings(bindings).map((e) => ({ ...e, composeDir, container, running: record.running === true })));
  }
  return out;
}

/** The docker snapshot: fresh from the CLI, else the last GOOD one (an unreachable
 * Docker must not un-vouch a running model), else nothing.
 *
 * STALE-WHILE-REVALIDATE + BACKOFF (H4): a failed read keeps the last good entries
 * and opens an exponential backoff window, so a hung `docker` is not re-run once
 * per forward; a read that is merely STALE is served and refreshed in the
 * background (`primeDockerInBackground`) rather than blocking the caller. */
async function dockerSnapshot(d, { force = false } = {}) {
  if (Array.isArray(d.dockerEntries)) return { ok: true, entries: d.dockerEntries };
  const now = d.now();
  if (!force) {
    // A good snapshot inside the TTL is served as is; a FAILED one is served until
    // the backoff window opens (never one docker spawn per request).
    if (_dockerCache.ok && _dockerCache.at && now - _dockerCache.at < VOUCH_TTL_MS) return _dockerCache;
    if (!_dockerCache.ok && now < _dockerBackoffUntil) return _dockerCache;
  }
  if (_dockerFlight) return _dockerFlight;
  const p = (async () => {
    try {
      const entries = await readDockerEntries(d);
      _dockerCache = { at: d.now(), ok: true, entries };
      _dockerFailures = 0;
      _dockerBackoffUntil = 0;
      return _dockerCache;
    } catch {
      // Docker is unreachable: keep the last GOOD entries (stale), never treat
      // "cannot ask" as "nothing is published".
      _dockerFailures += 1;
      _dockerBackoffUntil = d.now() + Math.min(DOCKER_BACKOFF_MAX_MS, 1_000 * 2 ** Math.min(_dockerFailures, 6));
      _dockerCache = { ..._dockerCache, at: _dockerCache.at || d.now(), ok: false };
      return _dockerCache;
    } finally {
      _dockerFlight = null;
    }
  })();
  _dockerFlight = p;
  return p;
}

/**
 * PRIME THE SNAPSHOT LAZILY (H3): the FIRST cached check in any process starts the
 * Docker read in the background, and a stale one is revalidated the same way — no
 * caller blocks on `docker`, and the next listing sees the answer.
 *
 * This is what makes the SYNC listing predicate work outside the gateway: the
 * pi-bots spawner and the memory server never call `primeLocalModelVouch`, so
 * before this a Docker-only model read "unverified-local" there forever. A failed
 * read is retried with backoff (`dockerSnapshot`), never on every forward.
 */
function primeDockerInBackground(d) {
  if (Array.isArray(d.dockerEntries)) return;
  if (_dockerFlight) return;
  const now = d.now();
  if (_dockerCache.ok && _dockerCache.at && now - _dockerCache.at < VOUCH_TTL_MS) return;
  if (!_dockerCache.ok && now < _dockerBackoffUntil) return;
  try { Promise.resolve(dockerSnapshot(d)).catch(() => {}); } catch { /* docker is optional */ }
}

/** Wait for the in-flight background Docker read, if any (tests, and a caller that
 * wants the primed snapshot before it lists). Never throws. */
export async function whenLocalModelVouchReady() {
  try { await _dockerFlight; } catch { /* docker is optional */ }
}

// ---------------------------------------------------------------------------
// The vouch snapshot
// ---------------------------------------------------------------------------

/** Warm the Docker half of the vouch cache. The SYNC listing predicate can only
 * use what is already there (it must never spawn a process), so the gateway calls
 * this once at boot, before its first pi models.json sync, so a container-started
 * model is not briefly "unverified-local" in a listing. Never throws. */
export async function primeLocalModelVouch(deps = {}) {
  try { await dockerSnapshot(resolveDeps(deps), { force: true }); } catch { /* docker is optional */ }
}

/**
 * Make the Docker half of the vouch cache READY before a sync decision reads it, in
 * a process that is not the gateway (the pi-bots spawner, skill review). The sync
 * predicate never spawns a process, so its FIRST call in a fresh process found an
 * empty cache, started the read in the background and answered "not-vouched": the
 * first contained turn after every bridge restart lost its door to a Docker-run
 * model and was refused. Awaited before that decision, this closes the window.
 *
 * Bounded: a good snapshot already in hand (fresh or stale; the sync path serves a
 * stale one and revalidates it in the background) returns at once; otherwise the
 * read is awaited for at most `timeoutMs`. A Docker that cannot answer in time
 * leaves the cache as it was, so the decision fails closed exactly as before, and a
 * turn never hangs on it. Never throws.
 */
export async function ensureLocalModelVouch({ timeoutMs = 4_000, deps = {}, targets = null } = {}) {
  let timer = null;
  const bound = new Promise((resolve) => { timer = setTimeout(resolve, Math.max(0, Number(timeoutMs) || 0)); });
  try {
    const d = resolveDeps(deps);
    if (!(_dockerCache.ok && _dockerCache.at)) {
      // Cold (or last read failed): a bounded wait, as before.
      await Promise.race([dockerSnapshot(d).catch(() => {}), bound]);
      return;
    }
    // REFRESH ON A MISS, never on age alone. A snapshot in hand predates any container
    // started or pinned after it (an on-demand model start, the nightly rotation, a fresh
    // `local-model-pin add-container`), and the sync door decision would read that as
    // not-vouched and refuse the first contained turn. Judge each target with the SAME sync
    // predicate the door uses; only a not-vouched LOCAL target (own host) pays for a read.
    if (!Array.isArray(targets) || !targets.length) return;
    const missed = targets.some((url) => {
      if (typeof url !== "string" || !url) return false;
      const r = isKnownLocalModelTargetCached(url, deps);
      return r.local === false && r.reason === "not-vouched";
    });
    if (!missed) return;
    if (d.now() - _dockerCache.at < VOUCH_MISS_REFRESH_MIN_AGE_MS) return; // thrash guard
    if (!_dockerFlight && d.now() < _dockerBackoffUntil) return;            // failure backoff
    // dockerSnapshot joins an in-flight read instead of starting a second one.
    await Promise.race([dockerSnapshot(d, { force: true }).catch(() => {}), bound]);
  } catch { /* docker is optional */ } finally {
    if (timer) clearTimeout(timer);
  }
}

/** Every vouch source, already parsed. Tests inject this shape via `deps.snapshot`. */
export function buildSyncVouch(d = {}) {
  const docker = Array.isArray(d.dockerEntries) ? { ok: true, entries: d.dockerEntries } : _dockerCache;
  return {
    at: d.now(),
    dockerOk: docker.ok,
    docker: docker.entries,
    bundles: bundleComposeEntries(d),
    native: nativeReservationEntries(d),
    pins: readPins(d),
    // The ports THIS gateways listens on are its own code, so a row naming one is
    // not a row-driven listener (self-target.js gatewayListenPorts: PORT, else
    // CROW_GATEWAY_PORT, else 3001).
    selfPorts: [...gatewayListenPorts()],
    crowHome: d.crowHome,
  };
}

async function buildVouch(d, { force = false } = {}) {
  const docker = await dockerSnapshot(d, { force });
  return {
    at: d.now(),
    dockerOk: docker.ok,
    docker: docker.entries,
    bundles: bundleComposeEntries(d),
    native: nativeReservationEntries(d),
    pins: readPins(d),
    selfPorts: [...gatewayListenPorts()],
    crowHome: d.crowHome,
  };
}

/** The source that vouches `port` on one of `addrs`, or null. */
export function vouchSourceFor(port, addrs, snapshot, { isProcessAlive = defaultIsProcessAlive } = {}) {
  const snap = snapshot || {};
  if ((snap.selfPorts || []).includes(port)) return "self";
  for (const e of snap.docker || []) if (Number(e.port) === port && bindingCovers(e.address, addrs)) return "docker";
  for (const e of snap.bundles || []) if (Number(e.port) === port && bindingCovers(e.address, addrs)) return "bundle";
  for (const e of snap.native || []) {
    // A reservation vouches its port only while the pid it RECORDED is alive: a
    // cell that names no pid names nobody, so it vouches nothing.
    const pid = Number(e.pid);
    if (Number(e.port) === port && Number.isInteger(pid) && pid > 0 && isProcessAlive(pid)) return "native";
  }
  for (const e of snap.pins || []) if (Number(e.port) === port && bindingCovers(e.address, addrs)) return "pin";
  return null;
}

// ---------------------------------------------------------------------------
// /proc/net parsing
// ---------------------------------------------------------------------------

/** A `/proc/net/tcp{,6}` address field → a comparable address. The kernel writes
 * each 32-bit word little-endian; tcp6 writes four of them. A v4-mapped address
 * (`::ffff:127.0.0.1`) becomes the IPv4 it carries. */
export function decodeProcNetAddress(hex, family) {
  const text = String(hex ?? "").trim();
  if (!text) return null;
  if (family === 4) {
    if (text.length !== 8 || !/^[0-9a-fA-F]{8}$/.test(text)) return null;
    const bytes = [];
    for (let i = 6; i >= 0; i -= 2) bytes.push(Number.parseInt(text.slice(i, i + 2), 16));
    return bytes.join(".");
  }
  if (text.length !== 32 || !/^[0-9a-fA-F]{32}$/.test(text)) return null;
  const groups = [];
  for (let g = 0; g < 4; g++) {
    const chunk = text.slice(g * 8, g * 8 + 8);
    const bytes = [];
    for (let i = 6; i >= 0; i -= 2) bytes.push(Number.parseInt(chunk.slice(i, i + 2), 16));
    groups.push((bytes[0] << 8) | bytes[1], (bytes[2] << 8) | bytes[3]);
  }
  const allZeroPrefix = groups.slice(0, 5).every((x) => x === 0);
  if (allZeroPrefix && groups[5] === 0xffff) {
    return `${groups[6] >> 8}.${groups[6] & 0xff}.${groups[7] >> 8}.${groups[7] & 0xff}`;
  }
  if (groups.every((x) => x === 0)) return "::";
  return groups.map((x) => x.toString(16)).join(":");
}

/** The kernel's spelling of a port in `/proc/net/tcp{,6}`: four hex digits, upper
 * case. `null` for anything that is not a port, which turns the pre-filter off. */
function kernelPortHex(port) {
  const n = Number(port);
  if (!Number.isInteger(n) || n <= 0 || n > 65535) return null;
  return n.toString(16).toUpperCase().padStart(4, "0");
}

/** Are the four characters at `at` the hex digits of `hex` (upper- or lower-case)? */
function sameHexAt(line, at, hex) {
  for (let i = 0; i < 4; i++) {
    const c = line.charCodeAt(at + i);
    // a-f fold to A-F; the kernel writes upper case, a fixture may write either.
    const folded = c >= 97 && c <= 102 ? c - 32 : c;
    if (folded !== hex.charCodeAt(i)) return false;
  }
  return true;
}

/** Does this RAW /proc line mention `hex` as a port (the local field or the remote
 * one)? The port is the four characters right after a colon and is followed by a
 * space in every `/proc/net/tcp{,6}` field, so the check is exact — it is only
 * cheap, not approximate, which is what makes it safe to drop every other line. */
function lineMentionsPort(line, hex) {
  for (let at = line.indexOf(":"); at >= 0; at = line.indexOf(":", at + 1)) {
    if (line.charCodeAt(at + 5) !== 32) continue;
    if (sameHexAt(line, at + 1, hex)) return true;
  }
  return false;
}

/**
 * ONE `/proc/net/tcp{,6}` table's rows, decoded — with a CHEAP PRE-FILTER on the raw
 * line, before any split and any address decode, because a busy box carries
 * thousands of rows and one judgement is about a handful (L1). `{ port }` keeps only
 * the lines that mention that port at all; the exact match is still made on the
 * DECODED fields below, so nothing about a verdict changes — a dropped line is one
 * that cannot have matched (`lineMentionsPort` is exact about where a port sits).
 */
function parseProcNetRows(text, family, { port = null, connections = false } = {}) {
  const src = String(text ?? "");
  if (!src) return [];
  const hex = port == null ? null : kernelPortHex(port);
  const lines = src.split(/\r?\n/);
  const out = [];
  for (let i = 1; i < lines.length; i++) {
    const line = lines[i];
    if (!line) continue;
    if (hex && !lineMentionsPort(line, hex)) continue;
    const f = line.trim().split(/\s+/);
    if (f.length < 10) continue;
    const local = f[1];
    const at = local.lastIndexOf(":");
    if (at <= 0) continue;
    const address = decodeProcNetAddress(local.slice(0, at), family);
    const rowPort = Number.parseInt(local.slice(at + 1), 16);
    if (address == null || !Number.isInteger(rowPort)) continue;
    if (!connections) {
      out.push({ address, port: rowPort, state: f[3], uid: Number(f[7]), inode: f[9] });
      continue;
    }
    const remote = f[2];
    const rat = String(remote ?? "").lastIndexOf(":");
    const remoteAddress = rat > 0 ? decodeProcNetAddress(String(remote).slice(0, rat), family) : null;
    const remotePort = rat > 0 ? Number.parseInt(String(remote).slice(rat + 1), 16) : null;
    out.push({
      address, port: rowPort,
      remoteAddress, remotePort: Number.isInteger(remotePort) ? remotePort : null,
      state: f[3], uid: Number(f[7]), inode: f[9],
    });
  }
  return out;
}

/** Every row of a `/proc/net/tcp{,6}` table: `{address, port, state, uid, inode}`. */
export function parseProcNet(text, family) { return parseProcNetRows(text, family); }

/** Every row of a `/proc/net/tcp{,6}` table WITH its remote end, decoded:
 * `{ address, port, remoteAddress, remotePort, state, uid, inode }`. `parseProcNet`
 * keeps its old shape (a LISTEN judgement does not need the peer); an ACCEPTED
 * connection is found by its full four-tuple, so this is the parser for that.
 * Remote fields that do not decode are `null`, never a guess. */
export function parseProcNetConnections(text, family) { return parseProcNetRows(text, family, { connections: true }); }

/** `fs.readFile` where the backend has the promise API, the sync read otherwise.
 * Unreadable is `""` (the same answer a sync read failure gave). */
async function readFileAsync(d, path) {
  const p = d.fs && d.fs.promises;
  if (p && typeof p.readFile === "function") {
    try { return String(await p.readFile(path, "utf8")); } catch { return ""; }
  }
  return readText(path, d) || "";
}

/** `fs.readdir` where the backend has the promise API, the sync read otherwise. */
async function readdirAsync(d, path) {
  const p = d.fs && d.fs.promises;
  if (p && typeof p.readdir === "function") {
    try { return await p.readdir(path); } catch { return null; }
  }
  try { return d.fs.readdirSync(path); } catch { return null; }
}

/** `fs.readlink` where the backend has the promise API, the sync read otherwise. */
async function readlinkAsync(d, path) {
  const p = d.fs && d.fs.promises;
  if (p && typeof p.readlink === "function") {
    try { return await p.readlink(path); } catch { return null; }
  }
  return readLink(path, d);
}

/**
 * ONE read of both `/proc/net/tcp{,6}` tables, for ONE judgement pass (L1).
 *
 * `deps.procNetTcp`/`procNetTcp6` override a table as a STRING (a test states what
 * the kernel says) or as a FUNCTION this calls per read (a table that changes
 * between reads: "the row leaves SYN_RECV on the third look"). A real table is read
 * through `fs.promises` when the backend has it, so a verification waiting on the
 * kernel does not block every other verification in the process (N3).
 */
async function procTables(d) {
  const table = (injected, name) => (injected != null
    ? Promise.resolve(typeof injected === "function" ? String(injected()) : String(injected))
    : readFileAsync(d, procPath(d, "net", name)));
  const [tcp, tcp6] = await Promise.all([table(d.procNetTcp, "tcp"), table(d.procNetTcp6, "tcp6")]);
  return { tcp, tcp6 };
}

/** A judgement pass's ONE table read, shared by every check inside it: the vouch's
 * listener half asks once per candidate address (a dual-stack name is two answers)
 * and the self-ownership check asks about the very same rows. The read is shared
 * ONLY inside one pass — anywhere the rule needs a LATER state of the kernel (after
 * the connect, and for the NAT branch's own listener check) a fresh read is taken. */
function tablesOnce(d) {
  let pending = null;
  return () => (pending ||= procTables(d));
}

/** Does a LISTEN row's local address cover the target's? A wildcard covers every
 * own address; otherwise the addresses must be the same one (in any spelling). */
function procAddressCovers(rowAddress, targetAddrs) {
  const a = normalizeAddress(rowAddress);
  if (WILDCARD_ADDRS.has(a)) return true;
  return targetAddrs.some((t) => compareAddress(t) === compareAddress(a));
}

// ---------------------------------------------------------------------------
// /proc/<pid> reads
// ---------------------------------------------------------------------------

function procPath(d, ...parts) { return join(d.procRoot, ...parts.map(String)); }

function readLink(path, d) {
  try { return d.fs.readlinkSync(path); } catch { return null; }
}

/** In-flight fd-table lookups, keyed procRoot|pid|inode. A lookup is a COALESCING
 * HINT only — it holds the promise until it settles, never the answer — so N
 * concurrent verifications of the same socket share ONE readdir+readlink pass
 * instead of serialising on synchronous /proc reads (N3). */
const _fdLookups = new Map();

/** Does ONE pid's fd table hold `socket:[inode]`? One readdir plus a readlink per fd
 * of a pid we already decided to look at — never a scan of the box. AWAIT-based, so
 * eight parallel forwards ask the kernel at the same time instead of one after the
 * other (N3); THIS process's own table is still asked first (`findTrustedSocketPid`),
 * and it is asked at `/proc/<pid>` — which the kernel resolves to the same table as
 * `/proc/self` without the syscall round trip of a magic link. */
function pidHoldsSocketInode(pid, inode, d) {
  const key = `${d.procRoot}|${pid}|${inode}`;
  const inflight = _fdLookups.get(key);
  if (inflight) return inflight;
  const flight = (async () => {
    const want = `socket:[${inode}]`;
    const dir = procPath(d, pid, "fd");
    const fds = await readdirAsync(d, dir);
    for (const fd of fds || []) {
      if (await readlinkAsync(d, procPath(d, pid, "fd", String(fd))) === want) return true;
    }
    return false;
  })();
  _fdLookups.set(key, flight);
  flight.then(() => { if (_fdLookups.get(key) === flight) _fdLookups.delete(key); }, () => { if (_fdLookups.get(key) === flight) _fdLookups.delete(key); });
  return flight;
}

/**
 * THE CANDIDATE-ONLY pid search (H4).
 *
 * The old `findPidForSocketInode` readdir'd EVERY process's fd table on every
 * forward (~40-50 ms on a busy box, and again on every refusal through
 * `selfOwnsListener`), which is a synchronous stall a bot could lean on. The rule
 * never needed the whole box: a socket may be trusted only if its holder is one of
 * a KNOWN, SMALL set of processes, so this builds that set instead:
 *   - this process (`d.selfPid`);
 *   - the native handles for THIS port (a live llama-server the gateway runs);
 *   - (cached ~5 s) same-uid processes that are in a Docker container cgroup, or
 *     execute a pinned executable / a managed llama-server binary.
 * A process outside that set is not trusted, exactly as before — the rule fails
 * CLOSED either way; only the cost changed. The scan is bounded: one readdir of
 * /proc, then one stat per pid (to skip other uids) and one or two readlinks.
 */
const SCAN_TTL_MS = 5_000;
let _scanCache = { key: "", at: 0, pids: [] };

/** Managed-binary paths (never contents: the content check belongs to
 * `listenerTrusted`, and hashing a few hundred MB per scan would not do). */
function managedRuntimeBinPathSet(d) {
  const out = new Set();
  for (const cand of managedRuntimeBinCandidates(d)) out.add(realPathOrSelf(cand.path, d));
  return out;
}

function scanSameUidCandidates(d, pins) {
  const out = [];
  let names;
  try { names = d.fs.readdirSync(d.procRoot); } catch { return out; }
  const pinExes = new Set((pins || []).map((p) => p.exe).filter(Boolean));
  const binPaths = managedRuntimeBinPathSet(d);
  for (const raw of names || []) {
    const name = String(raw);
    if (!/^\d+$/.test(name)) continue;
    const pid = Number(name);
    if (pid <= 1) continue;
    // Same uid only (one stat, no fd table): another uid's process is trusted by
    // the uid rule itself, and is none of our business here.
    let st;
    try { st = d.fs.statSync(procPath(d, pid)); } catch { continue; }
    if (!st || Number(st.uid) !== d.uid) continue;
    if (inDockerCgroup(pid, d)) { out.push(pid); continue; }
    if (!pinExes.size && !binPaths.size) continue;
    const exe = exeOf(pid, d);
    if (!exe) continue;
    if (pinExes.has(exe)) { out.push(pid); continue; }
    const real = realOrSelfExe(exe, d);
    if (pinExes.has(real)) { out.push(pid); continue; }
    if (binPaths.has(real)) out.push(pid);
  }
  return out;
}

function scannedCandidatePids(d, snapshot) {
  const pins = (snapshot && Array.isArray(snapshot.pins)) ? snapshot.pins : readPins(d);
  const key = `${d.procRoot}|${d.uid}|${d.crowHome || ""}|${pins.map((p) => `${p.port}:${p.exe}`).join(",")}`;
  const now = d.now();
  if (_scanCache.key === key && now - _scanCache.at < SCAN_TTL_MS) return _scanCache.pids;
  const pids = scanSameUidCandidates(d, pins);
  _scanCache = { key, at: now, pids };
  return pids;
}

/**
 * The pid that may hold `socket:[inode]`, out of the CANDIDATE set only, or null.
 * A pid found here still has to pass `listenerTrusted` (exe, user namespace,
 * docker cgroup, live handle), so this function only narrows WHERE to look.
 */
async function findTrustedSocketPid(inode, port, addresses, snapshot, d) {
  const tried = new Set();
  const holds = async (pid) => {
    if (!Number.isInteger(pid) || pid <= 0 || tried.has(pid)) return false;
    tried.add(pid);
    return pidHoldsSocketInode(pid, inode, d);
  };
  // THIS process first: the gateway's own listener is the common answer, and it is
  // the one lookup that never needs the candidate scan at all.
  if (await holds(d.selfPid)) return d.selfPid;
  for (const h of nativeHandlesOf(d)) if (Number(h.port) === port && await holds(h.pid)) return h.pid;
  for (const pid of scannedCandidatePids(d, snapshot)) if (await holds(pid)) return pid;
  return null;
}

/** The host a native handle's llama-server bound: a `host` on the handle, else
 * the `--host` it was launched with (`buildLlamaServerArgs`' default 127.0.0.1). */
export function nativeHandleHost(handle) {
  const direct = normalizeAddress(handle && handle.host);
  if (direct) return direct;
  const argv = Array.isArray(handle && handle.argv) ? handle.argv : [];
  const at = argv.indexOf("--host");
  if (at >= 0 && typeof argv[at + 1] === "string" && argv[at + 1]) return normalizeAddress(argv[at + 1]);
  return "127.0.0.1";
}

/** The native handles THIS process supervises, as `[{pid, port, host, live}]`.
 * `runtime.js`'s `getStatusSnapshot()` is the panel's own view of them, and a
 * handle carries `pid` (setpriv execs, so it IS llama-server's pid) and `port`. */
function defaultNativeHandles() {
  try {
    const snapshot = getStatusSnapshot();
    if (!Array.isArray(snapshot)) return [];
    return snapshot.map((s) => ({ pid: Number(s && s.pid), port: Number(s && s.port), host: nativeHandleHost(s), live: !(s && s.live === false) }));
  } catch {
    return [];
  }
}

/** The handles this process supervises — injected (`deps.nativeHandles`) by tests,
 * real otherwise. An EMPTY list is meaningful: it is the memory MCP child and the
 * pi-bots host processes, which start no llama-server and so fall to the binary rule. */
function nativeHandlesOf(d) {
  const raw = Array.isArray(d.nativeHandles) ? d.nativeHandles : defaultNativeHandles();
  return (raw || []).map((h) => ({
    pid: Number(h && h.pid),
    port: Number(h && h.port),
    host: nativeHandleHost(h),
    live: !(h && h.live === false),
  })).filter((h) => Number.isInteger(h.pid) && h.pid > 0 && Number.isInteger(h.port));
}

/** The user namespace a pid runs in (`user:[4026531837]`), or null. */
function userNsOf(pid, d) {
  return readLink(procPath(d, pid, "ns", "user"), d);
}

function selfUserNs(d) {
  if (typeof d.selfUserNs === "string") return d.selfUserNs;
  return userNsOf("self", d);
}

function sameUserNs(pid, d) {
  const self = selfUserNs(d);
  const other = userNsOf(pid, d);
  return self != null && other != null && self === other;
}

const inDockerCgroup = (pid, d) => DOCKER_CGROUP_RE.test(readText(procPath(d, pid, "cgroup"), d) || "");

/** The process's own executable, resolved (`/proc/<pid>/exe`), or null. */
function exeOf(pid, d) {
  const link = readLink(procPath(d, pid, "exe"), d);
  if (!link) return null;
  try { return d.fs.realpathSync ? d.fs.realpathSync(procPath(d, pid, "exe")) : link; } catch { return link; }
}

function realOrSelfExe(exe, d) {
  try { return d.fs.realpathSync ? d.fs.realpathSync(exe) : exe; } catch { return exe; }
}

// ---------------------------------------------------------------------------
// Managed-binary identity (the no-native-handles fallback)
// ---------------------------------------------------------------------------

/** A manifest `relBinPath` this module is willing to JOIN, or null. An absolute
 * path, or any path with a ".." segment, is IGNORED: the candidate must stay
 * inside the release dir it claims to belong to. */
function safeRelBinPath(rel) {
  if (typeof rel !== "string" || !rel) return null;
  if (isAbsolute(rel)) return null;
  const segs = rel.split(/[\\/]+/).filter(Boolean);
  if (!segs.length || segs.includes("..")) return null;
  return rel;
}

/** Is `path` lexically inside `dir` (not the dir itself, no parent hop)? */
function insideDir(dir, path) {
  const rel = relative(dir, path);
  if (!rel || isAbsolute(rel)) return false;
  return !rel.split(/[\\/]+/).includes("..");
}

/** `path`'s lstat when it is a REGULAR FILE inside `dir`, else null. lstat, never
 * stat: a symlink is not a regular file, so a link planted at a candidate's path
 * never stands in for the runtime's binary. */
function regularFileInside(dir, path, fs) {
  if (!insideDir(dir, path)) return null;
  let st;
  try { st = fs.lstatSync(path); } catch { return null; }
  if (!st || typeof st.isFile !== "function" || !st.isFile()) return null;
  return st;
}

/** `dev:ino` of a stat result, or null when the filesystem did not report them. */
function identityOf(st) {
  if (!st) return null;
  const dev = Number(st.dev);
  const ino = Number(st.ino);
  if (!Number.isFinite(dev) || !Number.isFinite(ino)) return null;
  return `${dev}:${ino}`;
}

/** The dev+inode `/proc/<pid>/exe` resolves to, or null. `stat` (not lstat)
 * follows the kernel's magic link to the file the process is really executing. */
function exeIdentity(pid, d) {
  try { return identityOf(d.fs.statSync(procPath(d, pid, "exe"))); } catch { return null; }
}

/** sha256 of a file, read in chunks (synchronously: the listener judgement is
 * synchronous and only misses the cache once per changed file). Null when the
 * file cannot be read. */
function sha256OfFileSync(path, fs) {
  try {
    const hash = createHash("sha256");
    if (typeof fs.openSync === "function" && typeof fs.readSync === "function" && typeof fs.closeSync === "function") {
      const fd = fs.openSync(path, "r");
      try {
        const buf = Buffer.allocUnsafe(HASH_CHUNK_BYTES);
        for (;;) {
          const n = fs.readSync(fd, buf, 0, buf.length, null);
          if (!n) break;
          hash.update(buf.subarray(0, n));
        }
      } finally {
        try { fs.closeSync(fd); } catch { /* already closed */ }
      }
      return hash.digest("hex");
    }
    return createHash("sha256").update(fs.readFileSync(path)).digest("hex");
  } catch {
    return null;
  }
}

/** sha256 results keyed dev+inode+size+mtime, so the forward path never re-hashes
 * an unchanged binary (and re-hashes one that changed in any of the four). */
const _binHashes = new Map();

function cachedFileSha256(path, st, fs) {
  const key = `${st.dev}:${st.ino}:${st.size}:${st.mtimeMs ?? (st.mtime && st.mtime.getTime && st.mtime.getTime()) ?? 0}`;
  const hit = _binHashes.get(key);
  if (hit !== undefined) return hit;
  const digest = sha256OfFileSync(path, fs);
  if (digest) _binHashes.set(key, digest);
  return digest;
}

/** The dev+inode of a managed candidate whose CONTENT is the binary the runtime
 * verified, or null. Identity is by content first (the recorded checksum), and
 * only then does the file's dev+inode say "the running process executes THIS
 * file": the stat used for the identity is the one whose bytes were hashed, so a
 * swap after it cannot launder a different binary into the verdict. */
function verifiedCandidateIdentity(cand, d) {
  const st = regularFileInside(cand.releaseDir, cand.path, d.fs);
  if (!st) return null;
  const digest = cachedFileSha256(cand.path, st, d.fs);
  if (!digest || digest.toLowerCase() !== cand.sha256) return null;
  return identityOf(st);
}

// ---------------------------------------------------------------------------
// Classification
// ---------------------------------------------------------------------------

/**
 * The address-class half, shared by the async and the sync entry points.
 * → { kind: "forbidden" | "not-local-class" | "classed", port }; "classed" means
 * local-class, so the own-host question is still open.
 */
function classifyTarget(url, d) {
  const port = targetPort(url) ?? 0;
  if (isForbiddenTarget(url)) return { kind: "forbidden", port };
  if (!isLocalClassTarget(url)) return { kind: "not-local-class", port };
  return { kind: "classed", port };
}

/** Names resolved by the async path, so the sync listing path can judge an
 * own-host MagicDNS name too (a host name, never a guess: only an answer THIS
 * process already got from the resolver is reused). */
const _nameAddrs = new Map();

// ---------------------------------------------------------------------------
// The public predicates
// ---------------------------------------------------------------------------

/**
 * Is `url` a model server this instance already knows about — vouched by a source
 * outside crow.db AND currently held by a process that is not a bot?
 *
 * → `{ local, reason, address }`; `reason` is one of "forbidden",
 * "not-local-class", "unresolved", "other-host" (local:true — a LAN/tailnet
 * peer; a bot cannot listen on another machine), "door-url-from-child" (a Crow
 * gateway door URL on this host, asked from a process that is not the gateway),
 * "not-vouched", "no-listener", "listener-not-trusted", or "vouched"
 * (local:true). `address` is the ONE
 * address this judgement was made over — the literal a caller must connect to
 * (null when the target was refused before any address was judged).
 *
 * A caller that has already resolved its target (`pinnedTargetOf`) hands the
 * answers over (`deps.dialAddresses`, or `deps.pinned`) and ONLY those are judged:
 * the vouch decides on exactly the address the socket will be opened to, never on
 * a broader set (a name is several addresses, and a forward lands on one).
 * `address` is what the caller dials, so no second resolution can happen between
 * this judgement and the connect.
 *
 * SEVERAL CANDIDATES ARE JUDGED IN ORDER. A dual-stack name is resolved to ONE
 * list, and the caller dials exactly one address from it: when it hands in more
 * than one answer (`localhost` -> [::1, 127.0.0.1], and the server binds only one
 * of them), each answer is judged IN TURN — vouch for THAT address, then the
 * listener on THAT address — and the FIRST one that passes is returned as
 * `address`. Refusal only when NONE passes. This is what keeps a legitimate model
 * server bound to 127.0.0.1 reachable through a `localhost` that resolves to ::1
 * first (the Ollama bundle publishes 127.0.0.1:11434; faster-whisper and Kokoro
 * bind 127.0.0.1; some containers' /etc/hosts list both), while still dialling
 * exactly ONE address, and one that was judged. An answer that is not this host is
 * never a candidate here (this judgement is the own-host half; a remote answer
 * cannot be vouched for locally, so it is skipped rather than dialled).
 *
 * Never throws; every unknown is a refusal.
 */
export async function isKnownLocalModelTarget(url, deps = {}) {
  const d = resolveDeps(deps);
  try {
    const cls = classifyTarget(url, d);
    if (cls.kind === "forbidden") return { local: false, reason: "forbidden", address: null };
    if (cls.kind === "not-local-class") return { local: false, reason: "not-local-class", address: null };
    // THE ADDRESSES THAT WILL BE DIALED — no broader set than the forward itself,
    // and resolved ONCE: a caller that already pinned its connection
    // (`pinnedTargetOf` + `pinnedLookup`) hands its answer(s) in, and ONLY those are
    // judged. An IP literal is that literal; any name is its resolved answers.
    const dialled = explicitDialAddresses(d);
    const addresses = dialled || (await targetAddresses(url, { lookupFn: d.lookupFn })).map((a) => a.address);
    if (!addresses.length) return { local: false, reason: "unresolved", address: null };
    const port = targetPort(url) ?? cls.port;
    if (!addresses.some((a) => isOwnHostAddress(a, d.ownAddrs))) return { local: true, reason: "other-host", address: addresses[0] };
    const host = targetHost(url);
    if (host) _nameAddrs.set(host, addresses);
    // M1: a Crow gateway DOOR URL on this host, asked from a process that is not
    // the gateway (the memory MCP child, a pi-bots host process). The listener on
    // that port belongs to the gateway, not to this process, so the old answer was
    // the accidental "listener-not-trusted" — a squat-shaped reason for a
    // different fact. A child may not drive the door: refuse it, by name.
    if (isDoorUrl(url) && !gatewayProcessHere(d)) {
      return { local: false, reason: "door-url-from-child", address: addresses[0] };
    }
    const snapshot = d.snapshot || await buildVouch(d);
    // SEVERAL CANDIDATES: judge each IN ORDER, dial the FIRST that is local, refuse
    // only when none passes. The address returned is the one judged, so the
    // caller's connect lands on it rather than on a fresh answer for the name.
    if (dialled && dialled.length > 1) {
      const pick = async (snap) => {
        let failure = null;
        // ONE table read for EVERY candidate of this pass: the answers are judged
        // from one instant of the kernel's view (a dual-stack name used to re-read
        // /proc once per address), and each answer is judged exactly as before.
        const tables = tablesOnce(d);
        for (const address of addresses) {
          if (!isOwnHostAddress(address, d.ownAddrs)) continue;
          const verdict = await addressVerdict(port, address, snap, d, tables);
          if (verdict.local) return { verdict };
          if (!failure) failure = verdict;
        }
        return { failure };
      };
      const first = await pick(snapshot);
      if (first.verdict) return first.verdict;
      // S2: a container created AFTER this snapshot can vouch the port, so a
      // not-vouched answer re-reads Docker ONCE (rate-limited) before refusing.
      if (first.failure && first.failure.reason === "not-vouched") {
        const refreshed = await refreshVouchFor(d);
        if (refreshed) {
          const again = await pick(refreshed);
          if (again.verdict) return again.verdict;
        }
      }
      return first.failure || { local: false, reason: "not-vouched", address: addresses[0] };
    }

    // ONE candidate (a pinned single answer or an IP literal): the one address this
    // judgement — and the caller's connect — is about. When the caller handed in NO
    // address (`dialled` null: a listing, a caller with no pin of its own) the whole
    // ANSWER SET is judged together, as it always was — that verdict is only used to
    // classify, because every forward resolves ONE address and hands that one in.
    const address = addresses[0];
    const decide = async (snap) => {
      // ONE table read for this pass, shared by the self-ownership check and the
      // listener verdict below (L1: the two used to read and parse both tables each).
      const tables = tablesOnce(d);
      if (!vouchSourceFor(port, addresses, snap, { isProcessAlive: d.isProcessAlive }) && !await selfOwnsListener(port, addresses, d, tables)) {
        return { local: false, reason: "not-vouched", address };
      }
      return { ...await listenerVerdict({ port, addresses, snapshot: snap, d, tables }), address };
    };
    const verdict = await decide(snapshot);
    if (verdict.reason !== "not-vouched") return verdict;
    // S2 (see above): one forced Docker re-read before the refusal stands.
    const refreshed = await refreshVouchFor(d);
    const again = refreshed ? await decide(refreshed) : null;
    return again && again.local ? again : verdict;
  } catch {
    return { local: false, reason: "listener-not-trusted", address: null };
  }
}

/**
 * S2: re-read Docker ONCE, with `force`, for a target nothing vouched for.
 *
 * The vouch snapshot is cached ~30 s (an unreachable Docker keeps the last good
 * one), and the acquire path can CREATE a model container a moment after the
 * snapshot was taken — the first forward after a cold start would be refused on a
 * container that is already running. So a not-vouched verdict asks Docker again,
 * once, before it stands.
 *
 * Rate-limited PROCESS-WIDE (`DOCKER_REFRESH_MIN_MS`), because this runs on the
 * forward path: a bot retrying in a loop — and a bot picks its own ports, so a
 * per-target window bounded nothing — must not turn the refresh into one `docker
 * inspect` per request. ONE stamp, ONE window, no per-target map. An INJECTED
 * `dockerEntries` snapshot is not re-read (a test states what Docker says), and a
 * failed read answers null so the caller keeps the verdict it had. Returns the
 * fresh snapshot, or null.
 *
 * CONCURRENT CALLERS SHARE ONE REFRESH: the first caller's read is parked in
 * `_refreshFlight`, and every caller that arrives while it runs awaits THAT
 * promise (so it gets the fresh snapshot too, instead of the stale one the window
 * would otherwise hand it). The flight is cleared when it settles.
 */
async function refreshVouchFor(d) {
  if (Array.isArray(d.dockerEntries)) return null;
  if (_refreshFlight) return _refreshFlight;
  if (_dockerRefreshAt != null) {
    const elapsed = d.now() - _dockerRefreshAt;
    // A stamp in the FUTURE bounds nothing (a clock that went backwards), so it
    // never blocks a refresh.
    if (elapsed >= 0 && elapsed < DOCKER_REFRESH_MIN_MS) return null;
  }
  _dockerRefreshAt = d.now();
  const flight = (async () => {
    try { return await buildVouch(d, { force: true }); } catch { return null; }
  })();
  _refreshFlight = flight;
  try { return await flight; } finally { if (_refreshFlight === flight) _refreshFlight = null; }
}

/** ONE own-host address's verdict: the port must be vouched FOR THAT ADDRESS and
 * the process holding its listening socket must not be a bot. This is the
 * per-candidate judgement the ordered selection above walks. */
async function addressVerdict(port, address, snapshot, d, tables = null) {
  const addresses = [address];
  if (!vouchSourceFor(port, addresses, snapshot, { isProcessAlive: d.isProcessAlive }) && !await selfOwnsListener(port, addresses, d, tables)) {
    return { local: false, reason: "not-vouched", address };
  }
  return { ...await listenerVerdict({ port, addresses, snapshot, d, tables }), address };
}

/** The exact addresses the caller says it will dial, or null (derive them from the
 * URL). `deps.dialAddresses` is a plain list; `deps.pinned` is a
 * `pinnedTargetOf` result (`{address, addresses}`). */
function explicitDialAddresses(d) {
  const list = Array.isArray(d.dialAddresses) && d.dialAddresses.length
    ? d.dialAddresses
    : d.pinned && typeof d.pinned === "object"
      ? (Array.isArray(d.pinned.addresses) && d.pinned.addresses.length ? d.pinned.addresses : [d.pinned.address])
      : null;
  if (!list) return null;
  const out = list
    .map((a) => normalizeAddress(typeof a === "string" ? a : (a && a.address)))
    .filter(Boolean);
  return out.length ? out : null;
}

/** The LISTEN rows of both /proc/net tables that match this address and port.
 * `tables` is a pass's shared read (`tablesOnce`); without one, a fresh read is
 * taken here. */
async function listenerRows(port, addresses, d, tables = null) {
  const t = await (tables ? tables() : procTables(d));
  const matching = (text, family) => parseProcNetRows(text, family, { port })
    .filter((r) => r.state === LISTEN_STATE && r.port === port && procAddressCovers(r.address, addresses));
  return [...matching(t.tcp, 4), ...matching(t.tcp6, 6)];
}

/**
 * The FIFTH vouch, and the strongest one there is: the listening socket on this
 * address and port belongs to THIS process. A `providers` row is bot-writable, but
 * nothing a bot writes can make the gateway open a listening socket — the socket
 * is the gateway's own code. (The path rule still decides what a forward to this
 * box may ask for; this only says the port is ours.)
 */
async function selfOwnsListener(port, addresses, d, tables = null) {
  let rows;
  try { rows = await listenerRows(port, addresses, d, tables); } catch { return false; }
  for (const row of rows) {
    if (row.uid !== d.uid) continue;
    // THIS process's fd table only — one readdir, never the box (H4).
    if (Number.isInteger(d.selfPid) && d.selfPid > 0 && await pidHoldsSocketInode(d.selfPid, row.inode, d)) return true;
  }
  return false;
}

/** (2) The listener half: who holds EVERY LISTEN socket on this address and port?
 *
 * EVERY same-uid row must be trusted — one trusted row does not vouch for the
 * others. A name can stand for several addresses (localhost is 127.0.0.1 AND ::1)
 * and SO_REUSEPORT lets two sockets share one address and port, so "a trusted
 * listener exists" would let a bot's socket answer the forward that a model's
 * socket vouched for. */
async function listenerVerdict({ port, addresses, snapshot, d, tables = null }) {
  const rows = await listenerRows(port, addresses, d, tables);
  if (!rows.length) return { local: false, reason: "no-listener" };
  // A uid that is not ours is not a bot (contain maps only the gateway's uid):
  // this is docker-proxy running as root, or another service.
  const mine = rows.filter((r) => r.uid === d.uid);
  for (const row of mine) {
    const pid = await findTrustedSocketPid(row.inode, port, addresses, snapshot, d);
    // A same-uid listener whose owner we cannot name is refused, never skipped.
    if (pid == null) return { local: false, reason: "listener-not-trusted" };
    if (!listenerTrusted(pid, port, addresses, snapshot, d)) return { local: false, reason: "listener-not-trusted" };
  }
  return { local: true, reason: "vouched" };
}

/**
 * The accept wait's poll interval for `elapsedMs` into the wait (L1). ~2 ms while
 * an accept is expected, then a backoff, capped by the caller's own `pollMs` base.
 * This decides nothing — only how often the same question is asked — and an
 * explicit `pollMs` still sets the base for a caller (a test) that wants its own.
 */
export function acceptPollDelay(elapsedMs, pollMs) {
  const base = Math.max(1, Math.min(ACCEPT_POLL_MAX_MS, Math.floor(Number(pollMs)) || ACCEPT_POLL_BASE_MS));
  if (!(elapsedMs >= ACCEPT_POLL_FAST_WINDOW_MS)) return Math.min(ACCEPT_POLL_FAST_MS, base);
  const doublings = Math.min(4, Math.floor((elapsedMs - ACCEPT_POLL_FAST_WINDOW_MS) / 100));
  return Math.min(ACCEPT_POLL_MAX_MS, base * 2 ** Math.max(0, doublings));
}

/**
 * THE ACCEPTED CONNECTION (H1): the socket a forward already has, verified BEFORE
 * any request byte is written.
 *
 * The LISTEN judgement above says "every same-uid listening socket on this address
 * and port is ours". A forward then connects — and llama.cpp's server sets
 * SO_REUSEPORT, so a same-uid `bot` (a contained bot shares the host network) can
 * open its OWN reuseport listener on the model's port IN THAT WINDOW and the kernel
 * may hand it the connection. A pooled keep-alive socket stretches one win over
 * many requests. So the connection itself is judged:
 *
 *   1. open the TCP socket ourselves (`net.connect` to the judged address:port);
 *   2. on `connect`, find the SERVER side of THIS connection in /proc/net/tcp{,6}:
 *      local = the server address:port, remote = OUR socket's
 *      localAddress:localPort, in ANY state except TIME_WAIT (a stale row from an
 *      earlier connection that reused our client port);
 *   3. a row whose uid is not ours is trusted (docker-proxy runs as root);
 *   4. our own uid, state ESTABLISHED: wait (bounded) until its inode stops being
 *      0 — that is the kernel's "accepted by an application" — and trust it ONLY
 *      when the inode is held by one of the CANDIDATE pids (`findTrustedSocketPid`:
 *      this process, a live native handle, a pinned/managed binary holder, a
 *      docker-cgroup pid) that also passes `listenerTrusted`. A row in SYN_RECV is
 *      PENDING, not a decision (N1: under load our connect completes before the
 *      server processed the final ACK, so a healthy model looked exactly like a
 *      squatter; the wait stays inside the accept budget). Our own uid in any
 *      OTHER state is a REFUSAL: the connection is in this namespace and the
 *      socket at the other end is already closing (FIN_WAIT), which is exactly a
 *      bot's accept-then-half-close;
 *   5. NO LOCAL ROW AT ALL, for the short window below: a RUNNING Docker
 *      container is reached through the kernel's own NAT, not through a socket in
 *      our network namespace (`noLocalRowIsDockerNat`), which is trusted with the
 *      reason "nat-to-container" — but only when a docker binding vouches the
 *      address:port, that container is RUNNING, AND no same-uid listener existed
 *      on it;
 *   6. anything else: destroy the socket and refuse.
 *
 * So the address that was judged is the address that was connected to, the
 * connection that was accepted is the connection that is used, and a bot's
 * reuseport socket can only ever be refused.
 */
export async function verifyAcceptedConnection({ address, port, clientAddress, clientPort, snapshot = null, deps = {}, timeoutMs = 2_000, pollMs = ACCEPT_POLL_BASE_MS } = {}) {
  const d = resolveDeps(deps);
  const serverAddresses = [normalizeAddress(address)];
  const startedAt = d.now();
  const deadline = startedAt + Math.max(0, Number(timeoutMs) || 0);
  // The NAT branch gets ONE short window, never the accept budget (J1): a local
  // listener's child is visible immediately — in ANY live state, so a squatter that
  // already hung up is caught too (K1) — so "still nothing after 10 ms" is the
  // answer, not "wait 2 s longer".
  const natDeadline = Math.min(deadline, startedAt + NAT_ROW_WAIT_MS);
  const snap = snapshot || buildSyncVouch(d);
  let natSettled = false;
  for (;;) {
    // A FRESH read every pass: this is the state of the kernel AFTER the connect, and
    // no row from before it may be reused for this decision.
    const tables = await procTables(d);
    let rows = [];
    try { rows = connectionRows(port, serverAddresses, clientAddress, clientPort, tables); } catch { rows = []; }
    if (rows.length) {
      let pending = false;
      let refused = false;
      for (const row of rows) {
        // A uid that is not ours is not a bot: docker-proxy (root), another service.
        if (row.uid !== d.uid) continue;
        // A row still in SYN_RECV is PENDING (N1): the kernel has this connection, and
        // the server has not processed the final ACK yet. Under load a healthy model
        // looked exactly like this, so wait for it within the accept budget rather
        // than refuse it. Every other non-ESTABLISHED state is a REFUSAL (below).
        if (row.state === SYN_RECV_STATE) { pending = true; continue; }
        // OUR OWN uid in anything but ESTABLISHED (FIN_WAIT1/2 after the peer's
        // half-close, CLOSE_WAIT, …): the connection IS in this network namespace
        // and the socket at the other end is closing. That is not a container
        // reached by NAT and it is not a socket Crow may talk to — it is the
        // shape of a squatter that accepted our connection and hung up.
        if (row.state !== ESTABLISHED_STATE) { refused = true; break; }
        // Not accepted by an application yet: the inode is still 0. Wait for the
        // kernel to hand the connection to a socket someone holds.
        if (!row.inode || row.inode === "0") { pending = true; continue; }
        const pid = await findTrustedSocketPid(row.inode, port, serverAddresses, snap, d);
        if (pid == null || !listenerTrusted(pid, port, serverAddresses, snap, d)) { refused = true; break; }
      }
      if (refused) return { trusted: false, reason: "connection-not-trusted" };
      if (!pending) return { trusted: true, reason: "vouched" };
    }
    const now = d.now();
    if (!rows.length && !natSettled && now >= natDeadline) {
      natSettled = true;
      const nat = await noLocalRowIsDockerNat({ port, addresses: serverAddresses, snapshot: snap, d });
      if (nat) return nat;
    }
    if (now >= deadline) return { trusted: false, reason: "connection-not-trusted" };
    await new Promise((r) => setTimeout(r, acceptPollDelay(now - startedAt, pollMs)));
  }
}

/**
 * THE NAT-TO-CONTAINER BRANCH (J1). Docker publishes a host port by installing its
 * own NAT rules, and an OUTBOUND connection from this host to one of its OWN
 * non-loopback addresses on a published port is DNAT'd by the kernel straight into
 * the container's network namespace (an iptables OUTPUT rule). Loopback is not:
 * `docker-proxy` accepts that one, so it has a server row like any other listener
 * and the ordinary path already verifies it.
 *
 * The consequence is that for such a connection there is NO server-side row in
 * OUR /proc/net/tcp{,6} — only the client row — and the inode verification above
 * polls to its deadline and refuses a perfectly good model server. So, after the
 * connect SUCCEEDED and a short window found no local row, the connection is
 * trusted with the reason "nat-to-container" when BOTH of these hold:
 *
 *   (1) a DOCKER binding (vouch (a), already through the compose-directory rule)
 *       vouches this exact address:port AND belongs to a container that is
 *       RUNNING — a stopped container keeps its published bindings but the kernel
 *       has no DNAT rule for it, so its port is a free one and a squatter there
 *       would produce exactly this no-row shape;
 *   (2) NO same-uid LISTEN row existed on that address:port when this was checked.
 *
 * (An injected snapshot entry must say `running: true` explicitly — N2: the real read
 * always says, `DOCKER_INSPECT_FORMAT` carries `.State.Running`, and an entry that
 * does not say it is not evidence that the kernel holds NAT rules for the port.)
 *
 * WHY THAT IS SOUND. A peer reached this way is OUTSIDE our network namespace, and
 * nothing a contained bot can do puts a socket there: it cannot create a network
 * namespace (seccomp/unshare denied in the contained tier) and it cannot add NAT
 * rules (no CAP_NET_ADMIN). Any listener a bot opens lives in OUR namespace, and
 * its connections — accepted or not — show a same-uid server row, which is exactly
 * what condition (2) excludes: a same-uid LISTEN row means the ordinary inode
 * verification applies and this branch is never taken, so a bot's socket can never
 * be the thing this trusts. (A bot that opens its listener AFTER our connection is
 * already established changes nothing about the socket we hold — the row for it
 * would still be absent because of the bot, not because of NAT.)
 *
 * THE RESIDUAL THIS DOES NOT ADD: a DOCKER-GROUP bot in an UNCONTAINED tier can
 * already mint a Docker vouch of its own (LIMITS (b) below), and a container it
 * starts is in a docker cgroup, which the ordinary listener half already trusts. So
 * this branch grants no reach that tier did not have; in a contained tier — no
 * docker socket, no unshare, no CAP_NET_ADMIN — nothing reaches it at all.
 */
async function noLocalRowIsDockerNat({ port, addresses, snapshot, d }) {
  const published = (snapshot.docker || []).some((e) => Number(e.port) === port
    && bindingCovers(e.address, addresses)
    // ONLY a container that is RUNNING: Docker removes the NAT rules with the
    // container, so "no local row" for a stopped container's published port is a
    // free port. A snapshot entry that does not say `running: true` counts as NOT
    // running (N2): the real read always says (`DOCKER_INSPECT_FORMAT` carries
    // `.State.Running`), and an entry that stays silent is not evidence that the
    // kernel has DNAT rules for that port.
    && e.running === true);
  if (!published) return null;
  let rows;
  try { rows = await listenerRows(port, addresses, d); } catch { return null; }
  // ANY same-uid listener at check time: the inode rule owns this connection.
  if (rows.some((r) => r.uid === d.uid)) return null;
  return { trusted: true, reason: "nat-to-container" };
}

/** The /proc rows for ONE connection, out of the tables the caller read for THIS pass
 * (a read taken after the connect, never a pre-connect one). */
function connectionRows(port, serverAddresses, clientAddress, clientPort, tables) {
  const rows = [
    ...parseProcNetRows(tables.tcp, 4, { port, connections: true }),
    ...parseProcNetRows(tables.tcp6, 6, { port, connections: true }),
  ];
  return rows.filter((r) => r.state !== TIME_WAIT_STATE
    && r.port === port
    && procAddressCovers(r.address, serverAddresses)
    && Number(r.remotePort) === Number(clientPort)
    && r.remoteAddress != null
    && compareAddress(r.remoteAddress) === compareAddress(clientAddress));
}

/** Is the process holding the listening socket one Crow itself put there? */
function listenerTrusted(pid, port, addresses, snapshot, d) {
  // (i) this very process: the gateway's own code. Nothing a bot writes into
  // crow.db can make the gateway open a listening socket.
  if (pid === d.selfPid) return true;
  // (i) a Docker container (the container's own process, not docker-proxy).
  if (inDockerCgroup(pid, d)) return true;
  const exe = exeOf(pid, d);
  // (ii) THE NATIVE RUNTIME'S OWN CHILD, matched by PID — never by ancestry. An
  // uncontained bot is a descendant of the gateway in the same user namespace, so
  // "descendant" proved nothing; a live handle (or the runtime's own binary on a
  // reserved port) is a fact Crow holds outside crow.db.
  const handles = nativeHandlesOf(d);
  if (handles.length) {
    for (const h of handles) {
      if (!h.live) continue;
      if (Number(h.port) !== port) continue;
      if (h.pid !== pid) continue;
      // ... and the ADDRESS it bound, not the port alone: a model on
      // 127.0.0.1 does not vouch a listener on another own address.
      if (!bindingCovers(h.host, addresses)) continue;
      return true;
    }
  } else if (portReservedLive(port, snapshot, d) && sameUserNs(pid, d)) {
    // A process that supervises no llama-server at all (the memory MCP child, a
    // pi-bots host process) trusts only the runtime's OWN BINARY, on a port
    // state.json reserves for a pid that is alive, and in THIS process's user
    // namespace (a bot sandbox has a namespace of its own — the pin rule's check).
    // The binary is identified BY CONTENT — the sha256 `ensureRuntime` recorded
    // when it verified it — and only then does its dev+inode have to equal
    // `/proc/<pid>/exe`'s. A path that merely looks like the runtime's, a symlink
    // at a candidate's path, a manifest naming something outside its release dir
    // and a manifest with no recorded checksum all fail here, one way or another.
    const running = exeIdentity(pid, d);
    if (running) {
      for (const cand of managedRuntimeBinCandidates(d)) {
        if (verifiedCandidateIdentity(cand, d) === running) return true;
      }
    }
  }
  // (iii) an operator pin: the pinned EXECUTABLE, run in the gateway's own user
  // namespace. A pinned path alone is not enough — a bot can name any path.
  if (exe) {
    for (const pin of snapshot.pins || []) {
      if (Number(pin.port) !== port || !bindingCovers(pin.address, addresses)) continue;
      if (pin.exe !== exe && realOrSelfExe(pin.exe, d) !== exe) continue;
      if (sameUserNs(pid, d)) return true;
    }
  }
  return false;
}

/**
 * The SYNC, VOUCH-ONLY predicate — for LISTING and CLASSIFICATION only, never to
 * authorize a forward (it does not look at the listener at all). It answers the
 * same `{ local, reason }` shape from the cached Docker snapshot plus the
 * sync-readable sources; an own-host target no source vouches for is
 * "unverified-local": neither local nor cloud.
 */
export function isKnownLocalModelTargetCached(url, deps = {}) {
  const d = resolveDeps(deps);
  try {
    const cls = classifyTarget(url, d);
    if (cls.kind === "forbidden") return { local: false, reason: "forbidden" };
    if (cls.kind === "not-local-class") return { local: false, reason: "not-local-class" };
    const host = targetHost(url);
    if (!host) return { local: false, reason: "not-local-class" };
    // Own host without asking a resolver: an IP literal is judged on the address,
    // a loopback name is loopback (RFC 6761), and a name this process has already
    // resolved is judged on that answer. Any other name is simply not this host
    // (a LAN/tailnet peer), which is what it was before and all a listing needs.
    let ownHost = isOwnHostAddress(host, d.ownAddrs) || LOOPBACK_NAMES.has(host) || host.endsWith(".localhost");
    // A LOOPBACK NAME stands for BOTH loopback addresses (RFC 6761: `localhost` is
    // 127.0.0.1 AND ::1). Judging the NAME as a string matched no binding at all,
    // so a row naming `localhost:<port>` — the Ollama bundle's `localhost:11434`,
    // a Kokoro on `localhost:8880` — dropped out of every listing as
    // "unverified-local" while the identical row written as 127.0.0.1 listed fine.
    let addresses = (LOOPBACK_NAMES.has(host) || host.endsWith(".localhost")) && !isLoopbackAddress(host)
      ? [...LOOPBACK_NAME_ADDRESSES]
      : [host];
    if (!ownHost && _nameAddrs.has(host)) {
      addresses = _nameAddrs.get(host);
      ownHost = addresses.some((a) => isOwnHostAddress(a, d.ownAddrs));
    }
    if (!ownHost) return { local: true, reason: "other-host" };
    const port = targetPort(url) ?? 0;
    // THE LISTING PATH NEVER SPAWNS A PROCESS, so a snapshot it does not have yet is
    // primed in the BACKGROUND and used from the next call on (H3). A process that
    // is not the gateway — the pi-bots spawner, the memory server — never called
    // `primeLocalModelVouch`, so before this every Docker-only model read
    // "unverified-local" there forever.
    primeDockerInBackground(d);
    const snapshot = d.snapshot || buildSyncVouch(d);
    if (!vouchSourceFor(port, addresses, snapshot, { isProcessAlive: d.isProcessAlive })) {
      return { local: false, reason: "not-vouched" };
    }
    return { local: true, reason: "vouched" };
  } catch {
    return { local: false, reason: "not-vouched" };
  }
}

/** The one question a LISTING asks: is this row the new "unverified-local" class
 * (this machine, and no model server vouches for the port)? */
export function isUnverifiedLocalTarget(url, deps = {}) {
  const r = isKnownLocalModelTargetCached(url, deps);
  return !r.local && (r.reason === "not-vouched" || r.reason === "no-listener" || r.reason === "listener-not-trusted");
}

/**
 * ONE log line per refused forward (the callers own it, so exactly one is
 * printed per refusal). Fixed shape: an operator greps for `[door] own-host
 * target`.
 */
export function logOwnHostTargetRefusal({ address, port, providerId, reason }, log = (l) => console.log(l)) {
  const host = address && String(address).includes(":") ? `[${address}]` : address || "?";
  log(`[door] own-host target ${host}:${port} is not a known model server (provider ${providerId}, ${reason})`);
}

/** The most specific own-host address for a target URL, for that log line. */
export function describeTarget(url) {
  const host = targetHost(url);
  const port = targetPort(url) ?? 0;
  const known = host && _nameAddrs.get(host);
  const address = known && known.length ? known[0] : host;
  return { address: address || "?", port };
}

/**
 * S1 (boot support): ONE log line per ENABLED provider row whose own-host target
 * nothing vouches for AT REST, printed by the gateway right after its first vouch
 * snapshot (`boot/admin-api.js`, beside `primeLocalModelVouch`).
 *
 * This is the diagnostic behind the forward refusal: an operator whose model runs
 * as a container of a NON-AI bundle, as a bare process nobody pinned, or as a
 * container Docker created after the snapshot, sees why the door says no — and
 * what to do about it (`local-model-pin add-compose`, or run it as a model
 * container). It changes NO decision and dials nothing: the judgement is
 * `isKnownLocalModelTargetCached` (sync, vouch-only, cached Docker snapshot), and
 * a row that is not own-host (a cloud row, a LAN/tailnet peer) is not mentioned at
 * all. Logs only, exactly one line per row, in a fixed shape an operator greps
 * for: `[local-model] provider <id> (<addr>:<port>) is not vouched at rest; …`.
 *
 * Returns how many lines it printed (tests).
 */
export function logUnvouchedProviderRows(rows, { log = (line) => console.log(line), deps = {} } = {}) {
  const d = resolveDeps(deps);
  let printed = 0;
  for (const row of Array.isArray(rows) ? rows : []) {
    if (!row || typeof row !== "object" || row.disabled) continue;
    const id = typeof row.id === "string" && row.id ? row.id : null;
    const url = typeof row.baseUrl === "string" && row.baseUrl ? row.baseUrl : null;
    if (!id || !url) continue;
    let verdict;
    try { verdict = isKnownLocalModelTargetCached(url, { ...deps, crowHome: d.crowHome }); } catch { continue; }
    // Only the own-host-and-nothing-vouches case: not-vouched. (An other-host row is
    // local:true; a forbidden/not-local-class row is not a local model at all.)
    if (verdict.local || verdict.reason !== "not-vouched") continue;
    const { address, port } = describeTarget(url);
    const host = address && String(address).includes(":") ? `[${address}]` : address || "?";
    log(`[local-model] provider ${id} (${host}:${port}) is not vouched at rest; it will be refused unless its server is running as a known model container or pinned`);
    printed++;
  }
  return printed;
}