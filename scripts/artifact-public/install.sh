#!/usr/bin/env bash
#
# Install the Crow artifacts public-link front end on this host.
#
# WHAT IT INSTALLS (all four pieces are one feature; nothing here works alone):
#
#   1. crow-report-readers.socket — SYSTEMD owns the door socket
#      (/run/crow-report-readers/door.sock, root:crow-artifact-public 0660), the
#      same shape the gateway's Caddy proxy socket already has, so no process
#      creates, chmods or unlinks a path and only root and one group can open it.
#      It is PartOf=crow-gateway.service, so stopping or restarting the gateway stops
#      or restarts this socket too: a request arriving at a gateway the operator
#      stopped on purpose cannot start it again, and the listener answers its 503
#      page until the gateway is started;
#   2. report-readers.conf — a crow-gateway.service drop-in that hands the gateway
#      that fd by socket activation (Wants=/After=/Sockets=) and clears and
#      re-states ExecStart so NODE ITSELF is the MainPID. systemd passes
#      activation fds to the MainPID only, and the gateway's pickActivatedFd
#      refuses a LISTEN_PID that is not its own pid, so without this the gateway
#      would receive nothing. Wants= and not Requires=: a gateway that can start
#      without the door socket is a gateway that can still be restarted for any
#      other reason, and the listener answers its 503 page until the socket is
#      back. The drop-in leaves WorkingDirectory, ExecStartPre, ExecStopPost and
#      the unit's Environment= lines exactly as the unit has them, because the
#      ExecStart it re-states is relative to the directory the unit already runs
#      in and the boot guard around it is not this installer's business;
#   3. crow-artifact-public.service — the public-link listener on port 3093: an
#      unprivileged, sandboxed process that can read node and its own two scripts
#      and nothing else, and cannot see this instance's home at all;
#   4. one scoped ufw rule — in on the sidecar bridge interface, from the
#      sidecar's own address, to the bind address, port 3093/tcp. Nothing widens
#      that port to any other source.
#
# WHERE THE NODE COMES FROM: the gateway's OWN unit, never PATH. Its ExecStart is
# read with `systemctl show` and the binary taken when that is node — or the node
# beside it when it is npm, which is what a unit using `npm run gateway` runs. That
# path must then be absolute (it starts with '/'), executable, and the major version
# package.json's engines declare, because on a box whose system node is older than the
# version the gateway actually runs, `command -v node` would pin a binary that cannot
# load it. Nothing here ever consults PATH, for node or for anything else: there is no
# fallback, and a path that is not absolute is a refusal.
#
# WHERE IT MAY RUN FROM: the unit's WorkingDirectory must be this very checkout, on
# branch main, with no uncommitted change to a tracked file, so a run from a worktree —
# or from a checkout somebody is halfway through editing — can never repoint production
# at code that is not what production runs. Every one of those checks refuses (exit 2,
# nothing changed) before a file is written.
#
# AND GIT NEVER RUNS AS ROOT: that state is read by running git AS the checkout's own
# owner (`runuser -u "$CHECKOUT_OWNER"`), with the system config ignored and the three
# repository-config switches that can run a command — core.fsmonitor, a filter through
# core.hooksPath, the untracked cache — turned off. A checkout owned by root, or one
# whose owner cannot be resolved to a numeric uid other than 0, is refused instead: root
# running git in a repository another user controls executes whatever that repository
# says to execute, with root's rights.
#
# WHAT HAPPENS IF IT DIES: nothing is left half applied, and the undo does not depend on this
# process surviving. Before the first change the script takes a root-only backup under /run
# (which of the three files existed, a copy of each, what state the two units were in), writes a
# standalone restore.sh beside it with those values baked in, and arms ONE detached transient
# systemd timer — the deadman — that runs that script through /bin/bash, never as a bare command,
# because /run is mounted noexec on the target box. So an install killed with SIGKILL — which no
# trap can catch — is still put back.
#
# ITS CAP IS NOT A GUESS. DEADMAN_AFTER is ADDED UP from the named budgets beside STEP_TIMEOUT —
# STEP_TIMEOUT times the number of capped steps, the wait for a new InvocationID, the /health
# poll and the round trip — plus a margin, and it is strictly above this run's own wall clock
# plus the kill-after that follows it. So the deadman always outlives the install: it can never
# fire while the process that armed it is still alive to finish, or to fail loudly. The
# arithmetic and its result are written out where those constants are.
#
# THE WORST-CASE WINDOW IN WHICH PRODUCTION CAN BE DOWN is the deadman's cap (2255 s from the
# moment it is armed, which is before anything production serves has changed) plus restore.sh's
# own bounded work (about 1600 s of capped steps and two bounded waits): a little over an hour,
# and in an ordinary run the gateway is back inside its first 60 s step. That is a ceiling, not
# a schedule — no step here is expected to take more than a second or two.
#
# AND KEEPING THE INSTALL IS THE OPERATOR'S DECISION, TAKEN WITH THE CHECKS IN FRONT OF THEM.
# On success this script prints the exact command that keeps it —
#
#     sudo touch <backup dir>/keep
#
# — plus the time the deadman fires and how long is left until then, and then exits 0 WITHOUT
# writing that file, without stopping the timer and without removing the backup. A script that kept
# its own work would make the deadman a decoration: only a human who has read the checks can say
# the install was wanted. If nobody runs it before the fire time, restore.sh puts the host back
# exactly as it was.
#
# THE KEEP WINDOW IS THE DEADMAN'S CAP MINUS THE TIME THIS RUN ACTUALLY TAKES. The cap is
# DEADMAN_AFTER — 2255 s, and 2255 / 60 = 37.6 minutes — added up from the named budgets beside
# STEP_TIMEOUT: 21 x 60 s of capped steps plus 875 s of bounded waits = 2135 s, a 60 s wall-clock
# margin = 2195 s, a 30 s kill-after, and a 30 s deadman margin. An ordinary run spends a second or
# two on those steps rather than their caps, so the operator normally has ABOUT 37 MINUTES to read
# the checks and run the keep command. Two caveats, and they are the whole of it: a `keep` touched
# AFTER the deadman has started does nothing at all — the restore has begun, and restore.sh looks at
# that file only before its first step — and touching `keep` BEFORE these checks have passed is
# deliberate and entirely at the operator's own risk, because this script cannot tell an install
# somebody wanted from one they have not yet decided about.
#
# WHAT IT PROVES BEFORE IT KEEPS ANYTHING: the gateway's /health answers 200, and
# a request through the listener for a token nobody was mailed comes back as the
# approved "this link doesn't open a report" 404 page with a sandboxed CSP. The
# second check can only pass when the whole chain is real — listener binding,
# socket present, gateway holding the fd, door answering — so it is the one check
# that says the feature works rather than that the units started.
#
# ANY FAILURE IS REPORTED, AND THE UNDO IS STARTED AT ONCE: there is no restoring trap, no lock,
# no second timer, no run id and no marker of any kind. There is exactly ONE undo implementation —
# the restore.sh written before the first change — so the undo a failure starts and the undo the
# deadman's timer fires cannot disagree about what "back the way it was" means, and this process
# can never half-restore a host while a unit is restoring the other half. A failing step (or TERM
# from the wall clock, or Ctrl-C) runs one handler: it names the failing step, starts that same
# script NOW — `systemctl start --no-block <deadman unit>.service`, the deadman's own service, so
# production is not left broken until the timer would have fired — prints the exact manual restore
# command — `sudo /bin/bash <backup dir>/restore.sh` — and the deadman's fire time (epoch and
# local), then exits non-zero. That one systemctl call is the only command the handler runs: no
# unit of its own is started, no rule deleted and no user removed, so the undo is still the one
# script. If the deadman was never armed, the handler starts nothing at all.
#
# AN EARLIER RUN'S DEADMAN IS REFUSED, NOT ADOPTED: before the backup directory is created this
# script refuses (exit 2, nothing changed) while any `crow-artifact-public-deadman-*.timer` is
# still active — which includes a timer whose restore is running right now — names each one, says
# which backup directory holds the restore.sh it would run, and prints two commands for it: 'to
# keep that run' first (touch keep, then run restore.sh, which changes nothing and only retires
# the timer) and 'to undo it' second (run restore.sh) — so no timer armed by an older run is ever
# left to undo a newer, kept install.
#
# WHAT THAT SCRIPT DOES, AND WHY IT IS SAFE TO RE-RUN: if `<backup dir>/keep` exists it logs
# "kept" and changes nothing. Otherwise it re-does every step
# — each of the three files back from its copy (or removed when it did not exist, and the
# drop-in's directory removed only if this run created it), both units stopped, disabled and then
# returned to the enabled/active state each had before, the system user removed only when the
# state file says this run created it (and only when that user is really there), the ufw rule
# deleted only when the state file says this run added it and `ufw show added` still lists it
# (under LC_ALL=C), a daemon-reload, a non-blocking gateway restart, then a bounded wait for a new
# active InvocationID and a bounded poll of /health — skipping the restart, the wait and the health
# check entirely when the state file says the gateway was never touched. There are no
# done/ran/lock/marker files: every step is a no-op the second time, so a second run is safe. A run
# BY HAND is safe only AFTER this installer has exited, because while it is still working the two
# would be changing the same files at once. Once its decision is final — kept, or fully restored,
# or finished but unhealthy — the script stops its own deadman timer and then clears it (and the
# deadman's service) out of the unit list with `systemctl reset-failed`, so no armed timer outlives
# the run that set it; each call is a harmless no-op when the script IS the process that timer
# started. Every step is logged to the journal under `logger -t
# crow-artifact-public-restore`, each under its own `timeout`, and a gateway that is unhealthy at
# the end gets a loud ATTENTION line instead of being left for somebody to find later.
#
# WHAT THIS ACCEPTS RATHER THAN FIXES: the listener holds at most maxConnections=64 sockets
# (servers/artifact-public/server.mjs), so a caller who opens 64 slow connections can keep
# other visitors waiting until their sockets time out — the same accepted shape as the
# process-wide request and byte budgets, which also let a caller spend this instance's time
# and be answered with the fixed "unavailable" page. Neither ceiling can read a report nobody
# was mailed, and neither is a reason to widen what this listener may see or to move it off
# its own unprivileged user.
#
# NO PASSWORD IS EVER TAKEN HERE: this file contains no `sudo -S`, no sshpass and
# no secret of any kind; it writes system units, so it must already be root. The
# operator's own sudo is how that happens:
#
#   sudo CROW_ARTIFACT_PUBLIC_BIND=<dotted IPv4> \
#        CROW_ARTIFACT_BRIDGE_IF=<the sidecar bridge interface> \
#        CROW_ARTIFACT_SIDECAR_IP=<the sidecar's IPv4> \
#        bash scripts/artifact-public/install.sh
#
# Optional: CROW_GATEWAY_HEALTH_URL (default http://127.0.0.1:3001/health) and
# CROW_HOME (default: the invoking user's home + /.crow, looked up in passwd).
#
set -uo pipefail

SELF_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
SELF="$SELF_DIR/$(basename -- "${BASH_SOURCE[0]}")"
# Two directories up from this script's own directory: scripts/artifact-public -> the app dir.
APP_DIR="$(cd -- "$SELF_DIR/../.." && pwd -P)"
TEMPLATE_DIR="$SELF_DIR"

SOCKET_UNIT_NAME="crow-report-readers.socket"
SOCKET_UNIT_TEMPLATE="$TEMPLATE_DIR/crow-report-readers.socket.tmpl"
SOCKET_UNIT_DEST="/etc/systemd/system/$SOCKET_UNIT_NAME"

LISTENER_UNIT_NAME="crow-artifact-public.service"
LISTENER_UNIT_TEMPLATE="$TEMPLATE_DIR/crow-artifact-public.service.tmpl"
LISTENER_UNIT_DEST="/etc/systemd/system/$LISTENER_UNIT_NAME"

GATEWAY_UNIT_NAME="crow-gateway.service"
DROP_IN_DIR="/etc/systemd/system/$GATEWAY_UNIT_NAME.d"
DROP_IN_NAME="report-readers.conf"
DROP_IN_TEMPLATE="$TEMPLATE_DIR/gateway-door.conf.tmpl"
DROP_IN_DEST="$DROP_IN_DIR/$DROP_IN_NAME"

PUBLIC_USER="crow-artifact-public"
PUBLIC_PORT=3093
GATEWAY_HEALTH_URL="${CROW_GATEWAY_HEALTH_URL:-http://127.0.0.1:3001/health}"

# Every system step gets its own limit, and the whole run gets a hard wall clock. Every number
# below is DERIVED, so the relationships live in the code rather than in this comment.
STEP_TIMEOUT=60
# THE STEP BUDGET: how many single `timeout "$STEP_TIMEOUT"` steps the install path has at most.
# The vetting reads (systemctl cat, the two systemctl show reads, node -v, the two git reads
# through git_as_owner, four is-enabled/is-active reads, ufw status, ufw show added), the arm,
# the useradd, the daemon-reload, enable+start of the socket, the InvocationID read, the restart,
# and enable+start of the listener.
CAPPED_STEPS=21
# THE WAIT BUDGET, the three bounded waits on the success path, each a fixed number of tries:
#   the wait for a NEW active InvocationID, deadline-bounded           300 s (+25 overshoot)
#   the /health poll, 30 tries x (10 s request cap + 1 s apart)             330 s
#   the round trip through the listener, 20 tries x (10 s + 1 s)           220 s
# Those are the numbers the loops in sections 9 and 10 use — there is no second copy of them.
GATEWAY_INVOCATION_WAIT=300
GATEWAY_INVOCATION_SLACK=25
GATEWAY_HEALTH_TRIES=30
GATEWAY_HEALTH_INTERVAL=1
GATEWAY_ROUND_TRIP_TRIES=20
GATEWAY_ROUND_TRIP_INTERVAL=1
GATEWAY_REQUEST_CAP=10
INSTALL_STEP_BUDGET=$(( STEP_TIMEOUT * CAPPED_STEPS ))
INSTALL_WAIT_BUDGET=$(( GATEWAY_INVOCATION_WAIT + GATEWAY_INVOCATION_SLACK \
  + GATEWAY_HEALTH_TRIES * ( GATEWAY_REQUEST_CAP + GATEWAY_HEALTH_INTERVAL ) \
  + GATEWAY_ROUND_TRIP_TRIES * ( GATEWAY_REQUEST_CAP + GATEWAY_ROUND_TRIP_INTERVAL ) ))
# THE INSTALL'S WHOLE WORST CASE: every capped step at its cap, then every bounded wait.
INSTALL_WORST_CASE=$(( INSTALL_STEP_BUDGET + INSTALL_WAIT_BUDGET ))
# THE WALL CLOCK (section 2) is that worst case plus a margin, so this outer `timeout` can never
# be the reason a run whose every step merely hit its own cap is cut short: 21 x 60 = 1260 s,
# plus 300 + 25 + 330 + 220 = 875 s of waits = 2135 s, plus 60 s = 2195 s.
WALL_CLOCK_MARGIN=60
WALL_CLOCK_SECONDS=$(( INSTALL_WORST_CASE + WALL_CLOCK_MARGIN ))
REEXEC_FLAG="CROW_ARTIFACT_PUBLIC_INSTALL_TIMEOUT"
# THE KILL-AFTER is only the grace after that TERM before the wrapper SIGKILLs this run. It bounds
# nothing else: the undo is not this process's job (section 4), so there is no undo to protect
# here — the deadman below is what guarantees the undo, and it is armed to outlive this wrapper.
WALL_CLOCK_KILL_AFTER=30
# THE DEADMAN'S CAP, and the whole point of the arithmetic: it is the SAME install worst case,
# plus the wall-clock TERM and kill-after that follow it, plus DEADMAN_MARGIN — 2195 + 30 + 30 =
# 2255 s. So the deadman always outlives this run: an install that is still working (or that was
# killed) is undone after it, never under it. This is the number the header's worst-case
# production-down window is quoted from, together with restore.sh's own bounded work.
DEADMAN_MARGIN=30
DEADMAN_AFTER=$(( WALL_CLOCK_SECONDS + WALL_CLOCK_KILL_AFTER + DEADMAN_MARGIN ))

# The token shape the door accepts is 32 random bytes in base64url = 43 characters,
# and nothing else. This one asks for a report nobody was mailed, so the answer is
# the fixed "doesn't open a report" 404 — no data, no mail, no real link involved.
ROUND_TRIP_TOKEN="AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"
if [ "${#ROUND_TRIP_TOKEN}" -ne 43 ]; then
  echo "artifact-public install: internal error: the round-trip token is ${#ROUND_TRIP_TOKEN} characters, not the 43 the door accepts" >&2
  exit 1
fi

log() { echo "artifact-public install: $*"; }

# Every refusal here happens BEFORE anything on this machine changes.
refuse() {
  echo "artifact-public install: refusing: $*" >&2
  exit 2
}

# A failure AFTER the backup and the deadman exist: name the step, then let the ERR trap
# (on_fail, armed in section 4e) start the undo, print the guidance and exit. This function never
# exits on its own, so there is exactly one place that starts the undo and prints the command.
FAILED_STEP=""
fail() {
  FAILED_STEP="$*"
  echo "artifact-public install: FAILED: $*" >&2
  return 1
}

# THE ONE WAY THIS INSTALLER RUNS GIT. It runs as the checkout's OWNER, never as root,
# and it turns off the three repository-config switches through which a checkout could
# get a command executed: core.fsmonitor, whatever core.hooksPath points at, and the
# untracked cache. GIT_CONFIG_NOSYSTEM=1 keeps root's own /etc/gitconfig out of it too, so
# the answer describes the checkout and nothing about this host. Every argument is passed
# straight through, and every git call in this file goes through here — there is no second
# place that invokes git, so there is no second place to get this wrong.
git_as_owner() { # git_as_owner <arguments for git...>
  timeout "$STEP_TIMEOUT" runuser -u "$CHECKOUT_OWNER" -- env GIT_CONFIG_NOSYSTEM=1 git -c core.fsmonitor=false -c core.hooksPath=/dev/null -c core.untrackedCache=false -C "$APP_DIR" "$@"
}

# ── 1. The inputs, validated before a single file is written ─────────────────
#
# The bind address and the sidecar's address are dotted IPv4 and nothing else: the
# environment value below ends up in a systemd Environment= line and in a firewall
# rule, so its shape is checked here (four octets, each one 0-255 by arithmetic,
# not merely matched by the regex) rather than trusted. A hostname, a CIDR, an
# IPv6 address and a wildcard (all-interfaces) address are all refused, because
# each of them would widen a surface this installer exists to keep narrow.

valid_ipv4() {
  local ip="${1:-}" octet
  [[ "$ip" =~ ^([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})\.([0-9]{1,3})$ ]] || return 1
  for octet in "${BASH_REMATCH[1]}" "${BASH_REMATCH[2]}" "${BASH_REMATCH[3]}" "${BASH_REMATCH[4]}"; do
    if (( 10#$octet < 0 || 10#$octet > 255 )); then return 1; fi
  done
  # The wildcard address (every octet zero) would publish the listener on every interface, which is the
  # one thing this bind exists to prevent. It is refused by arithmetic, so the address itself never has
  # to be written into this file.
  if (( 10#${BASH_REMATCH[1]} == 0 && 10#${BASH_REMATCH[2]} == 0 \
        && 10#${BASH_REMATCH[3]} == 0 && 10#${BASH_REMATCH[4]} == 0 )); then
    return 1
  fi
  return 0
}

valid_ifname() {
  [[ "${1:-}" =~ ^[A-Za-z0-9_.-]{1,15}$ ]]
}

[ -n "${CROW_ARTIFACT_PUBLIC_BIND:-}" ] \
  || refuse "CROW_ARTIFACT_PUBLIC_BIND is not set; set it to the dotted IPv4 address this listener binds (the address the sidecar reaches): sudo CROW_ARTIFACT_PUBLIC_BIND=<dotted IPv4> ... bash $0"
valid_ipv4 "${CROW_ARTIFACT_PUBLIC_BIND}" \
  || refuse "CROW_ARTIFACT_PUBLIC_BIND must be a dotted IPv4 address (four octets, each 0-255); got '${CROW_ARTIFACT_PUBLIC_BIND}'. A hostname, a CIDR, an IPv6 address and a wildcard (all-interfaces) address are all refused"

[ -n "${CROW_ARTIFACT_BRIDGE_IF:-}" ] \
  || refuse "CROW_ARTIFACT_BRIDGE_IF is not set; set it to the bridge interface the sidecar's container reaches this host on, so the firewall rule can be scoped to it"
valid_ifname "${CROW_ARTIFACT_BRIDGE_IF}" \
  || refuse "CROW_ARTIFACT_BRIDGE_IF must be an interface name (1-15 characters from A-Z a-z 0-9 _ . -); got '${CROW_ARTIFACT_BRIDGE_IF}'"

[ -n "${CROW_ARTIFACT_SIDECAR_IP:-}" ] \
  || refuse "CROW_ARTIFACT_SIDECAR_IP is not set; set it to the sidecar's own IPv4 address, which is the only source the firewall rule allows"
valid_ipv4 "${CROW_ARTIFACT_SIDECAR_IP}" \
  || refuse "CROW_ARTIFACT_SIDECAR_IP must be a dotted IPv4 address (four octets, each 0-255); got '${CROW_ARTIFACT_SIDECAR_IP}'"

if [ "$(id -u)" -ne 0 ]; then
  echo "artifact-public install: run with sudo — this writes systemd units under /etc/systemd/system, makes a system user and adds a firewall rule. Nothing was changed." >&2
  exit 2
fi

command -v timeout >/dev/null 2>&1 \
  || refuse "the 'timeout' command (coreutils) is missing; every step here is capped by a hard time limit, so the installer will not run without it"
# git is only ever run as the checkout's owner, and switching user is what does it. Checked
# here, with the other tools this installer cannot work without, before anything changes.
command -v runuser >/dev/null 2>&1 \
  || refuse "the 'runuser' command (util-linux) is missing; this installer makes every git call as the checkout's owner rather than as root, so it will not run without it. Nothing was changed."

# The drop-in is meaningless without the unit it extends, and BOTH the node pin and
# the working-directory check below are read out of that unit. Reading a unit that
# does not exist and then refusing for the wrong reason would be confusing, so it
# is checked first. Read-only: `systemctl cat` changes nothing.
if ! timeout "$STEP_TIMEOUT" systemctl cat "$GATEWAY_UNIT_NAME" >/dev/null 2>&1; then
  refuse "no $GATEWAY_UNIT_NAME on this machine; this host is not running the Crow gateway, so there is no process to hand the door socket to. Nothing was changed."
fi

# ── 2. One hard wall clock for the whole run ────────────────────────────────
#
# Re-exec once under `timeout`, so no step (a systemctl that hangs, a curl that
# never answers, a ufw that waits on a lock) can hold this process forever. The wrapper only
# bounds THIS process: the undo is the deadman's job (section 4), armed to fire after the wall
# clock and the kill-after below have both passed, so a run that is TERMed — or SIGKILLed — here
# is still put back, by a process that outlives it. The flag keeps it from recursing; the values
# are exported so the child sees exactly what this process validated.
if [ "${CROW_ARTIFACT_PUBLIC_INSTALL_TIMEOUT:-0}" != "1" ]; then
  export CROW_ARTIFACT_PUBLIC_BIND CROW_ARTIFACT_BRIDGE_IF CROW_ARTIFACT_SIDECAR_IP
  export CROW_GATEWAY_HEALTH_URL
  export "$REEXEC_FLAG=1"
  log "re-running under a hard ${WALL_CLOCK_SECONDS}s wall-clock limit (SIGKILL ${WALL_CLOCK_KILL_AFTER}s after it); the deadman fires ${DEADMAN_AFTER}s after it is armed, so it outlives both"
  exec timeout -k "$WALL_CLOCK_KILL_AFTER" "$WALL_CLOCK_SECONDS" bash "$SELF" "$@"
fi

# ── 3. The values the templates are rendered with ───────────────────────────
#
# NODE COMES FROM THE GATEWAY'S OWN UNIT, NEVER FROM PATH. The gateway is already
# running some node; on a box whose system node is older than the version this repo
# declares, `command -v node` would find that older one, and the drop-in would then
# re-state ExecStart with a binary that cannot load the gateway at all. What the
# unit's ExecStart names is the one node this host is known to run the gateway
# with, so that is what gets pinned. Everything below is read-only (`systemctl
# show`) and every refusal happens before a single file is written.

# `systemctl show -p ExecStart --value` prints one block per command, like:
#   { path=/some/dir/node ; argv[]=/some/dir/node servers/gateway/index.js ; ignore_errors=no ; ... }
# The binary is the FIRST path= field, terminated by " ;" and padded with spaces.
unit_exec_path() {
  local blob="${1:-}"
  printf '%s\n' "$blob" \
    | sed -n 's/^.*[ {]path=\([^;]*\);.*$/\1/p' \
    | sed -n '1p' \
    | sed -e 's/^[[:space:]]*//' -e 's/[[:space:]]*$//'
}

GATEWAY_EXEC_START="$(timeout "$STEP_TIMEOUT" systemctl show -p ExecStart --value "$GATEWAY_UNIT_NAME" 2>/dev/null || true)"
[ -n "$GATEWAY_EXEC_START" ] \
  || refuse "could not read ExecStart out of $GATEWAY_UNIT_NAME ('systemctl show -p ExecStart --value' printed nothing); nothing was changed"
UNIT_EXEC_PATH="$(unit_exec_path "$GATEWAY_EXEC_START")"
[ -n "$UNIT_EXEC_PATH" ] \
  || refuse "could not find the binary in $GATEWAY_UNIT_NAME's ExecStart ('$GATEWAY_EXEC_START'); nothing was changed"

UNIT_EXEC_NAME="$(basename -- "$UNIT_EXEC_PATH")"
case "$UNIT_EXEC_NAME" in
  node)
    NODE_CANDIDATE="$UNIT_EXEC_PATH"
    ;;
  npm)
    # A unit written as `npm run gateway` has npm as its MainPID and node as npm's
    # child, and npm is itself a node program: the node beside it in the same bin
    # directory is the interpreter npm runs under and the one that child inherits,
    # so it is the version the gateway is actually on.
    NODE_CANDIDATE="$(dirname -- "$UNIT_EXEC_PATH")/node"
    ;;
  *)
    refuse "$GATEWAY_UNIT_NAME runs '$UNIT_EXEC_NAME' ($UNIT_EXEC_PATH) as its ExecStart; this installer pins node only when that is node itself, or npm with a node in the same directory. Nothing was changed."
    ;;
esac
NODE_BIN="$(readlink -f -- "$NODE_CANDIDATE" 2>/dev/null || printf '%s' "$NODE_CANDIDATE")"
[ -n "$NODE_BIN" ] \
  || refuse "the binary $GATEWAY_UNIT_NAME runs ('$UNIT_EXEC_PATH') resolves to an empty path; nothing was changed"
# The three properties the pinned node must have, checked one at a time so each refusal
# names the one condition that failed. ABSOLUTE FIRST: a relative path would be resolved
# against whatever working directory systemd gave the run, and this installer never
# consults PATH to fill the gap.
case "$NODE_BIN" in
  /*) ;;
  *) refuse "the node $GATEWAY_UNIT_NAME runs resolves to '$NODE_BIN', which is not an absolute path (it must start with '/'); this installer never falls back to PATH. Nothing was changed." ;;
esac
[ -x "$NODE_BIN" ] \
  || refuse "the node $GATEWAY_UNIT_NAME runs ('$UNIT_EXEC_PATH') resolves to '$NODE_BIN', which is not an executable file; nothing was changed"
# The install PREFIX of that node: the bin directory's parent. The listener's unit
# binds this read-only so node can load its own bundled libraries, and binds
# nothing else of the host.
NODE_DIR="$(dirname -- "$(dirname -- "$NODE_BIN")")"

# The pinned node must actually run, and must be the major version package.json
# declares. An unparseable engines field is a refusal and never a guess: pinning the
# wrong node into the gateway's ExecStart is exactly how a gateway stops booting.
PKG_JSON="$APP_DIR/package.json"
[ -f "$PKG_JSON" ] \
  || refuse "missing $PKG_JSON; this installer pins the node major declared there, so it will not run without it"
WANT_NODE_MAJOR="$(sed -n 's/.*"node"[[:space:]]*:[[:space:]]*">=\([0-9]\{1,\}\).*$/\1/p' "$PKG_JSON" | sed -n '1p')"
[ -n "$WANT_NODE_MAJOR" ] \
  || refuse "could not read a node major out of $PKG_JSON's engines (expected \"node\": \">=N\"); nothing was changed"
NODE_VERSION_RAW=""
NODE_VERSION_RAW="$(timeout "$STEP_TIMEOUT" "$NODE_BIN" -v 2>/dev/null)" \
  || refuse "the node $GATEWAY_UNIT_NAME runs ($NODE_BIN) does not run: '$NODE_BIN -v' failed, and a binary that cannot run cannot be pinned. Nothing was changed."
GOT_NODE_MAJOR="$(printf '%s' "$NODE_VERSION_RAW" | sed -e 's/^v//' -e 's/\..*$//')"
case "$GOT_NODE_MAJOR" in
  ''|*[!0-9]*)
    refuse "could not read a major version out of '$NODE_BIN -v' (got '$NODE_VERSION_RAW'); nothing was changed"
    ;;
esac
[ "$GOT_NODE_MAJOR" = "$WANT_NODE_MAJOR" ] \
  || refuse "the gateway runs node $NODE_VERSION_RAW ($NODE_BIN), but $PKG_JSON declares node $WANT_NODE_MAJOR.x; install that version and point $GATEWAY_UNIT_NAME's ExecStart at it. Nothing was changed."

# The drop-in's ExecStart re-states the script path RELATIVE to whatever
# WorkingDirectory the unit already has, so this installer can only be right when
# that directory is the checkout this script lives in. A run from a worktree would
# otherwise repoint production at the worktree's copy — and none of its files would
# be the ones the gateway is meant to load.
UNIT_WORKDIR="$(timeout "$STEP_TIMEOUT" systemctl show -p WorkingDirectory --value "$GATEWAY_UNIT_NAME" 2>/dev/null || true)"
[ -n "$UNIT_WORKDIR" ] \
  || refuse "$GATEWAY_UNIT_NAME has no WorkingDirectory=, so the relative 'servers/gateway/index.js' in the drop-in would resolve nowhere; nothing was changed"
UNIT_WORKDIR_REAL="$(realpath -- "$UNIT_WORKDIR" 2>/dev/null || true)"
APP_DIR_REAL="$(realpath -- "$APP_DIR" 2>/dev/null || true)"
[ -n "$UNIT_WORKDIR_REAL" ] && [ -n "$APP_DIR_REAL" ] \
  || refuse "could not resolve $GATEWAY_UNIT_NAME's WorkingDirectory ('$UNIT_WORKDIR') and this checkout ('$APP_DIR') to compare them; nothing was changed"
[ "$UNIT_WORKDIR_REAL" = "$APP_DIR_REAL" ] \
  || refuse "$GATEWAY_UNIT_NAME runs from '$UNIT_WORKDIR_REAL' but this installer is '$APP_DIR_REAL'. Run the copy that lives in the directory the gateway's own unit names, so a worktree can never repoint production. Nothing was changed."

# The same checkout, but also the right state of it: the gateway runs what is on branch
# main with no uncommitted change to a tracked file, and an installer that pins that
# checkout's node and its relative script path can only be truthful about the same code.
# Untracked files are deliberately not part of this (a build artefact, a log or a local
# notes file changes nothing about what the gateway loads), hence --untracked-files=no.
#
# WHO OWNS THIS CHECKOUT: git is never run as root here. root running git inside a
# repository that belongs to somebody else executes whatever that repository's own config
# tells it to — core.fsmonitor, a clean/smudge filter, a hook — and would run it with
# root's rights. So the owner is read once and every git call is made AS that owner; a
# checkout root owns, or one whose owner will not resolve to a numeric uid other than 0,
# is refused (exit 2, nothing changed) rather than vetted as root.
command -v git >/dev/null 2>&1 \
  || refuse "the 'git' command is missing, so this installer cannot confirm that this checkout is the gateway's own working tree and that it is a clean main; nothing was changed"
CHECKOUT_OWNER="$(stat -c %U "$APP_DIR")"
[ -n "$CHECKOUT_OWNER" ] \
  || refuse "git must never run as root on a checkout another user controls, and who owns $APP_DIR could not be read ('stat -c %U' printed nothing), so there is no owner to run it as instead. Nothing was changed."
[ "$CHECKOUT_OWNER" != "root" ] \
  || refuse "git must never run as root on a checkout another user controls, and $APP_DIR is owned by root. Nothing was changed."
CHECKOUT_OWNER_UID="$(id -u "$CHECKOUT_OWNER" 2>/dev/null || true)"
case "$CHECKOUT_OWNER_UID" in
  ''|*[!0-9]*)
    refuse "git must never run as root on a checkout another user controls, and the owner of $APP_DIR ('$CHECKOUT_OWNER') does not resolve to a numeric uid ('id -u $CHECKOUT_OWNER' printed '${CHECKOUT_OWNER_UID:-nothing}'), so git could not be run as a real, unprivileged user. Nothing was changed."
    ;;
esac
[ "$CHECKOUT_OWNER_UID" -ne 0 ] \
  || refuse "git must never run as root on a checkout another user controls, and the owner of $APP_DIR ('$CHECKOUT_OWNER') resolves to uid 0. Nothing was changed."
CHECKOUT_BRANCH="$(git_as_owner rev-parse --abbrev-ref HEAD 2>/dev/null || true)"
[ "$CHECKOUT_BRANCH" = "main" ] \
  || refuse "this checkout is not on the main branch ('rev-parse --abbrev-ref HEAD', run as $CHECKOUT_OWNER, printed '${CHECKOUT_BRANCH:-nothing}'); install from a clean checkout of main. Nothing was changed."
CHECKOUT_DIRTY="$(git_as_owner status --porcelain --untracked-files=no 2>/dev/null || true)"
[ -z "$CHECKOUT_DIRTY" ] \
  || refuse "this checkout has uncommitted changes to tracked files ('status --porcelain --untracked-files=no', run as $CHECKOUT_OWNER, printed: $(printf '%s' "$CHECKOUT_DIRTY" | tr '\n' ' ')); commit or stash them and install from a clean main. Nothing was changed."

# The instance home the listener must not be able to see. An explicit CROW_HOME
# wins; otherwise the invoking user's passwd home (the operator's, not root's)
# decides, because that is where this instance lives.
crow_home_of() {
  local home=""
  if [ -n "${CROW_HOME:-}" ]; then printf '%s\n' "${CROW_HOME%/}"; return 0; fi
  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    home="$(getent passwd "$SUDO_USER" 2>/dev/null | cut -d: -f6 || true)"
  fi
  if [ -z "$home" ]; then home="${HOME:-}"; fi
  if [ -z "$home" ]; then printf '\n'; return 0; fi
  printf '%s\n' "${home%/}/.crow"
}
CROW_HOME="$(crow_home_of)"
[ -n "$CROW_HOME" ] \
  || refuse "could not work out the instance home (no CROW_HOME, no SUDO_USER home, no HOME); set CROW_HOME to this instance's home directory and run this again"

# A value that goes into a systemd unit line must not split it or be read as a list
# separator: whitespace, ':' and '%' are all refused rather than escaped, because a
# unit line has no quoting the installer could rely on.
check_plain_value() {
  local name="$1" value="$2"
  case "$value" in
    "") refuse "$name is empty" ;;
    *[[:space:]]*) refuse "$name must not contain whitespace (a systemd unit line would split it)" ;;
    *:*|*%*) refuse "$name must not contain ':' or '%' (systemd reads ':' as a list separator and '%' as a specifier)" ;;
  esac
}
check_plain_value NODE_BIN "$NODE_BIN"
check_plain_value NODE_DIR "$NODE_DIR"
check_plain_value APP_DIR "$APP_DIR"
check_plain_value CROW_HOME "$CROW_HOME"
check_plain_value CROW_ARTIFACT_PUBLIC_BIND "$CROW_ARTIFACT_PUBLIC_BIND"

for tpl in "$SOCKET_UNIT_TEMPLATE" "$LISTENER_UNIT_TEMPLATE" "$DROP_IN_TEMPLATE"; do
  [ -f "$tpl" ] || refuse "missing template $tpl (run this from the checkout it shipped with)"
done
[ -f "$APP_DIR/scripts/artifact-public/server.mjs" ] \
  || refuse "missing $APP_DIR/scripts/artifact-public/server.mjs (run this from the checkout it shipped with)"
[ -f "$APP_DIR/servers/gateway/index.js" ] \
  || refuse "missing $APP_DIR/servers/gateway/index.js (run this from the checkout it shipped with)"

# ── 3b. An earlier run's deadman must not be left to fire under this one ────
#
# BOTH BACKUP DIRECTORIES RESTORE THE SAME THREE FILES AND THE SAME TWO UNITS, so a timer an
# earlier run armed would put back the state THAT run saw — undoing this install an hour later,
# even though the operator kept it. Stopping that timer is not this run's decision to take on the
# other run's behalf, so this run refuses instead: exit 2, nothing changed, and a message naming
# every active timer plus the backup directory holding the restore.sh it would run. For each timer
# whose script can be read it prints two commands, in this order: KEEP THAT RUN — 'sudo touch
# <dir>/keep', then 'sudo /bin/bash <dir>/restore.sh', which with keep present changes nothing and
# only retires the timer — and UNDO IT — 'sudo /bin/bash <dir>/restore.sh'. Keeping a run does not
# stand its timer down by itself: the timer stays armed, and keeps blocking a re-run, for up to its
# full cap, until that restore.sh has run with keep present. There is no lock, no marker and no
# second timer here: the active timer itself is the evidence, and this check is the whole of it.
# Nothing below this point has changed anything yet — the backup directory has not even been created.
#
# THIS REFUSAL ALSO COVERS A RESTORE THAT IS ALREADY RUNNING. A transient `--on-active` timer made
# by systemd-run lists as ACTIVE both while it waits to fire and while the service it starts is
# running, and it leaves that list only when that service exits — so a re-run during a restore (a
# by-hand one, the on_fail one, or the one the cap has just started) is refused here until the
# restore has finished. That is the intent: two restores must never work over the same host at the
# same time, and the message tells the operator which one is in the way.
DEADMAN_UNIT_PREFIX="crow-artifact-public-deadman-"

# The restore.sh a deadman runs, read out of its service's ExecStart: `systemctl show -p ExecStart`
# prints one block per command, and the script is the argument after /bin/bash there. Empty when
# that cannot be read, which is not an error — the refusal then names the backup directories it
# can see on disk instead of guessing which one belongs to which timer.
deadman_restore_script_of() { # deadman_restore_script_of <deadman unit name>
  local blob="" path=""
  blob="$(timeout "$STEP_TIMEOUT" systemctl show -p ExecStart --value "${1%.timer}.service" 2>/dev/null || true)"
  path="$(printf '%s\n' "$blob" | tr ' \t' '\n\n' \
    | grep -E '^/run/crow-artifact-public-restore\.[^/]*/restore\.sh$' | sed -n '1p' || true)"
  printf '%s\n' "$path"
}

refuse_on_active_deadman() {
  local active="" line="" name="" script="" dir=""
  local report="" dirs=""
  local -a deadman_dirs=()
  active="$(timeout "$STEP_TIMEOUT" systemctl list-units --type=timer --state=active --no-legend --plain "${DEADMAN_UNIT_PREFIX}*.timer" 2>/dev/null || true)"
  [ -n "$active" ] || return 0
  while IFS= read -r line; do
    name="${line%%[[:space:]]*}"
    case "$name" in
      "${DEADMAN_UNIT_PREFIX}"*.timer) ;;
      *) continue ;;
    esac
    script="$(deadman_restore_script_of "$name")"
    report="${report}${report:+, }$name"
    if [ -n "$script" ]; then
      dir="$(dirname -- "$script")"
      report="$report (its restore script is $script, in backup directory $dir)"
      deadman_dirs+=("$dir")
    fi
  done <<<"$active"
  [ -n "$report" ] || return 0
  for script in /run/crow-artifact-public-restore.*; do
    [ -d "$script" ] || continue
    dirs="${dirs}${dirs:+, }$script"
  done
  echo "artifact-public install: refusing: an earlier install's deadman timer is still armed: $report" >&2
  echo "artifact-public install: until that run is stood down its deadman would undo THIS install when it fires, so this run changed nothing." >&2
  # One pair per detected timer whose script is known, keep first and undo second: a keep alone
  # leaves that run's timer armed, so the keep option carries the restore that retires it too.
  if [ "${#deadman_dirs[@]}" -gt 0 ]; then
    for dir in "${deadman_dirs[@]}"; do
      echo "artifact-public install: to keep that run: sudo touch $dir/keep and then sudo /bin/bash $dir/restore.sh (with keep present, restore.sh changes nothing and only retires the timer)" >&2
      echo "artifact-public install: to undo it: sudo /bin/bash $dir/restore.sh" >&2
    done
  else
    # No timer's script could be read, so nothing maps a timer to a directory: the two commands
    # name <dir> and the directories found on disk are listed under them, for the operator to match.
    echo "artifact-public install: to keep that run: sudo touch <dir>/keep and then sudo /bin/bash <dir>/restore.sh (with keep present, restore.sh changes nothing and only retires the timer; <dir> is the matching directory listed below)" >&2
    echo "artifact-public install: to undo it: sudo /bin/bash <dir>/restore.sh" >&2
  fi
  echo "artifact-public install: the backup directories on this machine are: ${dirs:-none under /run/crow-artifact-public-restore.*} (the matching one holds restore.sh)." >&2
  exit 2
}
refuse_on_active_deadman

# The drop-in is meaningless without the unit it extends, and the health check has
# nothing to ask. (The unit itself was checked right after the root check.)

log "app dir:   $APP_DIR (the WorkingDirectory $GATEWAY_UNIT_NAME already runs in)"
log "node:      $NODE_BIN ($NODE_VERSION_RAW, prefix $NODE_DIR, the node $GATEWAY_UNIT_NAME runs)"
log "crow home: $CROW_HOME (not visible to the listener)"
log "listener:  $CROW_ARTIFACT_PUBLIC_BIND:$PUBLIC_PORT, firewall from $CROW_ARTIFACT_SIDECAR_IP on $CROW_ARTIFACT_BRIDGE_IF"

# ── 4. The backup, the undo and the deadman — before anything changes ──────
#
# THE UNDO LIVES OUTSIDE THIS PROCESS ON PURPOSE. A trap cannot run when the shell is
# killed with SIGKILL (the wall clock's own kill-after, an OOM killer, a dropped ssh
# session), and an install interrupted half way is worse than one that never ran. So
# before the first change this script:
#
#   1. makes a root-only backup directory under /run (a tmpfs: gone at the next boot,
#      which is the right lifetime for the record of one install), copies in each of the
#      three files it may change, and writes a small key=value state file holding what a
#      copy cannot carry — whether each file existed, whether the system user existed,
#      whether the exact ufw rule was already there, the enabled/active state of both units,
#      and, written at the moment each becomes true, whether THIS run created the user and
#      whether THIS run added the rule;
#   2. writes a standalone restore.sh into that directory, with those values baked in and
#      independent of this checkout;
#   3. arms ONE detached transient timer — the deadman — that runs that script through
#      /bin/bash, past this run's own wall clock, its kill-after and a margin.
#
# There is no second copy of any of it: no lock, no second timer, no marker, no run id, and no
# restoring trap. THIS SCRIPT NEVER STOPS THE DEADMAN: only restore.sh does that, and only once its
# own decision is final — kept, or fully restored (4c) — and only after this run has armed it. And
# a run refuses to start at all while an EARLIER run's deadman is still armed (section 3b), so no
# timer is ever left to undo a newer, kept install.

# mktemp -d makes it 0700; the mode is re-stated so it is a fact in this file rather than
# a convention of the tool. Nothing here assumes /var/lib, /root or anybody's home.
RESTORE_DIR="$(mktemp -d /run/crow-artifact-public-restore.XXXXXX)" \
  || { echo "artifact-public install: could not create a restore directory under /run (mktemp failed); nothing on this machine was changed" >&2; exit 1; }
chmod 0700 "$RESTORE_DIR" \
  || { echo "artifact-public install: could not restrict $RESTORE_DIR to root (chmod 0700 failed); nothing on this machine was changed" >&2; exit 1; }
RESTORE_SCRIPT="$RESTORE_DIR/restore.sh"
RESTORE_STATE="$RESTORE_DIR/state"
RESTORE_SNAPSHOT="$RESTORE_DIR/snapshot"
# Where the rendered units are written before they are installed: inside the backup directory, so
# a half-written unit can never sit in /etc/systemd/system.
RESTORE_STAGE="$RESTORE_DIR/staged"
# THE ONE FILE ONLY A HUMAN TOUCHES. restore.sh looks for it before its first step and, when it
# is there, changes nothing at all. This installer WRITES IT, READS IT AND REMOVES IT NEVER:
# on success it prints the command that creates it and exits (section 11), because keeping an
# install is a decision taken by somebody who has read the checks, not by the script that made
# the changes.
RESTORE_KEEP="$RESTORE_DIR/keep"
mkdir -p "$RESTORE_SNAPSHOT" "$RESTORE_STAGE" \
  || { echo "artifact-public install: could not create $RESTORE_SNAPSHOT and $RESTORE_STAGE; nothing on this machine was changed" >&2; exit 1; }

# A failure in this window happens before anything on the host has changed, so there is
# nothing to restore — but the half-written directory is removed and the message says so.
# Only used BEFORE the deadman is armed: after that a failure goes through `fail` and the
# on_fail handler, which starts the undo (the deadman's own service), names the step, prints the
# manual restore command and the deadman's fire time, and exits non-zero.
abort_clean() { # abort_clean <message>
  rm -rf -- "$RESTORE_DIR" 2>/dev/null
  echo "artifact-public install: $*" >&2
  exit 1
}

# A deadman that cannot be armed is not "carry on without an undo": it is a REFUSAL (exit 2) with
# the half-written backup directory removed. Nothing on this machine has changed at that point, so
# there is nothing to undo — and an install with no out-of-process undo must not start at all.
abort_unarmed() { # abort_unarmed <message>
  rm -rf -- "$RESTORE_DIR" 2>/dev/null
  echo "artifact-public install: refusing: $*" >&2
  exit 2
}

# THIS RUN'S OWN NAME, for the deadman's transient unit only: a timestamp read once (so two
# runs never share one), plus this shell's pid (two runs within the same second still differ).
# The name is settled HERE, before restore.sh is generated, because that script has to change its
# own timer's state and therefore carries the name baked in (4c). Nothing else is named after it —
# no installed file carries it — and restore.sh itself is valid for any run, because it is safe to
# re-run.
DEADMAN_DATE_STAMP="$(date +%Y%m%d%H%M%S)"
[ -n "$DEADMAN_DATE_STAMP" ] \
  || abort_clean "could not read this run's own timestamp ('date +%Y%m%d%H%M%S' printed nothing), and the deadman's unit name is built from it; nothing on this machine was changed"
DEADMAN_STAMP="${DEADMAN_DATE_STAMP}-$$"
DEADMAN_UNIT_NAME="$DEADMAN_UNIT_PREFIX$DEADMAN_STAMP"
DEADMAN_TIMER="$DEADMAN_UNIT_NAME.timer"
# Whether THIS run's deadman is actually armed. on_fail starts that unit's service when a step
# fails, and it must never try to start a unit that was never created: a failure BEFORE the arm is
# an abort_clean/abort_unarmed, not a failure inside the run, so nothing is started there.
DEADMAN_ARMED=0

# The state file: one NAME=value line per fact the restore script cannot read back from
# the snapshot. Rewritten through a temp file and a rename, so a reader never sees half a
# line, and updated at the moment each fact becomes true — not at the end of the run,
# which a killed run never reaches.
: > "$RESTORE_STATE" || abort_clean "could not create $RESTORE_STATE; nothing on this machine was changed"
chmod 0600 "$RESTORE_STATE" || abort_clean "could not restrict $RESTORE_STATE to root; nothing on this machine was changed"
state_set() { # state_set <NAME> <value>
  local name="$1" value="$2" tmp="$RESTORE_STATE.new"
  { grep -v "^${name}=" "$RESTORE_STATE" 2>/dev/null || true; printf '%s=%s\n' "$name" "$value"; } > "$tmp" \
    || return 1
  mv -f "$tmp" "$RESTORE_STATE" || return 1
  chmod 0600 "$RESTORE_STATE" || return 1
}

# --- 4a. What was here before this run --------------------------------------
#
# Each file is recorded one of two ways: present, with a copy beside it, or absent (no
# copy — the restore script removes whatever it finds at that path). `cp -a` keeps the
# mode and owner of a unit file that was already installed.
snapshot_file() { # snapshot_file <target> <state flag>
  local target="$1" flag="$2"
  if [ -f "$target" ]; then
    cp -a -- "$target" "$RESTORE_SNAPSHOT/$(basename -- "$target")" \
      && state_set "$flag" 1
  else
    state_set "$flag" 0
  fi
}
snapshot_file "$LISTENER_UNIT_DEST" LISTENER_UNIT_PRESENT \
  || abort_clean "could not snapshot $LISTENER_UNIT_DEST into $RESTORE_DIR; nothing on this machine was changed"
snapshot_file "$SOCKET_UNIT_DEST" SOCKET_UNIT_PRESENT \
  || abort_clean "could not snapshot $SOCKET_UNIT_DEST into $RESTORE_DIR; nothing on this machine was changed"
snapshot_file "$DROP_IN_DEST" DROP_IN_PRESENT \
  || abort_clean "could not snapshot $DROP_IN_DEST into $RESTORE_DIR; nothing on this machine was changed"
if [ -d "$DROP_IN_DIR" ]; then
  state_set DROP_IN_DIR_PRESENT 1 \
    || abort_clean "could not record that $DROP_IN_DIR existed in $RESTORE_STATE; nothing on this machine was changed"
else
  state_set DROP_IN_DIR_PRESENT 0 \
    || abort_clean "could not record that $DROP_IN_DIR did not exist in $RESTORE_STATE; nothing on this machine was changed"
fi
state_set DROP_IN_DIR_CREATED 0 \
  || abort_clean "could not initialise $RESTORE_STATE; nothing on this machine was changed"
if id "$PUBLIC_USER" >/dev/null 2>&1; then
  state_set USER_EXISTED 1 \
    || abort_clean "could not record that $PUBLIC_USER existed in $RESTORE_STATE; nothing on this machine was changed"
else
  state_set USER_EXISTED 0 \
    || abort_clean "could not record that $PUBLIC_USER did not exist in $RESTORE_STATE; nothing on this machine was changed"
fi
state_set USER_CREATED 0 \
  || abort_clean "could not initialise $RESTORE_STATE; nothing on this machine was changed"
state_set UFW_RULE_ADDED 0 \
  || abort_clean "could not initialise $RESTORE_STATE; nothing on this machine was changed"
# Whether this run installed a file the gateway reads. It is written as 1 BEFORE either file
# goes in (section 7), so a run killed between the install and the restart still leaves an
# undo that restarts the gateway it half changed — and an undo that never touched the gateway
# leaves it alone.
state_set GATEWAY_TOUCHED 0 \
  || abort_clean "could not initialise $RESTORE_STATE; nothing on this machine was changed"

# What state the units were in BEFORE this run touched them, so a re-run's undo puts
# back "enabled and running" rather than only the file contents. `is-enabled` and
# `is-active` both report something for a unit systemd does not know, so "not-found",
# "unknown" and an error are all recorded as absent (empty) rather than as a state.
unit_state() { # unit_state <unit> <enabled|active>
  local unit="$1" what="$2" value=""
  case "$what" in
    enabled) value="$(timeout "$STEP_TIMEOUT" systemctl is-enabled "$unit" 2>/dev/null || true)" ;;
    active) value="$(timeout "$STEP_TIMEOUT" systemctl is-active "$unit" 2>/dev/null || true)" ;;
    *) return 1 ;;
  esac
  case "$value" in
    ""|not-found|unknown|error) printf '\n' ;;
    *) printf '%s\n' "$value" ;;
  esac
}
PREV_SOCKET_ENABLED="$(unit_state "$SOCKET_UNIT_NAME" enabled)"
PREV_SOCKET_ACTIVE="$(unit_state "$SOCKET_UNIT_NAME" active)"
PREV_LISTENER_ENABLED="$(unit_state "$LISTENER_UNIT_NAME" enabled)"
PREV_LISTENER_ACTIVE="$(unit_state "$LISTENER_UNIT_NAME" active)"
state_set PREV_SOCKET_ENABLED "$PREV_SOCKET_ENABLED" \
  || abort_clean "could not record the socket unit's previous state in $RESTORE_STATE; nothing on this machine was changed"
state_set PREV_SOCKET_ACTIVE "$PREV_SOCKET_ACTIVE" \
  || abort_clean "could not record the socket unit's previous state in $RESTORE_STATE; nothing on this machine was changed"
state_set PREV_LISTENER_ENABLED "$PREV_LISTENER_ENABLED" \
  || abort_clean "could not record the listener's previous state in $RESTORE_STATE; nothing on this machine was changed"
state_set PREV_LISTENER_ACTIVE "$PREV_LISTENER_ACTIVE" \
  || abort_clean "could not record the listener's previous state in $RESTORE_STATE; nothing on this machine was changed"

# --- 4b. The firewall rule: was the exact one already there? ----------------
#
# Read here, before the first change, because the undo has to know whether THIS run is
# the one that must delete the rule. The words are written once, so the text compared
# against `ufw show added` is the very text `ufw allow` is given further down: no rule
# can be "already there" by resemblance alone, and a rule for another source, another
# interface or another port is never mistaken for this one.
UFW_ACTIVE=0
UFW_STATUS=""
# EVERY ufw CALL IN THIS FILE RUNS UNDER LC_ALL=C, and this is why: both words this script reads
# back from ufw — "Status: active" here and "Rule added" in section 8 — are matched as English
# text, and a ufw that answers in the host's own language would make the first read say the
# firewall is off and the second say no rule was added. The locale is set on the call itself
# (not exported), so nothing else in this run is affected by it.
if command -v ufw >/dev/null 2>&1; then
  UFW_STATUS="$(LC_ALL=C timeout "$STEP_TIMEOUT" ufw status 2>/dev/null || true)"
  case "$UFW_STATUS" in
    *"Status: active"*) UFW_ACTIVE=1 ;;
  esac
fi
UFW_RULE=(allow in on "$CROW_ARTIFACT_BRIDGE_IF" from "$CROW_ARTIFACT_SIDECAR_IP" \
  to "$CROW_ARTIFACT_PUBLIC_BIND" port "$PUBLIC_PORT" proto tcp)
UFW_EXPECTED="ufw ${UFW_RULE[*]}"
UFW_RULE_EXISTED=0
if [ "$UFW_ACTIVE" -eq 1 ]; then
  UFW_ADDED_TEXT="$(LC_ALL=C timeout "$STEP_TIMEOUT" ufw show added 2>/dev/null || true)"
  while IFS= read -r line; do
    if [ "$line" = "$UFW_EXPECTED" ]; then
      UFW_RULE_EXISTED=1
      break
    fi
  done <<<"$UFW_ADDED_TEXT"
fi
state_set UFW_RULE_EXISTED "$UFW_RULE_EXISTED" \
  || abort_clean "could not record whether the ufw rule already existed in $RESTORE_STATE; nothing on this machine was changed"

# --- 4c. The script that undoes this run, with the values baked in ---------
#
# A quoted heredoc: nothing in the body is expanded here, so every path it uses is either
# baked in above with %q quoting or read from the state file at run time. That is what
# makes it usable with this checkout deleted and with nobody at the keyboard.
#
# THE DESTINATION PATHS ARE BAKED IN FROM THIS FILE'S OWN VARIABLES (LISTENER_UNIT_DEST,
# SOCKET_UNIT_DEST, DROP_IN_DIR, DROP_IN_DEST), so the same generator renders the script that
# restores /etc/systemd/system and — in the test suite — one pointed at a temp directory. In
# the real run they are the real paths and nothing else is substituted.
{
  printf '%s\n' '#!/usr/bin/env bash'
  printf '%s\n' '#'
  printf '%s\n' '# Written by the Crow artifact-public installer before it changed anything.'
  printf '%s\n' '# Standalone on purpose: it reads no checkout, asks for no password and needs'
  printf '%s\n' '# nothing but the values baked in below and the backup beside it.'
  printf '%s\n' '#'
  printf '%s\n' '# It changes NOTHING when <backup dir>/keep exists: that file is the operator saying this'
  printf '%s\n' '# install was wanted, and it is checked once, before the first undo step — so a keep touched'
  printf '%s\n' '# after this script has started changes nothing. Otherwise it re-does every undo step, and'
  printf '%s\n' '# every step is a no-op the second time it runs, so running it twice is safe. Running it BY'
  printf '%s\n' '# HAND is safe only once the installer that wrote it has exited: while that install is still'
  printf '%s\n' '# running, the two would be changing the same files at the same time.'
  printf '%s\n' '# It keeps no done/ran/lock/marker file of any kind.'
  printf '%s\n' '#'
  printf 'RESTORE_DIR=%q\n' "$RESTORE_DIR"
  printf 'LISTENER_UNIT=%q\n' "$LISTENER_UNIT_NAME"
  printf 'SOCKET_UNIT=%q\n' "$SOCKET_UNIT_NAME"
  printf 'GATEWAY_UNIT=%q\n' "$GATEWAY_UNIT_NAME"
  printf 'LISTENER_UNIT_DEST=%q\n' "$LISTENER_UNIT_DEST"
  printf 'SOCKET_UNIT_DEST=%q\n' "$SOCKET_UNIT_DEST"
  printf 'DROP_IN_DIR=%q\n' "$DROP_IN_DIR"
  printf 'DROP_IN_DEST=%q\n' "$DROP_IN_DEST"
  printf 'PUBLIC_USER=%q\n' "$PUBLIC_USER"
  printf 'BRIDGE_IF=%q\n' "$CROW_ARTIFACT_BRIDGE_IF"
  printf 'SIDECAR_IP=%q\n' "$CROW_ARTIFACT_SIDECAR_IP"
  printf 'BIND_ADDR=%q\n' "$CROW_ARTIFACT_PUBLIC_BIND"
  printf 'PUBLIC_PORT=%q\n' "$PUBLIC_PORT"
  printf 'GATEWAY_HEALTH_URL=%q\n' "$GATEWAY_HEALTH_URL"
  printf 'DEADMAN_TIMER=%q\n' "$DEADMAN_TIMER"
  printf '%s\n' 'STEP_TIMEOUT=60'
  cat <<'RESTORE_BODY'
set -uo pipefail

# Everything this script needs is either baked in above or in the state file beside it.
RESTORE_STATE="$RESTORE_DIR/state"
RESTORE_KEEP="$RESTORE_DIR/keep"
SNAPSHOT="$RESTORE_DIR/snapshot"

# This script's own bounds: every step below is one `timeout "$STEP_TIMEOUT"`, and both bounded
# waits have a fixed number of tries, so its whole worst case is bounded even when the deadman is
# what runs it — there is no install process alive to pass a budget down.
INVOCATION_WAIT=180
HEALTH_TRIES=30
HEALTH_SLEEP=5

say() {
  logger -t crow-artifact-public-restore "$*" 2>/dev/null || true
  printf 'crow-artifact-public-restore: %s\n' "$*" >&2
}

# The last value recorded for a fact, or nothing. The state file is READ, never sourced.
state_get() {
  local name="$1"
  [ -f "$RESTORE_STATE" ] || return 0
  sed -n "s/^${name}=//p" "$RESTORE_STATE" 2>/dev/null | tail -n 1
}

# NO ARMED TIMER MAY OUTLIVE THE RUN THAT SET IT, whichever way this run was started: early
# (the installer's on_fail starts the deadman's service), at the cap (the timer itself fired), or
# by hand. So once this script's decision is final — after a COMPLETE restore, on the keep path,
# and on the unhealthy exit at the end — BOTH units named in the deadman are cleared here:
#
#   * THE TIMER IS STOPPED AND THEN RESET. `stop` is what keeps an armed deadman from firing a
#     second time over a host that is already settled. `reset-failed` is what takes it out of the
#     unit list: a transient timer made by systemd-run has no [Install] section, so it cannot be
#     disabled — `stop` is the only thing that makes it not fire, and a fired transient unit
#     otherwise stays listed as failed.
#   * THE SERVICE IS ONLY RESET-FAILED, NEVER STOPPED: when the deadman fired, this very script
#     runs INSIDE that unit, so stopping it would kill this run half way.
#
# Each of the three calls is one `timeout "$STEP_TIMEOUT"`, and each FAILURE IS LOGGED and nothing
# else: the host is already back, or already accepted, and housekeeping that did not happen is
# not a reason to report a failed restore. The whole thing is a harmless no-op when this script IS
# the process that timer started (a fired --on-active timer has nothing left to do, and clearing
# the unit we are running inside is still the right thing to do).
stop_own_timer() {
  [ -n "${DEADMAN_TIMER:-}" ] || return 0
  local unit="${DEADMAN_TIMER%.timer}"
  if timeout "$STEP_TIMEOUT" systemctl stop "$DEADMAN_TIMER" >/dev/null 2>&1; then
    say "stopped $DEADMAN_TIMER: it cannot fire again"
  else
    say "could not stop $DEADMAN_TIMER (logged, not fatal: what this run did is already settled)"
  fi
  if timeout "$STEP_TIMEOUT" systemctl reset-failed "$DEADMAN_TIMER" >/dev/null 2>&1; then
    say "reset-failed $DEADMAN_TIMER: it is gone from the unit list"
  else
    say "could not reset-failed $DEADMAN_TIMER (logged, not fatal: what this run did is already settled)"
  fi
  if timeout "$STEP_TIMEOUT" systemctl reset-failed "$unit.service" >/dev/null 2>&1; then
    say "reset-failed $unit.service: it is gone from the unit list too"
  else
    say "could not reset-failed $unit.service (logged, not fatal: this run may be running inside it)"
  fi
  return 0
}

# THE OPERATOR'S DECISION COMES FIRST, AND IT IS THE ONLY EARLY EXIT. A `keep` file means a
# human read the install's checks and accepted it, so nothing is undone and nothing at all is
# changed. It is read here, on every run, and never cached anywhere — which is why a keep file
# touched after this script has already started changes nothing.
if [ -f "$RESTORE_KEEP" ]; then
  say "kept: $RESTORE_KEEP exists, so this install was accepted by the operator and nothing is undone"
  stop_own_timer
  exit 0
fi
say "no $RESTORE_KEEP, so this host is put back the way it was before the install"

# The gateway's /health, bounded: at most HEALTH_TRIES tries, HEALTH_SLEEP s apart, each
# request capped. An undo that leaves no working gateway has to say so where an operator
# will look.
check_gateway() {
  local code="" i
  for (( i = 0; i < HEALTH_TRIES; i++ )); do
    code="$(timeout 10 curl -s -o /dev/null -w '%{http_code}' --max-time 5 --noproxy '*' "$GATEWAY_HEALTH_URL" 2>/dev/null || true)"
    if [ "$code" = "200" ]; then
      say "the gateway answered 200 at $GATEWAY_HEALTH_URL after the restore"
      return 0
    fi
    timeout 10 sleep "$HEALTH_SLEEP"
  done
  say "ATTENTION: $GATEWAY_UNIT did NOT answer 200 at $GATEWAY_HEALTH_URL after the restore (last answer: '${code:-nothing}', $i tries). This machine may have NO working gateway right now: check 'systemctl status $GATEWAY_UNIT' and 'journalctl -u $GATEWAY_UNIT -n 100' before doing anything else."
  return 1
}

# A gateway restart is ASKED FOR and then WAITED FOR by a DIFFERENT, active process. /health
# alone cannot say that: the old process can answer 200 for a moment before it dies. So the
# InvocationID is recorded before the restart and this waits, bounded, until it differs and
# systemd calls the unit active — the same trick install.sh itself uses, for the same reason.
wait_for_new_invocation() { # wait_for_new_invocation <the InvocationID read before the restart>
  local old="${1:-}" deadline=$(( SECONDS + INVOCATION_WAIT )) now="" state=""
  while [ "$SECONDS" -lt "$deadline" ]; do
    now="$(timeout 10 systemctl show -p InvocationID --value "$GATEWAY_UNIT" 2>/dev/null || true)"
    state="$(timeout 10 systemctl is-active "$GATEWAY_UNIT" 2>/dev/null || true)"
    if [ -n "$now" ] && [ "$now" != "$old" ] && [ "$state" = "active" ]; then
      say "$GATEWAY_UNIT came back as a NEW, active invocation (${now})"
      return 0
    fi
    timeout 10 sleep 5
  done
  say "ATTENTION: $GATEWAY_UNIT did not come back as a new, active process within ${INVOCATION_WAIT}s of the restore's restart (InvocationID '${now:-nothing}', state '${state:-nothing}', against the pre-restart '${old:-nothing}'). Its /health may still be the OLD process's answer: check 'systemctl status $GATEWAY_UNIT' and 'journalctl -u $GATEWAY_UNIT -n 100'."
  return 1
}

# NOTHING ENDS THIS SCRIPT EARLY EXCEPT THE KEEP FILE, checked above. There is no lock to take,
# no marker to honour and no run id to compare, because the keep file answers the only question
# that mattered — was this install wanted? — and every step below is simply re-run on every run,
# each one a no-op the second time.
say "putting this host back: every undo step is (re-)run, and each is a no-op when it is already done"

# Stop and disable both units FIRST, while their files are still in place: disabling a unit whose
# file is already gone leaves its enablement symlink behind. Their previous state is re-applied
# further down, once the files are back and a daemon-reload has run.
for unit in "$LISTENER_UNIT" "$SOCKET_UNIT"; do
  timeout "$STEP_TIMEOUT" systemctl stop "$unit" >/dev/null 2>&1 && say "stopped $unit"
  timeout "$STEP_TIMEOUT" systemctl disable "$unit" >/dev/null 2>&1 && say "disabled $unit"
done

restore_one() { # restore_one <PRESENT flag> <target>
  local flag="$1" target="$2" snap=""
  snap="$SNAPSHOT/$(basename -- "$target")"
  if [ "$(state_get "$flag")" = "1" ] && [ -f "$snap" ]; then
    timeout "$STEP_TIMEOUT" install -m 0644 -- "$snap" "$target" && say "restored $target from $snap"
  elif [ -f "$target" ]; then
    timeout "$STEP_TIMEOUT" rm -f -- "$target" && say "removed $target (it did not exist before this install)"
  else
    say "$target is absent, as it was before this install"
  fi
}
restore_one LISTENER_UNIT_PRESENT "$LISTENER_UNIT_DEST"
restore_one SOCKET_UNIT_PRESENT "$SOCKET_UNIT_DEST"
restore_one DROP_IN_PRESENT "$DROP_IN_DEST"
# The drop-in's directory goes ONLY when this run created it, so a directory that was already
# there keeps whatever else lives in it (and rmdir refuses a directory that is not empty anyway).
if [ "$(state_get DROP_IN_DIR_CREATED)" = "1" ]; then
  timeout "$STEP_TIMEOUT" rmdir -- "$DROP_IN_DIR" 2>/dev/null && say "removed $DROP_IN_DIR (this install created it)"
fi

# Only what THIS install created is removed, and the state file is what says so. The value can be
# `pending` as well as `1`: the installer records `pending` BEFORE it runs `useradd` / `ufw allow`
# and confirms with `1` (or back to `0`) after, so a run killed between the command and its
# confirmation still leaves an undo that knows what to look for. `pending` is treated exactly like
# `1`, WITH ONE EXTRA STEP: the thing itself is checked before it is removed — `id <user>` for the
# user, an exact line in `ufw show added` for the rule — because a pending marker only says the
# command was started, not that it did anything. Something that is not there is not removed, and
# removing something this run did not create is the one thing this undo must never do.
ufw_rule_is_present() {
  local line="" text=""
  text="$(LC_ALL=C timeout "$STEP_TIMEOUT" ufw show added 2>/dev/null || true)"
  while IFS= read -r line; do
    if [ "$line" = "ufw allow in on $BRIDGE_IF from $SIDECAR_IP to $BIND_ADDR port $PUBLIC_PORT proto tcp" ]; then
      return 0
    fi
  done <<<"$text"
  return 1
}

# The ufw call runs under LC_ALL=C like every other ufw call in this project, so the rule it deletes
# is the same rule the install added, whatever language the host answers in.
case "$(state_get UFW_RULE_ADDED)" in
  1|pending)
    if ufw_rule_is_present; then
      LC_ALL=C timeout "$STEP_TIMEOUT" ufw delete allow in on "$BRIDGE_IF" from "$SIDECAR_IP" to "$BIND_ADDR" port "$PUBLIC_PORT" proto tcp >/dev/null 2>&1 \
        && say "deleted the one ufw rule this install added"
    else
      say "the ufw rule this install was adding is not in 'ufw show added', so there is nothing to delete"
    fi
    ;;
  *)
    say "no ufw rule is deleted: this install did not add one"
    ;;
esac
case "$(state_get USER_CREATED)" in
  1|pending)
    if id "$PUBLIC_USER" >/dev/null 2>&1; then
      timeout "$STEP_TIMEOUT" userdel "$PUBLIC_USER" >/dev/null 2>&1 \
        && say "deleted the $PUBLIC_USER system user this install created"
    else
      say "the $PUBLIC_USER system user is not there, so there is nothing to delete"
    fi
    ;;
  *)
    say "the $PUBLIC_USER system user is left alone: this install did not create it"
    ;;
esac

timeout "$STEP_TIMEOUT" systemctl reset-failed "$LISTENER_UNIT" "$SOCKET_UNIT" >/dev/null 2>&1
timeout "$STEP_TIMEOUT" systemctl daemon-reload >/dev/null 2>&1 && say "ran systemctl daemon-reload"

# The files alone are not the previous state: a re-run over a working install must leave both
# units as it found them. A unit that did not exist before this install stays stopped and disabled
# (which is what the stop/disable at the top left it as); a unit that did gets its own state back.
restore_unit_state() { # restore_unit_state <unit> <PRESENT flag> <enabled key> <active key>
  local unit="$1" flag="$2" was_enabled="" was_active=""
  if [ "$(state_get "$flag")" != "1" ]; then
    timeout "$STEP_TIMEOUT" systemctl stop "$unit" >/dev/null 2>&1
    timeout "$STEP_TIMEOUT" systemctl disable "$unit" >/dev/null 2>&1
    say "$unit did not exist before this install, so it stays stopped and disabled"
    return 0
  fi
  was_enabled="$(state_get "$3")"
  was_active="$(state_get "$4")"
  case "$was_enabled" in
    enabled|enabled-runtime) timeout "$STEP_TIMEOUT" systemctl enable "$unit" >/dev/null 2>&1 && say "$unit is enabled again, as it was" ;;
    *) timeout "$STEP_TIMEOUT" systemctl disable "$unit" >/dev/null 2>&1 && say "$unit is disabled again, as it was" ;;
  esac
  case "$was_active" in
    active|activating|reloading) timeout "$STEP_TIMEOUT" systemctl start "$unit" >/dev/null 2>&1 && say "$unit is running again, as it was" ;;
    *) timeout "$STEP_TIMEOUT" systemctl stop "$unit" >/dev/null 2>&1 && say "$unit is stopped again, as it was" ;;
  esac
  return 0
}
restore_unit_state "$SOCKET_UNIT" SOCKET_UNIT_PRESENT PREV_SOCKET_ENABLED PREV_SOCKET_ACTIVE
restore_unit_state "$LISTENER_UNIT" LISTENER_UNIT_PRESENT PREV_LISTENER_ENABLED PREV_LISTENER_ACTIVE

# The drop-in is gone, so the gateway has to restart to drop the fd it was handed — but ONLY
# when this run installed a file the gateway reads. install.sh records GATEWAY_TOUCHED in the
# state file BEFORE it installs the drop-in or the socket unit, so that flag is the record of what
# actually reached /etc, not a guess; a restart nobody needed would bounce a gateway this undo
# never changed. The restart, the InvocationID wait and the /health poll are all SKIPPED when the
# flag says the gateway was never touched. Non-blocking for the same reason the installer uses it:
# the unit allows a long TimeoutStartSec, and the InvocationID wait below is what does the waiting.
if [ "$(state_get GATEWAY_TOUCHED)" = "1" ]; then
  # The OLD process can answer /health 200 for a moment before it dies, so its InvocationID is
  # recorded FIRST and a different, active one is what everything below waits on.
  GATEWAY_INVOCATION_ID="$(timeout "$STEP_TIMEOUT" systemctl show -p InvocationID --value "$GATEWAY_UNIT" 2>/dev/null || true)"
  say "restarting $GATEWAY_UNIT so it drops the door fd it was handed"
  timeout "$STEP_TIMEOUT" systemctl restart --no-block "$GATEWAY_UNIT" >/dev/null 2>&1 \
    && say "asked $GATEWAY_UNIT to restart (non-blocking)"
  if [ -n "$GATEWAY_INVOCATION_ID" ]; then
    wait_for_new_invocation "$GATEWAY_INVOCATION_ID" \
      || say "ATTENTION: the /health answer below is still checked, but it may yet be the OLD process's"
  else
    say "ATTENTION: could not read $GATEWAY_UNIT's InvocationID before the restart, so a new process cannot be told apart from the old one; the /health answer below may be the old process's"
  fi
else
  say "not restarting $GATEWAY_UNIT: this install installed neither $DROP_IN_DEST nor $SOCKET_UNIT_DEST, so there is no fd for a restart to drop"
  say "restore complete: the listener, its socket, the gateway drop-in, the firewall rule and the system user are back the way they were"
  stop_own_timer
  exit 0
fi

if check_gateway; then
  say "restore complete: the listener, its socket, the gateway drop-in, the firewall rule and the system user are back the way they were"
  stop_own_timer
  exit 0
fi
# Its decision is final even when the outcome is bad, so the timer goes too: one that outlived
# this run would fire again over the same host, and there is nothing left for it to do.
stop_own_timer
say "ATTENTION: the restore finished with the gateway UNHEALTHY. This machine may have no working gateway right now: run 'systemctl status $GATEWAY_UNIT' and 'journalctl -u $GATEWAY_UNIT -n 100' before doing anything else. Re-running this script changes nothing that is already back, and the backup stays at $RESTORE_DIR"
exit 1
RESTORE_BODY
} > "$RESTORE_SCRIPT" \
  || abort_clean "could not write $RESTORE_SCRIPT; nothing on this machine was changed"
chmod 0700 "$RESTORE_SCRIPT" \
  || abort_clean "could not restrict $RESTORE_SCRIPT to root (chmod 0700 failed); nothing on this machine was changed"

# --- 4d. The deadman: the one undo if this process dies --------------------
#
# A transient timer of PID 1, not a child of this script: nothing this script does (including
# dying) can cancel it, and THIS SCRIPT never stops it — not on success either, because a finished
# install is only "kept" when a human says so (section 11). The only thing that stops it is
# restore.sh itself, once its own decision is final (kept, or fully restored), which it can do
# because the name settled in section 4 is baked into it. A refusal here happens before anything
# on this machine has changed, so there is nothing to undo yet.
#
# THE UNIT RUNS THE SCRIPT THROUGH /bin/bash, NEVER AS A BARE COMMAND. /run is mounted noexec on
# the target box, so `systemd-run ... "$RESTORE_SCRIPT"` would fail to exec it (status 203/EXEC)
# and the undo would never run at all — exactly in the case the deadman exists for. The absolute
# interpreter path is first and the script path is its argument, and this is the ONLY place this
# installer starts that script.
#
# ONE TIMER, ONE CAP, AND THE CAP OUTLIVES THIS RUN: DEADMAN_AFTER is the install's whole worst
# case plus the wall clock's margin, the kill-after and DEADMAN_MARGIN (the arithmetic is beside
# STEP_TIMEOUT), so the timer cannot fire while the process that armed it is still alive to finish
# or to fail loudly. The unit name carries a timestamp and this shell's pid, so two runs — even
# two in the same second — never collide. The name itself was settled in section 4, before
# restore.sh was generated, because that script stops this very timer and carries the name baked in.
# The fire time is read at arming and kept, so the failure path and the success output can both
# state it exactly: the epoch (for anything machine-readable) and local time (for a human).
DEADMAN_ARMED_AT="$(date +%s 2>/dev/null || true)"
case "$DEADMAN_ARMED_AT" in
  ''|*[!0-9]*)
    abort_unarmed "could not read the current time ('date +%s' printed '${DEADMAN_ARMED_AT:-nothing}'), so the deadman's fire time could not be reported to the operator; nothing on this machine was changed"
    ;;
esac
DEADMAN_FIRE_AT=$(( DEADMAN_ARMED_AT + DEADMAN_AFTER ))
deadman_fire_time_human() {
  date -d "@$DEADMAN_FIRE_AT" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null || printf 'epoch %s' "$DEADMAN_FIRE_AT"
}
# How much of the keep window is LEFT, in whole minutes, read from the same wall clock `date +%s`
# the fire epoch was built from — so the success line tells the operator the real remaining time
# rather than the cap this run started with. Never negative: a fire time already behind us reads 0.
deadman_remaining_minutes() {
  local now="" left=0
  now="$(date +%s 2>/dev/null || true)"
  case "$now" in
    ''|*[!0-9]*) printf 'an unreadable number of' ; return 0 ;;
  esac
  left=$(( DEADMAN_FIRE_AT - now ))
  if [ "$left" -lt 0 ]; then left=0; fi
  printf '%s' $(( left / 60 ))
}

command -v systemd-run >/dev/null 2>&1 \
  || abort_unarmed "the 'systemd-run' command is missing, so the undo that has to survive this process's death cannot be armed; nothing on this machine was changed"
if ! timeout "$STEP_TIMEOUT" systemd-run --on-active="${DEADMAN_AFTER}s" --unit="$DEADMAN_UNIT_NAME" --collect /bin/bash "$RESTORE_SCRIPT" >/dev/null 2>&1; then
  abort_unarmed "could not arm the deadman timer ($DEADMAN_TIMER, 'systemd-run --on-active=${DEADMAN_AFTER}s'), so an install killed half way would never be undone; nothing on this machine was changed"
fi
# THE UNDO NOW EXISTS, so a failure below may start it. Set only after systemd accepted the arm:
# on_fail must never ask systemd to start a unit that was never created.
DEADMAN_ARMED=1
log "armed the deadman: $DEADMAN_TIMER runs /bin/bash $RESTORE_SCRIPT (never the script alone: /run is noexec here) in ${DEADMAN_AFTER}s — at $(deadman_fire_time_human), epoch $DEADMAN_FIRE_AT — unless the operator keeps this install first"

# ── 4e. What this installer does when a step fails ────────────────────────
#
# A FAILURE IS REPORTED AND THE UNDO IS STARTED AT ONCE, and the undo that starts is still
# restore.sh's alone: this handler asks systemd to start the DEADMAN'S OWN SERVICE
# (`systemctl start --no-block <deadman unit>.service`), which runs the very script the timer would
# have run. So production is not left broken until the timer would have fired, and there is still
# exactly one description of "back the way it was" — no in-process undo, no second copy, and this
# process can never half-restore a host while a unit is restoring the other half. That one
# systemctl call is the ONLY command this handler runs: it stops no unit, deletes no rule and
# removes no user. It names the failing step, says the undo has started, prints the exact restore
# command and when the deadman's timer would have fired, and exits non-zero. TERM (the wall clock)
# and INT (Ctrl-C) run it too, because either of those on its own leaves the host half applied; the
# only difference is that the step is then named by the signal rather than by `fail`. If the
# deadman was never armed, nothing is started and the handler says so.
on_fail() { # on_fail <exit code>
  local rc="${1:-1}"
  set +e
  trap - ERR TERM INT
  if [ -n "$FAILED_STEP" ]; then
    echo "artifact-public install: FAILED at: $FAILED_STEP" >&2
  else
    echo "artifact-public install: FAILED (exit $rc) at the step above." >&2
  fi
  echo "artifact-public install: nothing further is tried by this process, and this process never undoes anything itself: the undo is restore.sh, as always." >&2
  if [ "${DEADMAN_ARMED:-0}" = "1" ]; then
    echo "artifact-public install: the undo has been STARTED now, as the deadman's own service $DEADMAN_UNIT_NAME.service (the same restore.sh the timer runs):" >&2
    if timeout "$STEP_TIMEOUT" systemctl start --no-block "$DEADMAN_UNIT_NAME.service" >/dev/null 2>&1; then
      echo "artifact-public install:   systemctl start --no-block $DEADMAN_UNIT_NAME.service — accepted, so this host is already being put back" >&2
    else
      echo "artifact-public install:   systemctl start --no-block $DEADMAN_UNIT_NAME.service — systemd did not accept it, so start the undo with the command below" >&2
    fi
    echo "artifact-public install: otherwise the deadman $DEADMAN_TIMER would have fired at $(deadman_fire_time_human) (epoch $DEADMAN_FIRE_AT) and put this host back unless the install was kept first." >&2
  else
    echo "artifact-public install: no deadman was armed yet, so no undo was started and this host is as it was before this run." >&2
  fi
  echo "artifact-public install: to put it back NOW, by hand, run exactly:" >&2
  echo "artifact-public install:   sudo /bin/bash $RESTORE_SCRIPT" >&2
  exit "$rc"
}

# From here on, a failure anywhere reaches on_fail. -E (errtrace) is what makes the ERR trap fire
# for a command that fails INSIDE a function — render_template's sed, a state_set, a systemctl
# inside wait_for_new_gateway_invocation — and not only for a top-level one. All three traps print
# the same guidance, which is why a run that fails and a run that is interrupted are repaired the
# same way — and why the deadman exists for the one case none of them can run (SIGKILL).
trap 'on_fail "$?"' ERR
trap 'on_fail 143' TERM
trap 'on_fail 130' INT
set -Eeuo pipefail

# ── 5. The system user the listener and the socket's group are named after ──

if id "$PUBLIC_USER" >/dev/null 2>&1; then
  log "the $PUBLIC_USER system user already exists (left as it is)"
else
  # No home and no login shell: this user exists only to run one process and to own
  # the socket's group. useradd makes its matching group, which SocketGroup= needs.
  #
  # `pending` IS WRITTEN BEFORE THE COMMAND AND CONFIRMED AFTER IT: a run killed between the two
  # has already changed this host, and the undo has to know that the user MIGHT be this run's. The
  # undo treats `pending` like `1` but checks with `id` that the user is really there before it
  # removes anything, so a `pending` marker for a useradd that never landed deletes nothing.
  state_set USER_CREATED pending \
    || fail "could not record USER_CREATED in $RESTORE_STATE, so the undo could not know that $PUBLIC_USER might be this run's to remove"
  timeout "$STEP_TIMEOUT" useradd --system --no-create-home --shell /usr/sbin/nologin "$PUBLIC_USER" \
    || fail "could not create the $PUBLIC_USER system user"
  # Confirmed the moment it is true, not at the end of the run.
  state_set USER_CREATED 1 \
    || fail "could not record USER_CREATED in $RESTORE_STATE, so the undo could not know that $PUBLIC_USER is this run's to remove"
  log "created the $PUBLIC_USER system user (no home, no login shell)"
fi
if ! getent group "$PUBLIC_USER" >/dev/null 2>&1; then
  fail "there is no '$PUBLIC_USER' group, which $SOCKET_UNIT_NAME needs for SocketGroup=; add it (addgroup --system $PUBLIC_USER) and run this again"
fi

# ── 6. Render the three units, refusing to install an unfilled template ─────

sed_escape() { printf '%s' "${1:-}" | sed -e 's/[\\&|]/\\&/g'; }

render_template() { # render_template <template> <staged output>
  local tpl="$1" out="$2" left=""
  [ -f "$tpl" ] || fail "missing template $tpl"
  sed \
    -e "s|@NODE_BIN@|$(sed_escape "$NODE_BIN")|g" \
    -e "s|@NODE_DIR@|$(sed_escape "$NODE_DIR")|g" \
    -e "s|@APP_DIR@|$(sed_escape "$APP_DIR")|g" \
    -e "s|@CROW_HOME@|$(sed_escape "$CROW_HOME")|g" \
    -e "s|@BIND@|$(sed_escape "$CROW_ARTIFACT_PUBLIC_BIND")|g" \
    "$tpl" > "$out" \
    || fail "could not render $tpl"
  # A placeholder this script does not know means the template and this installer
  # are from different versions: refuse rather than install a unit with a literal
  # @NAME@ in it, which systemd would read as a path or an address.
  left="$(grep -oE '@[A-Za-z_][A-Za-z0-9_]*@' "$out" | sort -u | tr '\n' ' ' || true)"
  if [ -n "$left" ]; then
    fail "$tpl still carries the placeholder(s) ${left}— this installer does not fill them, so nothing was installed"
  fi
  chmod 0644 "$out"
}

STAGE="$RESTORE_STAGE"
render_template "$SOCKET_UNIT_TEMPLATE" "$STAGE/$SOCKET_UNIT_NAME"
render_template "$LISTENER_UNIT_TEMPLATE" "$STAGE/$LISTENER_UNIT_NAME"
render_template "$DROP_IN_TEMPLATE" "$STAGE/$DROP_IN_NAME"

# ── 7. Install the three files (existing ones were backed up above) ─────────
#
# NOTHING IS ARMED OR LOCKED HERE ANY MORE: the deadman armed in section 4 is the only timer, it
# already outlives this whole run, and no lock or marker exists to take or write. The first
# production-facing file goes in below, which is why the deadman went up before it.
if [ ! -d "$DROP_IN_DIR" ]; then
  mkdir -p "$DROP_IN_DIR" || fail "could not create $DROP_IN_DIR"
  DROP_IN_DIR_CREATED=1
  state_set DROP_IN_DIR_CREATED 1 \
    || fail "could not record DROP_IN_DIR_CREATED in $RESTORE_STATE, so the undo could not know to remove $DROP_IN_DIR"
fi
# THE GATEWAY IS ABOUT TO BE TOUCHED, AND THE UNDO HAS TO KNOW IT. Two of these three files are
# the gateway's: the socket unit is the door it is handed by socket activation, and the drop-in
# is what makes that hand-over real at the next daemon-reload. Recorded HERE, before either one
# goes in, so a run killed between the install and the restart still leaves an undo that
# restarts the gateway it half changed — and a run that never gets this far leaves an undo that
# leaves the gateway alone.
state_set GATEWAY_TOUCHED 1 \
  || fail "could not record GATEWAY_TOUCHED in $RESTORE_STATE, so the undo could not know whether the gateway needs a restart"
install -m 0644 "$STAGE/$SOCKET_UNIT_NAME" "$SOCKET_UNIT_DEST" || fail "could not install $SOCKET_UNIT_DEST"
install -m 0644 "$STAGE/$LISTENER_UNIT_NAME" "$LISTENER_UNIT_DEST" || fail "could not install $LISTENER_UNIT_DEST"
install -m 0644 "$STAGE/$DROP_IN_NAME" "$DROP_IN_DEST" || fail "could not install $DROP_IN_DEST"

# ── 8. The one firewall rule, only if there is a firewall to scope it in ────
#
# Whether the rule was already there was read before the first change (4b), and written
# into the restore state, so the undo knows whether THIS run is the one that must delete
# it. Nothing is read from ufw here: this section only acts on that answer — and then only on
# what `ufw allow` itself said it did, below.

# DID ufw ACTUALLY ADD IT? `ufw allow` prints "Rule added" when it writes a rule (and
# "Rule added (v6)" for the IPv6 copy of the same rule), and "Skipping adding existing rule"
# when the rule was already there. Only the first is a rule THIS run must delete, so the
# decision is made from that output — the exit status alone would also be 0 for a skip — and a
# rule this run did not add is never removed by its undo.
ufw_output_added() { # ufw_output_added <the text the ufw allow call printed>
  case "${1:-}" in
    *"Rule added"*) return 0 ;;
  esac
  return 1
}

if [ "$UFW_ACTIVE" -eq 1 ]; then
  if [ "$UFW_RULE_EXISTED" -eq 1 ]; then
    log "the ufw rule '$UFW_EXPECTED' is already there, exactly as written (left as it is)"
  else
    # `pending` goes in BEFORE the rule is asked for, for the same reason as the user above: a run
    # killed inside the ufw call has changed this host, and the undo must know the rule MIGHT be
    # this run's. The undo treats `pending` like `1` but removes the rule only when `ufw show
    # added` still lists it exactly, so a marker for an allow that ufw refused deletes nothing.
    state_set UFW_RULE_ADDED pending \
      || fail "could not record UFW_RULE_ADDED in $RESTORE_STATE, so the undo could not know that the ufw rule might be this run's to delete"
    UFW_ALLOW_OUTPUT="$(LC_ALL=C timeout "$STEP_TIMEOUT" ufw "${UFW_RULE[@]}" 2>&1)" || fail "ufw refused '$UFW_EXPECTED'"
    if ufw_output_added "$UFW_ALLOW_OUTPUT"; then
      UFW_RULE_ADDED=1
      state_set UFW_RULE_ADDED 1 \
        || fail "could not record UFW_RULE_ADDED in $RESTORE_STATE, so the undo could not know that the ufw rule is this run's to delete"
      log "added the ufw rule: $UFW_EXPECTED"
    else
      # ufw said it did not add the rule, so the undo must not delete one: back to 0.
      UFW_RULE_ADDED=0
      state_set UFW_RULE_ADDED 0 \
        || fail "could not record UFW_RULE_ADDED in $RESTORE_STATE, so the undo could not know that the ufw rule is not this run's to delete"
      log "ufw answered '$UFW_EXPECTED' with '$(printf '%s' "$UFW_ALLOW_OUTPUT" | tr '\n' ' ')': this run added no rule, so the undo leaves the firewall alone"
    fi
  fi
else
  log "ufw is not installed or not active here, so no firewall rule was added: allow $CROW_ARTIFACT_SIDECAR_IP to reach $CROW_ARTIFACT_PUBLIC_BIND port $PUBLIC_PORT/tcp yourself, or the sidecar cannot reach the listener"
fi

# ── 9. Start it: socket first, then the gateway that receives it, then the door ──
#
# The deadman armed in section 4 is what bounds this whole run: the daemon-reload below is the
# first thing that changes what the running gateway sees, and from there an outage lasts until a
# restarted gateway answers again. DEADMAN_AFTER is sized above that whole span (see the
# arithmetic beside STEP_TIMEOUT), so nothing here has to watch the clock itself.
timeout "$STEP_TIMEOUT" systemctl daemon-reload || fail "systemctl daemon-reload failed"
timeout "$STEP_TIMEOUT" systemctl enable "$SOCKET_UNIT_NAME" >/dev/null || fail "could not enable $SOCKET_UNIT_NAME"
timeout "$STEP_TIMEOUT" systemctl start "$SOCKET_UNIT_NAME" || fail "$SOCKET_UNIT_NAME did not start"

# The gateway restart is ASKED FOR and then WAITED FOR, never assumed. It is
# `--no-block` because the gateway's own unit allows TimeoutStartSec=15min: a blocking
# restart would sit inside this step's 60 s cap and be killed half way, leaving a
# gateway that is still starting with nobody watching it. `--no-block` is only safe
# because of the wait below, and the wait needs a way to tell the new process from the
# one that is running now: /health could answer from the OLD gateway a moment before it
# dies, so its InvocationID is recorded first and a DIFFERENT one, active, is what the
# restart is waited on.
GATEWAY_INVOCATION_ID="$(timeout "$STEP_TIMEOUT" systemctl show -p InvocationID --value "$GATEWAY_UNIT_NAME" 2>/dev/null || true)"
[ -n "$GATEWAY_INVOCATION_ID" ] \
  || fail "could not read the running $GATEWAY_UNIT_NAME's InvocationID, so a new start could not be told apart from this one"
timeout "$STEP_TIMEOUT" systemctl restart --no-block "$GATEWAY_UNIT_NAME" || fail "$GATEWAY_UNIT_NAME was not asked to restart"
timeout "$STEP_TIMEOUT" systemctl enable "$LISTENER_UNIT_NAME" >/dev/null || fail "could not enable $LISTENER_UNIT_NAME"
timeout "$STEP_TIMEOUT" systemctl start "$LISTENER_UNIT_NAME" || fail "$LISTENER_UNIT_NAME did not start"

# Waits for the gateway to be a NEW, active process: at most GATEWAY_INVOCATION_WAIT seconds, in
# 5 s steps, each read under GATEWAY_REQUEST_CAP (the numbers INSTALL_WAIT_BUDGET, and so the
# deadman's cap, are added up from).
wait_for_new_gateway_invocation() {
  local deadline=$(( SECONDS + GATEWAY_INVOCATION_WAIT )) now="" state=""
  while [ "$SECONDS" -lt "$deadline" ]; do
    now="$(timeout "$GATEWAY_REQUEST_CAP" systemctl show -p InvocationID --value "$GATEWAY_UNIT_NAME" 2>/dev/null || true)"
    state="$(timeout "$GATEWAY_REQUEST_CAP" systemctl is-active "$GATEWAY_UNIT_NAME" 2>/dev/null || true)"
    if [ -n "$now" ] && [ "$now" != "$GATEWAY_INVOCATION_ID" ] && [ "$state" = "active" ]; then
      log "$GATEWAY_UNIT_NAME came back with a new InvocationID and is active"
      return 0
    fi
    timeout 10 sleep 5
  done
  echo "artifact-public install: $GATEWAY_UNIT_NAME did not come back as a new active process within five minutes (InvocationID '${now:-nothing}', state '${state:-nothing}') instead of the old '$GATEWAY_INVOCATION_ID'" >&2
  return 1
}

if ! wait_for_new_gateway_invocation; then
  fail "$GATEWAY_UNIT_NAME did not produce a new active invocation after the restart, so its /health would still be the old process's answer"
fi

# ── 10. Prove it ───────────────────────────────────────────────────────────
#
# A failed proof does not undo anything HERE: `fail` raises the ERR trap, and on_fail starts the
# one restore.sh through the deadman's own service, printing the failing step, the manual restore
# command and the deadman's fire time. The undo is restore.sh's job in every case — a human running
# it by hand, the service on_fail starts, or the timer at its fire time.

# The gateway is up and answering. GATEWAY_HEALTH_TRIES tries, GATEWAY_HEALTH_INTERVAL apart,
# each request under GATEWAY_REQUEST_CAP — the three numbers INSTALL_WAIT_BUDGET counts.
wait_for_gateway_health() {
  local code="" i
  for (( i = 0; i < GATEWAY_HEALTH_TRIES; i++ )); do
    code="$(timeout "$GATEWAY_REQUEST_CAP" curl -s -o /dev/null -w '%{http_code}' --max-time 5 --noproxy '*' "$GATEWAY_HEALTH_URL" 2>/dev/null || true)"
    if [ "$code" = "200" ]; then
      log "the gateway health check answered 200 ($GATEWAY_HEALTH_URL)"
      return 0
    fi
    sleep "$GATEWAY_HEALTH_INTERVAL"
  done
  echo "artifact-public install: $GATEWAY_HEALTH_URL answered '${code:-nothing}' instead of 200" >&2
  return 1
}

# The whole chain, from the outside: a token nobody was mailed, asked of the
# listener's port. The approved answer is 404 with a sandboxed CSP — the copy is
# deliberately NOT matched, so a wording change never breaks this check, while a
# wrong status, a redirect, an unsandboxed page or a listener that cannot reach
# the door all fail it.
round_trip_through_listener() {
  local code="" i url headers body
  url="http://$CROW_ARTIFACT_PUBLIC_BIND:$PUBLIC_PORT/r/$ROUND_TRIP_TOKEN"
  headers="$RESTORE_DIR/round-trip.headers"
  body="$RESTORE_DIR/round-trip.body"
  for (( i = 0; i < GATEWAY_ROUND_TRIP_TRIES; i++ )); do
    code="$(timeout "$GATEWAY_REQUEST_CAP" curl -s -o "$body" -D "$headers" -w '%{http_code}' --max-time 5 --noproxy '*' "$url" 2>/dev/null || true)"
    if [ "$code" = "404" ] && grep -qi '^content-security-policy:.*sandbox' "$headers" 2>/dev/null; then
      log "the round trip through $url answered 404 with a sandboxed content-security-policy"
      return 0
    fi
    sleep "$GATEWAY_ROUND_TRIP_INTERVAL"
  done
  echo "artifact-public install: $url answered '${code:-nothing}' (a sandboxed 404 was expected)" >&2
  return 1
}

if ! wait_for_gateway_health; then
  fail "the gateway health check did not pass after the restart"
fi
if ! round_trip_through_listener; then
  fail "the round trip through the listener did not return the sandboxed 404 page, so the door is not wired end to end"
fi

# ── 11. Done — and keeping it is the operator's decision ────────────────────
#
# Every check has passed. What is left is to say what was installed and to hand the operator the
# three facts that decide what happens next: the exact command that keeps the install, when the
# deadman fires, and how many minutes are left before it does. This script does NOT touch that
# file, does NOT stop the deadman and does NOT remove the backup directory — a script that kept
# its own work would make the deadman a decoration, and the point of the deadman is that only a
# human who has read these checks can say the install was wanted. If nobody says so, restore.sh
# puts the host back exactly as it was, which is why the timer was armed before the first change.
log "installed $SOCKET_UNIT_NAME -> /run/crow-report-readers/door.sock (root:$PUBLIC_USER 0660, owned by systemd)"
log "installed $DROP_IN_DEST (the gateway receives that fd by socket activation; node is its MainPID)"
log "installed $LISTENER_UNIT_NAME (user $PUBLIC_USER, port $PUBLIC_PORT, no access to $CROW_HOME)"
log "pinned node: $NODE_BIN ($NODE_VERSION_RAW), the node $GATEWAY_UNIT_NAME itself runs"
log "verified: the gateway answers /health and the listener answers a mailed report path with the sandboxed 404 page"
log "a re-run is safe; stopping the listener is 'systemctl disable --now $LISTENER_UNIT_NAME' plus removing $DROP_IN_DEST and $SOCKET_UNIT_DEST"
log "KEEP THIS INSTALL, once you have read the checks above: sudo touch $RESTORE_KEEP"
log "the deadman $DEADMAN_TIMER fires at $(deadman_fire_time_human) (epoch $DEADMAN_FIRE_AT), about $(deadman_remaining_minutes) minutes from now, and unless $RESTORE_KEEP exists by then it puts this host back exactly as it was before this run; a keep touched after the deadman has started does nothing (the restore has already begun), and a keep touched before the checks above passed was at your own risk"
log "to put it back yourself instead, once this run has exited: sudo /bin/bash $RESTORE_SCRIPT"
log "the backup and the restore script stay at $RESTORE_DIR (a tmpfs, gone at the next boot)"

# Nothing after this point can fail, because nothing else runs. The exit is 0 with the install
# unkept: the deadman is still armed and only the operator can stand it down.
exit 0