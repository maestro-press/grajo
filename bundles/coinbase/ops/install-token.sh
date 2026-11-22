#!/usr/bin/env bash
# postInstall: mint the engine's install token, once, right after the bundle's first
# `compose up`. The gateway pushes the exchange credentials at runtime, so the install
# token is the one secret the engine container reads for itself: it lives in
# <CROW_HOME>/coinbase/install/install_token, which the engine mounts read-only at
# /run/secrets. That folder is this bundle's own folder under the Crow home; its parent
# <CROW_HOME>/coinbase is the protected directory, and this one dir and this one file are
# opened up just enough for the engine's own uid to read it.
#
# Idempotent by design: an existing non-empty token is left exactly as it is. It is never
# rotated here, never overwritten, never printed, never put on a command line and never
# exported into an environment. The parent folder is tightened to 0700 even when a token
# already exists, so a folder left loose after an earlier run is narrowed on the next one.
set -euo pipefail

home="${CROW_HOME:-}"
if [ -z "$home" ]; then
  echo "CROW_HOME is not set, so the install token directory is unknown; nothing was created."
  exit 1
fi
case "$home" in
  /*) ;;
  *)
    echo "CROW_HOME is not an absolute path, so the install token directory is unknown; nothing was created."
    exit 1
    ;;
esac

parent="$home/coinbase"
dir="$parent/install"
token_file="$dir/install_token"

if [ -s "$token_file" ]; then
  # A token already exists, so nothing is minted below — but the folder it sits in is still
  # narrowed here, before this run reports success, and a mode this run cannot set stops the
  # run instead of reporting a token that is reachable through a looser parent.
  if ! chmod 0700 "$parent"; then
    echo "Could not make the token's parent folder private; no install token was created."
    exit 1
  fi
  echo "Install token already present."
  exit 0
fi

# Whatever this hook creates is created unreadable to anyone else first and opened up
# deliberately further down; the umask has to be in place before the first mkdir.
umask 077

mkdir -p "$dir"
# The parent is ALWAYS 0700, whether or not this run created it: the 0755 token
# directory and the 0644 token file below are only safe because <CROW_HOME>/coinbase
# is 0700 and because the add-on wall never binds coinbase/ into add-on code. A
# folder that already existed at a looser mode is narrowed here, never left as its
# owner happened to leave it, and a mode this run cannot set stops the run before
# any token is published.
if ! chmod 0700 "$parent"; then
  echo "Could not make the token's parent folder private; no install token was created."
  exit 1
fi

# 32 random bytes, base64url without padding: 43 characters of [A-Za-z0-9_-].
token="$(head -c 32 /dev/urandom | base64 | tr '+/' '-_' | tr -d '=\n')"
case "$token" in
  "") echo "Could not read random bytes; no install token was created."; exit 1 ;;
  *[!A-Za-z0-9_-]*) echo "Generated a token outside the base64url alphabet; no install token was created."; exit 1 ;;
esac
if [ "${#token}" -ne 43 ]; then
  echo "Generated a token of the wrong length; no install token was created."
  exit 1
fi

# Written through a temp file in the same directory and published with a hard link, so a
# reader never sees a half-written token and a token another process just published is never
# replaced: the link fails when the target already exists. The value goes in on a redirect,
# not as an argument. The temp file is removed on every path.
tmp="$(mktemp "$dir/.install_token.XXXXXX")"
trap 'rm -f "$tmp"' EXIT
printf '%s\n' "$token" >"$tmp"
if ln "$tmp" "$token_file" 2>/dev/null; then
  outcome=created
elif [ -s "$token_file" ]; then
  outcome=already
else
  outcome=failed
fi
rm -f "$tmp"
trap - EXIT

case "$outcome" in
  already)
    echo "Install token already present."
    exit 0
    ;;
  failed)
    echo "Could not publish the install token; no install token was created."
    exit 1
    ;;
esac

# The engine container runs as uid 1000 and reads the file through the bind mount.
# 0755 on this directory and 0644 on this file are only safe because <CROW_HOME>/coinbase
# itself is 0700 (set by every run above) and because the add-on wall never
# binds coinbase/ into add-on code.
chmod 0644 "$token_file"
chmod 0755 "$dir"

echo "Install token created."