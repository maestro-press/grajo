#!/usr/bin/env bash
# minio-bot-storage.sh — provision the SEPARATE, path-scoped storage key a contained bot's
# storage MCP child holds, so a bot never receives the instance's shared S3 credential.
#
# WHY. A bot's storage child (crow-storage, and the reviewed bundles that declare
# `needs: ["shared-storage"]`) used to be hydrated with this instance's `storage.shared.*`
# settings — the instance-wide (root-level) credential — and a sibling process in the sandbox can
# read the child's /proc/<pid>/environ. The credential a bot gets must therefore be its own, kept
# OUTSIDE crow.db (which a bot can write) in <CROW_HOME>/secrets/bot-storage.json, in the
# directory a bot sandbox is never bound. servers/shared/bot-storage-key.js reads it; with no file
# a bot simply has no storage (fail closed — never the shared settings, never the env).
#
#   scripts/ops/minio-bot-storage.sh apply <mc-alias> <crow-home> [prefix]
#   scripts/ops/minio-bot-storage.sh undo  <mc-alias> <crow-home> [prefix]
#   scripts/ops/minio-bot-storage.sh show  <mc-alias> <crow-home> [prefix]
#
# `<prefix>` is the instance's bucket prefix (S3_BUCKET_PREFIX / storage.shared.bucket_prefix,
# default "crow"): the files bucket is `<prefix>-files`. The MinIO user is
# `<prefix>-bot-<tag>`, where the tag is the first 12 hex of
# sha256("<hostname>:<realpath of the crow home>"), and the policy is `<user>-policy` — both
# PER INSTANCE. A crow home's directory name is not unique (every default install is ~/.crow), so
# naming the user after it made two instances on one host share one MinIO user and one policy;
# the host plus the real path is this instance's own, and the two names above are the only ones
# apply/undo ever create or remove.
#
# apply writes ONE policy — GetObject/PutObject/DeleteObject plus AbortMultipartUpload and
# ListMultipartUploadParts (minio-js switches to a multipart upload at 64 MiB) on `<prefix>-files`
# under projects/*, bots/*, studio/* and sunvox-studio/*; ListBucket on that bucket limited to those
# prefixes; ListBucketMultipartUploads on that bucket with NO condition; GetBucketLocation on that
# bucket. Nothing else: no bucket listing, no bucket creation, no other prefix, and no listing of
# the bucket root (HeadBucket — what a client's bucketExists sends — is s3:ListBucket with NO
# prefix, so it is refused by the same condition).
#
# ListBucketMultipartUploads is UNCONDITIONED because it has to be: MinIO refuses the policy
# outright when s3:prefix is attached to that action ("unsupported condition keys '[s3:prefix]'
# used for action 's3:ListBucketMultipartUploads'"), and minio-js needs the action to resume an
# upload over 64 MiB — without it a multipart PUT is AccessDenied. The cost, stated plainly: the
# bot's key can list the NAMES of in-progress (incomplete) multipart uploads ANYWHERE in
# `<prefix>-files`, not only under the granted prefixes. That listing names incomplete uploads
# only — never a completed object, never an object's contents — and every read, write or delete
# still needs the matching path under projects/*, bots/*, studio/* or sunvox-studio/*. apply then
# creates the user with a locally generated 40-character secret, attaches the policy, and writes
# <crow-home>/secrets/bot-storage.json (0600, in a 0700 directory, via a temp file + mv) with the
# alias's own URL, so the file states exactly the endpoint the policy was made for. The secret is
# never printed, echoed or logged.
#
# apply REFUSES when the key file already exists (a user's secret cannot be recovered from MinIO),
# and when this instance's MinIO user or policy already exists: run `undo` first. undo removes ONLY
# this instance's user and policy (plus the file), is idempotent, and says a name is absent rather
# than claiming it removed it. show prints this instance's tag, user and policy names, whether each
# exists, and the policy document as MinIO holds it — never a secret.
#
# TWO BUCKETS ARE OUTSIDE THIS POLICY, on purpose (a docs matter, not an accident):
#   - the figures bucket blog figures are published to (servers/blog/figures-bucket.js:
#     CROW_BLOG_FIGURES_BUCKET, default "blog-figures"), so a bot's data-dashboard figure publish
#     under this scoped key is REFUSED (the figures bucket is not <prefix>-files and is not in the
#     policy at all);
#   - `<prefix>-artifacts` (bundles/artifacts/server/blob-store-minio.js), the artifacts blob
#     store. Bots never reach it with this key: artifacts are reached only through the gateway's
#     /artifacts mount, which runs with the instance's own credential, so it is not affected.
# Widen the policy deliberately if you want a bot to publish figures itself.
#
# Needs the `mc` client on PATH (or MC=/path/to/mc) and an alias that already points at this
# instance's S3 endpoint: `mc alias set minio http://127.0.0.1:9000 <access key> <secret key>`.
set -euo pipefail

MC="${MC:-mc}"
umask 077

POLICY_FILE=""
cleanup() {
  if [ -n "$POLICY_FILE" ]; then rm -f "$POLICY_FILE"; fi
}
trap cleanup EXIT

usage() {
  cat <<'USAGE'
Usage:
  scripts/ops/minio-bot-storage.sh apply <mc-alias> <crow-home> [prefix]
  scripts/ops/minio-bot-storage.sh undo  <mc-alias> <crow-home> [prefix]
  scripts/ops/minio-bot-storage.sh show  <mc-alias> <crow-home> [prefix]

  <mc-alias>   an `mc alias` name that can administer this instance's S3 (e.g. minio)
  <crow-home>  the instance's Crow home (the one holding data/crow.db)
  [prefix]     bucket prefix (default: crow) — the files bucket is <prefix>-files

Creates the scoped `<prefix>-bot-<tag>-policy` policy and the `<prefix>-bot-<tag>` user (both per
instance: the tag hashes the host name and the crow home's real path), and writes
<crow-home>/secrets/bot-storage.json (0600). Never prints the secret.
USAGE
}

die() { printf 'minio-bot-storage: %s\n' "$*" >&2; exit 1; }
say() { printf '%s\n' "$*"; }

need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required (put it on PATH, or set MC=/path/to/mc)"; }

# The instance tag names the MinIO user (and, through it, the policy) for THIS crow home: the
# first 12 hex of sha256("<hostname>:<realpath of the crow home>"). A directory BASENAME is not
# unique — every default install is ~/.crow — so a basename-derived tag would make two instances on
# one host collide on one MinIO user and one policy. Only the tag (and the home's own basename) is
# ever printed: never another user's path.
sha256_hex() {
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -c1-64
  elif command -v shasum >/dev/null 2>&1; then shasum -a 256 | cut -c1-64
  elif command -v openssl >/dev/null 2>&1; then openssl dgst -sha256 -r | cut -c1-64
  else return 1
  fi
}

instance_tag() {
  local home="$1" real host digest
  real=$(realpath -- "$home" 2>/dev/null || readlink -f -- "$home" 2>/dev/null || printf '%s' "$home")
  host=$(uname -n 2>/dev/null || printf 'unknown-host')
  if ! digest=$(printf '%s' "${host}:${real}" | sha256_hex); then
    die "no sha256 tool is available (sha256sum, shasum or openssl): cannot derive this instance's tag (nothing was changed)"
  fi
  if [ -z "$digest" ]; then
    die "could not derive this instance's tag (nothing was changed)"
  fi
  printf '%s' "${digest:0:12}"
}

# This instance's two MinIO names. Nothing else is ever created or removed.
user_name() { printf '%s-bot-%s' "$1" "$2"; }
policy_name() { printf '%s-policy' "$1"; }

valid_prefix() {
  case "$1" in
    ''|*[!A-Za-z0-9._-]*) return 1 ;;
    [A-Za-z0-9]*) return 0 ;;
  esac
  return 1
}

# 40 characters, generated on this box. Never printed: its only consumers are `mc admin user add`
# and the 0600 file.
gen_secret() {
  local s=""
  if command -v openssl >/dev/null 2>&1; then
    s=$(openssl rand -hex 20)
  fi
  if [ -z "$s" ] && [ -r /dev/urandom ]; then
    s=$(head -c 128 /dev/urandom | od -An -tx1 | tr -d ' \n')
  fi
  if [ "${#s}" -lt 40 ]; then
    die "could not generate a secret on this box (no openssl and no /dev/urandom)"
  fi
  printf '%s' "${s:0:40}"
}

# The alias's endpoint URL, from `mc alias list <alias> --json` (falling back to the plain text
# form). Empty when the alias is unknown.
read_alias_url() {
  local alias="$1" json="" url=""
  if json=$("$MC" alias list "$alias" --json 2>/dev/null); then
    url=$(printf '%s' "$json" | tr ',{}' '\n\n\n' \
      | sed -n 's/^[[:space:]]*"URL"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' | sed -n '1p')
  fi
  if [ -z "$url" ]; then
    url=$("$MC" alias list "$alias" 2>/dev/null \
      | sed -n 's/^[[:space:]]*URL[[:space:]]*:[[:space:]]*//p' | head -n 1 | tr -d '\r')
  fi
  printf '%s' "$url"
}

# The policy, as MinIO will hold it — FOUR statements. ListBucket is conditioned on the s3:prefix
# values, so the bucket ROOT stays unlistable. ListBucketMultipartUploads gets a statement of its
# OWN, with NO condition, because MinIO will not accept this policy otherwise: it rejects
# s3:prefix on that action ("unsupported condition keys '[s3:prefix]' used for action
# 's3:ListBucketMultipartUploads'"), and minio-js needs the action for an upload over 64 MiB (with
# no grant at all the multipart PUT is AccessDenied). The cost of the unconditioned statement is
# bounded and is accepted: the key can list the NAMES of in-progress (incomplete) multipart uploads
# anywhere in the bucket — never a completed object, never an object's contents — while every
# read, write and delete still needs a path under one of the four granted prefixes.
policy_json() {
  local prefix="$1"
  cat <<JSON
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:GetObject", "s3:PutObject", "s3:DeleteObject", "s3:AbortMultipartUpload", "s3:ListMultipartUploadParts"],
      "Resource": [
        "arn:aws:s3:::${prefix}-files/projects/*",
        "arn:aws:s3:::${prefix}-files/bots/*",
        "arn:aws:s3:::${prefix}-files/studio/*",
        "arn:aws:s3:::${prefix}-files/sunvox-studio/*"
      ]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucket"],
      "Resource": ["arn:aws:s3:::${prefix}-files"],
      "Condition": {
        "StringLike": {
          "s3:prefix": [
            "projects/*", "bots/*", "studio/*", "sunvox-studio/*",
            "projects/", "bots/", "studio/", "sunvox-studio/"
          ]
        }
      }
    },
    {
      "Effect": "Allow",
      "Action": ["s3:ListBucketMultipartUploads"],
      "Resource": ["arn:aws:s3:::${prefix}-files"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:GetBucketLocation"],
      "Resource": ["arn:aws:s3:::${prefix}-files"]
    }
  ]
}
JSON
}

user_exists() { "$MC" admin user info "$1" "$2" >/dev/null 2>&1; }
policy_exists() { "$MC" admin policy info "$1" "$2" >/dev/null 2>&1; }

cmd_show() {
  local alias="${1:-}" crow_home="${2:-}" prefix="${3:-crow}"
  if [ -z "$alias" ] || [ -z "$crow_home" ]; then die "show needs an <mc-alias> and a <crow-home>"; fi
  valid_prefix "$prefix" || die "prefix '$prefix' is not a bucket prefix (letters, digits, dot, dash, underscore)"
  need "$MC"
  local tag user policy document
  tag=$(instance_tag "$crow_home")
  user=$(user_name "$prefix" "$tag")
  policy=$(policy_name "$user")
  # This instance's names only, and the derivation's inputs as basenames: a report an operator
  # pastes into a ticket names no other user's directory.
  say "tag:    $tag (from <host name>:<$(basename -- "$crow_home")>)"
  say "user:   $user"
  if user_exists "$alias" "$user"; then say "  exists: yes"; else say "  exists: no"; fi
  say "policy: $policy"
  if document=$("$MC" admin policy info "$alias" "$policy" 2>/dev/null); then
    say "  exists: yes"
    say "  document:"
    printf '%s\n' "$document"
  else
    say "  exists: no"
  fi
  say "bucket: ${prefix}-files (projects/*, bots/*, studio/*, sunvox-studio/*; not the bucket root, and not the figures or artifacts buckets)"
}

cmd_apply() {
  local alias="${1:-}" crow_home="${2:-}" prefix="${3:-crow}"
  if [ -z "$alias" ] || [ -z "$crow_home" ]; then die "apply needs an <mc-alias> and a <crow-home>"; fi
  valid_prefix "$prefix" || die "prefix '$prefix' is not a bucket prefix (letters, digits, dot, dash, underscore)"
  need "$MC"
  if [ ! -d "$crow_home" ]; then die "$crow_home is not a directory (nothing was changed)"; fi

  local secrets_dir key_file
  secrets_dir="$crow_home/secrets"
  key_file="$secrets_dir/bot-storage.json"
  # Refused BEFORE anything is created in MinIO: a user's secret cannot be recovered, so a second
  # apply would leave an orphan user behind with no file to match it.
  if [ -e "$key_file" ] || [ -L "$key_file" ]; then
    die "$key_file already exists — run 'undo' first (it removes this instance's user, its policy and the file)"
  fi

  local tag policy user bucket url scheme endpoint
  tag=$(instance_tag "$crow_home")
  user=$(user_name "$prefix" "$tag")
  policy=$(policy_name "$user")
  bucket="${prefix}-files"

  # The same refusal for this instance's own MinIO names: applying again would overwrite a policy
  # a live key is bound to (or, worse, attach a NEW user to it), and neither name belongs to
  # another instance — the tag is this crow home's.
  if user_exists "$alias" "$user"; then
    die "MinIO user $user already exists — run 'undo' first (nothing was changed)"
  fi
  if policy_exists "$alias" "$policy"; then
    die "MinIO policy $policy already exists — run 'undo' first (nothing was changed)"
  fi

  url=$(read_alias_url "$alias")
  if [ -z "$url" ]; then
    die "alias '$alias' is not known to mc (set it with: mc alias set $alias <url> <access key> <secret key>)"
  fi
  case "$url" in
    https://*) scheme=https ;;
    http://*)  scheme=http ;;
    *) die "alias '$alias' has an unexpected URL scheme (expected http:// or https://)" ;;
  esac
  endpoint="${url#"$scheme://"}"
  endpoint="${endpoint%%/*}"
  if [ -z "$endpoint" ]; then die "alias '$alias' has no host in its URL"; fi
  case "$endpoint" in
    *\"*|*\\*|*\'*) die "alias '$alias' has a URL this script will not write into a JSON file" ;;
  esac

  local use_ssl=false
  if [ "$scheme" = https ]; then use_ssl=true; fi

  POLICY_FILE=$(mktemp)
  policy_json "$prefix" > "$POLICY_FILE"
  chmod 600 "$POLICY_FILE"

  "$MC" admin policy create "$alias" "$policy" "$POLICY_FILE"

  local secret
  secret=$(gen_secret)
  "$MC" admin user add "$alias" "$user" "$secret"
  "$MC" admin policy attach "$alias" "$policy" --user "$user"

  mkdir -p "$secrets_dir"
  chmod 700 "$secrets_dir"
  local tmp
  tmp="$secrets_dir/.bot-storage.json.$$"
  # Every value below is generated here (the endpoint from the alias, the secret from this box),
  # and each is restricted to characters that cannot end a JSON string: nothing user-supplied is
  # interpolated unescaped. The file is created 0600 (umask 077) and renamed into place.
  {
    printf '{\n'
    printf '  "endpoint": "%s",\n' "$endpoint"
    printf '  "use_ssl": %s,\n' "$use_ssl"
    printf '  "region": "us-east-1",\n'
    printf '  "bucket_prefix": "%s",\n' "$prefix"
    printf '  "access_key": "%s",\n' "$user"
    printf '  "secret_key": "%s"\n' "$secret"
    printf '}\n'
  } > "$tmp"
  chmod 600 "$tmp"
  mv -f "$tmp" "$key_file"
  unset secret

  say "tag:    $tag (from <host name>:<$(basename -- "$crow_home")>)"
  say "policy: $policy"
  say "user:   $user"
  say "bucket: $bucket (projects/*, bots/*, studio/*, sunvox-studio/*)"
  say "endpoint: $endpoint (use_ssl: $use_ssl)"
  say "key file: $key_file"
}

cmd_undo() {
  local alias="${1:-}" crow_home="${2:-}" prefix="${3:-crow}"
  if [ -z "$alias" ] || [ -z "$crow_home" ]; then die "undo needs an <mc-alias> and a <crow-home>"; fi
  valid_prefix "$prefix" || die "prefix '$prefix' is not a bucket prefix (letters, digits, dot, dash, underscore)"
  need "$MC"
  local tag policy user key_file
  tag=$(instance_tag "$crow_home")
  user=$(user_name "$prefix" "$tag")
  policy=$(policy_name "$user")
  key_file="$crow_home/secrets/bot-storage.json"

  # ONLY this instance's user and policy (the names carry this crow home's tag), and each step says
  # what it actually did: an absent name is reported as absent, never as removed.
  if user_exists "$alias" "$user"; then
    if policy_exists "$alias" "$policy"; then
      "$MC" admin policy detach "$alias" "$policy" --user "$user" >/dev/null 2>&1 \
        || say "policy detach from $user failed (it was not attached?)"
    fi
    if "$MC" admin user remove "$alias" "$user" >/dev/null 2>&1; then
      say "removed user:   $user"
    else
      say "user:   $user (present, but mc could not remove it)"
    fi
  else
    say "user:   $user (absent — nothing to remove)"
  fi
  if policy_exists "$alias" "$policy"; then
    if "$MC" admin policy remove "$alias" "$policy" >/dev/null 2>&1; then
      say "removed policy: $policy"
    else
      say "policy: $policy (present, but mc could not remove it)"
    fi
  else
    say "policy: $policy (absent — nothing to remove)"
  fi
  if [ -e "$key_file" ] || [ -L "$key_file" ]; then
    rm -f "$key_file"
    say "removed file:   $key_file"
  else
    say "file:   $key_file (absent — nothing to remove)"
  fi
}

main() {
  local verb="${1:-}"
  case "$verb" in
    apply) shift; cmd_apply "$@" ;;
    undo)  shift; cmd_undo "$@" ;;
    show)  shift; cmd_show "$@" ;;
    -h|--help|help|"") usage; if [ -n "$verb" ]; then exit 0; fi; exit 2 ;;
    *) usage; die "unknown command '$verb'" ;;
  esac
}

main "$@"