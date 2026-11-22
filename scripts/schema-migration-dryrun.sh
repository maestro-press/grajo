#!/usr/bin/env bash
#
# Schema-bump dry-run gate.
#
# WHY: bumping SCHEMA_GENERATION does NOT run "just your new migration".
# needsSchemaInit (servers/shared/schema-version.js) -> servers/gateway/index.js
# runs the ENTIRE scripts/init-db.js, which contains 8 DROP TABLE
# rebuild-migrations (shared_items, crow_context, dashboard_settings,
# research_projects, a generic DROP TABLE ${tableName}) plus DELETE FROM
# schedules / project_spaces. They are guarded, but they have not executed since
# the current generation was stamped, and a bump re-arms every one of them
# against every live DB in the fleet.
#
# And PRAGMA integrity_check CANNOT detect the damage: it reports page-level
# integrity and returns "ok" for a table that was rebuilt having silently lost
# rows. user_version = <new> only proves the script reached its last line.
#
# So: before ANY schema-bumping PR merges, run init-db against a COPY of each
# prod DB and diff sqlite_master + per-table COUNT(*) + per-table COLUMNS
# (PRAGMA table_info) pre/post. Zero unexplained deltas is the merge gate.
# Never point this at a live DB — it always copies.
#
# The column diff is what proves an additive migration actually HAPPENED:
# ADDED columns are reported informationally (an ALTER TABLE ADD COLUMN
# migration is EXPECTED to add its column — not a failure); a REMOVED column
# means a table was rebuilt narrower and is a STOP (gate fails).
#
# USAGE:
#   scripts/schema-migration-dryrun.sh <label> <path-to-db> [<label> <db> ...]
#
# ENV:
#   DRYRUN_INIT_SCRIPT — the migration script to run against each copy
#     (absolute path, or relative to the repo root). Default: scripts/init-db.js.
#     Exists as a testability seam; production use should leave it unset.
#
# The whole fleet (run from crow; pull the remote DBs to local copies first):
#   scripts/schema-migration-dryrun.sh \
#     crow    ~/.crow/data/crow.db \
#     mpa     ~/.crow-mpa/data/crow.db \
#     server-b /tmp/server-b.db \
#     vps-1   /tmp/vps-1.db
#
# EXPECTED OUTPUT for a well-behaved additive migration: the only schema delta is
# your new column/table, user_version advances, and every row count is unchanged.
# ANY unexplained row-count delta or lost table is a STOP. A decrease is reported
# as "row loss", an increase as "unexplained row gain" — a migration has no
# business inventing rows either, so both fail the gate.
#
# FTS5 INDEX STRUCTURE IS NOT ROWS: a virtual table declared `USING fts5` owns
# shadow tables `<name>_data`, `<name>_idx` and `<name>_config` that ARE the
# search index itself — segment lists and term b-trees. Their row counts move
# whenever FTS maintenance rewrites segments ('optimize', 'rebuild', or the
# delete+insert pair a trigger fires on ONE ordinary UPDATE — which is what
# init-db's uuid backfill does to research_sources) while no document changes.
# They are therefore reported in their own informational section, "FTS5 index
# structure (not rows)", and never STOP the gate. `<name>_content` and
# `<name>_docsize` hold one row per DOCUMENT, and the virtual table's own
# COUNT(*) is the document count: those stay under the normal row-count rule.
# A row is discovered as an fts5 index only when the fts5 module name is followed
# by '(' — `USING fts5vocab(...)`, a different module over an fts5 table, is an
# ordinary table here — and a discovery query that ERRORS is itself a STOP.
# The FTS5 'integrity-check' section runs fts5's own index check per virtual
# table (cheap — init-db already relies on it after rebuilding research_sources).
# It verifies the index's b-tree structure only: probed against this SQLite, a
# content row missing from the index, a stale index entry, a stale content row
# and even an absent content table all report ok, so a FAILURE there is a STOP
# but a pass does not prove an index matches its documents.
#
set -uo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
INIT_SCRIPT="${DRYRUN_INIT_SCRIPT:-scripts/init-db.js}"
FAILED=0

# A sqlite_master 'table' row is an FTS5 VIRTUAL table only when the fts5 MODULE
# name is followed by its opening paren. The old `lower(sql) LIKE '%using fts5%'`
# also matched `USING fts5vocab(...)` — a different module (a term/row inspector
# over an existing fts5 table) — so a vocabulary table was treated as an fts5
# index and the integrity-check loop below inserted 'integrity-check' into it,
# which sqlite refuses ("table <v> may not be modified"): a false STOP on a
# healthy DB. Whitespace and the quoting around the module name are normalised
# away first, because sqlite_master keeps the CREATE statement exactly as typed
# ('USING fts5 (…)', a newline before the paren, or "fts5" are all legal).
FTS5_VTAB_MATCH="lower(replace(replace(replace(replace(replace(replace(sql,' ',''),char(9),''),char(10),''),char(13),''),char(34),''),char(96),'')) LIKE '%usingfts5(%'"

# List a copy's fts5 virtual tables into $2. A discovery query that FAILS must
# never read as "no FTS5 virtual tables": that silently disables both the shadow
# table classification (so the index b-trees fall back under the row-count STOP
# rule) and the integrity-check, i.e. a broken query would look like the
# cleanest possible DB. So stderr is captured, not discarded, and a non-zero
# sqlite3 exit prints a warning line and returns 1 — the caller makes it a STOP.
# `2>&1 >"$2"` (in that order): stderr goes to the capture, only stdout to the list.
discover_fts_vtabs() { # $1=db  $2=out-file  $3=which copy (pre-migration/post-migration)
  local err rc msg
  err=$(sqlite3 "$1" "SELECT name FROM sqlite_master WHERE type='table' AND $FTS5_VTAB_MATCH ORDER BY name;" 2>&1 > "$2")
  rc=$?
  [ "$rc" -eq 0 ] && return 0
  msg="${err%$'\n'}"   # one trailing newline only — the caller prefixes every line
  printf 'FTS5 virtual-table discovery FAILED on the %s copy (sqlite3 exit %s): %s\n' \
    "$3" "$rc" "${msg:-no error message}"
  return 1
}

snapshot() { # $1=db  $2=out-prefix
  sqlite3 "$1" \
    "SELECT type||' '||name FROM sqlite_master WHERE name NOT LIKE 'sqlite_%' ORDER BY 1;" \
    > "$2.schema" 2>/dev/null
  : > "$2.counts"
  : > "$2.columns"
  local t n
  # while-read, not `for t in $(...)`: an unquoted expansion word-splits table
  # names containing whitespace, silently dropping them from BOTH snapshots —
  # a false PASS on exactly the tables the diff exists to protect.
  while IFS= read -r t; do
    [ -n "$t" ] || continue
    n=$(sqlite3 "$1" "SELECT COUNT(*) FROM \"$t\";" 2>/dev/null || echo ERR)
    printf '%s\t%s\n' "$t" "$n" >> "$2.counts"
    sqlite3 "$1" "PRAGMA table_info(\"$t\");" 2>/dev/null \
      | awk -F'|' -v t="$t" '{printf "%s\t%s\t%s\n", t, $2, $3}' >> "$2.columns" \
      || printf '%s\t__PRAGMA_ERR__\t__PRAGMA_ERR__\n' "$t" >> "$2.columns"
  done < <(sqlite3 "$1" "SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name;" 2>/dev/null)
}

dryrun_one() { # $1=label  $2=src-db
  local label="$1" src="$2"
  local work cp rc pre_uv post_uv integ f
  if [ ! -f "$src" ]; then
    echo "════════ $label ════════"
    echo "  SKIP — no such DB: $src"
    return 0
  fi
  work="$(mktemp -d)"; cp="$work/crow.db"
  cp "$src" "$cp" || { echo "[$label] COPY FAILED"; FAILED=1; return 1; }

  snapshot "$cp" "$work/pre"
  # FTS5 virtual tables — a sqlite_master 'table' whose declaration is the fts5
  # module followed by '(' (see FTS5_VTAB_MATCH: fts5vocab is NOT one).
  # Discovered on BOTH copies and unioned below: a vtab the migration creates or
  # drops then still has its shadow tables classified as index structure.
  # A failed discovery query is collected here and STOPs the gate below.
  : > "$work/fts.disc.warn"
  discover_fts_vtabs "$cp" "$work/fts.vtabs.pre" "pre-migration" >> "$work/fts.disc.warn"
  pre_uv=$(sqlite3 "$cp" "PRAGMA user_version;")

  ( cd "$REPO_ROOT" && CROW_DB_PATH="$cp" node "$INIT_SCRIPT" ) > "$work/init.log" 2>&1
  rc=$?

  snapshot "$cp" "$work/post"
  discover_fts_vtabs "$cp" "$work/fts.vtabs.post" "post-migration" >> "$work/fts.disc.warn"
  sort -u "$work/fts.vtabs.pre" "$work/fts.vtabs.post" > "$work/fts.vtabs"
  # The shadow tables of each fts5 vtab that are INDEX STRUCTURE, never documents.
  # (_content/_docsize are one row per document and stay under the STOP rule.)
  : > "$work/fts.shadows"
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    printf '%s\n%s\n%s\n' "${f}_data" "${f}_idx" "${f}_config" >> "$work/fts.shadows"
  done < "$work/fts.vtabs"
  post_uv=$(sqlite3 "$cp" "PRAGMA user_version;")
  # `sed -n 1p`, not `head -1`: head stops reading at the first line and SIGPIPEs sqlite3.
  integ=$(sqlite3 "$cp" "PRAGMA integrity_check;" | sed -n '1p')

  echo "════════ $label ════════"
  # Always name the script that ran — a stale exported DRYRUN_INIT_SCRIPT must
  # never be able to substitute a different migration with no visible signal.
  echo "  init script: $INIT_SCRIPT"
  if [ -n "${DRYRUN_INIT_SCRIPT:-}" ]; then
    echo "  ⚠⚠ NON-DEFAULT INIT SCRIPT (DRYRUN_INIT_SCRIPT is set) — this is NOT a real init-db gate run"
  fi
  echo "  init-db exit=$rc   user_version: $pre_uv -> $post_uv   integrity: $integ"
  [ "$rc" -ne 0 ] && FAILED=1
  [ "$integ" != "ok" ] && FAILED=1

  # A discovery failure feeds an EMPTY fts5 list into every section below, which
  # is why it must STOP rather than quietly report "no FTS5 virtual tables".
  if [ -s "$work/fts.disc.warn" ]; then
    sed 's/^/  ⚠ /' "$work/fts.disc.warn"
    echo "  ^^^ STOP — FTS5 virtual-table discovery FAILED (the shadow-table classification and the integrity-check did NOT run; an empty table list must never read as \"no FTS5 tables\")"
    FAILED=1
  fi
  # …and the two sections that would otherwise announce an absent FTS5 index must
  # not claim one is absent when the discovery never produced an answer.
  local fts_absent="(none — no FTS5 virtual tables in this DB)"
  [ -s "$work/fts.disc.warn" ] && fts_absent="(unknown — the FTS5 virtual-table discovery query FAILED, see the STOP above)"

  echo "  ── schema objects added/removed ──"
  # Capture, don't branch on the pipeline: under `set -o pipefail` the old
  # `if diff | grep -q` inverted — diff exits 1 exactly when differences exist,
  # so this section printed "(none)" for EVERY real delta (found 2026-07-13 by
  # 2b's own gate run: the new table showed in the column diff but not here).
  # Indexes/triggers/views are covered ONLY by this section, so a removed one is
  # a STOP, not just display.
  local obj_delta
  obj_delta=$(diff "$work/pre.schema" "$work/post.schema" | grep -E '^[<>]' || true)
  if [ -n "$obj_delta" ]; then
    printf '%s\n' "$obj_delta" | sed 's/^/    /'
    # The here-string is the fix, not decoration: `printf … | grep -q` ends grep at its first
    # match and SIGPIPEs the writer, and under pipefail that made a MATCH read as "no match"
    # — a removed index/trigger/view passing as "(none)". Same shape below, twice.
    if grep -q '^<' <<<"$obj_delta"; then
      echo "    ^^^ STOP — schema object(s) REMOVED (index/trigger/view loss is invisible to every other section)"
      FAILED=1
    fi
  else
    echo "    (none)"
  fi

  echo "  ── ROW-COUNT DELTAS (what integrity_check cannot see) ──"
  # Captured whole, then judged: `join | awk | grep -q .` had two writers that could die of
  # SIGPIPE, and its exit 1 ("no difference") is indistinguishable from a real failure.
  #
  # The join still covers every table; FTS5 shadow rows (_data/_idx/_config) are
  # tagged FTS here so they are reported in their own informational section
  # instead of failing the gate — their counts are index bookkeeping, and FTS
  # maintenance moves them without touching a document. A count that did not
  # compare numerically (a COUNT(*) that errored) is CHANGE, never silently
  # dropped by a numeric comparison.
  local row_delta
  row_delta=$(join -t$'\t' "$work/pre.counts" "$work/post.counts" 2>/dev/null \
    | awk -F'\t' -v shadow_file="$work/fts.shadows" '
        BEGIN { while ((getline s < shadow_file) > 0) if (s != "") shadow[s] = 1; close(shadow_file) }
        $2 == $3 { next }
        {
          dir = "CHANGE"
          if ($2 ~ /^[0-9]+$/ && $3 ~ /^[0-9]+$/) dir = ($3 < $2) ? "LOSS" : "GAIN"
          printf "%s\t%s\t%s\t%s\t%s\n", (($1 in shadow) ? "FTS" : "ROW"), dir, $1, $2, $3
        }')
  # Labels are truthful: a DECREASE is row loss, an INCREASE is an unexplained row
  # gain (a migration may not invent rows either). For an ordinary table both are
  # a STOP; only the FTS5 index-structure shadows are informational.
  local lost_rows gained_rows odd_rows fts_delta
  lost_rows=$(awk -F'\t' '$1=="ROW" && $2=="LOSS" {printf "    %s: %s -> %s (row loss)\n", $3, $4, $5}' <<<"$row_delta")
  gained_rows=$(awk -F'\t' '$1=="ROW" && $2=="GAIN" {printf "    %s: %s -> %s (unexplained row gain)\n", $3, $4, $5}' <<<"$row_delta")
  odd_rows=$(awk -F'\t' '$1=="ROW" && $2=="CHANGE" {printf "    %s: %s -> %s (unexplained count change)\n", $3, $4, $5}' <<<"$row_delta")
  fts_delta=$(awk -F'\t' '$1=="FTS" {printf "    %s: %s -> %s\n", $3, $4, $5}' <<<"$row_delta")
  if [ -z "$lost_rows" ] && [ -z "$gained_rows" ] && [ -z "$odd_rows" ]; then
    echo "    (none — all preserved tables identical)"
  else
    [ -n "$lost_rows" ] && printf '%s\n' "$lost_rows"
    [ -n "$gained_rows" ] && printf '%s\n' "$gained_rows"
    [ -n "$odd_rows" ] && printf '%s\n' "$odd_rows"
    [ -n "$lost_rows" ] && echo "    ^^^ STOP — unexplained ROW LOSS (rows in the source copy are gone after the migration)"
    [ -n "$gained_rows" ] && echo "    ^^^ STOP — unexplained ROW GAIN (no migration may invent rows)"
    [ -n "$odd_rows" ] && echo "    ^^^ STOP — unexplained row-count change (a COUNT(*) did not compare numerically)"
    FAILED=1
  fi

  echo "  ── FTS5 index structure (not rows) ──"
  # <vtab>_data / _idx / _config are the search index: segment lists and term
  # b-trees. 'optimize', 'rebuild', or the delete+insert pair a trigger fires on
  # one ordinary UPDATE rewrites them with no document change, so their counts are
  # informational. The DOCUMENT counts (<vtab>, _content, _docsize) were judged in
  # the row-count section above.
  if [ -n "$fts_delta" ]; then
    printf '%s\n' "$fts_delta"
    echo "    (informational — segment/term b-tree bookkeeping; document counts are judged above)"
  elif [ -s "$work/fts.vtabs" ]; then
    echo "    (none — FTS5 index structure unchanged)"
  else
    echo "    $fts_absent"
  fi

  echo "  ── FTS5 integrity-check ──"
  # FTS5's own index check, run on the POST copy. It validates the index b-tree
  # structure; it does NOT compare the index against the documents (probed: a
  # content row missing from the index, a stale entry, a stale content row and an
  # absent content table all return ok), so this is a structural tripwire only.
  # A failure — a corrupt or half-restored index — is a STOP.
  local fts_failures=0 fts_err
  while IFS= read -r f; do
    [ -n "$f" ] || continue
    if fts_err=$(sqlite3 "$cp" "INSERT INTO \"$f\"(\"$f\") VALUES('integrity-check');" 2>&1); then
      echo "    $f: ok"
    else
      echo "    $f: FAILED — ${fts_err:-integrity-check returned an error}"
      fts_failures=$((fts_failures + 1))
    fi
  done < "$work/fts.vtabs.post"
  if [ ! -s "$work/fts.vtabs.post" ]; then
    echo "    $fts_absent"
  elif [ "$fts_failures" -ne 0 ]; then
    echo "    ^^^ STOP — an FTS5 index failed its integrity-check (structural corruption — rebuild the index before shipping this migration)"
    FAILED=1
  fi

  echo "  ── COLUMNS added/removed per table ──"
  local added_cols removed_cols
  sort "$work/pre.columns" > "$work/pre.columns.sorted"
  sort "$work/post.columns" > "$work/post.columns.sorted"
  added_cols=$(comm -13 "$work/pre.columns.sorted" "$work/post.columns.sorted")
  removed_cols=$(comm -23 "$work/pre.columns.sorted" "$work/post.columns.sorted")
  if [ -n "$added_cols" ]; then
    # Informational: an additive migration is EXPECTED to add its column.
    printf '%s\n' "$added_cols" | awk -F'\t' '{print "    + " $1 "." $2 " (" $3 ")"}'
  fi
  if [ -n "$removed_cols" ]; then
    printf '%s\n' "$removed_cols" | awk -F'\t' '{print "    - " $1 "." $2 " (" $3 ")"}'
    echo "    ^^^ STOP — column(s) REMOVED or CHANGED (name/type differs from source — verify before assuming data loss)"
    FAILED=1
  fi
  if [ -z "$added_cols" ] && [ -z "$removed_cols" ]; then
    echo "    (none)"
  fi

  echo "  ── tables that DISAPPEARED ──"
  # Captured whole, then judged: `comm … | grep -q .` had the same SIGPIPE inversion, and a
  # lost table would have printed "(none)".
  local lost_tables
  lost_tables=$(comm -23 <(cut -f1 "$work/pre.counts" | sort) <(cut -f1 "$work/post.counts" | sort))
  if [ -n "$lost_tables" ]; then
    printf '%s\n' "$lost_tables" | sed 's/^/    LOST: /'
    FAILED=1
  else
    echo "    (none)"
  fi

  [ "$rc" -ne 0 ] && { echo "  ── init-db errors ──"; tail -5 "$work/init.log" | sed 's/^/    /'; }
  rm -rf "$work"
}

# Usage text is the FILE HEADER, read to the first line of code — a fixed line
# count here silently truncated (or spilled into the body's comments) every time
# the header grew.
[ $# -lt 2 ] && { awk '/^set -uo pipefail/{exit} /^# /{sub(/^# ?/,""); print}' "$0"; exit 2; }
while [ $# -ge 2 ]; do dryrun_one "$1" "$2"; shift 2; echo; done

if [ "$FAILED" -eq 0 ]; then
  echo "✅ DRY-RUN GATE PASSED — no unexplained schema or row-count deltas."
  exit 0
fi
echo "❌ DRY-RUN GATE FAILED — do NOT merge the schema bump."
exit 1
