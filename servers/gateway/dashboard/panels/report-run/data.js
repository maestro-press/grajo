/**
 * The reads behind a report run page (R2-1): the project the path names, the report inside it, one of
 * that report's runs, and the artifact version that run wrote.
 *
 * WHAT THE PATH PROVES, and nothing else: the slug must be a live project of THIS instance, the report
 * must belong to that project (`reports.project_id`), and the run must belong to that report
 * (`report_runs.report_id`). Any of the three answers null, and the panel renders its not-found page.
 * The run view is reached from a dashboard link in a report email, so a report or run id from elsewhere
 * must not be readable through it.
 *
 * THE VERSION IS FOUND THROUGH THE RUN, not through the report's artifact: a preview run's version
 * lives in the report's separate preview artifact, and `report_versions` (run id + report id) names it
 * whichever artifact it is in. The artifact tables belong to the Artifacts bundle, which may not be
 * installed, and retention may have pruned the version: a missing table or row is "no document", which
 * the page says in words rather than failing on.
 *
 * EVERY ERROR TEXT IS REDACTED HERE, before it leaves this module: `report_runs.error_text` is written by
 * the run engine already redacted, and a stored row is re-checked against this instance's secret values
 * because it is shown on a page.
 */
import { ACTIVE_PROJECT_WHERE } from "../../../../shared/shell-items.js";
import { getSecretValues } from "../../../../shared/secret-values.js";
import { redactSecrets } from "../../../../shared/redact-secrets.js";

/** How many of a run's allowed links the page lists. */
export const MAX_SHOWN_LINKS = 200;

function text(value) {
  if (value == null) return "";
  return typeof value === "string" ? value : String(value);
}

/** This instance's secret values, or none: a page must render even if the list cannot be read. */
function secretValues() {
  try {
    const values = getSecretValues();
    return Array.isArray(values) ? values : [];
  } catch {
    return [];
  }
}

/** The live project the slug names, or null. */
async function projectFor(db, slug) {
  if (typeof slug !== "string" || !slug) return null;
  try {
    const { rows } = await db.execute({
      sql: `SELECT id, slug, name FROM project_spaces WHERE slug = ? AND ${ACTIVE_PROJECT_WHERE}`,
      args: [slug],
    });
    const row = rows[0];
    return row
      ? { id: Number(row.id), slug: String(row.slug), name: String(row.name || row.slug) }
      : null;
  } catch {
    return null;
  }
}

/**
 * The http(s) URLs a version recorded, in order, de-duplicated. The column is input (a stored row may be
 * hand-edited), so every entry is parsed again: anything that is not a string carrying an http or https
 * URL is dropped, never repaired.
 *
 * @param {*} json the `allowed_links_json` value
 * @returns {string[]}
 */
export function httpLinks(json) {
  let raw;
  try {
    raw = typeof json === "string" ? JSON.parse(json) : null;
  } catch {
    return [];
  }
  if (!Array.isArray(raw)) return [];
  const seen = new Set();
  const out = [];
  for (const entry of raw) {
    if (typeof entry !== "string") continue;
    let url;
    try {
      url = new URL(entry);
    } catch {
      continue;
    }
    if (url.protocol !== "http:" && url.protocol !== "https:") continue;
    if (seen.has(entry)) continue;
    seen.add(entry);
    out.push(entry);
  }
  return out;
}

/**
 * The markdown one artifact version was written with, or null when it cannot be read (no artifacts
 * tables, no such version, no markdown in its source).
 */
async function versionMarkdown(db, artifactId, n) {
  if (!artifactId) return null;
  let rows;
  try {
    ({ rows } = await db.execute({
      sql: "SELECT source_json FROM artifact_versions WHERE artifact_id = ? AND n = ?",
      args: [artifactId, n],
    }));
  } catch {
    return null;
  }
  const stored = rows[0];
  if (!stored || typeof stored.source_json !== "string") return null;
  let source;
  try {
    source = JSON.parse(stored.source_json);
  } catch {
    return null;
  }
  const markdown = source == null ? null : source.markdown;
  return typeof markdown === "string" ? markdown : null;
}

/** One line of error text: redacted, whitespace collapsed, or null when there is none. */
function errorLine(run, secrets) {
  const flat = redactSecrets(text(run == null ? "" : run.error_text), secrets).replace(/\s+/g, " ").trim();
  return flat || null;
}

/**
 * Everything the run view shows, or null when the path does not name a run this instance has.
 *
 * @param {object} db a libsql-shaped client
 * @param {{slug?: string, reportId?: string, runId?: string}} path the route's own segments
 * @returns {Promise<null|{project: object, report: object, run: object, version: object|null,
 *   links: string[], moreLinks: number}>}
 */
export async function loadReportRun(db, { slug = "", reportId = "", runId = "" } = {}) {
  const project = await projectFor(db, slug);
  if (!project) return null;
  if (!reportId || !runId) return null;

  const { rows: reportRows } = await db.execute({
    sql: "SELECT id, title, project_id FROM reports WHERE id = ? AND project_id = ?",
    args: [reportId, project.id],
  });
  const report = reportRows[0];
  if (!report) return null;

  const { rows: runRows } = await db.execute({
    sql: `SELECT id, report_id, status, error_text
            FROM report_runs WHERE id = ? AND report_id = ?`,
    args: [runId, report.id],
  });
  const run = runRows[0];
  if (!run) return null;

  const { rows: mappedRows } = await db.execute({
    sql: `SELECT artifact_id, n, allowed_links_json FROM report_versions
           WHERE run_id = ? AND report_id = ? LIMIT 1`,
    args: [run.id, report.id],
  });
  const mapped = mappedRows[0] ?? null;
  const all = httpLinks(mapped == null ? null : mapped.allowed_links_json);

  let version = null;
  if (mapped != null) {
    const artifactId = text(mapped.artifact_id);
    const n = Number(mapped.n);
    version = {
      artifactId,
      n: Number.isInteger(n) ? n : null,
      markdown: Number.isInteger(n) ? await versionMarkdown(db, artifactId, n) : null,
    };
  }

  return {
    project,
    report: { id: text(report.id), title: text(report.title) },
    run: { id: text(run.id), status: text(run.status), errorText: errorLine(run, secretValues()) },
    version,
    links: all.slice(0, MAX_SHOWN_LINKS),
    moreLinks: Math.max(0, all.length - MAX_SHOWN_LINKS),
  };
}