// Project ownership: can this caller own (and so re-status) this project?
//
// WHY THIS IS ITS OWN MODULE. servers/research/server.js is BOT-REACHABLE (a bot MCP child
// is spawned on servers/research/index.js), and all it ever needs from the lifecycle is
// `assertCanChangeStatus`. project-lifecycle.js is the whole delete machinery: its
// `defaultDisconnectBackend` lazy-imports servers/gateway/proxy.js, which lazy-imports
// fix-it/index.js, which imports every remedy — and a remedy's owner rule is
// servers/gateway/dashboard/local-session.js -> token-store.js, whose verifiers are minted
// under servers/shared/token-mac.js's HOST-ONLY HMAC key. A guard that only refuses the
// final `token-mac.js` import lets that whole chain into a bot's load path for nothing; the
// fix is to not be on the chain at all. So the owner rule (whose one dependency is
// AclError from project-acl.js) lives here, and the two bot-reachable callers
// (servers/research/server.js, and any other that only needs these helpers) import it,
// never project-lifecycle.js. tests/bot-seed-import-guard.test.js pins that: the walked
// set starting at servers/research/server.js contains neither servers/gateway/proxy.js nor
// servers/shared/token-mac.js.
//
// project-lifecycle.js re-exports THREE of the four exports below — canOwnProject,
// canOwnDeletedProject and assertCanChangeStatus; ownsProject stays private to this module —
// so every existing importer keeps working (archive/restore/delete still use canOwnProject,
// resume still uses canOwnDeletedProject).

import { AclError } from "./project-acl.js";

/**
 * canManageProject's rule (live row, local owner member, not revoked, role owner), except that
 * status='archived' is allowed. archived_at set and learner_profile rows are always false.
 */
export async function canOwnProject(db, projectId) {
  return ownsProject(db, projectId, { allowDeleted: false });
}

/**
 * The SAME owner rule with the tombstone allowed (archived_at NOT NULL). Only finishing a delete
 * that stopped partway uses it: the row it addresses is by definition already deleted, so the
 * ordinary rule could never pass. Everything else keeps using canOwnProject.
 */
export async function canOwnDeletedProject(db, projectId) {
  return ownsProject(db, projectId, { allowDeleted: true });
}

async function ownsProject(db, projectId, { allowDeleted }) {
  if (projectId == null || !Number.isFinite(Number(projectId))) return false;
  try {
    const { rows } = await db.execute({
      sql: `SELECT m.role FROM project_spaces ps
              JOIN project_members m ON m.project_id = ps.id AND m.contact_id IS NULL AND m.revoked_at IS NULL
             WHERE ps.id = ?${allowDeleted ? "" : " AND ps.archived_at IS NULL"} AND (ps.type IS NULL OR ps.type != 'learner_profile')
             LIMIT 1`,
      args: [Number(projectId)],
    });
    return !!rows[0] && rows[0].role === "owner";
  } catch (err) {
    console.warn("[project-ownership] owner lookup failed:", err.message);
    return false;
  }
}

/**
 * A status change is allowed only to the project's owner. Archiving is a soft delete (it hides
 * the project), so it takes delete's rule: `canOwnProject`, which already allows an archived
 * row but never a tombstone, a visited/clone-shared project, or a missing one. Throws
 * AclError('not_owner') so every caller answers it the way it answers a refused delete, and
 * callers run it BEFORE the write.
 */
export async function assertCanChangeStatus(db, projectId) {
  if (!(await canOwnProject(db, projectId))) {
    throw new AclError(`Only the owner can change project #${projectId}'s status`, "not_owner");
  }
}