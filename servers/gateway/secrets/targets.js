/**
 * Credential card: where a secret the operator typed can go (spec §10.5: the card, the submit
 * route and the request store never change when a target is added).
 *
 * A target is `{ validate(req) -> boolean, deliver(req, value, ctx) -> { ok, note } }`.
 *  - `validate` sees the request metadata only, when the bot asks.
 *  - `deliver` is the ONLY place a value exists, and only as its `value` argument: it must never
 *    assign it to anything that outlives the call, log it, or put it in an error or a note. The
 *    note it returns is a fixed line (plus a label and an entry id), and it is what the bot is told.
 *
 * Shipped: `keychain` and `report-credential`. `browser` is deliberately not registered until bot
 * containment lands (spec §10.5), so a browser request is refused as `bad_target` like any unknown
 * target.
 *
 * `report-credential` is how a report's credentialed source gets its key: the bot spells the binding in
 * the request's label (servers/gateway/reports/steps.js's `parseCredentialSpec`), the operator types the
 * value once, and `deliver` saves it as a keychain row under `crow-reports` and a `report_credentials`
 * row that WAITS for the owner's tap. The bot may only attach a credential to its OWN report, and only
 * for a host that report already has approved.
 */
import { randomUUID } from "node:crypto";
import { keychainKeyState } from "../keychain/key.js";
import { REPORTS_BUNDLE, addManualSecret, disconnectServiceSecrets, saveServiceSecret } from "../keychain/store.js";
import { recordCardSecret, recordServiceSecretValues } from "../../shared/secret-values.js";
import { SECRET_DELIVER_FAILED } from "./request-store.js";
import { getReport } from "../reports/store.js";
import {
  REPORT_CREDENTIAL_ENV_KEY, hostApproved, parseCredentialSpec, proposeCredential,
} from "../reports/steps.js";

export const KEYCHAIN_NOTES = Object.freeze({
  notSetUp: "The keychain isn't set up yet. Nothing was saved.",
  failed: "The password couldn't be saved. Nothing was saved.",
});

/** The fixed success line for a keychain save. */
export function keychainSavedNote(label, id) {
  return `Saved in the keychain as "${label}" (entry ${id}).`;
}

const registry = new Map();

/** Add (or replace) a target. */
export function registerTarget(name, target) {
  if (typeof name !== "string" || !/^[a-z][a-z0-9-]{0,31}$/.test(name)) throw new Error("secret target: bad name");
  if (!target || typeof target.validate !== "function" || typeof target.deliver !== "function") {
    throw new Error("secret target: validate and deliver are required");
  }
  registry.set(name, Object.freeze({ validate: target.validate, deliver: target.deliver }));
}

/** The registered target, or null. */
export function getTarget(name) {
  return (typeof name === "string" && registry.get(name)) || null;
}

export function targetNames() { return [...registry.keys()]; }

export const targets = Object.freeze({ register: registerTarget, get: getTarget, names: targetNames });

/**
 * keychain: stored as a manual keychain entry under the request's label (default
 * "<bot>: password"). It never creates a keychain key: with no key (or a damaged one) the save
 * is refused with a fixed note, so a bot can never set up the operator's keychain by asking.
 * ctx: { db (required), crowHome, audit(db, event, { details }), env (for the masking hashes) }.
 */
registerTarget("keychain", {
  validate(req) {
    return !!req && req.kind === "password";
  },
  async deliver(req, value, ctx = {}) {
    const st = keychainKeyState({ crowHome: ctx.crowHome });
    if (st.state !== "ok") return { ok: false, note: KEYCHAIN_NOTES.notSetUp };
    const label = req.label || `${req.botId}: password`;
    const { id } = await addManualSecret(ctx.db, st.key, { label, secret: value });
    // As the Passwords page does: the hash (never the value) masks it on approval cards.
    try { recordCardSecret(value, ctx.env || (ctx.crowHome ? { ...process.env, CROW_HOME: ctx.crowHome } : process.env)); } catch { /* masking falls back to display paths */ }
    if (typeof ctx.audit === "function") {
      try { await ctx.audit(ctx.db, "keychain_add", { details: { entry_id: id, label, source: "secret_request", bot_id: req.botId } }); } catch { /* an audit miss never undoes a save */ }
    }
    return { ok: true, note: keychainSavedNote(label, id), entryId: id };
  },
});

/**
 * The fixed success line for a report credential. The only new user-facing sentence this target adds:
 * one place, plain words, no dash. It says the credential waits for the owner, because it does: the
 * request only ever proposes the binding.
 */
export const REPORT_CREDENTIAL_SAVED_NOTE = "Saved. The credential waits for your OK on the report page.";

/**
 * The shortest value this target saves. It is the relay's own floor (`INJECT_SECRET_MIN_BYTES` in
 * scripts/pi-bots/pi_egress.mjs, which never injects a shorter value), repeated here rather than
 * imported so the gateway does not load the relay's modules for one number;
 * tests/secrets-report-credential-target.test.js holds the two equal.
 */
export const REPORT_CREDENTIAL_MIN_BYTES = 16;

/**
 * report-credential: a credentialed upstream's key for one report.
 *
 * The request carries no report fields, so the bot's label names the binding and `parseCredentialSpec`
 * is the whole grammar (servers/gateway/reports/steps.js). `validate` sees that label only. `deliver`
 * re-parses it, loads the report, and refuses unless the report belongs to the requesting bot and the
 * host is already approved for that report. It then mints a connection uuid, saves the value as a
 * keychain service row under `crow-reports`, and proposes the credential row: `proposed`, waiting for the
 * owner's tap. Replacing a credential for the same report and host retires the previous keychain row.
 *
 * The value exists only as this function's argument: it is never put in a note, a log line, an error or
 * a database column (the keychain row is sealed under the keychain key). It joins this process's masking
 * set (`recordServiceSecretValues`, which writes only its sha256 to the hidden secrets dir), so a log
 * line this gateway writes afterwards masks it. A proposal that fails after the sealed row was written
 * retires that keychain row, so a refused card leaves no orphan. Every refusal answers one of the
 * fixed lines, so a failure cannot describe what was typed.
 */
registerTarget("report-credential", {
  validate(req) {
    if (!req || typeof req.botId !== "string" || !req.botId) return false;
    return parseCredentialSpec(req.label) != null;
  },
  async deliver(req, value, ctx = {}) {
    const failed = { ok: false, note: SECRET_DELIVER_FAILED };
    const spec = req ? parseCredentialSpec(req.label) : null;
    if (!spec) return failed;
    if (typeof value !== "string" || value === "") return failed;
    // A value the relay would refuse to inject is refused here, before anything is sealed or proposed.
    if (Buffer.byteLength(value, "utf8") < REPORT_CREDENTIAL_MIN_BYTES) return failed;
    const db = ctx.db;
    if (!db) return failed;
    const st = keychainKeyState({ crowHome: ctx.crowHome });
    if (st.state !== "ok") return { ok: false, note: KEYCHAIN_NOTES.notSetUp };
    const report = await getReport(db, spec.reportId);
    // A bot may only attach a credential to its own report.
    if (!report || report.bot_id !== req.botId) return failed;
    const deps = {
      loadSeed: () => st.key.seed,
      loadKeychainKey: () => st.key,
      ...(ctx.crowHome ? { crowHome: ctx.crowHome } : {}),
    };
    // The host must already be one this report has approved; a proposed host is not enough.
    if (!(await hostApproved(db, deps, report.id, spec.host))) return failed;
    const connectionUuid = randomUUID();
    try {
      await saveServiceSecret(db, st.key, {
        connectionUuid,
        bundleId: REPORTS_BUNDLE,
        envKey: REPORT_CREDENTIAL_ENV_KEY,
        label: "report credential",
        secret: value,
      });
      // The value joins the masking set before any path can write it to a log, as the mail connect
      // route does. A recorder that cannot write its file never fails the save or echoes the value:
      // the credential is already sealed, and the display set still masks it in this process.
      try {
        recordServiceSecretValues([value], ctx.env || (ctx.crowHome ? { ...process.env, CROW_HOME: ctx.crowHome } : process.env));
      } catch { /* masking falls back to the display paths */ }
      const proposed = await proposeCredential(db, deps, {
        reportId: report.id,
        host: spec.host,
        connectionUuid,
        inject: spec.inject,
        proposedBy: `bot:${req.botId}`,
      });
      // A binding this one replaces leaves a keychain row nobody may read any more.
      if (proposed && proposed.previousConnectionUuid && proposed.previousConnectionUuid !== connectionUuid) {
        try { await disconnectServiceSecrets(db, proposed.previousConnectionUuid); } catch { /* never fails the save */ }
      }
    } catch {
      // A proposal that fails after the sealed row was written leaves no keychain row behind: the new
      // connection is retired at once, so a refused card never orphans a secret nothing can serve.
      try { await disconnectServiceSecrets(db, connectionUuid); } catch { /* the refusal is the answer */ }
      return failed;
    }
    return { ok: true, note: REPORT_CREDENTIAL_SAVED_NOTE };
  },
});
