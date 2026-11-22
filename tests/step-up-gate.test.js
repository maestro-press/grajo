/**
 * The shared dashboard step-up gate.
 *
 * The gate is one object per process, reached by the keychain and by the Trading panel's Connect
 * flow. It wraps the keychain's existing re-auth gate, so what is new here is: the TOTP code is
 * the only method when 2FA is on, a code that was already accepted is never accepted again, and
 * the one instance every caller asks for is the same instance.
 *
 * Every secret and every code in here is synthetic. The fake dependencies answer the gate; the
 * real TOTP reader is only asked whether it reports the matched counter as a number.
 */
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { rmScratch } from "./helpers/safe-rm.js";

const HOME = mkdtempSync(join(tmpdir(), "crow-step-up-gate-home-"));
process.env.CROW_HOME = HOME;
process.env.CROW_DATA_DIR = HOME;

const SYNTHETIC_SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP";
const NOW_MS = 1_700_000_000_000;
const FIFTEEN_MINUTES_MS = 15 * 60 * 1000;

const { createStepUpGate, sharedStepUpGate } = await import("../servers/gateway/dashboard/step-up.js");

after(() => {
  try {
    rmScratch(HOME);
  } catch {
    // already gone
  }
});

// ---- the per-session lockout ------------------------------------------------------------------

test("test_step_up_lockout_after_5_wrong", async () => {
  let nowMs = NOW_MS;
  let step = null; // null means "the code matches no time step at all"
  const gate = createStepUpGate({
    now: () => nowMs,
    is2faEnabled: async () => true,
    hasDashboardPassword: async () => true,
    verifyDashboardPassword: async () => true,
    getTotpSecret: async () => SYNTHETIC_SECRET,
    verifyTotpStep: async () => step,
  });

  assert.equal(await gate.method(), "totp", "with 2FA on only a code counts, never the password");

  const token = "session-a";
  const wrong = [];
  for (let i = 0; i < 5; i += 1) wrong.push(await gate.verify(token, { totp_code: "000000" }));
  assert.equal(wrong.every((result) => result.ok === false), true, "no wrong code is taken");
  assert.equal(
    wrong.slice(0, 4).every((result) => result.locked !== true),
    true,
    "the first four are ordinary refusals",
  );
  assert.equal(wrong[4].locked === true, false, "the fifth wrong code is the one that arms the lock");

  const locked = await gate.verify(token, { totp_code: "000000" });
  assert.equal(locked.ok, false);
  assert.equal(locked.locked, true, "a fifth wrong code locks that session");
  assert.ok(
    Number(locked.locked_until) > nowMs + FIFTEEN_MINUTES_MS - 60 * 1000,
    "the lock lasts fifteen minutes",
  );
  assert.equal(typeof locked.error, "string");
  assert.equal(locked.error.includes("000000"), false, "the refusal repeats no code");

  const otherSession = await gate.verify("session-b", { totp_code: "000000" });
  assert.equal(otherSession.locked === true, false, "another session is not the locked one");

  nowMs += FIFTEEN_MINUTES_MS + 1000;
  step = 5_500_000;
  const recovered = await gate.verify(token, { totp_code: "123456" });
  assert.equal(recovered.ok, true, "the session works again once the lock has run out");
});

// ---- the instance-wide ceiling ----------------------------------------------------------------

test("test_step_up_global_lockout_20", async () => {
  let step = null;
  const gate = createStepUpGate({
    now: () => NOW_MS,
    is2faEnabled: async () => true,
    hasDashboardPassword: async () => false,
    getTotpSecret: async () => SYNTHETIC_SECRET,
    verifyTotpStep: async () => step,
  });

  // One wrong code each from twenty different sessions: no session reaches its own five.
  for (let i = 0; i < 20; i += 1) {
    const result = await gate.verify(`session-${i}`, { totp_code: "000000" });
    assert.equal(result.ok, false);
    assert.equal(result.locked === true, false, `session-${i}: its own five are not reached`);
  }

  step = 5_500_000; // a code that would otherwise be taken
  const blocked = await gate.verify("session-fresh", { totp_code: "123456" });
  assert.equal(blocked.ok, false, "twenty failures lock the whole instance");
  assert.equal(blocked.locked, true);
  assert.equal(blocked.global, true, "the ceiling, not a session, is what refused");
  assert.ok(Number(blocked.locked_until) > NOW_MS, "the instance lock has an end");
  assert.equal(String(blocked.error).includes("123456"), false, "the refusal repeats no code");
});

// ---- the replay guard -------------------------------------------------------------------------

test("test_same_totp_twice_second_refused", async () => {
  let step = 5_500_000;
  const gate = createStepUpGate({
    now: () => NOW_MS,
    is2faEnabled: async () => true,
    hasDashboardPassword: async () => false,
    getTotpSecret: async () => SYNTHETIC_SECRET,
    verifyTotpStep: async () => step,
  });

  const first = await gate.verify("session-a", { totp_code: "123456" });
  assert.equal(first.ok, true, "the first use of the code is taken");

  const replay = await gate.verify("session-a", { totp_code: "123456" });
  assert.equal(replay.ok, false, "the same code a second time is refused");

  const replayElsewhere = await gate.verify("session-b", { totp_code: "123456" });
  assert.equal(replayElsewhere.ok, false, "the same time step is refused on another session too");

  step += 1;
  const later = await gate.verify("session-a", { totp_code: "654321" });
  assert.equal(later.ok, true, "a later time step is accepted");
});

// ---- a Connect code proves the owner without leaving a keychain grant --------------------------

test("test_connect_step_up_creates_no_keychain_grant", async () => {
  let step = 7_000_000;
  const gate = createStepUpGate({
    now: () => NOW_MS,
    is2faEnabled: async () => true,
    hasDashboardPassword: async () => true,
    getTotpSecret: async () => SYNTHETIC_SECRET,
    verifyTotpStep: async () => step,
  });

  // A Connect (or Disconnect) asks the same gate for a code, but the code it gets is not the
  // keychain's grant: nothing is left open for reveal, copy, export or delete afterwards.
  const connect = await gate.verify("session-connect", { totp_code: "123456", grant: false });
  assert.equal(connect.ok, true, "the code is still checked and still accepted");
  assert.equal(connect.method, "totp");
  assert.equal(gate.isGranted("session-connect"), false, "a Connect code leaves no keychain grant");
  assert.equal(gate.expiresAt("session-connect"), null, "and no expiry to read either");

  step += 1;
  const keychain = await gate.verify("session-keychain", { totp_code: "654321" });
  assert.equal(keychain.ok, true);
  assert.equal(gate.isGranted("session-keychain"), true, "the default still grants, so the keychain is unchanged");

  // The replay guard is the gate's, whatever the grant option says.
  const replay = await gate.verify("session-other", { totp_code: "654321", grant: false });
  assert.equal(replay.ok, false, "a step already accepted is refused");
  assert.equal(gate.isGranted("session-other"), false);

  // So is the failure counting: five wrong codes still lock that session, grant or not.
  const failing = createStepUpGate({
    now: () => NOW_MS,
    is2faEnabled: async () => true,
    hasDashboardPassword: async () => false,
    getTotpSecret: async () => SYNTHETIC_SECRET,
    verifyTotpStep: async () => null,
  });
  for (let i = 0; i < 5; i += 1) {
    const result = await failing.verify("session-fail", { totp_code: "000000", grant: false });
    assert.equal(result.ok, false, "a wrong code is never taken");
  }
  const locked = await failing.verify("session-fail", { totp_code: "000000", grant: false });
  assert.equal(locked.locked, true, "five wrong codes lock the session, grant or not");
  assert.equal(failing.isGranted("session-fail"), false);
});

// ---- one number: the login form and the step-up gate share the replay guard -------------------

test("test_login_code_then_step_up_replay_refused", async () => {
  let step = 8_000_000;
  const gate = createStepUpGate({
    now: () => NOW_MS,
    is2faEnabled: async () => true,
    hasDashboardPassword: async () => true,
    getTotpSecret: async () => SYNTHETIC_SECRET,
    verifyTotpStep: async () => step,
  });

  // A code the sign-in form accepted is spent for the gate too: one time step, one number.
  assert.equal(await gate.acceptLoginCode("123456", SYNTHETIC_SECRET), true, "the sign-in form takes it");
  const replayed = await gate.verify("session-a", { totp_code: "123456" });
  assert.equal(replayed.ok, false, "the same step cannot go on to step up a write");
  assert.equal(gate.isGranted("session-a"), false, "and no grant came of the refusal");

  // The other way round: a step the gate accepted is not the sign-in form's to use again.
  step += 1;
  const stepped = await gate.verify("session-b", { totp_code: "654321" });
  assert.equal(stepped.ok, true);
  assert.equal(await gate.acceptLoginCode("654321", SYNTHETIC_SECRET), false, "the sign-in form refuses a used step");

  // A later step is a fresh code for either of them, and the sign-in form leaves no grant.
  step += 1;
  assert.equal(await gate.acceptLoginCode("111111", SYNTHETIC_SECRET), true, "a later step is accepted again");
  assert.equal(gate.isGranted("session-a"), false, "the sign-in form itself grants nothing");
  assert.equal(await gate.acceptLoginCode("111111", SYNTHETIC_SECRET), false, "the same step a second time is refused");

  // A code matching no step at all is a refusal that records nothing.
  const noStep = createStepUpGate({
    now: () => NOW_MS,
    is2faEnabled: async () => true,
    hasDashboardPassword: async () => true,
    getTotpSecret: async () => SYNTHETIC_SECRET,
    verifyTotpStep: async () => null,
  });
  assert.equal(await noStep.acceptLoginCode("000000", SYNTHETIC_SECRET), false);
  assert.equal(await noStep.acceptLoginCode("000000", ""), false, "a missing secret is a refusal, not a throw");

  // The process-wide login check is the shared gate's own, so a restart-free process has one
  // replay state rather than two.
  const module = await import("../servers/gateway/dashboard/step-up.js");
  assert.equal(typeof module.verifyLoginTotp, "function", "the sign-in form's 2FA check is exported");
  assert.equal(typeof sharedStepUpGate().acceptLoginCode, "function", "the shared gate can take a login code");
});

// ---- the real reader answers the matched counter ----------------------------------------------

test("test_verify_totp_step_matches_verify_totp", async () => {
  const OTPAuth = await import("otpauth");
  const { verifyTotp, verifyTotpStep } = await import("../servers/gateway/dashboard/totp.js");

  const secret = new OTPAuth.Secret({ size: 20 }).base32;
  const reader = new OTPAuth.TOTP({
    issuer: "Crow",
    label: "Crow's Nest",
    algorithm: "SHA1",
    digits: 6,
    period: 30,
    secret: OTPAuth.Secret.fromBase32(secret),
  });
  const code = reader.generate();
  const wrongCode = code === "000000" ? "111111" : "000000";

  const matched = verifyTotpStep(code, secret);
  assert.equal(Number.isInteger(matched), true, "a matching code answers the time-step counter");
  const counterNow = Math.floor(Date.now() / 1000 / 30);
  assert.ok(Math.abs(matched - counterNow) <= 1, "the counter is the one at now, within the window");
  assert.equal(verifyTotp(code, secret), true, "verifyTotp still takes the same code");
  assert.equal(verifyTotpStep(wrongCode, secret), null, "a code matching no step answers null");

  assert.equal(verifyTotpStep("", secret), null);
  assert.equal(verifyTotpStep(undefined, secret), null);
  assert.equal(verifyTotpStep(code, null), null);
  assert.equal(verifyTotpStep(code, ""), null, "a missing secret is a refusal, not a throw");
});

// ---- one gate per process, and every caller reaches it ----------------------------------------

test("test_default_verify_step_up_uses_shared_gate", async () => {
  const first = sharedStepUpGate();
  const second = sharedStepUpGate();
  assert.equal(first, second, "one gate per process");
  assert.equal(typeof first.verify, "function");

  const keychainApi = await import("../servers/gateway/keychain/api.js");
  assert.equal(
    keychainApi.defaultReauthGate(),
    first,
    "the keychain's default gate is the shared one",
  );

  const { createConnectRoutes } = await import("../bundles/coinbase/panel/connect.js");
  const db = { execute: async () => ({ rows: [] }) };
  const routes = createConnectRoutes({
    db,
    crowHome: HOME,
    engineClientFactory: () => null,
    authMiddleware: (_req, _res, next) => next(),
  });
  assert.equal(typeof routes.getStepUpGate, "function", "the routes lend their gate out to a test");
  assert.equal(await routes.getStepUpGate(), first, "the panel's default is the shared gate too");
});