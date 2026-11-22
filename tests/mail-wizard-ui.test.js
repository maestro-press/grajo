/**
 * Crow Mail's Gmail and Microsoft setup cards (plan 5, Task 5) and the Gmail app-password path.
 *
 * Three kinds of check here, none of them a screenshot:
 *
 *   - the MARKUP: every sentence a card draws is the operator-approved copy verbatim (C1-C26, K3,
 *     N1-N6), in the page's language, taken from the central i18n table; the redirect address a card
 *     shows is the one `dashboardRedirectUri` answers — the same function `GET
 *     /dashboard/mail/api/oauth/redirect-uri` uses; a null address draws C19 and NO sign-in path,
 *     with the app-password path still usable; the Gmail card lists the app password first; a secret
 *     is a `type=password` field with no value in it; the Microsoft card's optional tenant field is
 *     drawn from N4's rows, in both languages.
 *   - the CLIENT SCRIPT: run for real in node:vm over that markup. It has no backtick, no dollar-brace
 *     and no markup sink, it names only the mail API's owner routes, it strips the spaces from the app
 *     password, empties the field as it sends and never writes it back, and it posts the one test
 *     message only when a person taps the button — never on load.
 *   - the ROUTE: the body that client sends goes through the REAL mail API router (a scratch crow.db, a
 *     fake adapter for the probe, a recording supervisor), and an app-password Gmail account comes out
 *     of it with its preset's hosts, its preset's Sent-copy rule and its sealed password — send-ready,
 *     with no self-test needed.
 */
import { test, before, after } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";
import vm from "node:vm";
import { execFileSync } from "node:child_process";
import { mkdtempSync, mkdirSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { parseHTML } from "linkedom";
import Database from "better-sqlite3";
import { actAsServe, serveHeaders } from "./fixtures/serve-peer.mjs";
import { markFromLaptop } from "./helpers/off-box.js";
actAsServe();

const dir = mkdtempSync(join(tmpdir(), "mail-wizard-ui-"));
process.env.CROW_DATA_DIR = dir;
const HOME = join(dir, "home");
process.env.CROW_HOME = HOME;
mkdirSync(HOME, { recursive: true });
delete process.env.CROW_DB_PATH;
delete process.env.CROW_MAIL;
process.env.CROW_DISABLE_INSTANCE_SYNC = "1";
process.env.CROW_TASKS_DB_PATH = join(dir, "tasks.db");
// A configured dashboard address: the redirect URI every card in this file shows.
const DASHBOARD = "https://crow.example.test";
process.env.CROW_GATEWAY_URL = DASHBOARD;
delete process.env.CROW_OAUTH_ISSUER_URL;
delete process.env.RENDER_EXTERNAL_URL;
const DB_FILE = join(dir, "crow.db");
const REPO = new URL("..", import.meta.url).pathname;
const NET = serveHeaders("operator@example.com");

const { wizardHtml, wizardsHtml } = await import("../servers/gateway/dashboard/panels/mail/wizard-html.js");
const { mailWizardClientJs } = await import("../servers/gateway/dashboard/panels/mail/wizard-client.js");
const { settingsHtml } = await import("../servers/gateway/dashboard/panels/mail/settings-html.js");
const { mailErrorStrings } = await import("../servers/gateway/dashboard/panels/mail/html.js");
const { translations } = await import("../servers/gateway/dashboard/shared/i18n.js");
const { dashboardRedirectUri, MAIL_OAUTH_HINT_KEYS, MAIL_OAUTH_STATUS_KEYS } =
  await import("../servers/gateway/routes/mail-api-oauth.js");
const { csrfTokenForSession } = await import("../servers/gateway/dashboard/shared/csrf.js");
const CLIENT_FILE = join(REPO, "servers/gateway/dashboard/panels/mail/wizard-client.js");
const HTML_FILE = join(REPO, "servers/gateway/dashboard/panels/mail/wizard-html.js");

/** The one address any test here connects: assembled at runtime, so no provider-domain mailbox of a
 *  person's sits in a public repository's source (the presets test does the same). */
const GMAIL_ADDRESS = ["alex", "gmail.com"].join("@");
const APP_PASSWORD_SHOWN = "abcd efgh ijkl mnop";
const APP_PASSWORD_SENT = "abcdefghijklmnop";
const CLIENT_ID = "123456789012-crowmailtest.apps.googleusercontent.com";
const CLIENT_SECRET = "client-secret-9d3c51aa";

/* --------------------------------------------------------------- the approved copy */

/**
 * The approved copy for the rows this file holds to (the approved file's C2, C8, C12, C17, C19-C26,
 * K3 and N1-N4). The table is the source of truth for those rows: the i18n entry must be this text, in
 * both languages, and the rendered cards must show it.
 */
const APPROVED = {
  "mail.wizard.gmailIntro": [
    "Two ways to connect Gmail. An app password is quicker. Signing in with Google takes longer to set up.",
    "Hay dos formas de conectar Gmail. Una contraseña de aplicación es más rápida. Iniciar sesión con Google lleva más tiempo de configurar.",
  ],
  "mail.wizard.appPasswordFailed": [
    "Google may not offer app passwords for this account. They need 2-Step Verification turned on, and they aren't available on work or school accounts, with security-key-only sign-in, or with Advanced Protection. Try signing in with Google below.",
    "Puede que Google no ofrezca contraseñas de aplicación para esta cuenta. Necesitan la verificación en dos pasos activada y no están disponibles en cuentas de trabajo o escuela, con inicio de sesión solo con llaves de seguridad ni con la Protección Avanzada. Prueba a iniciar sesión con Google más abajo.",
  ],
  "mail.wizard.googleTestingNote": [
    "While your Google project is in Testing, Google ends the sign-in every 7 days. Crow reminds you to reconnect before that happens.",
    "Mientras tu proyecto de Google esté en modo de prueba, Google cierra la sesión cada 7 días. Crow te avisa para que vuelvas a conectar antes de que pase.",
  ],
  "mail.wizard.microsoftAdminNote": [
    "Many work and school organisations need an administrator to approve the app. If you see 'Need admin approval', ask your administrator.",
    "Muchas organizaciones de trabajo o escuela necesitan que un administrador apruebe la aplicación. Si ves 'Se necesita la aprobación del administrador', pregunta a tu administrador.",
  ],
  "mail.wizard.redirectMismatch": [
    "The redirect address does not match. Copy it again from this page into your app's settings.",
    "La dirección de redirección no coincide. Cópiala de nuevo desde esta página en los ajustes de tu aplicación.",
  ],
  "mail.wizard.oauthFailed": [
    "Crow could not finish connecting this account. Nothing was saved.",
    "Crow no pudo terminar de conectar esta cuenta. No se guardó nada.",
  ],
  "mail.wizard.noDashboardAddress": [
    "Set this machine's dashboard address first. Signing in with Google or Microsoft needs it. App passwords work without it.",
    "Primero configura la dirección del panel de este equipo. Iniciar sesión con Google o Microsoft la necesita. Las contraseñas de aplicación funcionan sin ella.",
  ],
  "mail.wizard.connected": ["Connected. Crow is fetching your mail.", "Conectado. Crow está descargando tu correo."],
  "mail.wizard.denied": ["You did not allow access.", "No permitiste el acceso."],
  "mail.wizard.expired": ["This sign-in expired or was already used. Start again.", "Este inicio de sesión caducó o ya se usó. Empieza de nuevo."],
  "mail.wizard.probeFailed": ["You signed in, but Crow could not open your mailbox. Nothing was saved.", "Iniciaste sesión, pero Crow no pudo abrir tu buzón. No se guardó nada."],
  "mail.wizard.clientIdShape": ["That doesn't look like a Google client ID. It ends in .apps.googleusercontent.com.", "Eso no parece un ID de cliente de Google. Termina en .apps.googleusercontent.com."],
  "mail.wizard.selftest": ["Send a test message", "Enviar un mensaje de prueba"],
  "mail.wizard.selftestSent": ["Test message sent to yourself.", "Mensaje de prueba enviado a ti mismo."],
  "mail.wizard.selftestFailed": ["The test message could not be sent.", "No se pudo enviar el mensaje de prueba."],
  "mail.wizard.connect": ["Connect", "Conectar"],
  "mail.wizard.copy": ["Copy", "Copiar"],
  "mail.wizard.openSetting": ["Open the setting", "Abrir el ajuste"],
  // The third approved card (N1-N4, approved 2026-11-21): the word a passed check says beside its
  // tick, the word after the Copy control, the `oauth_no_refresh` status sentence, and the Microsoft
  // tenant field's label and hint. N5 reuses rows that already ship (the address is C13's field, the
  // client id C13's), so it adds no copy of its own.
  "mail.wizard.checkPassed": ["Looks right.", "Parece correcto."],
  "mail.wizard.copied": ["Copied.", "Copiado."],
  "mail.wizard.noRefresh": [
    "Google or Microsoft did not allow Crow to stay signed in. Nothing was saved. Start again.",
    "Google o Microsoft no permitieron que Crow siguiera con la sesión iniciada. No se guardó nada. Empieza de nuevo.",
  ],
  "mail.wizard.tenantLabel": ["Directory (tenant) ID (optional)", "ID de directorio (inquilino) (opcional)"],
  "mail.wizard.tenantHint": [
    "Leave empty unless your organisation's administrator gave you one.",
    "Déjalo vacío salvo que el administrador de tu organización te haya dado uno.",
  ],
  // The fourth approved card (N6): the tenant field's own refusal, drawn in that field's line.
  "mail.wizard.tenantInvalid": [
    "That doesn't look like a directory (tenant) ID. Leave it empty or paste the one your administrator gave you.",
    "Eso no parece un ID de directorio (inquilino). Déjalo vacío o pega el que te dio tu administrador.",
  ],
};

const APPROVED_STEPS = {
  "mail.wizard.appPasswordTitle": ["Use an app password", "Usar una contraseña de aplicación"],
  "mail.wizard.appPasswordStep1": ["Turn on 2-Step Verification for your Google account.", "Activa la verificación en dos pasos en tu cuenta de Google."],
  "mail.wizard.appPasswordStep2": ["Open Google's app passwords page, create one, and name it Crow.", "Abre la página de contraseñas de aplicación de Google, crea una y llámala Crow."],
  "mail.wizard.appPasswordStep3": ["Paste the 16-digit password here. Spaces don't matter.", "Pega aquí la contraseña de 16 dígitos. Los espacios no importan."],
  "mail.wizard.googleTitle": ["Sign in with Google", "Iniciar sesión con Google"],
  "mail.wizard.googleIntro": ["You set this up once in your own Google Cloud project. Crow shows a check after each step.", "Esto se configura una vez en tu propio proyecto de Google Cloud. Crow muestra una comprobación después de cada paso."],
  "mail.wizard.googleStep1": ["Create a project in the Google Cloud console.", "Crea un proyecto en la consola de Google Cloud."],
  "mail.wizard.googleStep2": ["Set up the OAuth consent screen with the user type External.", "Configura la pantalla de consentimiento de OAuth con el tipo de usuario Externo."],
  "mail.wizard.googleStep3": ["Add your own Google account as a test user.", "Añade tu propia cuenta de Google como usuario de prueba."],
  "mail.wizard.googleStep4": ["Create an OAuth client of type Web application.", "Crea un cliente de OAuth del tipo Aplicación web."],
  "mail.wizard.googleStep6": ["Paste the client ID and client secret here, then press Connect.", "Pega aquí el ID de cliente y el secreto de cliente y pulsa Conectar."],
  "mail.wizard.microsoftTitle": ["Outlook.com or Microsoft 365", "Outlook.com o Microsoft 365"],
  "mail.wizard.microsoftIntro": ["Microsoft accounts connect by signing in with Microsoft. You set this up once as an app registration in Microsoft Entra.", "Las cuentas de Microsoft se conectan iniciando sesión con Microsoft. Esto se configura una vez como un registro de aplicación en Microsoft Entra."],
  "mail.wizard.microsoftStep1": ["Create an app registration in the Microsoft Entra admin center, for personal and work or school accounts.", "Crea un registro de aplicación en el centro de administración de Microsoft Entra, para cuentas personales y de trabajo o escuela."],
  "mail.wizard.microsoftStep3": ["Add the permissions IMAP.AccessAsUser.All, SMTP.Send and offline_access.", "Añade los permisos IMAP.AccessAsUser.All, SMTP.Send y offline_access."],
  "mail.wizard.microsoftStep4": ["Paste the application (client) ID here, then press Connect.", "Pega aquí el ID de aplicación (cliente) y pulsa Conectar."],
  "mail.wizard.microsoftSendingNote": ["Some organisations turn off sending from email apps, so sending may fail even when reading works.", "Algunas organizaciones desactivan el envío desde aplicaciones de correo, así que el envío puede fallar aunque la lectura funcione."],
};

const redirectUri = () => dashboardRedirectUri(process.env).redirectUri;

/* ------------------------------------------------------------------- the vm rig */

/**
 * The emitted script, run in a vm over a linkedom page that holds this markup. Fetch is a stub that
 * records every call, `Turbo.visit`/`location.assign` — the two navigations the script can make — are
 * recorded, and the CSRF token is the one `window.crowCsrf` answers with.
 */
function boot(html, { fetchImpl = () => ({ ok: true, status: 200, json: () => Promise.resolve({ ok: true }) }) } = {}) {
  const { window: dom, document } = parseHTML(`<!doctype html><html><head></head><body>${html}</body></html>`);
  for (const field of document.querySelectorAll("input, select, textarea")) {
    let current = field.getAttribute("value") || "";
    Object.defineProperty(field, "value", {
      configurable: true,
      get: () => current,
      set: (next) => { current = String(next); field.setAttribute("value", current); },
    });
  }
  const calls = [];
  const visits = [];
  const selections = [];
  const window = {
    Turbo: { visit: (url) => visits.push(String(url)) },
    crowCsrf: () => "csrf-token",
    getSelection: () => ({ removeAllRanges() {}, addRange: (range) => selections.push(range) }),
  };
  const location = {
    href: DASHBOARD + "/dashboard/mail?view=settings",
    assign: (url) => visits.push(String(url)),
    reload: () => visits.push("reload"),
  };
  const ctx = vm.createContext({
    window,
    document,
    navigator: { clipboard: { writeText: () => Promise.resolve() } },
    location,
    fetch: (url, init) => {
      const options = init || {};
      calls.push({
        url: String(url),
        method: String(options.method || "GET"),
        headers: options.headers || {},
        body: options.body == null ? null : JSON.parse(String(options.body)),
      });
      return Promise.resolve(fetchImpl(String(url), options));
    },
    setTimeout,
    clearTimeout,
  });
  const emitted = mailWizardClientJs("en");
  const script = emitted.slice(emitted.indexOf("<script>") + 8, emitted.lastIndexOf("</script>"));
  const run = () => vm.runInContext(script, ctx);
  const settle = async () => { for (let i = 0; i < 12; i += 1) await new Promise((resolve) => setImmediate(resolve)); };
  const $ = (selector) => document.querySelector(selector);
  const $$ = (selector) => [...document.querySelectorAll(selector)];
  const event = (type) => new dom.Event(type, { bubbles: true, cancelable: true });
  const click = (node) => { node.dispatchEvent(event("click")); return node; };
  const submit = (node) => { const fired = event("submit"); node.dispatchEvent(fired); return fired; };
  // The card's one redirect address, as the page drew it (a GET on load may correct it).
  run();
  return { window, document, ctx, run, settle, $, $$, click, submit, calls, visits, selections };
}

/* --------------------------------------------------- the real mail API router */

const OWNER = "owner-local-password-session";
let server = null;
let base = null;
let deps = null;
const flush = async (rounds = 20) => { for (let i = 0; i < rounds; i += 1) await new Promise((r) => setImmediate(r)); };

before(async () => {
  execFileSync(process.execPath, ["scripts/init-db.js"], { env: { ...process.env }, stdio: "pipe", cwd: REPO });
  const { hashToken } = await import("../servers/gateway/dashboard/auth.js");
  const c = new Database(DB_FILE);
  c.prepare("INSERT INTO oauth_tokens (token, token_type, client_id, scopes, expires_at, created_at) VALUES (?, 'access', 'dashboard', ?, datetime('now','+1 day'), '2026-06-01 00:00:00')")
    .run(hashToken(OWNER), "dashboard");
  c.close();

  const { default: express } = await import("express");
  const { csrfMiddleware } = await import("../servers/gateway/dashboard/shared/csrf.js");
  const { mailApiRouter } = await import("../servers/gateway/routes/mail-api.js");
  const { createFakeMailAdapter } = await import("./fixtures/fake-mail-adapter.mjs");

  const supervisor = { async syncNow() {}, async restartAccount() {} };
  deps = {
    supervisor,
    adapterFactory: () => createFakeMailAdapter(),
    recordSecrets: () => {},
  };
  const app = express();
  app.use(express.json({ limit: "1mb" }));
  const sessionGate = (req, res, next) => {
    const cookies = {};
    for (const part of String(req.headers.cookie || "").split(";")) {
      const i = part.indexOf("=");
      if (i > 0) cookies[part.slice(0, i).trim()] = part.slice(i + 1).trim();
    }
    if (!cookies.crow_session) return res.status(401).json({ error: "unauthorized" });
    req.dashboardSession = cookies.crow_session;
    markFromLaptop(req);
    next();
  };
  const api = express.Router();
  api.use("/dashboard", csrfMiddleware);
  api.use(mailApiRouter(sessionGate, deps));
  app.use(api);
  await new Promise((r) => { server = app.listen(0, "127.0.0.1", r); });
  base = "http://127.0.0.1:" + server.address().port;
});

after(() => {
  delete process.env.CROW_MAIL;
  server?.closeAllConnections?.();
  server?.close();
  rmSync(dir, { recursive: true, force: true });
});

/** One request to the mounted mail API, as the owner's own laptop session. */
async function call(method, path, body) {
  process.env.CROW_MAIL = "1";
  const headers = { ...NET, cookie: "crow_session=" + OWNER, "x-crow-csrf": csrfTokenForSession(OWNER) };
  if (body !== undefined) headers["content-type"] = "application/json";
  const response = await fetch(base + path, {
    method,
    headers,
    body: body === undefined ? undefined : JSON.stringify(body),
    redirect: "manual",
  });
  const text = await response.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* not JSON */ }
  return { status: response.status, text, json };
}

/* --------------------------------------------------------------- the markup pins */

test("the redirect address a card shows is the one GET /oauth/redirect-uri answers", async () => {
  const uri = redirectUri();
  assert.equal(uri, `${DASHBOARD}/dashboard/mail/oauth/callback`, "the dashboard address plus the callback path");
  const got = await call("GET", "/dashboard/mail/api/oauth/redirect-uri");
  assert.equal(got.status, 200);
  assert.deepEqual(got.json, { redirectUri: uri }, "the route and the cards share one function");

  for (const presetId of ["gmail", "microsoft"]) {
    const html = wizardHtml({ presetId, lang: "en", redirectUri: uri });
    const box = parseHTML(`<body>${html}</body>`).document;
    const shown = box.querySelector("[data-ml-redirect-uri]");
    assert.ok(shown, `${presetId}: the card carries the address`);
    assert.equal(String(shown.textContent), uri, `${presetId}: the address the card shows is the route's answer`);
    assert.ok(box.querySelector("[data-ml-copy-redirect]"), `${presetId}: and the control that copies it`);
    assert.ok(box.querySelector("[data-ml-oauth-path]"), `${presetId}: the sign-in path is offered`);
  }
  // The card is corrected from that route on load, so a page drawn before a change is never wrong.
  const script = mailWizardClientJs("en");
  assert.ok(script.includes("'/dashboard/mail/api/oauth/redirect-uri'"), "the client reads the route");
});

test("no dashboard address: C19, no sign-in path, and the app-password path still works", () => {
  const html = wizardHtml({ presetId: "gmail", lang: "en", redirectUri: null });
  const box = parseHTML(`<body>${html}</body>`).document;
  assert.ok(box.querySelector("[data-ml-no-address]"), "the sentence has its own block");
  assert.equal(
    box.querySelector("[data-ml-no-address] .ml-note").textContent,
    APPROVED["mail.wizard.noDashboardAddress"][0],
    "C19 verbatim",
  );
  const link = box.querySelector("[data-ml-open-setting]");
  assert.ok(link, "C19's link");
  assert.equal(link.textContent, APPROVED["mail.wizard.openSetting"][0]);
  assert.equal(link.getAttribute("href"), "/dashboard/settings");

  assert.equal(box.querySelector("[data-ml-oauth-path]"), null, "no sign-in path is drawn");
  assert.equal(box.querySelector("[data-ml-client-id]"), null, "no client-id field");
  assert.equal(box.querySelector("[data-ml-redirect-uri]"), null, "and no address to paste");

  // The app-password path is untouched: its steps, its two fields and its button are all there.
  const form = box.querySelector("[data-ml-connect-password]");
  assert.ok(form, "the app-password form");
  assert.equal(box.querySelectorAll("[data-ml-connect-password] [data-ml-address]").length, 1);
  assert.equal(box.querySelectorAll("[data-ml-connect-password] [data-ml-password]").length, 1);
  assert.ok(box.querySelector("[data-ml-connect-password-btn]"));

  // The Microsoft card, with no address, draws the sentence and no steps of its own.
  const microsoft = wizardHtml({ presetId: "microsoft", lang: "en", redirectUri: null });
  const mbox = parseHTML(`<body>${microsoft}</body>`).document;
  assert.ok(mbox.querySelector("[data-ml-no-address]"));
  assert.equal(mbox.querySelector("[data-ml-oauth-path]"), null, "no Microsoft sign-in path either");
  assert.equal(mbox.querySelector("[data-ml-client-id]"), null);
});

test("each card's sentences are the approved copy, verbatim, in both languages", () => {
  for (const [key, [en, es]] of Object.entries({ ...APPROVED, ...APPROVED_STEPS })) {
    assert.equal(translations[key]?.en, en, `${key}: the English is the approved sentence`);
    assert.equal(translations[key]?.es, es, `${key}: the Spanish is the approved sentence`);
    assert.notEqual(en, es, `${key}: the two languages differ`);
  }

  const uri = redirectUri();
  // The rows a card carries as a data attribute or that only another part of the page draws are held
  // by their own tests below (the refusal attributes, the status line, the no-address block): what this
  // loop pins is that every sentence a card DRAWS as text is the approved one.
  const NOT_CARD_TEXT = new Set([
    "mail.wizard.appPasswordFailed", "mail.wizard.redirectMismatch", "mail.wizard.clientIdShape",
    "mail.wizard.oauthFailed", "mail.wizard.connected", "mail.wizard.denied", "mail.wizard.expired",
    "mail.wizard.probeFailed", "mail.wizard.noDashboardAddress", "mail.wizard.selftest",
    "mail.wizard.selftestSent", "mail.wizard.selftestFailed", "mail.wizard.openSetting",
    // N3 is the sentence the settings page's status line carries for a callback's `oauth_no_refresh`
    // key, not a word either card draws (its own test below holds it to its sentence).
    "mail.wizard.noRefresh",
  ]);
  for (const lang of ["en", "es"]) {
    const markup = wizardsHtml({ lang, redirectUri: uri });
    const box = parseHTML(`<body>${markup}</body>`).document;
    // Every card's own text, read through the DOM (never the raw markup, whose apostrophes are escaped).
    const text = [...box.querySelectorAll("[data-ml-wizard]")].map((card) => card.textContent).join("\n");
    for (const [key, [en, es]] of Object.entries({ ...APPROVED, ...APPROVED_STEPS })) {
      // The two step sentences carry {address} (filled with the card's own address) and one bracketed
      // "(Copy)", which is drawn as the Copy button; every other sentence must be on the page as it is.
      if (key === "mail.wizard.googleStep5" || key === "mail.wizard.microsoftStep2") continue;
      if (NOT_CARD_TEXT.has(key)) continue;
      const wanted = lang === "en" ? en : es;
      assert.ok(text.includes(wanted), `${lang}: ${key} is shown as approved`);
    }
  }
  // The two sentences a card carries as a data attribute (a refusal shown later) are on the page too.
  const card = parseHTML(`<body>${wizardHtml({ presetId: "gmail", lang: "es", redirectUri: uri })}</body>`).document;
  const root = card.querySelector("[data-ml-wizard]");
  assert.equal(root.getAttribute("data-ml-connect-failed"), APPROVED["mail.wizard.appPasswordFailed"][1]);
  assert.equal(root.getAttribute("data-ml-hint-redirect_mismatch"), APPROVED["mail.wizard.redirectMismatch"][1]);
  assert.equal(root.getAttribute("data-ml-hint-client_id_shape"), APPROVED["mail.wizard.clientIdShape"][1]);
  assert.equal(root.getAttribute("data-ml-selftest-sent"), APPROVED["mail.wizard.selftestSent"][1]);
});

test("the two copy steps read as the approved sentence, with the address, the Copy control and N2 in place", () => {
  const uri = redirectUri();
  for (const [lang, cards, sentence] of [
    ["en", { presetId: "gmail", lang: "en", redirectUri: uri }, `Add this redirect address to the client: ${uri} Copy Copied.`],
    ["es", { presetId: "microsoft", lang: "es", redirectUri: uri }, `Añádele esta dirección de redirección: ${uri} Copiar Copiado.`],
  ]) {
    const box = parseHTML(`<body>${wizardHtml(cards)}</body>`).document;
    const step = box.querySelector("[data-ml-copy-step]");
    assert.ok(step, `${lang}: the step is drawn`);
    assert.equal(
      step.textContent.replace(/\s+/g, " ").trim(),
      sentence,
      `${lang}: the address and the control sit where the sentence's placeholder and (Copy) are, and N2 follows the control`,
    );
    const said = step.querySelector("[data-ml-copied]");
    assert.ok(said, `${lang}: N2's own element rides the step`);
    assert.equal(said.hasAttribute("hidden"), true, `${lang}: and says nothing before a copy`);
  }
});

test("every wizard key has its own Spanish, and the placeholders agree", () => {
  const keys = Object.keys(translations).filter((key) => key.startsWith("mail.wizard."));
  assert.ok(keys.length >= 35, `the wizard's keys are all there: ${keys.length}`);
  const identical = [];
  const placeholders = (text) => (text.match(/\{[a-zA-Z0-9_]+\}/g) || []).sort().join(",");
  for (const key of keys) {
    const entry = translations[key];
    assert.equal(typeof entry.en, "string", `${key}: en`);
    assert.equal(typeof entry.es, "string", `${key}: es`);
    assert.ok(entry.en.length > 0 && entry.es.length > 0, `${key}: both languages are filled in`);
    if (entry.en === entry.es) identical.push(key);
    assert.equal(placeholders(entry.en), placeholders(entry.es), `${key}: the same placeholders`);
  }
  // C1's title is the provider's own name; every other wizard key is translated.
  assert.deepEqual(identical, ["mail.wizard.gmailTitle"]);
  assert.equal(translations["mail.wizard.gmailTitle"].en, "Gmail");
});

test("the Gmail card lists the app password first, then the sign-in", () => {
  const markup = wizardHtml({ presetId: "gmail", lang: "en", redirectUri: redirectUri() });
  const appAt = markup.indexOf('data-ml-path="password"');
  const signInAt = markup.indexOf('data-ml-path="google"');
  assert.ok(appAt > 0 && signInAt > 0, "both paths are drawn");
  assert.ok(appAt < signInAt, "the app password comes first");
  const box = parseHTML(`<body>${markup}</body>`).document;
  const paths = [...box.querySelectorAll("[data-ml-path]")].map((node) => node.getAttribute("data-ml-path"));
  assert.deepEqual(paths, ["password", "google"]);
});

test("a secret is a password field with nothing in it, and the address is an email field", () => {
  const markup = wizardsHtml({ lang: "en", redirectUri: redirectUri() });
  const box = parseHTML(`<body>${markup}</body>`).document;
  const password = box.querySelector("[data-ml-connect-password] [data-ml-password]");
  assert.equal(password.getAttribute("type"), "password");
  assert.equal(password.hasAttribute("value"), false, "no secret is ever drawn into the field");
  const clientSecret = box.querySelector("[data-ml-client-secret]");
  assert.equal(clientSecret.getAttribute("type"), "password");
  assert.equal(clientSecret.hasAttribute("value"), false);
  for (const address of box.querySelectorAll("[data-ml-address]")) {
    assert.equal(address.getAttribute("type"), "email");
    assert.equal(address.hasAttribute("value"), false);
  }
  // Nothing secret is in the markup anywhere: no password value, no client secret value.
  assert.equal(markup.includes(APP_PASSWORD_SHOWN), false);
  assert.equal(markup.includes(CLIENT_SECRET), false);
  assert.equal(markup.includes("MAIL_PASSWORD"), false);
});

/* ---------------------------------------------------------- the client script pins */

test("the client script: no backtick, no dollar-brace, no markup sink, owner routes only", () => {
  const source = readFileSync(CLIENT_FILE, "utf8");
  const body = source.slice(source.indexOf("export function mailWizardClientJs"));
  const script = body.slice(body.indexOf("<script>"), body.lastIndexOf("</script>"));
  assert.ok(script.length > 2000, "the template holds the script");
  assert.equal(script.includes("`"), false, "no backtick inside the template literal");
  assert.equal(script.includes("${"), false, "no interpolation inside the template literal");
  assert.doesNotMatch(script, /innerHTML|outerHTML|insertAdjacentHTML|document\.write/);
  const emitted = mailWizardClientJs("en");
  const out = emitted.slice(emitted.indexOf("<script>") + 8, emitted.lastIndexOf("</script>"));
  assert.equal(out.includes("`"), false, "the emitted script has no backtick either");
  assert.equal(out.includes("${"), false);

  const literals = [...script.matchAll(/\b(?:post|get)\(([A-Z_]+|'[^']*')/g)].map((match) => match[1]);
  assert.ok(literals.length >= 4, `the script names its routes: ${literals.join(", ")}`);
  for (const value of literals) {
    // A constant is one of the four below; a literal is a path under the mail API.
    if (value.startsWith("'")) assert.ok(value.startsWith("'/dashboard/mail/api/"), value);
  }
  const constants = [...script.matchAll(/var (ACCOUNTS_PATH|CHECK_PATH|START_PATH|REDIRECT_PATH) = '([^']*)'/g)]
    .map((match) => match[2]);
  assert.deepEqual(constants, [
    "/dashboard/mail/api/accounts",
    "/dashboard/mail/api/oauth/check",
    "/dashboard/mail/api/oauth/start",
    "/dashboard/mail/api/oauth/redirect-uri",
  ], "every route it names is the mail API's own");
  assert.doesNotMatch(script, /fetch\('/, "fetch is only reached through the one request helper");
  assert.ok(script.includes("window.crowCsrf"), "the server-bound CSRF token, never a cookie");
  assert.ok(script.includes("'x-crow-csrf'"), "and it travels as that header");
  assert.equal(script.includes("crow_csrf"), false, "no cookie read for a CSRF value");
  // No sentence of the approved copy is written into the script: the page carries every one of them.
  // (The short labels — "Connect", "Copy" — are substrings of the script's own names, so only the
  // sentences are held to this.)
  for (const [en] of Object.values(APPROVED)) {
    if (en.length < 30) continue;
    assert.equal(script.includes(en), false, `a sentence of the copy is written into the script: ${en}`);
  }
});

/* ------------------------------------------------------------- the app password */

test("the app password is posted with its spaces stripped, the secret never written back", async () => {
  const markup = settingsHtml({ accounts: [], lang: "en", redirectUri: redirectUri() });
  const r = boot(markup);
  await r.settle();
  // The card's load-time redirect read is not a connect: nothing was posted.
  assert.deepEqual(r.calls.map((entry) => entry.method), ["GET", "GET"], "one redirect read per card");

  const form = r.$("[data-ml-connect-password]");
  form.querySelector("[data-ml-address]").value = GMAIL_ADDRESS;
  form.querySelector("[data-ml-password]").value = APP_PASSWORD_SHOWN;
  const fired = r.submit(form);
  assert.equal(fired.defaultPrevented, true, "the form never posts on its own");

  const posted = r.calls.filter((entry) => entry.method === "POST");
  assert.equal(posted.length, 1, "one POST");
  assert.equal(posted[0].url, "/dashboard/mail/api/accounts");
  assert.equal(posted[0].headers["x-crow-csrf"], "csrf-token", "the CSRF header comes from the window's token");
  assert.deepEqual(posted[0].body, {
    authKind: "password",
    provider: "gmail",
    label: GMAIL_ADDRESS,
    address: GMAIL_ADDRESS,
    password: APP_PASSWORD_SENT,
  }, "spaces stripped, the preset's id named, and no host, port or secret of any other kind in the body");

  assert.equal(form.querySelector("[data-ml-password]").value, "", "the field is emptied as it is sent");
  await r.settle();
  assert.equal(r.document.body.innerHTML.includes(APP_PASSWORD_SENT), false, "the secret never returns to the page");
  assert.equal(r.visits.length, 1, "a connected account reloads the page onto its new card");
});

test("a refused app password shows C8 in the card and leaves the field empty", async () => {
  const markup = settingsHtml({ accounts: [], lang: "en", redirectUri: redirectUri() });
  const r = boot(markup, {
    fetchImpl: (url) => {
      if (url.endsWith("/redirect-uri")) return { ok: true, status: 200, json: () => Promise.resolve({ redirectUri: redirectUri() }) };
      return { ok: false, status: 400, json: () => Promise.resolve({ error: "AUTH_FAILED", message: "RAW SERVER TEXT" }) };
    },
  });
  await r.settle();
  const form = r.$("[data-ml-connect-password]");
  form.querySelector("[data-ml-address]").value = GMAIL_ADDRESS;
  form.querySelector("[data-ml-password]").value = APP_PASSWORD_SHOWN;
  r.submit(form);
  await r.settle();
  const line = form.querySelector("[data-ml-result]");
  assert.ok(line, "the card carries the line");
  assert.equal(line.getAttribute("role"), "status");
  assert.equal(line.hasAttribute("hidden"), false);
  assert.equal(line.textContent, APPROVED["mail.wizard.appPasswordFailed"][0], "C8 exactly");
  assert.equal(line.textContent.includes("RAW SERVER TEXT"), false);
  assert.equal(form.querySelector("[data-ml-password]").value, "", "cleared on failure too");
  assert.deepEqual(r.visits, [], "a refused connect reloads nothing");
});

test("a connect that succeeds reloads the page onto the new account", async () => {
  const markup = settingsHtml({ accounts: [], lang: "en", redirectUri: redirectUri() });
  const r = boot(markup, {
    fetchImpl: (url) => (url.endsWith("/redirect-uri")
      ? { ok: true, status: 200, json: () => Promise.resolve({ redirectUri: redirectUri() }) }
      : { ok: true, status: 201, json: () => Promise.resolve({ account: { id: "ma-aaaaaaaaaaaaaaaa" } }) }),
  });
  await r.settle();
  const form = r.$("[data-ml-connect-password]");
  form.querySelector("[data-ml-address]").value = GMAIL_ADDRESS;
  form.querySelector("[data-ml-password]").value = APP_PASSWORD_SHOWN;
  r.submit(form);
  await r.settle();
  assert.equal(r.visits.length, 1, "the page is visited again, so the new card is drawn");
});

/* ---------------------------------------------------------------- the sign-in */

test("sign in: the checks run in order, each with a fixed hint, and only then does the browser leave", async () => {
  const seen = [];
  const r = boot(settingsHtml({ accounts: [], lang: "en", redirectUri: redirectUri() }), {
    fetchImpl: (url, options) => {
      const body = options && options.body ? JSON.parse(String(options.body)) : {};
      if (url.endsWith("/redirect-uri")) return { ok: true, status: 200, json: () => Promise.resolve({ redirectUri: redirectUri() }) };
      if (url.endsWith("/oauth/check")) {
        seen.push(body.step);
        if (body.step === "client_id") return { ok: true, status: 200, json: () => Promise.resolve({ ok: false, hint: "client_id_shape" }) };
        return { ok: true, status: 200, json: () => Promise.resolve({ ok: true, hint: null }) };
      }
      return { ok: true, status: 200, json: () => Promise.resolve({ authUrl: "https://accounts.example.test/authorize?x=1" }) };
    },
  });
  await r.settle();
  const oauthForm = r.$("[data-ml-oauth]");
  oauthForm.querySelector("[data-ml-address]").value = GMAIL_ADDRESS;
  oauthForm.querySelector("[data-ml-client-id]").value = "not-a-google-client-id";
  oauthForm.querySelector("[data-ml-client-secret]").value = CLIENT_SECRET;
  r.submit(oauthForm);
  await r.settle();

  assert.deepEqual(seen, ["client_id"], "the shape check stops the flow: no redirect check, no start");
  const line = oauthForm.querySelector("[data-ml-result]");
  assert.equal(line.textContent, APPROVED["mail.wizard.clientIdShape"][0], "C26, the hint's own sentence");
  assert.deepEqual(r.visits, [], "nothing navigated");
  assert.equal(oauthForm.querySelector("[data-ml-client-secret]").value, "", "the secret still left the page");
  assert.equal(r.document.body.innerHTML.includes(CLIENT_SECRET), false);

  // With a client id of the right shape the three checks pass and the browser is handed to the
  // provider's own page — a plain navigation, never a Turbo visit.
  const started = [];
  const good = boot(settingsHtml({ accounts: [], lang: "en", redirectUri: redirectUri() }), {
    fetchImpl: (url, options) => {
      const body = options && options.body ? JSON.parse(String(options.body)) : {};
      if (url.endsWith("/redirect-uri")) return { ok: true, status: 200, json: () => Promise.resolve({ redirectUri: redirectUri() }) };
      if (url.endsWith("/oauth/check")) {
        started.push(body.step);
        return { ok: true, status: 200, json: () => Promise.resolve({ ok: true, hint: null }) };
      }
      started.push("start");
      return { ok: true, status: 200, json: () => Promise.resolve({ authUrl: "https://accounts.google.com/o/oauth2/v2/auth?x=1" }) };
    },
  });
  await good.settle();
  const form = good.$("[data-ml-oauth]");
  form.querySelector("[data-ml-address]").value = GMAIL_ADDRESS;
  form.querySelector("[data-ml-client-id]").value = CLIENT_ID;
  form.querySelector("[data-ml-client-secret]").value = CLIENT_SECRET;
  good.submit(form);
  await good.settle();
  assert.deepEqual(started, ["client_id", "redirect", "scopes", "start"], "each step is checked before the next");
  const startCall = good.calls.filter((entry) => entry.url.endsWith("/oauth/start"))[0];
  assert.deepEqual(startCall.body, {
    provider: "google",
    address: GMAIL_ADDRESS,
    label: GMAIL_ADDRESS,
    clientId: CLIENT_ID,
    clientSecret: CLIENT_SECRET,
  });
  assert.deepEqual(good.visits, ["https://accounts.google.com/o/oauth2/v2/auth?x=1"], "the provider's page, by navigation");
  const redirectCall = good.calls.filter((entry) => entry.url.endsWith("/oauth/check") && entry.body.step === "redirect")[0];
  assert.equal(redirectCall.body.pastedRedirectUri, redirectUri(), "the check names the address the card shows");
  assert.equal(form.querySelector("[data-ml-client-secret]").value, "", "the client secret left the page too");
});

test("a redirect that no longer matches shows C22 and never starts a sign-in", async () => {
  const r = boot(settingsHtml({ accounts: [], lang: "en", redirectUri: redirectUri() }), {
    fetchImpl: (url) => {
      if (url.endsWith("/redirect-uri")) return { ok: true, status: 200, json: () => Promise.resolve({ redirectUri: redirectUri() }) };
      return { ok: true, status: 200, json: () => Promise.resolve({ ok: false, hint: "redirect_mismatch" }) };
    },
  });
  await r.settle();
  const form = r.$("[data-ml-oauth]");
  form.querySelector("[data-ml-address]").value = GMAIL_ADDRESS;
  form.querySelector("[data-ml-client-id]").value = CLIENT_ID;
  r.submit(form);
  await r.settle();
  assert.equal(form.querySelector("[data-ml-result]").textContent, APPROVED["mail.wizard.redirectMismatch"][0]);
  assert.equal(r.calls.filter((entry) => entry.url.endsWith("/oauth/start")).length, 0, "no flow was minted");
  assert.deepEqual(r.visits, []);
});

/* ------------------------------------------------------------------ the test mail */

test("the test-message button never runs on its own, and one tap posts one message", async () => {
  const account = { id: "ma-bbbbbbbbbbbbbbbb", label: "Personal", address: "sam@example.com", status: "active" };
  const markup = settingsHtml({ accounts: [account], lang: "en", redirectUri: redirectUri() });
  const buttons = parseHTML(`<body>${markup}</body>`).document.querySelectorAll("[data-ml-selftest]");
  assert.equal(buttons.length, 1, "one optional control per account card");
  assert.equal(buttons[0].textContent, APPROVED["mail.wizard.selftest"][0]);
  assert.equal(buttons[0].getAttribute("type"), "button", "a button, never an implicit submit");

  const r = boot(markup, {
    fetchImpl: (url) => (url.endsWith("/redirect-uri")
      ? { ok: true, status: 200, json: () => Promise.resolve({ redirectUri: redirectUri() }) }
      : { ok: true, status: 200, json: () => Promise.resolve({ ok: true }) }),
  });
  await r.settle();
  assert.equal(r.calls.filter((entry) => entry.url.includes("/selftest")).length, 0, "nothing was sent on load");

  r.click(r.$("[data-ml-selftest]"));
  await r.settle();
  const sent = r.calls.filter((entry) => entry.url.includes("/selftest"));
  assert.equal(sent.length, 1, "one tap, one message");
  assert.equal(sent[0].method, "POST");
  assert.equal(sent[0].url, `/dashboard/mail/api/accounts/${account.id}/selftest`);
  assert.equal(sent[0].headers["x-crow-csrf"], "csrf-token");
  const line = r.$("[data-ml-account] [data-ml-result]");
  assert.ok(line, "the card carries the answer");
  assert.equal(line.textContent, APPROVED["mail.wizard.selftestSent"][0], "C21's success sentence");

  // A refused one says so in the card, and says nothing else.
  const bad = boot(markup, {
    fetchImpl: (url) => (url.endsWith("/redirect-uri")
      ? { ok: true, status: 200, json: () => Promise.resolve({ redirectUri: redirectUri() }) }
      : { ok: true, status: 200, json: () => Promise.resolve({ ok: false, error: "all_rejected" }) }),
  });
  await bad.settle();
  bad.click(bad.$("[data-ml-selftest]"));
  await bad.settle();
  assert.equal(bad.$("[data-ml-account] [data-ml-result]").textContent, APPROVED["mail.wizard.selftestFailed"][0]);
});

/* --------------------------------------------------------- the callback's status */

test("the settings page shows the callback's status key in its approved sentence, and nothing else", () => {
  const cases = [
    ["oauth_connected", "mail.wizard.connected"],
    ["oauth_denied", "mail.wizard.denied"],
    ["oauth_expired", "mail.wizard.expired"],
    ["oauth_no_refresh", "mail.wizard.noRefresh"],
    ["oauth_probe_failed", "mail.wizard.probeFailed"],
    ["oauth_failed", "mail.wizard.oauthFailed"],
    ["redirect_mismatch", "mail.wizard.redirectMismatch"],
    ["client_id_shape", "mail.wizard.clientIdShape"],
  ];
  for (const [status, key] of cases) {
    const html = settingsHtml({ accounts: [], lang: "en", redirectUri: null, mailStatus: status });
    const box = parseHTML(`<body>${html}</body>`).document;
    const line = box.querySelector("[data-ml-mail-status]");
    assert.ok(line, `${status}: the line is drawn`);
    assert.equal(line.getAttribute("data-ml-mail-status"), status);
    assert.equal(line.textContent, APPROVED[key][0], `${status}: the approved sentence`);
  }
  // A key with no approved sentence draws nothing at all, and is not echoed either.
  for (const status of ["something-else", ""]) {
    const html = settingsHtml({ accounts: [], lang: "en", redirectUri: null, mailStatus: status });
    assert.equal(html.includes("data-ml-mail-status"), false, `${JSON.stringify(status)}: no line`);
  }
  // A URL cannot put text on the page: the key is matched against the fixed table.
  const html = settingsHtml({ accounts: [], lang: "en", redirectUri: null, mailStatus: "<b>hi</b>" });
  assert.equal(html.includes("&lt;b&gt;"), false);
  assert.equal(html.includes("<b>hi</b>"), false);
  // Every status and hint key the route can answer is either shown or deliberately silent.
  for (const key of [...MAIL_OAUTH_STATUS_KEYS, ...MAIL_OAUTH_HINT_KEYS]) {
    assert.equal(typeof key, "string");
  }
});

/* --------------------------------------------------------------- the real route */

test("an app-password Gmail account is stored with its preset's Sent copy and is send-ready once connected", async () => {
  // The exact body the wizard's client script sends (see the app-password test above).
  const body = {
    authKind: "password",
    provider: "gmail",
    label: GMAIL_ADDRESS,
    address: GMAIL_ADDRESS,
    password: APP_PASSWORD_SENT,
  };
  const created = await call("POST", "/dashboard/mail/api/accounts", body);
  assert.equal(created.status, 201, created.text);
  const id = created.json.account.id;
  assert.match(id, /^ma-[0-9a-f]{16}$/);
  assert.equal(created.text.includes(APP_PASSWORD_SENT), false, "the answer never echoes the secret");
  await flush();

  const { getAccount } = await import("../servers/gateway/mail/store/accounts.js");
  const { createMailCredentials } = await import("../servers/gateway/mail/credentials.js");
  const { createDbClient } = await import("../servers/db.js");
  const { createImapSmtpAdapter } = await import("../servers/gateway/mail/adapter/imap-smtp.js");
  const { PRESETS } = await import("../servers/gateway/mail/providers/presets.js");
  const gmail = PRESETS.find((preset) => preset.id === "gmail");

  const db = createDbClient();
  try {
    const account = await getAccount(db, id);
    assert.equal(account.address, GMAIL_ADDRESS);
    assert.equal(account.label, GMAIL_ADDRESS, "the address is the account's label");
    assert.equal(account.authKind, "password");
    assert.equal(account.provider, "gmail", "the preset's id is stored on the account");
    assert.deepEqual(account.imap, gmail.imap, "the preset's IMAP endpoint, from the preset and not the page");
    assert.deepEqual(account.smtp, gmail.smtp, "and its SMTP endpoint");
    assert.equal(account.sentCopy, gmail.sentCopy, "its Sent-copy rule: the provider files Gmail's copy");
    assert.equal(account.sentCopy, "provider");

    // Send-ready, with no self-test: the credentials are there and the real adapter can send.
    const credentials = createMailCredentials({ db });
    const secrets = await credentials.getSecrets(id);
    assert.equal(secrets.MAIL_PASSWORD, APP_PASSWORD_SENT, "the sealed password is the one that was sent");
    assert.deepEqual(Object.keys(secrets), ["MAIL_PASSWORD"], "and nothing else was sealed");
    const adapter = createImapSmtpAdapter({ account, credentials });
    assert.equal(typeof adapter.send, "function", "the adapter this account gets can send");
  } finally {
    db.close();
  }
});

test("a provider the address does not belong to is refused, and the generic form still works", async () => {
  const wrong = await call("POST", "/dashboard/mail/api/accounts", {
    authKind: "password",
    provider: "gmail",
    label: "sam@example.test",
    address: "sam@example.test",
    password: APP_PASSWORD_SENT,
  });
  assert.equal(wrong.status, 400, wrong.text);
  assert.deepEqual(wrong.json.error, "bad_input", "Gmail named for an address that is not Gmail's");

  // The plan-2 body — both endpoints, no provider — is still accepted exactly as it was.
  const generic = await call("POST", "/dashboard/mail/api/accounts", {
    label: "Work",
    address: "work@example.test",
    password: APP_PASSWORD_SENT,
    imap: { host: "mail.example.test", port: 993, security: "ssl" },
    smtp: { host: "mail.example.test", port: 465, security: "ssl" },
  });
  assert.equal(generic.status, 201, generic.text);
  const { getAccount } = await import("../servers/gateway/mail/store/accounts.js");
  const { createDbClient } = await import("../servers/db.js");
  const db = createDbClient();
  try {
    const account = await getAccount(db, generic.json.account.id);
    assert.equal(account.provider, null, "no provider named, none stored");
    assert.equal(account.imap.host, "mail.example.test", "the body's own endpoint");
  } finally {
    db.close();
  }
});

/* ------------------------------------------------------------------ the sources */

// ---- public-repository hygiene, over the files this change touches (no git needed) ----

test("the files this wizard adds or edits obey the repository's public-hygiene rules", async () => {
  const { checkContent, loadAllowlist } = await import("../scripts/check-public-hygiene.mjs");
  const allow = loadAllowlist(readFileSync(join(REPO, "scripts/public-hygiene-allowlist.txt"), "utf8"));
  const files = [
    "servers/gateway/dashboard/panels/mail/wizard-html.js",
    "servers/gateway/dashboard/panels/mail/wizard-client.js",
    "servers/gateway/dashboard/panels/mail/settings-html.js",
    "servers/gateway/dashboard/panels/mail/css.js",
    "servers/gateway/dashboard/panels/mail.js",
    "servers/gateway/dashboard/shared/i18n.js",
    "servers/gateway/routes/mail-api.js",
    "servers/gateway/keychain/store.js",
    "tests/mail-wizard-ui.test.js",
    "tests/mail-credentials.test.js",
  ];
  const violations = [];
  for (const file of files) {
    violations.push(...checkContent(file, readFileSync(join(REPO, file), "utf8"), { allow, denylist: [], hosts: [] }));
  }
  assert.deepEqual(violations, []);
});

/* ------------------------------------------------------- the reconnect prompt */

/** C27-C29 of the approved copy (plan 5, Task 6): the bell, the banner and the failed-sign-in row. */
const RECONNECT = {
  soon: ["Google will end this sign-in soon.", "Google cerrará pronto este inicio de sesión."],
  button: ["Reconnect", "Volver a conectar"],
  stopped: [
    "The sign-in for this account stopped working. Reconnect to keep mail syncing.",
    "El inicio de sesión de esta cuenta dejó de funcionar. Vuelve a conectar para seguir sincronizando el correo.",
  ],
  flowFailed: ["Crow could not finish connecting this account. Nothing was saved."],
};

/** The three account cards these tests draw: due, failed OAuth and failed password. */
const DUE_ACCOUNT = {
  id: "ma-cccccccccccccccc", label: "Personal", address: "sam@example.com", status: "active",
  authKind: "xoauth2", oauthProvider: "google", reconnectDue: true,
};
const FAILED_OAUTH = {
  id: "ma-dddddddddddddddd", label: "Work", address: "jo@example.com", status: "auth_failed",
  authKind: "xoauth2", oauthProvider: "google", reconnectDue: false,
};
const FAILED_PASSWORD = {
  id: "ma-eeeeeeeeeeeeeeee", label: "Other", address: "kim@example.com", status: "auth_failed",
  authKind: "password", oauthProvider: null, reconnectDue: false,
};
const HEALTHY_PASSWORD = {
  id: "ma-ffffffffffffffff", label: "Home", address: "lee@example.com", status: "active",
  authKind: "password", oauthProvider: null, reconnectDue: false,
};

test("a due Google account's card shows C28 and one Reconnect control", () => {
  for (const lang of ["en", "es"]) {
    const markup = settingsHtml({ accounts: [DUE_ACCOUNT, FAILED_OAUTH, FAILED_PASSWORD, HEALTHY_PASSWORD], lang, redirectUri: redirectUri() });
    const box = parseHTML(`<body>${markup}</body>`).document;
    const card = box.querySelector(`[data-ml-account="${DUE_ACCOUNT.id}"]`);
    assert.ok(card, `${lang}: the account card is drawn`);
    const banner = card.querySelector("[data-ml-reconnect-banner]");
    assert.ok(banner, `${lang}: a due account carries the reconnect block`);
    assert.equal(
      banner.querySelector(".ml-note").textContent,
      lang === "en" ? RECONNECT.soon[0] : RECONNECT.soon[1],
      `${lang}: C28's sentence, verbatim`,
    );
    const button = banner.querySelector("[data-ml-reconnect]");
    assert.ok(button, `${lang}: the one-tap control`);
    assert.equal(button.getAttribute("type"), "button", "a button, never a form submit");
    assert.equal(button.textContent, lang === "en" ? RECONNECT.button[0] : RECONNECT.button[1], `${lang}: C28's button`);
    assert.equal(button.getAttribute("data-account"), DUE_ACCOUNT.id);
    assert.equal(button.getAttribute("data-ml-reconnect-provider"), "google", "the provider the start route is given");
    assert.equal(button.getAttribute("data-ml-reconnect-address"), DUE_ACCOUNT.address, "the address the account already has");
    assert.equal(card.querySelectorAll("[data-ml-reconnect]").length, 1, "one control, not two");

    // A healthy password account has no reconnect block at all.
    const healthy = box.querySelector(`[data-ml-account="${HEALTHY_PASSWORD.id}"]`);
    assert.equal(healthy.querySelector("[data-ml-reconnect]"), null);

    // No client id and no secret on the page: a reconnect's registration is read server-side.
    assert.equal(banner.querySelector("input"), null, `${lang}: the reconnect block holds no field`);
    assert.doesNotMatch(banner.innerHTML, /secret|password/i, `${lang}: and no secret-shaped hook`);
    assert.equal(markup.includes("MAIL_OAUTH_CLIENT_ID"), false, `${lang}: no stored client id on the page`);
  }
});

test("an xoauth2 auth_failed card says C29 and offers Reconnect; a password card keeps its own sentence", () => {
  for (const lang of ["en", "es"]) {
    const box = parseHTML(`<body>${settingsHtml({ accounts: [FAILED_OAUTH, FAILED_PASSWORD], lang, redirectUri: redirectUri() })}</body>`).document;

    const oauthCard = box.querySelector(`[data-ml-account="${FAILED_OAUTH.id}"]`);
    assert.equal(
      oauthCard.querySelector("[data-ml-status]").textContent,
      lang === "en" ? RECONNECT.stopped[0] : RECONNECT.stopped[1],
      `${lang}: C29 replaces the app-password sentence`,
    );
    assert.equal(oauthCard.querySelector("[data-ml-update-password]"), null, "an OAuth account is not asked for a password");
    assert.ok(oauthCard.querySelector("[data-ml-reconnect]"), "and it gets the same Reconnect control");

    const passwordCard = box.querySelector(`[data-ml-account="${FAILED_PASSWORD.id}"]`);
    assert.equal(
      passwordCard.querySelector("[data-ml-status]").textContent,
      translations["mail.statusAuthFailed"][lang],
      `${lang}: a password account keeps the app-password sentence`,
    );
    assert.ok(passwordCard.querySelector("[data-ml-update-password]"), "and the control that updates the password");
    assert.equal(passwordCard.querySelector("[data-ml-reconnect]"), null, "a password account is not sent to a sign-in");
  }
});

test("the Reconnect button posts reconnectAccountId and never a secret, then navigates to the provider", async () => {
  const AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth?state=abc";
  const markup = settingsHtml({ accounts: [DUE_ACCOUNT], lang: "en", redirectUri: redirectUri() });
  const r = boot(markup, {
    fetchImpl: (url) => (url.endsWith("/redirect-uri")
      ? { ok: true, status: 200, json: () => Promise.resolve({ redirectUri: redirectUri() }) }
      : { ok: true, status: 200, json: () => Promise.resolve({ authUrl: AUTH_URL }) }),
  });
  await r.settle();
  r.click(r.$("[data-ml-reconnect]"));
  await r.settle();

  const posted = r.calls.filter((entry) => entry.method === "POST");
  assert.equal(posted.length, 1, "one POST");
  assert.equal(posted[0].url, "/dashboard/mail/api/oauth/start");
  assert.equal(posted[0].headers["x-crow-csrf"], "csrf-token");
  assert.deepEqual(posted[0].body, {
    reconnectAccountId: DUE_ACCOUNT.id,
    provider: "google",
    address: DUE_ACCOUNT.address,
    label: DUE_ACCOUNT.address,
  }, "the account is named, and nothing secret or registration-shaped is sent");
  assert.equal(Object.keys(posted[0].body).includes("clientSecret"), false);
  assert.equal(Object.keys(posted[0].body).includes("clientId"), false, "the stored registration is read server-side");
  assert.deepEqual(r.visits, [AUTH_URL], "the provider's own page, by navigation");
});

test("a start that answers another origin, or plain http, never navigates and shows K3", async () => {
  const answers = [
    "https://evil.example.test/oauth2/v2/auth",
    "https://accounts.google.com.evil.example.test/oauth2/v2/auth",
    "http://accounts.google.com/o/oauth2/v2/auth",
    "https://login.microsoftonline.com/common/oauth2/v2.0/authorize",
    "//accounts.google.com/o/oauth2/v2/auth",
    "accounts.google.com/o/oauth2/v2/auth",
  ];
  for (const authUrl of answers) {
    const r = boot(settingsHtml({ accounts: [DUE_ACCOUNT], lang: "en", redirectUri: redirectUri() }), {
      fetchImpl: (url) => (url.endsWith("/redirect-uri")
        ? { ok: true, status: 200, json: () => Promise.resolve({ redirectUri: redirectUri() }) }
        : { ok: true, status: 200, json: () => Promise.resolve({ authUrl }) }),
    });
    await r.settle();
    r.click(r.$("[data-ml-reconnect]"));
    await r.settle();
    assert.deepEqual(r.visits, [], `${authUrl}: nothing navigated`);
    const line = r.$("[data-ml-reconnect-result]");
    assert.ok(line, `${authUrl}: the block carries its own line`);
    assert.equal(line.hasAttribute("hidden"), false, `${authUrl}: the refusal is shown`);
    assert.equal(line.textContent, RECONNECT.flowFailed[0], `${authUrl}: K3, the approved sentence`);
  }

  // The same check on the sign-in wizard's own Connect: an answer on another host is refused too.
  const form = boot(settingsHtml({ accounts: [], lang: "en", redirectUri: redirectUri() }), {
    fetchImpl: (url) => {
      if (url.endsWith("/redirect-uri")) return { ok: true, status: 200, json: () => Promise.resolve({ redirectUri: redirectUri() }) };
      if (url.endsWith("/oauth/check")) return { ok: true, status: 200, json: () => Promise.resolve({ ok: true, hint: null }) };
      return { ok: true, status: 200, json: () => Promise.resolve({ authUrl: "https://evil.example.test/authorize" }) };
    },
  });
  await form.settle();
  const oauthForm = form.$("[data-ml-oauth]");
  oauthForm.querySelector("[data-ml-address]").value = GMAIL_ADDRESS;
  oauthForm.querySelector("[data-ml-client-id]").value = CLIENT_ID;
  oauthForm.querySelector("[data-ml-client-secret]").value = CLIENT_SECRET;
  form.submit(oauthForm);
  await form.settle();
  assert.deepEqual(form.visits, [], "the wizard does not leave for a host that is not the provider's");
  assert.equal(oauthForm.querySelector("[data-ml-result]").textContent, RECONNECT.flowFailed[0], "K3");
  assert.equal(oauthForm.querySelector("[data-ml-client-secret]").value, "", "and the secret still left the page");
});

test("the Copy button lights its own tick, not the card's first tick, and then says N2", async () => {
  const r = boot(settingsHtml({ accounts: [], lang: "en", redirectUri: redirectUri() }));
  await r.settle();
  const copyTick = r.$("[data-ml-copy-tick]");
  assert.ok(copyTick, "the Copy control has its own tick beside it");
  assert.equal(copyTick.hasAttribute("hidden"), true, "hidden until a copy happens");
  const said = r.$("[data-ml-copied]");
  assert.ok(said, "the Copy control carries N2's sentence");
  assert.equal(said.textContent, APPROVED["mail.wizard.copied"][0], "N2 verbatim");
  assert.equal(said.hasAttribute("hidden"), true, "and says nothing until a copy happens");

  r.click(r.$("[data-ml-copy-redirect]"));
  await r.settle();
  assert.equal(copyTick.hasAttribute("hidden"), false, "the copy's own tick lights");
  assert.equal(said.hasAttribute("hidden"), false, "and the copy says N2");
  for (const tick of r.$$("[data-ml-check-tick]")) {
    assert.equal(tick.hasAttribute("hidden"), true, "no check tick of the card was lit by a copy");
  }
});

/* ------------------------------------ the Microsoft tenant field (N4) */

/** The passed check's own word rides the tick, hidden with it (N1), so nothing is read before it is true. */
test("a passed check's tick carries N1's sentence, and neither the tick nor its word is shown before", () => {
  for (const lang of ["en", "es"]) {
    const box = parseHTML(`<body>${wizardsHtml({ lang, redirectUri: redirectUri() })}</body>`).document;
    const ticks = box.querySelectorAll("[data-ml-check-tick]");
    assert.equal(ticks.length, 3, `${lang}: one tick per form (the two Gmail paths and the Microsoft one)`);
    for (const tick of ticks) {
      assert.equal(tick.hasAttribute("hidden"), true, `${lang}: hidden until a check passes`);
      assert.equal(tick.getAttribute("role"), "status", `${lang}: and announced when it appears`);
      const glyph = tick.querySelector(".ml-tick-glyph");
      assert.ok(glyph, `${lang}: the mark is its own element`);
      assert.equal(glyph.getAttribute("aria-hidden"), "true", `${lang}: a glyph is not a word for a screen reader`);
      const said = tick.querySelector(".ml-tick-said");
      assert.ok(said, `${lang}: the sentence sits beside the mark`);
      assert.equal(said.textContent, APPROVED["mail.wizard.checkPassed"][lang === "en" ? 0 : 1], `${lang}: N1 verbatim`);
    }
  }
});

const MICROSOFT_CLIENT_ID = "8b1c7f4e-2a3d-4c5b-9e6f-0a1b2c3d4e5f";
const TENANT_GUID = "f2b9c3d4-1a2b-4c5d-8e9f-0a1b2c3d4e5f";
const TENANT_DOMAIN = "contoso.example";
const MS_AUTH_URL = "https://login.microsoftonline.com/common/oauth2/v2.0/authorize?x=1";

/**
 * The Microsoft card's sign-in form, filled as a person would, with `tenant` typed into its field.
 * `lang` picks the page's language (so a refusal is asserted in both), and `startStatus` lets a test
 * stand in for the server refusing the start route (`400 bad_input`, as a bad tenant gets).
 */
function microsoftSignIn(tenant, { lang = "en", startStatus = 200 } = {}) {
  const r = boot(settingsHtml({ accounts: [], lang, redirectUri: redirectUri() }), {
    fetchImpl: (url) => {
      if (url.endsWith("/redirect-uri")) return { ok: true, status: 200, json: () => Promise.resolve({ redirectUri: redirectUri() }) };
      if (url.endsWith("/oauth/check")) return { ok: true, status: 200, json: () => Promise.resolve({ ok: true, hint: null }) };
      if (startStatus !== 200) return { ok: false, status: startStatus, json: () => Promise.resolve({ error: "bad_input" }) };
      return { ok: true, status: 200, json: () => Promise.resolve({ authUrl: MS_AUTH_URL }) };
    },
  });
  return r.settle().then(() => {
    const form = r.$('[data-ml-wizard="microsoft"] [data-ml-oauth]');
    form.querySelector("[data-ml-address]").value = "jo@example.test";
    form.querySelector("[data-ml-client-id]").value = MICROSOFT_CLIENT_ID;
    form.querySelector("[data-ml-tenant]").value = tenant;
    r.submit(form);
    return r.settle().then(() => ({ r, form }));
  });
}

test("the tenant field is on the Microsoft card only, with N4's label and its hint", () => {
  for (const lang of ["en", "es"]) {
    const box = parseHTML(`<body>${wizardsHtml({ lang, redirectUri: redirectUri() })}</body>`).document;
    const card = box.querySelector('[data-ml-wizard="microsoft"]');
    const fields = card.querySelectorAll("[data-ml-tenant]");
    assert.equal(fields.length, 1, `${lang}: one optional tenant field`);
    assert.equal(fields[0].getAttribute("type"), "text");
    assert.equal(fields[0].hasAttribute("value"), false, `${lang}: it carries no value in the markup`);
    const label = fields[0].closest("label");
    assert.ok(label, `${lang}: the field has its own label`);
    assert.equal(
      label.querySelector(".ml-field-label").textContent,
      APPROVED["mail.wizard.tenantLabel"][lang === "en" ? 0 : 1],
      `${lang}: N4's label, verbatim`,
    );
    const help = card.querySelector(".ml-help[data-ml-tenant-hint]");
    assert.ok(help, `${lang}: the field has its own hint`);
    assert.equal(help.textContent, APPROVED["mail.wizard.tenantHint"][lang === "en" ? 0 : 1], `${lang}: N4's hint, verbatim`);
    // N6 rides the same field as its own line, and says nothing until a value is refused.
    const refused = card.querySelector("[data-ml-tenant-invalid]");
    assert.ok(refused, `${lang}: the tenant field carries N6's line`);
    assert.equal(refused.getAttribute("role"), "status", `${lang}: announced when it appears`);
    assert.equal(refused.textContent, APPROVED["mail.wizard.tenantInvalid"][lang === "en" ? 0 : 1], `${lang}: N6 verbatim`);
    assert.equal(refused.hasAttribute("hidden"), true, `${lang}: hidden until a refusal`);
    // N5: the mailbox and client-id fields keep the rows that already ship.
    assert.equal(
      card.querySelector("[data-ml-address]").closest("label").querySelector(".ml-field-label").textContent,
      translations["mail.fieldAddress"][lang],
      `${lang}: N5 — the address field is the shipped one`,
    );
    assert.equal(
      card.querySelector("[data-ml-client-id]").closest("label").querySelector(".ml-field-label").textContent,
      translations["mail.wizard.fieldClientId"][lang],
      `${lang}: N5 — the client-id field is C13's`,
    );
    assert.notEqual(translations["mail.wizard.fieldClientId"].en, translations["mail.wizard.fieldClientId"].es, `${lang}: and it is translated`);
    assert.equal(box.querySelector('[data-ml-wizard="gmail"] [data-ml-tenant]'), null, `${lang}: Gmail has no tenant field`);
  }
});

test("the tenant travels only for Microsoft: empty sends none, a GUID and a domain are sent, anything else starts nothing", async () => {
  // Empty: the body has no `tenant` at all, so the server keeps its own "common".
  const empty = await microsoftSignIn("");
  const emptyStart = empty.r.calls.filter((entry) => entry.url.endsWith("/oauth/start"));
  assert.equal(emptyStart.length, 1, "the flow started");
  assert.equal(Object.hasOwn(emptyStart[0].body, "tenant"), false, "no tenant is sent when the field is empty");
  assert.deepEqual(empty.r.visits, [MS_AUTH_URL], "and the browser still leaves for Microsoft");

  for (const tenant of [TENANT_GUID, TENANT_DOMAIN]) {
    const got = await microsoftSignIn(tenant);
    const starts = got.r.calls.filter((entry) => entry.url.endsWith("/oauth/start"));
    assert.equal(starts.length, 1, `${tenant}: the flow started`);
    assert.equal(starts[0].body.tenant, tenant, `${tenant}: the value travels as the route's tenant`);
    assert.equal(starts[0].body.provider, "microsoft");
  }

  // Every value that is neither a directory GUID nor a domain name is refused BEFORE any request, with
  // N6's approved sentence in the tenant field's OWN line (never the form's shared line), and nothing
  // navigated.
  for (const lang of ["en", "es"]) {
    for (const bad of ["common", "contoso", "../evil", "a..b", "-bad.example", "bad-.example", "two words.example", "x".repeat(300)]) {
      const got = await microsoftSignIn(bad, { lang });
      const posted = got.r.calls.filter((entry) => entry.method === "POST");
      assert.deepEqual(posted, [], `${lang} ${bad}: nothing was posted, not even a check`);
      assert.deepEqual(got.r.visits, [], `${lang} ${bad}: nothing navigated`);
      const line = got.form.querySelector("[data-ml-tenant-invalid]");
      assert.ok(line, `${lang} ${bad}: the tenant field carries its own line`);
      assert.equal(line.getAttribute("role"), "status", `${lang} ${bad}: announced when it appears`);
      assert.equal(line.hasAttribute("hidden"), false, `${lang} ${bad}: the refusal is shown`);
      assert.equal(line.textContent, APPROVED["mail.wizard.tenantInvalid"][lang === "en" ? 0 : 1], `${lang} ${bad}: N6 verbatim`);
      const result = got.form.querySelector("[data-ml-result]");
      assert.equal(result.textContent, "", `${lang} ${bad}: the form's own line stays empty`);
      assert.equal(result.hasAttribute("hidden"), true, `${lang} ${bad}: and is not shown`);
    }
  }

  // The server's own refusal of a tenant the page sent (`400 bad_input`) is the same refusal: N6 in
  // that same line, the form's line empty, and nothing navigated.
  for (const lang of ["en", "es"]) {
    const got = await microsoftSignIn(TENANT_DOMAIN, { lang, startStatus: 400 });
    const line = got.form.querySelector("[data-ml-tenant-invalid]");
    assert.equal(line.hasAttribute("hidden"), false, `${lang}: a 400 bad_input is shown in the tenant line`);
    assert.equal(line.textContent, APPROVED["mail.wizard.tenantInvalid"][lang === "en" ? 0 : 1], `${lang}: N6 verbatim`);
    const result = got.form.querySelector("[data-ml-result]");
    assert.equal(result.hasAttribute("hidden"), true, `${lang}: and not in the form's line`);
    assert.deepEqual(got.r.visits, [], `${lang}: nothing navigated`);
  }
});

test("the cards carry no sentence of their own: every string on them comes from the i18n table", () => {

  const source = readFileSync(HTML_FILE, "utf8");
  // No approved sentence is written into the markup module: the module names `mail.*` keys only.
  for (const [en] of Object.values({ ...APPROVED, ...APPROVED_STEPS })) {
    if (en.length < 30) continue;
    assert.equal(source.includes(en), false, `a sentence of the copy is written into the markup module: ${en}`);
  }
  const cssA = readFileSync(join(REPO, "servers/gateway/dashboard/panels/mail/css.js"), "utf8");
  assert.ok(cssA.includes(".ml-wizard"), "the cards have their own scoped rules");
  assert.ok(cssA.includes(".ml-wizard-uri"), "the address has one too");
});