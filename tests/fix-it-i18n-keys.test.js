/**
 * The Fix-it copy lives in the i18n table now, not in the card renderer.
 *
 * Two guards:
 *   1. every key the contract names is in `translations` with the exact English
 *      (so the rendered Nest markup cannot change) and with the exact
 *      operator-approved Spanish; and no entry anywhere in the table still
 *      carries the old placeholder — a card string without approved Spanish
 *      throws while the i18n module loads;
 *   2. servers/gateway/fix-it/index.js holds no user-facing Fix-it string as a
 *      literal any more: they all come from t().
 *   3. the {placeholders} a card fills in are the same set in both languages.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { join } from "node:path";

import { translations, t } from "../servers/gateway/dashboard/shared/i18n.js";

const REPO = join(import.meta.dirname, "..");

/** The contract's i18n table, verbatim. */
const TABLE = {
  "fixit.notNow": "Not now",
  "fixit.comingSoon": "Coming soon",
  "fixit.technicalDetails": "Technical details",
  "fixit.capability": "Capability:",
  "fixit.requestingInstance": "Requesting instance:",
  "fixit.caddyfile": "Caddyfile:",
  "fixit.thingsNoticed": "Things Crow noticed",
  "fixit.fix": "Fix",
  "fixit.open": "Open",
  "fixit.flash.fixed": "Done — it's shared now.",
  "fixit.flash.done": "Done.",
  "fixit.flash.dismissed": "Dismissed for now.",
  "fixit.flash.error": "Couldn't apply that fix.",
  "fixit.flash.notPending": "That card isn't open any more — nothing was changed.",
  "fixit.flash.ownerOnly": "Only the owner, signed in on this Crow, can do that.",
  "fixit.flash.alreadyRestarting": "This add-on is already restarting. Give it a few minutes.",
  "fixit.flash.needsKey": "set {key} on the Extensions card first",
  "fixit.flash.needsKeyGeneric": "set the key on the Extensions card first",
  "fixit.flash.unwalled": "Done. {id} now runs without its wall on this computer. You can wall it again on its page under Extensions.",
  "fixit.flash.unwalledGeneric": "Done. That add-on now runs without its wall on this computer. You can wall it again on its page under Extensions.",
  "fixit.addonWall.title": "An add-on could not run inside its wall",
  "fixit.addonWall.why": "{id} {reason}. It stays off until you choose.",
  "fixit.addonWall.stale": "This failure is from before Crow last restarted; start the add-on again to see whether it still fails",
  "fixit.addonWall.keepOff": "Keep it off",
  "fixit.addonWall.unwall": "Run {id} without the wall",
};

/** The operator-approved Spanish, row for row with the table above. */
const TABLE_ES = {
  "fixit.notNow": "Ahora no",
  "fixit.comingSoon": "Próximamente",
  "fixit.technicalDetails": "Detalles técnicos",
  "fixit.capability": "Capacidad:",
  "fixit.requestingInstance": "Instancia que lo pide:",
  "fixit.caddyfile": "Caddyfile:",
  "fixit.thingsNoticed": "Cosas que Crow notó",
  "fixit.fix": "Arreglar",
  "fixit.open": "Abrir",
  "fixit.flash.fixed": "Listo: ya está compartido.",
  "fixit.flash.done": "Listo.",
  "fixit.flash.dismissed": "Descartado por ahora.",
  "fixit.flash.error": "No se pudo aplicar esa corrección.",
  "fixit.flash.notPending": "Esa tarjeta ya no está abierta: no se cambió nada.",
  "fixit.flash.ownerOnly": "Solo el propietario, con la sesión iniciada en este Crow, puede hacer eso.",
  "fixit.flash.alreadyRestarting": "Este complemento ya se está reiniciando. Dale unos minutos.",
  "fixit.flash.needsKey": "primero configura {key} en la tarjeta de Extensiones",
  "fixit.flash.needsKeyGeneric": "primero configura la clave en la tarjeta de Extensiones",
  "fixit.flash.unwalled": "Listo. {id} ahora se ejecuta sin su aislamiento en este equipo. Puedes volver a aislarlo en su página, en Extensiones.",
  "fixit.flash.unwalledGeneric": "Listo. Ese complemento ahora se ejecuta sin su aislamiento en este equipo. Puedes volver a aislarlo en su página, en Extensiones.",
  "fixit.addonWall.title": "Un complemento no pudo ejecutarse dentro de su aislamiento",
  "fixit.addonWall.why": "{id} {reason}. Seguirá apagado hasta que decidas.",
  "fixit.addonWall.stale": "Este fallo es de antes del último reinicio de Crow; vuelve a iniciar el complemento para ver si sigue fallando",
  "fixit.addonWall.keepOff": "Mantenerlo apagado",
  "fixit.addonWall.unwall": "Ejecutar {id} sin aislamiento",
};

test("every contract key is in the translations table with the exact English", () => {
  const missing = [];
  for (const [key, en] of Object.entries(TABLE)) {
    const entry = translations[key];
    if (!entry || typeof entry.en !== "string") { missing.push(key); continue; }
    assert.equal(entry.en, en, `translations["${key}"].en must stay byte-identical to the rendered copy`);
    assert.equal(t(key, "en"), en, `t("${key}", "en")`);
  }
  assert.deepEqual(missing, [], "i18n keys the contract names that are not in servers/gateway/dashboard/shared/i18n.js");
});

test("Spanish is the approved copy, key for key", () => {
  assert.deepEqual(Object.keys(TABLE_ES), Object.keys(TABLE),
    "the approved Spanish table must name every contract key, in the same order");
  for (const [key, es] of Object.entries(TABLE_ES)) {
    const got = translations[key]?.es;
    assert.equal(typeof got, "string", `translations["${key}"].es must exist`);
    assert.equal(got, es, `translations["${key}"].es must be the operator-approved Spanish`);
    assert.equal(t(key, "es"), es, `t("${key}", "es")`);
  }
});

test("no translation in the table still carries the old placeholder", () => {
  const pending = Object.entries(translations)
    .filter(([, entry]) => Object.values(entry).some((value) => (
      typeof value === "string" && value.startsWith("ES-PENDING")
    )))
    .map(([key]) => key);
  assert.deepEqual(pending, [],
    'every en/es value must be real copy: no translation may start with "ES-PENDING"');
});

test("each Fix-it card fills the same {placeholders} in English and in Spanish", () => {
  const placeholders = (text) => [...new Set(text.match(/\{[a-zA-Z0-9_]+\}/g) || [])].sort();
  for (const key of Object.keys(TABLE)) {
    assert.deepEqual(placeholders(translations[key].en), placeholders(translations[key].es),
      `${key}: placeholder sets differ between en ("${translations[key].en}") and es ("${translations[key].es}")`);
  }
});

/** The file without its comments, so a comment that names a phrase is not a literal. */
function withoutComments(source) {
  return source
    .replace(/\/\*[\s\S]*?\*\//g, "")
    .replace(/(^|[^:])\/\/[^\n]*/g, "$1");
}

test("fix-it/index.js holds no user-facing Fix-it string as a literal", () => {
  const src = withoutComments(readFileSync(join(REPO, "servers/gateway/fix-it", "index.js"), "utf8"));
  const literals = [
    ["Not now", "fixit.notNow"],
    ["Technical details", "fixit.technicalDetails"],
    ["Capability:", "fixit.capability"],
    ["Requesting instance:", "fixit.requestingInstance"],
    ["Caddyfile:", "fixit.caddyfile"],
    ["Things Crow noticed", "fixit.thingsNoticed"],
    ["Coming soon", "fixit.comingSoon"],
  ];
  for (const [literal, key] of literals) {
    assert.equal(src.includes(literal), false,
      `servers/gateway/fix-it/index.js still carries the literal "${literal}" — it must come from t("${key}", lang)`);
  }
});