/**
 * The browser block's operator-approved copy (approved 2026-11-19; the install consent
 * message and the guide copy were re-approved 2026-11-20 for item 67; the card's version
 * sentence was approved 2026-11-21) is byte-exact wherever it lands: the Fix-it card's
 * COPY object (EN + ES), the install consent message in the bundle manifest (its final
 * passage — the relay-gate copy approved for item 67), the turn-end paragraph of the guide
 * (EN + ES), and the guide's limits list. The strings below are the approved text; the
 * files must equal them character for character — no smart quotes, no re-wrapped words, no
 * paraphrase. `{running}` and `{new}` are the card's placeholders: the detector fills them
 * with the real versions and the stored card never carries a brace.
 *
 * Nothing here touches ~/.crow: the detector module is imported read-only, and the
 * manifest and guides are read from this checkout.
 */
import { test, describe } from "node:test";
import assert from "node:assert/strict";
import { readFileSync, readdirSync, statSync } from "node:fs";
import { join, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const ROOT = join(dirname(fileURLToPath(import.meta.url)), "..");

const APPROVED = {
  title: {
    en: "The browser add-on is still running the old version",
    es: "El complemento del navegador sigue ejecutando la versión anterior",
  },
  body: {
    en: "Crow updated the browser add-on, but the copy that is running is still the old one. Restart it to load the update. A restart cannot be undone, and the pages that are open in the browser now will close. Saved logins and cookies are kept.",
    es: "Crow actualizó el complemento del navegador, pero la copia que está en marcha sigue siendo la anterior. Reinícialo para cargar la actualización. Un reinicio no se puede deshacer, y las páginas que están abiertas ahora en el navegador se cerrarán. Los inicios de sesión y las cookies guardados se conservan.",
  },
  restartAction: {
    en: "Restart the browser add-on",
    es: "Reiniciar el complemento del navegador",
  },
  openExtensions: {
    en: "Open Extensions",
    es: "Abrir Extensiones",
  },
  // approved 2026-11-21: ONE sentence, naming the version that is running and the one an
  // update would install. The placeholders are substituted before the card is stored.
  versionKnown: {
    en: "Running now: version {running}. The update would install version {new}.",
    es: "En marcha ahora: versión {running}. La actualización instalaría la versión {new}.",
  },
  versionUnknown: {
    en: "Running now: an earlier version that does not report its number. The update would install version {new}.",
    es: "En marcha ahora: una versión anterior que no indica su número. La actualización instalaría la versión {new}.",
  },
};

// approved 2026-11-20 for item 67.
const APPROVED_CONSENT = {
  en: "Crow's own browser tools refuse private and local-network addresses (loopback, LAN, tailnet, link-local, cloud metadata) unless you list an exception in CROW_BROWSER_ALLOW_PRIVATE. This is a rule enforced on the browser's own requests, not a network wall: requests made by a page's background workers and some real-time connections are best effort. If a tool process dies and no other Crow browser tool is connected, the browser blocks every request from the pages it left open and then closes them. Between tools' turns the browser is empty and your own browsing in the viewer is not restricted by this rule, and a program that holds the control key is not limited by it.",
  es: "Las herramientas de navegador de Crow rechazan las direcciones privadas y de red local (loopback, LAN, tailnet, link-local, metadatos de la nube) salvo que indiques una excepción en CROW_BROWSER_ALLOW_PRIVATE. Es una regla aplicada a las solicitudes del propio navegador, no un muro de red: las solicitudes de los procesos en segundo plano de una página y algunas conexiones en tiempo real se bloquean solo en la medida de lo posible. Si un proceso de herramienta se detiene de forma inesperada y no hay otra herramienta de navegador de Crow conectada, el navegador bloquea todas las solicitudes de las páginas que dejó abiertas y luego las cierra. Entre un turno de herramientas y el siguiente, el navegador queda vacío y tu propia navegación en el visor no está limitada por esta regla, y un programa que tenga la clave de control tampoco queda limitado por ella.",
};

// approved 2026-11-20 for item 67.
const APPROVED_TURN_END = {
  en: "When a bot's turn ends, Crow sends every page in the browser to a blank page, waits until it is blank, and then closes it, leaving one empty page. This includes tabs you opened yourself, so nothing a bot opened keeps running and Back cannot bring it back. Cookies and saved logins are kept.",
  es: "Cuando termina el turno de un bot, Crow lleva cada página del navegador a una página en blanco, espera a que quede en blanco y luego la cierra, y deja una sola página vacía. Esto incluye las pestañas que abriste tú, así que nada de lo que abrió un bot sigue en marcha y el botón Atrás no puede recuperarlo. Las cookies y los inicios de sesión guardados se conservan.",
};

/**
 * The approved limits-list strings, in plain text (no markdown). `C` is the pair of
 * standalone sentences under the list; `D` is the relay bullet, the new cleanup bullet,
 * and the ending of the existing WebRTC bullet.
 */
const APPROVED_C = [
  {
    label: "C EN 1",
    lang: "en",
    text: "Between bot turns the browser holds one empty page and the gate lets requests through, so what you browse by hand in the viewer is not checked against the private-address rule.",
  },
  {
    label: "C EN 2",
    lang: "en",
    text: "Shared and service workers are closed rather than guarded, so pages that need them (some web apps) do not work in the bot browser. If you reopen a page a bot visited (a closed tab, typed history), it loads as any page you open yourself.",
  },
  {
    label: "C ES 1",
    lang: "es",
    text: "Entre los turnos del bot, el navegador tiene una sola página vacía y la puerta deja pasar las solicitudes, de modo que lo que navegues a mano en el visor no se comprueba contra la regla de direcciones privadas.",
  },
  {
    label: "C ES 2",
    lang: "es",
    text: "Los workers compartidos y los service workers se cierran en lugar de vigilarse, así que las páginas que los necesitan (algunas aplicaciones web) no funcionan en el navegador del bot. Si vuelves a abrir una página que visitó un bot (una pestaña cerrada, el historial escrito), se carga como cualquier página que abras tú mismo.",
  },
];

const APPROVED_D = [
  {
    label: "D relay EN",
    lang: "en",
    text: "Cleaned up by the relay, not by the tool. Since 1.9.0 the browser container's relay, not the MCP, does this cleanup: when a Crow browser tool's process goes away (a crash, SIGKILL, a segfault, the OOM killer) the relay fails every request from each page that tool left open and then closes those pages. If another Crow browser tool is still connected, those pages stay open under that tool's rule until it finishes, and then they are closed. A page whose tool has not yet installed its rule is in the same state and is treated the same way: /json/version shows Crow-Guard: gate/1 while the gate is running, and crow_browser_status reports it as gate. The cost of that stop path: a recycle can sign the browser out of sites you logged into since the last clean close, and you lose crash-restore of your own tabs.",
  },
  {
    label: "D relay ES",
    lang: "es",
    text: "La limpieza la hace el relay, no la herramienta. Desde 1.9.0 esa limpieza la ejecuta el relay del contenedor del navegador, no el MCP: cuando el proceso de una herramienta de navegador de Crow desaparece (un fallo, SIGKILL, un segfault, el OOM killer), el relay hace fallar todas las solicitudes de cada página que esa herramienta dejó abierta y luego cierra esas páginas. Si otra herramienta de navegador de Crow sigue conectada, esas páginas siguen abiertas bajo la regla de esa herramienta hasta que termine, y entonces se cierran. Una página cuya herramienta todavía no ha instalado su regla está en el mismo estado y recibe el mismo trato: /json/version muestra Crow-Guard: gate/1 mientras la puerta está en marcha, y crow_browser_status la informa como gate. El coste de esa vía de parada: un reciclaje puede cerrar la sesión del navegador en los sitios en los que iniciaste sesión desde el último cierre limpio, y pierdes la restauración de tus propias pestañas tras un fallo.",
  },
  {
    label: "D new EN",
    lang: "en",
    text: "A tab you open in the viewer while a cleanup is running makes the browser restart. Crow does not chase new tabs during a cleanup; it restarts the browser instead, which can sign it out of sites you logged into since the last clean close.",
  },
  {
    label: "D new ES",
    lang: "es",
    text: "Una pestaña que abres en el visor mientras se hace una limpieza hace que el navegador se reinicie. Crow no persigue pestañas nuevas durante una limpieza; en su lugar reinicia el navegador, lo que puede cerrar la sesión en los sitios en los que iniciaste sesión desde el último cierre limpio.",
  },
  {
    label: "D WebRTC ending EN",
    lang: "en",
    text: "but a live check found Chromium ignoring this switch, so it is not relied on: the init script's disable is the page-level control. A script inside a worker still reaches the API (this script does not run there), so this is best effort: the real fix for a page's own UDP is a UDP egress filter for the container, which Crow does not ship.",
  },
  {
    label: "D WebRTC ending ES",
    lang: "es",
    text: "pero una comprobación en vivo encontró Chromium ignorando esta opción, así que no se confía en ella: la desactivación del script de arranque es el control a nivel de página. Un script dentro de un worker todavía alcanza la API (este script no se ejecuta ahí), así que esto es lo mejor posible: la solución real para el UDP de una página es un filtro de salida (egress) de UDP para el contenedor, que Crow no incluye.",
  },
];

/**
 * The two guide files, the old opening words that must be gone from each, and the old
 * "your own tabs stay open" promise that the approved turn-end paragraph replaced.
 */
const GUIDES = [
  {
    lang: "en",
    path: join(ROOT, "docs", "guide", "browser-automation.md"),
    gone: "The exit cleanup is worth knowing about",
    goneTurnEnd: "Tabs you opened yourself before the turn stay open",
  },
  {
    lang: "es",
    path: join(ROOT, "docs", "es", "guide", "browser-automation.md"),
    gone: "Conviene conocer la limpieza de salida",
    goneTurnEnd: "Las pestañas que abriste tú antes del turno siguen abiertas",
  },
];

const read = (path) => readFileSync(path, "utf8");
/** A guide with its markdown emphasis and code spans removed, so plain text can be compared. */
const plain = (text) => text.replace(/\*\*/g, "").replace(/`/g, "");
const occurrences = (haystack, needle) => String(haystack).split(needle).length - 1;

/**
 * Every file under `dir`, skipping the usual non-source directories. The approved
 * marker text is a comment, not code, so nothing here needs to parse JavaScript.
 */
function walk(dir) {
  const out = [];
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.name === "node_modules" || entry.name === ".git") continue;
    const path = join(dir, entry.name);
    if (entry.isDirectory()) out.push(...walk(path));
    else if (entry.isFile()) out.push(path);
    else if (statSync(path, { throwIfNoEntry: false })?.isDirectory()) out.push(...walk(path));
  }
  return out;
}

describe("(a) the Fix-it card's COPY object carries the approved strings", () => {
  test("every field equals the approved EN and ES text", async () => {
    const { COPY } = await import("../servers/gateway/fix-it/detectors/browser-image-stale.js");
    assert.deepEqual(Object.keys(COPY).sort(), Object.keys(APPROVED).sort());
    for (const [field, langs] of Object.entries(APPROVED)) {
      for (const [lang, text] of Object.entries(langs)) {
        assert.equal(COPY[field][lang], text, `COPY.${field}.${lang} is the approved string`);
      }
    }
  });
});

describe("(b) the install consent message ends with the approved passage (item 67)", () => {
  const manifest = JSON.parse(read(join(ROOT, "bundles", "browser", "manifest.json")));

  for (const lang of ["en", "es"]) {
    test(`${lang}: the final sentence is the approved one, exactly once`, () => {
      const message = manifest.install_consent_messages?.[lang];
      assert.equal(typeof message, "string", `install_consent_messages.${lang} exists`);
      assert.ok(message.endsWith(APPROVED_CONSENT[lang]), `${lang} ends with the approved sentence`);
      assert.equal(occurrences(message, APPROVED_CONSENT[lang]), 1, `${lang} contains it exactly once`);
    });
  }
});

describe("(c) each guide carries the approved turn-end paragraph", () => {
  for (const { lang, path, gone, goneTurnEnd } of GUIDES) {
    test(`${lang}: the paragraph is one whole line, and the old one is gone`, () => {
      const text = read(path);
      const lines = text.split("\n");
      const hits = lines.filter((line) => line === APPROVED_TURN_END[lang]);
      assert.equal(hits.length, 1, `${lang} has the approved paragraph as a whole line`);
      assert.equal(occurrences(text, gone), 0, `${lang} no longer carries the old wording`);
      assert.equal(occurrences(text, goneTurnEnd), 0, `${lang} no longer says your own tabs stay open`);
    });
  }
});

describe("(e) the guide limits and the two sentences are the approved text", () => {
  const text = Object.fromEntries(GUIDES.map(({ lang, path }) => [lang, plain(read(path))]));

  for (const { label, lang, text: approved } of [...APPROVED_C, ...APPROVED_D]) {
    test(`${label}: the ${lang} guide carries the approved string exactly once`, () => {
      assert.ok(text[lang].includes(approved), `${label} is in the ${lang} guide`);
      assert.equal(occurrences(text[lang], approved), 1, `${label} occurs exactly once in ${lang}`);
    });
  }
});

describe("(d) the approval marker is gone from the card code", () => {
  test("no file under servers/gateway/fix-it says the copy is pending approval", () => {
    const marker = "PENDING OPERATOR APPROVAL";
    const files = walk(join(ROOT, "servers", "gateway", "fix-it"));
    assert.ok(files.length > 0, "the fix-it tree was walked");
    const offenders = files.filter((path) => read(path).includes(marker));
    assert.deepEqual(offenders, [], "the pending-approval marker is replaced by the approval date");
  });
});