/**
 * The mail provider presets: the IMAP and SMTP settings Crow offers when an owner types an address at
 * one of the big providers, so connecting a mailbox is a password rather than four host names, three
 * ports and a TLS choice.
 *
 * A preset is a starting point, never a lock. Every endpoint here is one the account store's own
 * validation accepts (servers/gateway/mail/store/accounts.js), and an account Crow has no preset for is
 * served by `generic`, which offers no host at all and leaves both endpoints to the owner.
 *
 * Two fields decide how an account behaves once it exists:
 *
 * - `security` is `"ssl"` (TLS from the first byte: the IMAP and SMTP "SSL" ports) or `"starttls"` (a
 *   plaintext port upgraded before any login, the "TLS" ports). A preset never offers `"none"`: a
 *   preset is advice, and the advice is never a cleartext login — the store allows that only for a
 *   server on this machine, which no preset is (Proton Bridge's `127.0.0.1` still speaks STARTTLS).
 * - `sentCopy` says who keeps the Sent copy. `"provider"` means the provider itself files a message
 *   Crow hands its SMTP server (Gmail does), so Crow must not also append one, or every sent message is
 *   stored twice. `"append"` means Crow appends the copy after the send, which is the safe default when
 *   a provider's own filing is not confirmed in its documentation (Outlook.com and the rest): a
 *   duplicate Sent copy is a visible annoyance, a missing one is lost mail.
 *
 * Each preset's settings were read off a page of the provider's own documentation, listed in its
 * `sources`; a preset that cannot cite a page claims nothing (`proton-bridge` and `generic` carry no
 * source). Proton Mail is the one entry with no official IMAP/SMTP page behind it: without Proton Bridge
 * a Proton mailbox speaks no IMAP or SMTP at all, and Bridge chooses its own local ports when it starts,
 * so the ports below are Bridge's default and a note tells the person to use the ones Bridge shows.
 *
 * `notes` are i18n KEYS, stored as plain strings and deliberately NOT in the message catalog yet: the
 * panel that renders a preset (a later change) adds each key together with its translations, so this
 * module ships no half-translated text and no panel-facing wording of its own.
 *
 * The table is deep-frozen: a preset is shared state (a page, a route and a probe may all hold the same
 * object), and nothing may edit a provider's settings in place.
 */

/** Freeze the whole tree, so neither the list nor a nested endpoint can be edited by a caller. */
function deepFreeze(value) {
  if (value && typeof value === "object") {
    for (const inner of Object.values(value)) deepFreeze(inner);
    Object.freeze(value);
  }
  return value;
}

/**
 * Every preset, in the order a picker shows them: the providers with a verified page first, then
 * Bridge, then the manual door. Ids are lower-case and stable — an account's `provider` column holds
 * one, and a stored id is read back by a later panel.
 *
 * @type {ReadonlyArray<Readonly<{
 *   id: string, label: string, authKinds: ReadonlyArray<"password"|"xoauth2">,
 *   imap: {host: string, port: number, security: "ssl"|"starttls"}|null,
 *   smtp: {host: string, port: number, security: "ssl"|"starttls"}|null,
 *   sentCopy: "provider"|"append", notes: ReadonlyArray<string>, sources: ReadonlyArray<string>,
 * }>>}
 */
export const PRESETS = deepFreeze([
  {
    id: "gmail",
    label: "Gmail",
    authKinds: ["password", "xoauth2"],
    imap: { host: "imap.gmail.com", port: 993, security: "ssl" },
    smtp: { host: "smtp.gmail.com", port: 465, security: "ssl" },
    // Gmail files a message it accepted over SMTP into Sent itself.
    sentCopy: "provider",
    notes: [],
    sources: [
      "https://developers.google.com/gmail/imap/imap-smtp",
      "https://support.google.com/mail/answer/78892",
    ],
  },
  {
    id: "outlook",
    label: "Outlook.com",
    // Microsoft's own IMAP/POP/SMTP page (cited below) states that Outlook.com requires Modern
    // authentication (OAuth2) for IMAP and SMTP: a password is not offered for it here.
    authKinds: ["xoauth2"],
    imap: { host: "outlook.office365.com", port: 993, security: "ssl" },
    smtp: { host: "smtp-mail.outlook.com", port: 587, security: "starttls" },
    // Not confirmed that the server files an SMTP-sent message, so Crow appends the copy itself.
    sentCopy: "append",
    notes: [],
    sources: [
      "https://support.microsoft.com/en-us/office/pop-imap-and-smtp-settings-for-outlook-com-d088b986-291d-42b8-9564-9c414e2aa040",
    ],
  },
  {
    id: "fastmail",
    label: "Fastmail",
    authKinds: ["password"],
    imap: { host: "imap.fastmail.com", port: 993, security: "ssl" },
    smtp: { host: "smtp.fastmail.com", port: 465, security: "ssl" },
    sentCopy: "append",
    notes: [],
    sources: ["https://www.fastmail.help/hc/en-us/articles/1500000278342"],
  },
  {
    id: "icloud",
    label: "iCloud Mail",
    authKinds: ["password"],
    imap: { host: "imap.mail.me.com", port: 993, security: "ssl" },
    smtp: { host: "smtp.mail.me.com", port: 587, security: "starttls" },
    sentCopy: "append",
    notes: [],
    sources: ["https://support.apple.com/en-us/102525"],
  },
  {
    id: "yahoo",
    label: "Yahoo Mail",
    authKinds: ["password"],
    imap: { host: "imap.mail.yahoo.com", port: 993, security: "ssl" },
    smtp: { host: "smtp.mail.yahoo.com", port: 465, security: "ssl" },
    sentCopy: "append",
    notes: [],
    sources: ["https://help.yahoo.com/kb/SLN4075.html"],
  },
  {
    id: "proton-bridge",
    label: "Proton Mail (Bridge)",
    authKinds: ["password"],
    // Bridge listens on this machine only, and its ports are its own defaults — see the note.
    imap: { host: "127.0.0.1", port: 1143, security: "starttls" },
    smtp: { host: "127.0.0.1", port: 1025, security: "starttls" },
    sentCopy: "append",
    // No official IMAP/SMTP page exists for this, so the person is told to use Bridge's own ports.
    notes: ["mail.preset.protonBridgePorts"],
    sources: [],
  },
  {
    id: "generic",
    label: "Other (IMAP/SMTP)",
    authKinds: ["password"],
    // The manual door: no host offered, so the owner types both endpoints.
    imap: null,
    smtp: null,
    sentCopy: "append",
    notes: [],
    sources: [],
  },
]);

/** The domains each preset answers for. A whole domain, matched lower-case: never a suffix of another. */
const DOMAIN_PRESET_IDS = new Map([
  ["gmail.com", "gmail"],
  ["googlemail.com", "gmail"],
  ["outlook.com", "outlook"],
  ["hotmail.com", "outlook"],
  ["live.com", "outlook"],
  ["icloud.com", "icloud"],
  ["me.com", "icloud"],
  ["fastmail.com", "fastmail"],
  ["yahoo.com", "yahoo"],
]);

const PRESETS_BY_ID = new Map(PRESETS.map((preset) => [preset.id, preset]));

/**
 * The preset offered for a mail domain, or null when Crow has none for it (the owner then gets
 * `generic`, or types the endpoints). The domain decides alone and is matched whole and lower-case:
 * `gmail.com` and `GoogleMail.COM` are both Gmail, while `mail.gmail.com` and `notgmail.com` are not.
 * Anything that is not a non-empty string is null.
 *
 * @param {string} domain
 * @returns {object|null} one of PRESETS, or null
 */
export function presetForDomain(domain) {
  if (typeof domain !== "string") return null;
  const normalised = domain.trim().toLowerCase();
  if (!normalised) return null;
  const id = DOMAIN_PRESET_IDS.get(normalised);
  return id ? (PRESETS_BY_ID.get(id) ?? null) : null;
}

/**
 * The preset offered for an address, by the domain after its last `@` — a thin wrapper over
 * `presetForDomain`, so the local part never matters (an address typed in any case is still its
 * provider's) and an address with no `@` or no domain is null.
 *
 * @param {string} address
 * @returns {object|null} one of PRESETS, or null
 */
export function presetFor(address) {
  if (typeof address !== "string") return null;
  const at = address.lastIndexOf("@");
  if (at < 0) return null;
  return presetForDomain(address.slice(at + 1));
}