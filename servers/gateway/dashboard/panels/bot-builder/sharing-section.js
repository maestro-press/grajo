/**
 * Bot Builder → Safety → Sharing: who ONE bot may write to.
 *
 * The bot sharing door (servers/gateway/sharing-bot/*) lets an enabled bot draft messages to the
 * people this section allows it. Every message it writes waits for the owner as a draft, and the
 * owner's own Send is what publishes it — so this list is a permission, not a channel: untick
 * somebody and the door refuses the next draft, while a draft already waiting is refused at the send
 * (servers/gateway/messages/drafts-bot-acl.js re-reads the file every time).
 *
 * The list is a FILE, `<CROW_HOME>/secrets/sharing-bot-acl.json` (acl.js explains why it cannot be a
 * table). This section only shows it and posts the owner's selection through the existing owner route
 * (`PUT /dashboard/bot-builder/api/sharing/:botId`, sharing-bot-acl-api.js), which pins the keys from
 * the live rows itself: a browser never sends a key, only crow ids and group ids. That is the whole
 * reason Save is a small fetch instead of another form field handed to the def save — keys pinned
 * from a posted body would be keys of the caller's choosing.
 *
 * What a person reads, per row:
 *  - the contact's name (or its crow id when it has none) and, for an ALREADY allowed contact whose
 *    key still matches the pinned one, the safety number they see in Contacts: the same symmetric
 *    string (`computeSafetyNumber`), which is what "safety number when allowed" means. A contact
 *    re-keyed since has a different number now, so no number is printed for it: the pinned key is
 *    not the key that person holds, and the door will refuse the send (`pubkey_changed`).
 *  - for a group or a room, its name and how many members were pinned with it.
 *
 * Rendered from renderSafety() beside the email-send card, as its OWN section after that form's
 * closing tag: it has a button of its own and must never become a field of the def save. Nothing here
 * writes anything; the one write is the owner's press, through the ACL route.
 */
import { escapeHtml } from "../../shared/components.js";
import { t, fill } from "../../shared/i18n.js";
import { resolveCrowHome } from "../../../../shared/crow-home.js";
import { DEFAULT_RATE_PER_HOUR, readBotAcl } from "../../../sharing-bot/acl.js";
import { card } from "./ui.js";

/** The row cap: a person's contact book, not a directory. Mirrors the route's own 500-row read. */
const MAX_ROWS = 500;

/** This instance's own ed25519 key, cached once per process (it cannot change without a restart). */
let myEd25519Cache = null;
async function myEd25519() {
  if (myEd25519Cache !== null) return myEd25519Cache;
  try {
    const { loadOrCreateIdentity } = await import("../../../../sharing/identity.js");
    myEd25519Cache = String(loadOrCreateIdentity()?.ed25519Pubkey || "");
  } catch {
    myEd25519Cache = "";
  }
  return myEd25519Cache;
}

/** The symmetric safety number for a contact, or "" when either key is missing. Never throws. */
async function safetyNumberFor(contact) {
  try {
    const theirEd = String(contact?.ed25519_pubkey || "").trim();
    if (!theirEd) return "";
    const mine = await myEd25519();
    if (!mine) return "";
    const { computeSafetyNumber } = await import("../../../../sharing/identity.js");
    const out = computeSafetyNumber(mine, theirEd);
    return /^\d{5}( \d{5}){7}$/.test(String(out)) ? String(out) : "";
  } catch {
    return "";
  }
}

/** The contacts this instance can offer, read the way the Messages panel reads them. */
async function contactsOf(db) {
  try {
    const { rows } = await db.execute({
      sql: `SELECT id, crow_id, display_name, secp256k1_pubkey, ed25519_pubkey, is_blocked
              FROM contacts ORDER BY display_name COLLATE NOCASE, id LIMIT ?`,
      args: [MAX_ROWS],
    });
    return (rows || []).filter((row) => String(row.crow_id || "").trim());
  } catch {
    return [];
  }
}

/** The message groups: every `contact_groups` row with at least one member (an empty one cannot be
 *  pinned — the route refuses it, and a message to it would reach nobody). */
async function groupsOf(db) {
  try {
    const { rows } = await db.execute({
      sql: `SELECT g.id, g.name, g.room_uid,
                   (SELECT COUNT(*) FROM contact_group_members m WHERE m.group_id = g.id) AS members
              FROM contact_groups g
             ORDER BY g.name COLLATE NOCASE, g.id LIMIT ?`,
      args: [MAX_ROWS],
    });
    return (rows || []).filter((row) => Number(row.members) > 0);
  } catch {
    return [];
  }
}

/** One checkbox row, with the optional pinned-key line under its name. */
function checkRow({ name, value, label, checked, note }) {
  return `<label class="btb-check-row">` +
    `<input type="checkbox" name="${escapeHtml(name)}" value="${escapeHtml(value)}"${checked ? " checked" : ""}> ` +
    `<span>${escapeHtml(label)}` +
    (note ? ` <span class="btb-muted">· ${escapeHtml(note)}</span>` : "") +
    `</span></label>`;
}

/**
 * The Sharing section for one bot.
 *
 * @param {object} ctx the Safety tab's ctx (db, def, lang, botId, crowHome…)
 * @returns {Promise<string>} the card (and its one inline script), or "" when there is no bot
 */
export async function renderSharingSection(ctx = {}) {
  const { db, lang } = ctx;
  const botId = ctx.botId == null ? "" : String(ctx.botId);
  if (!botId || !db) return "";
  const crowHome = ctx.crowHome || resolveCrowHome();

  const read = readBotAcl(crowHome, botId);
  const entry = read.ok ? read.entry : { contacts: [], groups: [], rate: { per_hour: DEFAULT_RATE_PER_HOUR } };
  const allowedContacts = new Map(
    (Array.isArray(entry.contacts) ? entry.contacts : []).map((c) => [String(c.crow_id), String(c.secp256k1_pubkey)]),
  );
  const allowedGroups = new Set((Array.isArray(entry.groups) ? entry.groups : []).map((g) => Number(g.id)));

  const [contacts, groups] = await Promise.all([contactsOf(db), groupsOf(db)]);

  const contactRows = [];
  for (const contact of contacts) {
    const crowId = String(contact.crow_id).trim();
    const pinned = allowedContacts.get(crowId);
    const allowed = pinned !== undefined;
    /* The safety number is printed only while the pinned key IS the key the contact holds: that is
       the string the operator saw when they allowed it. A re-keyed contact has a different number
       now, and the door refuses it, so printing one would name a key the bot may not use. */
    let note = "";
    if (allowed && pinned === String(contact.secp256k1_pubkey || "").trim()) {
      const safety = await safetyNumberFor(contact);
      if (safety) note = fill(t("botbuilder.sharing.pinned", lang), { n: safety });
    }
    const label = String(contact.display_name || "").trim() || crowId;
    contactRows.push(checkRow({ name: "sharing_contact", value: crowId, label, checked: allowed, note }));
  }

  const groupRows = groups.map((group) => {
    const id = Number(group.id);
    const label = String(group.name || "").trim() || String(id);
    return checkRow({ name: "sharing_group", value: String(id), label, checked: allowedGroups.has(id) });
  });

  const noneAllowed = allowedContacts.size === 0 && allowedGroups.size === 0;

  const list = (heading, rows) => `<div class="btb-group"><h4 class="btb-card-title">${escapeHtml(heading)}</h4>` +
    (rows.length
      ? `<div class="btb-check-list">${rows.join("")}</div>`
      : `<p class="btb-hint">${escapeHtml(t("botbuilder.sharing.none", lang))}</p>`) +
    `</div>`;

  const body = `<div class="btb-sharing" id="btb-sharing"` +
      ` data-url="/dashboard/bot-builder/api/sharing/${encodeURIComponent(botId)}"` +
      ` data-saved="${escapeHtml(t("messages.draft.saved", lang))}"` +
      ` data-failed="${escapeHtml(t("settings.saveFailed", lang))}">` +
    `<p class="btb-hint" data-testid="sharing-intro">${escapeHtml(t("botbuilder.sharing.intro", lang))}</p>` +
    (noneAllowed
      ? `<p class="btb-hint" data-testid="sharing-none">${escapeHtml(t("botbuilder.sharing.none", lang))}</p>`
      : "") +
    list(t("botbuilder.sharing.contacts", lang), contactRows) +
    list(t("botbuilder.sharing.groups", lang), groupRows) +
    `<p class="btb-hint" data-testid="sharing-status" role="status" aria-live="polite"></p>` +
    `<button type="button" class="btb-btn" data-testid="sharing-save">${escapeHtml(t("botbuilder.sharing.save", lang))}</button>` +
    `</div>`;

  /* One small script: the selection is the ids only, and the keys are pinned by the route from the
     live rows. Every value starts life server-escaped, so nothing here builds text. */
  const script = `<script>(function(){` +
    `var root=document.getElementById('btb-sharing');if(!root)return;` +
    `var btn=root.querySelector('[data-testid=sharing-save]');` +
    `var status=root.querySelector('[data-testid=sharing-status]');` +
    `function csrf(){try{return window.crowCsrf?window.crowCsrf():'';}catch(e){return '';}}` +
    `if(!btn)return;` +
    `btn.addEventListener('click',function(){` +
    `var contacts=[],groups=[];` +
    `root.querySelectorAll('input[name=sharing_contact]').forEach(function(b){if(b.checked)contacts.push(b.value);});` +
    `root.querySelectorAll('input[name=sharing_group]').forEach(function(b){if(b.checked)groups.push(b.value);});` +
    `btn.disabled=true;` +
    `fetch(root.getAttribute('data-url'),{method:'PUT',headers:{'Content-Type':'application/json','X-Crow-Csrf':csrf()},` +
    `body:JSON.stringify({contacts:contacts,groups:groups})})` +
    `.then(function(r){return r.json().then(function(j){return {ok:r.ok,j:j};},function(){return {ok:r.ok,j:null};});})` +
    `.then(function(out){btn.disabled=false;if(status)status.textContent=out.ok?root.getAttribute('data-saved'):root.getAttribute('data-failed');},` +
    `function(){btn.disabled=false;if(status)status.textContent=root.getAttribute('data-failed');});` +
    `});})();</script>`;

  return card(
    t("botbuilder.sharing.heading", lang),
    body,
  ) + script;
}

export default renderSharingSection;