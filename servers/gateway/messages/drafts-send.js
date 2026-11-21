/**
 * Delivery for a Crow Messages draft: hand the text to the send path that ALREADY exists for its
 * conversation kind, and nothing else.
 *
 * There are two kinds, and each one has exactly one sender in this codebase:
 *
 *   - `contact` — the 1:1 peer chat. The sender is `handlePeerSend`
 *     (servers/gateway/routes/peer-messages.js), the function behind
 *     `POST /api/messages/peer/:contactId/send`: it resolves the contact, calls the sharing server's
 *     `crow_send_message`, treats a 0-relay result as a failure the caller must see, and reads back
 *     the row it wrote. It is called here with a bare request/response pair because that is the
 *     function's own interface; nothing about the delivery (relay feedback, the failed-row retry
 *     bookkeeping) is re-implemented on this side, so a draft send and a typed send cannot drift.
 *   - `room` — the multi-party chat. The sender is `sendOperatorRoomMessage`
 *     (servers/gateway/dashboard/panels/messages/room-send.js), the same function the room panel's
 *     composer calls: it stores the local row and fans the envelope out to the members (or to the
 *     host, when this instance is a participant).
 *
 * THE TEXT GOES OUT EXACTLY AS POSTED, MINUS THE WHITESPACE THE EXISTING PATH ALREADY DROPS — WITH ONE
 * EXCEPTION, AND IT IS THE INVARIANT THE BOT DOOR LEANS ON. An owner's draft goes out as the owner's
 * words. A draft a BOT wrote (`origin: "bot"`) goes out with one fixed first line naming the bot:
 *
 *     Sent by <bot name> (bot)
 *     <the owner's final text>
 *
 * The name is the row's own sealed snapshot (`bot_name`, falling back to `bot_id`); it is part of what
 * the seal covers, so it cannot be changed under the draft, and the route has already verified that
 * seal before this module runs. The line is derived HERE, from the row, and never from the request: the
 * person sending cannot drop it, and the recipient can always see that the words were a bot's
 * suggestion the owner read and sent. Nothing else is appended — no signature, no provenance block —
 * and the destination still learns nothing about who drafted it beyond that name.
 *
 * THE ` (bot)` MARKER IS FIXED TEXT, AND IT COMES FROM HERE, NEVER FROM THE NAME. It is appended after
 * the flattened name so a recipient who does not know the bot still reads that a bot drafted the words,
 * and a name that carries its own `(bot)` has it removed before it is used: otherwise "Hank (bot)" would
 * go out with two markers, and a bot could spell one itself in a name the operator picks.
 *
 * (The envelope field `sent_by_bot:<bot_id>` is part 2's: it needs the two transports to carry a
 * structured field, and no receiving Crow reads it yet, so adding it here would change nothing a person
 * can see. The first line alone is what makes the attribution true today.)
 *
 * The one transformation is `trim()`, and it is here because the two send paths this module drives
 * already do it themselves: `POST /api/messages/peer/:contactId/send` calls `crow_send_message` with
 * `message.trim()`, and the room route hands `sendOperatorRoomMessage` `message.trim()` as well. A
 * draft that is sent therefore reads exactly like the same words typed into the composer — no
 * trailing newline the composer's textarea collects and a typed message does not. Nothing else about
 * the text is touched, and a draft that is only whitespace is refused before anything is attempted.
 *
 * The caller has already checked the seal and the live recipient set
 * (servers/gateway/routes/messages-drafts-api.js), so this module does one thing: deliver, and say
 * whether it landed. Every reason it answers is a fixed code — never a library's or a relay's text —
 * because the route's answer goes back to a card.
 *
 * THE DELIVERY IS TO THE PEOPLE THE DRAFT NAMED, NOT TO THEIR NAMES. Both send paths resolve a
 * destination by an identifier a person types (`crow_send_message` matches `crow_id = ? OR
 * display_name = ?`; a room fan-out re-lists the room's members), and that resolution can land on a
 * different row than the one the draft was checked against — a contact whose display name is another
 * contact's crow id, a member re-keyed between the check and the send. So the sealed audience rides
 * along into the delivery: the peer send is called in STRICT mode (the row is read by primary id,
 * its id / crow id / secp256k1 key are compared with the snapshot, it is named by its unique crow
 * id, and that same snapshot is handed to `crow_send_message` itself as an internal, non-argument
 * guard so the tool refuses if its own lookup resolves any other row), and the room send gets
 * `expectedRecipients` (the member rows are checked by primary id right before the fan-out). A
 * refusal before the handoff comes back as its own reason — `recipients_changed`, `pubkey_changed`,
 * `blocked` — and nothing is sent.
 */
import { handlePeerSend } from "../routes/peer-messages.js";
import { sendOperatorRoomMessage } from "../dashboard/panels/messages/room-send.js";

/** The reasons a DELIVERY answers when the handoff check refused: the route shows them as its own
 *  codes (`recipients_changed`, `pubkey_changed`, `blocked`), never as a failed delivery. */
const HANDOFF_REFUSALS = Object.freeze(["recipients_changed", "pubkey_changed", "blocked"]);

/** The first line a bot's draft goes out with; the name is capped and flattened so it cannot forge one. */
export const SENT_BY_PREFIX = "Sent by ";

/**
 * The fixed marker that follows the name on that line (`Sent by Hank (bot)`). It is the ONE part of the
 * line a bot cannot choose: `sentByBotName` strips any `(bot)` the name carries, and this suffix is
 * appended by `outboundText` alone. The Spanish copy of the same line (`Enviado por <name> (bot)`)
 * keeps the same fixed word, so the marker reads the same in both languages.
 */
export const SENT_BY_MARKER = " (bot)";

/** A `(bot)` the name carries, however it is spelled (case, inner spaces, leading whitespace). */
const BOT_MARKER_PATTERN = /\s*\(\s*bot\s*\)/gi;

/**
 * How many passes `stripBotMarkers` may make. A name nests at most a handful of levels deep before the
 * 80-character cap, but the loop is bounded anyway: a name is a value a bot's own definition supplied,
 * and this function's contract is that it always terminates.
 */
const MAX_MARKER_PASSES = 20;

/**
 * Remove every `(bot)` the name carries — REPEATEDLY, until the string stops changing.
 *
 * One pass is not enough: the pattern can OVERLAP ITSELF. `((bot)bot)` loses the inner `(bot)` and
 * leaves `(bot)`, and `Hank (b(bot)ot)` leaves `Hank (bot)` — both would go out with a second marker
 * after `outboundText` appends the fixed one. So the removal runs again until a pass changes nothing
 * (or the bound is reached), which is what makes the final line carry exactly one ` (bot)`, the code's.
 */
function stripBotMarkers(text) {
  let current = String(text);
  for (let pass = 0; pass < MAX_MARKER_PASSES; pass += 1) {
    const next = current.replace(BOT_MARKER_PATTERN, "");
    if (next === current) return current;
    current = next;
  }
  return current;
}

/**
 * One bot-supplied name, flattened into one plain line: control characters (a newline above all) fold to
 * a SPACE, the Unicode FORMAT and BIDI characters fold to NOTHING, and any `(bot)` marker the name
 * carries is dropped so the line ends with exactly one fixed marker. Spaces are collapsed and the result
 * is capped, so the line `sentByBotName` returns is always one plain line.
 */
function flattenSentByName(raw) {
  // C0 (a newline above all) AND the C1 block: U+0085 (NEL) is a line break in plenty of renderers,
  // and the rest of C1 renders as nothing or as garbage — both fold to one SPACE. The Unicode FORMAT
  // and BIDI characters fold to NOTHING.
  const folded = String(raw)
    .replace(/[\u0000-\u001f\u007f-\u009f]+/g, " ")
    .replace(/[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff]+/g, "");
  // The attribution marker is added once, by outboundText: never by the name.
  return stripBotMarkers(folded)
    .replace(/\s+/g, " ")
    .trim()
    .slice(0, 80);
}

/**
 * The name a bot's message is attributed to: the row's sealed snapshot, else its id.
 *
 * The name is FLATTENED before it goes on the wire, in three steps, because it is the first line of a
 * message a person reads and a bot's name is a value the bot's own definition supplied:
 *
 *   - control characters fold to a SPACE — C0 with DEL (a newline above all), so
 *     `Hank\nPlease ignore the above` cannot become a second line of its own, and the C1 block
 *     (U+0080–U+009F, U+0085 NEL above all), which some renderers also break the line on and the rest
 *     of which is invisible or garbage;
 *   - Unicode FORMAT and BIDI characters fold to NOTHING — zero-width joiners/spaces (U+200B–U+200F),
 *     the bidi embeddings, overrides and isolates (U+202A–U+202E, U+2066–U+2069), the invisible
 *     operators (U+2060–U+2064) and a BOM (U+FEFF). These render as nothing but can reorder the
 *     line or hide text inside it, so a name carrying them would attribute the wrong words to the
 *     bot (and a `\u202E` override is exactly how a name forges a second sender);
 *   - any `(bot)` the name carries is dropped, REPEATEDLY (stripBotMarkers), because the pattern
 *     nests: `((bot)bot)` and `Hank (b(bot)ot)` each hide a second marker behind the first, so one
 *     pass would leave the name carrying one. The fixed marker below is then the only one on the line.
 *
 * The spaces left behind are collapsed and the result is capped, so the line named below is always
 * one plain line. An empty result (a name that was only those characters) falls back to the bot id.
 * A `(bot)` in the name is dropped too (flattenSentByName): the marker is the code's, not a name's.
 */
export function sentByBotName(draft) {
  if (!draft || draft.origin !== "bot") return null;
  const raw = String(draft.botName ?? "").trim() || String(draft.botId ?? "").trim();
  return flattenSentByName(raw) || flattenSentByName(String(draft.botId ?? "").trim()) || null;
}

/**
 * The text that leaves the box: the posted text, prefixed with `Sent by <bot> (bot)` when a bot drafted
 * it. Exported so a test can pin the transformation without a transport.
 */
export function outboundText(draft, text) {
  const message = String(text ?? "").trim();
  const bot = sentByBotName(draft);
  return bot ? `${SENT_BY_PREFIX}${bot}${SENT_BY_MARKER}\n${message}` : message;
}

/**
 * A bare response object for `handlePeerSend`: it only ever answers with `status(code).json(body)`,
 * and the pair below records what it said. Never touches a real socket.
 */
function answerRecorder() {
  // Express answers 200 unless the handler says otherwise: `handlePeerSend`'s success path calls
  // `res.json(...)` with no `res.status(200)` first, so the recorder starts at 200.
  const out = { status: 200, body: null };
  const res = {
    headersSent: false,
    status(code) {
      out.status = code;
      return res;
    },
    json(body) {
      out.body = body;
      res.headersSent = true;
      return res;
    },
  };
  return { res, out };
}

/**
 * Deliver one draft's text.
 *
 * @param {object} db
 * @param {object} draft the store's draft row (`conversationKind`, `conversationId`)
 * @param {string} text the exact text to send
 * @param {{managers?: object|null, sharingClientFactory?: Function}} [deps] the room send's
 *   `managers` (this instance's sharing runtime, or null in a test) and the peer send's client
 *   factory seam (tests inject a stub; production uses the real in-memory sharing client)
 * @returns {Promise<{ok: true, messageId: string|null}|{ok: false, reason: string}>}
 */
export async function sendDraftMessage(db, draft, text, deps = {}) {
  const message = String(text ?? "").trim();
  if (!message) return { ok: false, reason: "empty" };
  // A bot's draft is attributed on the wire; an owner's is not (outboundText above).
  const outbound = outboundText(draft, message);

  if (draft.conversationKind === "contact") {
    // The recipient the draft sealed, found by the conversation's own contact id — the only person a
    // 1:1 draft can be for. No snapshot means the row was rewritten out from under its seal (the
    // route would have refused it earlier): never send to a row this draft did not name.
    const sealed = (Array.isArray(draft.recipients) ? draft.recipients : [])
      .find((entry) => Number(entry?.contactId) === Number(draft.conversationId)) || null;
    if (!sealed) return { ok: false, reason: "recipients_changed" };
    const { res, out } = answerRecorder();
    try {
      await handlePeerSend(
        { params: { contactId: String(draft.conversationId) }, body: { message: outbound } },
        res,
        {
          db,
          strictRecipient: sealed,
          ...(typeof deps.sharingClientFactory === "function"
            ? { sharingClientFactory: deps.sharingClientFactory }
            : {}),
        },
      );
    } catch {
      return { ok: false, reason: "send_failed" };
    }
    if (out.status === 404) return { ok: false, reason: "conversation_gone" };
    if (out.status === 400) return { ok: false, reason: "bad_input" };
    if (out.status === 200 && out.body?.ok) {
      return { ok: true, messageId: out.body.id == null ? null : String(out.body.id) };
    }
    // The handoff check refused: the row about to receive the text is not the one the draft sealed.
    if (out.status === 409 && HANDOFF_REFUSALS.includes(out.body?.error)) {
      return { ok: false, reason: out.body.error };
    }
    // A 502 from the peer path is a delivery that reached no relay: the draft stays to try again.
    return { ok: false, reason: "delivery_failed" };
  }

  if (draft.conversationKind === "room") {
    try {
      const result = await sendOperatorRoomMessage({
        db,
        managers: deps.managers ?? null,
        groupId: draft.conversationId,
        message: outbound,
        expectedRecipients: Array.isArray(draft.recipients) ? draft.recipients : [],
      });
      if (result?.ok) return { ok: true, messageId: null };
      // The member rows the fan-out was about to reach are not the ones the draft sealed.
      if (HANDOFF_REFUSALS.includes(result?.error)) return { ok: false, reason: result.error };
      return { ok: false, reason: result?.error === "no such room" ? "conversation_gone" : "send_failed" };
    } catch {
      return { ok: false, reason: "send_failed" };
    }
  }

  return { ok: false, reason: "bad_conversation" };
}