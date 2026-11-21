/**
 * Which items the report's link allow-lists may be built from.
 *
 * An allow-list (`itemLinks` in document.js) is "the URLs the reader can already see", and every path
 * that neutralises text nobody approved builds one: a custom step's section, a bot-written `text` block,
 * a model's commentary, and the document assembly's own join check. A custom step is bot-approved code
 * whose answer decides what the flow carries next, so its items are DATA only. A step that emits an item
 * carrying `https://evil.example/x` and a section linking it would otherwise approve its own URL, and
 * that URL would stay approved for every block after it and for the assembly.
 *
 * The rule is one line: an item a custom step produced is never part of an allow-list. `custom.js` marks
 * every item of its `output.items` with `markUntrusted` before they enter the flow, and `itemLinks`
 * skips a marked item. The items themselves still flow on and are still displayed as data: only their
 * URLs stop counting as something the report vouches for.
 *
 * THE MARK TRAVELS WITH A CLONE. The shape blocks rebuild the items they pass on (`diff_last` and
 * `dedupe_seen` add a field with a spread, `enrich_lookup` joins a retained source's fields into an
 * item), so a mark held only on the item a clone was built from would be lost and the clone's URLs would
 * read as approved. Every such site carries the mark with `carryUntrusted`: a clone is never more
 * trusted than what it was cloned from, and `enrich_lookup` carries it from BOTH sides (the item it
 * joined into and the retained row it joined from, which are a step's own items when the block it names
 * is a custom one). A new block that rebuilds items must carry the mark too, or compute its allow-list
 * from somewhere other than the current items: a lost mark is an allow-list that trusts a step's URL.
 *
 * TWO CONSEQUENCES THIS MODULE DOES NOT HIDE:
 *   - `enrich_lookup` joining a row out of a CUSTOM block's own output distrusts the WHOLE joined item,
 *     its source URLs included: every URL the result carries stops counting toward an allow-list, even one
 *     the item itself carried in from an approved source. That is fail closed by design, because the join
 *     mixes the step's answer into the item and no field of the result can be told apart from the step's
 *     word.
 *   - The mark stops a URL COUNTING toward an allow-list. It does not stop an item being rendered: a
 *     `table` or `cards` block still writes a whole-URL cell (`cellMarkdown`) as a live link, so a body
 *     can carry a link that `allowed_links_json` (`report_versions`, artifact-bridge.js) omits. PR 5 must
 *     settle that mismatch before any renderer checks a body's links against `allowed_links_json`.
 *
 * The mark is a `WeakSet`, so nothing about it is in the item: it never reaches a document, a prompt or a
 * database row, and a step's own JSON answer cannot spell it.
 */

const untrusted = new WeakSet();

/**
 * Mark every item of `items` as a custom step's own production: no allow-list may be built from it.
 *
 * @param {*[]} items
 * @returns {void}
 */
export function markUntrusted(items) {
  for (const item of Array.isArray(items) ? items : []) {
    if (item != null && typeof item === "object") untrusted.add(item);
  }
}

/**
 * Is this item one a custom step produced?
 *
 * @param {*} item
 * @returns {boolean}
 */
export function isUntrustedItem(item) {
  return item != null && typeof item === "object" && untrusted.has(item);
}

/**
 * Carry `source`'s mark onto `target`, a value rebuilt from it: a clone is untrusted when the thing it
 * was built from is. Answers `target`, so a clone site reads as one expression.
 *
 * @param {*} source what the value was built from (an item, or a retained source row)
 * @param {*} target the rebuilt value
 * @returns {*} `target`
 */
export function carryUntrusted(source, target) {
  if (isUntrustedItem(source)) markUntrusted([target]);
  return target;
}