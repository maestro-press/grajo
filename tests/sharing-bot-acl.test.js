// The bot sharing allow-list (servers/gateway/sharing-bot/acl.js): a 0600 file in the 0700 `secrets/`
// directory the pi sandbox masks from bots, written atomically, strict about its shape, and never
// treated as "no restrictions" when it cannot be read.
//
// A scratch CROW_HOME is all this test needs: the store is a file, and that is the point (a contained
// bot has crow.db read-write, so the allow-list must not live where the bot it constrains could widen
// it).
import { test, after } from "node:test";
import assert from "node:assert/strict";
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync, mkdirSync, symlinkSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  AclError, DEFAULT_RATE_PER_HOUR, MAX_RATE_PER_HOUR, MAX_ACL_BYTES, groupEntryId,
  normalizeBotEntry, readBotAcl, readSharingBotAcl, removeSharingBotAclEntry,
  setSharingBotAclEntry, sharingBotAclPath, sharingBotAclStat, sharingBotSecretsDirMode,
  writeSharingBotAcl,
} from "../servers/gateway/sharing-bot/acl.js";

const root = mkdtempSync(join(tmpdir(), "sharing-bot-acl-"));
after(() => rmSync(root, { recursive: true, force: true }));

let n = 0;
const home = () => {
  const dir = join(root, "home" + (++n));
  mkdirSync(dir, { recursive: true });
  return dir;
};

const PEER = { crow_id: "crow:peer", secp256k1_pubkey: "02" + "a".repeat(64) };
const OTHER = { crow_id: "crow:other", secp256k1_pubkey: "02" + "b".repeat(64) };
const ENTRY = {
  contacts: [PEER],
  groups: [{ id: 7, members: [PEER, OTHER] }],
  rate: { per_hour: 5 },
};

test("no file is an empty allow-list — the operator's starting state is nobody, not everybody", () => {
  const h = home();
  const read = readSharingBotAcl(h);
  assert.equal(read.ok, true);
  assert.deepEqual(read.acl, {});
  assert.deepEqual(readBotAcl(h, "hank"), { ok: false, reason: "no_entry" });
  assert.equal(sharingBotAclStat(h).present, false);
});

test("a written entry lands in secrets/ 0600, with the shape the door reads back", () => {
  const h = home();
  const written = setSharingBotAclEntry(h, "hank", ENTRY);
  assert.equal(written.ok, true);
  assert.deepEqual(written.entry, ENTRY);

  const path = sharingBotAclPath(h);
  assert.equal(path, join(h, "secrets", "sharing-bot-acl.json"), "the secrets dir, which the pi sandbox masks");
  assert.equal(statSync(path).mode & 0o777, 0o600, "owner-only file");
  assert.equal(sharingBotSecretsDirMode(h), 0o700, "owner-only directory");
  assert.deepEqual(JSON.parse(readFileSync(path, "utf8")), { hank: ENTRY });

  const read = readBotAcl(h, "hank");
  assert.equal(read.ok, true);
  assert.deepEqual(read.entry, ENTRY);
});

test("a write replaces the file atomically and leaves no temp files behind", () => {
  const h = home();
  writeSharingBotAcl(h, { hank: ENTRY });
  writeSharingBotAcl(h, { hank: { ...ENTRY, contacts: [PEER, OTHER] }, otto: ENTRY });
  const files = readdirSync(join(h, "secrets"));
  assert.deepEqual(files, ["sharing-bot-acl.json"], "one file: the rename replaced it");
  const read = readSharingBotAcl(h);
  assert.equal(read.ok, true);
  assert.deepEqual(Object.keys(read.acl), ["hank", "otto"]);
  assert.equal(read.acl.hank.contacts.length, 2);

  // Setting one bot's entry leaves the other's exactly as it was.
  const set = setSharingBotAclEntry(h, "otto", { contacts: [], groups: [], rate: { per_hour: 3 } });
  assert.equal(set.ok, true);
  assert.deepEqual(readSharingBotAcl(h).acl.otto, { contacts: [], groups: [], rate: { per_hour: 3 } });
  assert.equal(readSharingBotAcl(h).acl.hank.contacts.length, 2);
});

test("a group entry's id is `id`, the one spelling every reader uses — `group_id` is not a field", () => {
  // The stored entry (normalizeBotEntry) is `{ id, members }`. Both readers of an entry's groups — the
  // recipient picker (messages-drafts-api.js allowedRecipientsFor) and the send's own room re-check
  // (messages/drafts-bot-acl.js botAudienceRefusal), plus the door's resolveAllowedGroup — go through
  // groupEntryId, so they cannot disagree about which group an entry names.
  const entry = normalizeBotEntry(ENTRY);
  assert.equal(entry.groups[0].id, 7);
  assert.equal(Object.hasOwn(entry.groups[0], "group_id"), false, "the file's spelling is `id`");
  assert.equal(groupEntryId(entry.groups[0]), 7, "the accessor every reader uses");
  assert.equal(groupEntryId({ id: "7" }), 7, "a hand-written numeric string still reads");
  assert.equal(groupEntryId({ group_id: 7 }), null, "a reader must not invent the other spelling");
  assert.equal(groupEntryId({ id: 0 }), null);
  assert.equal(groupEntryId(null), null);
  // A file carrying `group_id` is not half-read: the strict shape refuses it, and the door refuses
  // every call that needs the allow-list rather than quietly seeing no group.
  assert.throws(() => normalizeBotEntry({ groups: [{ group_id: 7, members: [PEER] }] }),
    (err) => err instanceof AclError && err.detail === "groups");
});

test("a missing rate is the default cap; an explicit one is bounded", () => {
  const normalized = normalizeBotEntry({ contacts: [], groups: [] });
  assert.deepEqual(normalized.rate, { per_hour: DEFAULT_RATE_PER_HOUR });
  assert.throws(() => normalizeBotEntry({ rate: { per_hour: 0 } }), AclError);
  assert.throws(() => normalizeBotEntry({ rate: { per_hour: MAX_RATE_PER_HOUR + 1 } }), AclError);
  assert.throws(() => normalizeBotEntry({ rate: { per_hour: 1.5 } }), AclError);
  assert.throws(() => normalizeBotEntry({ rate: { per_hour: 5, extra: 1 } }), AclError);
});

test("the shape is strict: unknown fields, duplicates and non-hex keys are refused, not ignored", () => {
  const cases = [
    [{ contacts: [], groups: [], nickname: "x" }, "bot"],
    [{ contacts: [{ crow_id: "crow:a", secp256k1_pubkey: PEER.secp256k1_pubkey, name: "A" }] }, "contacts"],
    [{ contacts: [PEER, { ...PEER }] }, "contacts"],
    [{ contacts: [{ crow_id: "crow:a", secp256k1_pubkey: "not-a-key" }] }, "secp256k1_pubkey"],
    [{ contacts: [{ crow_id: "", secp256k1_pubkey: PEER.secp256k1_pubkey }] }, "crow_id"],
    [{ groups: [{ id: 0, members: [PEER] }] }, "group.id"],
    [{ groups: [{ id: 7, members: [] }] }, "members"],
    [{ groups: [{ id: 7, members: [PEER, PEER] }] }, "members"],
    [{ groups: [{ id: 7, members: [PEER], name: "Den" }] }, "groups"],
  ];
  for (const [entry, field] of cases) {
    assert.throws(() => normalizeBotEntry(entry), (err) => {
      assert.ok(err instanceof AclError, `${JSON.stringify(entry)} refused`);
      assert.equal(err.code, "BAD_INPUT");
      assert.equal(err.detail, field, `${JSON.stringify(entry)} names ${field}`);
      return true;
    });
  }
  // A numeric group id given as text normalizes to a number, and entries are sorted for a stable file.
  const normalized = normalizeBotEntry({
    contacts: [OTHER, PEER],
    groups: [{ id: "9", members: [PEER] }, { id: 7, members: [OTHER] }],
  });
  assert.deepEqual(normalized.contacts.map((contact) => contact.crow_id), ["crow:other", "crow:peer"]);
  assert.deepEqual(normalized.groups.map((group) => group.id), [7, 9]);
});

test("a bot id that is not one is refused, and writing it changes nothing", () => {
  const h = home();
  writeSharingBotAcl(h, { hank: ENTRY });
  const before1 = readFileSync(sharingBotAclPath(h), "utf8");
  assert.throws(() => setSharingBotAclEntry(h, "../etc", ENTRY), AclError);
  assert.equal(readFileSync(sharingBotAclPath(h), "utf8"), before1, "the previous allow-list is untouched");
});

test("an unreadable file is a refusal the door sees, never an empty allow-list", () => {
  const h = home();
  mkdirSync(join(h, "secrets"), { recursive: true, mode: 0o700 });
  const path = sharingBotAclPath(h);
  for (const body of ["{not json", "[]", "null", JSON.stringify({ hank: { contacts: [{ crow_id: "x", secp256k1_pubkey: "zz" }] } })]) {
    writeFileSync(path, body, { mode: 0o600 });
    assert.deepEqual(readSharingBotAcl(h), { ok: false, reason: "unreadable" }, body);
    assert.deepEqual(readBotAcl(h, "hank"), { ok: false, reason: "unreadable" });
    // A write that would have to merge into that file is refused: another bot's entry must not be
    // silently dropped.
    assert.deepEqual(setSharingBotAclEntry(h, "otto", ENTRY), { ok: false, reason: "unreadable" });
    assert.deepEqual(removeSharingBotAclEntry(h, "hank"), { ok: false, reason: "unreadable" });
    assert.equal(readFileSync(path, "utf8"), body, "the damaged file is left for the operator to fix");
  }

  // An oversized file is the same refusal: a planted multi-megabyte "allow-list" is not read.
  writeFileSync(path, "x".repeat(MAX_ACL_BYTES + 1), { mode: 0o600 });
  assert.deepEqual(readSharingBotAcl(h), { ok: false, reason: "unreadable" });

  // A directory where the file should be is unreadable too, not "no file".
  rmSync(path);
  mkdirSync(path);
  assert.deepEqual(readSharingBotAcl(h), { ok: false, reason: "unreadable" });
});

test("a symlink at the allow-list path is replaced, never written through", () => {
  const h = home();
  mkdirSync(join(h, "secrets"), { recursive: true, mode: 0o700 });
  const victim = join(h, "victim.json");
  writeFileSync(victim, "{\"keep\":true}", { mode: 0o644 });
  symlinkSync(victim, sharingBotAclPath(h));
  writeSharingBotAcl(h, { hank: ENTRY });
  assert.equal(readFileSync(victim, "utf8"), "{\"keep\":true}", "the link's target was not written through");
  assert.equal(statSync(sharingBotAclPath(h)).isFile(), true, "the path is now a plain file");
  assert.equal(statSync(sharingBotAclPath(h)).mode & 0o777, 0o600);
});

test("removing a bot's entry is idempotent and leaves the others alone", () => {
  const h = home();
  writeSharingBotAcl(h, { hank: ENTRY, otto: ENTRY });
  assert.deepEqual(removeSharingBotAclEntry(h, "hank"), { ok: true, removed: true });
  assert.deepEqual(Object.keys(readSharingBotAcl(h).acl), ["otto"]);
  assert.deepEqual(removeSharingBotAclEntry(h, "hank"), { ok: true, removed: false });
});

test("an invalid bot id in the file itself makes the whole file unreadable", () => {
  const h = home();
  mkdirSync(join(h, "secrets"), { recursive: true, mode: 0o700 });
  writeFileSync(sharingBotAclPath(h), JSON.stringify({ "../etc": ENTRY }), { mode: 0o600 });
  assert.equal(readSharingBotAcl(h).ok, false);
});