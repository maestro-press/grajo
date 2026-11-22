/**
 * The Fix-it card seed shared by tests/fix-it-attention-cards.test.js and
 * tests/fix-it-nest-unchanged.test.js.
 *
 * One pending `fix_it_items` row per card SOURCE the gateway can raise, written
 * through store.upsertItem with the remedies/context the real detectors store —
 * plus three shapes the detectors cannot produce on their own today (a repeated
 * card with count > 1, a `kind: "confirm"` gated remedy, and a row whose stored
 * title/why carry markup).
 *
 * The row ids are deterministic: the tests that use this run it once, in order,
 * against a freshly initialised scratch crow.db, so the first insert is id 1.
 * The add-on wall record binding is deterministic in the same way: the record's
 * random ref never reaches the markup (`wallFailureByItemId` rebuilds the card).
 */
import * as store from "../../servers/shared/fix-it/store.js";
import {
  bindWallFailureCard,
  recordWallFailure,
} from "../../scripts/addon-sandbox/failures.mjs";
import { BOOT_CHECK_DETECTORS } from "../../servers/gateway/fix-it/index.js";
import remoteExposureDetector from "../../servers/gateway/fix-it/detectors/remote-exposure.js";
import addonWallDetector, {
  DEFAULT_REASON as ADDON_WALL_DEFAULT_REASON,
  TITLE as ADDON_WALL_TITLE,
  whyText as addonWallWhyText,
} from "../../servers/gateway/fix-it/detectors/addon-wall.js";
import {
  COMPOSE_EDITED_SOURCE,
  COMPOSE_IMAGE_CHANGE_SOURCE,
  COMPOSE_NEEDS_CONFIG_SOURCE,
  REMEDY_ACTION_ID as EXTENSIONS_LINK_ACTION,
  REPO_DRIFT_SOURCE,
  composeEditedBody,
  composeEditedTitle,
  composeImageChangeBody,
  composeImageChangeTitle,
  composeNeedsConfigBody,
  composeNeedsConfigTitle,
  driftTitle,
  repoDriftBody,
  repoDriftTitle,
  widerBindBody,
} from "../../servers/gateway/fix-it/detectors/bundle-bind-drift.js";
import {
  SOURCE as RETIRED_BUNDLE_SOURCE,
  cardTitle as retiredBundleTitle,
  cardWhy as retiredBundleWhy,
} from "../../servers/gateway/fix-it/detectors/retired-bundle.js";
import {
  COPY as BROWSER_COPY,
  DEDUP_KEY as BROWSER_DEDUP_KEY,
  SOURCE as BROWSER_SOURCE,
} from "../../servers/gateway/fix-it/detectors/browser-image-stale.js";
import {
  OPEN_BOT_BUILDER_ACTION as OPEN_BOT_BUILDER_FOR_SHARING,
  SOURCE as SHARING_BOT_ACL_SOURCE,
  cardTitle as sharingCardTitle,
  cardWhy as sharingCardWhy,
} from "../../servers/gateway/fix-it/detectors/sharing-bot-acl.js";
import caddyAdminDetector, { DEDUP_KEY as CADDY_ADMIN_DEDUP_KEY } from "../../servers/gateway/fix-it/detectors/caddy-admin-socket.js";
import caddyProxyDetector, { DEDUP_KEY as CADDY_PROXY_DEDUP_KEY } from "../../servers/gateway/fix-it/detectors/caddy-proxy-socket.js";
import { DEDUP_KEY as BOOT_GUARD_DEDUP_KEY, SOURCE as BOOT_GUARD_SOURCE } from "../../servers/gateway/fix-it/detectors/boot-guard.js";
import { DEDUP_KEY as BACKEND_DEDUP_KEY, SOURCE as BACKEND_SOURCE, TITLE as BACKEND_TITLE, bodyText as backendBodyText } from "../../servers/gateway/fix-it/detectors/data-backend-reapproval.js";
import { CARD_ACTION_IDS, cardRemedies } from "../../servers/gateway/fix-it/peer-card-policy.js";
import {
  KEEP_OFF_ACTION,
  KEEP_OFF_LABEL,
  UNWALL_ACTION,
  unwallLabel,
} from "../../servers/gateway/fix-it/remedies/addon-unwall.js";
import {
  ACTION_ID as RESTORE_COMPOSE_ACTION,
  APPLY_UPDATE_ACTION_ID as APPLY_COMPOSE_UPDATE_ACTION,
  LABEL as RESTORE_COMPOSE_LABEL,
} from "../../servers/gateway/fix-it/remedies/restore-bundle-compose.js";
import { ACTION_ID as RESTART_BROWSER_ADDON_ACTION } from "../../servers/gateway/fix-it/remedies/restart-browser-addon.js";
import { ACTION_ID as REMOVE_RETIRED_ACTION, LABEL as REMOVE_RETIRED_LABEL } from "../../servers/gateway/fix-it/remedies/remove-retired-bundle.js";
import { ACTION_ID as REMOVE_BOT_SHARING_ACTION, label as removeBotSharingLabel } from "../../servers/gateway/fix-it/remedies/remove-bot-sharing.js";
import { t } from "../../servers/gateway/dashboard/shared/i18n.js";

/** The cards whose title/why/buttons come from CODE, never from the stored row. */
export const CODE_HELD_SOURCES = Object.freeze([
  RETIRED_BUNDLE_SOURCE, // "retired-bundle"
  addonWallDetector.source, // "addon-wall"
  SHARING_BOT_ACL_SOURCE, // "sharing-bot-acl"
]);

/**
 * Every card source the gateway can put in `fix_it_items`: the registered
 * detectors' own sources (from the gateway's own list of boot checks plus the
 * two event-driven detectors) AND the four extra sources the bundle-bind-drift
 * detector writes.
 */
export function expectedCardSources() {
  return new Set([
    ...BOOT_CHECK_DETECTORS.map((d) => d.source),
    remoteExposureDetector.source,
    addonWallDetector.source,
    COMPOSE_EDITED_SOURCE,
    REPO_DRIFT_SOURCE,
    COMPOSE_NEEDS_CONFIG_SOURCE,
    COMPOSE_IMAGE_CHANGE_SOURCE,
  ]);
}

/** Drop every card row (each test file starts from an empty table). */
export async function clearFixItCards(db) {
  await db.execute("DELETE FROM fix_it_items");
}

/**
 * Write the shared card set.
 * @returns {Promise<{cards: Array<{key: string, id: number, source: string, dedupKey: string}>, ids: Record<string, number>}>}
 */
export async function seedFixItCards(db) {
  const cards = [];
  const add = async (key, item) => {
    const { id } = await store.upsertItem(db, item);
    cards.push({ key, id, source: item.source, dedupKey: item.dedupKey });
    return id;
  };

  // ── the peer-exposure card: three Allow durations, each its own actionId ──
  const peerCard = {
    source: remoteExposureDetector.source,
    dedupKey: "expose|funkwhale|peer-x",
    title: "Your alex's laptop tried to use Music, but it isn't shared with this device yet",
    why: "Allow it for alex's laptop only — your other Crows stay unchanged, and the allowance can expire or be removed in Settings.",
    severity: "warn",
    remedies: cardRemedies("funkwhale", "peer-x"),
    context: { capability: "funkwhale", requestingInstance: "peer-x", toolName: "fw_play", pairingTag: null },
  };
  await add("remote-exposure", peerCard);

  // ── the two Caddy cards: nothing one-click, the Caddyfile row is the useful part ──
  await add("caddy-proxy-socket", {
    source: caddyProxyDetector.source,
    dedupKey: CADDY_PROXY_DEDUP_KEY,
    title: "Visitors coming in through this machine's Caddy are being turned away",
    why: "Caddy still hands them to the gateway over a loopback connection with its own forwarding header, which Crow cannot tell apart from any other program on this machine — so Crow's Nest refuses them. Crow does not run as root, so run this once on the server: sudo bash /srv/crow/scripts/fix-caddy-proxy-socket.sh",
    severity: "warn",
    remedies: [],
    context: { caddyfile: "/etc/caddy/Caddyfile", fixCommand: "sudo bash /srv/crow/scripts/fix-caddy-proxy-socket.sh" },
  });
  await add("caddy-admin-socket", {
    source: caddyAdminDetector.source,
    dedupKey: CADDY_ADMIN_DEDUP_KEY,
    title: "This machine's Caddy admin API is open to any program on it",
    why: "Caddy's admin API is on its default local address with no authentication, so any program or bot on this machine can rewrite the Caddy that fronts Crow. Crow does not run as root, so run this once on the server: sudo bash /srv/crow/scripts/fix-caddy-admin-socket.sh",
    severity: "warn",
    remedies: [],
    context: { caddyfile: "/etc/caddy/Caddyfile", fixCommand: "sudo bash /srv/crow/scripts/fix-caddy-admin-socket.sh" },
  });

  // ── the boot guard: detected twice, so the card carries count > 1 ──
  const bootGuardCard = {
    source: BOOT_GUARD_SOURCE,
    dedupKey: BOOT_GUARD_DEDUP_KEY,
    title: "The boot guard did not run",
    why: "This service is configured to roll back a Crow update that keeps crashing on startup (CROW_BOOT_GUARD=1), but the part that runs before every start did not run. Re-run the boot-guard install step for this service, then restart it.",
    severity: "warn",
    remedies: [],
    context: { reason: "launcher", detail: "launcher_ran_at is missing" },
  };
  await add("boot-guard", bootGuardCard);
  await store.upsertItem(db, bootGuardCard); // second sighting: count 2, one card

  // ── a data backend waiting to be approved again: a link, never a POST ──
  await add("data-backend-reapproval", {
    source: BACKEND_SOURCE,
    dedupKey: BACKEND_DEDUP_KEY,
    title: BACKEND_TITLE,
    why: backendBodyText(2),
    severity: "warn",
    remedies: [{ actionId: "open-projects-page", kind: "link", label: "Open the Projects page" }],
    context: { legacyApprovals: 2 },
  });

  // ── bundle-bind-drift and its four sibling sources ──
  await add("bundle-bind-drift", {
    source: "bundle-bind-drift",
    dedupKey: "bundle:audiobookshelf",
    title: driftTitle("Audiobookshelf"),
    why: widerBindBody("Audiobookshelf", "0.0.0.0", "13378"),
    severity: "warn",
    remedies: [{ actionId: EXTENSIONS_LINK_ACTION, kind: "link", label: "Open Extensions" }],
    context: { bundle: "audiobookshelf", bind: "0.0.0.0:13378", containerPort: "13378/tcp" },
  });
  await add("bundle-compose-edited", {
    source: COMPOSE_EDITED_SOURCE,
    dedupKey: "bundle:changedetection-io",
    title: composeEditedTitle("Changedetection.io"),
    why: composeEditedBody("Changedetection.io", "docker-compose.yml"),
    severity: "warn",
    remedies: [
      { actionId: RESTORE_COMPOSE_ACTION, kind: "instant", label: RESTORE_COMPOSE_LABEL, args: { bundle: "changedetection-io" } },
      { actionId: EXTENSIONS_LINK_ACTION, kind: "link", label: "Open Extensions" },
    ],
    context: { bundle: "changedetection-io", compose: "docker-compose.yml" },
  });
  await add("bundle-compose-needs-config", {
    source: COMPOSE_NEEDS_CONFIG_SOURCE,
    dedupKey: "bundle:vikunja",
    title: composeNeedsConfigTitle("Vikunja"),
    why: composeNeedsConfigBody("Vikunja", "VIKUNJA_DB_PASSWORD"),
    severity: "warn",
    remedies: [{ actionId: EXTENSIONS_LINK_ACTION, kind: "link", label: "Open Extensions" }],
    context: { bundle: "vikunja", compose: "docker-compose.yml", key: "VIKUNJA_DB_PASSWORD" },
  });
  await add("bundle-compose-image-change", {
    source: COMPOSE_IMAGE_CHANGE_SOURCE,
    dedupKey: "bundle:vikunja",
    title: composeImageChangeTitle("Vikunja"),
    why: composeImageChangeBody("Vikunja", { service: "vikunja", from: "vikunja/vikunja:0.24.6", to: "vikunja/vikunja:0.25.1" }),
    severity: "warn",
    remedies: [
      { actionId: APPLY_COMPOSE_UPDATE_ACTION, kind: "instant", label: "Apply the update", args: { bundle: "vikunja" } },
      { actionId: EXTENSIONS_LINK_ACTION, kind: "link", label: "Open Extensions" },
    ],
    context: { bundle: "vikunja", compose: "docker-compose.yml", service: "vikunja", from: "vikunja/vikunja:0.24.6", to: "vikunja/vikunja:0.25.1" },
  });
  await add("bundle-repo-bind-drift", {
    source: REPO_DRIFT_SOURCE,
    dedupKey: "bundle:audiobookshelf:repo",
    title: repoDriftTitle("Audiobookshelf"),
    why: repoDriftBody("Audiobookshelf"),
    severity: "warn",
    remedies: [{ actionId: EXTENSIONS_LINK_ACTION, kind: "link", label: "Open Extensions" }],
    context: { bundle: "audiobookshelf", bind: "0.0.0.0:13378", containerPort: "13378/tcp" },
  });

  // ── a retired bundle still installed: code-held title, why and button ──
  await add("retired-bundle", {
    source: RETIRED_BUNDLE_SOURCE,
    dedupKey: "retired:companion",
    title: retiredBundleTitle("companion", "en"),
    why: retiredBundleWhy("companion", "en"),
    severity: "warn",
    remedies: [{ actionId: REMOVE_RETIRED_ACTION, kind: "instant", label: REMOVE_RETIRED_LABEL, args: { bundle: "companion" } }],
    context: { bundle: "companion" },
  });

  // ── the browser add-on running an image built before the installed files ──
  await add("browser-image-stale", {
    source: BROWSER_SOURCE,
    dedupKey: BROWSER_DEDUP_KEY,
    title: BROWSER_COPY.title.en,
    why: BROWSER_COPY.body.en,
    severity: "warn",
    remedies: [
      { actionId: RESTART_BROWSER_ADDON_ACTION, kind: "instant", label: BROWSER_COPY.restartAction.en, args: { bundle: "browser" } },
      { actionId: EXTENSIONS_LINK_ACTION, kind: "link", label: BROWSER_COPY.openExtensions.en },
    ],
    context: { bundle: "browser", files: ["/app/cdp-relay.mjs"], installed: ["cdp-relay.mjs"] },
  });

  // ── an add-on that could not run inside its wall, WITH its live record ──
  const wallReason = "tried to reach 192.0.2.9:80, which it is not set up for";
  const wallRef = recordWallFailure("browser", wallReason);
  const wallId = await add("addon-wall-bound", {
    source: addonWallDetector.source,
    dedupKey: "addon-wall:browser",
    title: ADDON_WALL_TITLE,
    why: addonWallWhyText("browser", wallReason),
    severity: "warn",
    remedies: [
      { actionId: UNWALL_ACTION, kind: "instant", label: unwallLabel("browser"), args: { ref: wallRef } },
      { actionId: KEEP_OFF_ACTION, kind: "instant", label: KEEP_OFF_LABEL, args: {} },
    ],
    context: { addonId: "browser" },
  });
  if (!bindWallFailureCard(wallRef, { itemId: wallId, dedupKey: "addon-wall:browser" })) {
    throw new Error("the add-on wall record could not be bound to its card");
  }

  // ── the same card with NO live record (a restart's leftovers) ──
  await add("addon-wall-unbound", {
    source: addonWallDetector.source,
    dedupKey: "addon-wall:notes",
    title: ADDON_WALL_TITLE,
    why: addonWallWhyText("notes", ADDON_WALL_DEFAULT_REASON),
    severity: "warn",
    remedies: [
      { actionId: UNWALL_ACTION, kind: "instant", label: unwallLabel("notes"), args: { ref: "0".repeat(32) } },
      { actionId: KEEP_OFF_ACTION, kind: "instant", label: KEEP_OFF_LABEL, args: {} },
    ],
    context: { addonId: "notes" },
  });

  // ── a bot that selects crow-sharing with no allow-list entry ──
  await add("sharing-bot-acl", {
    source: SHARING_BOT_ACL_SOURCE,
    dedupKey: "sharing-acl:heron",
    title: sharingCardTitle("Heron", "heron", "en"),
    why: sharingCardWhy("en"),
    severity: "warn",
    remedies: [
      { actionId: OPEN_BOT_BUILDER_FOR_SHARING, kind: "link", label: t("botbuilder.sharing.heading", "en"), args: { bot: "heron" } },
      { actionId: REMOVE_BOT_SHARING_ACTION, kind: "instant", label: removeBotSharingLabel("en"), args: { bot: "heron" } },
    ],
    context: { bot: "heron", name: "Heron" },
  });

  // ── a GATED remedy (kind "confirm"): rendered disabled, never run ──
  await add("gated-confirm", {
    source: remoteExposureDetector.source,
    dedupKey: "expose|funkwhale|peer-gated",
    title: "Your other laptop tried to use Music, but it isn't shared with this device yet",
    why: "Allowing it for that laptop only leaves your other Crows unchanged.",
    severity: "warn",
    remedies: [{ actionId: CARD_ACTION_IDS[0], kind: "confirm", label: "Allow for 30 days", args: { capability: "funkwhale", requestingInstance: "peer-gated", days: 30 } }],
    context: { capability: "funkwhale", requestingInstance: "peer-gated" },
  });

  // ── a stored title/why carrying markup: the renderers must escape it ──
  await add("xss", {
    source: remoteExposureDetector.source,
    dedupKey: "expose|markup|peer-xss",
    title: "<script>alert('title')</script>",
    why: "<script>alert('why')</script> Allow it for that device only?",
    severity: "warn",
    remedies: [{ actionId: CARD_ACTION_IDS[0], kind: "instant", label: "Allow for 30 days", args: { capability: "markup", requestingInstance: "peer-xss", days: 30 } }],
    context: { capability: "<script>alert('ctx')</script>", requestingInstance: "peer-xss" },
  });

  // One fixed timestamp for every seeded row. listPending() orders by
  // (updated_at DESC, id DESC), so a seed that happened to cross a second
  // boundary would otherwise order itself differently on a slow box — and the
  // golden fixture pins the rendered order.
  await db.execute({ sql: "UPDATE fix_it_items SET updated_at = '2026-01-01 00:00:00'", args: [] });

  const ids = Object.fromEntries(cards.map((c) => [c.key, c.id]));
  return { cards, ids };
}