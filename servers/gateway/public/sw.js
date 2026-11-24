/**
 * Crow Service Worker — PWA + Web Push
 *
 * Cache-first for static assets, network-first for API/dashboard.
 * Handles push events and notification clicks.
 */

// v3: drops a v2 cache that may hold the nest rendered inside the new shell.
const CACHE_NAME = "crow-v3";
const SHELL_ASSETS = ["/dashboard/nest"];

// The offline copy of the nest is kept only when the nest itself answered.
// A new-mode device's /dashboard/nest redirects to its new home (Chat), and a
// redirected response may not answer a navigation (redirect: "manual"), so
// such a device keeps no offline copy: it gets the browser's own offline page,
// as every other /dashboard/ route does. A failed fetch never fails install.
self.addEventListener("install", (e) => {
  e.waitUntil(caches.open(CACHE_NAME).then((c) => Promise.all(SHELL_ASSETS.map((path) =>
    fetch(path, { credentials: "same-origin", redirect: "manual" })
      .then((r) => (r.ok && r.type === "basic" && !r.redirected ? c.put(path, r) : undefined))
      .catch(() => undefined)))));
  self.skipWaiting();
});

self.addEventListener("activate", (e) => {
  // Clean up old caches
  e.waitUntil(
    caches.keys().then((names) =>
      Promise.all(
        names
          .filter((name) => name !== CACHE_NAME)
          .map((name) => caches.delete(name))
      )
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (e) => {
  const url = e.request.url;

  // Don't intercept cross-origin requests. When the SW re-fetches a
  // stylesheet/font that the <link> tag would have fetched natively, the
  // SW's fetch() call is subject to the page's connect-src (which is 'self'
  // here), even though the original request was allowed under style-src /
  // font-src. Letting cross-origin requests fall through avoids spurious
  // CSP violations (Google Fonts CSS was the offender).
  let reqOrigin;
  try { reqOrigin = new URL(url).origin; } catch { reqOrigin = null; }
  if (reqOrigin && reqOrigin !== self.location.origin) return;

  // PR-F explicit guard (2026-09-13): the perch interactive API is
  // authenticated JSON, and its /events route is SSE. Never intercept
  // either. Authed responses must not touch any cache path — and even
  // respondWith(fetch()) on an event-stream route pipes the stream
  // through the SW's fetch layer instead of the browser's native
  // EventSource handling. No respondWith at all keeps both exactly as
  // if this worker were not there.
  if (url.includes("/dashboard/perch-api/")) return;
  if (e.request.destination === "eventsource") return;
  try {
    if ((e.request.headers.get("accept") || "").includes("text/event-stream")) return;
  } catch { /* header read on an odd request — let the branches below decide */ }

  // Special case: /dashboard/nest is pre-cached for offline shell loading
  // (a classic device only; see install). Online, the network answers, so a
  // new-mode device follows its redirect to Chat.
  if (url.endsWith("/dashboard/nest")) {
    e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
    return;
  }
  // The PWA's start_url, /dashboard, routes per mode; offline, it falls back
  // to the same cached nest (present for a classic device only).
  let path = null;
  try { path = new URL(url).pathname; } catch { /* odd URL: the branches below decide */ }
  if (path === "/dashboard" && e.request.mode === "navigate") {
    e.respondWith(fetch(e.request).catch(() => caches.match("/dashboard/nest").then((r) => r || Response.error())));
    return;
  }

  // Other /dashboard/* routes: network-only, NO cache fallback.
  // Under Turbo Drive, a cache fallback would return stale HTML to the
  // body-swap machinery, potentially corrupting the UI. Let the browser's
  // native offline UI handle failed fetches.
  if (url.includes("/dashboard/")) {
    e.respondWith(fetch(e.request));
    return;
  }

  // API routes: network-first with cache fallback (existing behavior)
  if (url.includes("/api/")) {
    e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
    return;
  }

  // Cache-first for static assets (icons, fonts, etc.)
  e.respondWith(
    caches.match(e.request).then((cached) => cached || fetch(e.request))
  );
});

self.addEventListener("push", (e) => {
  const data = e.data?.json() || {};
  e.waitUntil(showPush(data));
});

/**
 * Show a push. A fired recurring reminder's payload also carries its notification id and the
 * words of its "Stop reminding" action (R2) plus the after-stop notice (R4) — both resolved
 * server-side, because a service worker has no i18n module. Every other push is shown exactly
 * as before, and so is its notification data. The notification data never holds a secret: the
 * action fetches the CSRF token itself (GET /dashboard/csrf) when it is tapped.
 */
function showPush(data) {
  const stop = reminderStop(data);
  const options = {
    body: data.body || "",
    icon: "/icons/crow-icon.svg",
    badge: "/icons/crow-icon.svg",
    data: { url: data.url || "/dashboard" },
  };
  if (stop) {
    options.actions = stop.actions;
    options.data.reminder = stop.reminder;
  }
  return self.registration.showNotification(data.title || "Crow", options);
}

/**
 * What a push's notification offers as actions, and what the action needs later:
 * `{ actions, reminder }` for a fired recurring reminder, otherwise null. Pure.
 *
 * Requires all three of `recurring === true`, a positive integer `id` and the label text: an
 * old gateway's payload (or one whose words could not be resolved) shows no action rather than
 * one with words of our own.
 */
function reminderStop(payload) {
  if (!payload || payload.recurring !== true) return null;
  const id = Number(payload.id);
  if (!Number.isInteger(id) || id <= 0) return null;
  if (typeof payload.stopLabel !== "string" || !payload.stopLabel) return null;
  return {
    actions: [{ action: "stop", title: payload.stopLabel }],
    reminder: { id, stoppedText: typeof payload.stoppedText === "string" ? payload.stoppedText : "" },
  };
}

/**
 * Did the stop request actually happen? "done" only for a 2xx answer whose JSON says
 * `{ ok: true }`. A login redirect is not a refusal the owner can act on (both requests use
 * `redirect: "manual"`, so a redirect arrives as `type === "opaqueredirect"`), a non-2xx is a
 * refusal (the route answers 409 / 403 for R8 and for a non-owner session) and a non-JSON body
 * means some page answered instead of the route: all of those are "open" — the tap then opens
 * the reminder, where the owner can see what happened. Pure.
 */
function stopOutcome(res, body) {
  if (!res || res.redirected || res.type === "opaqueredirect" || !res.ok) return "open";
  return body && body.ok === true ? "done" : "open";
}

/** The JSON body of an answer that may carry one, else null (a redirect, a refusal, a page). */
async function jsonAnswer(res) {
  if (!res || res.redirected || res.type === "opaqueredirect" || !res.ok) return null;
  try {
    return await res.json();
  } catch {
    return null;
  }
}

/**
 * POST the dashboard's stop route (#72 part 1) for this notification: the CSRF token first
 * (GET /dashboard/csrf — the token is server-bound and never in a cookie), then the POST with
 * the `X-Crow-Csrf` header. Both are same-origin, so the session cookie rides along; both use
 * `redirect: "manual"`, so an expired session (a redirect to the login page) is told apart
 * from a refusal. → "done" | "open".
 */
async function requestStop(id) {
  let answer;
  try {
    const csrf = await jsonAnswer(await fetch("/dashboard/csrf", {
      credentials: "same-origin",
      redirect: "manual",
      cache: "no-store",
      headers: { Accept: "application/json" },
    }));
    if (!csrf || typeof csrf.token !== "string" || !csrf.token) return "open";
    answer = await fetch("/dashboard/reminders/" + encodeURIComponent(id) + "/stop", {
      method: "POST",
      credentials: "same-origin",
      redirect: "manual",
      cache: "no-store",
      headers: { "X-Crow-Csrf": csrf.token, Accept: "application/json" },
    });
  } catch {
    return "open";
  }
  return stopOutcome(answer, await jsonAnswer(answer));
}

/** The reminder's notification was stopped: replace it with the R4 words the payload carried. */
function showStopped(reminder, title, url) {
  return self.registration.showNotification(title || "Crow", {
    body: reminder.stoppedText || "",
    icon: "/icons/crow-icon.svg",
    badge: "/icons/crow-icon.svg",
    data: { url: url || "/dashboard" },
  });
}

/** Focus an open dashboard window (Turbo knows the route) or open a new one. */
function openDashboard(url) {
  return self.clients
    .matchAll({ type: "window", includeUncontrolled: true })
    .then((windowClients) => {
      // Focus existing window if one is open
      for (const client of windowClients) {
        if (client.url.includes("/dashboard/") && "focus" in client) {
          client.navigate(url);
          return client.focus();
        }
      }
      // Otherwise open a new window
      return self.clients.openWindow(url);
    });
}

self.addEventListener("notificationclick", (e) => {
  // /dashboard routes per device mode (new → Chat, classic → the nest).
  const url = e.notification.data?.url || "/dashboard";
  // "Stop reminding" (a recurring reminder's action) stops the schedule, then says so; any
  // trouble (a login redirect, a refusal, a network error) opens the reminder instead.
  const reminder = e.action === "stop" ? e.notification.data?.reminder : null;
  const title = e.notification.title;
  e.notification.close();
  if (reminder) {
    e.waitUntil(
      requestStop(reminder.id).then((outcome) =>
        outcome === "done" ? showStopped(reminder, title, url) : openDashboard(url)
      )
    );
    return;
  }
  e.waitUntil(openDashboard(url));
});
