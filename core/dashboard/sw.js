/* SonuShield dashboard service worker (Batch 6): app shell only.
 *
 * What it caches: the dashboard page, the manifest, and the PWA
 * icons — the static shell, which contains no secrets and no
 * live data. What it NEVER caches: API responses (/_bProxy/api/*),
 * SSO endpoints, or any request carrying credentials or a secret
 * header. Those always go straight to the network, uncached.
 * Non-shell same-origin GETs also bypass the cache entirely.
 *
 * The shell is served with no-store headers by the proxy, but
 * Cache Storage is a separate store the page opts into here;
 * the cached shell lets the installed app open offline and show
 * its disconnected state instead of a browser error page.
 * Bump SHELL_VERSION when the shell files change.
 */
"use strict";

var SHELL_VERSION = "sonushield-shell-v18";
var SHELL_URLS = [
  "./dashboard",
  "./manifest.webmanifest",
  "./icons/icon-192.png",
  "./icons/icon-512.png",
  "./icons/icon-maskable-512.png",
  "./icons/icon-180.png",
  "./vendor/three-r128.min.js",
  "./fonts/Inter-Regular.woff2",
  "./fonts/Inter-Medium.woff2",
  "./fonts/Inter-SemiBold.woff2",
  "./fonts/Inter-Bold.woff2",
  "./fonts/JetBrainsMono-Regular.woff2",
  "./fonts/JetBrainsMono-Medium.woff2",
  "./fonts/JetBrainsMono-Bold.woff2"
];

self.addEventListener("install", function (event) {
  event.waitUntil(
    caches.open(SHELL_VERSION).then(function (cache) {
      return cache.addAll(SHELL_URLS);
    }).then(function () {
      return self.skipWaiting();
    })
  );
});

self.addEventListener("activate", function (event) {
  event.waitUntil(
    caches.keys().then(function (keys) {
      return Promise.all(keys.map(function (key) {
        if (key !== SHELL_VERSION) return caches.delete(key);
        return Promise.resolve();
      }));
    }).then(function () {
      return self.clients.claim();
    })
  );
});

function isShellRequest(request) {
  if (request.method !== "GET") return false;
  var url = new URL(request.url);
  if (url.origin !== self.location.origin) return false;
  // The shell lives under the dashboard's own path prefix. The
  // admin secret is a path segment; matching the exact shell
  // suffixes keeps API and SSO paths out of the cache by
  // construction, even though they share the /_bProxy/ prefix.
  var path = url.pathname;
  if (path === self.location.pathname.replace(/sw\.js$/, "dashboard")) return true;
  if (path === self.location.pathname.replace(/sw\.js$/, "manifest.webmanifest")) return true;
  if (/\/icons\/icon-(192|512|180|maskable-512)\.png$/.test(path)) return true;
  if (/\/vendor\/three-r128\.min\.js$/.test(path)) return true;
  if (/\/fonts\/[A-Za-z0-9._-]+\.woff2$/.test(path)) return true;
  return false;
}

self.addEventListener("fetch", function (event) {
  if (!isShellRequest(event.request)) {
    // Everything else: network only, never cached. This covers
    // all API calls, SSO, and any request with credentials.
    return;
  }
  event.respondWith(
    caches.match(event.request, { ignoreSearch: true }).then(function (cached) {
      if (cached) return cached;
      return fetch(event.request);
    })
  );
});
