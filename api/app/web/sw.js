"use strict";
/* DentaCore Service Worker: yalnızca /static/* varlıklarını önbelleğe alır. /app/api ve /auth asla önbelleğe alınmaz. */
const CACHE_NAME = "dentacore-static-v7";
const STATIC_ASSETS = [
  "/static/landing.css",
  "/static/landing.js",
  "/static/app.css",
  "/static/app.js",
  "/static/favicon.svg",
  "/static/icon-192.png",
  "/static/icon-512.png",
  "/static/apple-touch-icon.png",
  "/static/inter-latin.woff2",
  "/static/inter-latin-ext.woff2",
  "/static/jakarta-latin.woff2",
  "/static/jakarta-latin-ext.woff2"
];

self.addEventListener("install", (event) => {
  event.waitUntil(
    caches.open(CACHE_NAME).then((cache) => cache.addAll(STATIC_ASSETS)).catch(() => {})
  );
  self.skipWaiting();
});

self.addEventListener("activate", (event) => {
  event.waitUntil(
    caches.keys().then((keys) =>
      Promise.all(keys.filter((k) => k !== CACHE_NAME).map((k) => caches.delete(k)))
    )
  );
  self.clients.claim();
});

self.addEventListener("fetch", (event) => {
  const req = event.request;
  if (req.method !== "GET") return;
  const url = new URL(req.url);
  if (url.origin !== self.location.origin) return;

  // API, kimlik doğrulama, takvim akışı ve klinik formları asla önbellekten dönülmez.
  if (
    url.pathname.startsWith("/app/api") ||
    url.pathname.startsWith("/auth") ||
    url.pathname.startsWith("/calendar/") ||
    url.pathname.startsWith("/form/") ||
    url.pathname.startsWith("/view/") ||
    url.pathname.startsWith("/lead") ||
    url.pathname.startsWith("/webhook/")
  ) {
    return;
  }

  // Yalnızca /static/ altındaki değişmez arayüz varlıkları cache-first sunulur.
  if (!url.pathname.startsWith("/static/")) return;

  // Stale-while-revalidate: anında önbellekten açılır, arka planda güncel sürüm çekilir.
  // Böylece CSS/JS güncellemeleri bir sonraki açılışta herkese ulaşır (eski tasarımda takılı kalmaz).
  event.respondWith(
    caches.open(CACHE_NAME).then((cache) =>
      cache.match(req).then((cached) => {
        const network = fetch(req).then((res) => {
          if (res && res.ok) cache.put(req, res.clone()).catch(() => {});
          return res;
        }).catch(() => cached);
        return cached || network;
      })
    )
  );
});
