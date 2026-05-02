/* ═══════════════════════════════════════════════════════════════════
   uni-co — service-worker.js
   App shell caching + push notification handling
═══════════════════════════════════════════════════════════════════ */

const CACHE = 'uni-co-v2';

const SHELL = [
  '/',
  '/index.html',
  '/styles.css',
  '/mobile.css',
  '/app.js',
  '/mobile-patches.js',
  '/manifest.json',
  '/icons/icon-192x192.png',
  '/icons/icon-512x512.png',
  '/icons/apple-touch-icon.png',
  'https://cdn.jsdelivr.net/npm/@supabase/supabase-js@2/dist/umd/supabase.min.js',
];

/* ── Install ───────────────────────────────────────────────────────── */
self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(CACHE)
      .then(c => c.addAll(SHELL))
      .then(() => self.skipWaiting())
  );
});

/* ── Activate ─────────────────────────────────────────────────────── */
self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys()
      .then(keys => Promise.all(keys.filter(k => k !== CACHE).map(k => caches.delete(k))))
      .then(() => self.clients.claim())
  );
});

/* ── Fetch: cache-first for shell, network-first for Supabase ──────── */
self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);
  if (url.hostname.includes('supabase.co')) {
    e.respondWith(fetch(e.request).catch(() => caches.match(e.request)));
    return;
  }
  e.respondWith(
    caches.match(e.request).then(cached => {
      if (cached) return cached;
      return fetch(e.request).then(res => {
        if (res && res.status === 200 && res.type === 'basic') {
          const clone = res.clone();
          caches.open(CACHE).then(c => c.put(e.request, clone));
        }
        return res;
      });
    })
  );
});

/* ── Push: receive server-sent push notifications ─────────────────── */
self.addEventListener('push', e => {
  let data = { title: 'uni-co', body: 'You have a new notification', projectId: null };
  try { data = { ...data, ...e.data.json() }; } catch (_) {}

  e.waitUntil(
    self.registration.showNotification(data.title, {
      body: data.body,
      icon: '/icons/icon-192x192.png',
      badge: '/icons/icon-72x72.png',
      tag: data.projectId ? `chat-${data.projectId}` : 'uni-co',
      renotify: true,
      vibrate: [200, 100, 200],
      data: { url: data.projectId ? `/?ws=${data.projectId}` : '/' },
      actions: [
        { action: 'open',    title: 'Open' },
        { action: 'dismiss', title: 'Dismiss' },
      ],
    })
  );
});

/* ── Notification click ────────────────────────────────────────────── */
self.addEventListener('notificationclick', e => {
  e.notification.close();
  if (e.action === 'dismiss') return;

  const targetUrl = e.notification.data?.url || '/';

  e.waitUntil(
    clients.matchAll({ type: 'window', includeUncontrolled: true }).then(clientList => {
      // If app is already open, focus it and navigate
      for (const client of clientList) {
        if (client.url.includes(self.location.origin) && 'focus' in client) {
          client.focus();
          client.postMessage({ type: 'NAVIGATE', url: targetUrl });
          return;
        }
      }
      // Otherwise open a new window
      if (clients.openWindow) return clients.openWindow(targetUrl);
    })
  );
});
