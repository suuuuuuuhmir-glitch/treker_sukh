const SHELL_CACHE = 'gymtracker-shell-v8';
const FONT_CACHE  = 'gymtracker-fonts-v2';
const SHELL_FILES = ['tracker.html', 'manifest.json', 'icon.svg'];

self.addEventListener('install', e => {
  e.waitUntil(
    caches.open(SHELL_CACHE)
      .then(c => c.addAll(SHELL_FILES))
      .then(()=>self.skipWaiting())
  );
});

self.addEventListener('activate', e => {
  e.waitUntil(
    caches.keys().then(keys=>
      Promise.all(keys.filter(k=>k!==SHELL_CACHE&&k!==FONT_CACHE).map(k=>caches.delete(k)))
    ).then(()=>clients.claim())
  );
});

self.addEventListener('message', e => {
  if(e.data&&e.data.type==='SKIP_WAITING') self.skipWaiting();
});

self.addEventListener('fetch', e => {
  const url = new URL(e.request.url);

  // Google Fonts — stale-while-revalidate
  if (url.hostname === 'fonts.googleapis.com' || url.hostname === 'fonts.gstatic.com') {
    e.respondWith(
      caches.open(FONT_CACHE).then(cache =>
        cache.match(e.request).then(cached => {
          const network = fetch(e.request).then(res => {
            cache.put(e.request, res.clone());
            return res;
          }).catch(() => cached);
          return cached || network;
        })
      )
    );
    return;
  }

  // App shell — cache-first, fallback to network
  if (url.origin === self.location.origin) {
    e.respondWith(
      caches.match(e.request).then(cached => {
        if (cached) return cached;
        return fetch(e.request).then(res => {
          if (res.ok) {
            const clone = res.clone();
            caches.open(SHELL_CACHE).then(c => c.put(e.request, clone));
          }
          return res;
        });
      })
    );
  }
});
