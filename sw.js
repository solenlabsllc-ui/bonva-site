const CACHE = 'bonva-v1';
const ASSETS = ['/'];
self.addEventListener('install', e => {
  e.waitUntil(caches.open(CACHE).then(c => c.addAll(ASSETS)));
});
self.addEventListener('fetch', e => {
  e.respondWith(caches.match(e.request).then(r => r || fetch(e.request)));
});
self.addEventListener('push', e => {
  const data = e.data ? e.data.json() : {};
  e.waitUntil(self.registration.showNotification(
    data.title || 'Bonva',
    { body: data.body || 'Time for your daily question with your partner 💛',
      icon: '/icon-192.png', badge: '/icon-192.png' }
  ));
});
