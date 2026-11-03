
const CACHE_NAME = 'medconnect-cache-v1';

self.addEventListener('install', (event) => {
    self.skipWaiting();
});

self.addEventListener('activate', (event) => {
    event.waitUntil(
        (async () => {
            await self.clients.claim();
        })()
    );
});

self.addEventListener('fetch', (event) => {
    // Use normal network requests. Do not cache login or API responses.
    if (event.request.method !== 'GET') return;
});
