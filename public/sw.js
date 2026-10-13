// Only cache non-sensitive static shell assets; never cache API replies or notes.
const CACHE='byteback-shell-v11';
const ASSETS=['/','/index.html','/app.js','/icon.svg','/manifest.webmanifest'];
self.addEventListener('install',event=>{
 event.waitUntil(caches.open(CACHE).then(c=>c.addAll(ASSETS)).then(()=>self.skipWaiting()));
});
self.addEventListener('activate',event=>{
 event.waitUntil(caches.keys().then(keys=>Promise.all(keys.filter(k=>k!==CACHE)
  .map(k=>caches.delete(k)))).then(()=>self.clients.claim()));
});
self.addEventListener('fetch',event=>{
 const url=new URL(event.request.url);
 // Never intercept authenticated requests; no API data is stored offline.
 if(url.origin!==self.location.origin||url.pathname.startsWith('/api/') ||
   url.pathname.startsWith('/aleph')||url.pathname.startsWith('/data'))return;
 if(!ASSETS.includes(url.pathname))return;
 event.respondWith(fetch(event.request).catch(()=>caches.match(event.request)));
});
