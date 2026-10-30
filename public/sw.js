// Sin cache de datos: el inventario vive solo en la nube (D-002). Solo muestra un aviso si no hay internet.
const OFFLINE = '<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Inventario</title>' +
  '<body style="font-family:system-ui,sans-serif;margin:0;padding:48px 24px;color:#16181D"><h1 style="font-size:22px;color:#1F4E9C">Inventario</h1>' +
  '<p>Sin conexi\u00f3n a internet. Con\u00e9ctate para ver tu inventario.</p><p style="color:#4A4F5A">No internet connection. Connect to see your inventory.</p></body>';
self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (e) => e.waitUntil(self.clients.claim()));
self.addEventListener("fetch", (e) => {
  if (e.request.mode === "navigate") {
    e.respondWith(fetch(e.request).catch(() => new Response(OFFLINE, { headers: { "content-type": "text/html; charset=utf-8" } })));
  }
});
