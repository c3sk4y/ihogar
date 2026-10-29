// Servidor del Inventario Hogar. Todo acceso a datos pasa por aquí (D-002, D-010).
export default {
  async fetch(request, env) {
    const url = new URL(request.url);

    if (url.pathname === "/api/health") {
      try {
        const r = await env.DB.prepare(
          "SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'"
        ).first();
        return Response.json({ ok: true, tables: r.n });
      } catch (e) {
        return Response.json({ ok: false }, { status: 500 });
      }
    }

    if (url.pathname.startsWith("/api/")) {
      return Response.json({ error: "not_found" }, { status: 404 });
    }

    return env.ASSETS.fetch(request);
  },
};
