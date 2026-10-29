// Servidor del Inventario Hogar. Todo acceso a datos pasa por aqui (D-002, D-010).
const enc = new TextEncoder();
const ITER = 100000; // tope del runtime de Workers
const MAX_FAILS = 3; // D-012
const LOCK_MS = 15 * 60 * 1000; // D-012
const IP_MAX = 15;
const SESSION_S = 7 * 24 * 3600;
const MAX_HOME = 3; // D-011

const b64 = (buf) => btoa(String.fromCharCode(...new Uint8Array(buf)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const b64url = (buf) => b64(buf).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
const json = (data, status = 200, headers = {}) =>
  new Response(JSON.stringify(data), {
    status,
    headers: { "content-type": "application/json", "cache-control": "no-store", ...headers },
  });
const DUMMY = `pbkdf2$${ITER}$${b64(new Uint8Array(16))}$${b64(new Uint8Array(32))}`;

async function derive(pw, salt, iter) {
  const key = await crypto.subtle.importKey("raw", enc.encode(pw), "PBKDF2", false, ["deriveBits"]);
  return new Uint8Array(
    await crypto.subtle.deriveBits({ name: "PBKDF2", hash: "SHA-256", salt, iterations: iter }, key, 256)
  );
}
async function hashPassword(pw) {
  const salt = crypto.getRandomValues(new Uint8Array(16));
  return `pbkdf2$${ITER}$${b64(salt)}$${b64(await derive(pw, salt, ITER))}`;
}
async function verifyPassword(pw, stored) {
  const [, it, s, h] = stored.split("$");
  const got = await derive(pw, unb64(s), Number(it));
  const want = unb64(h);
  let d = got.length ^ want.length;
  for (let i = 0; i < got.length; i++) d |= got[i] ^ (want[i] ?? 0);
  return d === 0;
}
async function sha256(s) {
  const d = await crypto.subtle.digest("SHA-256", enc.encode(s));
  return [...new Uint8Array(d)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

const norm = (e) => (typeof e === "string" ? e.trim().toLowerCase() : "");
const validEmail = (e) => e.length <= 254 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);

async function readJson(req) {
  if (!(req.headers.get("content-type") || "").includes("application/json")) return null;
  const text = await req.text();
  if (text.length > 4096) return null;
  try { return JSON.parse(text); } catch { return null; }
}

async function captchaOk(env, token, ip) {
  if (typeof token !== "string" || !token) return false;
  const body = new FormData();
  body.append("secret", env.TURNSTILE_SECRET);
  body.append("response", token);
  if (ip) body.append("remoteip", ip);
  const r = await fetch("https://challenges.cloudflare.com/turnstile/v0/siteverify", { method: "POST", body });
  const j = await r.json();
  return j.success === true;
}

async function getAttempts(env, key) {
  const row = await env.DB.prepare("SELECT failed, locked_until FROM login_attempts WHERE key = ?").bind(key).first();
  return row || { failed: 0, locked_until: null };
}
const lockedSeconds = (row) => {
  if (!row.locked_until) return 0;
  const ms = Date.parse(row.locked_until) - Date.now();
  return ms > 0 ? Math.ceil(ms / 1000) : 0;
};
async function addFail(env, key, max) {
  const row = await getAttempts(env, key);
  let failed = row.failed + 1;
  let locked = null;
  if (failed >= max) { locked = new Date(Date.now() + LOCK_MS).toISOString(); failed = 0; }
  await env.DB.prepare(
    "INSERT INTO login_attempts (key, failed, locked_until) VALUES (?1, ?2, ?3) ON CONFLICT(key) DO UPDATE SET failed = ?2, locked_until = ?3"
  ).bind(key, failed, locked).run();
  return { failed, locked };
}

async function newSession(env, personId, status = 200) {
  const raw = b64url(crypto.getRandomValues(new Uint8Array(32)));
  const exp = new Date(Date.now() + SESSION_S * 1000).toISOString();
  await env.DB.batch([
    env.DB.prepare("DELETE FROM sessions WHERE expires_at < ?").bind(new Date().toISOString()),
    env.DB.prepare("INSERT INTO sessions (id, person_id, expires_at) VALUES (?, ?, ?)").bind(await sha256(raw), personId, exp),
  ]);
  return json({ ok: true }, status, {
    "set-cookie": `sid=${raw}; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=${SESSION_S}`,
  });
}
function cookie(req, name) {
  const m = (req.headers.get("cookie") || "").match(new RegExp("(?:^|; )" + name + "=([^;]+)"));
  return m ? m[1] : null;
}
async function currentUser(req, env) {
  const raw = cookie(req, "sid");
  if (!raw) return null;
  return env.DB.prepare(
    "SELECT p.id, p.email, p.role, p.home_id, h.name AS home_name FROM sessions s JOIN people p ON p.id = s.person_id LEFT JOIN homes h ON h.id = p.home_id WHERE s.id = ? AND s.expires_at > ?"
  ).bind(await sha256(raw), new Date().toISOString()).first();
}

async function register(req, env, ip) {
  const b = await readJson(req);
  if (!b) return json({ error: "bad_request" }, 400);
  const email = norm(b.email);
  const pw = typeof b.password === "string" ? b.password : "";
  const home = typeof b.home_name === "string" ? b.home_name.trim() : "";
  if (!validEmail(email)) return json({ error: "invalid_email" }, 400);
  if (pw.length < 10 || pw.length > 200) return json({ error: "weak_password" }, 400);
  if (home.length < 1 || home.length > 60) return json({ error: "invalid_home" }, 400);
  if (!(await captchaOk(env, b.token, ip))) return json({ error: "captcha" }, 400);
  const hid = crypto.randomUUID();
  const pid = crypto.randomUUID();
  const hash = await hashPassword(pw);
  try {
    await env.DB.batch([
      env.DB.prepare("INSERT INTO homes (id, name, manager_id) VALUES (?, ?, ?)").bind(hid, home, pid),
      env.DB.prepare("INSERT INTO people (id, email, password_hash, home_id, role) VALUES (?, ?, ?, ?, 'manager')").bind(pid, email, hash, hid),
    ]);
  } catch (e) {
    if (/UNIQUE/i.test(String(e.message))) return json({ error: "email_in_use" }, 409);
    throw e;
  }
  return newSession(env, pid, 201);
}

async function login(req, env, ip) {
  const b = await readJson(req);
  if (!b) return json({ error: "bad_request" }, 400);
  const email = norm(b.email);
  const pw = typeof b.password === "string" ? b.password : "";
  if (!validEmail(email) || pw.length < 1 || pw.length > 200) return json({ error: "invalid_credentials" }, 401);
  if (!(await captchaOk(env, b.token, ip))) return json({ error: "captcha" }, 400);
  const ek = "email:" + email;
  const ik = "ip:" + ip;
  const [er, ir] = await Promise.all([getAttempts(env, ek), getAttempts(env, ik)]);
  const wait = Math.max(lockedSeconds(er), lockedSeconds(ir));
  if (wait > 0) return json({ error: "locked", retry_after: wait }, 423);
  const p = await env.DB.prepare("SELECT id, password_hash FROM people WHERE email = ?").bind(email).first();
  const ok = await verifyPassword(pw, p ? p.password_hash : DUMMY);
  if (!p || !ok) {
    const e = await addFail(env, ek, MAX_FAILS);
    await addFail(env, ik, IP_MAX);
    if (e.locked) return json({ error: "locked", retry_after: LOCK_MS / 1000 }, 423);
    return json({ error: "invalid_credentials", attempts_left: MAX_FAILS - e.failed }, 401);
  }
  await env.DB.prepare("DELETE FROM login_attempts WHERE key = ?").bind(ek).run();
  return newSession(env, p.id);
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (!url.pathname.startsWith("/api/")) return env.ASSETS.fetch(request);
    try {
      const ip = request.headers.get("cf-connecting-ip") || "unknown";
      const p = url.pathname;
      if (request.method === "GET" && p === "/api/health") {
        const r = await env.DB.prepare(
          "SELECT COUNT(*) AS n FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%' AND name NOT LIKE '_cf_%'"
        ).first();
        return json({ ok: true, tables: r.n, bindings: Object.keys(env) });
      }
      if (request.method === "GET" && p === "/api/me") {
        const u = await currentUser(request, env);
        if (!u) return json({ error: "unauthorized" }, 401);
        const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM people WHERE home_id = ?").bind(u.home_id).first();
        return json({ email: u.email, role: u.role, home: { name: u.home_name, members: c.n, max: MAX_HOME } });
      }
      if (request.method === "POST") {
        const origin = request.headers.get("origin");
        if (origin && new URL(origin).host !== url.host) return json({ error: "forbidden" }, 403);
        if (!env.TURNSTILE_SECRET) return json({ error: "server_config" }, 500);
        if (p === "/api/register") return await register(request, env, ip);
        if (p === "/api/login") return await login(request, env, ip);
        if (p === "/api/logout") {
          const raw = cookie(request, "sid");
          if (raw) await env.DB.prepare("DELETE FROM sessions WHERE id = ?").bind(await sha256(raw)).run();
          return json({ ok: true }, 200, { "set-cookie": "sid=; HttpOnly; Secure; SameSite=Strict; Path=/; Max-Age=0" });
        }
      }
      return json({ error: "not_found" }, 404);
    } catch (e) {
      return json({ error: "server" }, 500);
    }
  },
};
