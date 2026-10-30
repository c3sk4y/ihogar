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

async function readJson(req, max = 4096) {
  if (!(req.headers.get("content-type") || "").includes("application/json")) return null;
  const text = await req.text();
  if (text.length > max) return null;
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
  const invite = typeof b.invite === "string" && b.invite ? b.invite : null;
  if (!validEmail(email)) return json({ error: "invalid_email" }, 400);
  if (pw.length < 10 || pw.length > 200) return json({ error: "weak_password" }, 400);
  if (!invite && (home.length < 1 || home.length > 60)) return json({ error: "invalid_home" }, 400);
  if (!(await captchaOk(env, b.token, ip))) return json({ error: "captcha" }, 400);
  const pid = crypto.randomUUID();
  const hash = await hashPassword(pw);
  let stmts;
  if (invite) {
    const inv = await env.DB.prepare("SELECT id, home_id, email FROM invitations WHERE token_hash = ? AND status = 'pending' AND expires_at > ?")
      .bind(await sha256(invite), new Date().toISOString()).first();
    if (!inv || String(inv.email).toLowerCase() !== email) return json({ error: "invalid_invite" }, 400);
    const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM people WHERE home_id = ?").bind(inv.home_id).first();
    if (c.n >= MAX_HOME) return json({ error: "home_full" }, 409);
    stmts = [
      env.DB.prepare("INSERT INTO people (id, email, password_hash, home_id, role) VALUES (?, ?, ?, ?, 'member')").bind(pid, email, hash, inv.home_id),
      env.DB.prepare("UPDATE invitations SET status = 'accepted' WHERE id = ?").bind(inv.id),
    ];
  } else {
    const hid = crypto.randomUUID();
    stmts = [
      env.DB.prepare("INSERT INTO homes (id, name, manager_id) VALUES (?, ?, ?)").bind(hid, home, pid),
      env.DB.prepare("INSERT INTO people (id, email, password_hash, home_id, role) VALUES (?, ?, ?, ?, 'manager')").bind(pid, email, hash, hid),
      ...DEFAULT_LOCS.map((n) => env.DB.prepare("INSERT INTO locations (id, home_id, name) VALUES (?, ?, ?)").bind(crypto.randomUUID(), hid, n)),
    ];
  }
  try {
    await env.DB.batch(stmts);
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

const CATS = ["food", "cleaning", "supplies", "medicine"];
const UNITS = ["unit", "kg", "g", "l", "ml", "dose", "sachet", "tablet"];
const validPhoto = (p) => typeof p === "string" && p.length <= 160000 && /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+\/=]+$/.test(p);
async function fetchPhoto(url) {
  if (!/^https:\/\/images\.openfoodfacts\.org\/[\w\/.\-]+$/.test(url)) return null;
  try {
    const r = await fetch(url, { headers: { "user-agent": "InventarioHogar/0.1" }, signal: AbortSignal.timeout(4000) });
    if (!r.ok) return null;
    const ct = (r.headers.get("content-type") || "").split(";")[0];
    if (!/^image\/(jpeg|png|webp)$/.test(ct)) return null;
    const buf = new Uint8Array(await r.arrayBuffer());
    if (buf.length > 110000) return null;
    let bin = "";
    for (let i = 0; i < buf.length; i += 8192) bin += String.fromCharCode(...buf.subarray(i, i + 8192));
    return "data:" + ct + ";base64," + btoa(bin);
  } catch (e) { return null; }
}
async function getPhoto(env, u, pid) {
  const r = await env.DB.prepare("SELECT photo FROM products WHERE id = ? AND home_id = ?").bind(pid, u.home_id).first();
  const m = r && r.photo ? r.photo.match(/^data:(image\/[a-z]+);base64,(.+)$/) : null;
  if (!m) return new Response(null, { status: 404 });
  return new Response(Uint8Array.from(atob(m[2]), (c) => c.charCodeAt(0)), { headers: { "content-type": m[1], "cache-control": "private, max-age=300" } });
}
async function setPhoto(req, env, u, pid) {
  const b = await readJson(req, 250000);
  if (!b || !validPhoto(b.photo)) return json({ error: "invalid_photo" }, 400);
  const r = await env.DB.prepare("UPDATE products SET photo = ? WHERE id = ? AND home_id = ?").bind(b.photo, pid, u.home_id).run();
  if (!r.meta.changes) return json({ error: "not_found" }, 404);
  return json({ ok: true });
}
const PACKS = ["box", "jar", "bottle", "pack", "can", "tube", "bag"];
const pad14 = (c) => String(c).padStart(14, "0");
const DEFAULT_LOCS = ["kitchen", "pantry", "fridge", "bathroom", "medicine", "storage"];
const isDate = (s) => typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s));
const FIFO = "ORDER BY (b.expiry_date IS NULL), b.expiry_date, b.purchase_date, b.created_at";

async function listLocations(env, u) {
  const r = await env.DB.prepare("SELECT id, name FROM locations WHERE home_id = ? ORDER BY name").bind(u.home_id).all();
  return json({ locations: r.results });
}
async function listProducts(env, u) {
  const r = await env.DB.prepare("SELECT id, name, category, unit, barcode, min_stock, pack_size, pack_label, (photo IS NOT NULL) AS has_photo FROM products WHERE home_id = ? ORDER BY name").bind(u.home_id).all();
  return json({ products: r.results });
}
async function listInventory(env, u) {
  const r = await env.DB.prepare(
    "SELECT b.id AS batch_id, b.product_id, p.name, p.category, p.unit, p.min_stock, p.barcode, b.location_id, p.pack_size, p.pack_label, (p.photo IS NOT NULL) AS has_photo, b.initial_quantity, b.quantity, b.purchase_date, b.expiry_date, l.name AS location, o.email AS owner, " +
    "(SELECT SUM(b2.quantity) FROM batches b2 WHERE b2.product_id = p.id AND b2.status = 'active') AS total " +
    "FROM batches b JOIN products p ON p.id = b.product_id LEFT JOIN locations l ON l.id = b.location_id LEFT JOIN people o ON o.id = b.owner_id " +
    "WHERE p.home_id = ? AND b.status = 'active' " + FIFO
  ).bind(u.home_id).all();
  return json({ items: r.results });
}
async function addBatch(req, env, u) {
  const b = await readJson(req, 250000);
  if (!b) return json({ error: "bad_request" }, 400);
  const name = typeof b.name === "string" ? b.name.trim() : "";
  if (name.length < 1 || name.length > 80) return json({ error: "invalid_name" }, 400);
  if (!CATS.includes(b.category)) return json({ error: "invalid_category" }, 400);
  if (!UNITS.includes(b.unit)) return json({ error: "invalid_unit" }, 400);
  const n = Number(b.quantity);
  if (!(n > 0 && n <= 100000)) return json({ error: "invalid_quantity" }, 400);
  const packLabel = b.pack_label ? String(b.pack_label) : null;
  if (packLabel && !PACKS.includes(packLabel)) return json({ error: "invalid_pack" }, 400);
  const packSize = b.pack_size ? Number(b.pack_size) : null;
  if (packSize !== null && !(packSize > 0 && packSize <= 100000)) return json({ error: "invalid_pack" }, 400);
  const qty = Math.round(n * (packSize || 1) * 1e6) / 1e6;
  if (qty > 1000000) return json({ error: "invalid_quantity" }, 400);
  const min = Number(b.min_stock || 0);
  if (!(min >= 0 && min <= 1000000)) return json({ error: "invalid_quantity" }, 400);
  if (!isDate(b.purchase_date)) return json({ error: "invalid_date" }, 400);
  const exp = b.expiry_date ? b.expiry_date : null;
  if (exp && !isDate(exp)) return json({ error: "invalid_date" }, 400);
  if ((b.category === "food" || b.category === "medicine") && !exp) return json({ error: "expiry_required" }, 400);
  const barcode = typeof b.barcode === "string" && b.barcode.trim() ? b.barcode.trim() : null;
  if (barcode && !/^\d{6,14}$/.test(barcode)) return json({ error: "invalid_barcode" }, 400);
  const loc = await env.DB.prepare("SELECT id FROM locations WHERE id = ? AND home_id = ?").bind(String(b.location_id || ""), u.home_id).first();
  if (!loc) return json({ error: "invalid_location" }, 400);
  let photo = null;
  if (b.photo) { if (!validPhoto(b.photo)) return json({ error: "invalid_photo" }, 400); photo = b.photo; }
  else if (typeof b.photo_url === "string" && b.photo_url) photo = await fetchPhoto(b.photo_url);
  const prod = barcode
    ? await env.DB.prepare("SELECT id, (photo IS NOT NULL) AS hp FROM products WHERE home_id = ? AND substr('00000000000000' || barcode, -14) = ?").bind(u.home_id, pad14(barcode)).first()
    : await env.DB.prepare("SELECT id, (photo IS NOT NULL) AS hp FROM products WHERE home_id = ? AND barcode IS NULL AND lower(name) = lower(?) AND unit = ?").bind(u.home_id, name, b.unit).first();
  const stmts = [];
  let pid;
  if (prod) {
    pid = prod.id;
    if (photo && (b.photo || !prod.hp)) stmts.push(env.DB.prepare("UPDATE products SET photo = ? WHERE id = ?").bind(photo, pid));
    if (packSize || packLabel) stmts.push(env.DB.prepare("UPDATE products SET pack_size = ?, pack_label = ? WHERE id = ?").bind(packSize, packLabel, pid));
  } else {
    pid = crypto.randomUUID();
    stmts.push(env.DB.prepare("INSERT INTO products (id, home_id, name, category, barcode, unit, min_stock, pack_size, pack_label, photo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(pid, u.home_id, name, b.category, barcode, b.unit, min, packSize, packLabel, photo));
  }
  const bid = crypto.randomUUID();
  stmts.push(env.DB.prepare("INSERT INTO batches (id, product_id, location_id, owner_id, quantity, initial_quantity, purchase_date, expiry_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").bind(bid, pid, loc.id, u.id, qty, qty, b.purchase_date, exp));
  stmts.push(env.DB.prepare("INSERT INTO movements (id, batch_id, type, quantity, person_id) VALUES (?, ?, 'in', ?, ?)").bind(crypto.randomUUID(), bid, qty, u.id));
  await env.DB.batch(stmts);
  return json({ ok: true, id: bid }, 201);
}
async function deleteBatch(env, u, bid) {
  const r = await env.DB.prepare("SELECT b.id, b.owner_id, b.product_id FROM batches b JOIN products p ON p.id = b.product_id WHERE b.id = ? AND p.home_id = ?").bind(bid, u.home_id).first();
  if (!r) return json({ error: "not_found" }, 404);
  if (u.role !== "manager" && r.owner_id !== u.id) return json({ error: "forbidden" }, 403);
  try {
    await env.DB.batch([
      env.DB.prepare("DELETE FROM movements WHERE batch_id = ?").bind(bid),
      env.DB.prepare("DELETE FROM batches WHERE id = ?").bind(bid),
      env.DB.prepare("DELETE FROM products WHERE id = ? AND NOT EXISTS (SELECT 1 FROM batches WHERE product_id = ?)").bind(r.product_id, r.product_id),
    ]);
  } catch (e) { return json({ error: "in_use" }, 409); }
  return json({ ok: true });
}
const DEFAULT_LABELS = {
  kitchen: ["cocina", "kitchen"], pantry: ["despensa", "pantry"], fridge: ["refrigerador", "refrigerator", "refri", "fridge", "nevera"],
  bathroom: ["ba\u00f1o", "bano", "bathroom"], medicine: ["botiqu\u00edn", "botiquin", "medicine cabinet"], storage: ["bodega", "storage room", "storage"],
};
function canonLoc(name) {
  const l = name.toLowerCase();
  for (const k in DEFAULT_LABELS) if (DEFAULT_LABELS[k].includes(l)) return k;
  return name;
}
async function locName(req) {
  const b = await readJson(req);
  const n = b && typeof b.name === "string" ? b.name.trim() : "";
  return n.length >= 1 && n.length <= 40 ? canonLoc(n) : null;
}
async function createLocation(req, env, u) {
  const n = await locName(req);
  if (!n) return json({ error: "invalid_location_name" }, 400);
  if (await env.DB.prepare("SELECT id FROM locations WHERE home_id = ? AND lower(name) = lower(?)").bind(u.home_id, n).first()) return json({ error: "location_exists" }, 409);
  const id = crypto.randomUUID();
  await env.DB.prepare("INSERT INTO locations (id, home_id, name) VALUES (?, ?, ?)").bind(id, u.home_id, n).run();
  return json({ ok: true, id }, 201);
}
async function renameLocation(req, env, u, id) {
  if (u.role !== "manager") return json({ error: "forbidden" }, 403);
  const n = await locName(req);
  if (!n) return json({ error: "invalid_location_name" }, 400);
  if (await env.DB.prepare("SELECT id FROM locations WHERE home_id = ? AND id <> ? AND lower(name) = lower(?)").bind(u.home_id, id, n).first()) return json({ error: "location_exists" }, 409);
  const r = await env.DB.prepare("UPDATE locations SET name = ? WHERE id = ? AND home_id = ?").bind(n, id, u.home_id).run();
  if (!r.meta.changes) return json({ error: "not_found" }, 404);
  return json({ ok: true });
}
async function deleteLocation(env, u, id) {
  if (u.role !== "manager") return json({ error: "forbidden" }, 403);
  const l = await env.DB.prepare("SELECT id FROM locations WHERE id = ? AND home_id = ?").bind(id, u.home_id).first();
  if (!l) return json({ error: "not_found" }, 404);
  const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM batches WHERE location_id = ? AND status = 'active'").bind(id).first();
  if (c.n > 0) return json({ error: "location_in_use" }, 409);
  await env.DB.batch([
    env.DB.prepare("UPDATE batches SET location_id = NULL WHERE location_id = ?").bind(id),
    env.DB.prepare("DELETE FROM locations WHERE id = ? AND home_id = ?").bind(id, u.home_id),
  ]);
  return json({ ok: true });
}
async function editBatch(req, env, u, bid) {
  const r = await env.DB.prepare("SELECT b.id, b.owner_id, b.quantity, b.initial_quantity, b.product_id FROM batches b JOIN products p ON p.id = b.product_id WHERE b.id = ? AND p.home_id = ? AND b.status = 'active'").bind(bid, u.home_id).first();
  if (!r) return json({ error: "not_found" }, 404);
  if (u.role !== "manager" && r.owner_id !== u.id) return json({ error: "forbidden" }, 403);
  const b = await readJson(req, 250000);
  if (!b) return json({ error: "bad_request" }, 400);
  const name = typeof b.name === "string" ? b.name.trim() : "";
  if (name.length < 1 || name.length > 80) return json({ error: "invalid_name" }, 400);
  if (!CATS.includes(b.category)) return json({ error: "invalid_category" }, 400);
  if (!UNITS.includes(b.unit)) return json({ error: "invalid_unit" }, 400);
  const qty = Number(b.quantity);
  if (!(qty > 0 && qty <= 1000000)) return json({ error: "invalid_quantity" }, 400);
  const packLabel = b.pack_label ? String(b.pack_label) : null;
  if (packLabel && !PACKS.includes(packLabel)) return json({ error: "invalid_pack" }, 400);
  const packSize = b.pack_size ? Number(b.pack_size) : null;
  if (packSize !== null && !(packSize > 0 && packSize <= 100000)) return json({ error: "invalid_pack" }, 400);
  const min = Number(b.min_stock || 0);
  if (!(min >= 0 && min <= 1000000)) return json({ error: "invalid_quantity" }, 400);
  if (!isDate(b.purchase_date)) return json({ error: "invalid_date" }, 400);
  const exp = b.expiry_date ? b.expiry_date : null;
  if (exp && !isDate(exp)) return json({ error: "invalid_date" }, 400);
  if ((b.category === "food" || b.category === "medicine") && !exp) return json({ error: "expiry_required" }, 400);
  const barcode = typeof b.barcode === "string" && b.barcode.trim() ? b.barcode.trim() : null;
  if (barcode && !/^\d{6,14}$/.test(barcode)) return json({ error: "invalid_barcode" }, 400);
  if (barcode && (await env.DB.prepare("SELECT id FROM products WHERE home_id = ? AND id <> ? AND substr('00000000000000' || barcode, -14) = ?").bind(u.home_id, r.product_id, pad14(barcode)).first())) return json({ error: "barcode_in_use" }, 409);
  const loc = await env.DB.prepare("SELECT id FROM locations WHERE id = ? AND home_id = ?").bind(String(b.location_id || ""), u.home_id).first();
  if (!loc) return json({ error: "invalid_location" }, 400);
  if (b.photo && !validPhoto(b.photo)) return json({ error: "invalid_photo" }, 400);
  const initial = Math.max(r.initial_quantity || r.quantity, qty);
  const stmts = [
    env.DB.prepare("UPDATE products SET name = ?, category = ?, unit = ?, barcode = ?, min_stock = ?, pack_size = ?, pack_label = ? WHERE id = ?").bind(name, b.category, b.unit, barcode, min, packSize, packLabel, r.product_id),
    env.DB.prepare("UPDATE batches SET location_id = ?, quantity = ?, initial_quantity = ?, purchase_date = ?, expiry_date = ? WHERE id = ?").bind(loc.id, qty, initial, b.purchase_date, exp, bid),
  ];
  if (b.photo) stmts.push(env.DB.prepare("UPDATE products SET photo = ? WHERE id = ?").bind(b.photo, r.product_id));
  if (Math.abs(qty - r.quantity) > 1e-9) stmts.push(env.DB.prepare("INSERT INTO movements (id, batch_id, type, quantity, person_id, note) VALUES (?, ?, 'adjust', ?, ?, 'edit')").bind(crypto.randomUUID(), bid, Math.round((qty - r.quantity) * 1e6) / 1e6, u.id));
  try { await env.DB.batch(stmts); } catch (e) {
    if (/UNIQUE/i.test(String(e.message))) return json({ error: "barcode_in_use" }, 409);
    throw e;
  }
  return json({ ok: true });
}
async function useProduct(req, env, u, pid) {
  const b = await readJson(req);
  const qty = b ? Number(b.quantity) : 0;
  if (!(qty > 0 && qty <= 100000)) return json({ error: "invalid_quantity" }, 400);
  const prod = await env.DB.prepare("SELECT id FROM products WHERE id = ? AND home_id = ?").bind(pid, u.home_id).first();
  if (!prod) return json({ error: "not_found" }, 404);
  const rows = (await env.DB.prepare("SELECT b.id, b.quantity FROM batches b WHERE b.product_id = ? AND b.status = 'active' " + FIFO).bind(pid).all()).results;
  const total = rows.reduce((a, r) => a + r.quantity, 0);
  if (qty > total + 1e-9) return json({ error: "insufficient", available: total }, 409);
  let left = qty;
  const stmts = [];
  for (const r of rows) {
    if (left <= 1e-9) break;
    const take = Math.min(r.quantity, left);
    const rem = Math.round((r.quantity - take) * 1e6) / 1e6;
    stmts.push(env.DB.prepare("UPDATE batches SET quantity = ?, status = ? WHERE id = ?").bind(rem, rem <= 0 ? "empty" : "active", r.id));
    stmts.push(env.DB.prepare("INSERT INTO movements (id, batch_id, type, quantity, person_id) VALUES (?, ?, 'use', ?, ?)").bind(crypto.randomUUID(), r.id, take, u.id));
    left = Math.round((left - take) * 1e6) / 1e6;
  }
  await env.DB.batch(stmts);
  return json({ ok: true });
}
async function discardBatch(env, u, bid) {
  const r = await env.DB.prepare("SELECT b.id, b.quantity FROM batches b JOIN products p ON p.id = b.product_id WHERE b.id = ? AND p.home_id = ? AND b.status = 'active'").bind(bid, u.home_id).first();
  if (!r) return json({ error: "not_found" }, 404);
  await env.DB.batch([
    env.DB.prepare("UPDATE batches SET status = 'discarded' WHERE id = ?").bind(bid),
    env.DB.prepare("INSERT INTO movements (id, batch_id, type, quantity, person_id) VALUES (?, ?, 'waste', ?, ?)").bind(crypto.randomUUID(), bid, r.quantity, u.id),
  ]);
  return json({ ok: true });
}

async function lookup(env, u, code) {
  if (!/^\d{6,14}$/.test(code)) return json({ error: "invalid_barcode" }, 400);
  const own = await env.DB.prepare(
    "SELECT p.id, (p.photo IS NOT NULL) AS has_photo, p.name, p.category, p.unit, p.min_stock, p.pack_size, p.pack_label, (SELECT b.location_id FROM batches b WHERE b.product_id = p.id ORDER BY b.created_at DESC LIMIT 1) AS location_id " +
    "FROM products p WHERE p.home_id = ? AND substr('00000000000000' || p.barcode, -14) = ?"
  ).bind(u.home_id, pad14(code)).first();
  if (own) return json({ found: "home", product: own });
  try {
    const r = await fetch("https://world.openfoodfacts.org/api/v2/product/" + code + ".json?fields=product_name,brands,image_front_small_url", {
      headers: { "user-agent": "InventarioHogar/0.1" },
      signal: AbortSignal.timeout(4000),
    });
    if (r.ok) {
      const j = await r.json();
      if (j.status === 1 && j.product && j.product.product_name) {
        const brand = j.product.brands ? String(j.product.brands).split(",")[0].trim().slice(0, 40) : "";
        const img = typeof j.product.image_front_small_url === "string" && j.product.image_front_small_url.startsWith("https://images.openfoodfacts.org/") ? j.product.image_front_small_url : "";
        return json({ found: "off", product: { name: String(j.product.product_name).slice(0, 80), brand, image_url: img } });
      }
    }
  } catch (e) {}
  return json({ found: null });
}
async function homeInfo(env, u) {
  const members = (await env.DB.prepare("SELECT id, email, role FROM people WHERE home_id = ? ORDER BY (role = 'manager') DESC, email").bind(u.home_id).all()).results;
  let invitations = [];
  if (u.role === "manager") {
    invitations = (await env.DB.prepare("SELECT id, email, expires_at FROM invitations WHERE home_id = ? AND status = 'pending' AND expires_at > ? ORDER BY created_at")
      .bind(u.home_id, new Date().toISOString()).all()).results;
  }
  return json({ members, invitations, me: u.id, max: MAX_HOME });
}
async function createInvite(req, env, u) {
  if (u.role !== "manager") return json({ error: "forbidden" }, 403);
  const b = await readJson(req);
  const email = norm(b && b.email);
  if (!validEmail(email)) return json({ error: "invalid_email" }, 400);
  if (await env.DB.prepare("SELECT id FROM people WHERE email = ?").bind(email).first()) return json({ error: "email_in_use" }, 409);
  const now = new Date().toISOString();
  const m = await env.DB.prepare("SELECT COUNT(*) AS n FROM people WHERE home_id = ?").bind(u.home_id).first();
  const pd = await env.DB.prepare("SELECT COUNT(*) AS n FROM invitations WHERE home_id = ? AND status = 'pending' AND expires_at > ? AND email <> ?").bind(u.home_id, now, email).first();
  if (m.n + pd.n >= MAX_HOME) return json({ error: "home_full" }, 409);
  const raw = b64url(crypto.getRandomValues(new Uint8Array(24)));
  await env.DB.batch([
    env.DB.prepare("UPDATE invitations SET status = 'cancelled' WHERE home_id = ? AND email = ? AND status = 'pending'").bind(u.home_id, email),
    env.DB.prepare("INSERT INTO invitations (id, home_id, email, token_hash, expires_at) VALUES (?, ?, ?, ?, ?)")
      .bind(crypto.randomUUID(), u.home_id, email, await sha256(raw), new Date(Date.now() + 7 * 24 * 3600 * 1000).toISOString()),
  ]);
  return json({ ok: true, token: raw }, 201);
}
async function cancelInvite(env, u, id) {
  if (u.role !== "manager") return json({ error: "forbidden" }, 403);
  await env.DB.prepare("UPDATE invitations SET status = 'cancelled' WHERE id = ? AND home_id = ? AND status = 'pending'").bind(id, u.home_id).run();
  return json({ ok: true });
}
async function setManager(req, env, u) {
  if (u.role !== "manager") return json({ error: "forbidden" }, 403);
  const b = await readJson(req);
  const target = b && typeof b.person_id === "string"
    ? await env.DB.prepare("SELECT id FROM people WHERE id = ? AND home_id = ?").bind(b.person_id, u.home_id).first() : null;
  if (!target || target.id === u.id) return json({ error: "invalid_person" }, 400);
  await env.DB.batch([
    env.DB.prepare("UPDATE people SET role = 'member' WHERE id = ?").bind(u.id),
    env.DB.prepare("UPDATE people SET role = 'manager' WHERE id = ?").bind(target.id),
    env.DB.prepare("UPDATE homes SET manager_id = ? WHERE id = ?").bind(target.id, u.home_id),
  ]);
  return json({ ok: true });
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
        return json({ ok: true, tables: r.n });
      }
      if (request.method === "GET" && p === "/api/me") {
        const u = await currentUser(request, env);
        if (!u) return json({ error: "unauthorized" }, 401);
        const c = await env.DB.prepare("SELECT COUNT(*) AS n FROM people WHERE home_id = ?").bind(u.home_id).first();
        return json({ email: u.email, role: u.role, home: { name: u.home_name, members: c.n, max: MAX_HOME } });
      }
      if (["/api/locations", "/api/products", "/api/inventory", "/api/home", "/api/lookup", "/api/invitations", "/api/home/manager"].includes(p) || /^\/api\/(batches|batches\/[0-9a-f-]{36}\/(discard|delete|edit)|products\/[0-9a-f-]{36}\/(use|photo)|invitations\/[0-9a-f-]{36}\/cancel|locations\/[0-9a-f-]{36}\/(rename|delete))$/.test(p)) {
        const u = await currentUser(request, env);
        if (!u) return json({ error: "unauthorized" }, 401);
        if (request.method === "GET") {
          if (p === "/api/locations") return await listLocations(env, u);
          if (p === "/api/products") return await listProducts(env, u);
          if (p === "/api/inventory") return await listInventory(env, u);
          const mp = p.match(/^\/api\/products\/([0-9a-f-]{36})\/photo$/);
          if (mp) return await getPhoto(env, u, mp[1]);
          if (p === "/api/home") return await homeInfo(env, u);
          if (p === "/api/lookup") return await lookup(env, u, url.searchParams.get("code") || "");
        } else if (request.method === "POST") {
          const origin = request.headers.get("origin");
          if (origin && new URL(origin).host !== url.host) return json({ error: "forbidden" }, 403);
          if (p === "/api/batches") return await addBatch(request, env, u);
          if (p === "/api/invitations") return await createInvite(request, env, u);
          if (p === "/api/locations") return await createLocation(request, env, u);
          if (p === "/api/home/manager") return await setManager(request, env, u);
          let m = p.match(/^\/api\/batches\/([0-9a-f-]{36})\/edit$/);
          if (m) return await editBatch(request, env, u, m[1]);
          m = p.match(/^\/api\/locations\/([0-9a-f-]{36})\/rename$/);
          if (m) return await renameLocation(request, env, u, m[1]);
          m = p.match(/^\/api\/locations\/([0-9a-f-]{36})\/delete$/);
          if (m) return await deleteLocation(env, u, m[1]);
          m = p.match(/^\/api\/products\/([0-9a-f-]{36})\/photo$/);
          if (m) return await setPhoto(request, env, u, m[1]);
          m = p.match(/^\/api\/products\/([0-9a-f-]{36})\/use$/);
          if (m) return await useProduct(request, env, u, m[1]);
          m = p.match(/^\/api\/invitations\/([0-9a-f-]{36})\/cancel$/);
          if (m) return await cancelInvite(env, u, m[1]);
          m = p.match(/^\/api\/batches\/([0-9a-f-]{36})\/delete$/);
          if (m) return await deleteBatch(env, u, m[1]);
          m = p.match(/^\/api\/batches\/([0-9a-f-]{36})\/discard$/);
          if (m) return await discardBatch(env, u, m[1]);
        }
        return json({ error: "not_found" }, 404);
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
