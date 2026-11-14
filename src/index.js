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
  let sent = true;
  try { await sendToken(env, new URL(req.url).origin, { id: pid, email }, "verify"); } catch (e) { sent = false; }
  return json({ ok: true, verify: true, mail_sent: sent }, 201);
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
  const p = await env.DB.prepare("SELECT id, password_hash, email_verified FROM people WHERE email = ?").bind(email).first();
  const ok = await verifyPassword(pw, p ? p.password_hash : DUMMY);
  if (!p || !ok) {
    const e = await addFail(env, ek, MAX_FAILS);
    await addFail(env, ik, IP_MAX);
    if (e.locked) return json({ error: "locked", retry_after: LOCK_MS / 1000 }, 423);
    return json({ error: "invalid_credentials", attempts_left: MAX_FAILS - e.failed }, 401);
  }
  await env.DB.prepare("DELETE FROM login_attempts WHERE key = ?").bind(ek).run();
  if (!p.email_verified) return json({ error: "email_not_verified" }, 403);
  return newSession(env, p.id);
}

const CATS = ["food", "cleaning", "supplies", "medicine"];
const UNITS = ["unit", "kg", "g", "l", "ml", "dose", "sachet", "tablet", "portion"];
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
const PACKS = ["box", "jar", "bottle", "pack", "can", "tube", "bag", "wrap"];
const ITEM_UNITS = ["g", "kg", "ml", "l", "unit"];
const pad14 = (c) => String(c).padStart(14, "0");
const DEFAULT_LOCS = ["kitchen", "pantry", "fridge", "bathroom", "medicine", "storage"];
const isDate = (s) => typeof s === "string" && /^\d{4}-\d{2}-\d{2}$/.test(s) && !isNaN(Date.parse(s));
const FIFO = "ORDER BY (b.expiry_date IS NULL), b.expiry_date, b.purchase_date, b.created_at";

async function listLocations(env, u) {
  const r = await env.DB.prepare("SELECT id, name FROM locations WHERE home_id = ? ORDER BY name").bind(u.home_id).all();
  return json({ locations: r.results });
}
async function listProducts(env, u) {
  const r = await env.DB.prepare("SELECT id, name, category, unit, barcode, min_stock, pack_size, pack_label, item_amount, item_unit, (photo IS NOT NULL) AS has_photo FROM products WHERE home_id = ? ORDER BY name").bind(u.home_id).all();
  return json({ products: r.results });
}
async function listInventory(env, u) {
  const r = await env.DB.prepare(
    "SELECT b.id AS batch_id, b.product_id, p.name, p.category, p.unit, p.min_stock, p.barcode, b.location_id, b.owner_id, b.notes, p.item_amount, p.item_unit, p.pack_size, p.pack_label, (p.photo IS NOT NULL) AS has_photo, b.initial_quantity, b.quantity, b.purchase_date, b.expiry_date, l.name AS location, o.email AS owner, " +
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
  const itemAmount = b.item_amount ? Number(b.item_amount) : null;
  const itemUnit = itemAmount ? String(b.item_unit || "") : null;
  if (itemAmount !== null && itemAmount > 0 && !ITEM_UNITS.includes(itemUnit)) return json({ error: "item_unit_required" }, 400);
  if (itemAmount !== null && !(itemAmount > 0 && itemAmount <= 100000 && ITEM_UNITS.includes(itemUnit))) return json({ error: "invalid_pack" }, 400);
  const notes = typeof b.notes === "string" && b.notes.trim() ? b.notes.trim().slice(0, 120) : null;
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
  let ownerId = u.id;
  if (b.owner_id && b.owner_id !== u.id) { const o = await homePerson(env, u, b.owner_id); if (!o) return json({ error: "invalid_person" }, 400); ownerId = o.id; }
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
    if (packSize || packLabel || itemAmount) stmts.push(env.DB.prepare("UPDATE products SET pack_size = ?, pack_label = ?, item_amount = ?, item_unit = ? WHERE id = ?").bind(packSize, packLabel, itemAmount, itemUnit, pid));
  } else {
    pid = crypto.randomUUID();
    stmts.push(env.DB.prepare("INSERT INTO products (id, home_id, name, category, barcode, unit, min_stock, pack_size, pack_label, item_amount, item_unit, photo) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(pid, u.home_id, name, b.category, barcode, b.unit, min, packSize, packLabel, itemAmount, itemUnit, photo));
  }
  const bid = crypto.randomUUID();
  stmts.push(env.DB.prepare("INSERT INTO batches (id, product_id, location_id, owner_id, quantity, initial_quantity, purchase_date, expiry_date, notes) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)").bind(bid, pid, loc.id, ownerId, qty, qty, b.purchase_date, exp, notes));
  stmts.push(env.DB.prepare("INSERT INTO movements (id, batch_id, type, quantity, person_id) VALUES (?, ?, 'in', ?, ?)").bind(crypto.randomUUID(), bid, qty, u.id));
  await env.DB.batch(stmts);
  return json({ ok: true, id: bid, photo_failed: !!(b.photo_url && !b.photo && !photo) }, 201);
}
// Regalo de un lote a otro integrante del hogar, con historial (D-013, D-032).
async function giftBatch(req, env, u, bid) {
  const r = await env.DB.prepare("SELECT b.id, b.owner_id, b.quantity FROM batches b JOIN products p ON p.id = b.product_id WHERE b.id = ? AND p.home_id = ? AND b.status = 'active'").bind(bid, u.home_id).first();
  if (!r) return json({ error: "not_found" }, 404);
  if (u.role !== "manager" && r.owner_id !== u.id) return json({ error: "forbidden" }, 403);
  const b = await readJson(req);
  const to = b && typeof b.to_person_id === "string" ? await env.DB.prepare("SELECT id FROM people WHERE id = ? AND home_id = ?").bind(b.to_person_id, u.home_id).first() : null;
  if (!to || to.id === r.owner_id) return json({ error: "invalid_person" }, 400);
  await env.DB.batch([
    env.DB.prepare("UPDATE batches SET owner_id = ? WHERE id = ?").bind(to.id, bid),
    env.DB.prepare("INSERT INTO movements (id, batch_id, type, quantity, person_id, to_person_id) VALUES (?, ?, 'gift', ?, ?, ?)").bind(crypto.randomUUID(), bid, r.quantity, r.owner_id || u.id, to.id),
  ]);
  return json({ ok: true });
}
const homePerson = (env, u, id) => env.DB.prepare("SELECT id FROM people WHERE id = ? AND home_id = ?").bind(String(id), u.home_id).first();
// Modo cocina: descuenta ingredientes con FIFO y guarda la comida en el refrigerador (D-014, D-035).
async function createMeal(req, env, u) {
  const b = await readJson(req, 20000);
  if (!b) return json({ error: "bad_request" }, 400);
  const name = typeof b.name === "string" ? b.name.trim() : "";
  if (name.length < 1 || name.length > 80) return json({ error: "invalid_name" }, 400);
  const portions = Number(b.portions);
  if (!(portions > 0 && portions <= 1000)) return json({ error: "invalid_quantity" }, 400);
  if (!isDate(b.expiry_date)) return json({ error: b.expiry_date ? "invalid_date" : "expiry_required" }, 400);
  const buy = isDate(b.purchase_date) ? b.purchase_date : new Date().toISOString().slice(0, 10);
  if (!Array.isArray(b.items) || !b.items.length || b.items.length > 15) return json({ error: "invalid_items" }, 400);
  let ownerId = u.id;
  if (b.owner_id && b.owner_id !== u.id) { const o = await homePerson(env, u, b.owner_id); if (!o) return json({ error: "invalid_person" }, 400); ownerId = o.id; }
  const want = new Map();
  for (const it of b.items) {
    const q = Number(it && it.quantity);
    if (!it || typeof it.product_id !== "string" || !(q > 0 && q <= 100000)) return json({ error: "invalid_quantity" }, 400);
    const w = want.get(it.product_id) || { q: 0, move: false };
    w.q = Math.round((w.q + q) * 1e6) / 1e6; w.move = w.move || it.move === true;
    want.set(it.product_id, w);
  }
  const fr = await env.DB.prepare("SELECT id FROM locations WHERE home_id = ? AND lower(name) = 'fridge'").bind(u.home_id).first();
  const fridge = fr ? fr.id : crypto.randomUUID();
  const prod = await env.DB.prepare("SELECT id FROM products WHERE home_id = ? AND barcode IS NULL AND lower(name) = lower(?) AND unit = 'portion'").bind(u.home_id, name).first();
  const pid = prod ? prod.id : crypto.randomUUID(), bid = crypto.randomUUID(), mealId = crypto.randomUUID();
  const stmts = [];
  if (!fr) stmts.push(env.DB.prepare("INSERT INTO locations (id, home_id, name) VALUES (?, ?, 'fridge')").bind(fridge, u.home_id));
  if (!prod) stmts.push(env.DB.prepare("INSERT INTO products (id, home_id, name, category, unit, min_stock) VALUES (?, ?, ?, 'food', 'portion', 0)").bind(pid, u.home_id, name));
  stmts.push(env.DB.prepare("INSERT INTO batches (id, product_id, location_id, owner_id, quantity, initial_quantity, purchase_date, expiry_date) VALUES (?, ?, ?, ?, ?, ?, ?, ?)").bind(bid, pid, fridge, ownerId, portions, portions, buy, b.expiry_date));
  stmts.push(env.DB.prepare("INSERT INTO movements (id, batch_id, type, quantity, person_id, note) VALUES (?, ?, 'in', ?, ?, 'cook')").bind(crypto.randomUUID(), bid, portions, u.id));
  stmts.push(env.DB.prepare("INSERT INTO meals (id, home_id, name, batch_id, cooked_by) VALUES (?, ?, ?, ?, ?)").bind(mealId, u.home_id, name, bid, u.id));
  for (const [ppid, w] of want) {
    const rows = (await env.DB.prepare("SELECT b.id, b.quantity, b.location_id, p.name FROM batches b JOIN products p ON p.id = b.product_id WHERE p.id = ? AND p.home_id = ? AND b.status = 'active' " + FIFO).bind(ppid, u.home_id).all()).results;
    const total = rows.reduce((a, r) => a + r.quantity, 0);
    if (w.q > total + 1e-9) return json({ error: "insufficient", available: total, product: rows.length ? rows[0].name : "" }, 409);
    let left = w.q;
    for (const r of rows) {
      if (left <= 1e-9) break;
      const take = Math.min(r.quantity, left);
      const rem = Math.round((r.quantity - take) * 1e6) / 1e6;
      stmts.push(env.DB.prepare("UPDATE batches SET quantity = ?, status = ?, location_id = ? WHERE id = ?").bind(rem, rem <= 0 ? "empty" : "active", w.move && rem > 0 ? fridge : r.location_id, r.id));
      stmts.push(env.DB.prepare("INSERT INTO movements (id, batch_id, type, quantity, person_id, note) VALUES (?, ?, 'cook', ?, ?, ?)").bind(crypto.randomUUID(), r.id, take, u.id, name.slice(0, 60)));
      stmts.push(env.DB.prepare("INSERT INTO meal_items (meal_id, batch_id, quantity) VALUES (?, ?, ?)").bind(mealId, r.id, take));
      left = Math.round((left - take) * 1e6) / 1e6;
    }
  }
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
  const packLabel = b.pack_label ? String(b.pack_label) : null;
  if (packLabel && !PACKS.includes(packLabel)) return json({ error: "invalid_pack" }, 400);
  const packSize = b.pack_size ? Number(b.pack_size) : null;
  if (packSize !== null && !(packSize > 0 && packSize <= 100000)) return json({ error: "invalid_pack" }, 400);
  const itemAmount = b.item_amount ? Number(b.item_amount) : null;
  const itemUnit = itemAmount ? String(b.item_unit || "") : null;
  if (itemAmount !== null && itemAmount > 0 && !ITEM_UNITS.includes(itemUnit)) return json({ error: "item_unit_required" }, 400);
  if (itemAmount !== null && !(itemAmount > 0 && itemAmount <= 100000 && ITEM_UNITS.includes(itemUnit))) return json({ error: "invalid_pack" }, 400);
  const notes = typeof b.notes === "string" && b.notes.trim() ? b.notes.trim().slice(0, 120) : null;
  const n = Number(b.quantity);
  if (!(n > 0 && n <= 100000)) return json({ error: "invalid_quantity" }, 400);
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
  if (barcode && (await env.DB.prepare("SELECT id FROM products WHERE home_id = ? AND id <> ? AND substr('00000000000000' || barcode, -14) = ?").bind(u.home_id, r.product_id, pad14(barcode)).first())) return json({ error: "barcode_in_use" }, 409);
  const loc = await env.DB.prepare("SELECT id FROM locations WHERE id = ? AND home_id = ?").bind(String(b.location_id || ""), u.home_id).first();
  if (!loc) return json({ error: "invalid_location" }, 400);
  if (b.photo && !validPhoto(b.photo)) return json({ error: "invalid_photo" }, 400);
  let newOwner = r.owner_id;
  if (b.owner_id && b.owner_id !== r.owner_id) { const o = await homePerson(env, u, b.owner_id); if (!o) return json({ error: "invalid_person" }, 400); newOwner = o.id; }
  const initial = Math.max(r.initial_quantity || r.quantity, qty);
  const stmts = [
    env.DB.prepare("UPDATE products SET name = ?, category = ?, unit = ?, barcode = ?, min_stock = ?, pack_size = ?, pack_label = ?, item_amount = ?, item_unit = ? WHERE id = ?").bind(name, b.category, b.unit, barcode, min, packSize, packLabel, itemAmount, itemUnit, r.product_id),
    env.DB.prepare("UPDATE batches SET location_id = ?, quantity = ?, initial_quantity = ?, purchase_date = ?, expiry_date = ?, notes = ?, owner_id = ? WHERE id = ?").bind(loc.id, qty, initial, b.purchase_date, exp, notes, newOwner, bid),
  ];
  if (b.photo) stmts.push(env.DB.prepare("UPDATE products SET photo = ? WHERE id = ?").bind(b.photo, r.product_id));
  if (newOwner !== r.owner_id) stmts.push(env.DB.prepare("INSERT INTO movements (id, batch_id, type, quantity, person_id, to_person_id, note) VALUES (?, ?, 'gift', ?, ?, ?, 'edit')").bind(crypto.randomUUID(), bid, qty, r.owner_id || u.id, newOwner));
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

function parseQty(q) {
  if (typeof q !== "string") return null;
  const s = q.trim().toLowerCase().replace(",", ".");
  const conv = (a, u) => (u === "cl" ? [a * 10, "ml"] : [a, u]);
  let m = s.match(/^(\d+)\s*[x\u00d7]\s*(\d+(?:\.\d+)?)\s*(g|kg|ml|cl|l)$/);
  if (m) { const [a, u] = conv(Number(m[2]), m[3]); return { pack_size: Number(m[1]), unit: "unit", item_amount: a, item_unit: u }; }
  m = s.match(/^(\d+(?:\.\d+)?)\s*(g|kg|ml|cl|l)$/);
  if (m) { const [a, u] = conv(Number(m[1]), m[2]); return { pack_size: a, unit: u }; }
  return null;
}
async function lookup(env, u, code, homeOnly) {
  if (!/^\d{6,14}$/.test(code)) return json({ error: "invalid_barcode" }, 400);
  const own = await env.DB.prepare(
    "SELECT p.id, (p.photo IS NOT NULL) AS has_photo, p.name, p.category, p.unit, p.min_stock, p.pack_size, p.pack_label, p.item_amount, p.item_unit, (SELECT b.location_id FROM batches b WHERE b.product_id = p.id ORDER BY b.created_at DESC LIMIT 1) AS location_id " +
    "FROM products p WHERE p.home_id = ? AND substr('00000000000000' || p.barcode, -14) = ?"
  ).bind(u.home_id, pad14(code)).first();
  if (own) return json({ found: "home", product: own });
  if (homeOnly) return json({ found: null });
  try {
    const r = await fetch("https://world.openfoodfacts.org/api/v2/product/" + code + ".json?fields=product_name,brands,image_front_small_url,quantity", {
      headers: { "user-agent": "InventarioHogar/0.1" },
      signal: AbortSignal.timeout(4000),
    });
    if (r.ok) {
      const j = await r.json();
      if (j.status === 1 && j.product && j.product.product_name) {
        const brand = j.product.brands ? String(j.product.brands).split(",")[0].trim().slice(0, 40) : "";
        const img = typeof j.product.image_front_small_url === "string" && j.product.image_front_small_url.startsWith("https://images.openfoodfacts.org/") ? j.product.image_front_small_url : "";
        return json({ found: "off", product: { name: String(j.product.product_name).slice(0, 80), brand, image_url: img, ...(parseQty(j.product.quantity) || {}) } });
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

const dl = (body, type, name) => new Response(body, { headers: { "content-type": type, "content-disposition": 'attachment; filename="' + name + '"', "cache-control": "no-store" } });
const stamp = () => new Date().toISOString().slice(0, 10);
// Respaldo completo del hogar en JSON, solo gestor, sin contrasenas ni tokens (D-031).
async function backup(env, u) {
  if (u.role !== "manager") return json({ error: "forbidden" }, 403);
  const h = u.home_id, q = (sql) => env.DB.prepare(sql).bind(h).all();
  const [home, people, invs, locs, prods, bats, movs] = await Promise.all([
    env.DB.prepare("SELECT id, name FROM homes WHERE id = ?").bind(h).first(),
    q("SELECT id, email, role FROM people WHERE home_id = ? ORDER BY email"),
    q("SELECT id, email, status, expires_at, created_at FROM invitations WHERE home_id = ? ORDER BY created_at"),
    q("SELECT id, name FROM locations WHERE home_id = ? ORDER BY name"),
    q("SELECT * FROM products WHERE home_id = ? ORDER BY name"),
    q("SELECT b.* FROM batches b JOIN products p ON p.id = b.product_id WHERE p.home_id = ? ORDER BY b.created_at"),
    q("SELECT m.* FROM movements m JOIN batches b ON b.id = m.batch_id JOIN products p ON p.id = b.product_id WHERE p.home_id = ?"),
  ]);
  const out = { app: "iHogar", version: 1, exported_at: new Date().toISOString(), home, people: people.results, invitations: invs.results, locations: locs.results, products: prods.results, batches: bats.results, movements: movs.results };
  return dl(JSON.stringify(out), "application/json", "ihogar-respaldo-" + stamp() + ".json");
}
const csvCell = (v) => {
  if (v === null || v === undefined) return "";
  let s = String(v);
  if (/^[=+\-@\t\r]/.test(s) && isNaN(Number(s))) s = "'" + s; // evita formulas en planillas
  return /[",\n\r]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
};
// Inventario activo en CSV, cualquier integrante (D-031).
async function exportCsv(env, u) {
  const r = await env.DB.prepare(
    "SELECT p.name, p.category, p.barcode, b.quantity, p.unit, p.pack_size, p.pack_label, p.item_amount, p.item_unit, l.name AS location, b.purchase_date, b.expiry_date, b.notes, o.email AS owner, p.min_stock " +
    "FROM batches b JOIN products p ON p.id = b.product_id LEFT JOIN locations l ON l.id = b.location_id LEFT JOIN people o ON o.id = b.owner_id " +
    "WHERE p.home_id = ? AND b.status = 'active' " + FIFO
  ).bind(u.home_id).all();
  const cols = ["name", "category", "barcode", "quantity", "unit", "pack_size", "pack_label", "item_amount", "item_unit", "location", "purchase_date", "expiry_date", "notes", "owner", "min_stock"];
  const lines = [cols.join(",")].concat(r.results.map((x) => cols.map((c) => csvCell(x[c])).join(",")));
  return dl("\ufeff" + lines.join("\r\n") + "\r\n", "text/csv; charset=utf-8", "ihogar-inventario-" + stamp() + ".csv");
}

async function sendMail(env, to, subject, html) {
  if (!env.BREVO_API_KEY || !env.MAIL_FROM) throw new Error("mail_config");
  const r = await fetch("https://api.brevo.com/v3/smtp/email", {
    method: "POST",
    headers: { "api-key": env.BREVO_API_KEY, "content-type": "application/json", accept: "application/json" },
    body: JSON.stringify({ sender: { name: env.MAIL_NAME || "Inventario Hogar", email: env.MAIL_FROM }, to: [{ email: to }], subject, htmlContent: html }),
    signal: AbortSignal.timeout(8000),
  });
  if (!r.ok) throw new Error("mail_" + r.status);
}
function mailBody(link, kind) {
  const T = kind === "verify"
    ? { es: ["Confirma tu correo para activar tu cuenta de Inventario Hogar.", "Confirmar correo", "El enlace vence en 24 horas. Si no creaste esta cuenta, ignora este mensaje."],
        en: ["Confirm your email to activate your Inventario Hogar account.", "Confirm email", "The link expires in 24 hours. If you did not create this account, ignore this message."] }
    : { es: ["Recibimos una solicitud para restablecer tu contrase\u00f1a.", "Crear nueva contrase\u00f1a", "El enlace vence en 1 hora. Si no lo pediste, ignora este mensaje."],
        en: ["We received a request to reset your password.", "Create new password", "The link expires in 1 hour. If you did not request it, ignore this message."] };
  const btn = (txt) => '<p><a href="' + link + '" style="display:inline-block;background:#1F4E9C;color:#ffffff;padding:12px 22px;border-radius:10px;text-decoration:none;font-weight:bold">' + txt + "</a></p>";
  const part = (x) => "<p>" + x[0] + "</p>" + btn(x[1]) + '<p style="color:#4A4F5A;font-size:13px">' + x[2] + "</p>";
  return '<div style="font-family:Arial,sans-serif;max-width:480px;margin:auto;color:#16181D"><h2 style="color:#1F4E9C">Inventario Hogar</h2>' + part(T.es) + '<hr style="border:0;border-top:1px solid #D9DCE3;margin:24px 0">' + part(T.en) + "</div>";
}
async function sendToken(env, origin, person, kind) {
  const raw = b64url(crypto.getRandomValues(new Uint8Array(24)));
  const hours = kind === "verify" ? 24 : 1;
  await env.DB.batch([
    env.DB.prepare("DELETE FROM email_tokens WHERE person_id = ? AND type = ?").bind(person.id, kind),
    env.DB.prepare("INSERT INTO email_tokens (id, person_id, type, token_hash, expires_at) VALUES (?, ?, ?, ?, ?)")
      .bind(crypto.randomUUID(), person.id, kind, await sha256(raw), new Date(Date.now() + hours * 3600 * 1000).toISOString()),
  ]);
  await sendMail(env, person.email, kind === "verify" ? "Confirma tu correo / Confirm your email" : "Restablece tu contrase\u00f1a / Reset your password", mailBody(origin + "/#" + kind + "=" + raw, kind));
}
async function recentToken(env, personId, type) {
  const r = await env.DB.prepare("SELECT created_at FROM email_tokens WHERE person_id = ? AND type = ? ORDER BY created_at DESC LIMIT 1").bind(personId, type).first();
  return !!r && Date.now() - Date.parse(String(r.created_at).replace(" ", "T") + "Z") < 60000;
}
async function verifyEmail(req, env) {
  const b = await readJson(req);
  const tok = b && typeof b.token === "string" ? b.token : "";
  const r = tok ? await env.DB.prepare("SELECT person_id FROM email_tokens WHERE token_hash = ? AND type = 'verify' AND expires_at > ?").bind(await sha256(tok), new Date().toISOString()).first() : null;
  if (!r) return json({ error: "invalid_token" }, 400);
  await env.DB.batch([
    env.DB.prepare("UPDATE people SET email_verified = 1 WHERE id = ?").bind(r.person_id),
    env.DB.prepare("DELETE FROM email_tokens WHERE person_id = ? AND type = 'verify'").bind(r.person_id),
  ]);
  return json({ ok: true });
}
async function mailRequest(req, env, ip, kind) {
  const b = await readJson(req);
  const email = norm(b && b.email);
  if (!validEmail(email)) return json({ error: "invalid_email" }, 400);
  if (!(await captchaOk(env, b.token, ip))) return json({ error: "captcha" }, 400);
  const p = await env.DB.prepare(kind === "verify" ? "SELECT id, email FROM people WHERE email = ? AND email_verified = 0" : "SELECT id, email FROM people WHERE email = ?").bind(email).first();
  if (p && !(await recentToken(env, p.id, kind))) { try { await sendToken(env, new URL(req.url).origin, p, kind); } catch (e) {} }
  return json({ ok: true });
}
async function resetPassword(req, env) {
  const b = await readJson(req);
  const tok = b && typeof b.token === "string" ? b.token : "";
  const pw = b && typeof b.password === "string" ? b.password : "";
  if (pw.length < 10 || pw.length > 200) return json({ error: "weak_password" }, 400);
  const r = tok ? await env.DB.prepare("SELECT t.person_id, p.email FROM email_tokens t JOIN people p ON p.id = t.person_id WHERE t.token_hash = ? AND t.type = 'reset' AND t.expires_at > ?").bind(await sha256(tok), new Date().toISOString()).first() : null;
  if (!r) return json({ error: "invalid_token" }, 400);
  const hash = await hashPassword(pw);
  await env.DB.batch([
    env.DB.prepare("UPDATE people SET password_hash = ?, email_verified = 1 WHERE id = ?").bind(hash, r.person_id),
    env.DB.prepare("DELETE FROM sessions WHERE person_id = ?").bind(r.person_id),
    env.DB.prepare("DELETE FROM email_tokens WHERE person_id = ? AND type = 'reset'").bind(r.person_id),
    env.DB.prepare("DELETE FROM login_attempts WHERE key = ?").bind("email:" + r.email),
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
      if (["/api/locations", "/api/products", "/api/inventory", "/api/home", "/api/lookup", "/api/invitations", "/api/home/manager", "/api/backup", "/api/export", "/api/meals"].includes(p) || /^\/api\/(batches|batches\/[0-9a-f-]{36}\/(discard|delete|edit|gift)|products\/[0-9a-f-]{36}\/(use|photo)|invitations\/[0-9a-f-]{36}\/cancel|locations\/[0-9a-f-]{36}\/(rename|delete))$/.test(p)) {
        const u = await currentUser(request, env);
        if (!u) return json({ error: "unauthorized" }, 401);
        if (request.method === "GET") {
          if (p === "/api/locations") return await listLocations(env, u);
          if (p === "/api/products") return await listProducts(env, u);
          if (p === "/api/inventory") return await listInventory(env, u);
          const mp = p.match(/^\/api\/products\/([0-9a-f-]{36})\/photo$/);
          if (mp) return await getPhoto(env, u, mp[1]);
          if (p === "/api/home") return await homeInfo(env, u);
          if (p === "/api/lookup") return await lookup(env, u, url.searchParams.get("code") || "", url.searchParams.get("own") === "1");
          if (p === "/api/backup") return await backup(env, u);
          if (p === "/api/export") return await exportCsv(env, u);
        } else if (request.method === "POST") {
          const origin = request.headers.get("origin");
          if (origin && new URL(origin).host !== url.host) return json({ error: "forbidden" }, 403);
          if (p === "/api/batches") return await addBatch(request, env, u);
          if (p === "/api/meals") return await createMeal(request, env, u);
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
          m = p.match(/^\/api\/batches\/([0-9a-f-]{36})\/gift$/);
          if (m) return await giftBatch(request, env, u, m[1]);
        }
        return json({ error: "not_found" }, 404);
      }
      if (request.method === "POST") {
        const origin = request.headers.get("origin");
        if (origin && new URL(origin).host !== url.host) return json({ error: "forbidden" }, 403);
        if (!env.TURNSTILE_SECRET) return json({ error: "server_config" }, 500);
        if (p === "/api/register") return await register(request, env, ip);
        if (p === "/api/login") return await login(request, env, ip);
        if (p === "/api/verify") return await verifyEmail(request, env);
        if (p === "/api/resend") return await mailRequest(request, env, ip, "verify");
        if (p === "/api/forgot") return await mailRequest(request, env, ip, "reset");
        if (p === "/api/reset") return await resetPassword(request, env);
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
