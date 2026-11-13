'use strict';
const path = require('path');
const express = require('express');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const cookieParser = require('cookie-parser');
const { pool, init } = require('./db');

const { JWT_SECRET, PORT = 3000, NODE_ENV } = process.env;
if (!JWT_SECRET || JWT_SECRET.length < 24) {
  console.error('ต้องตั้งค่า JWT_SECRET ยาวอย่างน้อย 24 ตัวอักษร');
  process.exit(1);
}
const prod = NODE_ENV === 'production';

const app = express();
app.set('trust proxy', 1);
app.disable('x-powered-by');
app.use((req, res, next) => {
  res.set({
    'X-Content-Type-Options': 'nosniff',
    'X-Frame-Options': 'DENY',
    'Referrer-Policy': 'same-origin',
    'Content-Security-Policy':
      "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; " +
      "font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'",
  });
  next();
});
app.use(express.json({ limit: '2mb' }));
app.use(cookieParser());

/* ---------- ตัวช่วย ---------- */
const h = fn => (req, res, next) => fn(req, res).catch(next);
const str = (v, n) => String(v ?? '').slice(0, n);
const int = v => Math.max(0, Math.min(1e9, parseInt(v, 10) || 0));
const ID_RE = /^[\w-]{1,64}$/;
const USER_ROLES = new Set(['user', 'super_admin']);
const fail = (status, error) => Object.assign(new Error(error), { status });

const auth = (req, res, next) => {
  let claims;
  try { claims = jwt.verify(req.cookies.tk || '', JWT_SECRET); }
  catch (e) { return res.status(401).json({ error: 'auth' }); }
  pool.query('SELECT id,username,name,role,active,token_version FROM users WHERE id=$1 AND active=true', [claims.id])
    .then(({ rows }) => {
      const user = rows[0];
      if (!user || Number(claims.tv || 0) !== user.token_version) return res.status(401).json({ error: 'auth' });
      req.user = user;
      next();
    }).catch(next);
};
const superAdmin = (req, res, next) => req.user.role === 'super_admin'
  ? next() : res.status(403).json({ error: 'ต้องใช้บัญชี super admin' });

// จำกัดการเดารหัสผ่าน: 8 ครั้ง/5 นาที/IP
const tries = new Map();
const limited = ip => {
  const now = Date.now(), r = tries.get(ip);
  if (!r || now - r.t > 300000) { tries.set(ip, { n: 1, t: now }); return false; }
  return ++r.n > 8;
};
setInterval(() => { const now = Date.now(); tries.forEach((v, k) => now - v.t > 300000 && tries.delete(k)); }, 600000).unref();

/* ---------- เข้าสู่ระบบ ---------- */
app.post('/api/login', h(async (req, res) => {
  if (limited(req.ip)) throw fail(429, 'ลองผิดหลายครั้งเกินไป กรุณารอ 5 นาที');
  const { rows } = await pool.query(
    'SELECT id,username,name,pass_hash,role,active,token_version FROM users WHERE lower(username)=lower($1)',
    [str(req.body.username, 80)]);
  const u = rows[0];
  // เทียบ hash เสมอ แม้ไม่พบผู้ใช้ เพื่อไม่ให้เดาชื่อผู้ใช้จากเวลาตอบกลับได้
  const ok = await bcrypt.compare(str(req.body.password, 200), u ? u.pass_hash : '$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidinva');
  if (!u || !ok || !u.active) throw fail(401, 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');
  tries.delete(req.ip);
  const token = jwt.sign({ id: u.id, tv: u.token_version }, JWT_SECRET, { expiresIn: '12h' });
  res.cookie('tk', token, { httpOnly: true, sameSite: 'lax', secure: prod, maxAge: 12 * 3600 * 1000 });
  res.json({ name: u.name, role: u.role });
}));
app.post('/api/logout', (req, res) => { res.clearCookie('tk'); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json({ id: req.user.id, name: req.user.name, role: req.user.role }));
app.get('/healthz', h(async (req, res) => { await pool.query('SELECT 1'); res.send('ok'); }));

/* ---------- จัดการบัญชีผู้ใช้ ---------- */
function userId(value) {
  const id = Number(value);
  if (!/^\d+$/.test(String(value)) || !Number.isSafeInteger(id) || id < 1) {
    throw fail(400, 'รหัสผู้ใช้ไม่ถูกต้อง');
  }
  return id;
}
function userPassword(value) {
  if (typeof value !== 'string') throw fail(400, 'รหัสผ่านไม่ถูกต้อง');
  const password = value;
  if (password.length < 12 || Buffer.byteLength(password, 'utf8') > 72) {
    throw fail(400, 'รหัสผ่านต้องมีอย่างน้อย 12 ตัวอักษร และไม่เกิน 72 ไบต์');
  }
  return password;
}
async function writeUserAudit(client, actor, target, action, details) {
  await client.query(
    `INSERT INTO user_audit (actor_id,actor_name,target_id,target_username,action,details)
     VALUES ($1,$2,$3,$4,$5,$6::jsonb)`,
    [actor.id, actor.name, target.id, target.username, action, JSON.stringify(details || {})]);
}
app.get('/api/users', auth, superAdmin, h(async (req, res) => {
  const [users, audit] = await Promise.all([
    pool.query('SELECT id,username,name,role,active,created_at FROM users ORDER BY id'),
    pool.query(`SELECT id,actor_name,target_username,action,details,created_at
                FROM user_audit ORDER BY created_at DESC,id DESC LIMIT 100`),
  ]);
  res.json({ users: users.rows, audit: audit.rows });
}));
app.post('/api/users', auth, superAdmin, h(async (req, res) => {
  const username = str(req.body.username, 80).trim();
  const name = str(req.body.name, 100).trim();
  const password = userPassword(req.body.password);
  const role = req.body.role;
  if (!username || /\s/.test(username) || !name || !USER_ROLES.has(role)) {
    throw fail(400, 'กรุณาตรวจสอบชื่อผู้ใช้ ชื่อที่แสดง และบทบาท');
  }
  const passHash = await bcrypt.hash(password, 12);
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const { rows } = await c.query(
      `INSERT INTO users (username,name,pass_hash,role)
       VALUES ($1,$2,$3,$4) ON CONFLICT (lower(username)) DO NOTHING
       RETURNING id,username,name,role,active,created_at`,
      [username, name, passHash, role]);
    if (!rows.length) throw fail(409, 'ชื่อผู้ใช้นี้มีอยู่แล้ว');
    await writeUserAudit(c, req.user, rows[0], 'created', { role });
    await c.query('COMMIT');
    res.status(201).json(rows[0]);
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; }
  finally { c.release(); }
}));
app.patch('/api/users/:id', auth, superAdmin, h(async (req, res) => {
  const id = userId(req.params.id);
  const name = str(req.body.name, 100).trim();
  const role = req.body.role;
  const active = req.body.active;
  if (!name || !USER_ROLES.has(role) || typeof active !== 'boolean') {
    throw fail(400, 'ข้อมูลบัญชีผู้ใช้ไม่ถูกต้อง');
  }
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    await c.query('LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE');
    const { rows } = await c.query(
      'SELECT id,username,name,role,active,created_at FROM users WHERE id=$1 FOR UPDATE', [id]);
    const target = rows[0];
    if (!target) throw fail(404, 'ไม่พบบัญชีผู้ใช้นี้');
    if (target.id === req.user.id && (role !== target.role || !active)) {
      throw fail(409, 'ใช้บัญชี super admin อื่นเพื่อเปลี่ยนสิทธิ์หรือปิดบัญชีนี้');
    }
    if (target.role === 'super_admin' && target.active && (role !== 'super_admin' || !active)) {
      const count = await c.query(
        "SELECT count(*)::int AS n FROM users WHERE role='super_admin' AND active=true");
      if (count.rows[0].n <= 1) throw fail(409, 'ต้องมี super admin ที่เปิดใช้งานอย่างน้อย 1 บัญชี');
    }
    const updated = await c.query(
      `UPDATE users SET name=$2,role=$3,active=$4,
         token_version=token_version+CASE
           WHEN active IS DISTINCT FROM $4 OR role IS DISTINCT FROM $3 THEN 1 ELSE 0 END
       WHERE id=$1
       RETURNING id,username,name,role,active,created_at`,
      [id, name, role, active]);
    const next = updated.rows[0];
    const details = {};
    if (target.name !== name) details.name = { from: target.name, to: name };
    if (target.role !== role) details.role = { from: target.role, to: role };
    if (target.active !== active) details.active = { from: target.active, to: active };
    if (Object.keys(details).length) await writeUserAudit(c, req.user, next, 'updated', details);
    await c.query('COMMIT');
    res.json(next);
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; }
  finally { c.release(); }
}));
app.post('/api/users/:id/password', auth, superAdmin, h(async (req, res) => {
  const id = userId(req.params.id);
  if (id === req.user.id) throw fail(400, 'ใช้บัญชี super admin อื่นเพื่อรีเซ็ตรหัสผ่านนี้');
  const password = userPassword(req.body.password);
  const passHash = await bcrypt.hash(password, 12);
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const { rows } = await c.query('SELECT id,username FROM users WHERE id=$1 FOR UPDATE', [id]);
    const target = rows[0];
    if (!target) throw fail(404, 'ไม่พบบัญชีผู้ใช้นี้');
    await c.query(
      'UPDATE users SET pass_hash=$2,token_version=token_version+1 WHERE id=$1', [id, passHash]);
    await writeUserAudit(c, req.user, target, 'password_reset', {});
    await c.query('COMMIT');
    res.json({ ok: true });
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; }
  finally { c.release(); }
}));

/* ---------- ข้อมูลทั้งหมด (สินค้า + หมวดหมู่ + ประวัติล่าสุด 1,000 รายการ) ---------- */
app.get('/api/state', auth, h(async (req, res) => {
  const [p, l, c] = await Promise.all([
    pool.query(`SELECT id,sku,name,cat,qty,unit,min,loc,imgs,demo,version AS v,created_at AS created
                FROM products ORDER BY created_at`),
    pool.query(`SELECT * FROM (
                  SELECT t,product_id AS id,sku,name,type,n,qty_after AS "after",note,by_name AS "by"
                  FROM movements ORDER BY t DESC, id DESC LIMIT 1000) x ORDER BY t`),
    pool.query('SELECT name FROM categories ORDER BY lower(name),name'),
  ]);
  res.json({ items: p.rows, log: l.rows, categories: c.rows.map(row => row.name) });
}));

/* ---------- หมวดหมู่สินค้า ---------- */
app.post('/api/categories', auth, h(async (req, res) => {
  const name = str(req.body.name, 80).trim();
  if (!name) throw fail(400, 'กรุณาระบุชื่อหมวดหมู่');
  const { rows } = await pool.query(
    `INSERT INTO categories (name) VALUES ($1)
     ON CONFLICT (lower(name)) DO NOTHING RETURNING name`, [name]);
  if (!rows.length) throw fail(409, 'มีหมวดหมู่นี้อยู่แล้ว');
  res.status(201).json({ name: rows[0].name });
}));
app.delete('/api/categories/:name', auth, h(async (req, res) => {
  const name = str(req.params.name, 80).trim();
  if (!name) throw fail(400, 'ชื่อหมวดหมู่ไม่ถูกต้อง');
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    const category = await c.query(
      'SELECT name FROM categories WHERE lower(name)=lower($1) FOR UPDATE', [name]);
    if (!category.rowCount) throw fail(404, 'ไม่พบหมวดหมู่นี้');
    const canonicalName = category.rows[0].name;
    await c.query('LOCK TABLE products IN SHARE MODE');
    const usage = await c.query(
      'SELECT count(*)::int AS count FROM products WHERE lower(btrim(cat))=lower($1)', [canonicalName]);
    if (usage.rows[0].count) throw fail(409, `ลบไม่ได้ มีสินค้าใช้หมวดหมู่นี้ ${usage.rows[0].count} รายการ`);
    await c.query('DELETE FROM categories WHERE name=$1', [canonicalName]);
    await c.query('COMMIT');
    res.json({ ok: true, name: canonicalName });
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; }
  finally { c.release(); }
}));

/* ---------- บันทึกการเปลี่ยนแปลงสินค้า (ธุรกรรมเดียว + กันแก้ทับด้วยเลขเวอร์ชัน) ---------- */
function cleanProduct(p) {
  if (!p || !ID_RE.test(String(p.id)) || !str(p.sku, 80).trim() || !str(p.name, 200).trim()) throw fail(400, 'ข้อมูลสินค้าไม่ถูกต้อง');
  const created = new Date(p.created);
  return {
    id: String(p.id), sku: str(p.sku, 80).trim(), name: str(p.name, 200).trim(), cat: str(p.cat, 80).trim(),
    qty: int(p.qty), unit: str(p.unit, 30) || 'ชิ้น', min: int(p.min), loc: str(p.loc, 80),
    imgs: (Array.isArray(p.imgs) ? p.imgs : []).filter(k => ID_RE.test(String(k))).map(String).slice(0, 6),
    demo: !!p.demo, ver: int(p.v), created: isNaN(created) ? new Date() : created,
  };
}
app.post('/api/sync', auth, h(async (req, res) => {
  const ups = (Array.isArray(req.body.upserts) ? req.body.upserts : []).slice(0, 2000).map(cleanProduct);
  const dels = (Array.isArray(req.body.deletes) ? req.body.deletes : []).slice(0, 2000).map(String).filter(x => ID_RE.test(x));
  const c = await pool.connect(), versions = {};
  try {
    await c.query('BEGIN');
    for (const v of ups) {
      if (!v.cat) continue;
      const { rows } = await c.query(
        `INSERT INTO categories (name) VALUES ($1)
         ON CONFLICT (lower(name)) DO UPDATE SET name=categories.name RETURNING name`, [v.cat]);
      v.cat = rows[0].name;
    }
    if (dels.length) await c.query('DELETE FROM products WHERE id = ANY($1)', [dels]);
    for (const v of ups) {
      const a = [v.id, v.sku, v.name, v.cat, v.qty, v.unit, v.min, v.loc, v.imgs, v.demo, req.user.name];
      let r;
      if (v.ver > 0) {
        r = await c.query(
          `UPDATE products SET sku=$2,name=$3,cat=$4,qty=$5,unit=$6,min=$7,loc=$8,imgs=$9,demo=$10,
             updated_by=$11,updated_at=now(),version=version+1
           WHERE id=$1 AND version=$12 RETURNING version`, [...a, v.ver]);
        if (!r.rowCount) throw fail(409, 'conflict');
      } else {
        r = await c.query(
          `INSERT INTO products (id,sku,name,cat,qty,unit,min,loc,imgs,demo,updated_by,created_at)
           VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)
           ON CONFLICT (id) DO UPDATE SET sku=EXCLUDED.sku,name=EXCLUDED.name,cat=EXCLUDED.cat,qty=EXCLUDED.qty,
             unit=EXCLUDED.unit,min=EXCLUDED.min,loc=EXCLUDED.loc,imgs=EXCLUDED.imgs,
             demo=EXCLUDED.demo,updated_by=EXCLUDED.updated_by,updated_at=now(),version=products.version+1
           RETURNING version`, [...a, v.created]);
      }
      versions[v.id] = r.rows[0].version;
    }
    await c.query('COMMIT');
    res.json({ versions });
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; }
  finally { c.release(); }
}));

/* ---------- ประวัติรับ/เบิก ---------- */
app.post('/api/log', auth, h(async (req, res) => {
  const es = (Array.isArray(req.body.entries) ? req.body.entries : []).slice(0, 2000);
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    for (const e of es) {
      if (!['in', 'out', 'set'].includes(e.type)) continue;
      const t = new Date(e.t);
      await c.query(
        `INSERT INTO movements (t,product_id,sku,name,type,n,qty_after,note,by_name) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
        [isNaN(t) ? new Date() : t, str(e.id, 64), str(e.sku, 80), str(e.name, 200), e.type,
          Math.max(-1e9, Math.min(1e9, parseInt(e.n, 10) || 0)), int(e.after), str(e.note, 200), req.user.name]);
    }
    await c.query('COMMIT');
    res.json({ ok: true });
  } catch (e) { await c.query('ROLLBACK').catch(() => {}); throw e; }
  finally { c.release(); }
}));
app.post('/api/log/clear', auth, h(async (req, res) => { await pool.query('DELETE FROM movements'); res.json({ ok: true }); }));

/* ---------- รูปภาพ (เก็บเป็นข้อมูลในฐานข้อมูล เพราะดิสก์บนคลาวด์มักไม่ถาวร) ---------- */
const idList = v => (Array.isArray(v) ? v : []).map(String).filter(x => ID_RE.test(x)).slice(0, 500);
app.post('/api/images', auth, h(async (req, res) => {
  const { id, data } = req.body;
  if (!ID_RE.test(String(id)) || !/^data:image\/(jpeg|png|webp);base64,/.test(data || '') || data.length > 700000) throw fail(400, 'รูปภาพไม่ถูกต้องหรือใหญ่เกินไป');
  await pool.query('INSERT INTO images (id,data) VALUES ($1,$2) ON CONFLICT (id) DO UPDATE SET data=EXCLUDED.data', [id, data]);
  res.json({ ok: true });
}));
app.post('/api/images/get', auth, h(async (req, res) => {
  const { rows } = await pool.query('SELECT id,data FROM images WHERE id = ANY($1)', [idList(req.body.ids)]);
  res.json(Object.fromEntries(rows.map(r => [r.id, r.data])));
}));
app.post('/api/images/delete', auth, h(async (req, res) => {
  await pool.query('DELETE FROM images WHERE id = ANY($1)', [idList(req.body.ids)]);
  res.json({ ok: true });
}));
app.post('/api/images/clear', auth, h(async (req, res) => { await pool.query('DELETE FROM images'); res.json({ ok: true }); }));

/* ---------- หน้าเว็บ + จัดการข้อผิดพลาด ---------- */
app.use('/api', (req, res) => res.status(404).json({ error: 'ไม่พบ API นี้' }));
app.use(express.static(path.join(__dirname, 'public'), { maxAge: 0 }));
app.use((err, req, res, next) => {
  if (err.type === 'entity.too.large') return res.status(413).json({ error: 'ข้อมูลใหญ่เกินไป' });
  if (err.code === '23505') return res.status(409).json({ error: 'รหัสสินค้าซ้ำกับที่มีอยู่แล้ว' });
  if (err.code === '23514') return res.status(400).json({ error: 'ค่าไม่ถูกต้อง (เช่น จำนวนติดลบ)' });
  const status = err.status || 500;
  if (status >= 500) console.error(err);
  res.status(status).json({ error: status >= 500 ? 'เซิร์ฟเวอร์ขัดข้อง' : err.message });
});

/* ---------- เริ่มทำงาน ---------- */
(async () => {
  await init();
  const { rows } = await pool.query('SELECT count(*)::int AS n FROM users');
  if (!rows[0].n && process.env.ADMIN_USER && process.env.ADMIN_PASS) {
    const username = str(process.env.ADMIN_USER, 80).trim();
    const name = str(process.env.ADMIN_NAME || username, 100).trim();
    if (!username || /\s/.test(username) || !name) throw new Error('ADMIN_USER/ADMIN_NAME ไม่ถูกต้อง');
    const passHash = await bcrypt.hash(userPassword(process.env.ADMIN_PASS), 12);
    const { rows: created } = await pool.query(
      `INSERT INTO users (username,name,pass_hash,role) VALUES ($1,$2,$3,'super_admin')
       RETURNING id,username,name,role,active`, [username, name, passHash]);
    await pool.query(
      `INSERT INTO user_audit (actor_id,actor_name,target_id,target_username,action,details)
       VALUES (NULL,'environment bootstrap',$1,$2,'created',$3::jsonb)`,
      [created[0].id, created[0].username, JSON.stringify({ role: created[0].role })]);
    console.log('สร้าง super admin คนแรก: ' + username);
  } else if (!rows[0].n) console.warn('ยังไม่มีผู้ใช้ — ตั้ง ADMIN_USER/ADMIN_PASS หรือรัน npm run add-user');
  app.listen(PORT, () => console.log('พร้อมใช้งานที่พอร์ต ' + PORT));
})().catch(e => { console.error(e); process.exit(1); });
