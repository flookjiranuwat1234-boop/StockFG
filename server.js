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
const fail = (status, error) => Object.assign(new Error(error), { status });

const auth = (req, res, next) => {
  try { req.user = jwt.verify(req.cookies.tk || '', JWT_SECRET); next(); }
  catch (e) { res.status(401).json({ error: 'auth' }); }
};

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
  const { rows } = await pool.query('SELECT * FROM users WHERE lower(username)=lower($1)', [str(req.body.username, 80)]);
  const u = rows[0];
  // เทียบ hash เสมอ แม้ไม่พบผู้ใช้ เพื่อไม่ให้เดาชื่อผู้ใช้จากเวลาตอบกลับได้
  const ok = await bcrypt.compare(str(req.body.password, 200), u ? u.pass_hash : '$2a$12$invalidinvalidinvalidinvalidinvalidinvalidinvalidinvalidinva');
  if (!u || !ok) throw fail(401, 'ชื่อผู้ใช้หรือรหัสผ่านไม่ถูกต้อง');
  tries.delete(req.ip);
  const token = jwt.sign({ id: u.id, name: u.name }, JWT_SECRET, { expiresIn: '12h' });
  res.cookie('tk', token, { httpOnly: true, sameSite: 'lax', secure: prod, maxAge: 12 * 3600 * 1000 });
  res.json({ name: u.name });
}));
app.post('/api/logout', (req, res) => { res.clearCookie('tk'); res.json({ ok: true }); });
app.get('/api/me', auth, (req, res) => res.json({ name: req.user.name }));
app.get('/healthz', h(async (req, res) => { await pool.query('SELECT 1'); res.send('ok'); }));

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
    await pool.query('INSERT INTO users (username,name,pass_hash) VALUES ($1,$2,$3)',
      [process.env.ADMIN_USER, process.env.ADMIN_NAME || process.env.ADMIN_USER, await bcrypt.hash(process.env.ADMIN_PASS, 12)]);
    console.log('สร้างผู้ใช้แรก: ' + process.env.ADMIN_USER);
  } else if (!rows[0].n) console.warn('ยังไม่มีผู้ใช้ — ตั้ง ADMIN_USER/ADMIN_PASS หรือรัน npm run add-user');
  app.listen(PORT, () => console.log('พร้อมใช้งานที่พอร์ต ' + PORT));
})().catch(e => { console.error(e); process.exit(1); });
