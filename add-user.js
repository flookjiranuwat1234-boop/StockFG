'use strict';
// ใช้: npm run add-user -- <ชื่อผู้ใช้> <รหัสผ่าน 8 ตัวขึ้นไป> "<ชื่อที่แสดง>"
// ถ้ามีผู้ใช้อยู่แล้วจะเปลี่ยนรหัสผ่านและชื่อให้
const fs = require('fs');
try {
  fs.readFileSync(__dirname + '/../.env', 'utf8').split('\n').forEach(l => {
    const m = l.match(/^([A-Z_]+)=(.*)$/);
    if (m && !process.env[m[1]]) process.env[m[1]] = m[2];
  });
} catch (e) { /* ไม่มี .env ก็ใช้ค่าจากระบบ */ }
const bcrypt = require('bcryptjs');
const { pool, init } = require('../db');
(async () => {
  const [u, p, n] = process.argv.slice(2);
  if (!u || !p || p.length < 8) {
    console.error('ใช้: npm run add-user -- <ชื่อผู้ใช้> <รหัสผ่าน 8 ตัวขึ้นไป> "<ชื่อที่แสดง>"');
    process.exit(1);
  }
  await init();
  const hash = await bcrypt.hash(p, 12);
  await pool.query(
    `INSERT INTO users (username,name,pass_hash) VALUES ($1,$2,$3)
     ON CONFLICT (lower(username)) DO UPDATE SET pass_hash=EXCLUDED.pass_hash, name=EXCLUDED.name`,
    [u, n || u, hash]);
  console.log('บันทึกผู้ใช้ ' + u + ' แล้ว');
  await pool.end();
})().catch(e => { console.error(e.message); process.exit(1); });
