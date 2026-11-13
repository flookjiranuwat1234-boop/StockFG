'use strict';
// ใช้: npm run add-user -- <ชื่อผู้ใช้> <รหัสผ่าน 12 ตัวขึ้นไป> "<ชื่อที่แสดง>"
// เลื่อนบัญชีเดิมเป็น super admin: npm run add-user -- --promote <ชื่อผู้ใช้>
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
  const args = process.argv.slice(2);
  const promote = args[0] === '--promote';
  const [u, p, n] = promote ? [] : args;
  if ((promote && !args[1]) || (!promote && (!u || !p || p.length < 12 || Buffer.byteLength(p, 'utf8') > 72))) {
    if (promote) console.error('ใช้: npm run add-user -- --promote <ชื่อผู้ใช้>');
    else console.error('ใช้: npm run add-user -- <ชื่อผู้ใช้> <รหัสผ่าน 12 ตัวขึ้นไป> "<ชื่อที่แสดง>"');
    process.exit(1);
  }
  await init();
  const c = await pool.connect();
  try {
    await c.query('BEGIN');
    await c.query('LOCK TABLE users IN SHARE ROW EXCLUSIVE MODE');
    if (promote) {
      const { rows } = await c.query(
        'SELECT id,username,name,role,active FROM users WHERE lower(username)=lower($1) FOR UPDATE', [args[1]]);
      const target = rows[0];
      if (!target) throw new Error('ไม่พบบัญชีผู้ใช้นี้');
      await c.query(
        `UPDATE users SET role='super_admin',active=true,
           token_version=token_version+CASE
             WHEN active=false OR role IS DISTINCT FROM 'super_admin' THEN 1 ELSE 0 END
         WHERE id=$1`, [target.id]);
      const details = {};
      if (target.role !== 'super_admin') details.role = { from: target.role, to: 'super_admin' };
      if (!target.active) details.active = { from: false, to: true };
      if (Object.keys(details).length) {
        await c.query(
          `INSERT INTO user_audit (actor_id,actor_name,target_id,target_username,action,details)
           VALUES (NULL,'CLI',$1,$2,'updated',$3::jsonb)`,
          [target.id, target.username, JSON.stringify(Object.assign({ source: 'cli' }, details))]);
      }
      await c.query('COMMIT');
      console.log('เลื่อน ' + target.username + ' เป็น super admin แล้ว');
      return;
    }
    const hash = await bcrypt.hash(p, 12);
    const { rows } = await c.query('SELECT id,username,name FROM users WHERE lower(username)=lower($1)', [u]);
    if (rows.length) {
      const target = rows[0], newName = n || u;
      await c.query(
        'UPDATE users SET pass_hash=$2,name=$3,token_version=token_version+1 WHERE id=$1',
        [target.id, hash, newName]);
      const details = { source: 'cli' };
      if (target.name !== newName) details.name = { from: target.name, to: newName };
      await c.query(
        `INSERT INTO user_audit (actor_id,actor_name,target_id,target_username,action,details)
         VALUES (NULL,'CLI',$1,$2,'password_reset',$3::jsonb)`,
        [target.id, target.username, JSON.stringify(details)]);
    } else {
      const { rows: count } = await c.query('SELECT count(*)::int AS n FROM users');
      const role = count[0].n === 0 ? 'super_admin' : 'user';
      const { rows: created } = await c.query(
        'INSERT INTO users (username,name,pass_hash,role) VALUES ($1,$2,$3,$4) RETURNING id,username,role',
        [u, n || u, hash, role]);
      await c.query(
        `INSERT INTO user_audit (actor_id,actor_name,target_id,target_username,action,details)
         VALUES (NULL,'CLI',$1,$2,'created',$3::jsonb)`,
        [created[0].id, created[0].username, JSON.stringify({ role, source: 'cli' })]);
    }
    await c.query('COMMIT');
    console.log('บันทึกผู้ใช้ ' + u + ' แล้ว');
  } catch (e) {
    await c.query('ROLLBACK').catch(() => {});
    throw e;
  } finally {
    c.release();
    await pool.end();
  }
})().catch(e => { console.error(e.message); process.exit(1); });
