'use strict';
const { Pool } = require('pg');
const { DATABASE_URL } = process.env;
if (!DATABASE_URL) { console.error('ต้องตั้งค่า DATABASE_URL'); process.exit(1); }
const local = /localhost|127\.0\.0\.1/.test(DATABASE_URL);
const pool = new Pool({
  connectionString: DATABASE_URL,
  ssl: local || process.env.DATABASE_SSL === 'false' ? false : { rejectUnauthorized: false },
  max: 10,
});
const FOOD_CATEGORY_ALIASES = [
  ['Fresh produce', 'ผักและผลไม้'],
  ['Produce', 'ผักและผลไม้'],
  ['Meat', 'เนื้อสัตว์'],
  ['Seafood', 'อาหารทะเล'],
  ['Beverage', 'เครื่องดื่ม'],
  ['Beverages', 'เครื่องดื่ม'],
  ['Grocery', 'อาหารแห้ง'],
  ['ขนมอบ', 'ผลิตภัณฑ์ขนมอบ'],
  ['Bakery', 'ผลิตภัณฑ์ขนมอบ'],
  ['ผลิตภัณฑ์จากนม', 'นมและผลิตภัณฑ์จากนม'],
  ['Dairy', 'นมและผลิตภัณฑ์จากนม'],
  ['Snacks', 'ขนมขบเคี้ยว'],
];
const foodCategoryAliasMap = new Map(FOOD_CATEGORY_ALIASES.map(([alias, canonical]) => [alias.toLowerCase(), canonical]));
const normalizeCategory = value => {
  const name = String(value ?? '').trim();
  return foodCategoryAliasMap.get(name.toLowerCase()) || name;
};
const SCHEMA = `
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  username TEXT NOT NULL,
  name TEXT NOT NULL,
  pass_hash TEXT NOT NULL,
  role TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user','super_admin')),
  active BOOLEAN NOT NULL DEFAULT true,
  token_version INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE users ADD COLUMN IF NOT EXISTS role TEXT NOT NULL DEFAULT 'user';
ALTER TABLE users ADD COLUMN IF NOT EXISTS active BOOLEAN NOT NULL DEFAULT true;
ALTER TABLE users ADD COLUMN IF NOT EXISTS token_version INTEGER NOT NULL DEFAULT 0;
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_email TEXT;
ALTER TABLE users ADD COLUMN IF NOT EXISTS google_sub TEXT;
DO $$ BEGIN
  ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('user','super_admin'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS users_username_uq ON users (lower(username));
CREATE UNIQUE INDEX IF NOT EXISTS users_google_email_uq ON users (lower(google_email)) WHERE google_email IS NOT NULL;
CREATE UNIQUE INDEX IF NOT EXISTS users_google_sub_uq ON users (google_sub) WHERE google_sub IS NOT NULL;
CREATE TABLE IF NOT EXISTS user_audit (
  id BIGSERIAL PRIMARY KEY,
  actor_id INTEGER REFERENCES users(id),
  actor_name TEXT NOT NULL,
  target_id INTEGER NOT NULL REFERENCES users(id),
  target_username TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('created','updated','password_reset','google_linked')),
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE user_audit ALTER COLUMN actor_id DROP NOT NULL;
ALTER TABLE user_audit DROP CONSTRAINT IF EXISTS user_audit_action_check;
ALTER TABLE user_audit ADD CONSTRAINT user_audit_action_check
  CHECK (action IN ('created','updated','password_reset','google_linked'));
CREATE INDEX IF NOT EXISTS user_audit_created_at_idx ON user_audit (created_at DESC);
CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY,
  sku TEXT NOT NULL,
  name TEXT NOT NULL,
  cat TEXT NOT NULL DEFAULT '',
  description TEXT NOT NULL DEFAULT '',
  qty INTEGER NOT NULL DEFAULT 0 CHECK (qty >= 0),
  unit TEXT NOT NULL DEFAULT 'ชิ้น',
  min INTEGER NOT NULL DEFAULT 0 CHECK (min >= 0),
  loc TEXT NOT NULL DEFAULT '',
  imgs TEXT[] NOT NULL DEFAULT '{}',
  demo BOOLEAN NOT NULL DEFAULT false,
  published BOOLEAN NOT NULL DEFAULT false,
  version INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by TEXT
);
ALTER TABLE products DROP COLUMN IF EXISTS price;
ALTER TABLE products ADD COLUMN IF NOT EXISTS published BOOLEAN NOT NULL DEFAULT false;
ALTER TABLE products ADD COLUMN IF NOT EXISTS description TEXT NOT NULL DEFAULT '';
CREATE UNIQUE INDEX IF NOT EXISTS products_sku_uq ON products (lower(sku));
CREATE TABLE IF NOT EXISTS categories (
  name TEXT PRIMARY KEY,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX IF NOT EXISTS categories_name_uq ON categories (lower(name));
INSERT INTO categories (name)
SELECT min(btrim(cat))
FROM products
WHERE btrim(cat) <> ''
GROUP BY lower(btrim(cat))
ON CONFLICT DO NOTHING;
INSERT INTO categories (name)
SELECT food.name
FROM (VALUES
  ('ผักและผลไม้','Fresh produce'),
  ('เนื้อสัตว์','Meat'),
  ('อาหารทะเล','Seafood'),
  ('เครื่องดื่ม','Beverages'),
  ('อาหารแห้ง','Grocery'),
  ('ผลิตภัณฑ์ขนมอบ','Bakery'),
  ('นมและผลิตภัณฑ์จากนม','Dairy'),
  ('ขนมขบเคี้ยว','Snacks')
) AS food(name, english_name)
WHERE NOT EXISTS (
  SELECT 1 FROM categories existing
  WHERE lower(btrim(existing.name)) IN (lower(food.name),lower(food.english_name))
)
ON CONFLICT DO NOTHING;
CREATE TABLE IF NOT EXISTS images (
  id TEXT PRIMARY KEY,
  data TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS movements (
  id BIGSERIAL PRIMARY KEY,
  t TIMESTAMPTZ NOT NULL DEFAULT now(),
  product_id TEXT,
  sku TEXT, name TEXT,
  type TEXT NOT NULL CHECK (type IN ('in','out','set')),
  n INTEGER NOT NULL,
  qty_after INTEGER NOT NULL,
  note TEXT NOT NULL DEFAULT '',
  by_name TEXT
);
CREATE INDEX IF NOT EXISTS movements_t_idx ON movements (t DESC);
`;
const init = async () => {
  await pool.query(SCHEMA);

  const damagedMarks = [0x049f, 0x0477, 0x04a0].map(mark => String.fromCharCode(mark));
  const thaiMarks = [0x0e49, 0x0e48, 0x0e4a].map(mark => String.fromCharCode(mark));
  const damagedWater = `นํ${String.fromCharCode(0x049f)}า`;
  const damagedLow = `ตํ${String.fromCharCode(0x0477)}า`;
  const incompleteSeafood = 'ร้อมน้ำจิ้มซีฟู้ด';
  const completeSeafood = 'พร้อมน้ำจิ้มซีฟู้ด';
  const spacedBlackPepper = 'พริก ไทยดํา';
  const joinedBlackPepper = 'พริกไทยดำ';
  const sourceReference = 'แคตตาล็อก ต.ค. 2026 หน้า';

  const { rowCount } = await pool.query(
    `UPDATE products
     SET description = replace(
       replace(
         translate(
           replace(replace(description, $6, $7), $8, $9),
           $1, $2
         ),
         $10, $11
       ),
       $12, $13
     )
     WHERE strpos(description, $14) > 0
       AND (
         strpos(description, $3) > 0
         OR strpos(description, $4) > 0
         OR strpos(description, $5) > 0
         OR strpos(description, $10) > 0
         OR strpos(description, $12) > 0
       )`,
    [
      damagedMarks.join(''), thaiMarks.join(''),
      damagedMarks[0], damagedMarks[1], damagedMarks[2],
      damagedWater, 'น้ำ',
      damagedLow, 'ต่ำ',
      incompleteSeafood, completeSeafood,
      spacedBlackPepper, joinedBlackPepper,
      sourceReference,
    ],
  );
  if (rowCount) console.info(`แก้ไขข้อความสินค้า ${rowCount} รายการ`);

  const client = await pool.connect();
  try {
    await client.query('BEGIN');
    const canonicalNames = [...new Set(FOOD_CATEGORY_ALIASES.map(([, canonical]) => canonical))];
    await client.query(
      'INSERT INTO categories (name) SELECT unnest($1::text[]) ON CONFLICT DO NOTHING',
      [canonicalNames],
    );

    const mappingRows = FOOD_CATEGORY_ALIASES.map((_, index) =>
      `($${index * 2 + 1}, $${index * 2 + 2})`).join(',');
    const mappings = await client.query(
      `WITH aliases(alias, canonical) AS (VALUES ${mappingRows})
       UPDATE products AS p
       SET cat=aliases.canonical, version=p.version+1, updated_at=now()
       FROM aliases
       WHERE lower(btrim(p.cat))=lower(aliases.alias)
         AND p.cat IS DISTINCT FROM aliases.canonical`,
      FOOD_CATEGORY_ALIASES.flat(),
    );

    const aliasRows = FOOD_CATEGORY_ALIASES.map((_, index) => `($${index + 1})`).join(',');
    const removed = await client.query(
      `WITH aliases(name) AS (VALUES ${aliasRows})
       DELETE FROM categories AS c USING aliases
       WHERE lower(btrim(c.name))=lower(aliases.name)`,
      FOOD_CATEGORY_ALIASES.map(([alias]) => alias),
    );
    await client.query('COMMIT');
    if (mappings.rowCount || removed.rowCount) {
      console.info(`รวมหมวดอาหารแล้ว: ปรับสินค้า ${mappings.rowCount} รายการ, ลบชื่อหมวดซ้ำ ${removed.rowCount} รายการ`);
    }
  } catch (error) {
    await client.query('ROLLBACK').catch(() => {});
    throw error;
  } finally { client.release(); }
};
module.exports = { pool, init, normalizeCategory };
