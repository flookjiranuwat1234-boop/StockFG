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
DO $$ BEGIN
  ALTER TABLE users ADD CONSTRAINT users_role_check CHECK (role IN ('user','super_admin'));
EXCEPTION WHEN duplicate_object THEN NULL;
END $$;
CREATE UNIQUE INDEX IF NOT EXISTS users_username_uq ON users (lower(username));
CREATE TABLE IF NOT EXISTS user_audit (
  id BIGSERIAL PRIMARY KEY,
  actor_id INTEGER REFERENCES users(id),
  actor_name TEXT NOT NULL,
  target_id INTEGER NOT NULL REFERENCES users(id),
  target_username TEXT NOT NULL,
  action TEXT NOT NULL CHECK (action IN ('created','updated','password_reset')),
  details JSONB NOT NULL DEFAULT '{}'::jsonb,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
ALTER TABLE user_audit ALTER COLUMN actor_id DROP NOT NULL;
CREATE INDEX IF NOT EXISTS user_audit_created_at_idx ON user_audit (created_at DESC);
CREATE TABLE IF NOT EXISTS products (
  id TEXT PRIMARY KEY,
  sku TEXT NOT NULL,
  name TEXT NOT NULL,
  cat TEXT NOT NULL DEFAULT '',
  qty INTEGER NOT NULL DEFAULT 0 CHECK (qty >= 0),
  unit TEXT NOT NULL DEFAULT 'ชิ้น',
  min INTEGER NOT NULL DEFAULT 0 CHECK (min >= 0),
  loc TEXT NOT NULL DEFAULT '',
  imgs TEXT[] NOT NULL DEFAULT '{}',
  demo BOOLEAN NOT NULL DEFAULT false,
  version INTEGER NOT NULL DEFAULT 1,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_by TEXT
);
ALTER TABLE products DROP COLUMN IF EXISTS price;
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
const init = () => pool.query(SCHEMA);
module.exports = { pool, init };
