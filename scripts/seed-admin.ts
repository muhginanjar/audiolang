/**
 * Creates the first admin account. Safe to run repeatedly: it does nothing once an admin exists.
 *
 *   npm run seed:admin -- admin@domain.com                  (a strong random password is printed once)
 *   ADMIN_PASSWORD='...' npm run seed:admin -- admin@domain.com
 *
 * The email can also come from ADMIN_EMAIL. After logging in, change the password with
 * POST /auth/change-password, then add other users with POST /admin/users.
 */
import crypto from 'node:crypto';
import { openDb } from '../src/db.js';
import { config } from '../src/config.js';
import { PASSWORD_MAX, PASSWORD_MIN, hashPassword } from '../src/security.js';

const email = (process.argv[2] ?? process.env.ADMIN_EMAIL ?? '').trim().toLowerCase();
if (!/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
  console.error('Usage: npm run seed:admin -- <email>   (or set ADMIN_EMAIL)');
  process.exit(1);
}

const db = openDb(config.dbPath);

const existingAdmin = db.prepare("SELECT email FROM users WHERE role = 'admin' LIMIT 1").get() as
  | { email: string }
  | undefined;
if (existingAdmin) {
  console.log(`An admin already exists (${existingAdmin.email}); nothing to do.`);
  db.close();
  process.exit(0);
}
// Never silently promote an existing account: that is what `npm run user:role` is for
if (db.prepare('SELECT 1 FROM users WHERE email = ?').get(email)) {
  console.error(`User ${email} already exists but is not admin. Promote it with: npm run user:role -- ${email} admin`);
  db.close();
  process.exit(1);
}

const generated = !process.env.ADMIN_PASSWORD;
const password = process.env.ADMIN_PASSWORD ?? crypto.randomBytes(18).toString('base64url');
if (password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
  console.error(`ADMIN_PASSWORD must be ${PASSWORD_MIN}-${PASSWORD_MAX} characters`);
  process.exit(1);
}

db.prepare(
  "INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, 'admin', ?)",
).run(crypto.randomUUID(), email, await hashPassword(password), Date.now());
db.close();

console.log(`Admin created: ${email}`);
if (generated) {
  console.log(`Password (shown only once, store it now): ${password}`);
}
