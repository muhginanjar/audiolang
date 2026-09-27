/**
 * Admin CLI: create a user or change a user's role.
 *
 *   npm run user:create -- <email> <role>      (password is prompted, not passed as an argument)
 *   npm run user:role   -- <email> <role>
 *
 * Roles: viewer | uploader | admin
 */
import crypto from 'node:crypto';
import readline from 'node:readline';
import { openDb } from '../src/db.js';
import { config } from '../src/config.js';
import { PASSWORD_MAX, PASSWORD_MIN, hashPassword } from '../src/security.js';

const ROLES = ['viewer', 'uploader', 'admin'];
const [cmd, email, role] = process.argv.slice(2);

function ask(q: string): Promise<string> {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout, terminal: true });
  return new Promise((resolve) => {
    (rl as any)._writeToOutput = (s: string) => {
      if (s.includes(q)) (rl as any).output.write(s);
    };
    rl.question(q, (a) => {
      rl.close();
      process.stdout.write('\n');
      resolve(a);
    });
  });
}

if (!email || !ROLES.includes(role ?? '')) {
  console.error('Usage: create|role <email> <viewer|uploader|admin>');
  process.exit(1);
}

const db = openDb(config.dbPath);
const normalized = email.trim().toLowerCase();

if (cmd === 'create') {
  const password = process.env.NEW_USER_PASSWORD ?? (await ask('Password (min 12 chars): '));
  if (password.length < PASSWORD_MIN || password.length > PASSWORD_MAX) {
    console.error(`Password must be ${PASSWORD_MIN}-${PASSWORD_MAX} characters`);
    process.exit(1);
  }
  const passwordHash = await hashPassword(password);
  try {
    db.prepare(
      'INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)',
    ).run(crypto.randomUUID(), normalized, passwordHash, role, Date.now());
    console.log(`Created ${normalized} with role ${role}`);
  } catch (e: any) {
    console.error(e?.code === 'SQLITE_CONSTRAINT_UNIQUE' ? 'User already exists' : e);
    process.exit(1);
  }
} else if (cmd === 'role') {
  const r = db.prepare('UPDATE users SET role = ? WHERE email = ?').run(role, normalized);
  if (r.changes === 0) {
    console.error('User not found');
    process.exit(1);
  }
  console.log(`${normalized} is now ${role}`);
} else {
  console.error('Unknown command');
  process.exit(1);
}
db.close();
