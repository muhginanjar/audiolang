import { FastifyInstance } from 'fastify';
import crypto from 'node:crypto';
import fsp from 'node:fs/promises';
import path from 'node:path';
import type { Role } from '../app.js';
import { PASSWORD_MAX, PASSWORD_MIN, hashPassword } from '../security.js';
import { normalizeFolder, StorageError } from '../storage.js';
import { jwtOnly } from './auth.js';

const ROLES: Role[] = ['viewer', 'uploader', 'admin'];

interface UserRow {
  id: string;
  email: string;
  role: Role;
  folders: string;
  failed_attempts: number;
  locked_until: number | null;
  created_at: number;
}

const toDto = (u: UserRow, usage?: { files: number; bytes: number }) => ({
  id: u.id,
  email: u.email,
  role: u.role,
  folders: JSON.parse(u.folders) as string[],
  locked: !!u.locked_until && u.locked_until > Date.now(),
  createdAt: new Date(u.created_at).toISOString(),
  ...(usage && { files: usage.files, usedBytes: usage.bytes }),
});

const foldersSchema = {
  type: 'array',
  maxItems: 50,
  uniqueItems: true,
  items: { type: 'string', minLength: 1, maxLength: 400 },
} as const;

const idParams = {
  type: 'object',
  required: ['id'],
  additionalProperties: false,
  properties: { id: { type: 'string', format: 'uuid' } },
} as const;

function parseFolders(list: string[]): string[] {
  const out = list.map(normalizeFolder);
  if (out.includes('')) throw new StorageError(400, 'Use role "admin" to grant access to the root folder');
  return [...new Set(out)];
}

/** User management. Admins only, and only with a real login (an API key can never manage users). */
export async function adminRoutes(app: FastifyInstance, opts: { storageDir: string }) {
  const db = app.db;
  const storageDir = path.resolve(opts.storageDir);

  app.addHook('onRequest', app.authenticate);
  app.addHook('onRequest', jwtOnly);
  app.addHook('onRequest', app.requireRole('admin'));

  const getUser = (id: string) =>
    db.prepare('SELECT * FROM users WHERE id = ?').get(id) as UserRow | undefined;
  const adminCount = () =>
    (db.prepare("SELECT COUNT(*) AS n FROM users WHERE role = 'admin'").get() as { n: number }).n;

  app.get('/users', async () => {
    const rows = db.prepare('SELECT * FROM users ORDER BY created_at').all() as UserRow[];
    const usage = new Map(
      (
        db
          .prepare('SELECT user_id, COUNT(*) AS files, COALESCE(SUM(size), 0) AS bytes FROM files GROUP BY user_id')
          .all() as { user_id: string; files: number; bytes: number }[]
      ).map((r) => [r.user_id, r]),
    );
    return { data: rows.map((u) => toDto(u, usage.get(u.id) ?? { files: 0, bytes: 0 })) };
  });

  app.post<{ Body: { email: string; password: string; role: Role; folders?: string[] } }>(
    '/users',
    {
      schema: {
        body: {
          type: 'object',
          required: ['email', 'password', 'role'],
          additionalProperties: false,
          properties: {
            email: { type: 'string', format: 'email', maxLength: 254 },
            password: { type: 'string', minLength: PASSWORD_MIN, maxLength: PASSWORD_MAX },
            role: { type: 'string', enum: ROLES },
            folders: foldersSchema,
          },
        },
      },
      config: { rateLimit: { max: 20, timeWindow: '1 minute' } },
    },
    async (req, reply) => {
      const email = req.body.email.trim().toLowerCase();
      const folders = parseFolders(req.body.folders ?? []);
      const passwordHash = await hashPassword(req.body.password);
      const id = crypto.randomUUID();
      try {
        db.prepare(
          'INSERT INTO users (id, email, password_hash, role, folders, created_at) VALUES (?, ?, ?, ?, ?, ?)',
        ).run(id, email, passwordHash, req.body.role, JSON.stringify(folders), Date.now());
      } catch (e: any) {
        if (e?.code === 'SQLITE_CONSTRAINT_UNIQUE') {
          return reply.code(409).send({ error: 'Email already registered' });
        }
        throw e;
      }
      req.log.info({ adminId: req.user.sub, userId: id, role: req.body.role }, 'user created by admin');
      return reply.code(201).send(toDto(getUser(id)!));
    },
  );

  app.patch<{
    Params: { id: string };
    Body: { role?: Role; folders?: string[]; password?: string; unlock?: boolean };
  }>(
    '/users/:id',
    {
      schema: {
        params: idParams,
        body: {
          type: 'object',
          additionalProperties: false,
          minProperties: 1,
          properties: {
            role: { type: 'string', enum: ROLES },
            folders: foldersSchema,
            password: { type: 'string', minLength: PASSWORD_MIN, maxLength: PASSWORD_MAX },
            unlock: { type: 'boolean', const: true },
          },
        },
      },
      config: { rateLimit: { max: 20, timeWindow: '1 minute' } },
    },
    async (req, reply) => {
      const user = getUser(req.params.id);
      if (!user) return reply.code(404).send({ error: 'Not Found' });
      const { role, password, unlock } = req.body;
      if (user.role === 'admin' && role && role !== 'admin' && adminCount() <= 1) {
        return reply.code(409).send({ error: 'Cannot demote the last admin' });
      }
      const folders = req.body.folders && parseFolders(req.body.folders);
      const passwordHash = password && (await hashPassword(password));

      db.transaction(() => {
        if (role) db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, user.id);
        if (folders) db.prepare('UPDATE users SET folders = ? WHERE id = ?').run(JSON.stringify(folders), user.id);
        if (passwordHash) {
          db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(passwordHash, user.id);
          // A reset password must end every existing session of that user
          db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').run(user.id);
        }
        if (unlock || passwordHash) {
          db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?').run(user.id);
        }
      })();
      req.log.info(
        { adminId: req.user.sub, userId: user.id, fields: Object.keys(req.body) },
        'user updated by admin',
      );
      return toDto(getUser(user.id)!);
    },
  );

  // Deletes the user, their sessions, API keys and files (their public URLs stop working)
  app.delete<{ Params: { id: string } }>('/users/:id', { schema: { params: idParams } }, async (req, reply) => {
    const user = getUser(req.params.id);
    if (!user) return reply.code(404).send({ error: 'Not Found' });
    if (user.id === req.user.sub) return reply.code(409).send({ error: 'You cannot delete yourself' });
    if (user.role === 'admin' && adminCount() <= 1) {
      return reply.code(409).send({ error: 'Cannot delete the last admin' });
    }
    const files = db.prepare('SELECT stored_name FROM files WHERE user_id = ?').all(user.id) as {
      stored_name: string;
    }[];
    db.prepare('DELETE FROM users WHERE id = ?').run(user.id); // cascades to tokens, keys, files
    await Promise.all(files.map((f) => fsp.rm(path.join(storageDir, f.stored_name), { force: true })));
    req.log.info({ adminId: req.user.sub, userId: user.id, files: files.length }, 'user deleted by admin');
    return reply.code(204).send();
  });
}
