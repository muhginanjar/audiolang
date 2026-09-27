import { FastifyInstance, FastifyReply, FastifyRequest } from 'fastify';
import { verify } from '@node-rs/argon2';
import crypto from 'node:crypto';
import { config } from '../config.js';
import { PASSWORD_MAX, PASSWORD_MIN, hashPassword } from '../security.js';

const REFRESH_COOKIE = 'rt';

// Used when the email doesn't exist so login takes the same time either way (prevents user enumeration by timing)
const DUMMY_HASH_PROMISE = hashPassword('dummy-password-for-timing');

const credentialsSchema = {
  type: 'object',
  required: ['email', 'password'],
  additionalProperties: false,
  properties: {
    email: { type: 'string', format: 'email', maxLength: 254 },
    password: { type: 'string', minLength: PASSWORD_MIN, maxLength: PASSWORD_MAX },
  },
} as const;

const loginSchema = {
  ...credentialsSchema,
  properties: {
    ...credentialsSchema.properties,
    password: { type: 'string', minLength: 1, maxLength: PASSWORD_MAX },
  },
} as const;

interface UserRow {
  id: string;
  email: string;
  password_hash: string;
  failed_attempts: number;
  locked_until: number | null;
}
interface RefreshRow {
  token_hash: string;
  user_id: string;
  family_id: string;
  expires_at: number;
  used_at: number | null;
  revoked: number;
}

const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');

// Account/key management requires a real login (JWT), not an API key
export const jwtOnly = async (req: FastifyRequest, reply: FastifyReply) => {
  if (req.authVia !== 'jwt') return reply.code(403).send({ error: 'Login required' });
};

export async function authRoutes(app: FastifyInstance) {
  const db = app.db;

  function issueRefreshToken(userId: string, familyId: string) {
    const token = crypto.randomBytes(32).toString('base64url');
    const now = Date.now();
    db.prepare(
      `INSERT INTO refresh_tokens (token_hash, user_id, family_id, expires_at, created_at)
       VALUES (?, ?, ?, ?, ?)`,
    ).run(sha256(token), userId, familyId, now + config.refreshTokenDays * 86_400_000, now);
    return token;
  }

  function sendTokens(reply: FastifyReply, userId: string, familyId: string) {
    const refresh = issueRefreshToken(userId, familyId);
    const accessToken = app.jwt.sign({ sub: userId, typ: 'access' });
    reply.setCookie(REFRESH_COOKIE, refresh, {
      httpOnly: true, // not readable by JS -> safe from XSS token theft
      secure: config.isProd,
      sameSite: 'strict', // not sent on cross-site requests -> CSRF protection
      path: '/auth',
      maxAge: config.refreshTokenDays * 86_400,
    });
    return { accessToken, tokenType: 'Bearer', expiresIn: config.accessTokenTtl };
  }

  function clearRefreshCookie(reply: FastifyReply) {
    reply.clearCookie(REFRESH_COOKIE, { path: '/auth' });
  }

  // ---------- Register ----------
  app.post<{ Body: { email: string; password: string } }>(
    '/register',
    {
      schema: { body: credentialsSchema },
      config: { rateLimit: { max: 5, timeWindow: '1 minute' } },
    },
    async (req, reply) => {
      if (!config.allowRegistration) {
        return reply.code(403).send({ error: 'Registration is disabled' });
      }
      const email = req.body.email.trim().toLowerCase();
      const passwordHash = await hashPassword(req.body.password);
      const id = crypto.randomUUID();
      try {
        db.prepare(
          'INSERT INTO users (id, email, password_hash, created_at) VALUES (?, ?, ?, ?)',
        ).run(id, email, passwordHash, Date.now());
      } catch (e: any) {
        if (e?.code === 'SQLITE_CONSTRAINT_UNIQUE') {
          return reply.code(409).send({ error: 'Email already registered' });
        }
        throw e;
      }
      req.log.info({ userId: id }, 'user registered');
      return reply.code(201).send({ id, email });
    },
  );

  // ---------- Login ----------
  app.post<{ Body: { email: string; password: string } }>(
    '/login',
    {
      schema: { body: loginSchema },
      config: { rateLimit: { max: 5, timeWindow: '1 minute' } },
    },
    async (req, reply) => {
      const email = req.body.email.trim().toLowerCase();
      const user = db.prepare('SELECT * FROM users WHERE email = ?').get(email) as
        | UserRow
        | undefined;
      const fail = () => reply.code(401).send({ error: 'Invalid email or password' });

      if (!user) {
        await verify(await DUMMY_HASH_PROMISE, req.body.password);
        return fail();
      }

      const now = Date.now();
      if (user.locked_until && user.locked_until > now) {
        // Same generic response; lockout is not revealed
        await verify(await DUMMY_HASH_PROMISE, req.body.password);
        req.log.warn({ userId: user.id }, 'login attempt on locked account');
        return fail();
      }

      const ok = await verify(user.password_hash, req.body.password);
      if (!ok) {
        const attempts = user.failed_attempts + 1;
        const lock = attempts >= config.maxLoginAttempts;
        db.prepare('UPDATE users SET failed_attempts = ?, locked_until = ? WHERE id = ?').run(
          lock ? 0 : attempts,
          lock ? now + config.lockoutMinutes * 60_000 : null,
          user.id,
        );
        req.log.warn({ userId: user.id, attempts, locked: lock }, 'failed login');
        return fail();
      }

      db.prepare('UPDATE users SET failed_attempts = 0, locked_until = NULL WHERE id = ?').run(
        user.id,
      );
      req.log.info({ userId: user.id }, 'login success');
      return sendTokens(reply, user.id, crypto.randomUUID());
    },
  );

  // ---------- Refresh (rotation + reuse detection) ----------
  app.post(
    '/refresh',
    { config: { rateLimit: { max: 20, timeWindow: '1 minute' } } },
    async (req, reply) => {
      const token = req.cookies[REFRESH_COOKIE];
      if (!token) return reply.code(401).send({ error: 'Unauthorized' });

      const row = db
        .prepare('SELECT * FROM refresh_tokens WHERE token_hash = ?')
        .get(sha256(token)) as RefreshRow | undefined;

      if (!row) {
        clearRefreshCookie(reply);
        return reply.code(401).send({ error: 'Unauthorized' });
      }

      if (row.used_at || row.revoked) {
        // A rotated token was presented again: likely stolen. Kill the whole session family.
        db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?').run(row.family_id);
        req.log.warn({ userId: row.user_id }, 'refresh token reuse detected; family revoked');
        clearRefreshCookie(reply);
        return reply.code(401).send({ error: 'Unauthorized' });
      }

      if (row.expires_at < Date.now()) {
        clearRefreshCookie(reply);
        return reply.code(401).send({ error: 'Unauthorized' });
      }

      const rotate = db.transaction(() => {
        const r = db
          .prepare('UPDATE refresh_tokens SET used_at = ? WHERE token_hash = ? AND used_at IS NULL')
          .run(Date.now(), row.token_hash);
        return r.changes === 1;
      });
      if (!rotate()) return reply.code(401).send({ error: 'Unauthorized' });

      return sendTokens(reply, row.user_id, row.family_id);
    },
  );

  // ---------- Logout (this session) ----------
  app.post('/logout', async (req, reply) => {
    const token = req.cookies[REFRESH_COOKIE];
    if (token) {
      const row = db
        .prepare('SELECT family_id FROM refresh_tokens WHERE token_hash = ?')
        .get(sha256(token)) as { family_id: string } | undefined;
      if (row) {
        db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE family_id = ?').run(row.family_id);
      }
    }
    clearRefreshCookie(reply);
    return reply.code(204).send();
  });

  // ---------- Logout from all devices ----------
  app.post('/logout-all', { onRequest: [app.authenticate] }, async (req, reply) => {
    db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').run(req.user.sub);
    clearRefreshCookie(reply);
    return reply.code(204).send();
  });

  // ---------- Current user ----------
  app.get('/me', { onRequest: [app.authenticate] }, async (req, reply) => {
    const u = db
      .prepare('SELECT id, email, role, folders, created_at FROM users WHERE id = ?')
      .get(req.user.sub) as
      | { id: string; email: string; role: string; folders: string; created_at: number }
      | undefined;
    if (!u) return reply.code(401).send({ error: 'Unauthorized' });
    return {
      id: u.id,
      email: u.email,
      role: u.role,
      folders: JSON.parse(u.folders),
      createdAt: new Date(u.created_at).toISOString(),
    };
  });

  // ---------- Change own password (revokes every session and must re-login) ----------
  app.post<{ Body: { currentPassword: string; newPassword: string } }>(
    '/change-password',
    {
      onRequest: [app.authenticate, jwtOnly],
      schema: {
        body: {
          type: 'object',
          required: ['currentPassword', 'newPassword'],
          additionalProperties: false,
          properties: {
            currentPassword: { type: 'string', minLength: 1, maxLength: PASSWORD_MAX },
            newPassword: { type: 'string', minLength: PASSWORD_MIN, maxLength: PASSWORD_MAX },
          },
        },
      },
      config: { rateLimit: { max: 5, timeWindow: '1 minute' } },
    },
    async (req, reply) => {
      const u = db.prepare('SELECT password_hash FROM users WHERE id = ?').get(req.user.sub) as
        | { password_hash: string }
        | undefined;
      if (!u || !(await verify(u.password_hash, req.body.currentPassword))) {
        return reply.code(401).send({ error: 'Current password is incorrect' });
      }
      const passwordHash = await hashPassword(req.body.newPassword);
      db.transaction(() => {
        db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(passwordHash, req.user.sub);
        db.prepare('UPDATE refresh_tokens SET revoked = 1 WHERE user_id = ?').run(req.user.sub);
      })();
      req.log.info({ userId: req.user.sub }, 'password changed');
      clearRefreshCookie(reply);
      return reply.code(204).send();
    },
  );

  // ---------- API keys (for uploading from your other servers) ----------

  app.post<{ Body: { name: string } }>(
    '/api-keys',
    {
      onRequest: [app.authenticate, jwtOnly, app.requireRole('uploader', 'admin')],
      schema: {
        body: {
          type: 'object',
          required: ['name'],
          additionalProperties: false,
          properties: { name: { type: 'string', minLength: 1, maxLength: 64 } },
        },
      },
      config: { rateLimit: { max: 10, timeWindow: '1 minute' } },
    },
    async (req, reply) => {
      const active = db
        .prepare('SELECT COUNT(*) AS n FROM api_keys WHERE user_id = ? AND revoked = 0')
        .get(req.user.sub) as { n: number };
      if (active.n >= 10) return reply.code(409).send({ error: 'Too many active API keys' });

      const id = crypto.randomUUID();
      const key = `cdn_${crypto.randomBytes(32).toString('base64url')}`;
      db.prepare(
        'INSERT INTO api_keys (id, user_id, key_hash, prefix, name, created_at) VALUES (?, ?, ?, ?, ?, ?)',
      ).run(id, req.user.sub, sha256(key), key.slice(0, 10), req.body.name, Date.now());
      req.log.info({ userId: req.user.sub, keyId: id }, 'api key created');
      // The raw key is shown exactly once; only its hash is stored
      return reply.code(201).send({ id, name: req.body.name, key });
    },
  );

  app.get('/api-keys', { onRequest: [app.authenticate, jwtOnly] }, async (req) => {
    const rows = db
      .prepare(
        'SELECT id, name, prefix, created_at, last_used_at FROM api_keys WHERE user_id = ? AND revoked = 0 ORDER BY created_at DESC',
      )
      .all(req.user.sub) as any[];
    return {
      data: rows.map((r) => ({
        id: r.id,
        name: r.name,
        prefix: r.prefix,
        createdAt: new Date(r.created_at).toISOString(),
        lastUsedAt: r.last_used_at ? new Date(r.last_used_at).toISOString() : null,
      })),
    };
  });

  app.delete<{ Params: { id: string } }>(
    '/api-keys/:id',
    {
      onRequest: [app.authenticate, jwtOnly],
      schema: {
        params: {
          type: 'object',
          required: ['id'],
          additionalProperties: false,
          properties: { id: { type: 'string', format: 'uuid' } },
        },
      },
    },
    async (req, reply) => {
      const r = db
        .prepare('UPDATE api_keys SET revoked = 1 WHERE id = ? AND user_id = ? AND revoked = 0')
        .run(req.params.id, req.user.sub);
      if (r.changes === 0) return reply.code(404).send({ error: 'Not Found' });
      return reply.code(204).send();
    },
  );
}
