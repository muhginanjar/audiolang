import Fastify, { FastifyReply, FastifyRequest } from 'fastify';
import helmet from '@fastify/helmet';
import cors from '@fastify/cors';
import cookie from '@fastify/cookie';
import jwt from '@fastify/jwt';
import rateLimit from '@fastify/rate-limit';
import crypto from 'node:crypto';
import { config } from './config.js';
import { openDb, DB } from './db.js';
import { authRoutes } from './routes/auth.js';
import { fileRoutes, publicFileRoutes } from './routes/files.js';
import { adminRoutes } from './routes/admin.js';
import { adminUiRoutes } from './routes/admin-ui.js';

export type Role = 'viewer' | 'uploader' | 'admin';

declare module 'fastify' {
  interface FastifyInstance {
    db: DB;
    authenticate: (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
    requireRole: (...roles: Role[]) => (req: FastifyRequest, reply: FastifyReply) => Promise<void>;
  }
  interface FastifyRequest {
    authVia?: 'jwt' | 'api-key';
  }
}
declare module '@fastify/jwt' {
  interface FastifyJWT {
    payload: { sub: string; typ: 'access' };
    user: { sub: string; typ: 'access' };
  }
}

export interface BuildOptions {
  dbPath?: string;
  storageDir?: string;
  logger?: boolean;
}

export const sha256 = (s: string) => crypto.createHash('sha256').update(s).digest('hex');

export async function buildApp(opts: BuildOptions = {}) {
  const app = Fastify({
    logger:
      opts.logger === false
        ? false
        : {
            level: config.isProd ? 'info' : 'debug',
            // Never log credentials or tokens
            redact: {
              paths: [
                'req.headers.authorization',
                'req.headers.cookie',
                'req.headers["x-api-key"]',
                'res.headers["set-cookie"]',
              ],
              censor: '[REDACTED]',
            },
          },
    bodyLimit: 16 * 1024, // JSON bodies; uploads have their own limit (multipart)
    trustProxy: config.trustProxy,
    ajv: {
      customOptions: {
        removeAdditional: false, // reject unknown fields instead of silently stripping
        coerceTypes: false,
        allErrors: false,
      },
    },
  });

  app.decorate('db', openDb(opts.dbPath ?? config.dbPath));
  app.addHook('onClose', async () => app.db.close());

  await app.register(helmet, {
    contentSecurityPolicy: {
      useDefaults: false, // start from nothing; an API needs no scripts/styles at all
      directives: {
        defaultSrc: ["'none'"],
        frameAncestors: ["'none'"],
        sandbox: [], // even if a malicious file slips through, it can't run scripts
      },
    },
    hsts: { maxAge: 31536000, includeSubDomains: true, preload: true },
    crossOriginResourcePolicy: { policy: 'same-origin' }, // relaxed only on public file route
  });

  // CORS for the management API (upload/list/delete). Public file GETs set their own headers.
  await app.register(cors, {
    origin: (origin, cb) => {
      if (!origin || config.corsOrigins.includes(origin)) return cb(null, true);
      cb(null, false);
    },
    credentials: true,
    methods: ['GET', 'POST', 'PATCH', 'DELETE'],
  });

  await app.register(cookie);

  await app.register(jwt, {
    secret: config.jwtSecret,
    sign: {
      algorithm: 'HS256',
      expiresIn: config.accessTokenTtl,
      iss: config.jwtIssuer,
      aud: config.jwtAudience,
    },
    verify: {
      algorithms: ['HS256'], // pin algorithm: blocks alg=none / confusion attacks
      allowedIss: config.jwtIssuer,
      allowedAud: config.jwtAudience,
    },
  });

  await app.register(rateLimit, { global: true, max: 100, timeWindow: '1 minute' });

  // Accepts either "Authorization: Bearer <jwt>" (humans / web dashboard)
  // or "X-API-Key: <key>" (server-to-server uploads from your other websites).
  app.decorate('authenticate', async (req: FastifyRequest, reply: FastifyReply) => {
    const apiKey = req.headers['x-api-key'];
    if (typeof apiKey === 'string' && apiKey.length > 0) {
      const row = app.db
        .prepare('SELECT id, user_id FROM api_keys WHERE key_hash = ? AND revoked = 0')
        .get(sha256(apiKey)) as { id: string; user_id: string } | undefined;
      if (!row) return reply.code(401).send({ error: 'Unauthorized' });
      app.db.prepare('UPDATE api_keys SET last_used_at = ? WHERE id = ?').run(Date.now(), row.id);
      req.user = { sub: row.user_id, typ: 'access' };
      req.authVia = 'api-key';
      return;
    }
    try {
      await req.jwtVerify();
      if (req.user.typ !== 'access') throw new Error('wrong token type');
      req.authVia = 'jwt';
    } catch {
      return reply.code(401).send({ error: 'Unauthorized' });
    }
  });

  // Role is read from the DB on every request, so demoting a user takes effect immediately
  app.decorate('requireRole', (...roles: Role[]) => async (req: FastifyRequest, reply: FastifyReply) => {
    const u = app.db.prepare('SELECT role FROM users WHERE id = ?').get(req.user.sub) as
      | { role: Role }
      | undefined;
    if (!u || !roles.includes(u.role)) return reply.code(403).send({ error: 'Forbidden' });
  });

  // API responses are never cached, unless a route set its own policy (public files do)
  app.addHook('onSend', async (_req, reply, payload) => {
    if (!reply.hasHeader('Cache-Control')) reply.header('Cache-Control', 'no-store');
    return payload;
  });

  // Generic errors: never leak stack traces or internals
  app.setErrorHandler((err: any, req, reply) => {
    if (err.validation) {
      return reply.code(400).send({ error: 'Invalid request', details: err.message });
    }
    const status = err.statusCode ?? 500;
    if (status >= 500) {
      req.log.error({ err }, 'unhandled error');
      return reply.code(500).send({ error: 'Internal Server Error' });
    }
    return reply.code(status).send({ error: err.message });
  });

  app.setNotFoundHandler((_req, reply) => reply.code(404).send({ error: 'Not Found' }));

  app.get('/health', { config: { rateLimit: false } }, async () => ({ status: 'ok' }));

  const storageDir = opts.storageDir ?? config.storageDir;
  await app.register(authRoutes, { prefix: '/auth' });
  await app.register(fileRoutes, { prefix: '/files', storageDir });
  await app.register(adminRoutes, { prefix: '/admin', storageDir });
  await app.register(adminUiRoutes); // the /admin/ console page (public shell; all actions use the API)
  // Serves /f/<uuid>.<ext> and virtual paths like /ar/voice01001.mp3 (must stay last: it has a catch-all)
  await app.register(publicFileRoutes, { storageDir });

  return app;
}
