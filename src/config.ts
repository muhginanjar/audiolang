import 'dotenv/config';

function required(name: string): string {
  const v = process.env[name];
  if (!v) throw new Error(`Missing required env var: ${name}`);
  return v;
}

const env = process.env.NODE_ENV ?? 'development';

export const config = {
  env,
  isProd: env === 'production',
  port: Number(process.env.PORT ?? 3000),
  host: process.env.HOST ?? '0.0.0.0',
  dbPath: process.env.DB_PATH ?? './data/app.db',
  jwtSecret: required('JWT_SECRET'),
  jwtIssuer: process.env.JWT_ISSUER ?? 'secure-api',
  jwtAudience: process.env.JWT_AUDIENCE ?? 'secure-api-clients',
  accessTokenTtl: process.env.ACCESS_TOKEN_TTL ?? '15m',
  refreshTokenDays: Number(process.env.REFRESH_TOKEN_DAYS ?? 7),
  corsOrigins: (process.env.CORS_ORIGINS ?? '')
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean),
  trustProxy: process.env.TRUST_PROXY === 'true',
  maxLoginAttempts: Number(process.env.MAX_LOGIN_ATTEMPTS ?? 5),
  lockoutMinutes: Number(process.env.LOCKOUT_MINUTES ?? 15),
  // Public registration is off by default: uploaders are created by an admin (npm run user:create)
  allowRegistration: process.env.ALLOW_REGISTRATION === 'true',
  // CDN / upload settings
  storageDir: process.env.STORAGE_DIR ?? './data/files',
  // Base URL used in generated links, e.g. https://cdn.example.com (your CDN domain in front of this API)
  publicBaseUrl: (process.env.PUBLIC_BASE_URL ?? 'http://localhost:3000').replace(/\/+$/, ''),
  maxFileBytes: Number(process.env.MAX_FILE_MB ?? 10) * 1024 * 1024,
  userQuotaBytes: Number(process.env.USER_QUOTA_MB ?? 1024) * 1024 * 1024,
  // Browser/CDN cache for virtual-path files (/ar/x.mp3), which can be overwritten in place
  pathCacheSeconds: Number(process.env.PATH_CACHE_SECONDS ?? 86400),
  // Public folder index pages (/, /ar/, ...) listing every virtual-path file. Off unless enabled.
  publicIndex: process.env.PUBLIC_INDEX === 'true',
  publicIndexTitle: process.env.PUBLIC_INDEX_TITLE ?? 'File Library',
};

if (config.jwtSecret.length < 32) {
  throw new Error('JWT_SECRET must be at least 32 characters');
}
if (config.isProd && config.corsOrigins.length === 0) {
  throw new Error('CORS_ORIGINS must be set in production');
}
