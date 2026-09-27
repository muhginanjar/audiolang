import { FastifyInstance } from 'fastify';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Serves the admin console (admin-ui/) at /admin/. The page itself is public (it shows a login
 * form); every action goes through the authenticated API. Files are read once at startup and served
 * from fixed routes, so no request path ever reaches the filesystem.
 */

// admin-ui/ sits at the project root: two levels up from src/routes, three from dist/src/routes
const here = path.dirname(fileURLToPath(import.meta.url));
const UI_DIR = [path.resolve(here, '../../admin-ui'), path.resolve(here, '../../../admin-ui')].find((d) =>
  fs.existsSync(path.join(d, 'index.html')),
);

const ASSETS = {
  'index.html': 'text/html; charset=utf-8',
  'app.js': 'text/javascript; charset=utf-8',
  'app.css': 'text/css; charset=utf-8',
} as const;

// No inline code at all: scripts and styles only from this origin, API calls only to this origin
const CSP = [
  "default-src 'none'",
  "script-src 'self'",
  "style-src 'self'",
  "connect-src 'self'",
  "img-src 'self' data:",
  "media-src 'self'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join('; ');

export async function adminUiRoutes(app: FastifyInstance) {
  if (!UI_DIR) throw new Error('admin-ui/ folder not found next to the app');
  const files = Object.fromEntries(
    Object.keys(ASSETS).map((name) => [name, fs.readFileSync(path.join(UI_DIR, name))]),
  ) as Record<keyof typeof ASSETS, Buffer>;

  const serve = (name: keyof typeof ASSETS) => async (_req: unknown, reply: any) =>
    reply
      .type(ASSETS[name])
      .header('Content-Security-Policy', CSP)
      // HTML is never cached; assets revalidate so a deploy is picked up right away
      .header('Cache-Control', name === 'index.html' ? 'no-store' : 'no-cache')
      .header('X-Robots-Tag', 'noindex, nofollow')
      .send(files[name]);

  app.get('/admin', async (_req, reply) => reply.redirect('/admin/', 301));
  app.get('/admin/', serve('index.html'));
  app.get('/admin/app.js', serve('app.js'));
  app.get('/admin/app.css', serve('app.css'));
}
