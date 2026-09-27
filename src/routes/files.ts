import { FastifyInstance, FastifyReply } from 'fastify';
import multipart from '@fastify/multipart';
import fastifyStatic from '@fastify/static';
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { Transform } from 'node:stream';
import { config } from '../config.js';
import {
  ALLOWED,
  STORED_NAME_RE,
  FileRow,
  IN_FOLDER_SQL,
  StorageError,
  buildVirtualPath,
  canWriteFolder,
  commitFile,
  detectType,
  getActor,
  inFolderArg,
  normalizeFolder,
  parseVirtualPath,
} from '../storage.js';
import { buildListing, renderListing } from './listing.js';

const publicUrl = (f: Pick<FileRow, 'stored_name' | 'vpath'>) =>
  f.vpath ? `${config.publicBaseUrl}/${f.vpath}` : `${config.publicBaseUrl}/f/${f.stored_name}`;

const toDto = (f: FileRow) => ({
  id: f.id,
  url: publicUrl(f),
  path: f.vpath,
  originalName: f.original_name,
  mime: f.mime,
  size: f.size,
  sha256: f.sha256,
  createdAt: new Date(f.created_at).toISOString(),
});

function sanitizeName(name: string | undefined): string {
  const base = path.basename(name ?? 'file');
  // strip control chars and anything path/HTML-ish; keep it short
  const clean = base.replace(/[\u0000-\u001f\u007f<>:"/\\|?*]/g, '_').slice(0, 200);
  return clean || 'file';
}

const idParams = {
  type: 'object',
  required: ['id'],
  additionalProperties: false,
  properties: { id: { type: 'string', format: 'uuid' } },
} as const;

// ---------------- Management API (authenticated) ----------------
export async function fileRoutes(app: FastifyInstance, opts: { storageDir: string }) {
  const db = app.db;
  const storageDir = path.resolve(opts.storageDir);
  const tmpDir = path.join(storageDir, '.tmp');
  await fsp.mkdir(tmpDir, { recursive: true, mode: 0o700 });

  await app.register(multipart, {
    limits: {
      fileSize: config.maxFileBytes,
      files: 1,
      fields: 0,
      parts: 1,
      headerPairs: 50,
    },
  });

  app.addHook('onRequest', app.authenticate);

  // Admins manage every file; everyone else only sees their own (no BOLA/IDOR)
  const findFile = (id: string, userId: string) => {
    const admin = getActor(db, userId)?.role === 'admin';
    return (
      admin
        ? db.prepare('SELECT * FROM files WHERE id = ?').get(id)
        : db.prepare('SELECT * FROM files WHERE id = ? AND user_id = ?').get(id, userId)
    ) as FileRow | undefined;
  };

  /**
   * Upload -> returns the public URL.
   *   POST /files                              -> https://cdn/f/<uuid>.mp3
   *   POST /files?folder=ar                    -> https://cdn/ar/<uploaded file name>
   *   POST /files?folder=ar&name=voice01.mp3   -> https://cdn/ar/voice01.mp3
   *   add &overwrite=true to replace an existing file at that path
   */
  app.post<{ Querystring: { folder?: string; name?: string; overwrite?: 'true' | 'false' } }>(
    '/',
    {
      onRequest: [app.requireRole('uploader', 'admin')],
      schema: {
        querystring: {
          type: 'object',
          additionalProperties: false,
          properties: {
            folder: { type: 'string', maxLength: 400 },
            name: { type: 'string', minLength: 1, maxLength: 100 },
            overwrite: { type: 'string', enum: ['true', 'false'] },
          },
        },
      },
      config: { rateLimit: { max: 30, timeWindow: '1 minute' } },
    },
    async (req, reply) => {
      if (!req.isMultipart()) {
        return reply.code(415).send({ error: 'Expected multipart/form-data' });
      }
      const actor = getActor(db, req.user.sub)!;
      const virtual = req.query.folder !== undefined || req.query.name !== undefined;
      const folder = normalizeFolder(req.query.folder ?? '');
      // Checked before reading the body, so unauthorized uploads never touch the disk
      if (virtual && !canWriteFolder(actor.role, actor.folders, folder)) {
        req.log.warn({ userId: req.user.sub, folder }, 'upload to forbidden folder');
        return reply.code(403).send({ error: 'You may not upload to this folder' });
      }

      let part;
      try {
        part = await req.file();
      } catch {
        return reply.code(400).send({ error: 'Invalid upload' });
      }
      if (!part) return reply.code(400).send({ error: 'No file provided' });

      const id = crypto.randomUUID();
      const tmpPath = path.join(tmpDir, `${id}.upload`);
      const hasher = crypto.createHash('sha256');
      let size = 0;

      const counter = new Transform({
        transform(chunk, _enc, cb) {
          size += chunk.length;
          hasher.update(chunk);
          cb(null, chunk);
        },
      });

      const cleanup = () => fsp.rm(tmpPath, { force: true });

      try {
        await pipeline(part.file, counter, fs.createWriteStream(tmpPath, { mode: 0o600 }));
      } catch (err) {
        await cleanup();
        if ((err as any)?.code === 'FST_REQ_FILE_TOO_LARGE') {
          return reply.code(413).send({ error: 'File too large' });
        }
        throw err;
      }

      if (part.file.truncated) {
        await cleanup();
        return reply.code(413).send({ error: 'File too large' });
      }
      if (size === 0) {
        await cleanup();
        return reply.code(400).send({ error: 'Empty file' });
      }

      const detected = await detectType(tmpPath);
      if (!detected) {
        await cleanup();
        req.log.warn({ userId: req.user.sub }, 'rejected upload type');
        return reply.code(415).send({
          error: 'Unsupported file type',
          allowed: Object.keys(ALLOWED),
        });
      }

      const originalName = sanitizeName(part.filename);
      let row: FileRow;
      try {
        row = await commitFile(
          db,
          storageDir,
          tmpPath,
          {
            id,
            user_id: req.user.sub,
            stored_name: `${id}.${detected.ext}`,
            original_name: originalName,
            mime: detected.mime,
            size,
            sha256: hasher.digest('hex'),
            created_at: Date.now(),
            vpath: virtual
              ? buildVirtualPath(folder, req.query.name ?? originalName, detected.ext)
              : null,
          },
          {
            overwrite: req.query.overwrite === 'true',
            actorRole: actor.role,
            quotaBytes: actor.role === 'admin' ? null : config.userQuotaBytes,
          },
        );
      } catch (err) {
        await cleanup();
        throw err;
      }

      req.log.info({ userId: req.user.sub, fileId: id, size, mime: row.mime, path: row.vpath }, 'file uploaded');
      return reply.code(201).send(toDto(row));
    },
  );

  // List files (paginated). Optional ?folder=ar lists that folder and its subfolders.
  app.get<{ Querystring: { limit?: string; offset?: string; folder?: string } }>(
    '/',
    {
      schema: {
        querystring: {
          type: 'object',
          additionalProperties: false,
          properties: {
            limit: { type: 'string', pattern: '^[0-9]{1,3}$' },
            offset: { type: 'string', pattern: '^[0-9]{1,6}$' },
            folder: { type: 'string', maxLength: 400 },
          },
        },
      },
    },
    async (req) => {
      const limit = Math.min(Math.max(Number(req.query.limit ?? 20), 1), 100);
      const offset = Number(req.query.offset ?? 0);
      const admin = getActor(db, req.user.sub)?.role === 'admin';
      const where: string[] = [];
      const args: unknown[] = [];
      if (!admin) {
        where.push('user_id = ?');
        args.push(req.user.sub);
      }
      if (req.query.folder !== undefined) {
        const folder = normalizeFolder(req.query.folder);
        where.push(folder ? IN_FOLDER_SQL : 'vpath IS NOT NULL');
        if (folder) args.push(inFolderArg(folder));
      }
      const clause = where.length ? `WHERE ${where.join(' AND ')}` : '';
      const rows = db
        .prepare(`SELECT * FROM files ${clause} ORDER BY vpath, created_at DESC LIMIT ? OFFSET ?`)
        .all(...args, limit, offset) as FileRow[];
      const total = db.prepare(`SELECT COUNT(*) AS n FROM files ${clause}`).get(...args) as { n: number };
      const usage = db
        .prepare('SELECT COALESCE(SUM(size), 0) AS used FROM files WHERE user_id = ?')
        .get(req.user.sub) as { used: number };
      return {
        data: rows.map(toDto),
        total: total.n,
        limit,
        offset,
        usage: { usedBytes: usage.used, quotaBytes: admin ? null : config.userQuotaBytes },
      };
    },
  );

  // One folder of the virtual tree: its subfolders and the files directly inside it.
  // Admins see every file; others only their own (same scoping as GET /files).
  app.get<{ Querystring: { folder?: string } }>(
    '/browse',
    {
      schema: {
        querystring: {
          type: 'object',
          additionalProperties: false,
          properties: { folder: { type: 'string', maxLength: 400 } },
        },
      },
    },
    async (req) => {
      const actor = getActor(db, req.user.sub)!;
      const admin = actor.role === 'admin';
      const folder = normalizeFolder(req.query.folder ?? '');
      const where = [folder ? IN_FOLDER_SQL.replace('vpath', 'f.vpath') : 'f.vpath IS NOT NULL'];
      const args: unknown[] = folder ? [inFolderArg(folder)] : [];
      if (!admin) {
        where.push('f.user_id = ?');
        args.push(req.user.sub);
      }
      const rows = db
        .prepare(`SELECT f.*, u.email AS owner FROM files f JOIN users u ON u.id = f.user_id WHERE ${where.join(' AND ')}`)
        .all(...args) as (FileRow & { owner: string; vpath: string })[];

      const prefix = folder ? `${folder}/` : '';
      const folders = new Map<string, { name: string; files: number; size: number }>();
      const files: ReturnType<typeof toDto>[] = [];
      for (const r of rows) {
        const rest = r.vpath.slice(prefix.length);
        const slash = rest.indexOf('/');
        if (slash === -1) {
          files.push({ ...toDto(r), ...(admin && { owner: r.owner }) });
          continue;
        }
        const name = rest.slice(0, slash);
        const f = folders.get(name) ?? { name, files: 0, size: 0 };
        f.files++;
        f.size += r.size;
        folders.set(name, f);
      }
      const byName = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' }).compare;
      return {
        folder,
        writable: canWriteFolder(actor.role, actor.folders, folder),
        folders: [...folders.values()].sort((a, b) => byName(a.name, b.name)),
        files: files.sort((a, b) => byName(a.path!, b.path!)),
      };
    },
  );

  // Rename or move one file to another virtual path. The target folder needs write access.
  app.patch<{ Params: { id: string }; Body: { path: string } }>(
    '/:id',
    {
      onRequest: [app.requireRole('uploader', 'admin')],
      schema: {
        params: idParams,
        body: {
          type: 'object',
          required: ['path'],
          additionalProperties: false,
          properties: { path: { type: 'string', minLength: 1, maxLength: 512 } },
        },
      },
    },
    async (req, reply) => {
      const row = findFile(req.params.id, req.user.sub);
      if (!row) return reply.code(404).send({ error: 'Not Found' });
      const actor = getActor(db, req.user.sub)!;
      const target = req.body.path.replace(/^\/+/, '');
      const slash = target.lastIndexOf('/');
      const folder = normalizeFolder(slash === -1 ? '' : target.slice(0, slash));
      if (!canWriteFolder(actor.role, actor.folders, folder)) {
        return reply.code(403).send({ error: 'You may not move files to this folder' });
      }
      // The stored name's extension is the type detected at upload time
      const vpath = buildVirtualPath(folder, target.slice(slash + 1), path.extname(row.stored_name).slice(1));
      if (vpath !== row.vpath) {
        try {
          db.prepare('UPDATE files SET vpath = ? WHERE id = ?').run(vpath, row.id);
        } catch (e: any) {
          if (e?.code === 'SQLITE_CONSTRAINT_UNIQUE') {
            return reply.code(409).send({ error: 'A file already exists at this path' });
          }
          throw e;
        }
        req.log.info({ userId: req.user.sub, fileId: row.id, from: row.vpath, to: vpath }, 'file moved');
      }
      return toDto({ ...row, vpath });
    },
  );

  // Get metadata of one file
  app.get<{ Params: { id: string } }>('/:id', { schema: { params: idParams } }, async (req, reply) => {
    const row = findFile(req.params.id, req.user.sub);
    if (!row) return reply.code(404).send({ error: 'Not Found' });
    return toDto(row);
  });

  // Delete a file: the public URL stops working (purge your CDN cache too)
  app.delete<{ Params: { id: string } }>(
    '/:id',
    { onRequest: [app.requireRole('uploader', 'admin')], schema: { params: idParams } },
    async (req, reply) => {
      const row = findFile(req.params.id, req.user.sub);
      if (!row) return reply.code(404).send({ error: 'Not Found' });
      db.prepare('DELETE FROM files WHERE id = ?').run(row.id);
      await fsp.rm(path.join(storageDir, row.stored_name), { force: true });
      req.log.info({ userId: req.user.sub, fileId: row.id, path: row.vpath }, 'file deleted');
      return reply.code(204).send();
    },
  );
}

// ---------------- Public file serving (the CDN origin) ----------------
export async function publicFileRoutes(app: FastifyInstance, opts: { storageDir: string }) {
  const db = app.db;
  const storageDir = path.resolve(opts.storageDir);

  await app.register(fastifyStatic, {
    root: storageDir,
    serve: false, // only serve through the validated routes below
    dotfiles: 'deny',
    index: false,
    cacheControl: false, // we set our own
    acceptRanges: true, // audio/video seeking / resumable downloads
  });

  const send = (
    reply: FastifyReply,
    row: { stored_name: string; mime: string; original_name: string },
    downloadName: string,
    cacheControl: string,
  ) => {
    if (!STORED_NAME_RE.test(row.stored_name)) return reply.code(404).send({ error: 'Not Found' });
    // Public files are anonymous: never pair "*" with credentials
    reply.removeHeader('access-control-allow-credentials');
    reply
      .header('Content-Type', row.mime)
      .header('X-Content-Type-Options', 'nosniff')
      // Allow other websites to embed/fetch these files
      .header('Cross-Origin-Resource-Policy', 'cross-origin')
      .header('Access-Control-Allow-Origin', '*')
      .header('Cache-Control', cacheControl)
      .header('Content-Disposition', `inline; filename*=UTF-8''${encodeURIComponent(downloadName)}`);
    return reply.sendFile(row.stored_name);
  };

  // The CDN in front absorbs most traffic; this only limits origin hammering
  const rateLimit = { max: 1000, timeWindow: '1 minute' };

  app.get<{ Params: { name: string } }>(
    '/f/:name',
    {
      schema: {
        params: {
          type: 'object',
          required: ['name'],
          additionalProperties: false,
          properties: { name: { type: 'string', maxLength: 64 } },
        },
      },
      config: { rateLimit },
    },
    async (req, reply) => {
      const { name } = req.params;
      // Strict whitelist of the name format: blocks path traversal (../), dotfiles, etc.
      if (!STORED_NAME_RE.test(name)) return reply.code(404).send({ error: 'Not Found' });

      const row = db
        .prepare('SELECT stored_name, mime, original_name FROM files WHERE stored_name = ?')
        .get(name) as { stored_name: string; mime: string; original_name: string } | undefined;
      if (!row) return reply.code(404).send({ error: 'Not Found' });
      // File names are unique per upload and never change -> cache forever at the CDN and browser
      return send(reply, row, row.original_name, 'public, max-age=31536000, immutable');
    },
  );

  // Virtual paths, e.g. /ar/voice01001.mp3. The path is only a DB lookup key; the bytes are read
  // from the random stored name, so the URL can never address anything else on disk.
  const notFound = (reply: FastifyReply) => reply.code(404).send({ error: 'Not Found' });
  const isFolder = (folder: string) =>
    !!db.prepare(`SELECT 1 FROM files WHERE ${IN_FOLDER_SQL} LIMIT 1`).get(inFolderArg(folder));

  const sendIndex = (reply: FastifyReply, folder: string) => {
    const listing = buildListing(db, folder);
    if (!listing) return notFound(reply);
    const nonce = crypto.randomBytes(16).toString('base64');
    reply
      .header(
        'Content-Security-Policy',
        `default-src 'none'; style-src 'nonce-${nonce}'; script-src 'nonce-${nonce}'; media-src 'self'; ` +
          "img-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
      )
      .header('Cache-Control', 'public, max-age=60')
      .type('text/html; charset=utf-8');
    return renderListing(listing, { baseUrl: config.publicBaseUrl, title: config.publicIndexTitle, nonce });
  };

  app.get<{ Params: { '*': string }; Querystring: { path?: unknown } }>('/*', { config: { rateLimit } }, async (req, reply) => {
    const raw = req.params['*'];

    if (config.publicIndex) {
      // Folder pages: "/" and "/ar/"
      if (raw === '') return sendIndex(reply, '');
      if (raw.endsWith('/')) {
        const folder = parseVirtualPath(raw.slice(0, -1));
        return folder ? sendIndex(reply, folder) : notFound(reply);
      }
      // Old links: /index.php?path=ar -> /ar/
      if (raw === 'index.php') {
        const p = typeof req.query.path === 'string' ? req.query.path.replace(/^\/+|\/+$/g, '') : '';
        if (p && !parseVirtualPath(p)) return notFound(reply);
        return reply.redirect(p ? `/${p}/` : '/', 301);
      }
    }

    const vpath = parseVirtualPath(raw);
    if (!vpath) return notFound(reply);
    const row = db
      .prepare('SELECT stored_name, mime, original_name FROM files WHERE vpath = ?')
      .get(vpath) as { stored_name: string; mime: string; original_name: string } | undefined;
    if (!row) {
      // "/ar" -> "/ar/"
      if (config.publicIndex && isFolder(vpath)) return reply.redirect(`/${vpath}/`, 301);
      return notFound(reply);
    }
    // Can be overwritten in place, so not immutable; ETag/Last-Modified allow cheap revalidation
    return send(reply, row, path.basename(vpath), `public, max-age=${config.pathCacheSeconds}`);
  });
}
