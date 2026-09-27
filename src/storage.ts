import fsp from 'node:fs/promises';
import path from 'node:path';
import { fileTypeFromFile } from 'file-type';
import type { DB } from './db.js';
import type { Role } from './app.js';

/**
 * Allowed types, detected from the file's actual bytes (magic numbers),
 * NOT from the filename or the client-sent Content-Type (both are attacker-controlled).
 * SVG, HTML, XML and scripts are deliberately excluded: they can carry JavaScript (stored XSS).
 */
export const ALLOWED: Record<string, string> = {
  'image/jpeg': 'jpg',
  'image/png': 'png',
  'image/webp': 'webp',
  'image/gif': 'gif',
  'image/avif': 'avif',
  'application/pdf': 'pdf',
  'video/mp4': 'mp4',
  'audio/mpeg': 'mp3',
  'audio/wav': 'wav',
  'audio/ogg': 'ogg',
};
// Extra spellings a caller may use in a virtual file name for the same detected type
const EXT_ALIASES: Record<string, string[]> = { jpg: ['jpeg'] };

const EXT_PATTERN = Object.values(ALLOWED).join('|');
export const STORED_NAME_RE = new RegExp(`^[0-9a-f-]{36}\\.(${EXT_PATTERN})$`);

/**
 * Virtual paths (e.g. "ar/voice01001.mp3") are only keys in the DB; files on disk keep random
 * UUID names, so a virtual path can never reach the filesystem. Still, every segment is
 * whitelisted: no dotfiles, no "..", no spaces or encoded tricks.
 */
const SEGMENT_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const MAX_DEPTH = 10;
const MAX_PATH_LEN = 512;
// First segments that would shadow API routes
export const RESERVED_ROOTS = new Set(['auth', 'files', 'f', 'admin', 'health']);

export class StorageError extends Error {
  constructor(public statusCode: number, message: string) {
    super(message);
  }
}

function validSegment(s: string) {
  return SEGMENT_RE.test(s) && !s.includes('..');
}

/** Normalizes "/ar//sub/" -> "ar/sub". Empty string means the root. Throws on anything unsafe. */
export function normalizeFolder(input: string): string {
  const parts = input.split('/').filter(Boolean);
  if (parts.length > MAX_DEPTH - 1) throw new StorageError(400, 'Folder is nested too deep');
  for (const p of parts) {
    if (!validSegment(p)) throw new StorageError(400, `Invalid folder name: ${p}`);
  }
  if (parts.length && RESERVED_ROOTS.has(parts[0].toLowerCase())) {
    throw new StorageError(400, `Folder "${parts[0]}" is reserved`);
  }
  return parts.join('/');
}

/** Full check of a virtual path as it arrives on the public route. Returns null if invalid. */
export function parseVirtualPath(p: string): string | null {
  if (!p || p.length > MAX_PATH_LEN) return null;
  const parts = p.split('/');
  if (parts.length > MAX_DEPTH) return null;
  if (!parts.every(validSegment)) return null;
  if (RESERVED_ROOTS.has(parts[0].toLowerCase())) return null;
  return p;
}

/** A user may write to a folder if they are admin or it is inside one of their granted folders. */
export function canWriteFolder(role: Role, grants: string[], folder: string): boolean {
  if (role === 'admin') return true;
  if (role !== 'uploader' || !folder) return false;
  return grants.some((g) => folder === g || folder.startsWith(g + '/'));
}

export async function detectType(file: string) {
  const detected = await fileTypeFromFile(file);
  const ext = detected ? ALLOWED[detected.mime] : undefined;
  return detected && ext ? { mime: detected.mime, ext } : null;
}

/** Builds the virtual path; the name's extension must match the type detected from content. */
export function buildVirtualPath(folder: string, name: string, detectedExt: string): string {
  if (!validSegment(name)) throw new StorageError(400, 'Invalid file name');
  const ext = path.extname(name).slice(1).toLowerCase();
  const accepted = [detectedExt, ...(EXT_ALIASES[detectedExt] ?? [])];
  if (!accepted.includes(ext)) {
    throw new StorageError(400, `File name extension must be .${detectedExt} for this content`);
  }
  const vpath = folder ? `${folder}/${name}` : name;
  if (!parseVirtualPath(vpath)) throw new StorageError(400, 'Invalid path');
  return vpath;
}

export interface FileRow {
  id: string;
  user_id: string;
  stored_name: string;
  original_name: string;
  mime: string;
  size: number;
  sha256: string;
  created_at: number;
  vpath: string | null;
}

export interface CommitOptions {
  overwrite: boolean;
  actorRole: Role;
  quotaBytes: number | null; // null = no quota (admins, CLI import)
}

/**
 * Moves a verified temp file into storage and records it. The file is moved first (to a fresh
 * UUID name, so nothing is ever clobbered), then the DB is updated atomically; on any failure the
 * new file is removed again. A replaced file's old bytes are deleted only after the DB commit.
 */
export async function commitFile(
  db: DB,
  storageDir: string,
  tmpPath: string,
  row: FileRow,
  opts: CommitOptions,
): Promise<FileRow> {
  const finalPath = path.join(storageDir, row.stored_name);
  await fsp.rename(tmpPath, finalPath);

  let replaced: FileRow | undefined;
  try {
    db.transaction(() => {
      replaced = row.vpath
        ? (db.prepare('SELECT * FROM files WHERE vpath = ?').get(row.vpath) as FileRow | undefined)
        : undefined;
      if (replaced) {
        if (!opts.overwrite) throw new StorageError(409, 'A file already exists at this path');
        if (replaced.user_id !== row.user_id && opts.actorRole !== 'admin') {
          throw new StorageError(403, 'This path belongs to another user');
        }
      }
      if (opts.quotaBytes !== null) {
        const used = db
          .prepare('SELECT COALESCE(SUM(size), 0) AS used FROM files WHERE user_id = ?')
          .get(row.user_id) as { used: number };
        const freed = replaced && replaced.user_id === row.user_id ? replaced.size : 0;
        if (used.used - freed + row.size > opts.quotaBytes) {
          throw new StorageError(413, 'Storage quota exceeded');
        }
      }
      if (replaced) db.prepare('DELETE FROM files WHERE id = ?').run(replaced.id);
      db.prepare(
        `INSERT INTO files (id, user_id, stored_name, original_name, mime, size, sha256, created_at, vpath)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).run(row.id, row.user_id, row.stored_name, row.original_name, row.mime, row.size, row.sha256, row.created_at, row.vpath);
    })();
  } catch (err) {
    await fsp.rm(finalPath, { force: true });
    throw err;
  }

  if (replaced) await fsp.rm(path.join(storageDir, replaced.stored_name), { force: true });
  return row;
}

export function getActor(db: DB, userId: string) {
  const u = db.prepare('SELECT role, folders FROM users WHERE id = ?').get(userId) as
    | { role: Role; folders: string }
    | undefined;
  if (!u) return undefined;
  return { role: u.role, folders: JSON.parse(u.folders) as string[] };
}
