/**
 * Imports an existing folder tree, keeping its structure as public virtual paths.
 *
 *   npm run import -- <sourceDir> --owner <email> [--into <folder>] [--overwrite] [--dry-run]
 *
 * Example: npm run import -- ~/Downloads/audiolang.cc --owner admin@domain.com
 *   audiolang.cc/ar/voice01001.mp3  ->  ${PUBLIC_BASE_URL}/ar/voice01001.mp3
 *
 * Every file goes through the same checks as an API upload (type detected from content, strict
 * path rules). Dotfiles/dotfolders are skipped; files of a type that isn't allowed (.php, .html)
 * are reported and skipped.
 */
import crypto from 'node:crypto';
import fs from 'node:fs';
import fsp from 'node:fs/promises';
import path from 'node:path';
import { pipeline } from 'node:stream/promises';
import { openDb } from '../src/db.js';
import { config } from '../src/config.js';
import type { Role } from '../src/app.js';
import { buildVirtualPath, commitFile, detectType, normalizeFolder } from '../src/storage.js';

const args = process.argv.slice(2);
const flag = (name: string) => args.includes(`--${name}`);
const option = (name: string) => {
  const i = args.indexOf(`--${name}`);
  return i >= 0 ? args[i + 1] : undefined;
};
const source = args[0];
const ownerEmail = option('owner')?.trim().toLowerCase();
if (!source || source.startsWith('--') || !ownerEmail) {
  console.error('Usage: npm run import -- <sourceDir> --owner <email> [--into <folder>] [--overwrite] [--dry-run]');
  process.exit(1);
}
const root = path.resolve(source);
const into = normalizeFolder(option('into') ?? '');
const overwrite = flag('overwrite');
const dryRun = flag('dry-run');

const db = openDb(config.dbPath);
const owner = db.prepare('SELECT id, role FROM users WHERE email = ?').get(ownerEmail) as
  | { id: string; role: Role }
  | undefined;
if (!owner) {
  console.error(`User not found: ${ownerEmail}`);
  process.exit(1);
}

const storageDir = path.resolve(config.storageDir);
const tmpDir = path.join(storageDir, '.tmp');
await fsp.mkdir(tmpDir, { recursive: true, mode: 0o700 });

async function* walk(dir: string): AsyncGenerator<string> {
  const entries = await fsp.readdir(dir, { withFileTypes: true });
  entries.sort((a, b) => a.name.localeCompare(b.name, undefined, { numeric: true }));
  for (const e of entries) {
    if (e.name.startsWith('.')) continue; // .well-known, .DS_Store, ...
    const full = path.join(dir, e.name);
    if (e.isDirectory()) yield* walk(full);
    else if (e.isFile()) yield full; // symlinks are ignored on purpose
  }
}

const stats = { imported: 0, skipped: 0, failed: 0 };
for await (const file of walk(root)) {
  const rel = path.relative(root, file).split(path.sep).join('/');
  const id = crypto.randomUUID();
  const tmpPath = path.join(tmpDir, `${id}.upload`);
  try {
    const detected = await detectType(file);
    if (!detected) {
      console.log(`skip  ${rel} (type not allowed)`);
      stats.skipped++;
      continue;
    }
    const relDir = path.posix.dirname(rel);
    const folder = normalizeFolder([into, relDir === '.' ? '' : relDir].filter(Boolean).join('/'));
    const vpath = buildVirtualPath(folder, path.basename(file), detected.ext);
    if (dryRun) {
      console.log(`would ${rel} -> ${config.publicBaseUrl}/${vpath}`);
      stats.imported++;
      continue;
    }

    const hasher = crypto.createHash('sha256');
    await pipeline(
      fs.createReadStream(file),
      async function* (src) {
        for await (const chunk of src) {
          hasher.update(chunk);
          yield chunk;
        }
      },
      fs.createWriteStream(tmpPath, { mode: 0o600 }),
    );
    const { size } = await fsp.stat(tmpPath);
    await commitFile(
      db,
      storageDir,
      tmpPath,
      {
        id,
        user_id: owner.id,
        stored_name: `${id}.${detected.ext}`,
        original_name: path.basename(file),
        mime: detected.mime,
        size,
        sha256: hasher.digest('hex'),
        created_at: Date.now(),
        vpath,
      },
      { overwrite, actorRole: owner.role, quotaBytes: null },
    );
    console.log(`ok    ${rel} -> ${config.publicBaseUrl}/${vpath}`);
    stats.imported++;
  } catch (err: any) {
    await fsp.rm(tmpPath, { force: true });
    console.log(`fail  ${rel}: ${err?.message ?? err}`);
    stats.failed++;
  }
}
db.close();

console.log(`\n${dryRun ? 'Dry run: ' : ''}${stats.imported} imported, ${stats.skipped} skipped, ${stats.failed} failed`);
process.exit(stats.failed ? 1 : 0);
