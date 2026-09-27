# Secure CDN API

A file upload API that returns CDN-ready URLs. Built with Fastify, TypeScript, and SQLite.
Authorized users upload a file and the API immediately returns a public URL that can be
embedded on any website.

```
Other websites  ──GET──►  CDN (Cloudflare/Bunny)  ──cache miss──►  this API  /f/<id>.png
Server/admin    ──POST /files (API key / login)──►  this API  ──►  { "url": "https://cdn.../f/<id>.png" }
```

## Quick start

Requires **Node.js 20.6+ or 22+** (tested on 20.20 and 24.21). `better-sqlite3` is a native module, so run
`npm ci` again after switching Node versions.

```bash
npm install
cp .env.example .env                   # set JWT_SECRET (openssl rand -hex 32) and PUBLIC_BASE_URL
npm run seed:admin -- you@example.com  # first admin; a random password is printed ONCE
npm run dev
```

`seed:admin` is safe to run repeatedly: if an admin already exists, it does nothing. To choose the
password yourself: `ADMIN_PASSWORD='...' npm run seed:admin -- you@example.com`. After logging in,
change the password with `POST /auth/change-password`.

Run the security test suite with `npm test`.

## Admin console

Open **`/admin/`** (e.g. http://localhost:3000/admin/) and log in. From there you can:

- **Browse folders** and files, play audio, and copy public links.
- **Upload** files or whole folders (button or drag & drop). A dropped folder keeps its structure:
  dropping `ar/` into `lessons/` creates `lessons/ar/...`. File names with unsupported characters
  are cleaned up automatically (`My Song.mp3` -> `My-Song.mp3`). Tick *Replace files that already exist* to overwrite.
- **Create a folder**: open *New folder*, then upload into it. Folders are virtual and exist only while they contain files.
- **Rename/move** files, and (admins) rename/move or delete whole folders.
- **Manage users** (admins): add users, set their role and folders, reset passwords, unlock, delete.
- Manage your **API keys** and change your password.

Uploaders see only their own files and can only upload into their granted folders. The console is
plain HTML/JS in `admin-ui/`, served under a strict CSP (`script-src 'self'`, no inline code).
The access token is kept in memory only; the session survives a reload through the HttpOnly refresh cookie.

## Usage

**1. Log in** to get an access token (valid for 15 minutes):
```bash
curl -X POST http://localhost:3000/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"you@example.com","password":"..."}'
```

**2. Create an API key** for automated uploads from other servers/websites. The key is shown only once, so store it right away:
```bash
curl -X POST http://localhost:3000/auth/api-keys \
  -H "Authorization: Bearer <accessToken>" \
  -H 'content-type: application/json' -d '{"name":"blog-server"}'
```

**3. Upload a file:**
```bash
curl -X POST http://localhost:3000/files -H "X-API-Key: cdn_xxx" -F "file=@photo.jpg"
```
Response:
```json
{
  "id": "e15fbb5f-...",
  "url": "https://cdn.example.com/f/e15fbb5f-....jpg",
  "mime": "image/jpeg",
  "size": 48213,
  "sha256": "..."
}
```

**4. Use the URL anywhere:** `<img src="https://cdn.example.com/f/e15fbb5f-....jpg">`

## Folders / virtual paths (like audiolang.cc)

Besides random `/f/<uuid>.mp3` URLs, a file can have a **virtual path**, so an existing folder layout keeps its URLs:

```
upload to folder "ar" with name "voice01001.mp3"  ->  https://cdn.example.com/ar/voice01001.mp3
```

On disk the file still has a random UUID name; the path is only a database key, so a URL can never
point to anything else on the server (such as `.env` or the database).

```bash
# name taken from the uploaded file
curl -X POST "http://localhost:3000/files?folder=ar" -H "X-API-Key: cdn_xxx" -F "file=@voice01001.mp3"
# explicit name, replacing the file if it already exists
curl -X POST "http://localhost:3000/files?folder=ar&name=voice01001.mp3&overwrite=true" \
  -H "X-API-Key: cdn_xxx" -F "file=@new-recording.mp3"
# list a folder
curl "http://localhost:3000/files?folder=ar" -H "Authorization: Bearer <token>"
```

Rules:
- Folder and file names may only contain `A-Z a-z 0-9 . _ -`, must not start with a dot, must not contain `..`,
  and may be at most 10 levels deep. The folders `auth`, `files`, `f`, `admin`, and `health` are reserved for the API.
- The file name's extension must match the actual content (an MP3 must be named `.mp3`).
- An existing path is rejected (409) unless `overwrite=true`, and only the file's owner or an admin may overwrite it.
- **Uploaders may only upload to folders an admin has granted them** (including subfolders). Without a folder
  grant, an uploader can only upload to `/f/<uuid>`. Admins may upload anywhere and have no quota.
- Virtual-path files are cached for `PATH_CACHE_SECONDS` (default 1 day) rather than `immutable`, because they
  can be overwritten. After overwriting a file, purge the CDN cache for that URL.

### Managing folders via the API

```bash
# what is inside a folder (subfolders + files)
curl "http://localhost:3000/files/browse?folder=ar" -H "Authorization: Bearer <token>"
# rename/move one file (the target folder must be writable for you; the extension must stay the same)
curl -X PATCH http://localhost:3000/files/<id> -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' -d '{"path":"ar_old/voice01001.mp3"}'
# admin: rename/move a whole folder (folder grants of users follow along)
curl -X POST http://localhost:3000/admin/folders/move -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' -d '{"from":"ar_old","to":"archive/ar"}'
# admin: delete a folder and everything in it
curl -X DELETE "http://localhost:3000/admin/folders?folder=archive" -H "Authorization: Bearer <token>"
```

A folder move is all-or-nothing: if any destination path is already taken, nothing moves (409).
Moved or deleted files lose their old URLs, so purge those from your CDN cache.

### Importing an existing folder

```bash
npm run import -- ~/Downloads/audiolang.cc --owner you@example.com --dry-run   # preview first
npm run import -- ~/Downloads/audiolang.cc --owner you@example.com
```

`ar/voice01001.mp3` becomes `${PUBLIC_BASE_URL}/ar/voice01001.mp3`, and `ar_old/0001.mp3` becomes
`${PUBLIC_BASE_URL}/ar_old/0001.mp3`. Dot folders (`.well-known`) are skipped, and files of a disallowed
type (`.php`, `.html`) are reported and skipped. Options: `--into <folder>` to place everything under another
folder, `--overwrite` to replace paths that already exist.

### Public file index (replaces index.php)

With `PUBLIC_INDEX=true`, every folder has a page anyone can open: `/`, `/ar/`, `/ar_old/`.
It offers search, an audio player, download buttons, and copyable embed code (direct link + `<audio>` tag).

- `/ar` redirects to `/ar/`, and old `index.php?path=ar` links redirect (301) to `/ar/`.
- The page only reads the file list from the database and cannot change anything. All text is escaped,
  and the page runs under a nonce-based CSP (no `unsafe-inline`).
- Only virtual-path files are shown; `/f/<uuid>` files are never listed.
- The root page title is set with `PUBLIC_INDEX_TITLE`. Set `PUBLIC_INDEX=false` (the default) to turn it off.

## Managing users (admin)

All `/admin/*` endpoints require the `admin` role **with a real login** (API keys are rejected).

```bash
# add an uploader who may only upload to the ar and ar_old folders
curl -X POST http://localhost:3000/admin/users -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' \
  -d '{"email":"editor@example.com","password":"at-least-12-characters","role":"uploader","folders":["ar","ar_old"]}'

# change role / folder grants / reset password / unlock the account
curl -X PATCH http://localhost:3000/admin/users/<id> -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' -d '{"folders":["ar"],"unlock":true}'
```

The last admin cannot be demoted or deleted, and admins cannot delete themselves.
Resetting a password revokes all of that user's sessions. Deleting a user also deletes their files.

### Endpoints

| Method | Path | Access | Purpose |
|---|---|---|---|
| POST | `/auth/login` | public | Log in, get an access token + refresh cookie |
| POST | `/auth/refresh` | cookie | New access token (refresh token is rotated) |
| POST | `/auth/logout` | cookie | Log out this session |
| POST | `/auth/logout-all` | login | Log out of all devices |
| POST | `/auth/change-password` | login (not API key) | Change own password; all sessions are revoked |
| GET | `/auth/me` | login | User info (including folder grants) |
| POST/GET | `/auth/api-keys` | login (not API key) | Create / list API keys |
| DELETE | `/auth/api-keys/:id` | login (not API key) | Revoke an API key |
| POST | `/files[?folder=&name=&overwrite=]` | uploader | Upload a file and get its URL |
| GET | `/files[?folder=]` | login | List own files (admin: all) + quota usage |
| GET | `/files/browse[?folder=]` | login | Subfolders + files of one folder (admin: all users) |
| GET | `/files/:id` | login | Metadata of an own file (admin: any) |
| PATCH | `/files/:id` | uploader | Rename/move a file to another path |
| DELETE | `/files/:id` | uploader | Delete a file (its URL stops working) |
| GET/POST | `/admin/users` | admin | List / add users |
| PATCH/DELETE | `/admin/users/:id` | admin | Change role, folders, password, unlock / delete a user |
| POST | `/admin/folders/move` | admin | Rename/move a folder with all its files |
| DELETE | `/admin/folders?folder=` | admin | Delete a folder with all its files |
| GET | `/admin/` | public page (login inside) | Admin console |
| GET | `/f/:name` | **public** | File for other websites (cached for 1 year) |
| GET | `/<folder>/<name>` | **public** | Virtual-path file, e.g. `/ar/voice01001.mp3` |
| GET | `/`, `/<folder>/` | **public** (if `PUBLIC_INDEX=true`) | File index page |

Roles: `viewer` (read only), `uploader`, `admin`. From the CLI: `npm run user:create -- email role`
and `npm run user:role -- email role`.

## Security layers

**Uploads**
- File type is detected from the **content (magic bytes)**, not from the name or the client-sent Content-Type.
- Only JPEG, PNG, WebP, GIF, AVIF, PDF, MP4, MP3, WAV, and OGG are accepted. **SVG and HTML are rejected** because they can carry JavaScript (stored XSS).
- Files are stored on disk under random (UUID) names, so URLs cannot be guessed. The original name is kept only as metadata.
- There is a per-file size limit and a per-user quota. Uploads are streamed to a temporary file, so memory use stays flat.
- Public routes only accept strictly validated names (`<uuid>.<ext>` or whitelisted virtual-path segments), and virtual paths are only database keys, so path traversal (`../`) is impossible.
- Public files are served with `nosniff` and a `sandbox` CSP. Even if a malicious file slipped through, the browser would not execute it.

**Authentication & access**
- Passwords are hashed with Argon2id (OWASP parameters). API keys and refresh tokens are stored as hashes, never in raw form.
- Short-lived JWTs with the algorithm pinned to HS256 (rejects `alg: none`); issuer and audience are verified.
- Refresh tokens are rotated. If an old token is reused (a sign of theft), the entire session is revoked.
- The refresh cookie uses `HttpOnly`, `Secure`, `SameSite=Strict`, and `Path=/auth`.
- Per-IP rate limits (login 5/minute) and account lockout after 5 failed attempts. Login errors are identical so emails cannot be enumerated.
- Public registration is **off** by default. Only admins create users.
- Non-admin queries are scoped by `user_id`, so users cannot access or delete other people's files (BOLA/IDOR).
- Uploaders can only write to folders an admin has granted them.
- An API key cannot be used to create other API keys or manage users (prevents escalation).

**General**
- All input is validated with JSON Schema, and unknown fields are rejected.
- All SQL queries use parameters (prepared statements).
- Security headers from Helmet: HSTS, strict CSP, and `frame-ancestors 'none'`.
- Stack traces are never sent to clients. Logs automatically redact the `Authorization` header, cookies, and API keys.
- Docker runs as non-root with a read-only filesystem, all capabilities dropped, and the port bound to localhost only.

## Deploying to production

1. **Always use HTTPS.** Put a reverse proxy (Nginx/Caddy) or Cloudflare in front of the API, then set `TRUST_PROXY=true`.
2. **Put a CDN** on the `PUBLIC_BASE_URL` domain (e.g. `cdn.example.com`) pointing at this API. The `Cache-Control: immutable` header lets the CDN keep `/f/` files for a year, so the origin is rarely hit.
3. After deleting or overwriting a file, **purge the CDN cache** for that URL. Otherwise the old file can still be served from cache.
4. Run `docker compose up -d --build`, then create the first admin inside the container:
   ```bash
   docker compose exec api node dist/scripts/seed-admin.js you@example.com
   ```
   To import an existing folder, mount it read-only into the container and run
   `node dist/scripts/import-dir.js /import --owner you@example.com`.
5. **Back up** the `/data` volume, which holds the SQLite database and the files.
6. Run `npm audit` regularly and enable Dependabot.

### SQLite limits
SQLite is a good fit for a single server. If you later need several servers, move the metadata to PostgreSQL and the files to object storage (S3/R2). The code already keeps them separate, so the migration is straightforward.

### Suggested next steps
- **Strip EXIF metadata** (GPS location in photos) with `sharp` before storing files.
- **Antivirus scanning** (ClamAV) for PDFs.
- **Signed URLs** if some files must not be public.
- **2FA (TOTP)** for admin accounts.
