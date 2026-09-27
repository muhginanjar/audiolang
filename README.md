# Secure CDN API

API upload file dengan URL CDN otomatis. Dibuat dengan Fastify, TypeScript, dan SQLite.
User yang berwenang meng-upload file, lalu API langsung mengembalikan URL publik yang bisa
dipasang di website mana pun.

```
Website lain  ──GET──►  CDN (Cloudflare/Bunny)  ──cache miss──►  API ini  /f/<id>.png
Server/admin  ──POST /files (API key / login)──►  API ini  ──►  { "url": "https://cdn.../f/<id>.png" }
```

## Mulai cepat

```bash
npm install
cp .env.example .env               # isi JWT_SECRET (openssl rand -hex 32) dan PUBLIC_BASE_URL
npm run seed:admin -- kamu@email.com   # admin pertama; password acak ditampilkan SEKALI
npm run dev
```

`seed:admin` aman dijalankan berulang: jika sudah ada admin, tidak melakukan apa-apa. Untuk memakai
password sendiri: `ADMIN_PASSWORD='...' npm run seed:admin -- kamu@email.com`. Setelah login, ganti
password lewat `POST /auth/change-password`.

Jalankan test keamanan dengan `npm test`.

## Cara pakai

**1. Login** untuk mendapatkan access token (berlaku 15 menit):
```bash
curl -X POST http://localhost:3000/auth/login \
  -H 'content-type: application/json' \
  -d '{"email":"kamu@email.com","password":"..."}'
```

**2. Buat API key** untuk upload otomatis dari server/website lain. Key ini hanya ditampilkan sekali, jadi langsung simpan:
```bash
curl -X POST http://localhost:3000/auth/api-keys \
  -H "Authorization: Bearer <accessToken>" \
  -H 'content-type: application/json' -d '{"name":"server-blog"}'
```

**3. Upload file:**
```bash
curl -X POST http://localhost:3000/files -H "X-API-Key: cdn_xxx" -F "file=@foto.jpg"
```
Respons:
```json
{
  "id": "e15fbb5f-...",
  "url": "https://cdn.domainkamu.com/f/e15fbb5f-....jpg",
  "mime": "image/jpeg",
  "size": 48213,
  "sha256": "..."
}
```

**4. Pakai URL-nya di mana saja:** `<img src="https://cdn.domainkamu.com/f/e15fbb5f-....jpg">`

## Folder / path virtual (seperti audiolang.cc)

Selain URL acak `/f/<uuid>.mp3`, file bisa punya **path virtual** sehingga susunan folder lama tetap sama:

```
upload ke folder "ar" dengan nama "voice01001.mp3"  ->  https://cdn.domainkamu.com/ar/voice01001.mp3
```

Di disk file tetap bernama UUID acak; path hanya kunci di database, jadi URL tidak mungkin menunjuk
ke file lain di server (misalnya `.env` atau database).

```bash
# nama diambil dari file yang di-upload
curl -X POST "http://localhost:3000/files?folder=ar" -H "X-API-Key: cdn_xxx" -F "file=@voice01001.mp3"
# nama ditentukan sendiri, dan timpa jika sudah ada
curl -X POST "http://localhost:3000/files?folder=ar&name=voice01001.mp3&overwrite=true" \
  -H "X-API-Key: cdn_xxx" -F "file=@rekaman-baru.mp3"
# lihat isi folder
curl "http://localhost:3000/files?folder=ar" -H "Authorization: Bearer <token>"
```

Aturan:
- Nama folder/file hanya boleh `A-Z a-z 0-9 . _ -`, tidak boleh diawali titik, tidak boleh `..`, maks. 10 level.
  Folder `auth`, `files`, `f`, `admin`, `health` dicadangkan untuk API.
- Ekstensi nama file harus sesuai isi file sebenarnya (MP3 harus `.mp3`).
- Path yang sudah ada ditolak (409) kecuali `overwrite=true`, dan hanya pemilik file atau admin yang boleh menimpa.
- **Uploader hanya boleh upload ke folder yang diizinkan admin** (termasuk subfoldernya). Tanpa izin folder,
  uploader hanya bisa upload ke `/f/<uuid>`. Admin boleh upload ke mana saja dan tidak terkena kuota.
- File ber-path di-cache `PATH_CACHE_SECONDS` (default 1 hari), bukan `immutable`, karena bisa ditimpa.
  Setelah menimpa file, purge cache CDN untuk URL tersebut.

### Import folder yang sudah ada

```bash
npm run import -- ~/Downloads/audiolang.cc --owner kamu@email.com --dry-run   # cek dulu
npm run import -- ~/Downloads/audiolang.cc --owner kamu@email.com
```

`ar/voice01001.mp3` menjadi `${PUBLIC_BASE_URL}/ar/voice01001.mp3`, `ar_old/0001.mp3` menjadi
`${PUBLIC_BASE_URL}/ar_old/0001.mp3`. Folder bertitik (`.well-known`) dilewati, dan file yang tipenya
tidak diizinkan (`.php`, `.html`) dilaporkan lalu dilewati. Opsi: `--into <folder>` untuk menaruh di
bawah folder lain, `--overwrite` untuk menimpa path yang sudah ada.

### Halaman daftar file publik (pengganti index.php)

Dengan `PUBLIC_INDEX=true`, setiap folder punya halaman yang bisa dibuka siapa saja: `/`, `/ar/`, `/ar_old/`.
Isinya pencarian, pemutar audio, tombol download, dan kode embed (link langsung + tag `<audio>`) yang bisa disalin.

- `/ar` diarahkan ke `/ar/`, dan link lama `index.php?path=ar` diarahkan (301) ke `/ar/`.
- Halaman ini hanya membaca daftar file dari database dan tidak bisa mengubah apa pun. Semua teks di-escape,
  dan halaman berjalan dengan CSP ber-nonce (tanpa `unsafe-inline`).
- Yang tampil hanya file ber-path virtual; file `/f/<uuid>` tidak pernah ikut terdaftar.
- Judul halaman root diatur lewat `PUBLIC_INDEX_TITLE`. Set `PUBLIC_INDEX=false` (default) untuk mematikannya.

## Kelola user (admin)

Semua endpoint `/admin/*` hanya untuk role `admin` **dengan login** (API key ditolak).

```bash
# tambah uploader yang hanya boleh upload ke folder ar dan ar_old
curl -X POST http://localhost:3000/admin/users -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' \
  -d '{"email":"editor@email.com","password":"minimal-12-karakter","role":"uploader","folders":["ar","ar_old"]}'

# ubah role / izin folder / reset password / buka kunci akun
curl -X PATCH http://localhost:3000/admin/users/<id> -H "Authorization: Bearer <token>" \
  -H 'content-type: application/json' -d '{"folders":["ar"],"unlock":true}'
```

Admin terakhir tidak bisa diturunkan atau dihapus, dan admin tidak bisa menghapus dirinya sendiri.
Reset password mencabut semua sesi user tersebut. Menghapus user juga menghapus file-filenya.

### Endpoint

| Method | Path | Akses | Fungsi |
|---|---|---|---|
| POST | `/auth/login` | publik | Login, mendapat access token + refresh cookie |
| POST | `/auth/refresh` | cookie | Access token baru (refresh token dirotasi) |
| POST | `/auth/logout` | cookie | Logout sesi ini |
| POST | `/auth/logout-all` | login | Logout dari semua perangkat |
| POST | `/auth/change-password` | login (bukan API key) | Ganti password sendiri, semua sesi dicabut |
| GET | `/auth/me` | login | Info user (termasuk izin folder) |
| POST/GET | `/auth/api-keys` | login (bukan API key) | Buat / lihat API key |
| DELETE | `/auth/api-keys/:id` | login (bukan API key) | Cabut API key |
| POST | `/files[?folder=&name=&overwrite=]` | uploader | Upload file dan mendapat URL |
| GET | `/files[?folder=]` | login | Daftar file milik sendiri (admin: semua) + pemakaian kuota |
| GET | `/files/:id` | login | Metadata file milik sendiri (admin: semua) |
| DELETE | `/files/:id` | uploader | Hapus file (URL berhenti berfungsi) |
| GET/POST | `/admin/users` | admin | Daftar / tambah user |
| PATCH/DELETE | `/admin/users/:id` | admin | Ubah role, folder, password, unlock / hapus user |
| GET | `/f/:nama` | **publik** | File untuk website lain (dengan cache 1 tahun) |
| GET | `/<folder>/<nama>` | **publik** | File ber-path virtual, mis. `/ar/voice01001.mp3` |
| GET | `/`, `/<folder>/` | **publik** (jika `PUBLIC_INDEX=true`) | Halaman daftar file |

Role: `viewer` (hanya lihat), `uploader`, `admin`. Dari CLI: `npm run user:create -- email role`
dan `npm run user:role -- email role`.

## Lapisan keamanan

**Upload**
- Tipe file dicek dari **isi file (magic bytes)**, bukan dari nama atau Content-Type kiriman klien.
- Hanya JPEG, PNG, WebP, GIF, AVIF, PDF, MP4, MP3, WAV, dan OGG yang diterima. **SVG dan HTML ditolak** karena bisa membawa JavaScript (stored XSS).
- Nama file di disk diacak (UUID), sehingga URL tidak bisa ditebak. Nama asli hanya disimpan sebagai metadata.
- Ada batas ukuran per file dan kuota per user. Upload berjalan sebagai stream ke file sementara, jadi RAM tidak jebol.
- Route publik hanya menerima nama dengan format ketat `<uuid>.<ext>`, sehingga path traversal (`../`) tidak mungkin.
- File publik dikirim dengan `nosniff` dan CSP `sandbox`. Walaupun ada file berbahaya yang lolos, browser tidak akan menjalankannya.

**Autentikasi & akses**
- Password di-hash dengan Argon2id (parameter OWASP). API key dan refresh token disimpan dalam bentuk hash, bukan mentah.
- JWT berumur pendek dengan algoritma dikunci ke HS256 (menolak `alg: none`), serta issuer dan audience diverifikasi.
- Refresh token dirotasi. Jika token lama dipakai ulang (tanda dicuri), seluruh sesi tersebut dicabut.
- Refresh cookie memakai `HttpOnly`, `Secure`, `SameSite=Strict`, dan `Path=/auth`.
- Rate limit per IP (login 5/menit) dan lockout akun setelah 5 kali gagal. Pesan error login dibuat sama agar email tidak bisa ditebak.
- Registrasi publik **mati** secara default. Hanya admin yang membuat user.
- Setiap query dibatasi `user_id`, sehingga user tidak bisa mengakses atau menghapus file orang lain (BOLA/IDOR).
- API key tidak bisa dipakai untuk membuat API key lain (mencegah eskalasi).

**Umum**
- Semua input divalidasi dengan JSON Schema, dan field yang tidak dikenal ditolak.
- Semua query SQL memakai parameter (prepared statement).
- Security headers dari Helmet: HSTS, CSP ketat, dan frame-ancestors none.
- Stack trace tidak pernah dikirim ke klien. Log otomatis menyensor header `Authorization`, cookie, dan API key.
- Docker berjalan sebagai non-root dengan filesystem read-only, semua capability di-drop, dan port hanya dibuka ke localhost.

## Deploy ke production

1. **Selalu pakai HTTPS.** Pasang reverse proxy (Nginx/Caddy) atau langsung Cloudflare di depan API, lalu set `TRUST_PROXY=true`.
2. **Pasang CDN** dengan domain `PUBLIC_BASE_URL` (misalnya `cdn.domainkamu.com`) yang mengarah ke API ini. Header `Cache-Control: immutable` membuat CDN menyimpan file selama setahun, sehingga server asal jarang tersentuh.
3. Setelah menghapus file, **purge cache CDN** untuk URL tersebut. Kalau tidak, file masih bisa diakses dari cache.
4. Jalankan `docker compose up -d --build`, lalu buat admin pertama di dalam container:
   ```bash
   docker compose exec api node dist/scripts/seed-admin.js kamu@email.com
   ```
   Untuk import folder lama, mount foldernya read-only ke container lalu jalankan
   `node dist/scripts/import-dir.js /import --owner kamu@email.com`.
5. **Backup** volume `/data`, yang berisi database SQLite dan file.
6. Jalankan `npm audit` secara rutin dan aktifkan Dependabot.

### Batasan SQLite
SQLite cocok untuk satu server. Kalau nanti butuh beberapa server sekaligus, pindahkan metadata ke PostgreSQL dan file ke object storage (S3/R2). Strukturnya sudah dipisah sehingga migrasinya tidak sulit.

### Pengembangan lanjutan yang disarankan
- **Hapus metadata EXIF** (lokasi GPS di foto) dengan `sharp` sebelum file disimpan.
- **Scan antivirus** (ClamAV) untuk PDF.
- **Signed URL** jika sebagian file tidak boleh publik.
- **2FA (TOTP)** untuk akun admin.
