import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import crypto from 'node:crypto';
import { hash } from '@node-rs/argon2';

const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'cdn-test-'));
process.env.JWT_SECRET = crypto.randomBytes(48).toString('hex');
process.env.PUBLIC_BASE_URL = 'https://cdn.example.com';
process.env.MAX_FILE_MB = '1';
process.env.USER_QUOTA_MB = '2';
process.env.ALLOW_REGISTRATION = 'false';
process.env.PUBLIC_INDEX = 'true';

const { buildApp } = await import('../src/app.js');
type App = Awaited<ReturnType<typeof buildApp>>;
let app: App;

const PNG = Buffer.from(
  'iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mNkYPhfDwAChwGA60e6kgAAAABJRU5ErkJggg==',
  'base64',
);
const PASSWORD = 'correct horse battery staple';
let ipCounter = 1;
const ip = () => `10.0.${Math.floor(ipCounter / 250)}.${ipCounter++ % 250 + 1}`;

function multipart(filename: string, content: Buffer, contentType = 'image/png') {
  const boundary = '----test' + crypto.randomBytes(8).toString('hex');
  const body = Buffer.concat([
    Buffer.from(
      `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${filename}"\r\nContent-Type: ${contentType}\r\n\r\n`,
    ),
    content,
    Buffer.from(`\r\n--${boundary}--\r\n`),
  ]);
  return { payload: body, headers: { 'content-type': `multipart/form-data; boundary=${boundary}` } };
}

async function createUser(email: string, role: string) {
  const h = await hash(PASSWORD, { memoryCost: 19456, timeCost: 2, parallelism: 1 });
  app.db
    .prepare('INSERT INTO users (id, email, password_hash, role, created_at) VALUES (?, ?, ?, ?, ?)')
    .run(crypto.randomUUID(), email, h, role, Date.now());
}

async function login(email: string, password = PASSWORD) {
  return app.inject({
    method: 'POST',
    url: '/auth/login',
    remoteAddress: ip(),
    payload: { email, password },
  });
}

async function tokenFor(email: string) {
  const res = await login(email);
  assert.equal(res.statusCode, 200, res.body);
  return res.json().accessToken as string;
}

// ID3v2 header (empty tag) followed by an MPEG-1 Layer III frame header
const MP3 = Buffer.concat([
  Buffer.from([0x49, 0x44, 0x33, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]),
  Buffer.from([0xff, 0xfb, 0x90, 0x64]),
  Buffer.alloc(413),
]);

async function upload(token: string, filename: string, content: Buffer, ct?: string, query = '') {
  const mp = multipart(filename, content, ct);
  return app.inject({
    method: 'POST',
    url: `/files${query}`,
    remoteAddress: ip(),
    headers: { ...mp.headers, authorization: `Bearer ${token}` },
    payload: mp.payload,
  });
}

before(async () => {
  app = await buildApp({
    dbPath: path.join(tmp, 'test.db'),
    storageDir: path.join(tmp, 'files'),
    logger: false,
  });
  await createUser('alice@example.com', 'uploader');
  await createUser('bob@example.com', 'uploader');
  await createUser('viewer@example.com', 'viewer');
  await createUser('lock@example.com', 'uploader');
  await createUser('admin@example.com', 'admin');
  await createUser('carol@example.com', 'uploader');
  await createUser('dave@example.com', 'uploader');
});

function api(method: 'GET' | 'POST' | 'PATCH' | 'DELETE', url: string, token: string, payload?: object) {
  return app.inject({
    method,
    url,
    remoteAddress: ip(),
    headers: { authorization: `Bearer ${token}` },
    ...(payload && { payload }),
  });
}

const userId = (email: string) =>
  (app.db.prepare('SELECT id FROM users WHERE email = ?').get(email) as { id: string }).id;

after(async () => {
  await app.close();
  fs.rmSync(tmp, { recursive: true, force: true });
});

test('security headers are present', async () => {
  const res = await app.inject({ method: 'GET', url: '/health' });
  assert.equal(res.headers['x-content-type-options'], 'nosniff');
  assert.match(String(res.headers['strict-transport-security']), /max-age=31536000/);
  assert.match(String(res.headers['content-security-policy']), /default-src 'none'/);
  assert.equal(res.headers['cache-control'], 'no-store');
});

test('public registration is disabled by default', async () => {
  const res = await app.inject({
    method: 'POST',
    url: '/auth/register',
    remoteAddress: ip(),
    payload: { email: 'new@example.com', password: 'a-very-long-password' },
  });
  assert.equal(res.statusCode, 403);
});

test('login: wrong password and unknown email give the same generic 401', async () => {
  const a = await login('alice@example.com', 'wrong-password');
  const b = await login('nobody@example.com', 'wrong-password');
  assert.equal(a.statusCode, 401);
  assert.equal(b.statusCode, 401);
  assert.deepEqual(a.json(), b.json());
});

test('login sets a hardened refresh cookie', async () => {
  const res = await login('alice@example.com');
  assert.equal(res.statusCode, 200);
  assert.ok(res.json().accessToken);
  const cookie = String(res.headers['set-cookie']);
  assert.match(cookie, /HttpOnly/);
  assert.match(cookie, /SameSite=Strict/);
  assert.match(cookie, /Path=\/auth/);
});

test('JSON bodies with unknown fields are rejected', async () => {
  const res = await app.inject({
    method: 'POST',
    url: '/auth/login',
    remoteAddress: ip(),
    payload: { email: 'alice@example.com', password: PASSWORD, role: 'admin' },
  });
  assert.equal(res.statusCode, 400);
});

test('account locks after repeated failures (even with the right password)', async () => {
  for (let i = 0; i < 5; i++) await login('lock@example.com', 'wrong-password');
  const res = await login('lock@example.com');
  assert.equal(res.statusCode, 401);
});

test('login is rate-limited per IP', async () => {
  const addr = '192.0.2.77';
  let last = 0;
  for (let i = 0; i < 7; i++) {
    const r = await app.inject({
      method: 'POST',
      url: '/auth/login',
      remoteAddress: addr,
      payload: { email: 'x@example.com', password: 'nope' },
    });
    last = r.statusCode;
  }
  assert.equal(last, 429);
});

test('forged / unsigned JWTs are rejected', async () => {
  const b64 = (o: object) => Buffer.from(JSON.stringify(o)).toString('base64url');
  const none = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: 'x', typ: 'access' })}.`;
  const res = await app.inject({
    method: 'GET',
    url: '/auth/me',
    headers: { authorization: `Bearer ${none}` },
  });
  assert.equal(res.statusCode, 401);
});

test('upload returns a CDN URL; the file is publicly served with CDN-friendly headers', async () => {
  const token = await tokenFor('alice@example.com');
  const res = await upload(token, 'logo.png', PNG);
  assert.equal(res.statusCode, 201, res.body);
  const f = res.json();
  assert.match(f.url, /^https:\/\/cdn\.example\.com\/f\/[0-9a-f-]{36}\.png$/);
  assert.equal(f.mime, 'image/png');

  const pub = await app.inject({ method: 'GET', url: new URL(f.url).pathname });
  assert.equal(pub.statusCode, 200);
  assert.equal(pub.headers['content-type'], 'image/png');
  assert.equal(pub.headers['cross-origin-resource-policy'], 'cross-origin');
  assert.equal(pub.headers['access-control-allow-origin'], '*');
  assert.equal(pub.headers['access-control-allow-credentials'], undefined);
  assert.doesNotMatch(String(pub.headers['content-security-policy']), /script-src/);
  assert.match(String(pub.headers['cache-control']), /immutable/);
  assert.equal(pub.headers['x-content-type-options'], 'nosniff');
  assert.deepEqual(pub.rawPayload, PNG);
});

test('viewer role cannot upload', async () => {
  const token = await tokenFor('viewer@example.com');
  const res = await upload(token, 'logo.png', PNG);
  assert.equal(res.statusCode, 403);
});

test('unauthenticated upload is rejected', async () => {
  const mp = multipart('a.png', PNG);
  const res = await app.inject({ method: 'POST', url: '/files', headers: mp.headers, payload: mp.payload });
  assert.equal(res.statusCode, 401);
});

test('file type is checked by content: HTML/SVG disguised as .png is rejected', async () => {
  const token = await tokenFor('alice@example.com');
  const html = await upload(token, 'evil.png', Buffer.from('<html><script>alert(1)</script></html>'));
  assert.equal(html.statusCode, 415);
  const svg = await upload(
    token,
    'evil.svg',
    Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'),
    'image/svg+xml',
  );
  assert.equal(svg.statusCode, 415);
});

test('files over the size limit are rejected', async () => {
  const token = await tokenFor('alice@example.com');
  const big = Buffer.concat([PNG, Buffer.alloc(1.5 * 1024 * 1024)]);
  const res = await upload(token, 'big.png', big);
  assert.equal(res.statusCode, 413);
});

test('per-user quota is enforced', async () => {
  const token = await tokenFor('bob@example.com');
  const chunk = Buffer.concat([PNG, Buffer.alloc(900 * 1024)]); // ~0.9 MB each, quota 2 MB
  assert.equal((await upload(token, 'a.png', chunk)).statusCode, 201);
  assert.equal((await upload(token, 'b.png', chunk)).statusCode, 201);
  assert.equal((await upload(token, 'c.png', chunk)).statusCode, 413);
});

test("a user cannot see or delete someone else's file (BOLA)", async () => {
  const alice = await tokenFor('alice@example.com');
  const bob = await tokenFor('bob@example.com');
  const f = (await upload(alice, 'mine.png', PNG)).json();

  const get = await app.inject({
    method: 'GET',
    url: `/files/${f.id}`,
    headers: { authorization: `Bearer ${bob}` },
  });
  assert.equal(get.statusCode, 404);

  const del = await app.inject({
    method: 'DELETE',
    url: `/files/${f.id}`,
    headers: { authorization: `Bearer ${bob}` },
  });
  assert.equal(del.statusCode, 404);

  const own = await app.inject({
    method: 'DELETE',
    url: `/files/${f.id}`,
    headers: { authorization: `Bearer ${alice}` },
  });
  assert.equal(own.statusCode, 204);
  const gone = await app.inject({ method: 'GET', url: new URL(f.url).pathname });
  assert.equal(gone.statusCode, 404);
});

test('path traversal on the public route is blocked', async () => {
  for (const url of ['/f/..%2Ftest.db', '/f/%2e%2e%2f%2e%2e%2fetc%2fpasswd', '/f/.tmp', '/f/test.db']) {
    const res = await app.inject({ method: 'GET', url });
    assert.equal(res.statusCode, 404, url);
  }
});

test('refresh token rotation + reuse detection revokes the session', async () => {
  const res = await login('alice@example.com');
  const rt1 = res.cookies.find((c) => c.name === 'rt')!.value;

  const r1 = await app.inject({ method: 'POST', url: '/auth/refresh', cookies: { rt: rt1 } });
  assert.equal(r1.statusCode, 200);
  const rt2 = r1.cookies.find((c) => c.name === 'rt')!.value;
  assert.notEqual(rt1, rt2);

  // Attacker replays the old token -> whole family revoked
  const replay = await app.inject({ method: 'POST', url: '/auth/refresh', cookies: { rt: rt1 } });
  assert.equal(replay.statusCode, 401);
  const legit = await app.inject({ method: 'POST', url: '/auth/refresh', cookies: { rt: rt2 } });
  assert.equal(legit.statusCode, 401);
});

test('API key can upload but cannot manage API keys; revoked key stops working', async () => {
  const token = await tokenFor('alice@example.com');
  const created = await app.inject({
    method: 'POST',
    url: '/auth/api-keys',
    headers: { authorization: `Bearer ${token}` },
    payload: { name: 'blog-server' },
  });
  assert.equal(created.statusCode, 201);
  const { id, key } = created.json();

  const mp = multipart('k.png', PNG);
  const up = await app.inject({
    method: 'POST',
    url: '/files',
    headers: { ...mp.headers, 'x-api-key': key },
    payload: mp.payload,
  });
  assert.equal(up.statusCode, 201);

  const escalate = await app.inject({
    method: 'POST',
    url: '/auth/api-keys',
    headers: { 'x-api-key': key },
    payload: { name: 'another' },
  });
  assert.equal(escalate.statusCode, 403);

  const stored = app.db.prepare('SELECT key_hash FROM api_keys WHERE id = ?').get(id) as any;
  assert.notEqual(stored.key_hash, key, 'raw key must not be stored');

  await app.inject({
    method: 'DELETE',
    url: `/auth/api-keys/${id}`,
    headers: { authorization: `Bearer ${token}` },
  });
  const mp2 = multipart('k2.png', PNG);
  const after = await app.inject({
    method: 'POST',
    url: '/files',
    headers: { ...mp2.headers, 'x-api-key': key },
    payload: mp2.payload,
  });
  assert.equal(after.statusCode, 401);
});

test('passwords are stored as Argon2id hashes', () => {
  const row = app.db.prepare("SELECT password_hash FROM users WHERE email = 'alice@example.com'").get() as any;
  assert.match(row.password_hash, /^\$argon2id\$/);
});

// ---------------- Virtual paths (folder structure) ----------------

test('uploader cannot write to a folder until an admin grants it', async () => {
  const carol = await tokenFor('carol@example.com');
  const denied = await upload(carol, 'voice01.mp3', MP3, 'audio/mpeg', '?folder=ar');
  assert.equal(denied.statusCode, 403);

  const admin = await tokenFor('admin@example.com');
  const grant = await api('PATCH', `/admin/users/${userId('carol@example.com')}`, admin, { folders: ['ar'] });
  assert.equal(grant.statusCode, 200, grant.body);
  assert.deepEqual(grant.json().folders, ['ar']);

  const ok = await upload(carol, 'voice01.mp3', MP3, 'audio/mpeg', '?folder=ar');
  assert.equal(ok.statusCode, 201, ok.body);
  assert.equal(ok.json().url, 'https://cdn.example.com/ar/voice01.mp3');
  assert.equal(ok.json().path, 'ar/voice01.mp3');

  // grants cover subfolders but not siblings
  assert.equal((await upload(carol, 'x.mp3', MP3, 'audio/mpeg', '?folder=ar/sub')).statusCode, 201);
  assert.equal((await upload(carol, 'x.mp3', MP3, 'audio/mpeg', '?folder=ar_old')).statusCode, 403);
  assert.equal((await upload(carol, 'x.mp3', MP3, 'audio/mpeg', '?name=x.mp3')).statusCode, 403);
});

test('virtual path is served publicly with the detected type', async () => {
  const pub = await app.inject({ method: 'GET', url: '/ar/voice01.mp3' });
  assert.equal(pub.statusCode, 200);
  assert.equal(pub.headers['content-type'], 'audio/mpeg');
  assert.equal(pub.headers['access-control-allow-origin'], '*');
  assert.equal(pub.headers['x-content-type-options'], 'nosniff');
  assert.doesNotMatch(String(pub.headers['cache-control']), /immutable/);
  assert.deepEqual(pub.rawPayload, MP3);

  const range = await app.inject({ method: 'GET', url: '/ar/voice01.mp3', headers: { range: 'bytes=0-9' } });
  assert.equal(range.statusCode, 206);
  assert.equal(range.rawPayload.length, 10);
});

test('existing path needs overwrite=true, and only its owner or an admin may overwrite', async () => {
  const carol = await tokenFor('carol@example.com');
  const dup = await upload(carol, 'voice01.mp3', MP3, 'audio/mpeg', '?folder=ar');
  assert.equal(dup.statusCode, 409);

  const newer = Buffer.concat([MP3, Buffer.from('v2')]);
  const replaced = await upload(carol, 'voice01.mp3', newer, 'audio/mpeg', '?folder=ar&overwrite=true');
  assert.equal(replaced.statusCode, 201, replaced.body);
  const pub = await app.inject({ method: 'GET', url: '/ar/voice01.mp3' });
  assert.deepEqual(pub.rawPayload, newer);

  const admin = await tokenFor('admin@example.com');
  await api('PATCH', `/admin/users/${userId('dave@example.com')}`, admin, { folders: ['ar'] });
  const dave = await tokenFor('dave@example.com');
  const steal = await upload(dave, 'voice01.mp3', MP3, 'audio/mpeg', '?folder=ar&overwrite=true');
  assert.equal(steal.statusCode, 403);
  assert.deepEqual((await app.inject({ method: 'GET', url: '/ar/voice01.mp3' })).rawPayload, newer);
});

test('file name extension must match the real content', async () => {
  const admin = await tokenFor('admin@example.com');
  const res = await upload(admin, 'x', MP3, 'audio/mpeg', '?folder=ar&name=voice.png');
  assert.equal(res.statusCode, 400);
  const html = await upload(admin, 'x.mp3', Buffer.from('<html><script>alert(1)</script>'), 'audio/mpeg', '?folder=ar');
  assert.equal(html.statusCode, 415);
});

test('unsafe or reserved folder names are rejected', async () => {
  const admin = await tokenFor('admin@example.com');
  for (const folder of ['../etc', 'ar/../../x', '.well-known', 'auth', 'Files', 'f', 'a b', 'ar/.git']) {
    const res = await upload(admin, 'x.mp3', MP3, 'audio/mpeg', `?folder=${encodeURIComponent(folder)}`);
    assert.equal(res.statusCode, 400, folder);
  }
});

test('public virtual route cannot reach anything but registered paths', async () => {
  for (const url of [
    '/ar/..%2F..%2Fdata%2Fapp.db',
    '/ar/%2e%2e/%2e%2e/etc/passwd',
    '/.tmp/x',
    '/.well-known/acme-challenge/x',
    '/auth/unknown',
    '/ar/missing.mp3',
    '/test.db',
    '/nope/',
    '/.tmp/',
    '/auth/',
    '/index.php?path=../../etc',
  ]) {
    const res = await app.inject({ method: 'GET', url });
    assert.equal(res.statusCode, 404, url);
  }
});

test('listing can be filtered by folder', async () => {
  const carol = await tokenFor('carol@example.com');
  const res = await api('GET', '/files?folder=ar/sub', carol);
  assert.equal(res.statusCode, 200);
  assert.deepEqual(
    res.json().data.map((f: any) => f.path),
    ['ar/sub/x.mp3'],
  );
});

// ---------------- Admin API ----------------

test('only admins with a real login can manage users', async () => {
  const alice = await tokenFor('alice@example.com');
  assert.equal((await api('GET', '/admin/users', alice)).statusCode, 403);
  assert.equal((await app.inject({ method: 'GET', url: '/admin/users' })).statusCode, 401);

  const admin = await tokenFor('admin@example.com');
  const key = (await api('POST', '/auth/api-keys', admin, { name: 'ci' })).json().key;
  const viaKey = await app.inject({ method: 'GET', url: '/admin/users', headers: { 'x-api-key': key } });
  assert.equal(viaKey.statusCode, 403);

  const list = await api('GET', '/admin/users', admin);
  assert.equal(list.statusCode, 200);
  assert.ok(list.json().data.some((u: any) => u.email === 'admin@example.com'));
  assert.ok(!('password_hash' in list.json().data[0]));
});

test('admin can create, update and delete users', async () => {
  const admin = await tokenFor('admin@example.com');
  const created = await api('POST', '/admin/users', admin, {
    email: 'New.User@Example.com',
    password: PASSWORD,
    role: 'uploader',
    folders: ['/ar_old/'],
  });
  assert.equal(created.statusCode, 201, created.body);
  const u = created.json();
  assert.equal(u.email, 'new.user@example.com');
  assert.deepEqual(u.folders, ['ar_old']);

  assert.equal((await api('POST', '/admin/users', admin, { email: 'new.user@example.com', password: PASSWORD, role: 'viewer' })).statusCode, 409);
  assert.equal((await api('POST', '/admin/users', admin, { email: 'w@example.com', password: 'short', role: 'viewer' })).statusCode, 400);
  assert.equal((await api('POST', '/admin/users', admin, { email: 'w@example.com', password: PASSWORD, role: 'root' })).statusCode, 400);
  assert.equal((await api('POST', '/admin/users', admin, { email: 'w@example.com', password: PASSWORD, role: 'uploader', folders: ['../x'] })).statusCode, 400);

  const token = await tokenFor('new.user@example.com');
  const f = (await upload(token, 'a.mp3', MP3, 'audio/mpeg', '?folder=ar_old')).json();
  assert.equal((await app.inject({ method: 'GET', url: '/ar_old/a.mp3' })).statusCode, 200);

  const reset = await api('PATCH', `/admin/users/${u.id}`, admin, { password: 'another long password!' });
  assert.equal(reset.statusCode, 200);
  assert.equal((await login('new.user@example.com')).statusCode, 401);

  assert.equal((await api('DELETE', `/admin/users/${u.id}`, admin)).statusCode, 204);
  assert.equal((await app.inject({ method: 'GET', url: '/ar_old/a.mp3' })).statusCode, 404);
  assert.equal((await app.inject({ method: 'GET', url: new URL(f.url).pathname })).statusCode, 404);
});

test('the last admin cannot be demoted or delete themselves', async () => {
  const admin = await tokenFor('admin@example.com');
  const id = userId('admin@example.com');
  assert.equal((await api('PATCH', `/admin/users/${id}`, admin, { role: 'uploader' })).statusCode, 409);
  assert.equal((await api('DELETE', `/admin/users/${id}`, admin)).statusCode, 409);
});

test('change password requires the current one and ends other sessions', async () => {
  await createUser('erin@example.com', 'viewer');
  const res = await login('erin@example.com');
  const token = res.json().accessToken;
  const rt = res.cookies.find((c) => c.name === 'rt')!.value;

  const wrong = await api('POST', '/auth/change-password', token, { currentPassword: 'nope', newPassword: 'brand new password 1' });
  assert.equal(wrong.statusCode, 401);
  const ok = await api('POST', '/auth/change-password', token, { currentPassword: PASSWORD, newPassword: 'brand new password 1' });
  assert.equal(ok.statusCode, 204);

  assert.equal((await app.inject({ method: 'POST', url: '/auth/refresh', cookies: { rt } })).statusCode, 401);
  assert.equal((await login('erin@example.com', 'brand new password 1')).statusCode, 200);
});

// ---------------- Public folder index ----------------

test('root index lists folders, folder index lists files with player and embed code', async () => {
  const root = await app.inject({ method: 'GET', url: '/' });
  assert.equal(root.statusCode, 200);
  assert.match(String(root.headers['content-type']), /^text\/html/);
  assert.match(root.body, /href="\/ar\/"/);
  assert.doesNotMatch(root.body, /\/f\//, 'anonymous /f/ uploads are never listed');

  const ar = await app.inject({ method: 'GET', url: '/ar/' });
  assert.equal(ar.statusCode, 200);
  assert.match(ar.body, /voice01\.mp3/);
  assert.match(ar.body, /href="\/ar\/sub\/"/);
  assert.match(ar.body, /data-src="\/ar\/voice01\.mp3"/);
  assert.match(ar.body, /value="https:\/\/cdn\.example\.com\/ar\/voice01\.mp3"/);
  assert.match(ar.body, /&lt;audio controls&gt;/, 'embed code is escaped');
});

test('index page runs under a nonce CSP with no inline handlers', async () => {
  const res = await app.inject({ method: 'GET', url: '/ar/' });
  const csp = String(res.headers['content-security-policy']);
  const nonce = csp.match(/script-src 'nonce-([^']+)'/)?.[1];
  assert.ok(nonce, csp);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.doesNotMatch(res.body, /\son[a-z]+=/i);
  for (const tag of res.body.match(/<(script|style)[^>]*>/g)!) assert.ok(tag.includes(`nonce="${nonce}"`), tag);
  const again = await app.inject({ method: 'GET', url: '/ar/' });
  assert.notEqual(String(again.headers['content-security-policy']), csp, 'nonce is fresh per request');
});

test('folder without slash and old index.php links redirect', async () => {
  const a = await app.inject({ method: 'GET', url: '/ar' });
  assert.equal(a.statusCode, 301);
  assert.equal(a.headers.location, '/ar/');
  const b = await app.inject({ method: 'GET', url: '/index.php?path=ar%2Fsub' });
  assert.equal(b.statusCode, 301);
  assert.equal(b.headers.location, '/ar/sub/');
  const c = await app.inject({ method: 'GET', url: '/index.php' });
  assert.equal(c.headers.location, '/');
});

// ---------------- Folder management ----------------

test('browse shows one folder level; non-admins only see their own files', async () => {
  const admin = await tokenFor('admin@example.com');
  const res = await api('GET', '/files/browse?folder=ar', admin);
  assert.equal(res.statusCode, 200, res.body);
  const b = res.json();
  assert.equal(b.writable, true);
  assert.deepEqual(b.folders.map((f: any) => f.name), ['sub']);
  assert.ok(b.files.some((f: any) => f.path === 'ar/voice01.mp3' && f.owner === 'carol@example.com'));

  const dave = await tokenFor('dave@example.com');
  const d = (await api('GET', '/files/browse?folder=ar', dave)).json();
  assert.equal(d.writable, true);
  assert.equal(d.files.length, 0, 'dave owns nothing in ar');
  assert.equal((await api('GET', '/files/browse', dave)).json().writable, false, 'no grant on root');
  assert.equal((await api('GET', '/files/browse?folder=..%2Fetc', dave)).statusCode, 400);
});

test('a file can be renamed/moved only within writable folders, keeping its type', async () => {
  const carol = await tokenFor('carol@example.com');
  const f = (await upload(carol, 'mv.mp3', MP3, 'audio/mpeg', '?folder=ar')).json();

  const ok = await api('PATCH', `/files/${f.id}`, carol, { path: 'ar/sub/moved.mp3' });
  assert.equal(ok.statusCode, 200, ok.body);
  assert.equal(ok.json().url, 'https://cdn.example.com/ar/sub/moved.mp3');
  assert.equal((await app.inject({ method: 'GET', url: '/ar/sub/moved.mp3' })).statusCode, 200);
  assert.equal((await app.inject({ method: 'GET', url: '/ar/mv.mp3' })).statusCode, 404);

  assert.equal((await api('PATCH', `/files/${f.id}`, carol, { path: 'ar_old/moved.mp3' })).statusCode, 403);
  assert.equal((await api('PATCH', `/files/${f.id}`, carol, { path: 'ar/moved.png' })).statusCode, 400);
  assert.equal((await api('PATCH', `/files/${f.id}`, carol, { path: 'ar/voice01.mp3' })).statusCode, 409);
  assert.equal((await api('PATCH', `/files/${f.id}`, carol, { path: 'ar/../x.mp3' })).statusCode, 400);

  const dave = await tokenFor('dave@example.com');
  assert.equal((await api('PATCH', `/files/${f.id}`, dave, { path: 'ar/stolen.mp3' })).statusCode, 404);
});

test('admin can move a folder; files and folder grants follow; clashes roll back', async () => {
  const admin = await tokenFor('admin@example.com');
  for (const [folder, name] of [['mv/a', '1.mp3'], ['mv/a/b', '2.mp3'], ['clash', '1.mp3']]) {
    assert.equal((await upload(admin, name, MP3, 'audio/mpeg', `?folder=${folder}`)).statusCode, 201);
  }
  await api('PATCH', `/admin/users/${userId('dave@example.com')}`, admin, { folders: ['ar', 'mv/a/b'] });

  const moved = await api('POST', '/admin/folders/move', admin, { from: 'mv/a', to: 'mv2' });
  assert.equal(moved.statusCode, 200, moved.body);
  assert.equal(moved.json().moved, 2);
  assert.equal((await app.inject({ method: 'GET', url: '/mv2/1.mp3' })).statusCode, 200);
  assert.equal((await app.inject({ method: 'GET', url: '/mv2/b/2.mp3' })).statusCode, 200);
  assert.equal((await app.inject({ method: 'GET', url: '/mv/a/1.mp3' })).statusCode, 404);
  const dave = await tokenFor('dave@example.com');
  assert.deepEqual((await api('GET', '/auth/me', dave)).json().folders, ['ar', 'mv2/b']);

  const clash = await api('POST', '/admin/folders/move', admin, { from: 'mv2', to: 'clash' });
  assert.equal(clash.statusCode, 409);
  assert.equal((await app.inject({ method: 'GET', url: '/mv2/1.mp3' })).statusCode, 200, 'nothing moved');

  assert.equal((await api('POST', '/admin/folders/move', admin, { from: 'mv2', to: 'mv2/inner' })).statusCode, 400);
  assert.equal((await api('POST', '/admin/folders/move', admin, { from: 'nope', to: 'x' })).statusCode, 404);
  assert.equal((await api('POST', '/admin/folders/move', admin, { from: 'mv2', to: 'auth' })).statusCode, 400);
  const carol = await tokenFor('carol@example.com');
  assert.equal((await api('POST', '/admin/folders/move', carol, { from: 'ar', to: 'x' })).statusCode, 403);
});

test('moving a folder up into its parent works even when paths overlap', async () => {
  const admin = await tokenFor('admin@example.com');
  await upload(admin, 'z.mp3', MP3, 'audio/mpeg', '?folder=p/q/q');
  await upload(admin, 'z.mp3', MP3, 'audio/mpeg', '?folder=p/q');
  // p/q/q/z.mp3 -> p/q/z.mp3 (currently taken by the file that itself moves to p/z.mp3)
  const res = await api('POST', '/admin/folders/move', admin, { from: 'p/q', to: 'p' });
  assert.equal(res.statusCode, 200, res.body);
  assert.equal((await app.inject({ method: 'GET', url: '/p/z.mp3' })).statusCode, 200);
  assert.equal((await app.inject({ method: 'GET', url: '/p/q/z.mp3' })).statusCode, 200);
});

test('admin can delete a folder with everything in it', async () => {
  const admin = await tokenFor('admin@example.com');
  const carol = await tokenFor('carol@example.com');
  assert.equal((await api('DELETE', '/admin/folders?folder=mv2', carol)).statusCode, 403);
  assert.equal((await api('DELETE', '/admin/folders?folder=', admin)).statusCode, 400);
  const res = await api('DELETE', '/admin/folders?folder=mv2', admin);
  assert.equal(res.statusCode, 200, res.body);
  assert.equal(res.json().deleted, 2);
  assert.equal((await app.inject({ method: 'GET', url: '/mv2/1.mp3' })).statusCode, 404);
  assert.equal((await api('DELETE', '/admin/folders?folder=mv2', admin)).statusCode, 404);
});

// ---------------- Admin console page ----------------

test('admin console is served with a strict CSP and no inline code', async () => {
  const redirect = await app.inject({ method: 'GET', url: '/admin' });
  assert.equal(redirect.statusCode, 301);
  assert.equal(redirect.headers.location, '/admin/');

  const page = await app.inject({ method: 'GET', url: '/admin/' });
  assert.equal(page.statusCode, 200);
  assert.match(String(page.headers['content-type']), /^text\/html/);
  const csp = String(page.headers['content-security-policy']);
  assert.match(csp, /script-src 'self'/);
  assert.match(csp, /frame-ancestors 'none'/);
  assert.doesNotMatch(csp, /unsafe-inline|unsafe-eval/);
  assert.equal(page.headers['cache-control'], 'no-store');
  assert.doesNotMatch(page.body, /<script>(?!<\/script>)|\son[a-z]+=/i);

  const js = await app.inject({ method: 'GET', url: '/admin/app.js' });
  assert.equal(js.statusCode, 200);
  assert.match(String(js.headers['content-type']), /javascript/);
  assert.doesNotMatch(js.body, /innerHTML|outerHTML|insertAdjacentHTML|document\.write|eval\(/);
  assert.equal((await app.inject({ method: 'GET', url: '/admin/app.css' })).statusCode, 200);
  assert.equal((await app.inject({ method: 'GET', url: '/admin/../src/config.ts' })).statusCode, 404);
});
