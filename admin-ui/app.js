'use strict';
/*
 * CDN admin console. Plain JS, no build step.
 * - The access token lives only in memory; the session survives reloads through the HttpOnly
 *   refresh cookie (POST /auth/refresh).
 * - All server data is inserted with textContent / setAttribute, never parsed as HTML.
 */

// ---------------- DOM helpers ----------------
function h(tag, props, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(props || {})) {
    if (v == null || v === false) continue;
    if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
    else if (k === 'class') el.className = v;
    else el.setAttribute(k, v === true ? '' : String(v));
  }
  for (const kid of kids.flat(Infinity)) {
    if (kid == null || kid === false) continue;
    el.append(kid instanceof Node ? kid : String(kid));
  }
  return el;
}
const app = document.getElementById('app');
const toasts = document.getElementById('toasts');

function toast(message, kind = 'ok') {
  const t = h('div', { class: `toast ${kind}`, role: kind === 'err' ? 'alert' : 'status' }, message);
  toasts.append(t);
  setTimeout(() => t.remove(), kind === 'err' ? 7000 : 3500);
}

const field = (label, input, help) =>
  h('label', { class: 'field' }, h('span', { class: 'label' }, label), input, help && h('small', { class: 'help' }, help));

function formatBytes(n) {
  const units = ['B', 'KB', 'MB', 'GB', 'TB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i++; }
  return `${i ? n.toFixed(1) : n} ${units[i]}`;
}
const formatDate = (iso) => (iso ? new Date(iso).toLocaleString() : '—');
const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

// Mirrors the server rules: segments of [A-Za-z0-9._-], not starting with a dot, no ".."
const SEGMENT_RE = /^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/;
const validFolder = (p) => p.split('/').every((s) => SEGMENT_RE.test(s) && !s.includes('..'));
function safeName(name) {
  const clean = name
    .normalize('NFKD')
    .replace(/[\u0300-\u036f]/g, '') // strip accents left by NFKD
    .replace(/[^A-Za-z0-9._-]+/g, '-')
    .replace(/\.{2,}/g, '.')
    .replace(/^[^A-Za-z0-9]+/, '')
    .slice(0, 100);
  return clean || 'file';
}

// ---------------- Dialogs ----------------
function modal({ title, body = [], submitText = 'Save', danger = false, cancelText = 'Cancel', onSubmit }) {
  return new Promise((resolve) => {
    const dlg = h('dialog', { class: 'modal' });
    const err = h('p', { class: 'form-error', hidden: true });
    const submit = h('button', { type: 'submit', class: danger ? 'danger' : 'primary' }, submitText);
    const done = (value) => { dlg.close(); dlg.remove(); resolve(value); };
    const form = h(
      'form',
      {
        onsubmit: async (e) => {
          e.preventDefault();
          err.hidden = true;
          submit.disabled = true;
          try {
            const result = onSubmit ? await onSubmit(form) : true;
            done(result === undefined ? true : result);
          } catch (ex) {
            err.textContent = ex.message;
            err.hidden = false;
          } finally {
            submit.disabled = false;
          }
        },
      },
      h('h2', {}, title),
      body,
      err,
      h('div', { class: 'actions' },
        cancelText && h('button', { type: 'button', class: 'ghost', onclick: () => done(null) }, cancelText),
        submit),
    );
    dlg.append(form);
    dlg.addEventListener('cancel', (e) => { e.preventDefault(); done(null); });
    document.body.append(dlg);
    dlg.showModal();
    const first = form.querySelector('input:not([type=checkbox]), select, textarea');
    if (first) { first.focus(); if (first.select) first.select(); }
  });
}

function prompt({ title, label, value = '', help, submitText = 'Save', validate }) {
  const input = h('input', { type: 'text', value, required: true, spellcheck: 'false', autocomplete: 'off' });
  return modal({
    title,
    submitText,
    body: [field(label, input, help)],
    onSubmit: () => {
      const v = input.value.trim().replace(/^\/+|\/+$/g, '');
      if (validate) validate(v);
      return v;
    },
  });
}

function confirmTyped({ title, message, expect, submitText = 'Delete' }) {
  const input = h('input', { type: 'text', required: true, autocomplete: 'off', spellcheck: 'false' });
  return modal({
    title,
    danger: true,
    submitText,
    body: [h('p', {}, message), field(`Type "${expect}" to confirm`, input)],
    onSubmit: () => {
      if (input.value.trim() !== expect) throw new Error('The text does not match.');
    },
  });
}

const confirmSimple = (title, message, submitText = 'Delete') =>
  modal({ title, danger: true, submitText, body: [h('p', {}, message)] });

// ---------------- API ----------------
const state = { token: null, me: null };
const isAdmin = () => state.me?.role === 'admin';
const NO_RETRY = new Set(['/auth/login', '/auth/change-password']);

async function refreshToken() {
  try {
    const r = await fetch('/auth/refresh', { method: 'POST', credentials: 'same-origin' });
    if (!r.ok) return false;
    state.token = (await r.json()).accessToken;
    return true;
  } catch {
    return false;
  }
}

async function api(method, url, body, retried = false) {
  const headers = {};
  if (state.token) headers.authorization = `Bearer ${state.token}`;
  if (body !== undefined) headers['content-type'] = 'application/json';
  const r = await fetch(url, {
    method,
    headers,
    credentials: 'same-origin',
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (r.status === 401 && !NO_RETRY.has(url)) {
    if (!retried && (await refreshToken())) return api(method, url, body, true);
    showLogin('Your session has expired. Please log in again.');
    throw new Error('Session expired');
  }
  const data = r.status === 204 ? null : await r.json().catch(() => null);
  if (!r.ok) throw new Error(data?.details || data?.error || `${r.status} ${r.statusText}`);
  return data;
}

const sleep = (ms) => new Promise((res) => setTimeout(res, ms));

// XHR instead of fetch for upload progress. Retries on an expired token and on rate limiting.
function uploadOnce(file, folder, name, overwrite, onProgress) {
  return new Promise((resolve, reject) => {
    const qs = new URLSearchParams({ folder, name });
    if (overwrite) qs.set('overwrite', 'true');
    const xhr = new XMLHttpRequest();
    xhr.open('POST', `/files?${qs}`);
    xhr.setRequestHeader('authorization', `Bearer ${state.token}`);
    xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total);
    xhr.onload = () => {
      let data = null;
      try { data = JSON.parse(xhr.responseText); } catch { /* not JSON */ }
      if (xhr.status >= 200 && xhr.status < 300) return resolve(data);
      const e = new Error(data?.error || `${xhr.status} ${xhr.statusText}`);
      e.status = xhr.status;
      e.retryAfter = Number(xhr.getResponseHeader('retry-after')) || 0;
      reject(e);
    };
    xhr.onerror = () => reject(new Error('Network error'));
    const fd = new FormData();
    fd.append('file', file);
    xhr.send(fd);
  });
}

async function upload(file, folder, name, overwrite, onProgress, onWait) {
  for (let attempt = 0; ; attempt++) {
    try {
      return await uploadOnce(file, folder, name, overwrite, onProgress);
    } catch (e) {
      if (e.status === 401 && attempt === 0 && (await refreshToken())) continue;
      if (e.status === 429 && attempt < 20) {
        const secs = Math.min(Math.max(e.retryAfter, 5), 60);
        onWait(secs);
        await sleep(secs * 1000);
        continue;
      }
      throw e;
    }
  }
}

// ---------------- Session ----------------
function showLogin(message) {
  state.token = null;
  state.me = null;
  const email = h('input', { type: 'email', required: true, autocomplete: 'username' });
  const password = h('input', { type: 'password', required: true, autocomplete: 'current-password' });
  const err = h('p', { class: 'form-error', hidden: !message }, message || '');
  const btn = h('button', { type: 'submit', class: 'primary' }, 'Log in');
  const form = h(
    'form',
    {
      class: 'card',
      onsubmit: async (e) => {
        e.preventDefault();
        btn.disabled = true;
        err.hidden = true;
        try {
          const r = await api('POST', '/auth/login', { email: email.value.trim(), password: password.value });
          state.token = r.accessToken;
          await start();
        } catch (ex) {
          err.textContent = ex.message;
          err.hidden = false;
          password.value = '';
          password.focus();
        } finally {
          btn.disabled = false;
        }
      },
    },
    h('h1', {}, 'CDN Admin'),
    h('p', { class: 'muted' }, 'Sign in to manage files, folders and users.'),
    field('Email', email),
    field('Password', password),
    err,
    btn,
  );
  stopPlayer();
  app.replaceChildren(h('div', { class: 'login' }, form));
  email.focus();
}

async function start() {
  state.me = await api('GET', '/auth/me');
  if (!location.hash) history.replaceState(null, '', '#files/');
  route();
}

async function logout() {
  await fetch('/auth/logout', { method: 'POST', credentials: 'same-origin' }).catch(() => {});
  showLogin();
}

function changePassword() {
  const current = h('input', { type: 'password', required: true, autocomplete: 'current-password' });
  const next = h('input', { type: 'password', required: true, minlength: 12, maxlength: 128, autocomplete: 'new-password' });
  const again = h('input', { type: 'password', required: true, autocomplete: 'new-password' });
  modal({
    title: 'Change password',
    submitText: 'Change password',
    body: [
      field('Current password', current),
      field('New password', next, 'At least 12 characters.'),
      field('Repeat new password', again),
    ],
    onSubmit: async () => {
      if (next.value !== again.value) throw new Error('The new passwords do not match.');
      await api('POST', '/auth/change-password', { currentPassword: current.value, newPassword: next.value });
    },
  }).then((ok) => {
    if (ok) showLogin('Password changed. Please log in with your new password.');
  });
}

// ---------------- Layout & routing ----------------
let renderSeq = 0;

function shell(active, ...content) {
  const tabs = [['files', 'Files', '#files/']];
  if (isAdmin()) tabs.push(['users', 'Users', '#users']);
  tabs.push(['keys', 'API keys', '#keys']);
  const main = h('main', { class: 'main' }, content);
  app.replaceChildren(
    h('header', { class: 'topbar' },
      h('div', { class: 'brand' }, 'CDN Admin'),
      h('nav', { class: 'tabs' }, tabs.map(([id, label, href]) => h('a', { href, class: id === active ? 'active' : null }, label))),
      h('div', { class: 'account' },
        h('span', { class: 'who' }, state.me.email, h('span', { class: 'badge' }, state.me.role)),
        h('button', { class: 'ghost small', onclick: changePassword }, 'Change password'),
        h('button', { class: 'ghost small', onclick: logout }, 'Log out'))),
    main,
  );
  return main;
}

function route() {
  if (!state.me) return;
  const [tab, ...rest] = decodeURIComponent(location.hash.slice(1)).split('/');
  if (tab === 'users' && isAdmin()) return renderUsers();
  if (tab === 'keys') return renderKeys();
  return renderFiles(tab === 'files' ? rest.filter(Boolean).join('/') : '');
}
window.addEventListener('hashchange', route);

const goFolder = (folder) => { location.hash = `#files/${folder}`; };
const loading = () => h('p', { class: 'muted' }, 'Loading…');
const errorBox = (message) => h('p', { class: 'form-error' }, message);

function searchBox(rows) {
  return h('input', {
    type: 'search',
    class: 'search',
    placeholder: 'Filter…',
    'aria-label': 'Filter',
    oninput: (e) => {
      const t = e.target.value.trim().toLowerCase();
      for (const row of rows()) row.hidden = !row.dataset.name.includes(t);
    },
  });
}

// ---------------- Player ----------------
let player = null;
function play(src, name) {
  if (!player) {
    const audio = h('audio', { controls: true, preload: 'none' });
    const label = h('span', { class: 'pname' });
    player = h('div', { class: 'player' },
      h('span', { 'aria-hidden': 'true' }, '🎵'), label, audio,
      h('button', { class: 'ghost small', 'aria-label': 'Close player', onclick: stopPlayer }, '✕'));
    player.audio = audio;
    player.label = label;
    document.body.append(player);
  }
  player.label.textContent = name;
  player.audio.src = src;
  player.audio.play().catch(() => {});
}
function stopPlayer() {
  if (!player) return;
  player.audio.pause();
  player.remove();
  player = null;
}

// ---------------- Files & folders ----------------
async function renderFiles(folder) {
  const seq = ++renderSeq;
  const main = shell('files', loading());
  let data;
  try {
    data = await api('GET', `/files/browse?folder=${encodeURIComponent(folder)}`);
  } catch (e) {
    if (seq === renderSeq) main.replaceChildren(errorBox(e.message), h('a', { href: '#files/' }, 'Back to root'));
    return;
  }
  if (seq !== renderSeq) return;
  const admin = isAdmin();
  const parts = folder ? folder.split('/') : [];

  // Breadcrumb
  const crumbs = h('nav', { class: 'crumbs', 'aria-label': 'Folder path' },
    parts.length ? h('a', { href: '#files/' }, '🏠 Root') : h('span', { class: 'current' }, '🏠 Root'));
  parts.forEach((p, i) => {
    crumbs.append(h('span', { class: 'sep' }, '›'));
    crumbs.append(i === parts.length - 1
      ? h('span', { class: 'current' }, p)
      : h('a', { href: `#files/${parts.slice(0, i + 1).join('/')}` }, p));
  });

  // Upload controls
  const queue = h('ul', { class: 'queue' });
  const overwrite = h('input', { type: 'checkbox' });
  const fileInput = h('input', { type: 'file', multiple: true, class: 'file-input' });
  const dirInput = h('input', { type: 'file', multiple: true, webkitdirectory: true, class: 'file-input' });
  const startUpload = (items) => uploadItems(items, folder, overwrite.checked, queue);
  fileInput.addEventListener('change', () => { startUpload([...fileInput.files].map((file) => ({ file, dir: '' }))); fileInput.value = ''; });
  dirInput.addEventListener('change', () => {
    startUpload([...dirInput.files].map((file) => {
      const rel = file.webkitRelativePath || file.name;
      return { file, dir: rel.includes('/') ? rel.slice(0, rel.lastIndexOf('/')) : '' };
    }));
    dirInput.value = '';
  });

  const rows = [];
  const toolbar = h('div', { class: 'toolbar' },
    searchBox(() => rows),
    h('span', { class: 'spacer' }),
    h('button', { onclick: () => newFolder(folder) }, '＋ New folder'),
    data.writable && [
      h('button', { onclick: () => dirInput.click() }, 'Upload folder'),
      h('button', { class: 'primary', onclick: () => fileInput.click() }, '⬆ Upload files'),
      fileInput, dirInput,
    ],
    admin && folder && [
      h('button', { onclick: () => moveFolder(folder) }, 'Rename / move'),
      h('button', { class: 'link-danger', onclick: () => deleteFolder(folder, null) }, 'Delete folder'),
    ],
  );

  const intro = [];
  if (data.writable) {
    intro.push(h('label', { class: 'check' }, overwrite, 'Replace files that already exist'));
  } else {
    intro.push(h('p', { class: 'note' }, state.me.role === 'viewer'
      ? 'Your account is read-only.'
      : 'You cannot upload to this folder. Ask an admin to grant you access.'));
  }
  if (!admin && !folder && state.me.folders.length) {
    intro.push(h('div', { class: 'chips' }, h('span', { class: 'muted' }, 'Your folders:'),
      state.me.folders.map((f) => h('a', { class: 'chip', href: `#files/${f}` }, `📁 ${f}`))));
  }

  // Listing
  const tbody = h('tbody');
  for (const f of data.folders) {
    const path = folder ? `${folder}/${f.name}` : f.name;
    const tr = h('tr', { 'data-name': f.name.toLowerCase() },
      h('td', {}, h('div', { class: 'name-cell' }, h('span', { 'aria-hidden': 'true' }, '📁'), h('a', { href: `#files/${path}` }, f.name))),
      h('td', { class: 'num' }, formatBytes(f.size)),
      admin && h('td', { class: 'hide-sm muted' }, '—'),
      h('td', { class: 'nowrap muted hide-sm' }, plural(f.files, 'file')),
      h('td', { class: 'actions' }, admin && [
        h('button', { class: 'small', onclick: () => moveFolder(path) }, 'Rename'),
        h('button', { class: 'small link-danger', onclick: () => deleteFolder(path, f.files) }, 'Delete'),
      ]),
    );
    rows.push(tr);
    tbody.append(tr);
  }
  for (const f of data.files) {
    const name = f.path.slice(f.path.lastIndexOf('/') + 1);
    const isAudio = f.mime.startsWith('audio/');
    const tr = h('tr', { 'data-name': name.toLowerCase() },
      h('td', {}, h('div', { class: 'name-cell' },
        h('span', { 'aria-hidden': 'true' }, isAudio ? '🎵' : f.mime.startsWith('image/') ? '🖼️' : f.mime.startsWith('video/') ? '🎬' : '📄'),
        h('a', { href: `/${f.path}`, target: '_blank', rel: 'noopener' }, name))),
      h('td', { class: 'num' }, formatBytes(f.size)),
      admin && h('td', { class: 'hide-sm muted' }, f.owner),
      h('td', { class: 'nowrap muted hide-sm' }, formatDate(f.createdAt)),
      h('td', { class: 'actions' },
        isAudio && h('button', { class: 'small', onclick: () => play(`/${f.path}`, name) }, '▶ Play'),
        h('button', { class: 'small', onclick: () => copy(f.url, 'Link copied') }, 'Copy link'),
        data.writable || admin || state.me.role === 'uploader' ? [
          h('button', { class: 'small', onclick: () => moveFile(f) }, 'Rename'),
          h('button', { class: 'small link-danger', onclick: () => deleteFile(f) }, 'Delete'),
        ] : null),
    );
    rows.push(tr);
    tbody.append(tr);
  }

  const empty = !data.folders.length && !data.files.length;
  const table = empty
    ? h('div', { class: 'empty' },
        folder
          ? h('p', {}, 'This folder is empty. ', data.writable ? 'Upload files to create it — ' : '', 'folders only exist while they contain files.')
          : h('p', {}, 'No files yet.'))
    : h('div', { class: 'table-wrap' }, h('table', {},
        h('thead', {}, h('tr', {},
          h('th', {}, 'Name'), h('th', { class: 'num' }, 'Size'),
          admin && h('th', { class: 'hide-sm' }, 'Owner'),
          h('th', { class: 'hide-sm' }, 'Uploaded'), h('th', {}, h('span', { class: 'hide-sm' }, 'Actions')))),
        tbody));

  const summary = h('span', { class: 'muted' },
    [data.folders.length && plural(data.folders.length, 'folder'), plural(data.files.length, 'file')].filter(Boolean).join(' · '));
  const panel = h('div', { class: 'panel dropzone' }, table);
  main.replaceChildren(
    h('div', { class: 'page-title' }, h('h1', {}, parts.length ? parts[parts.length - 1] : 'Files'), summary),
    crumbs, toolbar, intro, queue, panel);

  if (data.writable) enableDrop(panel, startUpload);
}

function enableDrop(zone, onItems) {
  let depth = 0;
  zone.addEventListener('dragenter', (e) => { e.preventDefault(); depth++; zone.classList.add('dragging'); });
  zone.addEventListener('dragover', (e) => e.preventDefault());
  zone.addEventListener('dragleave', () => { if (--depth <= 0) { depth = 0; zone.classList.remove('dragging'); } });
  zone.addEventListener('drop', async (e) => {
    e.preventDefault();
    depth = 0;
    zone.classList.remove('dragging');
    onItems(await collectDropped(e.dataTransfer));
  });
}

// Walks dropped folders so their structure is kept (ar/sub/x.mp3 -> <current>/ar/sub/x.mp3)
async function collectDropped(dt) {
  const entries = [...dt.items].map((i) => i.webkitGetAsEntry && i.webkitGetAsEntry()).filter(Boolean);
  if (!entries.length) return [...dt.files].map((file) => ({ file, dir: '' }));
  const out = [];
  async function walk(entry, dir) {
    if (entry.name.startsWith('.')) return; // .DS_Store, .git, ...
    if (entry.isFile) {
      out.push({ file: await new Promise((res, rej) => entry.file(res, rej)), dir });
    } else if (entry.isDirectory) {
      const reader = entry.createReader();
      const sub = dir ? `${dir}/${entry.name}` : entry.name;
      for (;;) {
        const batch = await new Promise((res, rej) => reader.readEntries(res, rej));
        if (!batch.length) break;
        for (const child of batch) await walk(child, sub);
      }
    }
  }
  for (const entry of entries) await walk(entry, '');
  return out;
}

async function uploadItems(items, folder, overwrite, queue) {
  items = items.filter(({ file }) => !file.name.startsWith('.'));
  if (!items.length) return;
  const jobs = items.map(({ file, dir }) => {
    const target = [folder, ...dir.split('/').filter(Boolean).map(safeName)].filter(Boolean).join('/');
    const name = safeName(file.name);
    const bar = h('progress', { max: '1', value: '0' });
    const status = h('span', { class: 'status muted' }, 'Waiting');
    queue.append(h('li', {}, h('span', { class: 'qname', title: `${target ? `${target}/` : ''}${name}` }, `${target ? `${target}/` : ''}${name}`), bar, status));
    return { file, target, name, bar, status };
  });
  let ok = 0;
  for (const job of jobs) {
    job.status.textContent = 'Uploading';
    try {
      await upload(job.file, job.target, job.name, overwrite,
        (p) => { job.bar.value = p; },
        (secs) => { job.status.textContent = `Waiting ${secs}s (rate limit)`; });
      job.bar.value = 1;
      job.status.textContent = '✓ Done';
      job.status.className = 'status ok';
      ok++;
    } catch (e) {
      job.status.textContent = e.message;
      job.status.className = 'status err';
    }
  }
  const failed = jobs.length - ok;
  toast(failed ? `${ok} uploaded, ${failed} failed` : `${plural(ok, 'file')} uploaded`, failed ? 'err' : 'ok');
  if (!failed) setTimeout(() => route(), 800);
  else if (ok) {
    // keep the queue visible so errors can be read; refresh the listing below it
    const keep = [...queue.children];
    await route();
    const q = document.querySelector('.queue');
    if (q) q.append(...keep);
  }
}

async function copy(text, message) {
  try {
    await navigator.clipboard.writeText(text);
    toast(message);
  } catch {
    await prompt({ title: 'Copy', label: 'Copy this value', value: text, submitText: 'Close' });
  }
}

async function newFolder(parent) {
  const name = await prompt({
    title: 'New folder',
    label: 'Folder name',
    help: `Created inside ${parent ? `"${parent}"` : 'the root'}. Use letters, numbers, dot, dash or underscore. You can type a/b for nested folders.`,
    submitText: 'Open folder',
    validate: (v) => { if (!v || !validFolder(v)) throw new Error('Invalid folder name.'); },
  });
  if (name) goFolder(parent ? `${parent}/${name}` : name);
}

async function moveFolder(from) {
  const to = await prompt({
    title: 'Rename or move folder',
    label: 'New folder path',
    value: from,
    help: 'Every file inside moves along and old URLs stop working (purge your CDN cache). Folder permissions of users follow the rename.',
    submitText: 'Move',
    validate: (v) => { if (!v || !validFolder(v)) throw new Error('Invalid folder path.'); },
  });
  if (!to || to === from) return;
  try {
    const r = await api('POST', '/admin/folders/move', { from, to });
    toast(`Moved ${plural(r.moved, 'file')} to ${r.to}`);
    state.me = await api('GET', '/auth/me');
    const current = decodeURIComponent(location.hash).replace(/^#files\/?/, '');
    if (current === from || current.startsWith(`${from}/`)) goFolder(r.to + current.slice(from.length));
    else route();
  } catch (e) {
    toast(e.message, 'err');
  }
}

async function deleteFolder(folder, count) {
  const ok = await confirmTyped({
    title: 'Delete folder',
    message: `This permanently deletes ${count == null ? 'every file' : plural(count, 'file')} in "${folder}" and its subfolders. Their public URLs stop working.`,
    expect: folder,
  });
  if (!ok) return;
  try {
    const r = await api('DELETE', `/admin/folders?folder=${encodeURIComponent(folder)}`);
    toast(`Deleted ${plural(r.deleted, 'file')}`);
    const parent = folder.includes('/') ? folder.slice(0, folder.lastIndexOf('/')) : '';
    const current = decodeURIComponent(location.hash).replace(/^#files\/?/, '');
    if (current === folder || current.startsWith(`${folder}/`)) goFolder(parent);
    else route();
  } catch (e) {
    toast(e.message, 'err');
  }
}

async function moveFile(f) {
  const path = await prompt({
    title: 'Rename or move file',
    label: 'Path',
    value: f.path,
    help: 'Change the folder part to move it, e.g. ar_old/voice01001.mp3. The extension must stay the same. The old URL stops working.',
    submitText: 'Save',
  });
  if (!path || path === f.path) return;
  try {
    await api('PATCH', `/files/${f.id}`, { path });
    toast('File moved');
    route();
  } catch (e) {
    toast(e.message, 'err');
  }
}

async function deleteFile(f) {
  if (!(await confirmSimple('Delete file', `Delete "${f.path}"? Its public URL stops working.`))) return;
  try {
    await api('DELETE', `/files/${f.id}`);
    toast('File deleted');
    route();
  } catch (e) {
    toast(e.message, 'err');
  }
}

// ---------------- Users (admin) ----------------
const ROLES = ['viewer', 'uploader', 'admin'];
const parseFolders = (text) => text.split(/[\s,]+/).map((s) => s.replace(/^\/+|\/+$/g, '')).filter(Boolean);
const roleSelect = (value) => h('select', {}, ROLES.map((r) => h('option', { value: r, selected: r === value }, r)));
function randomPassword() {
  const bytes = crypto.getRandomValues(new Uint8Array(18));
  return btoa(String.fromCharCode(...bytes)).replace(/\+/g, '-').replace(/\//g, '_');
}
function passwordField(label, required, help) {
  const input = h('input', { type: 'text', required, minlength: 12, maxlength: 128, autocomplete: 'new-password', spellcheck: 'false', class: 'mono' });
  const gen = h('button', { type: 'button', onclick: () => { input.value = randomPassword(); input.select(); } }, 'Generate');
  return { input, node: field(label, h('div', { class: 'inline' }, input, gen), help) };
}

async function renderUsers() {
  const seq = ++renderSeq;
  const main = shell('users', loading());
  let users;
  try {
    users = (await api('GET', '/admin/users')).data;
  } catch (e) {
    if (seq === renderSeq) main.replaceChildren(errorBox(e.message));
    return;
  }
  if (seq !== renderSeq) return;
  const rows = [];
  const tbody = h('tbody', {}, users.map((u) => {
    const tr = h('tr', { 'data-name': u.email.toLowerCase() },
      h('td', {}, h('span', { class: 'mono' }, u.email), u.id === state.me.id && h('span', { class: 'badge' }, 'you')),
      h('td', {}, u.role),
      h('td', { class: 'hide-sm' }, u.role === 'admin' ? h('span', { class: 'muted' }, 'all') : u.folders.length ? u.folders.join(', ') : h('span', { class: 'muted' }, 'none')),
      h('td', { class: 'num hide-sm' }, `${u.files} · ${formatBytes(u.usedBytes)}`),
      h('td', {}, u.locked ? h('span', { class: 'badge warn' }, 'locked') : h('span', { class: 'muted' }, 'active')),
      h('td', { class: 'actions' },
        h('button', { class: 'small', onclick: () => editUser(u) }, 'Edit'),
        u.id !== state.me.id && h('button', { class: 'small link-danger', onclick: () => deleteUser(u) }, 'Delete')),
    );
    rows.push(tr);
    return tr;
  }));
  main.replaceChildren(
    h('div', { class: 'page-title' }, h('h1', {}, 'Users'), h('span', { class: 'muted' }, plural(users.length, 'user'))),
    h('div', { class: 'toolbar' }, searchBox(() => rows), h('span', { class: 'spacer' }),
      h('button', { class: 'primary', onclick: addUser }, '＋ Add user')),
    h('p', { class: 'note' }, 'Uploaders can only upload into their folders (and subfolders). Admins can upload anywhere and manage everything. Viewers are read-only.'),
    h('div', { class: 'panel' }, h('div', { class: 'table-wrap' }, h('table', {},
      h('thead', {}, h('tr', {}, h('th', {}, 'Email'), h('th', {}, 'Role'), h('th', { class: 'hide-sm' }, 'Folders'),
        h('th', { class: 'num hide-sm' }, 'Files'), h('th', {}, 'Status'), h('th', {}))),
      tbody))),
  );
}

async function addUser() {
  const email = h('input', { type: 'email', required: true, autocomplete: 'off' });
  const role = roleSelect('uploader');
  const folders = h('textarea', { placeholder: 'ar\nar_old', spellcheck: 'false', class: 'mono' });
  const pw = passwordField('Password', true, 'At least 12 characters. Share it with the user securely; they can change it after logging in.');
  const ok = await modal({
    title: 'Add user',
    submitText: 'Create user',
    body: [field('Email', email), field('Role', role), pw.node,
      field('Folders', folders, 'Uploaders only: one per line or comma-separated. Subfolders are included.')],
    onSubmit: () => api('POST', '/admin/users', {
      email: email.value.trim(),
      password: pw.input.value,
      role: role.value,
      folders: parseFolders(folders.value),
    }),
  });
  if (ok) { toast(`User ${ok.email} created`); renderUsers(); }
}

async function editUser(u) {
  const role = roleSelect(u.role);
  const folders = h('textarea', { spellcheck: 'false', class: 'mono' }, u.folders.join('\n'));
  const pw = passwordField('New password', false, 'Leave empty to keep the current password. Setting one logs the user out everywhere.');
  const unlock = h('input', { type: 'checkbox' });
  const ok = await modal({
    title: `Edit ${u.email}`,
    body: [field('Role', role),
      field('Folders', folders, 'Uploaders only: one per line or comma-separated. Subfolders are included.'),
      pw.node,
      u.locked && h('label', { class: 'check' }, unlock, 'Unlock account (it is locked after repeated failed logins)')],
    onSubmit: async () => {
      const body = {};
      if (role.value !== u.role) body.role = role.value;
      const f = parseFolders(folders.value);
      if (f.join('\n') !== u.folders.join('\n')) body.folders = f;
      if (pw.input.value) body.password = pw.input.value;
      if (unlock.checked) body.unlock = true;
      if (!Object.keys(body).length) return 'unchanged';
      return api('PATCH', `/admin/users/${u.id}`, body);
    },
  });
  if (ok && ok !== 'unchanged') {
    toast('User updated');
    if (u.id === state.me.id) state.me = await api('GET', '/auth/me');
    route();
  }
}

async function deleteUser(u) {
  const ok = await confirmTyped({
    title: 'Delete user',
    message: `This deletes ${u.email}, their API keys and all ${plural(u.files, 'file')} they uploaded. Those public URLs stop working.`,
    expect: u.email,
  });
  if (!ok) return;
  try {
    await api('DELETE', `/admin/users/${u.id}`);
    toast('User deleted');
    renderUsers();
  } catch (e) {
    toast(e.message, 'err');
  }
}

// ---------------- API keys ----------------
async function renderKeys() {
  const seq = ++renderSeq;
  const main = shell('keys', loading());
  let keys;
  try {
    keys = (await api('GET', '/auth/api-keys')).data;
  } catch (e) {
    if (seq === renderSeq) main.replaceChildren(errorBox(e.message));
    return;
  }
  if (seq !== renderSeq) return;
  const canCreate = state.me.role !== 'viewer';
  main.replaceChildren(
    h('div', { class: 'page-title' }, h('h1', {}, 'API keys'), h('span', { class: 'muted' }, plural(keys.length, 'active key'))),
    h('div', { class: 'toolbar' }, h('span', { class: 'spacer' }),
      canCreate && h('button', { class: 'primary', onclick: createKey }, '＋ New API key')),
    h('p', { class: 'note' }, 'API keys let your other servers upload with the header X-API-Key, with the same folder permissions as your account. They cannot manage users or other keys.'),
    h('div', { class: 'panel' }, keys.length
      ? h('div', { class: 'table-wrap' }, h('table', {},
          h('thead', {}, h('tr', {}, h('th', {}, 'Name'), h('th', {}, 'Key'), h('th', { class: 'hide-sm' }, 'Created'), h('th', { class: 'hide-sm' }, 'Last used'), h('th', {}))),
          h('tbody', {}, keys.map((k) => h('tr', {},
            h('td', {}, k.name),
            h('td', { class: 'mono' }, `${k.prefix}…`),
            h('td', { class: 'nowrap muted hide-sm' }, formatDate(k.createdAt)),
            h('td', { class: 'nowrap muted hide-sm' }, formatDate(k.lastUsedAt)),
            h('td', { class: 'actions' }, h('button', { class: 'small link-danger', onclick: () => revokeKey(k) }, 'Revoke')))))))
      : h('div', { class: 'empty' }, 'No API keys yet.')),
  );
}

async function createKey() {
  const name = h('input', { type: 'text', required: true, maxlength: 64, placeholder: 'e.g. blog-server' });
  const created = await modal({
    title: 'New API key',
    submitText: 'Create',
    body: [field('Name', name, 'Only for you to recognise the key later.')],
    onSubmit: () => api('POST', '/auth/api-keys', { name: name.value.trim() }),
  });
  if (!created) return;
  const keyInput = h('input', { type: 'text', readonly: true, value: created.key, class: 'mono' });
  await modal({
    title: 'Copy your API key',
    submitText: 'Done',
    cancelText: null,
    body: [
      h('p', {}, 'This key is shown only once. Store it somewhere safe now.'),
      field('API key', h('div', { class: 'inline' }, keyInput,
        h('button', { type: 'button', onclick: () => copy(created.key, 'API key copied') }, 'Copy'))),
    ],
  });
  renderKeys();
}

async function revokeKey(k) {
  if (!(await confirmSimple('Revoke API key', `Revoke "${k.name}"? Anything using it will stop working immediately.`, 'Revoke'))) return;
  try {
    await api('DELETE', `/auth/api-keys/${k.id}`);
    toast('API key revoked');
    renderKeys();
  } catch (e) {
    toast(e.message, 'err');
  }
}

// ---------------- Boot ----------------
(async () => {
  if (await refreshToken()) {
    try {
      await start();
      return;
    } catch { /* fall through to login */ }
  }
  showLogin();
})();
