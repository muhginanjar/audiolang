import type { DB } from '../db.js';

/**
 * Public folder index (the replacement for the old index.php): folders, files, search, an inline
 * player and copyable embed code. Everything dynamic is HTML-escaped, and the page runs under a
 * nonce-based CSP, so neither injected markup nor inline handlers can execute.
 */

export interface Listing {
  folder: string; // '' = root
  folders: { name: string; files: number }[];
  files: { name: string; size: number; mime: string }[];
}

const collator = new Intl.Collator(undefined, { numeric: true, sensitivity: 'base' });

/** Builds the listing for one folder from the virtual paths. Returns null if the folder is empty. */
export function buildListing(db: DB, folder: string): Listing | null {
  const prefix = folder ? `${folder}/` : '';
  const rows = (
    folder
      ? // Segments are [A-Za-z0-9._-] only, so escaping "_" is all LIKE needs
        db.prepare("SELECT vpath, size, mime FROM files WHERE vpath LIKE ? ESCAPE '\\'").all(`${prefix.replace(/_/g, '\\_')}%`)
      : db.prepare('SELECT vpath, size, mime FROM files WHERE vpath IS NOT NULL').all()
  ) as { vpath: string; size: number; mime: string }[];
  if (!rows.length) return null;

  const folders = new Map<string, number>();
  const files: Listing['files'] = [];
  for (const r of rows) {
    const rest = r.vpath.slice(prefix.length);
    const slash = rest.indexOf('/');
    if (slash === -1) files.push({ name: rest, size: r.size, mime: r.mime });
    else folders.set(rest.slice(0, slash), (folders.get(rest.slice(0, slash)) ?? 0) + 1);
  }
  return {
    folder,
    folders: [...folders].map(([name, n]) => ({ name, files: n })).sort((a, b) => collator.compare(a.name, b.name)),
    files: files.sort((a, b) => collator.compare(a.name, b.name)),
  };
}

const esc = (s: string) =>
  s.replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]!);

function formatBytes(n: number) {
  const units = ['B', 'KB', 'MB', 'GB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${i ? n.toFixed(2) : n} ${units[i]}`;
}

const icon = (mime: string) =>
  mime.startsWith('audio/') ? '🎵' : mime.startsWith('image/') ? '🖼️' : mime.startsWith('video/') ? '🎬' : '📄';

function embedTag(mime: string, url: string) {
  if (mime.startsWith('audio/')) return `<audio controls><source src="${url}" type="${mime}"></audio>`;
  if (mime.startsWith('video/')) return `<video controls><source src="${url}" type="${mime}"></video>`;
  if (mime.startsWith('image/')) return `<img src="${url}" alt="">`;
  return `<a href="${url}">${url}</a>`;
}

export function renderListing(l: Listing, opts: { baseUrl: string; title: string; nonce: string }) {
  const { baseUrl, title, nonce } = opts;
  const parts = l.folder ? l.folder.split('/') : [];
  const heading = parts.length ? parts[parts.length - 1] : title;

  const crumbs = [`<a href="/">🏠 Root</a>`];
  parts.forEach((p, i) => {
    const href = `/${parts.slice(0, i + 1).join('/')}/`;
    crumbs.push(i === parts.length - 1 ? `<span aria-current="page">${esc(p)}</span>` : `<a href="${esc(href)}">${esc(p)}</a>`);
  });

  const stats = [`${l.files.length} file${l.files.length === 1 ? '' : 's'}`];
  if (l.folders.length) stats.push(`${l.folders.length} folder${l.folders.length === 1 ? '' : 's'}`);

  const folderItems = l.folders
    .map(
      (f) => `
    <li class="item" data-name="${esc(f.name.toLowerCase())}">
      <a class="row folder" href="/${esc([...parts, f.name].join('/'))}/">
        <span class="ico" aria-hidden="true">📁</span>
        <span class="name">${esc(f.name)}</span>
        <span class="meta">${f.files} file${f.files === 1 ? '' : 's'}</span>
      </a>
    </li>`,
    )
    .join('');

  const fileItems = l.files
    .map((f, i) => {
      const rel = `/${[...parts, f.name].join('/')}`;
      const abs = `${baseUrl}${rel}`;
      const num = f.name.match(/(\d+)\.[^.]+$/)?.[1] ?? String(i + 1);
      const audio = f.mime.startsWith('audio/');
      return `
    <li class="item" id="file-${esc(num)}" data-name="${esc(f.name.toLowerCase())}" data-src="${esc(rel)}">
      <div class="row">
        <span class="num">#${esc(num)}</span>
        <span class="ico" aria-hidden="true">${icon(f.mime)}</span>
        <span class="name">${esc(f.name)}</span>
        <span class="meta">${formatBytes(f.size)}</span>
        <span class="actions">
          ${audio ? `<button type="button" data-act="play" class="primary"><span aria-hidden="true">▶</span> <span class="lbl">Play</span></button>` : `<a class="btn" href="${esc(rel)}" target="_blank" rel="noopener">Open</a>`}
          <a class="btn" href="${esc(rel)}" download="${esc(f.name)}">Download</a>
          <button type="button" data-act="embed" aria-expanded="false">Embed</button>
        </span>
      </div>
      <div class="player" hidden></div>
      <div class="embed" hidden>
        <label>Direct link
          <span class="copy"><input type="text" readonly value="${esc(abs)}"><button type="button" data-act="copy">Copy</button></span>
        </label>
        <label>HTML tag
          <span class="copy"><input type="text" readonly value="${esc(embedTag(f.mime, abs))}"><button type="button" data-act="copy">Copy</button></span>
        </label>
      </div>
    </li>`;
    })
    .join('');

  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(parts.length ? `${l.folder} · ${title}` : title)}</title>
<style nonce="${nonce}">
:root{--bg:#f4f5fb;--card:#fff;--text:#1d2033;--muted:#6b7089;--line:#e6e8f2;--accent:#5b5bd6;--accent-soft:#ececfd;--ok:#1f9d55;--hero1:#667eea;--hero2:#764ba2}
@media (prefers-color-scheme:dark){:root{--bg:#12131a;--card:#1b1d27;--text:#e8e9f1;--muted:#9a9db3;--line:#2b2e3d;--accent:#8f8ff5;--accent-soft:#272a45;--ok:#4ade80;--hero1:#3d3f9e;--hero2:#4b2a6e}}
*{box-sizing:border-box}[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--text);font:15px/1.5 system-ui,-apple-system,"Segoe UI",Roboto,sans-serif}
.wrap{max-width:880px;margin:0 auto;padding:24px 16px 64px}
header{background:linear-gradient(135deg,var(--hero1),var(--hero2));color:#fff;border-radius:16px;padding:28px 24px;margin-bottom:16px}
header h1{margin:0 0 4px;font-size:1.7rem;word-break:break-all}
header p{margin:0;opacity:.85}
nav{display:flex;flex-wrap:wrap;gap:6px;align-items:center;margin-top:14px;font-size:.9rem}
nav a{color:#fff;background:rgba(255,255,255,.18);padding:3px 10px;border-radius:999px;text-decoration:none}
nav a:hover{background:rgba(255,255,255,.3)}
nav span[aria-current]{padding:3px 4px;font-weight:600}
nav .sep{opacity:.6}
.search{width:100%;padding:12px 14px;border:1px solid var(--line);border-radius:12px;background:var(--card);color:var(--text);font:inherit;margin-bottom:12px}
.search:focus{outline:2px solid var(--accent);outline-offset:1px}
ul{list-style:none;margin:0;padding:0;background:var(--card);border:1px solid var(--line);border-radius:14px;overflow:hidden}
.item+.item{border-top:1px solid var(--line)}
.row{display:flex;align-items:center;gap:10px;padding:10px 14px;min-height:52px;flex-wrap:wrap}
a.row{color:inherit;text-decoration:none}a.row:hover{background:var(--accent-soft)}
.num{color:var(--muted);font-variant-numeric:tabular-nums;font-size:.85rem;min-width:52px}
.name{flex:1;min-width:140px;font-weight:500;word-break:break-all}
.meta{color:var(--muted);font-size:.85rem;font-variant-numeric:tabular-nums;white-space:nowrap}
.actions{display:flex;gap:6px;margin-left:auto}
button,.btn{font:inherit;font-size:.85rem;padding:6px 12px;border-radius:8px;border:1px solid var(--line);background:var(--card);color:var(--text);cursor:pointer;text-decoration:none;white-space:nowrap}
button:hover,.btn:hover{border-color:var(--accent);color:var(--accent)}
button.primary{background:var(--accent);border-color:var(--accent);color:#fff}
button.primary:hover{filter:brightness(1.1);color:#fff}
button.done{border-color:var(--ok);color:var(--ok)}
.player,.embed{padding:0 14px 14px}
.player audio{width:100%}
.embed{display:grid;gap:10px}
.embed label{display:grid;gap:4px;font-size:.8rem;color:var(--muted)}
.copy{display:flex;gap:6px}
.copy input{flex:1;min-width:0;padding:7px 10px;border:1px solid var(--line);border-radius:8px;background:var(--bg);color:var(--text);font:13px ui-monospace,SFMono-Regular,Menlo,monospace}
.empty{padding:28px;text-align:center;color:var(--muted)}
@media (max-width:560px){.num{min-width:0}.actions{width:100%;margin-left:0}.actions>*{flex:1;text-align:center}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <h1>${esc(heading)}</h1>
    <p>${stats.join(' · ')}</p>
    ${parts.length ? `<nav aria-label="Breadcrumb">${crumbs.join('<span class="sep">›</span>')}</nav>` : ''}
  </header>
  <input class="search" id="q" type="search" placeholder="Search files…" aria-label="Search files" autocomplete="off">
  <ul id="list">${folderItems}${fileItems}</ul>
  <p class="empty" id="none" hidden>No files match your search.</p>
</div>
<script nonce="${nonce}">
(() => {
  const q = document.getElementById('q');
  const none = document.getElementById('none');
  const items = [...document.querySelectorAll('#list .item')];
  q.addEventListener('input', () => {
    const t = q.value.trim().toLowerCase();
    let shown = 0;
    for (const el of items) { el.hidden = !el.dataset.name.includes(t); if (!el.hidden) shown++; }
    none.hidden = shown > 0;
  });

  let current = null;
  const label = (item, playing) => {
    const b = item.querySelector('[data-act=play]');
    b.firstElementChild.textContent = playing ? '❚❚' : '▶';
    b.querySelector('.lbl').textContent = playing ? 'Pause' : 'Play';
  };
  function play(item) {
    const box = item.querySelector('.player');
    let audio = box.querySelector('audio');
    if (!audio) {
      audio = document.createElement('audio');
      audio.controls = true;
      audio.preload = 'none';
      audio.src = item.dataset.src;
      audio.addEventListener('play', () => { if (current && current !== audio) current.pause(); current = audio; label(item, true); });
      audio.addEventListener('pause', () => label(item, false));
      box.append(audio);
    }
    box.hidden = false;
    audio.paused ? audio.play() : audio.pause();
  }
  async function copy(btn) {
    const input = btn.previousElementSibling;
    try { await navigator.clipboard.writeText(input.value); }
    catch { input.select(); document.execCommand('copy'); }
    const old = btn.textContent;
    btn.textContent = 'Copied!'; btn.classList.add('done');
    setTimeout(() => { btn.textContent = old; btn.classList.remove('done'); }, 1500);
  }
  document.addEventListener('click', (e) => {
    const btn = e.target.closest('button[data-act]');
    if (!btn) return;
    const item = btn.closest('.item');
    if (btn.dataset.act === 'play') play(item);
    else if (btn.dataset.act === 'copy') copy(btn);
    else if (btn.dataset.act === 'embed') {
      const panel = item.querySelector('.embed');
      panel.hidden = !panel.hidden;
      btn.setAttribute('aria-expanded', String(!panel.hidden));
      btn.textContent = panel.hidden ? 'Embed' : 'Hide';
    }
  });
})();
</script>
</body>
</html>`;
}
