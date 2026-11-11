'use strict';
// The demo page. It talks only to the demo server's /api; nothing here decides
// what the pipeline did. The Pipeline view renders the server's events and store
// reads. The Logs view renders the aggregator's response for the chosen identity.

const $ = (s, el = document) => el.querySelector(s);
const $$ = (s, el = document) => [...el.querySelectorAll(s)];
const h = (tag, attrs = {}, ...kids) => {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === 'class') el.className = v;
    else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
    else if (v !== undefined && v !== null && v !== false) el.setAttribute(k, v);
  }
  for (const kid of kids.flat()) if (kid !== null && kid !== undefined && kid !== false) el.append(kid);
  return el;
};
const api = async (path, body) => {
  const r = await fetch(path, body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
  return r.json();
};
const zoneTag = { plain: 'PLAINTEXT', sealed: 'SEALED', key: 'KEY', denied: 'DENIED', info: 'INFO' };
const clock = (ts, withDate) => {
  const d = new Date(ts);
  const t = d.toLocaleTimeString([], { hour12: false }) + '.' + String(d.getMilliseconds()).padStart(3, '0');
  return withDate ? d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ' ' + t : t;
};

let statusTimer;
function status(res) {
  const el = $('#status');
  el.className = 'status on ' + (res.zone || '');
  el.textContent = res.status;
  clearTimeout(statusTimer);
  statusTimer = setTimeout(() => el.classList.remove('on'), 7000);
}

// ---------------- views ----------------
let view = 'pipeline';
function showView(v) {
  view = v;
  $$('.views button').forEach((b) => b.setAttribute('aria-selected', b.dataset.view === v));
  $('#view-pipeline').hidden = v !== 'pipeline';
  $('#view-logs').hidden = v !== 'logs';
  if (location.hash !== '#' + v) history.replaceState(null, '', '#' + v);
  if (v === 'logs') { lv.load(); loadGrants(); } else stopTail();
}
$$('.views button').forEach((b) => b.addEventListener('click', () => showView(b.dataset.view)));

// ---------------- pipeline ----------------
const pv = { stages: [], traces: [], trace: null, stage: 0, lastSteps: '' };

function renderPipeline() {
  const t = pv.traces.find((x) => x.id === pv.trace);
  const box = $('#pipeline');
  box.replaceChildren(...pv.stages.flatMap((st, i) => {
    const b = h('button', { class: 'box ' + ((t && t.stages[st]) || '') + (i === pv.stage ? ' sel' : ''), type: 'button',
      onclick: () => { pv.stage = i; renderPipeline(); inspect(); } }, st);
    return i < pv.stages.length - 1 ? [b, h('span', { class: 'arrow' }, '→')] : [b];
  }));
  $('#ins-stage').textContent = '· ' + (pv.stages[pv.stage] || '');
}

function renderTraces() {
  const sel = $('#trace-sel');
  const opts = pv.traces.slice().reverse().map((t) => h('option', { value: t.id, selected: t.id === pv.trace }, `${t.id} · ${t.msg.slice(0, 40)}`));
  if (!opts.length) opts.push(h('option', { value: '' }, 'nothing sent yet'));
  sel.replaceChildren(...opts);
}

function renderSteps() {
  const t = pv.traces.find((x) => x.id === pv.trace);
  const key = t ? t.id + JSON.stringify(t.steps) : '';
  if (key === pv.lastSteps) return;
  pv.lastSteps = key;
  const ol = $('#steps');
  if (!t) { ol.replaceChildren(h('li', { class: 'muted' }, 'Send a line. Each step of its trip shows up here.')); return; }
  ol.replaceChildren(...t.steps.map((s, i) => h('li', {},
    h('span', { class: 'n' }, String(i + 1).padStart(2, '0')),
    h('span', { class: 't' }, clock(s.ts)),
    h('span', { class: 'tag ' + s.zone }, zoneTag[s.zone] || ''),
    h('span', { class: 'stage' }, s.stage),
    h('span', {}, s.title),
    s.detail ? h('span', { class: 'detail' }, s.detail) : null)));
  ol.scrollTop = ol.scrollHeight;
}

async function poll() {
  try {
    const s = await api('/api/state');
    pv.stages = s.stages;
    pv.traces = s.traces;
    if (!pv.trace && s.traces.length) pv.trace = s.traces[s.traces.length - 1].id;
    $('#ctx').textContent = `project ${s.project} · cluster ${s.kube_context || 'in-cluster'}`;
    $('#proj').textContent = s.project;
    $('#lv-proj').textContent = s.project;
    renderPipeline();
    renderTraces();
    renderSteps();
  } catch (e) {
    $('#ctx').textContent = 'demo server not reachable';
  }
}

let inspecting = false;
async function inspect() {
  if (inspecting) return;
  inspecting = true;
  try {
    const r = await api(`/api/inspect?trace=${encodeURIComponent(pv.trace || '')}&stage=${encodeURIComponent(pv.stages[pv.stage] || '')}`);
    $('#ins-source').textContent = r.source ? '(' + r.source + ')' : '';
    const box = $('#ins-lines');
    const top = box.scrollTop;
    box.replaceChildren(...r.lines.map((l) => h('div', { class: l.kind === 'head' ? 'head' : 'k-' + l.kind }, l.text)));
    box.scrollTop = top;
  } finally { inspecting = false; }
}

// composer
const form = $('#compose');
function composed() {
  const f = new FormData(form);
  return { level: f.get('level'), stream: f.get('stream'), session: f.get('session'), attrs: f.get('attrs'), msg: f.get('msg') };
}
function preview() {
  const c = composed();
  const attrs = {};
  for (const p of c.attrs.split(/\s+/).filter(Boolean)) {
    const i = p.indexOf('=');
    if (i <= 0) {
      $('#preview').className = 'preview mono small err';
      $('#preview').textContent = `attributes must be key=value pairs separated by spaces (got "${p}")`;
      return;
    }
    attrs[p.slice(0, i)] = p.slice(i + 1);
  }
  attrs.trace = 't_……';
  const rec = { ts: '…', level: c.level, msg: c.msg };
  if (c.session.trim()) rec.session_id = c.session.trim();
  rec.attrs = attrs;
  $('#preview').className = 'preview mono small';
  $('#preview').textContent = `${c.stream} will get: ${JSON.stringify(rec)}`;
}
form.addEventListener('input', preview);
form.addEventListener('submit', async (e) => {
  e.preventDefault();
  const res = await api('/api/send', composed());
  status(res);
  if (res.trace) { pv.trace = res.trace; pv.stage = 0; await poll(); inspect(); }
});
form.msg.addEventListener('keydown', (e) => { if (e.key === 'Enter' && !e.shiftKey) { e.preventDefault(); form.requestSubmit(); } });
$('#trace-sel').addEventListener('change', (e) => { pv.trace = e.target.value; pv.lastSteps = ''; renderPipeline(); renderSteps(); inspect(); });

// actions
$$('[data-read]').forEach((b) => b.addEventListener('click', async () => {
  if (!pv.trace) return status({ status: 'Send a line first.', zone: 'info' });
  status({ status: 'Reading as ' + b.textContent.toLowerCase() + '…', zone: 'info' });
  status(await api('/api/read', { trace: pv.trace, as: b.dataset.read }));
  poll();
}));
$('#scan').addEventListener('click', async () => {
  status({ status: 'Scanning every object in the bucket and every row in ClickHouse…', zone: 'info' });
  status(await api('/api/scan', { trace: pv.trace || '' }));
  poll();
});
$('#plaintext').addEventListener('click', async () => status(await api('/api/plaintext', {})));
$('#purge').addEventListener('click', async () => {
  if (!confirm("Destroy today's keys for the demo project? Every log written today becomes unreadable for good.")) return;
  status(await api('/api/purge', {}));
  poll();
});

// ---------------- logs view ----------------
const LEVELS = ['debug', 'info', 'warn', 'error'];
const SOURCES = { sidecar: 'Hosted agent', sdk: 'SDK' };
const lv = {
  since: '1h', as: 'member', text: '', levels: new Set(), sources: new Set(), session: '',
  data: null, rows: [], sel: -1, loading: false,
  live: false, es: null, fresh: new Set(), grants: [], grantSig: '',
};

function parseQuery(s) {
  const words = [];
  for (const tok of s.trim().split(/\s+/).filter(Boolean)) {
    const m = tok.match(/^(level|severity|source|session):(.+)$/i);
    if (!m) { words.push(tok); continue; }
    const [, k, v] = m;
    if (k === 'level' || k === 'severity') v.toLowerCase().split(',').forEach((x) => LEVELS.includes(x) && lv.levels.add(x));
    if (k === 'source') v.toLowerCase().split(',').forEach((x) => lv.sources.add(x));
    if (k === 'session') lv.session = v;
  }
  lv.text = words.join(' ');
}

function renderChips() {
  const chips = [];
  const chip = (label, clear) => h('button', { class: 'chip', type: 'button', title: 'Remove filter', onclick: () => { clear(); lv.load(); } }, label);
  if (lv.levels.size) chips.push(chip('level:' + [...lv.levels].join(','), () => lv.levels.clear()));
  if (lv.sources.size) chips.push(chip('source:' + [...lv.sources].join(','), () => lv.sources.clear()));
  if (lv.session) chips.push(chip('session:' + lv.session, () => { lv.session = ''; }));
  if (lv.text) chips.push(chip('"' + lv.text + '"', () => { lv.text = ''; }));
  $('#lv-chips').replaceChildren(...chips);
}

function buildRows(data) {
  const chunks = new Map((data.chunks || []).map((c) => [c.chunk_id, c]));
  const rows = (data.lines || []).map((l) => ({ kind: 'line', ts: l.ts, level: l.level, msg: l.msg, session: l.session_id,
    chunk: chunks.get(l.chunk_id), stream: l.stream, attrs: l.attrs || {}, source: (chunks.get(l.chunk_id) || {}).source }));
  for (const c of data.chunks || []) {
    if (c.status === 'decrypted') continue;
    rows.push({ kind: 'sealed', ts: c.ts_max || c.ts_min, session: c.session_id, source: c.source, chunk: c,
      level: LEVELS.slice().reverse().find((l) => (c.levels || {})[l] > 0) || 'info' });
  }
  rows.sort((a, b) => new Date(b.ts) - new Date(a.ts));
  return rows;
}

function visible(r) {
  if (lv.sources.size && !lv.sources.has(r.source)) return false;
  if (!lv.levels.size) return true;
  if (r.kind === 'line') return lv.levels.has(r.level);
  return [...lv.levels].some((l) => (r.chunk.levels || {})[l] > 0);
}

lv.load = async function () {
  renderChips();
  if (lv.loading) return;
  lv.loading = true;
  if (!lv.data) $('#lv-empty').textContent = 'Loading logs…';
  try {
    const q = new URLSearchParams({ as: lv.as, since: lv.since, q: lv.text, session: lv.session });
    const startedAt = new Date().toISOString();
    const r = await fetch('/api/logs?' + q);
    lv.data = await r.json();
    if (!r.ok) throw new Error(lv.data.error || r.status);
    lv.allRows = buildRows(lv.data);
    lv.render();
    if (lv.live) startTail(startedAt);
  } catch (e) {
    lv.allRows = [];
    $('#lv-rows').replaceChildren();
    $('#lv-hist').replaceChildren();
    $('#lv-note').textContent = String(e.message || e);
    $('#lv-empty').textContent = 'Logs could not be loaded.';
  } finally { lv.loading = false; }
};

lv.render = function () {
  const all = lv.allRows || [];
  const prevKey = lv.rows[lv.sel] && rowKey(lv.rows[lv.sel]);
  lv.rows = all.filter(visible);
  lv.sel = prevKey ? lv.rows.findIndex((r) => rowKey(r) === prevKey) : -1;

  const caller = lv.data.caller || {};
  const chunks = lv.data.chunks || [];
  const sealedN = chunks.filter((c) => c.status !== 'decrypted').length;
  $('#lv-note').textContent = `Querying as ${caller.sub} (${caller.role}${caller.project ? ', ' + caller.project : ''}). ` +
    `The index matched ${chunks.length} chunk(s): ${chunks.length - sealedN} decrypted, ${sealedN} still sealed.`;

  const longRange = ['24h', '168h'].includes(lv.since);
  $('#lv-rows').replaceChildren(...lv.rows.map((r, i) => {
    const src = h('span', { class: 'src' }, SOURCES[r.source] || r.source || '—');
    if (r.kind === 'line') {
      return h('tr', { class: (i === lv.sel ? 'sel' : '') + (lv.fresh.has(rowKey(r)) ? ' fresh' : ''), onclick: () => select(i) },
        h('td', { class: 'lvl' }, h('span', { class: 'lvbar ' + r.level, title: r.level })),
        h('td', { class: 'time' }, clock(r.ts, longRange)), h('td', {}, src),
        h('td', { class: 'mono small' }, r.session || ''), h('td', { class: 'msg', title: r.msg }, r.msg));
    }
    const c = r.chunk;
    const destroyed = c.status === 'destroyed';
    return h('tr', { class: 'sealed-row denied' + (i === lv.sel ? ' sel' : '') + (lv.fresh.has(rowKey(r)) ? ' fresh' : ''), onclick: () => select(i) },
      h('td', { class: 'lvl' }, h('span', { class: 'lvbar ' + (destroyed ? 'denied' : 'sealed') })),
      h('td', { class: 'time' }, clock(r.ts, longRange)), h('td', {}, src),
      h('td', { class: 'mono small' }, r.session || ''),
      h('td', { class: 'msg' }, h('span', { class: 'lock' }, destroyed ? '✕' : '🔒'),
        `${destroyed ? 'Key destroyed' : 'Sealed'} · ${c.lines} line${c.lines === 1 ? '' : 's'} · `,
        h('span', { class: 'why' }, c.reason || c.status), `  ct=${c.ct_preview || ''}…`));
  }));

  const filtered = lv.levels.size || lv.sources.size || lv.session || lv.text;
  $('#lv-empty').textContent = lv.rows.length ? '' : filtered ? 'No logs match this filter in the selected window.' : 'No logs in the selected window.';
  renderHist(lv.rows);
  renderFields(all);
  renderDetail();
};

const rowKey = (r) => r.kind + (r.chunk ? r.chunk.chunk_id : '') + r.ts + (r.msg || '');

function renderHist(rows) {
  const span = { '15m': 9e5, '1h': 36e5, '4h': 144e5, '24h': 864e5, '168h': 6048e5 }[lv.since];
  const n = 48, now = Date.now(), from = now - span;
  const buckets = Array.from({ length: n }, () => ({ debug: 0, info: 0, warn: 0, error: 0, sealed: 0 }));
  for (const r of rows) {
    const i = Math.min(n - 1, Math.max(0, Math.floor(((new Date(r.ts) - from) / span) * n)));
    if (r.kind === 'line') buckets[i][r.level]++;
    else buckets[i].sealed += r.chunk.lines || 1;
  }
  const max = Math.max(1, ...buckets.map((b) => b.debug + b.info + b.warn + b.error + b.sealed));
  $('#lv-hist').replaceChildren(...buckets.map((b) => {
    const parts = ['debug', 'info', 'warn', 'error', 'sealed'].filter((k) => b[k]);
    const title = parts.map((k) => `${k}: ${b[k]}`).join(', ') || 'no logs';
    return h('div', { class: 'bar', title }, ...parts.map((k) => {
      const seg = h('i', { class: k });
      seg.style.height = (b[k] / max) * 100 + '%';
      return seg;
    }));
  }));
}

function renderFields(all) {
  const count = (fn) => {
    const m = new Map();
    for (const r of all) for (const [k, v] of fn(r)) m.set(k, (m.get(k) || 0) + v);
    return [...m.entries()].sort((a, b) => b[1] - a[1]);
  };
  const levelCounts = count((r) => (r.kind === 'line' ? [[r.level, 1]] : LEVELS.map((l) => [l, (r.chunk.levels || {})[l] || 0]).filter((x) => x[1])));
  const sourceCounts = count((r) => [[r.source || '—', r.kind === 'line' ? 1 : r.chunk.lines]]);
  const sessionCounts = count((r) => [[r.session || '—', r.kind === 'line' ? 1 : r.chunk.lines]]);
  const group = (title, entries, isOn, toggle, fmt = (k) => k) => h('div', {}, h('h3', {}, title),
    entries.length ? entries.map(([k, c]) => h('label', {}, h('input', { type: 'checkbox', checked: isOn(k), onchange: () => toggle(k) }),
      h('span', { class: title === 'Session' ? 'mono' : '' }, fmt(k)), h('span', { class: 'cnt' }, c)))
      : h('div', { class: 'small muted' }, 'No values in this window'));
  const flip = (set, k) => { set.has(k) ? set.delete(k) : set.add(k); lv.render(); renderChips(); };
  $('#lv-fields').replaceChildren(
    group('Level', LEVELS.map((l) => [l, (levelCounts.find((x) => x[0] === l) || [l, 0])[1]]), (k) => lv.levels.has(k), (k) => flip(lv.levels, k)),
    group('Source', sourceCounts, (k) => lv.sources.has(k), (k) => flip(lv.sources, k), (k) => SOURCES[k] || k),
    group('Session', sessionCounts, (k) => lv.session === k, (k) => { lv.session = lv.session === k ? '' : k; lv.load(); }),
    h('p', { class: 'small muted' }, 'Counts for sealed chunks come from the index, which every caller can read. Their text never leaves the bucket.'));
}

function select(i) {
  lv.sel = lv.sel === i ? -1 : i;
  lv.render();
}

function renderDetail() {
  const el = $('#lv-detail');
  const r = lv.rows[lv.sel];
  $('.lv-body').classList.toggle('with-detail', !!r);
  el.hidden = !r;
  if (!r) return;
  const c = r.chunk || {};
  const kv = (pairs) => h('dl', {}, ...pairs.filter(([, v]) => v !== undefined && v !== '').flatMap(([k, v]) => [h('dt', {}, k), h('dd', {}, String(v))]));
  const json = r.kind === 'line'
    ? { ts: r.ts, level: r.level, msg: r.msg, session_id: r.session, stream: r.stream, source: r.source, chunk_id: c.chunk_id, key_id: c.key_id, attrs: r.attrs }
    : { chunk_id: c.chunk_id, key_id: c.key_id, status: c.status, reason: c.reason, session_id: c.session_id, source: c.source,
        ts_min: c.ts_min, ts_max: c.ts_max, lines: c.lines, levels: c.levels, ct_preview: c.ct_preview, ct_bytes: c.ct_bytes };
  el.replaceChildren(
    h('div', { class: 'dh' }, h('h2', {}, r.kind === 'line' ? 'Log line' : c.status === 'destroyed' ? 'Destroyed chunk' : 'Sealed chunk'),
      h('div', {}, h('button', { class: 'btn', type: 'button', onclick: () => navigator.clipboard && navigator.clipboard.writeText(JSON.stringify(json, null, 2)) }, 'Copy JSON'),
        ' ', h('button', { class: 'btn', type: 'button', onclick: () => select(lv.sel) }, 'Close'))),
    ...(r.kind === 'line'
      ? [kv([['Time', new Date(r.ts).toISOString()], ['Level', r.level], ['Source', SOURCES[r.source] || r.source], ['Session', r.session],
          ['Stream', r.stream], ['Chunk', c.chunk_id], ['Key', c.key_id]]),
        h('pre', { class: 'k-plain' }, r.msg),
        h('h3', { class: 'small muted' }, 'Attributes'), h('pre', {}, JSON.stringify(r.attrs, null, 2))]
      : [h('p', { class: 'small' }, c.status === 'destroyed'
          ? "This chunk's key was destroyed. The ciphertext is still in the bucket, and nobody can read it again."
          : `This chunk's text is sealed. keysvc only unwraps its key for members of ${(c.key_id || '').split('/')[0]}, or for operator staff they've given temporary access.`),
        kv([['Status', c.status], ['Reason', c.reason], ['Session', c.session_id], ['Source', SOURCES[c.source] || c.source],
          ['From', c.ts_min && new Date(c.ts_min).toISOString()], ['To', c.ts_max && new Date(c.ts_max).toISOString()],
          ['Lines', c.lines], ['Levels', LEVELS.filter((l) => (c.levels || {})[l]).map((l) => `${l} ${c.levels[l]}`).join(', ')],
          ['Chunk', c.chunk_id], ['Key', c.key_id], ['Ciphertext', `${c.ct_preview || ''}…  (${c.ct_bytes} B)`]])]),
    h('div', { class: 'foot' }, 'Use ↑/↓ to view the previous or next log, Esc to close.'));
}

document.addEventListener('keydown', (e) => {
  if (view !== 'logs' || lv.sel < 0 || ['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement.tagName)) return;
  if (e.key === 'ArrowDown' && lv.sel < lv.rows.length - 1) { e.preventDefault(); lv.sel++; lv.render(); }
  if (e.key === 'ArrowUp' && lv.sel > 0) { e.preventDefault(); lv.sel--; lv.render(); }
  if (e.key === 'Escape') { lv.sel = -1; lv.render(); }
  const tr = $('#lv-rows tr.sel');
  if (tr) tr.scrollIntoView({ block: 'nearest' });
});

$('#lv-q').addEventListener('keydown', (e) => {
  if (e.key !== 'Enter') return;
  parseQuery(e.target.value);
  e.target.value = '';
  lv.load();
});
$('#lv-as').addEventListener('change', (e) => { lv.as = e.target.value; lv.sel = -1; lv.grantSig = ''; lv.load(); loadGrants(); });
$$('#lv-range button').forEach((b) => b.addEventListener('click', () => {
  lv.since = b.dataset.since;
  $$('#lv-range button').forEach((x) => x.setAttribute('aria-pressed', x === b));
  lv.load();
}));
$('#lv-refresh').addEventListener('click', () => lv.load());
$('#lv-live').addEventListener('change', (e) => {
  lv.live = e.target.checked;
  if (lv.live) lv.load(); else stopTail();
});

// ---------------- live tail ----------------
// The aggregator streams new chunks as server-sent events, decrypted (or not)
// for the chosen identity exactly as a query would be. Rows merge into the view.
function stopTail() {
  if (lv.es) lv.es.close();
  lv.es = null;
  $('#lv-live-dot').hidden = true;
}

function startTail(after) {
  stopTail();
  const q = new URLSearchParams({ as: lv.as, q: lv.text, session: lv.session, after });
  if (lv.levels.size === 1) q.set('level', [...lv.levels][0]);
  const es = new EventSource('/api/tail?' + q);
  lv.es = es;
  const dot = $('#lv-live-dot');
  dot.hidden = false;
  dot.className = 'live-dot small';
  dot.textContent = '● Live';
  es.addEventListener('chunk', (m) => {
    const { chunk, lines } = JSON.parse(m.data);
    if (!lv.data) return;
    const chunks = lv.data.chunks || (lv.data.chunks = []);
    if (chunks.some((c) => c.chunk_id === chunk.chunk_id)) return;
    chunks.push(chunk);
    lv.data.lines = (lv.data.lines || []).concat(lines || []);
    const before = new Set((lv.allRows || []).map(rowKey));
    lv.allRows = buildRows(lv.data);
    for (const r of lv.allRows) if (!before.has(rowKey(r))) lv.fresh.add(rowKey(r));
    lv.render();
    setTimeout(() => lv.fresh.clear(), 2500);
  });
  // A key was destroyed, or someone's access ended: what's on screen may now be
  // out of date, so reload it all (which restarts the tail).
  es.addEventListener('revoked', () => lv.load());
  es.onerror = () => { dot.className = 'live-dot small down'; dot.textContent = '● Reconnecting'; };
  es.onopen = () => { dot.className = 'live-dot small'; dot.textContent = '● Live'; };
}

// ---------------- support access ----------------
// Operator staff can't read a customer's logs. They can ask for time-boxed
// access; a member of the project approves or denies it, and can end it early.
// keysvc enforces all of it; this panel only shows and asks.
const fmtLeft = (ms) => { const s = Math.max(0, Math.round(ms / 1000)); return `${Math.floor(s / 60)}:${String(s % 60).padStart(2, '0')}`; };

async function loadGrants() {
  if (view !== 'logs' || lv.as === 'other') { $('#lv-access').hidden = true; return; }
  try {
    const r = await fetch('/api/grants?as=' + lv.as);
    lv.grants = r.ok ? await r.json() : [];
  } catch { lv.grants = []; }
  const sig = lv.as + JSON.stringify(lv.grants.map((g) => [g.id, g.status]));
  if (lv.grantSig && sig !== lv.grantSig) lv.load(); // access changed: re-query
  lv.grantSig = sig;
  renderAccess();
}

async function grantAction(id, action, as) {
  const r = await fetch(`/api/grants/${id}/${action}?as=${as}`, { method: 'POST' });
  const out = await r.json();
  if (!r.ok) status({ status: out.error || 'failed', zone: 'denied' });
  loadGrants();
}

function renderAccess() {
  const el = $('#lv-access');
  const proj = $('#lv-proj').textContent || 'the project';
  const gs = lv.grants || [];
  const active = gs.filter((g) => g.status === 'active');
  const pending = gs.filter((g) => g.status === 'pending');
  const ended = gs.filter((g) => !['active', 'pending'].includes(g.status)).slice(0, 3);
  const hist = ended.length ? h('div', { class: 'hist' }, 'Earlier: ' + ended.map((g) =>
    `${g.id} ${g.status}${g.decided_by ? ' (' + (g.ended_by || g.decided_by) + ')' : ''}`).join(' · ')) : null;
  el.hidden = false;
  el.classList.toggle('active', active.length > 0);

  if (lv.as === 'staff') {
    const g = active[0];
    if (g) {
      el.replaceChildren(h('div', { class: 'row' },
        h('span', {}, '🔓'),
        h('span', { class: 'grow' }, `Temporary access to ${g.project}, approved by ${g.decided_by}. You can read its logs for `,
          h('span', { class: 'left', 'data-expires': g.expires_at }, fmtLeft(new Date(g.expires_at) - Date.now())), '.'),
        h('button', { class: 'btn', type: 'button', onclick: () => grantAction(g.id, 'revoke', 'staff') }, 'End access now')), hist);
      return;
    }
    if (pending[0]) {
      const p = pending[0];
      el.replaceChildren(h('div', { class: 'row' }, h('span', {}, '⏳'),
        h('span', { class: 'grow' }, `Access requested for ${p.minutes} min ("${p.reason}"). Waiting for a member of ${p.project} to approve. `,
          h('span', { class: 'muted' }, 'Switch Viewing as to the project member to approve it.'))), hist);
      return;
    }
    const reason = h('input', { value: 'Ticket #4821: customer reports failed card charges', 'aria-label': 'Reason' });
    const mins = h('select', { 'aria-label': 'Duration' }, h('option', { value: '2' }, '2 min'), h('option', { value: '15', selected: true }, '15 min'), h('option', { value: '60' }, '1 hour'));
    el.replaceChildren(
      h('div', { class: 'row' }, h('span', {}, '🔒'), h('span', { class: 'grow' },
        `You can see when and where ${proj} logged, not what it said. To read it, ask the customer for temporary access.`)),
      h('div', { class: 'row' }, reason, mins, h('button', { class: 'btn primary', type: 'button', onclick: async () => {
        const r = await fetch('/api/grants', { method: 'POST', headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ reason: reason.value, minutes: Number(mins.value) }) });
        const out = await r.json();
        status(r.ok ? { status: `Requested ${out.id}. A member of ${proj} has to approve it.`, zone: 'key' } : { status: out.error, zone: 'denied' });
        loadGrants();
      } }, 'Request access')), hist);
    return;
  }

  // project member
  const rows = [];
  for (const p of pending) rows.push(h('div', { class: 'row' }, h('span', {}, '🙋'),
    h('span', { class: 'grow' }, h('b', {}, p.grantee), ` (operator staff) asks for ${p.minutes} min of access to read ${p.project}'s logs: "${p.reason}"`),
    h('button', { class: 'btn primary', type: 'button', onclick: () => grantAction(p.id, 'approve', 'member') }, 'Approve'),
    h('button', { class: 'btn', type: 'button', onclick: () => grantAction(p.id, 'deny', 'member') }, 'Deny')));
  for (const g of active) rows.push(h('div', { class: 'row' }, h('span', {}, '🔓'),
    h('span', { class: 'grow' }, h('b', {}, g.grantee), ` can read ${g.project}'s logs for `,
      h('span', { class: 'left', 'data-expires': g.expires_at }, fmtLeft(new Date(g.expires_at) - Date.now())), ` (approved by ${g.decided_by}).`),
    h('button', { class: 'btn danger', type: 'button', onclick: () => grantAction(g.id, 'revoke', 'member') }, 'Revoke')));
  if (!rows.length) { if (!hist) { el.hidden = true; return; } rows.push(h('div', { class: 'small muted' }, 'No support access requests.')); }
  el.replaceChildren(...rows, hist);
}

setInterval(() => {
  for (const s of $$('#lv-access [data-expires]')) {
    const left = new Date(s.dataset.expires) - Date.now();
    s.textContent = fmtLeft(left);
    if (left <= 0) loadGrants();
  }
}, 1000);
setInterval(loadGrants, 2000);

// ---------------- start ----------------
preview();
showView(location.hash === '#logs' ? 'logs' : 'pipeline');
window.addEventListener('hashchange', () => showView(location.hash === '#logs' ? 'logs' : 'pipeline'));
poll().then(inspect);
setInterval(() => { if (view === 'pipeline') poll(); }, 700);
setInterval(() => { if (view === 'pipeline') inspect(); }, 2000);
