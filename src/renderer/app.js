/* Power Scan window. Renders engine events; every action goes through window.powerScan. */
(() => {
  'use strict';
  const api = window.powerScan;

  /* ---------- helpers ---------- */
  const $ = (s, r = document) => r.querySelector(s);
  const $$ = (s, r = document) => Array.from(r.querySelectorAll(s));
  const NS = 'http://www.w3.org/2000/svg';
  const esc = (s) => String(s == null ? '' : s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
  const fmtN = (n) => Math.round(n || 0).toLocaleString('en-US');
  const baseName = (p) => String(p || '').split(/[\\/]/).pop();
  const clockStr = (t) => new Date(t).toLocaleTimeString([], { hour: 'numeric', minute: '2-digit' });
  const dayStr = (t) => { const d = new Date(t); const today = new Date(); return d.toDateString() === today.toDateString() ? 'Today, ' + clockStr(t) : d.toLocaleDateString([], { month: 'short', day: 'numeric' }) + ', ' + clockStr(t); };
  const dur = (ms) => { const s = Math.max(0, Math.round(ms / 1000)); const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), x = s % 60; return (h ? h + ':' + String(m).padStart(2, '0') : String(m).padStart(2, '0')) + ':' + String(x).padStart(2, '0'); };
  const fmtSpeed = (v) => (v == null ? '—' : v < 100 ? Number(v).toFixed(1) : String(Math.round(v)));
  const plural = (n, w) => `${n} ${w}${n === 1 ? '' : 's'}`;

  const svgIcon = (body, sw) => `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="${sw || 2}" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${body}</svg>`;
  const IC = {
    power: svgIcon('<path d="M12 3.5v8"/><path d="M6.6 7.2a7.6 7.6 0 1 0 10.8 0"/>', 2.3),
    check: svgIcon('<path d="M5 12.5l4.5 4.5L19 7.5"/>', 2.6),
    warn: svgIcon('<path d="M12 4.5l8.5 15h-17z"/><path d="M12 10.5v4"/><path d="M12 17.2v.01"/>', 2),
    okc: svgIcon('<circle cx="12" cy="12" r="8.5"/><path d="M8.3 12.3l2.6 2.6 4.9-5.4"/>', 2),
    warnc: svgIcon('<circle cx="12" cy="12" r="8.5"/><path d="M12 7.8v5"/><path d="M12 16.2v.01"/>', 2),
    badc: svgIcon('<circle cx="12" cy="12" r="8.5"/><path d="M9.2 9.2l5.6 5.6M14.8 9.2l-5.6 5.6"/>', 2),
    upc: svgIcon('<circle cx="12" cy="12" r="8.5"/><path d="M12 16V8.6"/><path d="M8.7 11.6L12 8.3l3.3 3.3"/>', 2),
    infoc: svgIcon('<circle cx="12" cy="12" r="8.5"/><path d="M12 11v5"/><path d="M12 7.9v.01"/>', 2),
    x: svgIcon('<path d="M6.5 6.5l11 11M17.5 6.5l-11 11"/>', 2),
  };
  const FIND_IC = { bad: IC.warnc, up: IC.upc, info: IC.infoc, ok: IC.okc };
  const CAT = {
    display: svgIcon('<rect x="3.5" y="4.5" width="17" height="11" rx="1.5"/><path d="M9 19.5h6M12 15.5v4"/>', 1.8),
    net: svgIcon('<path d="M4.5 9.6a11 11 0 0 1 15 0"/><path d="M7.4 12.8a6.6 6.6 0 0 1 9.2 0"/><path d="M10.3 15.9a2.4 2.4 0 0 1 3.4 0"/><path d="M12 18.8v.01"/>', 1.8),
    audio: svgIcon('<path d="M5 9.5h3l4-3.5v12l-4-3.5H5z"/><path d="M15.5 9.5a3.5 3.5 0 0 1 0 5"/><path d="M17.8 7.2a6.8 6.8 0 0 1 0 9.6"/>', 1.8),
    chip: svgIcon('<rect x="7" y="7" width="10" height="10" rx="1.5"/><path d="M10 3.5V7M14 3.5V7M10 17v3.5M14 17v3.5M3.5 10H7M3.5 14H7M17 10h3.5M17 14h3.5"/>', 1.8),
  };

  /* ---------- state ---------- */
  const S = {
    info: null, tab: 'scan', phases: { scan: ['Kernel', 'Boot', 'Startup', 'Programs', 'Files'], drivers: ['Inventory', 'Versions', 'Health', 'Performance'] },
    scan: { status: 'idle', findings: [], log: [] }, lastScanAt: null,
    listener: { on: false, phase: 'off', note: '', watch: [] }, traffic: [],
    speed: { status: 'idle', vals: {}, samples: [] },
    drv: { status: 'idle', issues: [], log: [] }, lastDriverCheckAt: null,
  };
  const isWin = () => !S.info || S.info.platform === 'win';

  /* ---------- DOM ---------- */
  const tabs = $('#tabs');
  const TAB_ORDER = ['scan', 'speed', 'drivers'];
  const TAB_BTN = { scan: $('#tabScan'), speed: $('#tabSpeed'), drivers: $('#tabDrivers') };
  const TAB_PANEL = { scan: $('#panelScan'), speed: $('#panelSpeed'), drivers: $('#panelDrivers') };
  const scanScroll = $('#scanScroll'), speedScroll = $('#speedScroll'), drvScroll = $('#drvScroll');
  const scanChip = $('#scanChip'), scanEngine = $('#scanEngine'), scanDial = $('#scanDial'), scanPower = $('#scanPower'), scanCaption = $('#scanCaption');
  const scanFeed = $('#scanFeed'), scanPhases = $('#scanPhases'), scanLog = $('#scanLog'), scanResults = $('#scanResults'), scanGlance = $('#scanGlance'), scanNotes = $('#scanNotes');
  const cChecked = $('#cChecked'), cThreats = $('#cThreats'), cThreatsBox = $('#cThreatsBox'), cTime = $('#cTime');
  const traffic = $('#traffic'), listenerSwitch = $('#listenerSwitch'), listenerSub = $('#listenerSub'), listenerLive = $('#listenerLive');
  const speedChip = $('#speedChip'), speedDial = $('#speedDial'), speedPower = $('#speedPower'), speedCaption = $('#speedCaption');
  const speedPhases = $('#speedPhases'), readouts = $('#readouts'), monitor = $('#monitor'), monSvg = $('#monSvg'), diag = $('#diag');
  const drvChip = $('#drvChip'), drvEngine = $('#drvEngine'), drvDial = $('#drvDial'), drvPower = $('#drvPower'), drvCaption = $('#drvCaption');
  const drvFeed = $('#drvFeed'), drvPhases = $('#drvPhases'), drvLog = $('#drvLog'), drvResults = $('#drvResults'), drvGlance = $('#drvGlance');
  const dChecked = $('#dChecked'), dIssues = $('#dIssues'), dIssuesBox = $('#dIssuesBox'), dTime = $('#dTime');
  const banner = $('#banner'), sheetWrap = $('#sheetWrap'), sheet = $('#sheet');
  const dot = { scan: $('#dotScan'), speed: $('#dotSpeed'), drivers: $('#dotDrivers') };

  /* ---------- dials ---------- */
  const GAUGE = [0, 5, 10, 25, 50, 100, 250, 500, 1000];
  function buildRing(svgEl, o) {
    const ticks = [];
    for (let i = 0; i < o.count; i++) {
      const deg = o.start + (o.sweep === 360 ? (360 * i) / o.count : (o.sweep * i) / (o.count - 1));
      const a = (deg * Math.PI) / 180;
      const major = i % o.majorEvery === 0;
      const r1 = major ? o.rMajor : o.rIn;
      const l = document.createElementNS(NS, 'line');
      l.setAttribute('x1', (120 + r1 * Math.cos(a)).toFixed(2));
      l.setAttribute('y1', (120 + r1 * Math.sin(a)).toFixed(2));
      l.setAttribute('x2', (120 + o.rOut * Math.cos(a)).toFixed(2));
      l.setAttribute('y2', (120 + o.rOut * Math.sin(a)).toFixed(2));
      l.setAttribute('class', major ? 'tick major' : 'tick');
      svgEl.appendChild(l);
      ticks.push(l);
    }
    if (o.labels) {
      o.labels.forEach((v, k) => {
        const a = ((o.start + (o.sweep * k) / (o.labels.length - 1)) * Math.PI) / 180;
        const t = document.createElementNS(NS, 'text');
        t.setAttribute('x', (120 + o.rLabel * Math.cos(a)).toFixed(1));
        t.setAttribute('y', (120 + o.rLabel * Math.sin(a) + 3.8).toFixed(1));
        t.setAttribute('text-anchor', 'middle');
        t.setAttribute('class', 'gauge-label');
        t.textContent = v;
        svgEl.appendChild(t);
      });
      const u = document.createElementNS(NS, 'text');
      u.setAttribute('x', '120'); u.setAttribute('y', '226'); u.setAttribute('text-anchor', 'middle');
      u.setAttribute('class', 'gauge-unit'); u.textContent = 'MBPS';
      svgEl.appendChild(u);
    }
    return ticks;
  }
  const RING = { count: 60, start: -90, sweep: 360, rOut: 113, rIn: 104, rMajor: 99, majorEvery: 5 };
  const scanTicks = buildRing($('#scanRing'), RING);
  const drvTicks = buildRing($('#drvRing'), RING);
  const speedTicks = buildRing($('#speedRing'), { count: 49, start: 135, sweep: 270, rOut: 98, rIn: 90, rMajor: 85, majorEvery: 6, labels: GAUGE, rLabel: 110 });
  function setTicks(ticks, frac, arc) {
    const n = ticks.length;
    const on = frac <= 0 ? 0 : arc ? Math.round(frac * (n - 1)) + 1 : Math.round(frac * n);
    for (let i = 0; i < n; i++) ticks[i].classList.toggle('on', i < on);
  }
  function gaugeFrac(v) {
    if (!(v > 0)) return 0;
    if (v >= 1000) return 1;
    let i = 0;
    while (i < GAUGE.length - 1 && v > GAUGE[i + 1]) i++;
    return (i + (v - GAUGE[i]) / (GAUGE[i + 1] - GAUGE[i])) / (GAUGE.length - 1);
  }
  const stackHTML = (big, unit, tone) => `<span class="stack${tone ? ' ' + tone : ''}"><span class="big">${big}</span><span class="unit">${unit}</span></span>`;
  const setChip = (el, tone, text) => { el.className = 'chip' + (tone ? ' ' + tone : ''); el.textContent = text; };
  function scrollIntoPanel(container, el) {
    if (!el || el.hidden) return;
    const top = container.scrollTop + el.getBoundingClientRect().top - container.getBoundingClientRect().top - 10;
    container.scrollTo({ top: Math.max(0, top), behavior: 'smooth' });
  }
  function railHTML(labels) { return labels.map((l) => `<div class="ph"><span>${esc(l)}</span><div class="bar"><i></i></div></div>`).join(''); }
  function paintRail(container, idx, frac) {
    $$('.ph', container).forEach((el, i) => {
      el.classList.toggle('done', i < idx);
      el.classList.toggle('cur', i === idx);
      el.querySelector('i').style.width = (i < idx ? 100 : i === idx ? Math.round((frac || 0) * 100) : 0) + '%';
    });
  }
  function logHTML(log) {
    return log.map((e, k) => {
      const tone = e.tone || '';
      return `<li class="${tone}${k === log.length - 1 ? ' cur' : ''}"><span class="m">${tone ? '!' : '✓'}</span><span class="p">${e.dir ? `<span class="d">${esc(e.dir)}</span>` : ''}<span class="f">${esc(e.file)}</span></span><span class="s">${esc(e.sub || '')}</span></li>`;
    }).join('');
  }
  const pushLog = (arr, e) => { arr.push(e); if (arr.length > 8) arr.shift(); };
  let painting = false;
  const paintQueue = new Set();
  function schedule(fn) {
    paintQueue.add(fn);
    if (painting) return;
    painting = true;
    requestAnimationFrame(() => { painting = false; const fns = [...paintQueue]; paintQueue.clear(); fns.forEach((f) => f()); });
  }

  /* ---------- tabs ---------- */
  function setTab(t) {
    S.tab = t;
    tabs.dataset.tab = t;
    TAB_ORDER.forEach((k) => {
      TAB_BTN[k].setAttribute('aria-selected', String(k === t));
      TAB_BTN[k].tabIndex = k === t ? 0 : -1;
      TAB_PANEL[k].hidden = k !== t;
    });
    updateTabDots();
    if (t === 'speed') drawChart();
  }
  TAB_ORDER.forEach((k) => TAB_BTN[k].addEventListener('click', () => setTab(k)));
  tabs.addEventListener('keydown', (e) => {
    if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
    const i = TAB_ORDER.indexOf(S.tab);
    const next = TAB_ORDER[(i + (e.key === 'ArrowRight' ? 1 : TAB_ORDER.length - 1)) % TAB_ORDER.length];
    setTab(next);
    TAB_BTN[next].focus();
    e.preventDefault();
  });
  function updateTabDots() {
    const sc = S.scan, sp = S.speed, dv = S.drv;
    const tones = {
      scan: sc.status === 'running' ? 'run' : sc.status === 'threats' || S.traffic.some((t) => t.state === 'held') ? 'bad' : '',
      speed: ['running', 'retest', 'fixing'].includes(sp.status) ? 'run' : sp.status === 'bad' ? 'warn' : '',
      drivers: dv.status === 'running' || (dv.issues || []).some((i) => i.state === 'working' || i.state === 'queued') ? 'run' : dv.status === 'issues' ? 'warn' : '',
    };
    for (const k of TAB_ORDER) { dot[k].className = 'tab-dot ' + tones[k]; dot[k].hidden = S.tab === k || !tones[k]; }
  }

  /* ---------- sheet ---------- */
  let sheetConfirm = null, sheetReturn = null;
  function openSheet(o) {
    sheet.innerHTML = `<h3 id="sheetTitle">${esc(o.title)}</h3>${o.body}<div class="acts"><button class="btn" type="button" data-sheet="cancel">Cancel</button><button class="btn ${o.confirmClass || 'primary'}" type="button" data-sheet="ok">${esc(o.confirm)}</button></div>`;
    sheetConfirm = o.onConfirm;
    sheetReturn = document.activeElement;
    sheetWrap.hidden = false;
    sheet.querySelector('[data-sheet="ok"]').focus({ preventScroll: true });
  }
  function closeSheet() {
    if (sheetWrap.hidden) return;
    sheetWrap.hidden = true;
    sheetConfirm = null;
    if (sheetReturn && document.body.contains(sheetReturn)) { try { sheetReturn.focus({ preventScroll: true }); } catch (_) { /* gone */ } }
  }
  sheetWrap.addEventListener('click', (e) => {
    if (e.target === sheetWrap) { closeSheet(); return; }
    const b = e.target.closest('[data-sheet]');
    if (!b) return;
    if (b.dataset.sheet === 'ok') {
      const fn = sheetConfirm;
      const checked = $$('input[type="checkbox"]:checked', sheet).map((x) => x.value);
      closeSheet();
      if (fn) fn(checked);
    } else closeSheet();
  });
  sheet.addEventListener('change', () => {
    const boxes = $$('input[type="checkbox"]', sheet);
    if (boxes.length) sheet.querySelector('[data-sheet="ok"]').disabled = !boxes.some((x) => x.checked);
  });
  document.addEventListener('keydown', (e) => { if (e.key === 'Escape' && !sheetWrap.hidden) closeSheet(); });

  /* ---------- banner ---------- */
  let bannerTimer = null;
  function showBanner(html, tone) {
    banner.className = 'banner' + (tone ? ' ' + tone : '');
    banner.innerHTML = html;
    banner.hidden = false;
    clearTimeout(bannerTimer);
    bannerTimer = setTimeout(() => { banner.hidden = true; }, 10000);
  }

  /* ======================= Virus Scan ======================= */
  const scanCaps = () => [isWin() ? 'Checking kernel drivers' : 'Checking kernel modules', 'Checking boot protection', 'Reading startup entries', 'Checking running programs', 'Scanning every file'];
  const findingOpen = (f) => f.state === 'open' || f.state === 'removing' || f.state === 'failed';

  function renderScan() {
    const sc = S.scan;
    const list = sc.findings || [];
    const open = list.filter(findingOpen);
    const kept = list.filter((f) => f.state === 'kept').length;
    const restart = list.some((f) => f.state === 'removed-restart');
    scanEngine.textContent = S.info ? S.info.engineLabel : '';
    let chip;
    switch (sc.status) {
      case 'running': chip = ['run', `Scanning · pass ${(sc.phaseIdx || 0) + 1} of 5`]; break;
      case 'stopped': chip = ['warn', `Stopped at ${Math.floor((sc.progress || 0) * 100)}%`]; break;
      case 'threats': chip = ['bad', `${plural(open.length, 'item')} found`]; break;
      case 'resolved': chip = restart ? ['warn', 'Protected · restart to finish'] : kept ? ['warn', `Protected · ${kept} kept`] : ['ok', 'Protected']; break;
      case 'clean': chip = ['ok', 'Protected · nothing found']; break;
      default: chip = ['', S.lastScanAt ? 'Last scan ' + dayStr(S.lastScanAt) : 'Not scanned yet'];
    }
    setChip(scanChip, chip[0], chip[1]);
    scanDial.dataset.tone = sc.status === 'running' ? 'run' : sc.status === 'threats' ? 'bad' : sc.status === 'resolved' || sc.status === 'clean' ? 'ok' : '';
    scanDial.classList.toggle('is-running', sc.status === 'running');
    if (sc.status === 'running') {
      paintScan();
      scanPower.setAttribute('aria-label', 'Stop scan');
    } else {
      setTicks(scanTicks, sc.status === 'idle' ? 0 : sc.status === 'stopped' ? sc.progress || 0 : 1, false);
      if (sc.status === 'threats') scanPower.innerHTML = stackHTML(open.length, open.length === 1 ? 'to review' : 'to review');
      else if (sc.status === 'resolved' || sc.status === 'clean') scanPower.innerHTML = `<span class="stack">${IC.check}<span class="unit">Clean</span></span>`;
      else scanPower.innerHTML = `<span class="glyph">${IC.power}</span>`;
      scanPower.setAttribute('aria-label', sc.status === 'idle' ? 'Start full scan' : 'Scan again');
    }
    let cap = 'Press to scan everything, starting at the kernel';
    if (sc.status === 'running') cap = scanCaps()[sc.phaseIdx || 0];
    else if (sc.status === 'stopped') cap = 'Press to start a new full scan';
    else if (sc.finishedAt) cap = `Finished ${clockStr(sc.finishedAt)} · ${fmtN(sc.checked)} items · ${dur(sc.finishedAt - sc.startedAt)}`;
    scanCaption.textContent = cap;

    const notes = (sc.status === 'idle' || sc.status === 'stopped') ? ((S.info && S.info.notes) || []).map((text) => ({ tone: 'warn', text })) : sc.notes || [];
    scanNotes.innerHTML = sc.status === 'running' ? '' : notes.map((n) => (n.tone === 'info'
      ? `<div class="note info">${IC.infoc}<span>${esc(n.text)}</span></div>`
      : `<div class="note">${IC.warn}<span>${esc(n.text)}</span></div>`)).join('');
    scanFeed.hidden = sc.status !== 'running';
    scanResults.hidden = !(sc.status === 'threats' || sc.status === 'resolved' || (sc.status === 'stopped' && list.length));
    scanGlance.hidden = !(sc.status === 'idle' || sc.status === 'stopped' || sc.status === 'clean' || sc.status === 'resolved');
    if (!scanGlance.hidden) renderGlance();
    if (!scanResults.hidden) renderResults();
    renderTraffic();
    renderListener();
    updateTabDots();
  }

  function paintScan() {
    const sc = S.scan;
    setTicks(scanTicks, sc.progress || 0, false);
    scanPower.innerHTML = stackHTML(Math.floor((sc.progress || 0) * 100) + '<small>%</small>', 'Press to stop');
    paintRail(scanPhases, sc.phaseIdx || 0, sc.phaseFrac || 0);
    scanLog.innerHTML = logHTML(sc.log);
    cChecked.textContent = fmtN(sc.checked);
    cThreats.textContent = (sc.findings || []).length;
    cThreatsBox.classList.toggle('bad', (sc.findings || []).length > 0);
    cTime.textContent = dur(Date.now() - (sc.startedAt || Date.now()));
  }

  function renderGlance() {
    const L = S.listener;
    const tiles = ((S.info && S.info.glance) || []).concat([
      ['Last full scan', S.lastScanAt ? dayStr(S.lastScanAt) : 'Never', S.lastScanAt ? 'ok' : 'warn'],
      ['Passive Listener', L.phase === 'listening' ? 'Listening' : L.phase === 'baseline' ? 'Starting' : 'Off', L.phase === 'listening' ? 'ok' : L.phase === 'baseline' ? 'run' : ''],
    ]);
    scanGlance.innerHTML = tiles.map(([k, v, t]) => `<div class="tile"><span class="k">${esc(k)}</span><span class="v"><i class="dot ${t}"></i>${esc(v)}</span></div>`).join('');
  }

  function findingCard(f) {
    const sev = String(f.sev || 'Medium').toLowerCase();
    const nameCls = f.kind === 'file' ? 'tname' : 'fname';
    if (findingOpen(f)) {
      let acts;
      if (f.state === 'removing') acts = '<span class="working"><span class="spin"></span>Working</span>';
      else acts = (f.primary ? `<button class="btn primary sm" type="button" data-act="f-remove" data-id="${f.id}">${esc(f.primary.label)}</button>` : '') + (f.secondary ? `<button class="btn quiet sm" type="button" data-act="f-keep" data-id="${f.id}">${esc(f.secondary.label)}</button>` : '');
      return `<article class="threat" data-id="${f.id}"><div class="top"><span class="sev ${sev}">${esc(f.sev)}</span><span class="${nameCls}">${esc(f.name)}</span></div><p class="what">${esc(f.what)}</p>${f.path ? `<p class="path">${esc(f.path)}</p>` : ''}${f.state === 'failed' || f.message && f.state === 'open' ? `<p class="fail">${esc(f.message)}</p>` : ''}<div class="acts">${acts}</div></article>`;
    }
    const kept = f.state === 'kept';
    const tone = kept ? 'warn' : 'ok';
    return `<article class="threat done" data-id="${f.id}"><span class="done-ic ${tone}">${kept ? IC.warn : IC.check}</span><div class="done-t"><span class="${nameCls}">${esc(f.name)}</span><span class="done-s ${tone}">${esc(f.message || (kept ? 'Kept' : 'Done'))}</span></div></article>`;
  }

  function renderResults() {
    const sc = S.scan, list = sc.findings || [];
    const open = list.filter((f) => f.state === 'open');
    const removable = open.filter((f) => f.kind === 'file' && f.primary);
    const pending = list.filter(findingOpen).length;
    let h = sc.status === 'threats' || (sc.status === 'stopped' && pending)
      ? `<div class="results-head"><h3>${pending} item${pending === 1 ? ' needs' : 's need'} your decision</h3>${removable.length > 1 ? '<button class="btn primary sm" type="button" data-act="f-remove-all">Remove all threats</button>' : ''}</div>`
      : '<div class="results-head"><h3>Scan results</h3></div>';
    h += list.map(findingCard).join('');
    if (list.some((f) => f.state === 'removed-restart')) h += `<div class="note">${IC.warn}<span>Restart the computer to finish these changes.</span></div>`;
    scanResults.innerHTML = h;
  }

  function onFinding(id, action) {
    const f = (S.scan.findings || []).find((x) => x.id === id);
    if (!f || !findingOpen(f) || f.state === 'removing') return;
    if (action === 'remove' && f.primary) {
      openSheet({
        title: (f.confirm && f.confirm.title) || `${f.primary.label}?`,
        body: `${f.confirm && f.confirm.body ? `<p>${esc(f.confirm.body)}</p>` : ''}${f.path ? `<p class="sheet-path">${esc(f.path)}</p>` : ''}`,
        confirm: f.primary.label,
        onConfirm: () => scanAct(f, 'remove'),
      });
    } else if (action === 'keep') {
      if (f.kind === 'file') {
        openSheet({
          title: `Keep ${baseName(f.path)}?`,
          body: `<p>It was flagged as <b>${esc(f.name)}</b>. Keeping it leaves it on this computer and future scans skip it. Only keep files you trust.</p>`,
          confirm: 'Keep file', confirmClass: 'danger',
          onConfirm: () => scanAct(f, 'keep'),
        });
      } else scanAct(f, 'keep');
    }
  }
  async function scanAct(f, action) {
    if (action === 'remove') { f.state = 'removing'; renderResults(); }
    const r = await api.scan.act(f.id, action);
    if (r) updateFinding(r);
  }
  function updateFinding(nf) {
    const list = S.scan.findings || [];
    const i = list.findIndex((x) => x.id === nf.id);
    if (i >= 0) list[i] = nf; else list.push(nf);
    if (S.scan.status === 'threats' && !list.some(findingOpen)) S.scan.status = 'resolved';
    renderScan();
  }
  function removeAll() {
    const open = (S.scan.findings || []).filter((f) => f.state === 'open' && f.kind === 'file' && f.primary);
    if (!open.length) return;
    openSheet({
      title: `Remove ${plural(open.length, 'threat')}?`,
      body: `<ul class="sheet-list">${open.map((f) => `<li>${esc(f.name)}</li>`).join('')}</ul><p>${isWin() ? 'Microsoft Defender moves them to quarantine. You can restore them from Windows Security, Protection history.' : 'Power Scan moves them to quarantine.'}</p>`,
      confirm: `Remove ${open.length}`,
      onConfirm: async () => { for (const f of open) await scanAct(f, 'remove'); },
    });
  }

  scanPower.addEventListener('click', () => { if (S.scan.status === 'running') api.scan.stop(); else api.scan.start(); });
  setInterval(() => { if (S.scan.status === 'running') cTime.textContent = dur(Date.now() - (S.scan.startedAt || Date.now())); if (S.drv.status === 'running') dTime.textContent = dur(Date.now() - (S.drv.startedAt || Date.now())); if (S.speed.status === 'running' || S.speed.status === 'retest') schedule(paintSpeed); }, 500);

  api.on('scan', (e) => {
    const sc = S.scan;
    switch (e.type) {
      case 'start':
        S.scan = { status: 'running', phaseIdx: 0, phaseFrac: 0, progress: 0, checked: 0, log: [], findings: [], startedAt: e.startedAt };
        renderScan();
        setTimeout(() => scrollIntoPanel(scanScroll, scanFeed), 50);
        break;
      case 'phase': sc.phaseIdx = e.idx; sc.phaseFrac = 0; sc.progress = e.progress; renderScan(); break;
      case 'item': pushLog(sc.log, e); schedule(paintScan); break;
      case 'progress': sc.progress = e.progress; sc.phaseFrac = e.phaseFrac; sc.checked = e.checked; schedule(paintScan); break;
      case 'finding': (sc.findings = sc.findings || []).push(e.finding); schedule(paintScan); updateTabDots(); break;
      case 'stopped': sc.status = 'stopped'; sc.progress = e.progress; if (e.findings) sc.findings = e.findings; renderScan(); break;
      case 'done':
        S.scan = { ...e, log: sc.log };
        S.lastScanAt = e.finishedAt;
        renderScan();
        setTimeout(() => scrollIntoPanel(scanScroll, e.status === 'threats' ? scanResults : scanCaption), 80);
        break;
      case 'finding-update': updateFinding(e.finding); break;
      case 'resolved': sc.status = 'resolved'; renderScan(); break;
      default: break;
    }
  });

  /* ======================= Passive Listener + Traffic ======================= */
  function renderListener() {
    const L = S.listener;
    listenerSwitch.setAttribute('aria-checked', String(!!L.on));
    let sub;
    if (L.phase === 'listening') sub = 'Listening · ' + ((L.watch || []).join(', ') || 'Downloads');
    else if (L.phase === 'baseline') sub = 'Running the first full scan';
    else sub = L.note ? 'Off · ' + L.note : "Off · downloads aren't checked before they open";
    listenerSub.textContent = sub;
    listenerLive.hidden = L.phase !== 'listening';
  }
  listenerSwitch.addEventListener('click', async () => {
    listenerSwitch.disabled = true;
    try { S.listener = await api.listener.set(!S.listener.on); } finally { listenerSwitch.disabled = false; }
    renderScan();
  });
  api.on('listener', (l) => { S.listener = l; renderScan(); });

  const scannerName = () => (isWin() ? 'Microsoft Defender' : 'ClamAV');
  function trafficStateHTML(it) {
    switch (it.state) {
      case 'locked': return '<span>Locked · waiting to be checked</span>';
      case 'checking': return `<span class="run">Checking · ${Math.round((it.pct || 0) * 100)}%</span>`;
      case 'cleared': return '<span class="ok">Cleared · safe to open</span>';
      case 'held': return `<span class="bad">Held · ${esc(it.threat)}</span>`;
      case 'removed': return `<span>${esc(it.message || 'Removed · it never ran')}</span>`;
      case 'released': return '<span class="warn">Released by you</span>';
      case 'gone': return `<span class="ok">Removed by ${scannerName()} as it arrived</span>`;
      case 'unchecked': return `<span class="warn">Not checked</span> <span class="muted">${esc(it.what || '')}</span>`;
      default: return '';
    }
  }
  function trafficRow(it) {
    return `<div class="tr-row" data-id="${it.id}" data-state="${it.state}">
      <span class="light" aria-hidden="true"><i class="r"></i><i class="y"></i><i class="g"></i></span>
      <div class="tr-main">
        <div class="tr-name" title="${esc(it.name)}">${esc(it.name)}</div>
        <div class="tr-sub">${esc(it.size)} · ${esc(it.from)} · ${clockStr(it.at)}</div>
        <div class="tr-state">${trafficStateHTML(it)}</div>
        ${it.state === 'checking' ? `<div class="tr-prog"><i style="width:${Math.round((it.pct || 0) * 100)}%"></i></div>` : ''}
        ${it.state === 'held' ? `<p class="tr-what">${esc(it.what)}</p><div class="tr-acts"><button class="btn primary sm" type="button" data-act="tr-remove" data-id="${it.id}">Remove</button><button class="btn quiet sm" type="button" data-act="tr-keep" data-id="${it.id}">Keep</button></div>` : ''}
      </div>
    </div>`;
  }
  function renderTraffic() {
    traffic.hidden = !S.listener.on;
    if (!S.listener.on) return;
    const listening = S.listener.phase === 'listening';
    const items = S.traffic;
    const checked = items.filter((t) => t.state !== 'locked' && t.state !== 'checking').length;
    const held = items.filter((t) => t.state === 'held').length;
    let h = `<div class="traffic-head"><h3><span class="live-dot${listening ? ' on' : ''}"></span>Traffic</h3><span class="meta">${listening ? `${checked} checked${held ? ` · <b>${held} held</b>` : ''}` : 'Opens after the first scan'}</span></div>`;
    if (!listening) h += '<p class="traffic-empty">Traffic opens when the first full scan finishes.</p>';
    else if (!items.length) h += `<p class="traffic-empty">Waiting for downloads in ${esc((S.listener.watch || []).join(' and ') || 'your Downloads folder')}. New files stay locked here until ${scannerName()} has checked them.</p>`;
    else h += items.slice(0, 8).map(trafficRow).join('') + (items.length > 8 ? `<p class="traffic-more">${items.length - 8} earlier downloads</p>` : '');
    traffic.innerHTML = h;
  }
  function updateTrafficRow(it) {
    const row = traffic.querySelector(`.tr-row[data-id="${it.id}"]`);
    if (!row || row.dataset.state !== it.state) { renderTraffic(); return; }
    row.querySelector('.tr-state').innerHTML = trafficStateHTML(it);
    const bar = row.querySelector('.tr-prog i');
    if (bar) bar.style.width = Math.round((it.pct || 0) * 100) + '%';
  }
  function upsertTraffic(it) {
    const i = S.traffic.findIndex((x) => x.id === it.id);
    if (i >= 0) S.traffic[i] = it; else S.traffic.unshift(it);
  }
  api.on('traffic', (e) => {
    if (e.type === 'add') { upsertTraffic(e.item); renderTraffic(); }
    else if (e.type === 'update') { upsertTraffic(e.item); updateTrafficRow(e.item); updateTabDots(); }
    else if (e.type === 'held') {
      upsertTraffic(e.item);
      renderTraffic();
      updateTabDots();
      if (e.item.state === 'gone') showBanner(`<span class="b-ic">${IC.check}</span><div class="b-t"><b>${scannerName()} removed ${esc(e.item.name)}</b><span>It was harmful and never ran</span></div><button class="b-x" type="button" data-act="banner-x" aria-label="Dismiss">${IC.x}</button>`, 'info');
      else showBanner(`<span class="b-ic">${IC.warn}</span><div class="b-t"><b>Traffic held ${esc(e.item.name)}</b><span>${esc(e.item.threat)} · it was not opened</span></div><button class="btn sm" type="button" data-act="review" data-id="${e.item.id}">Review</button><button class="b-x" type="button" data-act="banner-x" aria-label="Dismiss">${IC.x}</button>`);
    }
  });
  function onTraffic(id, action) {
    const it = S.traffic.find((x) => x.id === id);
    if (!it || it.state !== 'held') return;
    if (action === 'remove') {
      openSheet({ title: `Remove ${it.name}?`, body: '<p>The download is deleted or quarantined. It never ran, so nothing else on this computer changed.</p>', confirm: 'Remove', onConfirm: async () => { banner.hidden = true; const r = await api.traffic.act(id, 'remove'); if (r) { upsertTraffic(r); renderTraffic(); updateTabDots(); } } });
    } else {
      openSheet({ title: `Keep ${it.name}?`, body: `<p>It was flagged as <b>${esc(it.threat)}</b>. Keeping it releases the file so it can run. Only keep files you trust.</p>`, confirm: 'Keep and release', confirmClass: 'danger', onConfirm: async () => { banner.hidden = true; const r = await api.traffic.act(id, 'keep'); if (r) { upsertTraffic(r); renderTraffic(); updateTabDots(); } } });
    }
  }
  function reviewTraffic(id) {
    setTab('scan');
    banner.hidden = true;
    setTimeout(() => {
      const row = traffic.querySelector(`.tr-row[data-id="${id}"]`);
      if (!row) return;
      scrollIntoPanel(scanScroll, row);
      row.classList.add('flash');
      setTimeout(() => row.classList.remove('flash'), 1400);
    }, 60);
  }

  /* ======================= Speed Test ======================= */
  const SP = ['Ping', 'Download', 'Upload', 'Stability'];
  speedPhases.innerHTML = railHTML(SP);
  const RO = [['down', 'Download', 'Mbps'], ['up', 'Upload', 'Mbps'], ['ping', 'Ping', 'ms'], ['jitter', 'Jitter', 'ms'], ['loss', 'Packet loss', '%'], ['drops', 'Drops', 'in 30 s']];
  readouts.innerHTML = RO.map(([k, l, u]) => `<div class="ro" id="ro-${k}"><span class="k">${l}</span><span class="v"><b>—</b><small>${u}</small></span></div>`).join('');
  function setRO(k, text, tone, active) {
    const el = $('#ro-' + k);
    el.querySelector('b').textContent = text;
    el.className = 'ro' + (tone ? ' ' + tone : '') + (active ? ' active' : '');
  }
  function liveStats(samples) {
    const s = samples.filter(Boolean);
    if (!s.length) return { loss: null, drops: null };
    let drops = 0, prev = true;
    for (const x of s) { const ok = x.net && x.net.ok; if (!ok && prev) drops++; prev = ok; }
    return { loss: Math.round((100 * s.filter((x) => !(x.net && x.net.ok)).length / s.length) * 10) / 10, drops };
  }
  function paintSpeed() {
    const sp = S.speed, st = sp.status;
    const running = st === 'running' || st === 'retest';
    const ph = running ? Math.min(sp.phase || 0, 3) : -1;
    const d = sp.diagnosis;
    const r = d ? d.result : null;
    let chip;
    if (running) chip = ['run', `${st === 'retest' ? 'Re-testing' : 'Testing'} · ${SP[ph]}`];
    else if (st === 'fixing') chip = ['run', 'Applying fixes'];
    else if (st === 'bad') chip = ['warn', r && r.drops ? `Unstable · ${plural(r.drops, 'drop')}` : 'Needs attention'];
    else if (st === 'good') chip = ['ok', 'Healthy'];
    else if (st === 'fixed') chip = d && d.status === 'good' ? ['ok', 'Fixed · stable'] : ['warn', 'Re-tested · still unstable'];
    else if (st === 'stopped') chip = ['warn', 'Test stopped'];
    else if (st === 'error') chip = ['bad', 'Test failed'];
    else chip = ['', 'Not tested yet'];
    setChip(speedChip, chip[0], chip[1]);
    speedDial.classList.toggle('is-running', running);
    speedDial.dataset.tone = running || st === 'fixing' ? 'run' : st === 'bad' ? 'warn' : st === 'good' || (st === 'fixed' && d && d.status === 'good') ? 'ok' : '';
    const vals = sp.vals || {};
    const gv = running && (ph === 1 || ph === 2) ? sp.live : vals.down != null ? vals.down : r ? r.down : 0;
    setTicks(speedTicks, gaugeFrac(gv), true);
    let inner, label = 'Start speed test';
    if (running) {
      label = 'Stop test';
      if (ph === 0) inner = stackHTML(sp.live != null ? Math.round(sp.live) : '—', 'ms ping');
      else if (ph === 1) inner = stackHTML(fmtSpeed(sp.live || 0), 'Mbps down');
      else if (ph === 2) inner = stackHTML(fmtSpeed(sp.live || 0), 'Mbps up');
      else {
        const last = (sp.samples || []).filter(Boolean).slice(-1)[0];
        inner = !last ? stackHTML('…', 'settling') : last.net && last.net.ok ? stackHTML(last.net.ms, 'ms latency') : stackHTML('—', 'no reply', 'bad');
      }
    } else if (st === 'fixing') { inner = '<span class="stack"><span class="spin lg"></span><span class="unit">Fixing</span></span>'; label = 'Applying fixes'; }
    else if (r) { inner = stackHTML(Math.round(r.down), 'Mbps down'); label = 'Test again'; }
    else inner = `<span class="glyph">${IC.power}</span>`;
    speedPower.innerHTML = inner;
    speedPower.setAttribute('aria-label', label);
    speedPower.disabled = st === 'fixing';
    let cap = 'Press to test speed and stability';
    if (running) cap = ph === 3 ? `Watching for drops · ${Math.max(1, 30 - Math.floor((Date.now() - (sp.phase3At || Date.now())) / 1000))} s left` : 'Measuring ' + SP[ph].toLowerCase();
    else if (st === 'fixing') cap = 'Applying fixes';
    else if (r) cap = 'Press to test again';
    else if (st === 'stopped' || st === 'error') cap = 'Press to start again';
    speedCaption.textContent = cap;
    speedPhases.hidden = !running;
    if (running) paintRail(speedPhases, ph, ph === 3 ? Math.min(1, (Date.now() - (sp.phase3At || Date.now())) / 32500) : 0.5);
    const live = running && ph === 3 ? liveStats(sp.samples || []) : null;
    const pick = (k) => (vals[k] != null ? vals[k] : r ? r[k] : null);
    setRO('down', ph === 1 ? fmtSpeed(sp.live || 0) : fmtSpeed(pick('down')), '', ph === 1);
    setRO('up', ph === 2 ? fmtSpeed(sp.live || 0) : fmtSpeed(pick('up')), '', ph === 2);
    setRO('ping', ph === 0 && sp.live != null ? String(Math.round(sp.live)) : pick('ping') != null ? String(pick('ping')) : '—', pick('ping') > 100 ? 'warn' : '', ph === 0);
    setRO('jitter', pick('jitter') != null ? String(pick('jitter')) : '—', pick('jitter') > 30 ? 'warn' : '', ph === 0);
    const loss = r && !running ? r.loss : live ? live.loss : null;
    const drops = r && !running ? r.drops : live ? live.drops : null;
    setRO('loss', loss != null ? String(loss) : '—', loss > 0 ? 'bad' : loss === 0 ? 'ok' : '', ph === 3);
    setRO('drops', drops != null ? String(drops) : '—', drops > 0 ? 'bad' : drops === 0 ? 'ok' : '', ph === 3);
    monitor.hidden = !((running && ph >= 3) || (r && sp.samples && sp.samples.length));
    if (!monitor.hidden) drawChart();
    updateTabDots();
  }

  function drawChart() {
    const sp = S.speed;
    const data = (sp.samples || []).filter(Boolean);
    if (monitor.hidden || !data.length) { if (!monitor.hidden) monSvg.innerHTML = ''; return; }
    const W = Math.max(220, Math.round(monSvg.getBoundingClientRect().width || 300));
    const H = 88, right = 44, top = 8, bottom = 8, plotW = W - right;
    const okMs = data.filter((s) => s.net && s.net.ok).map((s) => s.net.ms);
    const peak = Math.max(40, ...okMs);
    const max = peak <= 50 ? 50 : peak <= 100 ? 100 : peak <= 200 ? 200 : peak <= 500 ? 500 : 1000;
    const N = 30;
    const X = (i) => 3 + (i / (N - 1)) * (plotW - 6);
    const Y = (v) => top + (H - top - bottom) * (1 - Math.min(v, max) / max);
    let out = '';
    [0, max / 2, max].forEach((v) => {
      out += `<line class="grid-line" x1="0" x2="${plotW}" y1="${Y(v).toFixed(1)}" y2="${Y(v).toFixed(1)}"/>`;
      out += `<text class="axis" x="${W - 1}" y="${(Y(v) + 3.5).toFixed(1)}" text-anchor="end">${v} ms</text>`;
    });
    let i = 0;
    while (i < data.length) {
      if (!(data[i].net && data[i].net.ok)) {
        let j = i;
        while (j + 1 < data.length && !(data[j + 1].net && data[j + 1].net.ok)) j++;
        const x0 = X(i) - 3, x1 = X(j) + 3;
        out += `<rect class="drop-band" x="${x0.toFixed(1)}" y="${top - 4}" width="${(x1 - x0).toFixed(1)}" height="${H - top - bottom + 8}" rx="2"/>`;
        out += `<rect class="drop-mark" x="${x0.toFixed(1)}" y="${H - 4}" width="${(x1 - x0).toFixed(1)}" height="3" rx="1.5"/>`;
        i = j + 1;
      } else i++;
    }
    let d = '', pen = false;
    data.forEach((s, k) => {
      if (!(s.net && s.net.ok)) { pen = false; return; }
      d += (pen ? 'L' : 'M') + X(k).toFixed(1) + ' ' + Y(s.net.ms).toFixed(1) + ' ';
      pen = true;
    });
    if (d) out += `<path class="lat-line" d="${d}"/>`;
    const last = data[data.length - 1];
    if (last.net && last.net.ok) out += `<circle class="lat-end" cx="${X(data.length - 1).toFixed(1)}" cy="${Y(last.net.ms).toFixed(1)}" r="3.2"/>`;
    monSvg.setAttribute('viewBox', `0 0 ${W} ${H}`);
    monSvg.innerHTML = out;
  }

  function wifiDriverRow(row) {
    const net = S.speed.net;
    if (!net || !net.isWifi) return '';
    const i = (S.drv.issues || []).find((x) => x.cat === 'net' && /wi-?fi|wireless|wlan|802\.11|be20|ax2|iwl/i.test(x.name + ' ' + x.meta));
    if (!i) return '';
    if (i.state === 'done') return row('ok', 'Wi-Fi driver', 'updated today');
    if (i.state === 'open' || i.state === 'failed') return row('warn', 'Wi-Fi driver', 'update available · see Drivers');
    return '';
  }

  function renderDiag() {
    const sp = S.speed, st = sp.status, d = sp.diagnosis;
    const show = ['bad', 'good', 'fixing', 'retest', 'fixed', 'error'].includes(st);
    diag.hidden = !show;
    if (!show) return;
    const row = (tone, label, val) => `<li><span class="ci ${tone}">${tone === 'ok' ? IC.okc : tone === 'bad' ? IC.badc : IC.warnc}</span><span>${esc(label)}</span><span class="val">${esc(val)}</span></li>`;
    let h = '';
    if (st === 'error') {
      h = `<h3 class="warn">${IC.warn}<span>The test could not finish</span></h3><p class="err">${esc(sp.message)}</p><div class="acts"><button class="btn" type="button" data-act="sp-retest">Try again</button></div>`;
    } else if (st === 'bad' || st === 'good') {
      const bad = st === 'bad';
      h = `<h3 class="${bad ? 'warn' : 'ok'}">${bad ? IC.warn : IC.check}<span>${bad ? 'Unstable connection' : 'Healthy connection'}</span></h3>
        <ul class="checks">${d.checks.map(([t, l, v]) => row(t, l, v)).join('')}${bad ? wifiDriverRow(row) : ''}</ul>
        <p>${esc(d.text)}</p>
        ${sp.fixMessage ? `<p class="fixmsg">${esc(sp.fixMessage)}</p>` : ''}
        <div class="acts">${bad && d.fixes.length ? '<button class="btn primary" type="button" data-act="sp-fix">Fix it</button>' : ''}<button class="btn" type="button" data-act="sp-retest">Test again</button></div>`;
    } else if (st === 'fixing' || st === 'retest') {
      const steps = sp.fixSteps || [];
      h = `<h3><span class="spin"></span><span>${st === 'fixing' ? 'Applying fixes' : 'Testing again'}</span></h3>
        <ul class="steps">${steps.map((s) => `<li class="${s.st}"><span class="si">${s.st === 'done' ? IC.check : s.st === 'failed' ? IC.x : s.st === 'running' ? '<span class="spin"></span>' : '<span class="pend"></span>'}</span><span><span>${esc(s.label)}</span><code>${esc(s.cmd)}</code>${s.st === 'failed' && s.message ? `<code>${esc(s.message)}</code>` : ''}</span></li>`).join('')}</ul>
        <p>${st === 'fixing' ? 'The connection drops for a few seconds while the adapter restarts.' : 'Running the full test again to check whether the fixes helped.'}</p>`;
    } else if (st === 'fixed') {
      const b = sp.before || {}, a = d.result;
      const tr = (label, bv, av, worse) => `<tr><th scope="row">${label}</th><td class="before">${bv}</td><td class="after${worse ? ' worse' : ''}">${av}</td></tr>`;
      const msOr = (v) => (v == null ? '—' : v + ' ms');
      h = `<h3 class="${d.status === 'good' ? 'ok' : 'warn'}">${d.status === 'good' ? IC.check : IC.warn}<span>${d.status === 'good' ? 'Fixed · connection stable' : 'Re-tested · still unstable'}</span></h3>
        <table class="compare"><thead><tr><th scope="col"><span class="sr">Measure</span></th><th scope="col">Before</th><th scope="col">After</th></tr></thead><tbody>
          ${tr('Drops in 30 s', b.drops != null ? b.drops : '—', a.drops, a.drops > (b.drops || 0))}
          ${tr('Packet loss', (b.loss != null ? b.loss : '—') + '%', a.loss + '%', a.loss > (b.loss || 0))}
          ${tr('DNS lookup', msOr(b.dns), msOr(a.dns), a.dns > (b.dns || 0))}
          ${tr('Jitter', msOr(b.jitter), msOr(a.jitter), a.jitter > (b.jitter || 0))}
          ${tr('Download', b.down != null ? Math.round(b.down) + ' Mbps' : '—', Math.round(a.down) + ' Mbps', a.down < (b.down || 0) * 0.8)}
        </tbody></table>
        <p>${esc(d.text)}</p>
        <div class="acts"><button class="btn" type="button" data-act="sp-retest">Test again</button>${(sp.applied || []).includes('dns') && sp.dnsPrevious ? '<button class="btn quiet" type="button" data-act="sp-undo-dns">Undo DNS change</button>' : ''}</div>`;
    }
    diag.innerHTML = h;
  }

  function openFixSheet() {
    const d = S.speed.diagnosis;
    if (!d || !d.fixes.length) return;
    openSheet({
      title: 'Fix connection problems',
      body: `<p>Power Scan will make these changes. ${esc(d.askText || '')}, and the connection drops for a few seconds.</p>
        <div class="fixlist">${d.fixes.map((f) => `<label class="fx"><input type="checkbox" value="${esc(f.id)}" checked><span><span class="fx-l">${esc(f.label)}</span><code>${esc(f.cmd)}</code></span></label>`).join('')}</div>`,
      confirm: 'Apply fixes',
      onConfirm: (ids) => { if (ids.length) api.speed.fix(ids); },
    });
  }

  speedPower.addEventListener('click', () => {
    const st = S.speed.status;
    if (st === 'running' || st === 'retest') api.speed.stop();
    else if (st !== 'fixing') api.speed.start();
  });

  api.on('speed', (e) => {
    const sp = S.speed;
    switch (e.type) {
      case 'start':
        S.speed = { status: e.retest ? 'retest' : 'running', phase: 0, live: null, vals: {}, samples: [], before: e.retest && sp.diagnosis ? sp.diagnosis.result : null, applied: e.retest ? sp.applied : null, fixSteps: e.retest ? sp.fixSteps : null, dnsPrevious: sp.dnsPrevious, net: sp.net };
        renderDiag(); paintSpeed();
        if (!e.retest) speedScroll.scrollTo({ top: 0, behavior: 'smooth' });
        break;
      case 'phase':
        sp.phase = e.idx; sp.live = null;
        if (e.idx === 3) { sp.phase3At = Date.now(); sp.samples = []; }
        paintSpeed();
        break;
      case 'live': sp.live = e.value; schedule(paintSpeed); break;
      case 'value': sp.vals[e.key] = e.value; schedule(paintSpeed); break;
      case 'sample': sp.samples[e.i] = e.sample; schedule(paintSpeed); break;
      case 'done': {
        const keep = { before: sp.before, applied: sp.applied, fixSteps: sp.fixSteps };
        S.speed = { ...e.state, ...keep, vals: {}, samples: e.state.samples || [] };
        if (!S.speed.before && e.state.before) S.speed.before = e.state.before;
        paintSpeed(); renderDiag();
        setTimeout(() => scrollIntoPanel(speedScroll, diag), 80);
        break;
      }
      case 'stopped': S.speed = { status: 'stopped', vals: {}, samples: [] }; paintSpeed(); renderDiag(); break;
      case 'error': S.speed = { status: 'error', message: e.message, vals: {}, samples: [] }; paintSpeed(); renderDiag(); break;
      case 'fixing': sp.status = 'fixing'; sp.fixSteps = e.steps; sp.fixMessage = ''; paintSpeed(); renderDiag(); setTimeout(() => scrollIntoPanel(speedScroll, diag), 40); break;
      case 'fix-cancelled': S.speed = { ...sp, ...e.state, status: e.state.status, fixMessage: 'Nothing was changed. The fixes need administrator permission.' }; paintSpeed(); renderDiag(); break;
      default: break;
    }
  });

  /* ======================= Drivers ======================= */
  drvPhases.innerHTML = railHTML(S.phases.drivers);
  const DRV_CAPS = ['Listing devices and drivers', 'Comparing versions', 'Checking device health', 'Checking crashes and resets'];
  const verbOf = (i) => (i.kind === 'update' ? 'Update' : i.kind === 'install' ? 'Install' : isWin() ? 'Open in Device Manager' : 'Show steps');
  const issuePending = (i) => ['open', 'queued', 'working', 'failed'].includes(i.state);

  function renderDrv() {
    const dv = S.drv;
    const list = dv.issues || [];
    const pending = list.filter(issuePending).length;
    const ignored = list.filter((x) => x.state === 'ignored').length;
    const restart = list.some((x) => x.state === 'done' && x.restart);
    const busy = list.some((x) => x.state === 'working' || x.state === 'queued');
    drvEngine.textContent = S.info ? S.info.driverSource : '';
    let chip;
    switch (dv.status) {
      case 'running': chip = ['run', `Checking · pass ${(dv.phaseIdx || 0) + 1} of 4`]; break;
      case 'stopped': chip = ['warn', 'Check stopped']; break;
      case 'error': chip = ['bad', 'Check failed']; break;
      case 'issues': chip = ['warn', `${pending} need${pending === 1 ? 's' : ''} attention`]; break;
      case 'resolved': chip = restart ? ['warn', 'Restart to finish'] : ignored ? ['warn', `Healthy · ${ignored} ignored`] : ['ok', 'All drivers healthy']; break;
      case 'clean': chip = ['ok', 'All drivers healthy']; break;
      default: chip = ['', S.lastDriverCheckAt ? 'Last check ' + dayStr(S.lastDriverCheckAt) : 'Not checked yet'];
    }
    setChip(drvChip, chip[0], chip[1]);
    drvDial.dataset.tone = dv.status === 'running' ? 'run' : dv.status === 'issues' ? 'warn' : dv.status === 'resolved' || dv.status === 'clean' ? 'ok' : '';
    drvDial.classList.toggle('is-running', dv.status === 'running');
    if (dv.status === 'running') {
      paintDrv();
      drvPower.setAttribute('aria-label', 'Stop driver check');
    } else {
      setTicks(drvTicks, dv.status === 'idle' || dv.status === 'error' ? 0 : dv.status === 'stopped' ? dv.progress || 0 : 1, false);
      if (dv.status === 'issues') drvPower.innerHTML = stackHTML(pending, 'need attention', 'warn');
      else if (dv.status === 'resolved' || dv.status === 'clean') drvPower.innerHTML = `<span class="stack">${IC.check}<span class="unit">Healthy</span></span>`;
      else drvPower.innerHTML = `<span class="glyph">${IC.power}</span>`;
      drvPower.setAttribute('aria-label', dv.status === 'idle' ? 'Check drivers' : 'Check drivers again');
    }
    drvPower.disabled = busy;
    let cap = 'Press to check every driver';
    if (dv.status === 'running') cap = DRV_CAPS[dv.phaseIdx || 0];
    else if (busy) cap = 'Changing drivers one at a time';
    else if (dv.status === 'stopped' || dv.status === 'error') cap = dv.status === 'error' ? dv.message || 'Press to try again' : 'Press to check again';
    else if (dv.finishedAt) cap = `Checked ${clockStr(dv.finishedAt)} · ${fmtN(dv.total)} drivers · ${fmtN(dv.devices)} devices`;
    drvCaption.textContent = cap;
    drvFeed.hidden = dv.status !== 'running';
    drvResults.hidden = !(dv.status === 'issues' || dv.status === 'resolved' || dv.status === 'clean');
    drvGlance.hidden = !['idle', 'stopped', 'resolved', 'clean', 'error'].includes(dv.status);
    if (!drvResults.hidden) renderDrvResults();
    if (!drvGlance.hidden) renderDrvGlance();
    updateTabDots();
  }
  function paintDrv() {
    const dv = S.drv;
    setTicks(drvTicks, dv.progress || 0, false);
    drvPower.innerHTML = stackHTML(Math.floor((dv.progress || 0) * 100) + '<small>%</small>', 'Press to stop');
    paintRail(drvPhases, dv.phaseIdx || 0, dv.phaseFrac || 0);
    drvLog.innerHTML = logHTML(dv.log || []);
    dChecked.textContent = fmtN(dv.checked);
    dIssues.textContent = dv.flagged || 0;
    dIssuesBox.classList.toggle('warn', (dv.flagged || 0) > 0);
    dTime.textContent = dur(Date.now() - (dv.startedAt || Date.now()));
  }
  function renderDrvGlance() {
    const dv = S.drv;
    const changes = (dv.issues || []).filter((x) => x.state === 'done' && (x.kind === 'update' || x.kind === 'install')).length;
    const tiles = [['Last check', S.lastDriverCheckAt ? dayStr(S.lastDriverCheckAt) : 'Never', S.lastDriverCheckAt ? 'ok' : 'warn']]
      .concat((S.info && S.info.driverGlance) || [])
      .concat([['Changes today', changes ? String(changes) : 'None', changes ? 'ok' : '']]);
    drvGlance.innerHTML = tiles.map(([k, v, t]) => `<div class="tile"><span class="k">${esc(k)}</span><span class="v"><i class="dot ${t}"></i>${esc(v)}</span></div>`).join('');
  }
  function drvCard(i) {
    if (i.state === 'done' || i.state === 'ignored') {
      const ign = i.state === 'ignored';
      return `<article class="threat done" data-id="${i.id}"><span class="done-ic ${ign ? 'warn' : 'ok'}">${ign ? IC.warn : IC.check}</span><div class="done-t"><span class="drv-done-name">${esc(i.name)}</span><span class="done-s ${ign ? 'warn' : 'ok'}">${esc(ign ? 'Ignored · not flagged again for this version' : i.doneText)}</span></div></article>`;
    }
    let foot;
    if (i.state === 'working') foot = `<div class="drv-prog"><span class="working"><span class="spin"></span>${esc(i.stepLabel || 'Working')}</span></div>`;
    else if (i.state === 'queued') foot = '<span class="working">Waiting for the driver before it</span>';
    else foot = `${i.state === 'failed' || i.message ? `<p class="fail">${esc(i.state === 'failed' ? i.doneText : i.message)}</p>` : ''}<div class="acts"><button class="btn primary sm" type="button" data-act="drv-do" data-id="${i.id}">${i.state === 'failed' ? 'Try again' : verbOf(i)}</button>${i.state === 'open' ? `<button class="btn quiet sm" type="button" data-act="drv-ignore" data-id="${i.id}">Ignore</button>` : ''}</div>`;
    return `<article class="drv" data-id="${i.id}"><div class="drv-top"><span class="cat">${CAT[i.cat] || CAT.chip}</span><span class="drv-name"><b>${esc(i.name)}</b><span>${esc(i.meta)}</span></span><span class="tag ${i.tag[0]}">${esc(i.tag[1])}</span></div><ul class="finds">${i.finds.map(([t, html]) => `<li class="${t}">${FIND_IC[t] || IC.infoc}<span>${html}</span></li>`).join('')}</ul>${foot}</article>`;
  }
  function renderDrvResults() {
    const dv = S.drv, list = dv.issues || [];
    const prev = drvResults.querySelector('details.healthy');
    const wasOpen = !!(prev && prev.open);
    const batchable = list.filter((x) => x.state === 'open' && x.batch !== false && (x.kind === 'update' || x.kind === 'install'));
    const pending = list.filter(issuePending).length;
    let h;
    if (dv.status === 'issues') h = `<div class="results-head"><h3>${pending} driver${pending === 1 ? ' needs' : 's need'} attention</h3>${batchable.length > 1 ? `<button class="btn primary sm" type="button" data-act="drv-all">Update all ${batchable.length}</button>` : ''}</div>`;
    else if (dv.status === 'clean') h = '<div class="results-head"><h3>No driver problems found</h3></div>';
    else h = '<div class="results-head"><h3>Driver changes</h3></div>';
    h += (dv.notes || []).map((n) => `<div class="note">${IC.warn}<span>${esc(n.text)}</span></div>`).join('');
    h += list.map(drvCard).join('');
    if (dv.restoreAt) h += `<div class="note ok">${IC.check}<span>Restore point made at ${clockStr(dv.restoreAt)}. Any change can be undone with System Restore.</span></div>`;
    else if (dv.restoreNote && /^failed/.test(dv.restoreNote)) h += `<div class="note">${IC.warn}<span>No restore point was made (${esc(dv.restoreNote.replace(/^failed:\s*/, ''))}). Drivers can still be rolled back in Device Manager.</span></div>`;
    if (list.some((x) => x.state === 'done' && x.restart)) h += `<div class="note">${IC.warn}<span>Restart the computer to finish ${isWin() ? 'these updates' : 'and start using the new kernel. The old one stays in the boot menu'}.</span></div>`;
    const healthyCount = Math.max(0, (dv.total || 0) - list.length);
    if (dv.healthy && dv.healthy.length) {
      h += `<details class="healthy"${wasOpen ? ' open' : ''}><summary><i class="dot ok"></i>${fmtN(healthyCount)} drivers working and up to date</summary><ul>${dv.healthy.map(([n, v]) => `<li><span>${esc(n)}</span><span class="v">${esc(v)}</span></li>`).join('')}${healthyCount > dv.healthy.length ? `<li class="more">and ${fmtN(healthyCount - dv.healthy.length)} more</li>` : ''}</ul></details>`;
    }
    drvResults.innerHTML = h;
  }
  function updateDrvCard(i) {
    const el = drvResults.querySelector(`article[data-id="${i.id}"]`);
    if (el) el.outerHTML = drvCard(i); else renderDrvResults();
  }
  function confirmDrv(i) {
    if (!i || !(i.state === 'open' || i.state === 'failed')) return;
    if (i.kind === 'rollback' || i.kind === 'review') { api.drivers.act([i.id]); return; }
    let title, line;
    if (i.kind === 'update') { title = `Update ${i.name}?`; line = i.ver && i.newVer ? `Updates ${esc(i.ver)} to <b>${esc(i.newVer)}</b>.` : 'Installs the newer version.'; }
    else { title = `Install a driver for ${i.name}?`; line = `Installs <b>${esc(i.newName || i.newVer || 'the driver')}</b>.`; }
    let how;
    if (isWin()) how = 'It comes from Windows Update and is signed by Microsoft. ' + (S.info && S.info.restoreOn ? (S.drv.restoreAt ? '' : 'A restore point is made first. ') : 'System Restore is off on this PC, so no restore point can be made; drivers can still be rolled back in Device Manager. ') + 'Windows asks for administrator permission.';
    else how = "It comes from your distribution's packages, and the old version stays available to switch back. Linux asks for your password.";
    openSheet({
      title,
      body: `<p>${line} ${esc(how)}</p>${i.note ? `<p>${esc(i.note)}</p>` : ''}${i.cmd ? `<p class="sheet-path">${esc(i.cmd)}</p>` : ''}`,
      confirm: verbOf(i),
      onConfirm: () => api.drivers.act([i.id]),
    });
  }
  function confirmDrvAll() {
    const open = (S.drv.issues || []).filter((x) => x.state === 'open' && x.batch !== false && (x.kind === 'update' || x.kind === 'install'));
    if (!open.length) return;
    const rp = isWin() && S.info && S.info.restoreOn && !S.drv.restoreAt ? 'A restore point is made first. ' : '';
    openSheet({
      title: `Update ${plural(open.length, 'driver')}?`,
      body: `<ul class="sheet-list">${open.map((x) => `<li>${esc(x.name)}</li>`).join('')}</ul><p>${rp}They install one after another${isWin() ? ' from Windows Update' : ''}, and each device drops out for a few seconds while its driver changes. ${isWin() ? 'Windows asks for administrator permission once.' : 'Linux asks for your password once.'}${(S.drv.issues || []).some((x) => x.state === 'open' && x.batch === false) ? ' Firmware updates are left out; update those one at a time.' : ''}</p>`,
      confirm: `Update ${open.length}`,
      onConfirm: () => api.drivers.act(open.map((x) => x.id)),
    });
  }

  drvPower.addEventListener('click', () => {
    if (S.drv.status === 'running') api.drivers.stop();
    else api.drivers.start();
  });

  api.on('drivers', (e) => {
    const dv = S.drv;
    switch (e.type) {
      case 'start': S.drv = { status: 'running', phaseIdx: 0, phaseFrac: 0, progress: 0, checked: 0, flagged: 0, log: [], issues: [], startedAt: e.startedAt }; renderDrv(); setTimeout(() => scrollIntoPanel(drvScroll, drvFeed), 50); break;
      case 'phase': dv.phaseIdx = e.idx; dv.phaseFrac = 0; dv.progress = e.progress; renderDrv(); break;
      case 'item': pushLog(dv.log, e); schedule(paintDrv); break;
      case 'progress': dv.progress = e.progress; dv.phaseFrac = e.phaseFrac; dv.checked = e.checked; dv.flagged = e.flagged; schedule(paintDrv); break;
      case 'done': S.drv = { ...e, log: dv.log }; S.lastDriverCheckAt = e.finishedAt; renderDrv(); setTimeout(() => scrollIntoPanel(drvScroll, drvResults), 80); break;
      case 'stopped': dv.status = 'stopped'; renderDrv(); break;
      case 'error': S.drv = { status: 'error', message: e.message, issues: [], log: [] }; renderDrv(); break;
      case 'issue': {
        const list = dv.issues || [];
        const k = list.findIndex((x) => x.id === e.issue.id);
        const before = k >= 0 ? list[k].state : null;
        if (k >= 0) list[k] = e.issue; else list.push(e.issue);
        if (before === e.issue.state && e.issue.state === 'working') updateDrvCard(e.issue); else renderDrv();
        if (S.speed.diagnosis) renderDiag();
        break;
      }
      case 'restore': dv.restoreAt = e.restoreAt; dv.restoreNote = e.note; renderDrv(); break;
      case 'resolved': dv.status = 'resolved'; renderDrv(); break;
      default: break;
    }
  });

  /* ---------- clicks inside the window ---------- */
  document.addEventListener('click', (e) => {
    const b = e.target.closest('[data-act]');
    if (!b) return;
    const id = b.dataset.id;
    switch (b.dataset.act) {
      case 'f-remove': onFinding(id, 'remove'); break;
      case 'f-keep': onFinding(id, 'keep'); break;
      case 'f-remove-all': removeAll(); break;
      case 'tr-remove': onTraffic(id, 'remove'); break;
      case 'tr-keep': onTraffic(id, 'keep'); break;
      case 'review': reviewTraffic(id); break;
      case 'banner-x': banner.hidden = true; break;
      case 'sp-fix': openFixSheet(); break;
      case 'sp-retest': api.speed.start(); break;
      case 'sp-undo-dns': api.speed.undoDns().then((r) => { if (r && r.ok) { S.speed.dnsPrevious = null; S.speed.applied = (S.speed.applied || []).filter((x) => x !== 'dns'); renderDiag(); showBanner(`<span class="b-ic">${IC.check}</span><div class="b-t"><b>DNS change undone</b><span>Your previous DNS settings are back</span></div><button class="b-x" type="button" data-act="banner-x" aria-label="Dismiss">${IC.x}</button>`, 'info'); } }); break;
      case 'drv-do': confirmDrv((S.drv.issues || []).find((x) => x.id === id)); break;
      case 'drv-ignore': api.drivers.ignore(id); break;
      case 'drv-all': confirmDrvAll(); break;
      default: break;
    }
  });

  /* ---------- window controls ---------- */
  $('#btnMin').addEventListener('click', () => api.win.minimize());
  $('#btnMax').addEventListener('click', () => api.win.toggleMaximize());
  $('#btnClose').addEventListener('click', () => api.win.close());
  function setMaxIcon(max) {
    $('#icoMax').innerHTML = max ? '<rect x="3.5" y="5.5" width="7" height="7" rx="1.1"/><path d="M5.5 5.5V4.6c0-.6.5-1.1 1.1-1.1h4.8c.6 0 1.1.5 1.1 1.1v4.8c0 .6-.5 1.1-1.1 1.1h-.9"/>' : '<rect x="3.5" y="3.5" width="9" height="9" rx="1.2"/>';
    $('#btnMax').setAttribute('aria-label', max ? 'Restore' : 'Maximize');
    $('#btnMax').title = max ? 'Restore' : 'Maximize';
  }
  api.on('win', (w) => setMaxIcon(!!w.maximized));
  const wide = () => { $('#win').classList.toggle('is-wide', window.innerWidth >= 700); drawChart(); };
  window.addEventListener('resize', wide);

  /* ---------- start ---------- */
  scanPhases.innerHTML = railHTML(S.phases.scan);
  renderScan(); paintSpeed(); renderDrv();
  api.init().then((d) => {
    S.info = d.info;
    S.phases = d.phases || S.phases;
    scanPhases.innerHTML = railHTML(S.phases.scan);
    drvPhases.innerHTML = railHTML(S.phases.drivers);
    S.listener = d.listener;
    S.traffic = d.traffic || [];
    S.lastScanAt = d.lastScanAt;
    S.lastDriverCheckAt = d.lastDriverCheckAt;
    if (d.scan && d.scan.status && d.scan.status !== 'idle') S.scan = { ...d.scan, log: [] };
    if (d.drivers && d.drivers.status && d.drivers.status !== 'idle') S.drv = { ...d.drivers, log: [] };
    if (d.speed && d.speed.status && !['idle', 'running', 'retest'].includes(d.speed.status)) S.speed = { ...d.speed, vals: {}, samples: d.speed.samples || [] };
    setMaxIcon(d.maximized);
    wide();
    renderScan(); paintSpeed(); renderDiag(); renderDrv();
  });
})();
