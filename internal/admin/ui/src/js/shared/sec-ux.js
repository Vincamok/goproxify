// ── Noyau d'interactions du menu Sécurité ─────────────────────────────────────────────────
// Briques partagées par Bans, Ephor et la palette Ctrl+K : une cible IP/CIDR et une durée se saisissent à la
// main, chaque IP affichée se glisse vers une action ou ouvre un menu, une expiration se modifie sur place,
// et toute action destructive s'annule (bouton du toast, ou Ctrl+Z). Aucune donnée propre : tout passe par
// l'API existante (/security/bans, /security/bans/whitelist, /security/bans/preview).

const SecUX = (() => {
  const H = 3600e3, D = 24 * H;
  const DURS = [['1h', '1 h', H], ['24h', '24 h', 24 * H], ['7j', '7 j', 7 * D], ['30j', '30 j', 30 * D], ['perm', '∞', null]];
  const DUR_KEY = 'gpx.sec.dur';

  // ── Saisie ────────────────────────────────────────────────────────────────────────────
  function parseTarget(raw) {
    const s = String(raw || '').trim();
    let m = /^((?:\d{1,3}\.){3}\d{1,3})(?:\/(\d{1,2}))?$/.exec(s);
    if (m) {
      if (m[1].split('.').some(o => +o > 255) || (m[2] != null && +m[2] > 32)) return null;
      return { value: s, v6: false, cidr: m[2] != null };
    }
    m = /^([0-9a-f:.]+)(?:\/(\d{1,3}))?$/i.exec(s);
    if (m && m[1].includes(':') && (m[2] == null || +m[2] <= 128)) {
      try { new URL('http://[' + m[1] + ']/'); } catch { return null; }
      return { value: s.toLowerCase(), v6: true, cidr: m[2] != null };
    }
    return null;
  }

  // ms, null (permanent) ou undefined (illisible). « 36h », « 3j », « 2sem », « 90min », « perm ».
  function parseDur(text) {
    const s = String(text || '').trim().toLowerCase().replace(/\s+/g, '');
    if (['perm', 'permanent', '∞', 'vie', 'àvie', 'avie'].includes(s)) return null;
    const m = /^(\d+(?:[.,]\d+)?)(min|m|h|j|d|sem|w)$/.exec(s);
    if (!m) return undefined;
    const unit = { min: 60e3, m: 60e3, h: H, j: D, d: D, sem: 7 * D, w: 7 * D }[m[2]];
    const ms = Math.round(parseFloat(m[1].replace(',', '.')) * unit);
    return ms >= 60e3 ? ms : undefined;
  }

  function durLabel(ms) {
    if (ms === null) return 'à vie';
    if (ms < H) return Math.round(ms / 60e3) + ' min';
    if (ms < 2 * D) return Math.round(ms / H) + ' h';
    return Math.round(ms / D) + ' jours';
  }

  // Durée au format Go (« 36h », « 90m ») : celle qu'attendent les réglages d'Ephor.
  function goDuration(ms) {
    return ms % H === 0 ? (ms / H) + 'h' : Math.round(ms / 60e3) + 'm';
  }

  const iso = ms => new Date(ms).toISOString().replace(/\.\d+Z$/, 'Z');
  // SQLite renvoie « YYYY-MM-DD HH:MM:SS » en UTC sans fuseau.
  function timeOf(s) {
    if (!s) return null;
    const ms = Date.parse(/^\d{4}-\d\d-\d\d \d\d:\d\d:\d\d$/.test(s) ? s.replace(' ', 'T') + 'Z' : s);
    return Number.isNaN(ms) ? null : ms;
  }

  function lastDur() {
    try { const k = localStorage.getItem(DUR_KEY); if (DURS.some(d => d[0] === k)) return k; } catch { /* stockage indisponible */ }
    return '24h';
  }
  function saveDur(key) { try { localStorage.setItem(DUR_KEY, key); } catch { /* stockage indisponible */ } }
  const durMs = key => (DURS.find(d => d[0] === key) || DURS[1])[2];

  // ── Annuler ───────────────────────────────────────────────────────────────────────────
  const stack = [];

  async function runUndo(entry) {
    const i = stack.indexOf(entry);
    if (i >= 0) stack.splice(i, 1);
    try { await entry.undo(); } catch (e) { toast(e.message, 'error'); }
  }

  // Affiche le toast avec « Annuler » et garde l'action pour Ctrl+Z (10 minutes).
  function remember(label, undo) {
    const entry = undo ? { label, undo, at: Date.now() } : null;
    if (entry) { stack.push(entry); if (stack.length > 20) stack.shift(); }
    const box = document.getElementById('toasts');
    if (!box) { toast(label, 'success'); return; }
    const el = document.createElement('div');
    el.className = 'toast toast-success';
    el.innerHTML = `<span>${esc(label)}</span>`;
    if (entry) {
      const b = document.createElement('button');
      b.type = 'button';
      b.className = 'secux-undo';
      b.textContent = 'Annuler';
      b.onclick = async () => { b.disabled = true; el.remove(); await runUndo(entry); };
      el.append(b);
    }
    box.append(el);
    setTimeout(() => el.remove(), entry ? 9000 : 3500);
  }

  // Le noyau sert aussi les pages Observabilité (IP des journaux, de Prism, des alertes) : mêmes gestes, mêmes annulations.
  const inScope = () => (typeof SECURITY_PAGES !== 'undefined' && SECURITY_PAGES.has(state.page)) || (typeof ObsUX !== 'undefined' && ObsUX.isObs());

  function refresh() {
    const p = state.page || '';
    if (typeof ObsUX !== 'undefined' && ObsUX.isObs(p)) return ObsUX.reload();
    if (/security-bans$/.test(p) && typeof bnQuietReload === 'function') return bnQuietReload();
    if (/security-ephor$/.test(p) && typeof sentReload === 'function') return sentReload(true);
    return reloadCurrentSecurityPage();
  }

  document.addEventListener('keydown', e => {
    if (!(e.ctrlKey || e.metaKey) || e.shiftKey || e.key.toLowerCase() !== 'z') return;
    if (!inScope()) return;
    const tag = (e.target.tagName || '').toLowerCase();
    if (tag === 'input' || tag === 'textarea' || tag === 'select' || e.target.isContentEditable) return;
    const entry = stack[stack.length - 1];
    if (!entry || Date.now() - entry.at > 600e3) return;
    e.preventDefault();
    runUndo(entry);
  });

  // ── Actions sur l'API ────────────────────────────────────────────────────────────────
  // Le ban recréé par « Annuler » reprend source, motif, domaine, expiration et portée de l'original ;
  // il reçoit un nouvel identifiant et l'historique garde la trace du déban puis du nouveau ban.
  const banBody = b => {
    const body = { ip: b.ip, domain: b.domain || '', reason: b.reason || '', source: b.source || 'native' };
    const exp = timeOf(b.expires_at);
    if (exp != null) body.expires_at = iso(exp);
    if (b.target_scope) body.target_scope = b.target_scope;
    return body;
  };

  async function ban(target, { ms = 24 * H, reason = '', domain = '', scope = '', quiet = false } = {}) {
    const body = { ip: target, domain, reason, source: 'native' };
    if (ms !== null) body.expires_at = iso(Date.now() + ms);
    if (scope) body.target_scope = scope;
    const r = await api('POST', '/security/bans', body);
    const id = r && r.id;
    if (!quiet) remember(`${target} banni ${ms === null ? 'à vie' : 'pour ' + durLabel(ms)}`,
      id ? async () => { await api('DELETE', '/security/bans/' + encodeURIComponent(id)); refresh(); } : null);
    refresh();
    return id;
  }

  async function unban(bans) {
    const list = Array.isArray(bans) ? bans : [bans];
    const done = [];
    const failed = [];
    for (const b of list) {
      try { await api('DELETE', '/security/bans/' + encodeURIComponent(b.id)); done.push(b); } catch (e) { failed.push(e.message); }
    }
    if (failed.length) toast(`${failed.length} déban(s) en échec : ${failed[0]}`, 'error');
    if (done.length) {
      remember(done.length === 1 ? `Ban levé sur ${done[0].ip}` : `${done.length} bans levés`, async () => {
        for (const b of done) await api('POST', '/security/bans', banBody(b));
        refresh();
      });
    }
    refresh();
  }

  async function setExpiry(bans, ms) {
    const list = (Array.isArray(bans) ? bans : [bans]);
    const done = [];
    for (const b of list) {
      try {
        const patch = ms === null ? { permanent: true } : { expires_at: iso(Date.now() + ms) };
        await api('PATCH', '/security/bans/' + encodeURIComponent(b.id), patch);
        done.push(b);
      } catch (e) { toast(e.message, 'error'); }
    }
    if (done.length) {
      const what = ms === null ? 'banni à vie' : 'expire dans ' + durLabel(ms);
      remember(done.length === 1 ? `${done[0].ip} ${what}` : `${done.length} bans : ${what}`, async () => {
        for (const b of done) {
          const prev = timeOf(b.expires_at);
          await api('PATCH', '/security/bans/' + encodeURIComponent(b.id), prev == null ? { permanent: true } : { expires_at: iso(prev) });
        }
        refresh();
      });
    }
    refresh();
  }

  // Prolonge à partir de la fin actuelle (ou de maintenant si le ban est déjà expiré) ; les bans permanents sont ignorés.
  async function extend(bans, ms) {
    const list = (Array.isArray(bans) ? bans : [bans]).filter(b => timeOf(b.expires_at) != null);
    const done = [];
    for (const b of list) {
      try {
        await api('PATCH', '/security/bans/' + encodeURIComponent(b.id), { expires_at: iso(Math.max(timeOf(b.expires_at), Date.now()) + ms) });
        done.push(b);
      } catch (e) { toast(e.message, 'error'); }
    }
    if (done.length) {
      remember(done.length === 1 ? `${done[0].ip} prolongé de ${durLabel(ms)}` : `${done.length} bans prolongés de ${durLabel(ms)}`, async () => {
        for (const b of done) await api('PATCH', '/security/bans/' + encodeURIComponent(b.id), { expires_at: iso(timeOf(b.expires_at)) });
        refresh();
      });
    }
    refresh();
  }

  async function allow(value, comment = '') {
    const r = await api('POST', '/security/bans/whitelist', { ip: value, comment });
    if (r && r.added === false) { toast(`Déjà couvert par ${r.covered_by}`, 'info'); return; }
    remember(`${value} toujours autorisée`, async () => {
      await api('DELETE', '/security/bans/whitelist?ip=' + encodeURIComponent(value));
      refresh();
    });
    refresh();
  }

  async function unallow(entry) {
    await api('DELETE', '/security/bans/whitelist?ip=' + encodeURIComponent(entry.value));
    remember(`${entry.value} retiré de la liste blanche`, async () => {
      await api('POST', '/security/bans/whitelist', { ip: entry.value, comment: entry.comment || '' });
      refresh();
    });
    refresh();
  }

  // Bans actifs dont la cible est exactement cette adresse (ou ce CIDR), toutes passerelles confondues.
  async function activeBansFor(value) {
    const list = await api('GET', '/security/bans?active=true').catch(() => []);
    const v = String(value).toLowerCase();
    return (list || []).filter(b => String(b.ip).toLowerCase() === v);
  }

  async function onActive(value, fn, none) {
    const bans = await activeBansFor(value);
    if (!bans.length) { toast(none || `Aucun ban actif pour ${value}`, 'info'); return; }
    return fn(bans);
  }

  // ── Actions disponibles sur une IP (menu, zones de dépôt, palette) ───────────────────────
  const IP_DO = {
    ban1h:   { label: 'Bannir 1 h', bad: true, run: ip => ban(ip, { ms: H }) },
    ban24h:  { label: 'Bannir 24 h', bad: true, run: ip => ban(ip, { ms: 24 * H }) },
    ban7d:   { label: 'Bannir 7 jours', bad: true, run: ip => ban(ip, { ms: 7 * D }) },
    banperm: { label: 'Bannir à vie', bad: true, run: ip => ban(ip, { ms: null }) },
    allow:   { label: 'Toujours autoriser', run: ip => allow(ip) },
    unban:   { label: 'Lever le ban', run: ip => onActive(ip, unban) },
    extend:  { label: 'Prolonger de 24 h', run: ip => onActive(ip, b => extend(b, 24 * H)) },
    perm:    { label: 'Rendre permanent', run: ip => onActive(ip, b => setExpiry(b, null)) },
    trace:   { label: 'Tracer le parcours', run: ip => openIPTrace(ip) },
    logs:    { label: 'Logs de cette IP', run: ip => openLogsFiltered({ ip }) },
    history: { label: 'Historique de l’IP', run: ip => showBanHistory(ip) },
    prism:   { label: 'Voir dans Prism', run: ip => openPrismForBanIP(ip) },
    copy:    { label: 'Copier', run: ip => copyText(ip) },
  };

  async function doIP(action, ip) {
    try { await IP_DO[action].run(ip); } catch (e) { toast(e.message, 'error'); }
  }

  // Une IP déplaçable : ouvre le menu au clic, à Entrée ou à Espace, et se glisse vers une zone de dépôt.
  // Un <span> et non un <button> : Firefox ne démarre pas de glisser-déposer depuis un bouton.
  function ipHTML(ip) {
    const v = esc(ip);
    return `<span role="button" tabindex="0" class="secux-ip" draggable="true" data-secip="${v}" title="Cliquer pour agir, ou glisser vers une action">${v}</span>`;
  }

  // ── Fenêtre flottante ───────────────────────────────────────────────────────────────────
  let pop = null, popAnchor = null;
  function closePop() { pop?.remove(); pop = null; popAnchor = null; }

  function openPop(anchor, html) {
    closePop();
    pop = document.createElement('div');
    pop.className = 'secux-pop';
    pop.setAttribute('role', 'dialog');
    pop.innerHTML = html;
    document.body.append(pop);
    popAnchor = anchor;
    const r = anchor.getBoundingClientRect();
    const w = pop.offsetWidth, h = pop.offsetHeight;
    const left = Math.min(Math.max(8, r.left), Math.max(8, window.innerWidth - w - 8));
    let top = r.bottom + 6;
    if (top + h > window.innerHeight - 8) top = Math.max(8, r.top - h - 6);
    pop.style.left = left + window.scrollX + 'px';
    pop.style.top = top + window.scrollY + 'px';
    return pop;
  }

  document.addEventListener('mousedown', e => {
    if (pop && !pop.contains(e.target) && !(popAnchor && popAnchor.contains(e.target))) closePop();
  }, true);
  document.addEventListener('keydown', e => { if (e.key === 'Escape' && pop) { e.stopPropagation(); closePop(); } }, true);

  function ipMenu(btn) {
    if (popAnchor === btn) { closePop(); return; }
    const ip = btn.dataset.secip;
    const rows = ['ban1h', 'ban24h', 'banperm', 'allow', 'trace', 'logs', 'history', 'prism', 'copy']
      .map(k => `<button type="button" class="secux-mi${IP_DO[k].bad ? ' bad' : ''}" data-do="${k}">${esc(IP_DO[k].label)}</button>`).join('');
    const p = openPop(btn, `<div class="secux-pop-h"><span class="mono">${esc(ip)}</span></div>${rows}`);
    p.addEventListener('click', e => {
      const b = e.target.closest('[data-do]');
      if (!b) return;
      closePop();
      doIP(b.dataset.do, ip);
    });
    p.querySelector('button')?.focus();
  }

  // Expiration d'un ban : prolonger d'un pas, fixer « expire dans … » à la main, ou rendre permanent.
  function expiryPop(anchor, id) {
    if (popAnchor === anchor) { closePop(); return; }
    const b = (window._secBans || []).find(x => String(x.id) === String(id));
    if (!b) return;
    const exp = timeOf(b.expires_at);
    const chips = [['1 h', H], ['24 h', 24 * H], ['7 j', 7 * D], ['30 j', 30 * D]]
      .map(([l, ms]) => `<button type="button" class="secux-chip" data-ext="${ms}" ${exp == null ? 'disabled' : ''}>+ ${l}</button>`).join('');
    const p = openPop(anchor, `<div class="secux-pop-h"><span class="mono">${esc(b.ip)}</span>
      <span class="secux-mute">${exp == null ? 'Permanent' : 'expire ' + esc(fmtDate(b.expires_at))}</span></div>
      <div class="secux-pop-l">Prolonger de</div><div class="secux-row">${chips}</div>
      <div class="secux-pop-l">Expire dans</div>
      <div class="secux-row"><input class="input secux-in" id="secux-exp-in" placeholder="36h, 3j, 2sem…" autocomplete="off" spellcheck="false">
        <button type="button" class="btn btn-primary btn-sm" id="secux-exp-ok">OK</button></div>
      <div class="secux-row" style="margin-top:8px"><button type="button" class="btn btn-ghost btn-sm" data-perm="1" ${exp == null ? 'disabled' : ''}>Rendre permanent</button></div>`);
    const input = p.querySelector('#secux-exp-in');
    const apply = async () => {
      const ms = parseDur(input.value);
      if (ms === undefined) { input.classList.add('bad'); input.focus(); return; }
      closePop();
      await setExpiry(b, ms);
    };
    p.addEventListener('click', e => {
      const ext = e.target.closest('[data-ext]');
      if (ext) { closePop(); extend(b, +ext.dataset.ext); return; }
      if (e.target.closest('[data-perm]')) { closePop(); setExpiry(b, null); return; }
      if (e.target.closest('#secux-exp-ok')) apply();
    });
    input.addEventListener('input', () => input.classList.remove('bad'));
    input.addEventListener('keydown', e => { if (e.key === 'Enter') { e.preventDefault(); apply(); } });
    input.focus();
  }

  // ── Glisser-déposer ───────────────────────────────────────────────────────────────────
  // Chaque type d'objet déplaçable a ses zones de dépôt : une IP (bannir, autoriser, tracer), une CVE (statut),
  // une entrée du référentiel (rejeter, restaurer). Le type se lit sur data-secdrag="type:charge".
  let bar = null, barKind = '', dragging = false;
  const KINDS = {
    ip: {
      hint: 'déposez l’IP ici',
      zones: [['ban1h', 'Bannir 1 h', true], ['ban24h', 'Bannir 24 h', true], ['banperm', 'Bannir à vie', true], ['allow', 'Toujours autoriser', false], ['trace', 'Tracer', false]],
      run: (zone, raw) => {
        const t = parseTarget(raw);
        if (!t) { toast('Ce n’est pas une adresse IP ni un CIDR', 'error'); return; }
        doIP(zone, t.value);
      },
    },
    cve: {
      hint: 'déposez la CVE ici',
      zones: [['fixed', 'Corrigée', false], ['ignored', 'Ignorée', false], ['open', 'Rouverte', false]],
      run: (zone, id) => vsSetStatus(Number(id), zone),
    },
    ref: {
      hint: 'déposez l’entrée ici',
      zones: [['rejected', 'Rejeter', true], ['candidate', 'Restaurer', false]],
      run: (zone, raw) => { const e = JSON.parse(decodeURIComponent(raw)); return arSetEntryStatus(e.kind, e.value, zone); },
    },
  };

  function showBar(kind) {
    if (!bar) {
      bar = document.createElement('div');
      bar.id = 'secux-dropbar';
      bar.setAttribute('aria-hidden', 'true');
      document.body.append(bar);
    }
    if (barKind !== kind) {
      barKind = kind;
      bar.innerHTML = KINDS[kind].zones.map(([k, l, bad]) => `<div class="secux-dz${bad ? ' bad' : ''}" data-do="${k}"><span>${l}</span><small>${KINDS[kind].hint}</small></div>`).join('');
    }
    bar.classList.add('show');
  }

  // Ce que l'élément glissé transporte : { kind, payload } ; une IP vient d'un data-secip ou d'un texte sélectionné.
  function dragSource(e) {
    const el = e.target.closest?.('[data-secdrag]');
    if (el) {
      const v = el.dataset.secdrag, i = v.indexOf(':');
      if (KINDS[v.slice(0, i)]) return { kind: v.slice(0, i), payload: v.slice(i + 1) };
    }
    const ip = e.target.closest?.('[data-secip]')?.dataset.secip;
    if (ip) return { kind: 'ip', payload: ip };
    const sel = String(window.getSelection?.() || '').trim();
    return parseTarget(sel) ? { kind: 'ip', payload: sel } : null;
  }

  document.addEventListener('dragstart', e => {
    if (!inScope()) return;
    const src = dragSource(e);
    if (!src || !e.dataTransfer) return;
    e.dataTransfer.setData('text/plain', src.kind === 'ip' ? src.payload : src.kind + ':' + src.payload);
    e.dataTransfer.effectAllowed = 'copy';
    dragging = true;
    closePop();
    showBar(src.kind);
  });
  document.addEventListener('dragend', () => { dragging = false; bar?.classList.remove('show'); bar?.querySelectorAll('.hot').forEach(z => z.classList.remove('hot')); });
  document.addEventListener('dragover', e => {
    const z = e.target.closest?.('.secux-dz');
    if (!z) return;
    e.preventDefault();
    bar.querySelectorAll('.hot').forEach(x => { if (x !== z) x.classList.remove('hot'); });
    z.classList.add('hot');
  });
  document.addEventListener('dragleave', e => { e.target.closest?.('.secux-dz')?.classList.remove('hot'); });
  document.addEventListener('drop', async e => {
    const z = e.target.closest?.('.secux-dz');
    if (!z) return;
    e.preventDefault();
    dragging = false;
    bar.classList.remove('show');
    z.classList.remove('hot');
    const raw = e.dataTransfer?.getData('text/plain') || '';
    const i = raw.indexOf(':');
    const typed = i > 0 && KINDS[raw.slice(0, i)] && raw.slice(0, i) !== 'ip' && !parseTarget(raw);
    const kind = typed ? raw.slice(0, i) : 'ip';
    if (kind !== barKind) return;
    try { await KINDS[kind].run(z.dataset.do, typed ? raw.slice(i + 1) : raw); } catch (err) { toast(err.message, 'error'); }
  });

  document.addEventListener('click', e => {
    const b = e.target.closest?.('.secux-ip');
    if (b) { e.preventDefault(); ipMenu(b); }
  });
  document.addEventListener('keydown', e => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const b = e.target.closest?.('.secux-ip');
    if (b) { e.preventDefault(); ipMenu(b); }
  });

  // ── Ajout rapide d'un ban ───────────────────────────────────────────────────────────────
  const Q = { dur: null, durKey: '24h', target: null, seq: 0, timer: null };

  function quickBanHTML() {
    Q.durKey = lastDur();
    Q.dur = durMs(Q.durKey);
    const chips = DURS.map(([k, l]) => `<button type="button" class="secux-chip${k === Q.durKey ? ' on' : ''}" data-dur="${k}" onclick="SecUX.quickDur('${k}')" aria-pressed="${k === Q.durKey}">${l}</button>`).join('');
    return `<div id="secux-quick" class="card blueprint secux-quick">
      <div class="secux-quick-row">
        <input id="secux-q" class="input mono" list="secux-sugg" autocomplete="off" spellcheck="false" aria-label="Adresse IP ou CIDR à bannir"
          placeholder="Collez une IP ou un CIDR, puis Entrée (ex. 203.0.113.0/24 7j)" oninput="SecUX.quickInput(this.value)" onkeydown="SecUX.quickKey(event)">
        <datalist id="secux-sugg">${suggestions()}</datalist>
        <span class="secux-chips" role="group" aria-label="Durée du ban">${chips}</span>
        <button type="button" class="btn btn-danger btn-sm" id="secux-go" onclick="SecUX.quickGo()" disabled>Bannir</button>
        <button type="button" class="btn btn-ghost btn-sm" onclick="SecUX.quickMore()" title="Domaine, motif, portée, mesure d’impact">Plus d’options…</button>
      </div>
      <div id="secux-prev" class="secux-prev" aria-live="polite"></div>
    </div>`;
  }

  // IP déjà vues : détections CrowdSec puis bans expirés (re-bannir) ; le navigateur filtre à la frappe.
  function suggestions() {
    const seen = new Set();
    const opts = [];
    const add = (ip, why) => {
      if (!ip || seen.has(ip) || seen.size >= 80) return;
      seen.add(ip);
      opts.push(`<option value="${esc(ip)}" label="${esc(why || '')}"></option>`);
    };
    (window._secThreats || []).forEach(th => add(th.ip, th.scenario || 'CrowdSec'));
    (typeof _bn !== 'undefined' ? _bn.history || [] : []).forEach(b => add(b.ip, 'ban expiré'));
    return opts.join('');
  }

  function quickInput(v) {
    const [first, second] = String(v).trim().split(/\s+/);
    const tgt = first ? parseTarget(first) : null;
    Q.target = tgt;
    const input = document.getElementById('secux-q');
    input?.classList.toggle('bad', !!first && !tgt && /[\d:]/.test(first) && first.length > 6);
    if (second !== undefined) {
      const d = parseDur(second);
      if (d !== undefined) {
        Q.dur = d;
        const key = DURS.find(x => x[2] === d)?.[0] || '';
        document.querySelectorAll('#secux-quick [data-dur]').forEach(b => { const on = b.dataset.dur === key; b.classList.toggle('on', on); b.setAttribute('aria-pressed', on); });
      }
    }
    const go = document.getElementById('secux-go');
    if (go) go.disabled = !tgt;
    clearTimeout(Q.timer);
    const prev = document.getElementById('secux-prev');
    if (!tgt) { if (prev) prev.innerHTML = ''; return; }
    const seq = ++Q.seq;
    Q.timer = setTimeout(() => preview(tgt.value, seq), 350);
  }

  async function preview(value, seq) {
    const box = document.getElementById('secux-prev');
    if (!box) return;
    try {
      const r = await api('GET', '/security/bans/preview?ip=' + encodeURIComponent(value));
      if (seq !== Q.seq) return;
      const warns = (r.warnings || []).map(w => `<li>${esc(w)}</li>`).join('');
      box.innerHTML = `<b>${esc(t('security.ban_modal.preview_title', { target: r.target, addresses: Math.round(r.addresses) }))}</b>
        ${esc(t('security.ban_modal.preview_traffic', { hours: r.hours, requests: r.requests, ips: r.ips, blocked: r.blocked, ok: r.ok_requests, okips: r.ok_ips }))}
        ${warns ? `<ul class="secux-warn">${warns}</ul>` : ''}`;
    } catch (e) {
      if (seq === Q.seq) box.innerHTML = `<span class="secux-err">${esc(e.message)}</span>`;
    }
  }

  function quickDur(key) {
    Q.durKey = key;
    Q.dur = durMs(key);
    saveDur(key);
    document.querySelectorAll('#secux-quick [data-dur]').forEach(b => { const on = b.dataset.dur === key; b.classList.toggle('on', on); b.setAttribute('aria-pressed', on); });
    // Le mot de durée tapé après l'adresse ne doit pas contredire le choix qu'on vient de faire.
    const input = document.getElementById('secux-q');
    if (input) { const [first] = input.value.trim().split(/\s+/); input.value = first || ''; }
    document.getElementById('secux-q')?.focus();
  }

  function quickKey(e) {
    if (e.key === 'Enter') { e.preventDefault(); quickGo(); }
  }

  async function quickGo() {
    const input = document.getElementById('secux-q');
    const tgt = Q.target;
    if (!tgt) { input?.classList.add('bad'); input?.focus(); return; }
    try {
      await ban(tgt.value, { ms: Q.dur });
      const el = document.getElementById('secux-q');
      if (el) { el.value = ''; el.focus(); }
      const prev = document.getElementById('secux-prev');
      if (prev) prev.innerHTML = '';
      Q.target = null;
    } catch (e) { toast(e.message, 'error'); }
  }

  function quickMore() {
    const v = (document.getElementById('secux-q')?.value || '').trim().split(/\s+/)[0] || '';
    openBanModal({ ip: v, ms: Q.dur });
  }

  // ── Édition en place ───────────────────────────────────────────────────────────────────
  // Remplace le contenu de `el` par un champ : Entrée enregistre, Échap annule, sortir du champ annule.
  // `parse` renvoie la valeur à enregistrer, ou undefined si la saisie est invalide.
  function editInline(el, { value = '', type = 'text', min, step, placeholder = '', parse, onSave }) {
    if (el.querySelector('input')) return;
    const keep = el.innerHTML;
    const input = document.createElement('input');
    input.type = type;
    input.className = 'secux-inline';
    input.value = value;
    input.placeholder = placeholder;
    if (min != null) input.min = min;
    if (step != null) input.step = step;
    input.setAttribute('aria-label', placeholder || 'Valeur');
    el.innerHTML = '';
    el.append(input);
    input.focus();
    input.select();
    let finished = false;
    const restore = () => { if (finished) return; finished = true; el.innerHTML = keep; };
    input.addEventListener('keydown', async e => {
      if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); restore(); return; }
      if (e.key !== 'Enter') return;
      e.preventDefault();
      const v = parse ? parse(input.value) : input.value;
      if (v === undefined) { input.classList.add('bad'); return; }
      finished = true;
      el.innerHTML = '<span class="secux-mute">…</span>';
      await onSave(v);
    });
    input.addEventListener('blur', restore);
  }

  // ── Palette Ctrl+K : actions contextuelles ─────────────────────────────────────────────
  const norm = s => String(s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');
  const onPage = re => re.test(state.page || '');

  function staticActions() {
    const list = [
      { label: 'Nouveau ban…', kw: 'ajouter bannir ip cidr', run: () => openBanModal() },
      { label: 'Importer une liste de bans', kw: 'import csv json texte liste', run: () => openBanImport() },
      { label: 'Liste blanche des bans', kw: 'whitelist autoriser exception confiance', run: () => openBanWhitelist() },
      { label: 'Bannir un opérateur (ASN)', kw: 'asn as hébergeur opérateur plages', run: () => openBanAsn() },
      { label: 'Exporter les bans (CSV)', kw: 'export csv télécharger', run: () => exportBansCSV() },
      { label: 'Moteurs de sécurité', kw: 'ephor waf crowdsec seuils multi-passerelles scan sla moteurs', run: () => { _syn.mode = securityModeFromPage(state.page); secEnginesOpen('ephor'); } },
      { label: 'Réglages d’Ephor', kw: 'ephor réglages seuils tiroir', only: /security-ephor$/, run: () => openEphorSettings() },
      { label: 'Lancer une analyse de vulnérabilités', kw: 'scan trivy cve analyser', only: /^edge-security-vulns$/, run: () => triggerVulnscan() },
      { label: 'Recalculer le référentiel des attaques', kw: 'référentiel mineur lancer calcul', only: /security-attack-ref$/, run: () => arRun() },
      { label: 'Actualiser la page', kw: 'recharger rafraîchir', run: () => reloadCurrentSecurityPage() },
    ];
    return list.filter(a => !a.only || a.only.test(state.page || ''));
  }

  function paletteProvider(q) {
    if (!inScope()) return [];
    const sec = typeof SECURITY_PAGES !== 'undefined' && SECURITY_PAGES.has(state.page);
    const raw = String(q || '').trim();
    const mk = (label, group, run) => ({ action: true, label, group, scope: 'action', run });
    const out = [];
    const [first, second] = raw.split(/\s+/);
    const tgt = first ? parseTarget(first) : null;
    if (tgt) {
      const typed = second !== undefined ? parseDur(second) : undefined;
      const ms = typed !== undefined ? typed : durMs(lastDur());
      const keys = ['ban1h', 'ban24h', 'ban7d', 'banperm'];
      out.push(mk(`Bannir ${tgt.value} ${durLabel(ms)}`, typed !== undefined ? 'durée saisie' : 'dernière durée', () => { const k = DURS.find(d => d[2] === ms)?.[0]; if (k) saveDur(k); return ban(tgt.value, { ms }).catch(e => toast(e.message, 'error')); }));
      keys.forEach(k => out.push(mk(`${IP_DO[k].label} · ${tgt.value}`, '', () => doIP(k, tgt.value))));
      ['allow', 'unban', 'extend', 'perm', 'trace', 'logs', 'history', 'prism'].forEach(k => out.push(mk(`${IP_DO[k].label} · ${tgt.value}`, '', () => doIP(k, tgt.value))));
      return out;
    }
    if (!sec) return [];
    const words = norm(raw).split(/\s+/).filter(Boolean);
    const acts = staticActions().filter(a => !words.length || words.every(w => norm(a.label + ' ' + a.kw).includes(w)));
    acts.slice(0, words.length ? 8 : 5).forEach(a => out.push(mk(a.label, '', a.run)));
    return out;
  }


  // ── Navigation entre les sous-pages d'un espace ────────────────────────────────────────
  // Menaces : Bans, Traçage IP, Référentiel ; Défenses : Ephor, Moteurs ; Exposition : Vulnérabilités, Score par proxy.
  // Traçage IP et Référentiel n'existent que côté Admin. `window._secBadges` porte les compteurs ({ bans, vulns, attackref }).
  const SPACE_SUBS = {
    threats: [['bans'], ['trace', 1], ['attackref', 1]],
    defenses: [['ephor'], ['engines']],
    exposure: [['vulns'], ['posture']],
  };
  function subNav(space, active, mode) {
    const edge = mode === 'edge', badges = window._secBadges || {};
    const items = (SPACE_SUBS[space] || []).filter(([, adminOnly]) => !(adminOnly && edge));
    if (items.length < 2) return '';
    return `<div class="sx-subnav" role="tablist">${items.map(([k]) => {
      const n = badges[k];
      return `<button type="button" role="tab" class="chip${k === active ? ' active' : ''}" aria-selected="${k === active}" onclick="navigate('${securityPageId(k, mode)}')">${esc(t('sec.tab.' + k))}${n ? `<span class="chip-n">${n}</span>` : ''}</button>`;
    }).join('')}</div>`;
  }


  // ── Lignes à glisser ───────────────────────────────────────────────────────────────────
  // <li class="sx-swipe" data-swipe="fn" data-id="…"> : vers la gauche appelle window[fn](id, 'left'), vers la droite 'right'.
  // Un glissement qui part d'un bouton, d'un champ ou d'une IP déplaçable ne compte pas.
  let SW = null;
  document.addEventListener('pointerdown', e => {
    const fg = e.target.closest?.('.sx-swipe-fg');
    if (!fg || e.pointerType === 'mouse' && e.button !== 0 || e.target.closest('button,input,select,textarea,a,[draggable="true"]')) return;
    SW = { fg, li: fg.parentElement, x0: e.clientX, y0: e.clientY, dx: 0, lock: false, pid: e.pointerId };
  });
  document.addEventListener('pointermove', e => {
    if (!SW) return;
    const dx = e.clientX - SW.x0, dy = e.clientY - SW.y0;
    if (!SW.lock) {
      if (Math.abs(dx) > 8 && Math.abs(dx) > Math.abs(dy) * 1.4) { SW.lock = true; SW.fg.setPointerCapture?.(SW.pid); SW.fg.style.transition = 'none'; }
      else if (Math.abs(dy) > 10) { SW = null; return; } else return;
    }
    SW.dx = Math.max(-170, Math.min(170, dx));
    SW.fg.style.transform = `translateX(${SW.dx}px)`;
    SW.li.dataset.dir = SW.dx < 0 ? 'left' : 'right';
    SW.li.style.setProperty('--p', Math.min(1, Math.abs(SW.dx) / 90));
  });
  const swipeEnd = () => {
    if (!SW) return;
    const s = SW; SW = null;
    if (!s.lock) return;
    s.fg.style.transition = '';
    const fn = window[s.li.dataset.swipe];
    if (s.dx <= -90 && fn) { s.fg.style.transform = 'translateX(-110%)'; setTimeout(() => fn(s.li.dataset.id, 'left'), 140); }
    else { s.fg.style.transform = ''; if (s.dx >= 90 && fn) fn(s.li.dataset.id, 'right'); }
    s.li.removeAttribute('data-dir');
  };
  document.addEventListener('pointerup', swipeEnd);
  document.addEventListener('pointercancel', swipeEnd);

  window.gpxPaletteProviders = window.gpxPaletteProviders || [];
  window.gpxPaletteProviders.push(paletteProvider);

  return {
    parseTarget, parseDur, durLabel, goDuration, timeOf, iso,
    remember, refresh, ban, unban, setExpiry, extend, allow, unallow,
    ipHTML, ipMenu, expiryPop, closePop,
    quickBanHTML, quickInput, quickKey, quickGo, quickDur, quickMore,
    editInline, subNav, doIP,
    get dragging() { return dragging; },
  };
})();
