// ── Noyau d'interactions du menu Observabilité ────────────────────────────────────────────
// Briques partagées par Synthèse, Trafic (Prism, Vue Proxy), Journaux (accès, système, audit) et Santé (métriques,
// alertes et SLO) : navigation par espaces, période saisie à la main, plage tracée à la souris sur un graphique,
// IP déplaçables vers la barre de dépôt de SecUX, requête à jetons (status:5xx ip:… since:6h), objectif SLO modifiable
// sur place, actions contextuelles dans la palette Ctrl+K. Aucune donnée propre : tout passe par l'API existante.

const ObsUX = (() => {
  const adminRole = () => state.user?.role === 'superadmin' || state.user?.role === 'admin';

  // Chaque sous-page garde son identifiant d'avant la refonte : adresses, liens et SPACE_EQUIV restent valables.
  const SUBS = {
    traffic: [
      { admin: 'prism', edge: 'edge-prism' },
      { admin: 'proxy-inspector', edge: 'edge-proxy-inspector' },
    ],
    logs: [
      { admin: 'logs', edge: 'edge-logs-access' },
      { admin: 'logs-system', edge: 'edge-logs-system' },
      { admin: 'audit', edge: null, guard: adminRole },
    ],
    health: [
      { admin: 'obs-metrics', edge: 'edge-metrics' },
      { admin: 'obs-alerts', edge: 'edge-obs-alerts', badge: 'obs_alerts' },
    ],
  };
  const PAGES = new Set(['admin-observability', 'edge-observability', 'obs-synthese', 'edge-obs-synthese']);
  Object.values(SUBS).flat().forEach(s => { if (s.admin) PAGES.add(s.admin); if (s.edge) PAGES.add(s.edge); });
  const isObs = (page = state.page) => PAGES.has(page);

  // ── Ce que la page affichée met à la disposition du noyau ──────────────────────────────
  // reload() : se redessiner après une action ; range(ms) : changer de période ; brush({from,to}) : plage tracée ;
  // live() / liveOn() : flux en direct ; export(fmt) ; refresh() ; actions() : [{ label, kw, run }] propres à la page.
  let hooks = {};
  const setPage = h => { hooks = h || {}; };
  const resetPage = () => { hooks = {}; closeSuggest(); };
  const reload = () => (hooks.reload ? hooks.reload() : undefined);

  // ── Navigation entre les sous-pages d'un espace ────────────────────────────────────────
  function subNav(pageId = state.page) {
    const edge = pageId.startsWith('edge-');
    for (const list of Object.values(SUBS)) {
      const hit = list.find(s => s.admin === pageId || s.edge === pageId);
      if (!hit) continue;
      const items = list.filter(s => (edge ? s.edge : s.admin && (!s.guard || s.guard())));
      if (items.length < 2) return '';
      const badges = window._secBadges || {};
      const titles = APP_CONFIG.pageTitles || {};
      return `<div class="sx-subnav" role="tablist">${items.map(s => {
        const id = edge ? s.edge : s.admin;
        const n = s.badge ? badges[s.badge] : 0;
        return `<button type="button" role="tab" class="chip${s === hit ? ' active' : ''}" aria-selected="${s === hit}" onclick="navigate('${id}')">${esc(gpxPageLabel(id, titles[id]))}${n ? `<span class="chip-n">${n}</span>` : ''}</button>`;
      }).join('')}</div>`;
    }
    return '';
  }

  // Compteur de l'onglet Santé : alertes des dernières 24 h ni acquittées ni mises en sourdine.
  let badgeAt = 0, badgeKey = '';
  async function loadBadges(force) {
    const node = state.selectedEdge ? (state.selectedEdge.node_name || state.selectedEdge.id || '') : '';
    if (!force && Date.now() - badgeAt < 60000 && node === badgeKey) return;
    badgeAt = Date.now();
    badgeKey = node;
    const p = new URLSearchParams({ limit: '200', days: '1' });
    if (node) p.set('node', node);
    const list = await api('GET', '/alert-events?' + p).catch(() => null);
    if (!Array.isArray(list)) return;
    const n = list.filter(e => !e.acked && !e.silenced).length;
    const b = (window._secBadges = window._secBadges || {});
    if (b.obs_alerts === n) return;
    b.obs_alerts = n;
    if (isObs() && typeof renderPageTabs === 'function') renderPageTabs(state.page);
  }

  // ── Période saisie ──────────────────────────────────────────────────────────────────────
  // « 90min », « 3h », « 2j », « 2sem » : la même écriture que les durées de bans.
  function parseSpan(text) {
    const ms = SecUX.parseDur(text);
    return typeof ms === 'number' ? ms : undefined;
  }
  function spanLabel(ms) {
    if (ms >= 86400000 && ms % 86400000 === 0) return ms / 86400000 + 'j';
    if (ms >= 3600000 && ms % 3600000 === 0) return ms / 3600000 + 'h';
    return Math.round(ms / 60000) + 'min';
  }

  // periods : [[libellé, ms]]. attr : attribut posé sur chaque puce quand la page a déjà son gestionnaire de clic.
  function rangeHTML(periods, activeMs, { attr = 'data-oux-range', all = '' } = {}) {
    const known = periods.some(([, ms]) => ms === activeMs);
    const btns = periods.map(([l, ms]) => `<button type="button" class="seg-btn${ms === activeMs ? ' active' : ''}" ${attr}="${ms}">${esc(l)}</button>`).join('');
    const custom = activeMs && !known ? spanLabel(activeMs) : '';
    const hint = esc(t('obs.ux.period_hint'));
    return `<div class="logs-seg oux-range" role="group">${btns}${all}<input type="text" class="oux-range-in${custom ? ' on' : ''}" data-oux-range-in value="${esc(custom)}" placeholder="${esc(t('obs.ux.other_period'))}" title="${hint}" aria-label="${hint}" autocomplete="off" spellcheck="false"></div>`;
  }

  document.addEventListener('click', e => {
    const chip = e.target.closest?.('[data-oux-range]');
    if (chip && isObs() && hooks.range) { e.preventDefault(); hooks.range(parseInt(chip.dataset.ouxRange, 10)); }
  });
  document.addEventListener('keydown', e => {
    const input = e.target.closest?.('[data-oux-range-in]');
    if (!input || e.key !== 'Enter') return;
    e.preventDefault();
    const v = input.value.trim();
    if (!v) return;
    const ms = parseSpan(v);
    if (ms === undefined || !hooks.range) { input.classList.add('bad'); return; }
    input.classList.remove('bad');
    hooks.range(ms);
  });
  document.addEventListener('input', e => e.target.closest?.('[data-oux-range-in]')?.classList.remove('bad'));

  // ── Plage tracée sur un graphique ──────────────────────────────────────────────────────
  // Glisser sur un histogramme ou sur la courbe de requêtes choisit une plage ; un simple clic garde son effet
  // d'avant (zoomer sur la tranche). La page reçoit { from, to } en ISO.
  let br = null, swallow = false;
  const bucketAttr = el => { for (const a of el.attributes) if (/^data-.*bucket$/.test(a.name)) return a.value; return ''; };

  function brushModel(svg) {
    const vb = svg.viewBox.baseVal;
    if (svg.classList.contains('gpx-hist-svg')) {
      const gs = [...svg.querySelectorAll('g[data-unit]')];
      const bw = vb.width / (gs.length || 1);
      return { unit: gs[0]?.dataset.unit || 'hour', h: vb.height, vb, cells: gs.map((g, i) => ({ bucket: bucketAttr(g), x0: i * bw, x1: (i + 1) * bw })) };
    }
    const cs = [...svg.querySelectorAll('circle[data-bucket]')];
    const xs = cs.map(c => +c.getAttribute('cx'));
    return { unit: svg.dataset.unit || 'hour', h: vb.height, vb, cells: cs.map((c, i) => ({ bucket: c.dataset.bucket, x0: i ? (xs[i - 1] + xs[i]) / 2 : xs[i], x1: i < cs.length - 1 ? (xs[i] + xs[i + 1]) / 2 : xs[i] })) };
  }
  function brushIndex(b, clientX) {
    const r = b.svg.getBoundingClientRect();
    const x = (clientX - r.left) / (r.width || 1) * b.m.vb.width + b.m.vb.x;
    const cells = b.m.cells;
    for (let i = 0; i < cells.length; i++) if (x < cells[i].x1) return i;
    return cells.length - 1;
  }
  function brushDraw(b) {
    if (!b.box) {
      b.box = document.createElementNS('http://www.w3.org/2000/svg', 'rect');
      b.box.setAttribute('class', 'oux-brush');
      b.box.setAttribute('pointer-events', 'none');
      b.svg.append(b.box);
    }
    const [lo, hi] = b.i0 <= b.i1 ? [b.i0, b.i1] : [b.i1, b.i0];
    const x0 = b.m.cells[lo].x0, x1 = Math.max(b.m.cells[hi].x1, x0 + 2);
    b.box.setAttribute('x', x0);
    b.box.setAttribute('y', 0);
    b.box.setAttribute('width', x1 - x0);
    b.box.setAttribute('height', b.m.h);
  }
  document.addEventListener('pointerdown', e => {
    if (!hooks.brush || (e.pointerType === 'mouse' && e.button !== 0)) return;
    const svg = e.target.closest?.('svg.gpx-hist-svg, svg.prism-svg');
    if (!svg) return;
    const m = brushModel(svg);
    if (m.cells.length < 2) return;
    br = { svg, m, pid: e.pointerId, x: e.clientX, moved: false, box: null };
    br.i0 = br.i1 = brushIndex(br, e.clientX);
  });
  document.addEventListener('pointermove', e => {
    if (!br) return;
    if (!br.moved) {
      if (Math.abs(e.clientX - br.x) < 6) return;
      br.moved = true;
      try { br.svg.setPointerCapture(br.pid); } catch { /* le pointeur a déjà disparu */ }
    }
    br.i1 = brushIndex(br, e.clientX);
    brushDraw(br);
  });
  const brushEnd = e => {
    if (!br) return;
    const b = br;
    br = null;
    b.box?.remove();
    if (!b.moved || b.i0 === b.i1) return;
    swallow = true;
    setTimeout(() => { swallow = false; }, 0);
    const [lo, hi] = b.i0 <= b.i1 ? [b.i0, b.i1] : [b.i1, b.i0];
    const r0 = obsBucketRange(b.m.cells[lo].bucket, b.m.unit), r1 = obsBucketRange(b.m.cells[hi].bucket, b.m.unit);
    if (!r0.from || !r1.to) return;
    hooks.brush({ from: new Date(r0.from).toISOString(), to: new Date(r1.to).toISOString(), fromLocal: r0.from, toLocal: r1.to });
  };
  // Une ligne glissée n'est pas une ligne cliquée : le clic qui suit un glissement ne doit rien ouvrir.
  let rowDown = null;
  document.addEventListener('pointerdown', e => { rowDown = e.target.closest?.('.sx-swipe-fg') ? e.clientX : null; }, true);
  document.addEventListener('click', e => {
    if (rowDown !== null && isObs() && Math.abs(e.clientX - rowDown) > 8 && e.target.closest?.('.sx-swipe-fg')) { e.stopPropagation(); e.preventDefault(); }
    rowDown = null;
  }, true);
  document.addEventListener('pointerup', brushEnd);
  document.addEventListener('pointercancel', () => { br?.box?.remove(); br = null; });
  document.addEventListener('click', e => { if (swallow) { e.stopPropagation(); e.preventDefault(); } }, true);

  // ── IP : déplaçable vers la barre de dépôt, menu au clic droit ──────────────────────────
  // Le clic garde l'effet que la page lui donne (filtrer) ; glisser bannit, autorise ou trace.
  // menu : l'IP n'a pas d'autre clic (Vue Proxy, flux en direct), donc le clic ouvre directement le menu d'actions.
  function ipBtn(ip, { cls = '', attrs = '', label, actionable = true, menu = false, tag = 'span' } = {}) {
    const v = esc(ip), shown = label == null ? v : label;
    if (!actionable || !SecUX.parseTarget(ip)) return `<${tag} ${attrs ? 'role="button" tabindex="0" ' : ''}class="${menu ? 'mono ' : 'log-filter-link '}${attrs ? 'oux-act ' : ''}${cls}" ${attrs}>${shown}</${tag}>`;
    return `<${tag} role="button" tabindex="0" class="${menu ? 'oux-ipmenu mono ' : 'log-filter-link '}oux-ipb oux-act ${cls}" draggable="true" data-secip="${v}" ${attrs} title="${esc(t(menu ? 'obs.ux.ip_hint_menu' : 'obs.ux.ip_hint'))}">${shown}</${tag}>`;
  }
  document.addEventListener('click', e => {
    const el = e.target.closest?.('.oux-ipmenu');
    if (el && isObs()) { e.preventDefault(); SecUX.ipMenu(el); }
  });
  document.addEventListener('contextmenu', e => {
    const el = e.target.closest?.('[data-secip]');
    if (!el || !isObs() || el.classList.contains('secux-ip')) return;
    e.preventDefault();
    SecUX.ipMenu(el);
  });
  document.addEventListener('keydown', e => {
    if (e.key !== 'Enter' && e.key !== ' ') return;
    const el = e.target.closest?.('.oux-act');
    if (!el || el.tagName === 'BUTTON' || el.tagName === 'INPUT' || !isObs()) return;
    e.preventDefault();
    el.click();
  });

  // ── Requête à jetons ────────────────────────────────────────────────────────────────────
  // « status:5xx ip:203.0.113.7 domain:example.com since:6h texte libre » : chaque jeton complet devient un filtre,
  // le reste est la recherche libre. Le dernier mot, encore en cours de frappe, n'est pas touché sauf avec final.
  const QKEYS = { status: 'status', code: 'status', ip: 'ip', domain: 'domain', host: 'domain', path: 'path', method: 'method', level: 'level', node: 'node_name', edge: 'node_name', component: 'component', ja4: 'tls_ja4', ja3: 'tls_ja3' };
  const QLEVELS = ['info', 'warn', 'error', 'debug'];
  function qValue(field, v) {
    v = v.replace(/^["']|["']$/g, '');
    if (!v) return null;
    if (field === 'status') return /^[2-5]xx$/i.test(v) ? v.toLowerCase() : /^[1-5]\d\d$/.test(v) ? v : null;
    if (field === 'method') return /^[a-z]{3,7}$/i.test(v) ? v.toUpperCase() : null;
    if (field === 'level') return QLEVELS.includes(v.toLowerCase()) ? v.toLowerCase() : null;
    return v;
  }
  function parseQuery(text, { final = false, fields } = {}) {
    const src = String(text || '');
    const chunks = src.split(/\s+/).filter(Boolean);
    const open = !final && chunks.length && !/\s$/.test(src);
    const filters = {}, kept = [];
    let since = null;
    chunks.forEach((w, i) => {
      if (open && i === chunks.length - 1) { kept.push(w); return; }
      const m = /^([a-z0-9]+):(.+)$/i.exec(w);
      if (m) {
        const k = m[1].toLowerCase();
        if (k === 'since' || k === 'depuis') {
          const ms = parseSpan(m[2]);
          if (ms !== undefined) { since = ms; return; }
        } else if (QKEYS[k] && (!fields || fields.includes(QKEYS[k]))) {
          const v = qValue(QKEYS[k], m[2]);
          if (v) { filters[QKEYS[k]] = v; return; }
        }
      }
      kept.push(w);
    });
    const rest = kept.join(' ') + (kept.length && !open && /\s$/.test(src) ? ' ' : '');
    return { filters, since, rest, matched: since !== null || Object.keys(filters).length > 0 };
  }

  // ── Saisie assistée : proposition de mots pour un champ ────────────────────────────────
  let sg = null;
  function closeSuggest() { sg?.box.remove(); sg = null; }
  // items(mot) renvoie [{ label, insert }] ; Tab ou Entrée accepte la proposition en surbrillance.
  function attachSuggest(input, items, onPick) {
    if (input._ouxSg) return;
    input._ouxSg = true;
    const word = () => { const m = /(\S*)$/.exec(input.value.slice(0, input.selectionStart ?? input.value.length)); return m ? m[1] : ''; };
    const show = () => {
      const list = items(word());
      if (!list.length) { closeSuggest(); return; }
      if (!sg || sg.input !== input) {
        closeSuggest();
        const box = document.createElement('div');
        box.className = 'oux-sg';
        box.setAttribute('role', 'listbox');
        input.parentElement.append(box);
        sg = { box, input, list, hl: 0 };
      }
      sg.list = list;
      sg.hl = Math.min(sg.hl, list.length - 1);
      sg.box.innerHTML = list.map((it, i) => `<button type="button" role="option" class="oux-sg-i${i === sg.hl ? ' hl' : ''}" data-i="${i}">${esc(it.label)}</button>`).join('');
    };
    const pick = i => {
      const it = sg?.list[i];
      if (!it) return;
      const pos = input.selectionStart ?? input.value.length;
      const w = word();
      const head = input.value.slice(0, pos - w.length), tail = input.value.slice(pos);
      const add = it.insert + (it.insert.endsWith(':') ? '' : ' ');
      input.value = head + add + tail.replace(/^\S*/, '');
      input.setSelectionRange(head.length + add.length, head.length + add.length);
      closeSuggest();
      input.focus();
      onPick?.();
    };
    input.addEventListener('input', show);
    input.addEventListener('focus', show);
    input.addEventListener('keydown', e => {
      if (!sg || sg.input !== input) return;
      if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        sg.hl = (sg.hl + (e.key === 'ArrowDown' ? 1 : -1) + sg.list.length) % sg.list.length;
        sg.box.querySelectorAll('.oux-sg-i').forEach((b, i) => b.classList.toggle('hl', i === sg.hl));
      } else if (e.key === 'Tab' || (e.key === 'Enter' && !e.shiftKey && sg.list[sg.hl] && sg.list[sg.hl].insert !== word())) {
        if (e.key === 'Tab' && !sg.list.length) return;
        e.preventDefault();
        e.stopImmediatePropagation();
        pick(sg.hl);
      } else if (e.key === 'Escape') { closeSuggest(); }
    }, true);
    input.addEventListener('blur', () => setTimeout(() => { if (sg?.input === input && document.activeElement !== input) closeSuggest(); }, 150));
    input.parentElement.addEventListener('mousedown', e => {
      const b = e.target.closest('.oux-sg-i');
      if (b) { e.preventDefault(); pick(+b.dataset.i); }
    });
  }

  // ── Objectif SLO ────────────────────────────────────────────────────────────────────────
  // Puces à la place du sélecteur ; « … » ouvre un champ pour une valeur libre (90 à 99,999 %). Tout s'annule.
  const SLO_MIN = 90, SLO_MAX = 99.999;
  const sloQuery = node => (node ? '?node_name=' + encodeURIComponent(node) : '');

  async function sloSet(card, target) {
    const node = card.dataset.node || '';
    const prev = parseFloat(card.dataset.target);
    const had = card.dataset.override === '1';
    if (!(target >= SLO_MIN && target <= SLO_MAX)) { toast(t('obs.ux.slo_bad'), 'error'); return; }
    if (target === prev && (had || !node)) return;
    try {
      await api('PUT', '/prism/slo/config' + sloQuery(node), { target });
    } catch (err) { toast(err.message, 'error'); return; }
    SecUX.remember(t('obs.ux.slo_set', { v: target }), async () => {
      if (node && !had) await api('DELETE', '/prism/slo/config' + sloQuery(node));
      else await api('PUT', '/prism/slo/config' + sloQuery(node), { target: prev });
      reload();
    });
    reload();
  }

  async function sloReset(card) {
    const node = card.dataset.node || '';
    const prev = parseFloat(card.dataset.target);
    if (!node) return;
    try {
      await api('DELETE', '/prism/slo/config' + sloQuery(node));
    } catch (err) { toast(err.message, 'error'); return; }
    SecUX.remember(t('obs.ux.slo_reset_done'), async () => {
      await api('PUT', '/prism/slo/config' + sloQuery(node), { target: prev });
      reload();
    });
    reload();
  }

  document.addEventListener('click', e => {
    const chip = e.target.closest?.('[data-oux-slo]');
    if (chip) { e.preventDefault(); sloSet(chip.closest('.oux-slo-card'), parseFloat(chip.dataset.ouxSlo)); return; }
    const custom = e.target.closest?.('[data-oux-slo-custom]');
    if (custom) {
      e.preventDefault();
      const card = custom.closest('.oux-slo-card');
      SecUX.editInline(custom, {
        value: card.dataset.target, type: 'number', min: SLO_MIN, step: 'any', placeholder: '99.95',
        parse: v => { const n = parseFloat(String(v).replace(',', '.')); return n >= SLO_MIN && n <= SLO_MAX ? n : undefined; },
        onSave: n => sloSet(card, n),
      });
      return;
    }
    const reset = e.target.closest?.('[data-oux-slo-reset]');
    if (reset) { e.preventDefault(); sloReset(reset.closest('.oux-slo-card')); }
  });

  // ── Ouvrir un proxy dans la Vue Proxy ───────────────────────────────────────────────────
  function openProxyView(host) {
    window._pxiPreset = String(host || '');
    navigate(state.selectedEdge ? 'edge-proxy-inspector' : 'proxy-inspector');
  }

  // ── Palette Ctrl+K : actions contextuelles ─────────────────────────────────────────────
  const norm = s => String(s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');
  const HOST_RE = /^(?=.{4,253}$)([a-z0-9-]+\.)+[a-z]{2,}$/i;
  const PRESETS = [['15 min', 900000], ['1 h', 3600000], ['6 h', 21600000], ['24 h', 86400000], ['7 j', 604800000]];

  function openLogsWith(q) {
    const o = { ...q.filters };
    if (q.since) o.date_from = new Date(Date.now() - q.since).toISOString();
    if (q.rest.trim()) o.search = q.rest.trim();
    if (typeof logsFilters !== 'undefined') for (const k of ['status', 'ip', 'path', 'method', 'level', 'search', 'tls_ja3', 'tls_ja4', 'date_from', 'date_to']) if (!(k in o)) o[k] = '';
    if (q.filters.node_name && typeof logsFilters !== 'undefined') logsFilters.node_name = q.filters.node_name;
    openLogsFiltered(o);
  }

  function paletteProvider(q) {
    if (!isObs()) return [];
    const raw = String(q || '').trim();
    const mk = (label, group, run) => ({ action: true, label, group, scope: 'action', run });
    const out = [];
    const tok = parseQuery(raw, { final: true });
    if (raw && tok.matched) out.push(mk(t('obs.ux.a_query_logs', { q: raw }), '', () => openLogsWith(tok)));
    if (HOST_RE.test(raw)) {
      out.push(mk(t('obs.ux.a_host_proxy', { h: raw }), '', () => openProxyView(raw)));
      out.push(mk(t('obs.ux.a_host_logs', { h: raw }), '', () => openLogsFiltered({ domain: raw })));
      out.push(mk(t('obs.ux.a_host_prism', { h: raw }), '', () => openPrismForProxy(raw)));
    }
    if (hooks.range && /^\d/.test(raw)) {
      const ms = parseSpan(raw);
      if (ms !== undefined) out.push(mk(t('obs.ux.a_period', { p: spanLabel(ms) }), '', () => hooks.range(ms)));
    }
    if (out.length && (tok.matched || HOST_RE.test(raw))) return out;

    const acts = [];
    if (hooks.refresh) acts.push({ label: t('obs.ux.a_refresh'), kw: 'actualiser recharger refresh rafraichir', run: hooks.refresh });
    if (hooks.range) PRESETS.forEach(([l, ms]) => acts.push({ label: t('obs.ux.a_period', { p: l }), kw: 'periode plage duree temps period range', run: () => hooks.range(ms) }));
    if (hooks.live) acts.push({ label: t(hooks.liveOn && hooks.liveOn() ? 'obs.ux.a_live_off' : 'obs.ux.a_live_on'), kw: 'direct live temps reel flux stream', run: hooks.live });
    if (hooks.export) {
      acts.push({ label: t('obs.ux.a_export_csv'), kw: 'export csv telecharger download', run: () => hooks.export('csv') });
      acts.push({ label: t('obs.ux.a_export_json'), kw: 'export json telecharger download', run: () => hooks.export('json') });
    }
    if (hooks.actions) acts.push(...hooks.actions());
    const words = norm(raw).split(/\s+/).filter(Boolean);
    const hit = acts.filter(a => !words.length || words.every(w => norm(a.label + ' ' + (a.kw || '')).includes(w)));
    hit.slice(0, words.length ? 8 : 5).forEach(a => out.push(mk(a.label, '', a.run)));
    return out;
  }
  window.gpxPaletteProviders = window.gpxPaletteProviders || [];
  window.gpxPaletteProviders.push(paletteProvider);

  return {
    isObs, setPage, resetPage, reload, subNav, loadBadges, badgeRefresh: () => loadBadges(true),
    parseSpan, spanLabel, rangeHTML, ipBtn, parseQuery, attachSuggest, openProxyView, openLogsWith,
    sloSet, sloReset,
  };
})();
