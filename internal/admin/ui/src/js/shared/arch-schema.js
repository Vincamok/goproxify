// Schéma d'architecture : rendu commun de la vue Infrastructure et du wizard.
// Le modèle (hôtes → rôles → capacités) vient de architecture.json (via _archLoad) ;
// l'état live (/nodes, /nodes/live) n'est qu'une surcouche.
// Dépend de pages/architecture-wizard.js (_arch, _ARCH_ICONS, _archBuildPacks…) et de core/api.js.

window._asLive = {};   // node_name → { rps, risk_level }
window._asHist = {};   // node_name → échantillons de statut de la session : g ok · o dégradé · r hors ligne · x inconnu
window._asHealthOK = true;
const AS_HIST_LEN = 24;

const _AS_ROLE = {
  edge:  { k: 'var(--purple)', label: 'arch.svc.edge' },
  agent: { k: 'var(--green)', label: 'arch.svc.agent' },
  admin: { k: 'var(--orange, #f97316)', label: 'arch.svc.admin' },
};

function _asKey(svc) { return svc.nodeName || svc.name; }

function _asState(svc) {
  if (svc.type === 'admin') return window._asHealthOK ? 'ok' : 'warn';
  if (svc.status === 'online') return 'ok';
  if (svc.status === 'declared') return 'off';
  return 'warn';
}

function _asAllSvcs(model) {
  return model.hosts.flatMap(h => (h.services || []).map(s => ({ s, h })));
}

function _asGroupOf(model, id) {
  return (model.haGroups || []).find(g => g.members.includes(id)) || null;
}

function _asCaps(model, svc) {
  const c = [];
  if (svc.type === 'edge') {
    if (svc.access) c.push('Access');
    if (_asGroupOf(model, svc.id)) c.push('HA');
    if (svc.domains || svc.acme) c.push('TLS');
  } else if (svc.type === 'agent') {
    if (svc.docker) c.push('Docker');
    if (svc.podman) c.push('Podman');
    if (svc.portainer) c.push('Portainer');
    if (svc.k8s) c.push('K8s');
  }
  return c;
}

function _asLiveNode(svc) {
  return (_arch.nodes || []).find(n => n.role === svc.type &&
    (n.node_name === svc.nodeName || n.node_name === svc.name || n.display_name === svc.name)) || null;
}

/** Une mesure par nœud : appelée au chargement puis à chaque tick du live. */
function asSample(model) {
  for (const { s } of _asAllSvcs(model)) {
    if (s.type === 'admin') continue;
    const st = _asState(s);
    const live = window._asLive[_asKey(s)];
    const ch = st === 'off' ? 'x' : st === 'warn' ? 'r' : (live && live.risk_level && live.risk_level !== 'low' ? 'o' : 'g');
    const h = window._asHist[_asKey(s)] = window._asHist[_asKey(s)] || [];
    h.push(ch);
    if (h.length > AS_HIST_LEN) h.shift();
  }
}

function _asSpark(key) {
  const h = (window._asHist[key] || []).slice();
  while (h.length < AS_HIST_LEN) h.unshift('x');
  return `<div class="as-spk">${h.map(c => `<i${c === 'g' ? '' : ` data-s="${c}"`}></i>`).join('')}</div>`;
}

function _asPct(key) {
  const h = (window._asHist[key] || []).filter(c => c !== 'x');
  if (!h.length) return null;
  return Math.round(h.filter(c => c === 'g' || c === 'o').length / h.length * 1000) / 10;
}

function _asNodeHTML(model, svc, host, o) {
  const role = _AS_ROLE[svc.type];
  const st = _asState(svc);
  const key = _asKey(svc);
  const live = window._asLive[key];
  const stTxt = st === 'ok' ? t('as.st.online') : st === 'off' ? t('as.st.declared') : t('as.st.offline');
  const caps = _asCaps(model, svc);
  let body = '';
  if (o.edit && svc.type !== 'admin') {
    body = '';
  } else if (svc.type === 'admin') {
    const ne = _asAllSvcs(model).filter(x => x.s.type === 'edge').length;
    const na = _asAllSvcs(model).filter(x => x.s.type === 'agent').length;
    body = `<div class="as-ft" style="margin-top:10px"><span>${esc(t('as.manages_n', { e: ne, a: na }))}</span></div>`;
  } else {
    const pct = _asPct(key);
    const right = svc.type === 'edge'
      ? (live ? esc(t('as.req_s', { n: live.rps < 10 ? live.rps.toFixed(1) : Math.round(live.rps) })) : '')
      : '';
    body = `${_asSpark(key)}<div class="as-ft"><span>${pct == null ? '—' : `<b>${String(pct).replace('.', ',')} %</b> · ${esc(t('as.session'))}`}</span><span>${right}</span></div>`;
  }
  const meta = svc.type === 'admin'
    ? `${t('as.admin_role')} · ${host ? host.name : ''}`
    : `${t(role.label)} · ${host ? host.name : ''}`;
  const virtual = svc.virtual ? ' data-virtual' : '';
  return `<button type="button" class="as-node" style="--k:${role.k};--h:${_asHostColor(model, host)}" data-svc="${esc(svc.id)}"${virtual}${o.sel ? ' data-sel' : ''}${st === 'warn' ? ' data-tone="warn"' : ''}
    onclick="asNodeClick('${esc(svc.id)}')">
    <span class="as-hd"><span class="as-ic">${_ARCH_ICONS[svc.type] || ''}</span>
      <span class="as-nm">${esc(svc.name)}<small>${esc(meta)}</small></span>
      <span class="as-st" data-tone="${st}">${esc(stTxt)}</span></span>
    ${body}
    ${caps.length ? `<span class="as-cs">${caps.map(c => `<span>${esc(c)}</span>`).join('')}</span>` : ''}
  </button>`;
}

function _asKpis(model, edges, agents) {
  const all = edges.concat(agents);
  const up = all.filter(x => _asState(x.s) === 'ok').length;
  const rps = edges.reduce((n, x) => n + ((window._asLive[_asKey(x.s)] || {}).rps || 0), 0);
  const grp = (model.haGroups || []).find(g => g.members.length >= 2);
  const quorum = grp ? `${grp.members.filter(id => { const x = all.find(y => y.s.id === id); return x && _asState(x.s) === 'ok'; }).length} <small>/ ${grp.members.length}</small>` : '—';
  const bad = all.find(x => _asState(x.s) === 'warn');
  return `<div class="as-kpis">
    <div class="as-kpi"><div class="as-kpi-l">${esc(t('as.kpi.reqs'))}</div><div class="as-kpi-v">${rps < 10 ? rps.toFixed(1) : Math.round(rps)} <small>req/s</small></div></div>
    <div class="as-kpi"><div class="as-kpi-l">${esc(t('as.kpi.online'))}</div><div class="as-kpi-v">${up} <small>/ ${all.length}</small></div></div>
    <div class="as-kpi"><div class="as-kpi-l">${esc(t('as.kpi.quorum'))}</div><div class="as-kpi-v">${quorum}</div></div>
    <div class="as-kpi"${bad ? ' data-tone="warn"' : ''}><div class="as-kpi-l">${esc(t('as.kpi.alert'))}</div><div class="as-kpi-v" style="font-size:14px">${bad ? esc(t('as.offline_node', { name: bad.s.name })) : esc(t('as.kpi.no_alert'))}</div></div>
  </div>`;
}

/** model = { hosts, haGroups } ; o = { edit, selectedId, kpis } */
function _asTiersHTML(model, o) {
  o = o || {};
  const all = _asAllSvcs(model);
  const edges = all.filter(x => x.s.type === 'edge');
  const agents = all.filter(x => x.s.type === 'agent');
  let admin = all.find(x => x.s.type === 'admin');
  if (!all.length && !o.edit) return `<div class="as-empty">${esc(t('as.empty'))}</div>`;
  if (!admin) admin = { s: { id: 'admin-virtual', type: 'admin', name: 'Admin', status: 'online', virtual: true }, h: null };
  const node = x => _asNodeHTML(model, x.s, x.h, { sel: o.selectedId === x.s.id, edit: !!o.edit });
  const add = type => o.edit ? `<button type="button" class="as-add" onclick="asAdd('${type}')">${esc(t('as.add'))}</button>` : '';

  const grouped = new Set();
  const groups = (model.haGroups || []).map(g => {
    const members = edges.filter(x => g.members.includes(x.s.id));
    members.forEach(x => grouped.add(x.s.id));
    if (!members.length) return '';
    const leader = members[0].s.name;
    const upN = members.filter(x => _asState(x.s) === 'ok').length;
    return `<div class="as-ha"><span class="as-ha-tag">${esc(t('as.ha_tag', { id: g.id, leader, up: upN, n: members.length }))}</span>
      <div class="as-ha-in">${members.map(node).join('')}</div></div>`;
  }).join('');
  const loose = edges.filter(x => !grouped.has(x.s.id));
  const gateways = `<div style="display:grid;gap:10px;min-width:0">${groups}${loose.length ? `<div class="as-ha-in">${loose.map(node).join('')}</div>` : ''}${!edges.length ? `<div class="as-empty" style="padding:14px 0">${esc(t('as.no_gateway'))}</div>` : ''}</div>`;

  const upE = edges.filter(x => _asState(x.s) === 'ok').length;
  const upA = agents.filter(x => _asState(x.s) === 'ok').length;
  return `<div class="as-tiers">
    ${o.kpis ? _asKpis(model, edges, agents) : ''}
    <div class="as-net"><span class="as-pill">${_ARCH_ICONS.globe} ${esc(t('as.internet'))}</span></div>
    <div class="as-vl"><span>80 / 443</span></div>
    <div class="as-tier">
      <div class="as-th"><b>${esc(t('as.gateways'))}</b>${add('edge')}<span class="as-th-m">${esc(t('as.tier_online', { up: upE, n: edges.length }))}</span></div>
      <div class="as-row">
        ${gateways}
        <div class="as-hl"><span>${esc(t('as.manages'))}</span></div>
        <div class="as-who"><span class="as-pill">${esc(t('as.administrator'))}</span><div class="as-vl" data-dashed style="height:26px;--c:var(--purple)"></div>${node(admin)}</div>
      </div>
    </div>
    <div class="as-vl" data-up style="--c:var(--green)"><span>${esc(t('as.flow_ws', { n: agents.length }))}</span></div>
    <div class="as-tier">
      <div class="as-th"><b>${esc(t('as.agents'))}</b>${add('agent')}<span class="as-th-m">${esc(t('as.tier_online', { up: upA, n: agents.length }))}</span></div>
      <div class="as-ag">${agents.map(x => `<div>${node(x)}</div>`).join('')}${o.edit ? `<div><button type="button" class="as-slot" onclick="asAdd('agent')">+ ${esc(t('as.add_agent'))}</button></div>` : ''}</div>
      ${!agents.length && !o.edit ? `<div class="as-empty" style="padding:14px 0">${esc(t('as.no_agent'))}</div>` : ''}
    </div>
    ${o.kpis ? `<div class="as-legend"><span style="--c:var(--blue)">${esc(t('as.legend.users'))}</span><span style="--c:var(--green)">${esc(t('as.legend.ws'))}</span><span style="--c:var(--purple)">${esc(t('as.legend.admin'))}</span></div>` : ''}
  </div>`;
}

// ── Hôtes : chaque hôte porte un ou plusieurs rôles (passerelle, agent, Admin) ; un agent porte une ou plusieurs plateformes ──

const _AS_HOST_COLORS = ['#378ADD', '#D85A30', '#7F77DD', '#1D9E75', '#BA7517', '#D4537E'];

function _asHostColor(model, host) {
  const i = host ? model.hosts.indexOf(host) : -1;
  return i < 0 ? 'var(--border)' : _AS_HOST_COLORS[i % _AS_HOST_COLORS.length];
}

window._asMode = (function () {
  try { return localStorage.getItem('gpx_as_mode') === 'host' ? 'host' : 'role'; } catch { return 'role'; }
})();
window._asMenu = null;

function _asRerender() {
  if (window._asEdit) { _archRender(); return; }
  const root = document.getElementById('as-root');
  if (root) root.innerHTML = asSchemaHTML(_arch, { kpis: true });
}

function asSetMode(mode) {
  window._asMode = mode;
  try { localStorage.setItem('gpx_as_mode', mode); } catch {}
  _asRerender();
}

function asToggleMenu(hostId) {
  window._asMenu = window._asMenu === hostId ? null : hostId;
  _asRerender();
}

function asAddTo(hostId, type) {
  window._asMenu = null;
  const host = _arch.hosts.find(h => h.id === hostId);
  if (host && type === 'edge' && !(host.services || []).length) host.internet = true;
  _archAddService(hostId, type);
}

function asAddHost() {
  const h = _archEmptyHost(_arch.hosts.length + 1);
  _arch.hosts.push(h);
  _arch.selectedHostId = h.id;
  _arch.selectedSvcId = null;
  _archRender();
}

/** Plateformes portées par les agents d'un hôte (Docker ou Podman, Portainer, K8s : cumulables sauf Docker/Podman). */
function _asPlatforms(h) {
  const set = new Set();
  for (const s of h.services || []) {
    if (s.type !== 'agent') continue;
    if (s.docker) set.add('Docker');
    if (s.podman) set.add('Podman');
    if (s.portainer) set.add('Portainer');
    if (s.k8s) set.add('K8s');
  }
  return [...set];
}

function _asAddMenu(model, h) {
  if (window._asMenu !== h.id) return '';
  const hasAdmin = _asAllSvcs(model).some(x => x.s.type === 'admin' && !x.s.virtual);
  const item = (type, desc, off) => `<button type="button" class="as-mi" ${off ? 'disabled' : ''} onclick="event.stopPropagation();asAddTo('${h.id}','${type}')"><span>${esc(t(_AS_ROLE[type].label))}</span><small>${esc(desc)}</small></button>`;
  return `<div class="as-menu">${item('edge', t('arch.role.edge_desc'))}${item('agent', t('arch.role.agent_desc'))}${item('admin', t('arch.role.admin_desc'), hasAdmin)}</div>`;
}

function _asHostHead(model, h, o) {
  const inet = !!h.internet;
  const zone = o.edit
    ? `<button type="button" class="as-zt" data-p="${inet ? 0 : 1}" onclick="event.stopPropagation();_archSetHostInternet('${h.id}',${!inet})" title="${esc(t('arch.host.internet_hint'))}">${esc(inet ? t('arch.host.internet') : t('arch.host.private'))}</button>`
    : `<span class="as-zt" data-p="${inet ? 0 : 1}">${esc(inet ? t('arch.host.internet') : t('arch.host.private'))}</span>`;
  return `<div class="as-hh"><span class="as-hd-dot"></span><b>${esc(h.name)}</b>${zone}</div>
    ${h.region ? `<small class="as-hsub">${esc(h.region)}</small>` : ''}`;
}

/** Bandeau d'hôtes du wizard : une carte par hôte + « Ajouter un hôte ». */
function _asHostStripHTML(model, o) {
  const cards = model.hosts.map(h => {
    const sel = o.selectedHostId === h.id && !o.selectedId;
    const roles = (h.services || []).map(s => `<span class="as-hrole" style="--k:${_AS_ROLE[s.type].k}" onclick="event.stopPropagation();asNodeClick('${esc(s.id)}')">${esc(s.name)}</span>`).join('');
    const plats = _asPlatforms(h).map(p => `<span class="as-hplat">${esc(p)}</span>`).join('');
    return `<div class="as-hcard"${sel ? ' data-sel' : ''} style="--h:${_asHostColor(model, h)}" onclick="_archSelectHost('${h.id}')">
      ${_asHostHead(model, h, o)}
      <div class="as-hroles">${roles || `<span class="as-hempty">${esc(t('as.host_empty'))}</span>`}</div>
      ${plats ? `<div class="as-hroles">${plats}</div>` : ''}
      <button type="button" class="as-add" onclick="event.stopPropagation();asToggleMenu('${h.id}')">${esc(t('as.add_element'))}</button>
      ${_asAddMenu(model, h)}
    </div>`;
  }).join('');
  return `<div class="as-hosts">${cards}<button type="button" class="as-hcard as-hnew" onclick="asAddHost()">+ ${esc(t('as.add_host'))}</button></div>`;
}

/** Vue « Par hôte » : chaque hôte est un cadre qui contient ses rôles. */
function _asByHostHTML(model, o) {
  const boxes = model.hosts.map(h => {
    const svcs = (h.services || []).map(s => _asNodeHTML(model, s, h, { sel: o.selectedId === s.id, edit: !!o.edit })).join('');
    const sel = o.edit && o.selectedHostId === h.id && !o.selectedId;
    const plats = _asPlatforms(h).map(p => `<span class="as-hplat">${esc(p)}</span>`).join('');
    return `<section class="as-hostbox"${sel ? ' data-sel' : ''} style="--h:${_asHostColor(model, h)}"${o.edit ? ` onclick="_archSelectHost('${h.id}')"` : ''}>
      ${_asHostHead(model, h, o)}
      ${plats ? `<div class="as-hroles">${plats}</div>` : ''}
      <div class="as-hostgrid">${svcs || `<span class="as-hempty">${esc(t('as.host_empty'))}</span>`}
        ${o.edit ? `<div class="as-hostadd"><button type="button" class="as-slot" onclick="event.stopPropagation();asToggleMenu('${h.id}')">${esc(t('as.add_element'))}</button>${_asAddMenu(model, h)}</div>` : ''}
      </div>
    </section>`;
  }).join('');
  return `<div class="as-byhost">${boxes}${o.edit ? `<button type="button" class="as-slot" style="min-height:64px" onclick="asAddHost()">+ ${esc(t('as.add_host'))}</button>` : ''}</div>`;
}

function _asToolbarHTML() {
  const b = (m, k) => `<button type="button"${window._asMode === m ? ' data-on' : ''} onclick="asSetMode('${m}')">${esc(t(k))}</button>`;
  return `<div class="as-seg">${b('role', 'as.by_role')}${b('host', 'as.by_host')}</div>`;
}

/** model = { hosts, haGroups } ; o = { edit, selectedId, selectedHostId, kpis } */
function asSchemaHTML(model, o) {
  o = o || {};
  const byHost = window._asMode === 'host';
  const all = _asAllSvcs(model);
  const kpis = o.kpis && byHost ? _asKpis(model, all.filter(x => x.s.type === 'edge'), all.filter(x => x.s.type === 'agent')) : '';
  return `<div class="as">
    ${_asToolbarHTML()}
    ${o.edit && !byHost ? _asHostStripHTML(model, o) : ''}
    ${kpis}
    ${byHost ? _asByHostHTML(model, o) : _asTiersHTML(model, o)}
  </div>`;
}

function asNodeClick(id) {
  if (id === 'admin-virtual') return;
  if (window._asEdit) { _archSelectSvc(id); return; }
  asOpenDetail(id);
}

/** Wizard : ajoute un nœud à l'hôte sélectionné, sinon sur un hôte libre (ou un nouvel hôte). */
function asAdd(type) {
  let host = _arch.hosts.find(h => h.id === _arch.selectedHostId)
    || _arch.hosts.find(h => !(h.services || []).length);
  if (!host) { host = _archEmptyHost(_arch.hosts.length + 1); _arch.hosts.push(host); }
  if (type === 'edge' && !(host.services || []).length) host.internet = true;
  _archAddService(host.id, type);
}

function asMoveSvc(svcId, toHostId) {
  if (toHostId === 'new') {
    const h = _archEmptyHost(_arch.hosts.length + 1);
    _arch.hosts.push(h);
    toHostId = h.id;
  }
  _archMoveSvc(svcId, toHostId);
}

/** Inspecteur du wizard : rôle sélectionné + hôte qui le porte. */
function asInspectorHTML() {
  const svc = _arch.selectedSvcId ? _archFindSvc(_arch.selectedSvcId) : null;
  if (!svc) {
    const h = _arch.selectedHostId ? _arch.hosts.find(x => x.id === _arch.selectedHostId) : null;
    if (!h) return `<div class="as-ins"><div class="arch-insp-empty">${esc(t('arch.inspector_empty'))}</div></div>`;
    const roles = (h.services || []).map(s => `<button class="arch-addrole" style="--arch-accent:${_archRoleAccent(s.type)};display:block;width:100%;text-align:left;margin-bottom:5px;" onclick="_archSelectSvc('${s.id}')">${esc(t(_ARCH_ROLES[s.type].label))} · ${esc(s.name)}</button>`).join('');
    return `<div class="as-ins" style="padding:0;border:0;background:none"><div class="arch-panel">
      <div class="arch-insp-head"><div class="arch-insp-level">${esc(t('as.host'))}</div><div class="arch-insp-name">${esc(h.name)}</div><div class="arch-insp-note">${esc(t('as.host_note'))}</div></div>
      <div class="arch-insp-body">
        ${_archGroup(t('arch.group.identity'),
          _archField(t('arch.host.name'), `<input class="arch-input" value="${esc(h.name)}" onchange="_archRenameHost('${h.id}',this.value);_archRender()">`) +
          _archField(t('arch.host.region'), `<input class="arch-input" value="${esc(h.region || '')}" placeholder="eu-west-1" onchange="_archSetHostRegion('${h.id}',this.value)">`) +
          _archCapRow(!!h.internet, t('arch.host.internet'), t('arch.host.internet_hint'), `_archSetHostInternet('${h.id}',this.checked)`))}
        ${_archGroup(t('as.host_elements'), roles || `<div class="arch-cap-desc">${esc(t('as.host_empty'))}</div>`)}
        <div class="as-acts" style="margin-top:0">
          <button class="btn btn-secondary btn-sm" onclick="asOpenConfig('${h.id}')">${esc(t('as.config'))}</button>
          ${_arch.hosts.length > 1 ? `<button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="_archRemoveHost('${h.id}')">${esc(t('arch.host.remove'))}</button>` : ''}
        </div>
      </div></div></div>`;
  }
  const host = _archFindHostOfSvc(svc.id);
  const hostOpts = _arch.hosts.map(h => `<option value="${esc(h.id)}"${host && h.id === host.id ? ' selected' : ''}>${esc(h.name)}</option>`).join('')
    + `<option value="new">${esc(t('as.new_host'))}</option>`;
  const hostBlock = host ? `<div class="arch-panel" style="margin-top:10px">
      <div class="arch-insp-body">
        ${_archGroup(t('as.host'),
          _archField(t('as.host'), `<select class="arch-select" onchange="asMoveSvc('${svc.id}',this.value)">${hostOpts}</select>`) +
          _archField(t('arch.host.name'), `<input class="arch-input" value="${esc(host.name)}" onchange="_archRenameHost('${host.id}',this.value);_archRender()">`) +
          _archField(t('arch.host.region'), `<input class="arch-input" value="${esc(host.region || '')}" placeholder="eu-west-1" onchange="_archSetHostRegion('${host.id}',this.value)">`) +
          _archCapRow(!!host.internet, t('arch.host.internet'), t('arch.host.internet_hint'), `_archSetHostInternet('${host.id}',this.checked)`))}
        <div class="as-acts" style="margin-top:0"><button class="btn btn-secondary btn-sm" onclick="asOpenConfig('${host.id}')">${esc(t('as.config'))}</button></div>
      </div></div>` : '';
  return `<div class="as-ins" style="padding:0;border:0;background:none">${_archInspectRole(svc)}${hostBlock}</div>`;
}

// ── Détail d'un nœud (vue) ───────────────────────────────────────────────────

const _asM = { hostId: null, tab: 'f', fmt: 'compose', versions: null, current: null, verName: null, verData: null, ticket: null, detailId: null };

function _asOverlay(html) {
  let ov = document.getElementById('as-overlay');
  if (!ov) {
    ov = document.createElement('div');
    ov.id = 'as-overlay';
    ov.className = 'as-ov';
    ov.onclick = e => { if (e.target === ov) asCloseModal(); };
    document.body.appendChild(ov);
    document.addEventListener('keydown', _asEsc);
  }
  ov.innerHTML = `<div class="as-md">${html}</div>`;
}

function _asEsc(e) { if (e.key === 'Escape') asCloseModal(); }

function asCloseModal() {
  const ov = document.getElementById('as-overlay');
  if (ov) ov.remove();
  document.removeEventListener('keydown', _asEsc);
}

function asOpenDetail(id) {
  const x = _asAllSvcs(_arch).find(y => y.s.id === id);
  if (!x) return;
  _asM.detailId = id;
  const { s, h } = x;
  const node = _asLiveNode(s);
  const st = _asState(s);
  const row = (k, v) => v ? `<tr><td style="color:var(--text2);padding:4px 12px 4px 0;font-size:12px">${esc(k)}</td><td style="font-size:12px">${esc(v)}</td></tr>` : '';
  const btn = (kind, label, cls) => `<button class="btn ${cls || 'btn-secondary'} btn-sm" onclick="asAct('${kind}','${esc(id)}')">${esc(label)}</button>`;
  let acts = btn('config', t('as.config'), 'btn-primary');
  if (node && s.type === 'edge') {
    acts += btn('traffic', t('infra.title.traffic')) + btn('settings', t('infra.title.general_settings')) +
      btn('update', t('infra.title.update')) + btn('rollback', t('infra.title.rollback'));
  } else if (node && s.type === 'agent') {
    acts += btn('rescan', t('infra.title.rescan')) + btn('agent_update', t('infra.title.update_agent')) +
      btn('containers', t('infra.title.discovered_containers')) + btn('events', t('infra.title.events')) + btn('agent_cfg', t('infra.configure'));
  }
  if (s.type !== 'admin') acts += btn('delete', t('infra.title.delete_node'), 'btn-ghost');
  _asOverlay(`<div class="as-mh"><span class="as-ic" style="--k:${_AS_ROLE[s.type].k}">${_ARCH_ICONS[s.type] || ''}</span><b>${esc(s.name)}</b>
      <span class="as-st" data-tone="${st}">${esc(st === 'ok' ? t('as.st.online') : st === 'off' ? t('as.st.declared') : t('as.st.offline'))}</span>
      <button class="btn btn-ghost btn-sm" style="margin-left:auto" onclick="asCloseModal()">×</button></div>
    <table>${row(t('as.host'), h && h.name)}${row(t('arch.host.region'), h && h.region)}${row(t('arch.opt.reachable'), s.reachable)}${row('Version', node && node.version)}
      ${row(t('as.caps'), _asCaps(_arch, s).join(' · '))}</table>
    <div class="as-acts">${acts}</div>`);
}

function asAct(kind, id) {
  const x = _asAllSvcs(_arch).find(y => y.s.id === id);
  if (!x) return;
  const s = x.s;
  const node = _asLiveNode(s);
  const name = s.name;
  const nn = node ? node.node_name : (s.nodeName || s.name);
  if (kind === 'config') { asOpenConfig(x.h.id); return; }
  asCloseModal();
  switch (kind) {
    case 'traffic': selectEdge(node, 'edge-trafic'); break;
    case 'settings': selectEdge(node, 'edge-general'); break;
    case 'update': nodeAction(nn, 'update'); break;
    case 'rollback': nodeAction(nn, 'rollback'); break;
    case 'rescan': agentRescan(nn); break;
    case 'agent_update': agentUpdate(nn); break;
    case 'containers': agentContainers(nn, name); break;
    case 'events': agentEvents(nn, name); break;
    case 'agent_cfg': agentConfigure(nn, node); break;
    case 'delete': {
      if (node) { deleteActiveNode(s.type === 'agent' ? nn : node.id, name, s.type); break; }
      const dn = (_arch.declaredNodes || []).find(n => n.role === s.type && n.name === (s.nodeName || s.name));
      if (dn) deleteDeclaredNode(dn.id);
      break;
    }
  }
}

// ── Modale Configuration : formats · écarts · versions ──────────────────────

function asOpenConfig(hostId, tab) {
  Object.assign(_asM, { hostId: hostId || null, tab: tab || (hostId ? 'f' : 'v'), fmt: 'compose', verName: null, verData: null, ticket: null });
  asRenderConfig();
}

function _asStable(v) {
  if (Array.isArray(v)) return '[' + v.map(_asStable).join(',') + ']';
  if (v && typeof v === 'object') return '{' + Object.keys(v).sort().map(k => JSON.stringify(k) + ':' + _asStable(v[k])).join(',') + '}';
  return JSON.stringify(v === undefined ? null : v);
}

function _asCfgOf(n) {
  const c = n && n.config;
  if (!c) return {};
  if (typeof c === 'string') { try { return JSON.parse(c); } catch { return {}; } }
  return c;
}

/** Différences entre deux versions du fichier d'architecture. */
function asDiffArch(oldA, newA) {
  const key = n => n.role + ':' + n.name;
  const om = new Map((oldA.nodes || []).map(n => [key(n), n]));
  const nm = new Map((newA.nodes || []).map(n => [key(n), n]));
  const out = [];
  for (const [k, n] of nm) {
    if (!om.has(k)) { out.push({ kind: 'add', text: n.name }); continue; }
    const a = _asCfgOf(om.get(k)), b = _asCfgOf(n);
    const keys = [...new Set([...Object.keys(a), ...Object.keys(b)])].filter(x => x !== 'env_vars' && x !== 'arch_bootstrap' && _asStable(a[x]) !== _asStable(b[x]));
    if (keys.length) out.push({ kind: 'mod', text: n.name + ' · ' + keys.join(', ') });
  }
  for (const [k, n] of om) if (!nm.has(k)) out.push({ kind: 'del', text: n.name });
  return out;
}

function _asFormatFlows(host) {
  const flows = (typeof _archNetworkFlows === 'function' ? _archNetworkFlows() : []);
  const mine = flows.filter(f => String(f.from).includes(host.name) || String(f.to).includes(host.name));
  return (mine.length ? mine : flows).map(f => `${f.from} → ${f.to}  [${f.dir}]  ${f.why}`).join('\n') || '—';
}

function _asDriftRows(s, host) {
  const node = _asLiveNode(s);
  const rows = [];
  const decSt = t('as.st.declared');
  rows.push({ p: t('as.drift.status'), d: decSt, l: node ? (node.status || '—') : t('as.drift.not_connected'), bad: !!node && node.status !== 'online' });
  if (node && node.region && host.region && host.region !== node.region) rows.push({ p: t('arch.host.region'), d: host.region || '—', l: node.region || '—', bad: true });
  if (s.type === 'agent' && node) {
    const rts = (node.container_runtimes || []).map(r => String(r).toLowerCase());
    const dec = s.podman ? 'podman' : s.docker ? 'docker' : '—';
    if (rts.length) rows.push({ p: t('as.drift.runtime'), d: dec, l: rts.join(', '), bad: dec !== '—' && !rts.some(r => r.includes(dec)) });
    const pl = node._agent_config && node._agent_config.portainer;
    if (pl && pl.enabled !== undefined) rows.push({ p: 'Portainer', d: s.portainer ? 'on' : 'off', l: pl.enabled ? 'on' : 'off', bad: !!s.portainer !== !!pl.enabled });
  }
  if (s.type === 'edge' && node) {
    const ep = node.endpoint || node.node_endpoint || '';
    if (s.reachable || ep) rows.push({ p: t('arch.opt.reachable'), d: s.reachable || '—', l: ep || '—', bad: !!s.reachable && !!ep && !ep.includes(s.reachable) });
  }
  return rows;
}

const _AS_FMTS = [['compose', 'as.fmt.compose'], ['env', 'as.fmt.env'], ['cli', 'as.fmt.cli'], ['flows', 'as.fmt.flows'], ['declared', 'as.fmt.declared'], ['ticket', 'as.fmt.ticket']];

function _asFormatsHTML(host) {
  const pack = _archBuildPacks().find(p => p.hostId === host.id);
  let text = '';
  if (_asM.fmt === 'compose') text = pack ? pack.composeText : '';
  else if (_asM.fmt === 'env') text = pack ? pack.envText : '';
  else if (_asM.fmt === 'cli') text = pack ? pack.cliText : '';
  else if (_asM.fmt === 'flows') text = _asFormatFlows(host);
  else if (_asM.fmt === 'declared') {
    const names = new Set(host.services.map(s => s.type + ':' + (s.nodeName || s.name)));
    text = JSON.stringify({ nodes: (_arch.declaredNodes || []).filter(n => names.has(n.role + ':' + n.name)) }, null, 2);
  }
  const pills = `<div class="as-pills">${_AS_FMTS.map(([id, k]) => `<button type="button"${_asM.fmt === id ? ' data-on' : ''} onclick="_asM.fmt='${id}';asRenderConfig()">${esc(t(k))}</button>`).join('')}</div>`;
  if (_asM.fmt === 'ticket') {
    const tk = _asM.ticket;
    return pills + (tk
      ? `<div class="arch-field-label">${esc(t('arch.install_label'))}</div><pre class="as-code">${esc(tk.installCmd || '')}</pre>
         <div class="arch-field-label" style="margin-top:10px">${esc(t('arch.bootstrap_label'))}</div><pre class="as-code">${esc(tk.url || '')}</pre>
         ${tk.qr ? `<img src="${esc(tk.qr)}" alt="QR" width="140" height="140" style="background:#fff;padding:8px;margin-top:10px">` : ''}`
      : `<p style="font-size:12.5px;color:var(--text2);margin:0 0 10px">${esc(t('as.ticket.hint'))}</p>
         <button class="btn btn-primary btn-sm" ${pack ? '' : 'disabled'} onclick="asMakeTicket('${host.id}')">${esc(t('as.ticket.generate'))}</button>`);
  }
  if (!text) return pills + `<div class="as-empty">${esc(t(_asM.fmt === 'env' && pack ? 'as.env_inline' : 'as.no_config'))}</div>`;
  return `${pills}<pre class="as-code" id="as-code">${esc(text)}</pre>
    <div class="as-acts"><button class="btn btn-secondary btn-sm" onclick="asCopy()">${esc(t('as.copy'))}</button>
    <button class="btn btn-secondary btn-sm" onclick="asDownload('${host.name.replace(/[^a-z0-9_-]/gi, '_')}-${_asM.fmt}.txt')">${esc(t('as.download'))}</button></div>`;
}

function _asDriftHTML(host) {
  const rows = host.services.filter(s => s.type !== 'admin').flatMap(s => _asDriftRows(s, host).map(r => ({ ...r, p: `${s.name} · ${r.p}` })));
  return `<table class="as-diff"><tr><th>${esc(t('as.drift.col.param'))}</th><th>${esc(t('as.drift.col.declared'))}</th><th>${esc(t('as.drift.col.live'))}</th></tr>
    ${rows.map(r => `<tr${r.bad ? ' data-bad' : ''}><td>${esc(r.p)}</td><td>${esc(r.d)}</td><td>${esc(r.l)}</td></tr>`).join('')}</table>`;
}

function _asVersionsHTML() {
  if (!_asM.versions) return `<p style="color:var(--text2)">${esc(t('common.loading'))}</p>`;
  const rows = _asM.versions.map(v => {
    const on = _asM.verName === v.name;
    return `<div class="as-ver"${on ? ' data-on' : ''}><div><b>${esc(new Date(v.saved_at).toLocaleString())}</b><small>${esc(v.name)}</small></div>
      <div class="as-ver-b"><button class="btn btn-secondary btn-sm" onclick="asViewVersion('${esc(v.name)}')">${esc(t('as.ver.view'))}</button>
      <button class="btn btn-ghost btn-sm" onclick="asRestoreVersion('${esc(v.name)}')">${esc(t('as.ver.restore'))}</button></div></div>`;
  }).join('');
  let detail = '';
  if (_asM.verData && _asM.current) {
    const d = asDiffArch(_asM.verData, _asM.current);
    const sym = { add: '+', del: '−', mod: '~' };
    detail = `<div style="margin-top:12px"><div class="arch-field-label">${esc(t('as.ver.diff_title'))}</div>
      ${d.length ? `<table class="as-diff">${d.map(x => `<tr><td style="width:24px">${sym[x.kind]}</td><td>${esc(x.text)}</td><td style="color:var(--text2)">${esc(t('as.ver.' + x.kind))}</td></tr>`).join('')}</table>` : `<div class="as-empty" style="padding:10px 0">${esc(t('as.ver.same'))}</div>`}
      <details style="margin-top:8px"><summary style="cursor:pointer;font-size:12px;color:var(--text2)">${esc(t('as.ver.content'))}</summary><pre class="as-code" style="margin-top:6px">${esc(JSON.stringify(_asM.verData, null, 2))}</pre></details></div>`;
  }
  return `${rows || `<div class="as-empty">${esc(t('as.ver.none'))}</div>`}${detail}`;
}

function asRenderConfig() {
  const host = _asM.hostId ? _arch.hosts.find(h => h.id === _asM.hostId) : null;
  if (_asM.tab !== 'v' && !host) _asM.tab = 'v';
  const tabs = [host ? ['f', 'as.tab.formats'] : null, host ? ['e', 'as.tab.drift'] : null, ['v', 'as.tab.versions']].filter(Boolean);
  let body = '';
  if (_asM.tab === 'f') body = _asFormatsHTML(host);
  else if (_asM.tab === 'e') body = _asDriftHTML(host);
  else {
    body = _asVersionsHTML();
    if (!_asM.versions) asLoadVersions();
  }
  const drift = host ? host.services.filter(s => s.type !== 'admin').some(s => _asDriftRows(s, host).some(r => r.bad)) : false;
  _asOverlay(`<div class="as-mh"><b>${esc(host ? t('as.cfg.title', { name: host.name }) : t('as.history'))}</b>
      ${host ? `<span class="as-st" data-tone="${drift ? 'warn' : 'ok'}">${esc(drift ? t('as.drift.bad') : t('as.drift.ok'))}</span>` : ''}
      <button class="btn btn-ghost btn-sm" style="margin-left:auto" onclick="asCloseModal()">×</button></div>
    <div class="as-tabs">${tabs.map(([id, k]) => `<button type="button"${_asM.tab === id ? ' data-on' : ''} onclick="_asM.tab='${id}';asRenderConfig()">${esc(t(k))}</button>`).join('')}</div>
    ${body}`);
}

async function asLoadVersions() {
  const [list, cur] = await Promise.all([
    api('GET', '/architecture/versions').catch(() => []),
    api('GET', '/architecture').catch(() => null),
  ]);
  _asM.versions = Array.isArray(list) ? list : [];
  _asM.current = cur;
  if (document.getElementById('as-overlay')) asRenderConfig();
}

async function asViewVersion(name) {
  _asM.verName = name;
  _asM.verData = await api('GET', '/architecture/versions/' + encodeURIComponent(name)).catch(() => null);
  asRenderConfig();
}

function asRestoreVersion(name) {
  confirm_(t('as.ver.confirm'), async () => {
    try {
      await api('POST', '/architecture/restore', { name });
      toast(t('as.ver.restored'), 'success');
      asCloseModal();
      navigate(state.page === 'architecture' ? 'architecture' : 'infrastructure');
      if (state.page === 'architecture') { _arch.loading = true; _archLoad(); }
    } catch (e) {
      toast(t('common.error_msg', { msg: e.message }), 'error');
    }
  });
}

async function asMakeTicket(hostId) {
  const pack = _archBuildPacks().find(p => p.hostId === hostId);
  if (!pack) return;
  await _archCreateTickets([pack]);
  _asM.ticket = { installCmd: pack.installCmd, url: pack.bootstrapUrl, qr: pack.qrCode };
  asRenderConfig();
}

function asCopy() {
  const el = document.getElementById('as-code');
  if (el) navigator.clipboard.writeText(el.textContent).then(() => toast(t('common.copied') || 'Copié', 'success'));
}

function asDownload(filename) {
  const el = document.getElementById('as-code');
  if (!el) return;
  const a = document.createElement('a');
  a.href = URL.createObjectURL(new Blob([el.textContent], { type: 'text/plain' }));
  a.download = filename;
  a.click();
  URL.revokeObjectURL(a.href);
}
