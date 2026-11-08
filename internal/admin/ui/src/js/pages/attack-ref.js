// Page Référentiel des attaques (ADR 0023, étape 1) : ce que les IP bannies ont fait, et les entrées retenues parce
// qu'elles discriminent les attaquants des visiteurs. Lecture et rejet seulement : rien ici ne bloque le trafic.
// Données : GET /security/attack-ref/{summary,entries,dossiers}, POST /security/attack-ref/{entries/status,run}.

const _ar = { summary: null, entries: [], entriesTotal: 0, dossiers: [], dossiersTotal: 0, kind: '', status: '', profile: '', open: null, error: '' };
let _arPoll = null;

function arLift(e) {
  if (e.lift < 0) return `<span title="${esc(t('aref.lift_hint'))}" style="color:var(--text3)">${esc(t('aref.lift_unmeasured'))}</span>`;
  return e.lift >= 1000 ? '≥ 1000' : Math.round(e.lift).toString();
}

function arEntryRow(e) {
  const rejected = e.status === 'rejected';
  const act = rejected ? 'candidate' : 'rejected';
  const label = rejected ? t('aref.restore') : t('aref.reject');
  return `<tr${rejected ? ' style="opacity:.55"' : ''}>
    <td>${esc(e.kind)}</td>
    <td class="tr-mono" title="${esc(e.sample || '')}">${esc(e.value)}</td>
    <td>${esc(e.family)}</td>
    <td>${e.distinct_ips}</td><td>${e.days}</td><td>${e.hits}</td>
    <td>${arLift(e)}</td><td>${e.clean_hits}</td>
    <td>${esc(fmtDate(e.last_seen))}</td>
    <td>${esc(t('aref.status.' + e.status))}</td>
    <td><button type="button" class="btn btn-ghost btn-sm" data-kind="${esc(e.kind)}" data-value="${esc(e.value)}" data-status="${act}" onclick="arSetStatus(this)">${esc(label)}</button></td>
  </tr>`;
}

function arChips(list) {
  return (list || []).map(c => `<span class="tr-chip">${esc(c)}</span>`).join('');
}

function arDossierRow(d, i) {
  const main = (d.profiles && d.profiles[0]) ? d.profiles[0].profile : 'unclassified';
  const open = _ar.open === i;
  let detail = '';
  if (open) {
    const why = (d.profiles || []).map(p => `<div><b>${esc(p.profile)}</b> — ${esc(p.why)}</div>`).join('');
    const paths = (d.paths || []).slice(0, 40).map(p => `<div class="tr-mono">${esc(p.method)} ${esc(p.template)} <i>×${p.count}</i> <span style="color:var(--text3)">${esc(Object.entries(p.statuses || {}).map(([s, n]) => s + '×' + n).join(' '))}</span></div>`).join('');
    detail = `<tr><td colspan="6"><div class="card blueprint" style="padding:12px">
      ${why}
      ${d.user_agent ? `<div class="tr-meta" style="margin-top:6px">${esc(t('trace.ua'))} : <span class="tr-mono">${esc(d.user_agent)}</span></div>` : ''}
      ${(d.signals || []).length ? `<div style="margin-top:6px">${arChips(d.signals)}</div>` : ''}
      ${Object.keys(d.waf || {}).length ? `<div style="margin-top:6px">${arChips(Object.entries(d.waf).map(([k, n]) => k + ' ×' + n))}</div>` : ''}
      <div style="margin-top:8px">${paths}</div>
    </div></td></tr>`;
  }
  return `<tr style="cursor:pointer" onclick="arToggleDossier(${i})">
    <td class="tr-mono">${esc(d.ip)}</td><td>${esc(main)}</td><td>${esc(fmtDate(d.banned_at))}</td>
    <td>${d.requests}</td><td>${d.distinct_paths}</td><td>${arChips(d.families)}</td>
  </tr>${detail}`;
}

function arSegBtn(group, value, label) {
  const on = _ar[group] === value;
  return `<button type="button" class="seg-btn${on ? ' active' : ''}" onclick="arFilter('${group}','${value}')">${esc(label)}</button>`;
}

function arPaint() {
  const content = document.getElementById('content');
  if (!content) return;
  if (_ar.error) {
    content.innerHTML = `<p class="tr-empty">${esc(_ar.error)}</p>`;
    return;
  }
  const s = _ar.summary || {};
  const sum = s.summary || {};
  const miner = s.miner || {};
  const cfg = s.config || {};
  const tile = (v, label) => `<div class="bn-kpi"><b>${v}</b><span>${esc(label)}</span></div>`;
  const profiles = Object.keys(sum.profiles || {}).sort();
  const profSeg = [arSegBtn('profile', '', t('aref.all'))].concat(profiles.map(p => arSegBtn('profile', p, p + ' (' + sum.profiles[p] + ')'))).join('');
  const last = miner.last_run_at ? fmtDate(miner.last_run_at) : t('aref.never');
  const degraded = miner.last_result && miner.last_result.degraded ? `<p class="tr-meta" style="color:var(--orange,#d97706)">${esc(t('aref.degraded'))}</p>` : '';
  const entryRows = _ar.entries.map(arEntryRow).join('');
  const dossierRows = _ar.dossiers.map(arDossierRow).join('');
  content.innerHTML = `<div class="tr-page">
    <p class="tr-meta" style="margin:0 0 10px">${esc(t('aref.subtitle'))}</p>
    <div class="bn-kpis">
      ${tile(sum.dossiers || 0, t('aref.kpi.dossiers'))}
      ${tile((sum.entries_by_status || {}).candidate || 0, t('aref.kpi.candidates'))}
      ${tile((sum.entries_by_status || {}).rejected || 0, t('aref.kpi.rejected'))}
    </div>
    <div class="card blueprint" style="padding:12px 16px;margin-bottom:16px;display:flex;gap:12px;flex-wrap:wrap;align-items:center">
      <button type="button" class="btn btn-primary btn-sm" onclick="arRun()" ${miner.running ? 'disabled' : ''}>${esc(miner.running ? t('aref.running') : t('aref.run'))}</button>
      <span class="tr-meta">${esc(t('aref.last_run'))} : ${esc(last)}</span>
      <span class="tr-meta">${esc(t('aref.thresholds', { ips: cfg.min_ips, days: cfg.min_days, lift: cfg.min_lift, lookback: cfg.lookback_days }))}</span>
    </div>
    ${degraded}
    <h3 style="margin:0 0 8px">${esc(t('aref.entries'))}</h3>
    <div class="logs-seg" style="margin-bottom:8px">${arSegBtn('kind', '', t('aref.all'))}${arSegBtn('kind', 'path', 'path')}${arSegBtn('kind', 'ua', 'ua')}</div>
    <div class="logs-seg" style="margin-bottom:8px">${arSegBtn('status', '', t('aref.all'))}${arSegBtn('status', 'candidate', t('aref.status.candidate'))}${arSegBtn('status', 'rejected', t('aref.status.rejected'))}</div>
    ${_ar.entries.length ? `<div class="table-wrap"><table class="bn-table"><thead><tr>
      <th>${esc(t('aref.col.kind'))}</th><th>${esc(t('aref.col.value'))}</th><th>${esc(t('aref.col.family'))}</th><th>${esc(t('aref.col.ips'))}</th>
      <th>${esc(t('aref.col.days'))}</th><th>${esc(t('aref.col.hits'))}</th><th>${esc(t('aref.col.lift'))}</th><th>${esc(t('aref.col.clean'))}</th>
      <th>${esc(t('aref.col.last'))}</th><th>${esc(t('aref.col.status'))}</th><th></th></tr></thead><tbody>${entryRows}</tbody></table></div>`
      : `<p class="tr-empty">${esc(t('aref.empty_entries'))}</p>`}
    <h3 style="margin:20px 0 8px">${esc(t('aref.dossiers'))}</h3>
    <div class="logs-seg" style="margin-bottom:8px">${profSeg}</div>
    ${_ar.dossiers.length ? `<div class="table-wrap"><table class="bn-table"><thead><tr>
      <th>${esc(t('aref.col.ip'))}</th><th>${esc(t('aref.col.profile'))}</th><th>${esc(t('aref.col.banned'))}</th>
      <th>${esc(t('aref.col.requests'))}</th><th>${esc(t('aref.col.paths'))}</th><th>${esc(t('aref.col.families'))}</th></tr></thead><tbody>${dossierRows}</tbody></table></div>`
      : `<p class="tr-empty">${esc(t('aref.empty_dossiers'))}</p>`}
  </div>`;
}

async function arLoad() {
  try {
    const q = new URLSearchParams({ limit: 200 });
    if (_ar.kind) q.set('kind', _ar.kind);
    if (_ar.status) q.set('status', _ar.status);
    const dq = new URLSearchParams({ limit: 100 });
    if (_ar.profile) dq.set('profile', _ar.profile);
    const [summary, entries, dossiers] = await Promise.all([
      api('GET', '/security/attack-ref/summary'),
      api('GET', '/security/attack-ref/entries?' + q),
      api('GET', '/security/attack-ref/dossiers?' + dq),
    ]);
    _ar.summary = summary;
    _ar.entries = (entries && entries.entries) || [];
    _ar.entriesTotal = (entries && entries.total) || 0;
    _ar.dossiers = (dossiers && dossiers.dossiers) || [];
    _ar.dossiersTotal = (dossiers && dossiers.total) || 0;
    _ar.error = '';
  } catch (e) {
    _ar.error = t('aref.unavailable');
  }
  arPaint();
  arSchedulePoll();
}

// Un passage lit un mois de logs : tant qu'il tourne, la page se rafraîchit pour en montrer le résultat.
function arSchedulePoll() {
  clearTimeout(_arPoll);
  _arPoll = null;
  const running = _ar.summary && _ar.summary.miner && _ar.summary.miner.running;
  if (running && document.getElementById('content')?.querySelector('.tr-page')) {
    _arPoll = setTimeout(() => { if (typeof state !== 'undefined' && state.page === 'security-attack-ref') arLoad(); }, 4000);
  }
}

window.arFilter = (group, value) => { _ar[group] = value; _ar.open = null; arLoad(); };
window.arToggleDossier = i => { _ar.open = _ar.open === i ? null : i; arPaint(); };

window.arSetStatus = async btn => {
  try {
    await api('POST', '/security/attack-ref/entries/status', { kind: btn.dataset.kind, value: btn.dataset.value, status: btn.dataset.status });
  } catch (e) {
    toast(e.message || String(e), 'error');
  }
  arLoad();
};

window.arRun = async () => {
  try {
    const r = await api('POST', '/security/attack-ref/run');
    toast(r && r.started ? t('aref.run_started') : t('aref.run_busy'), 'info');
  } catch (e) {
    toast(e.message || String(e), 'error');
  }
  arLoad();
};

pages['security-attack-ref'] = async () => {
  const ta = document.getElementById('topbar-actions');
  if (ta) ta.innerHTML = '';
  await arLoad();
};
