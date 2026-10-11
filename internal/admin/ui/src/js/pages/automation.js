// ── PAGES: Automatisation — vue d'ensemble, journal, mises en sourdine ────────────────────────
// Onglets des flux : security-rules, automation-schedules, automation-playbooks (automation-lists.js),
// automation-flow (éditeur), rules-store (modèles). Onglets « Alertes » : alert-channels, alerts.

window._auGo = function(page, opts) {
  Object.assign(window, opts || {});
  navigate(page);
};

pages.automation = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-primary btn-sm" onclick="_auGo('automation-flow',{_flowSel:'new'})">+ ${t('flow.new')}</button>`;
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;
  const [stats, recent, pending, channels] = await Promise.all([
    api('GET', '/automation/stats').catch(() => null),
    api('GET', '/automation/runs?limit=6').catch(() => []),
    api('GET', '/automation/runs?status=waiting_approval&limit=20').catch(() => []),
    api('GET', '/alert-channels').catch(() => []),
    FlowCatalog.load().catch(() => null),
  ]);
  const S = stats || { flows: {}, hourly: [] };
  const P = pending || [];
  const C = channels || [];
  const activeChannels = C.filter(c => c.enabled !== false).length;
  const max = Math.max(1, ...(S.hourly || [0]));
  const tile = (page, label, value, sub, color) => `
    <div class="sec-tile" style="cursor:pointer" onclick="navigate('${page}')">
      <div class="sec-tile-label">${label}</div>
      <div class="sec-tile-value" style="color:${color}">${value}</div>
      <div class="sec-tile-sub">${sub}</div>
    </div>`;
  const nRules = (S.flows.condition || 0) + (S.flows.event || 0);
  content.innerHTML = `
    <p style="margin:0 0 16px;font-size:13px;color:var(--text2)">${t('automation.subtitle')}</p>
    ${S.failed_24h ? `<div class="au-banner"><span>⚠</span><div style="flex:1"><b>${t('automation.failed_banner', { n: S.failed_24h })}</b></div>
      <button class="btn btn-ghost btn-sm" onclick="_auGo('automation-history',{_auJournalFilter:'failed'})">${t('automation.see_failures')}</button></div>` : ''}
    ${P.length ? `<div class="card" style="padding:14px 16px;margin-bottom:12px;border-color:var(--accent)">
      <div style="font-weight:600;font-size:13px;margin-bottom:8px">${t('automation.pending_banner', { n: P.length })}</div>
      <div style="display:flex;flex-direction:column;gap:8px">${P.map(p => `
        <div style="display:flex;align-items:center;gap:10px;flex-wrap:wrap;padding:8px 10px;background:var(--surf2, var(--bg2));border-radius:8px">
          <div style="flex:1;min-width:180px">
            <b style="font-size:12.5px">${esc(p.flow_name)}</b>
            <div style="font-size:11.5px;color:var(--text2)">${esc(p.pending?.message || '')} · ${fmtDate(p.updated_at)}</div>
          </div>
          <button class="btn btn-primary btn-sm" onclick="_flDecide('${esc(p.id)}',true,this)">${t('flow.approve')}</button>
          <button class="btn btn-ghost btn-sm" onclick="_flDecide('${esc(p.id)}',false,this)">${t('flow.reject')}</button>
        </div>`).join('')}</div>
    </div>` : ''}
    <div class="sec-tiles" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(190px,1fr));gap:12px">
      ${tile('security-rules', t('flow.tab_rules'), nRules, t('flow.tile_rules_sub'), nRules ? 'var(--accent)' : 'var(--text3)')}
      ${tile('automation-schedules', t('flow.tab_schedules'), S.flows.schedule || 0, t('flow.tile_schedules_sub'), 'var(--accent)')}
      ${tile('automation-playbooks', t('flow.tab_playbooks'), S.flows.manual || 0, t('flow.tile_playbooks_sub'), 'var(--accent)')}
      ${tile('automation-history', t('automation.tile_runs'), S.runs_24h || 0, t('automation.tile_runs_sub', { n: S.failed_24h || 0 }), S.failed_24h ? 'var(--yellow)' : 'var(--green)')}
      ${tile('alert-channels', t('automation.tile_channels'), activeChannels, `${C.length} ${t('common.total')}`, activeChannels ? 'var(--green)' : 'var(--text3)')}
      ${tile('rules-store', t('automation.tile_store'), S.templates || 0, t('automation.tile_store_sub'), 'var(--accent)')}
    </div>
    <div class="au-grid">
      <div class="card" style="padding:16px 18px">
        <div style="font-weight:600;font-size:13px">${t('automation.activity_24h')}</div>
        <div class="au-bars" style="margin-top:14px">${(S.hourly || []).map((n, i) =>
          `<i style="height:${Math.max(3, Math.round(n / max * 72))}px" title="${n} — −${23 - i} h"></i>`).join('')}</div>
        <div style="display:flex;justify-content:space-between;font-size:11px;color:var(--text3);margin-top:4px"><span>−24 h</span><span>${t('automation.now')}</span></div>
      </div>
      <div class="card" style="padding:16px 18px">
        <div style="font-weight:600;font-size:13px;margin-bottom:6px">${t('automation.recent')}</div>
        ${(recent || []).map(r => `<div class="au-feed-row"><span class="au-dot ${_auDot(r.status)}"></span>
          <div style="min-width:0"><div>${esc(r.flow_name)} ${flowRunStatusTag(r.status)}</div>
          <div style="font-size:11.5px;color:var(--text3)">${fmtDate(r.started_at)} · ${esc(_flSource(r.source))}${r.error ? ' · ' + esc(r.error).slice(0, 90) : ''}</div></div></div>`).join('')
          || `<p style="font-size:12.5px;color:var(--text3)">${t('flow.no_runs')}</p>`}
      </div>
    </div>
    <div class="card" style="padding:16px 18px;margin-top:12px">
      <div style="font-weight:600;font-size:13px">${t('automation.shortcuts')}</div>
      <div class="au-chips">
        <button class="btn btn-ghost btn-sm" onclick="_auGo('automation-flow',{_flowSel:'new'})">${t('flow.new')}</button>
        <button class="btn btn-ghost btn-sm" onclick="navigate('rules-store')">${t('automation.install_template')}</button>
        <button class="btn btn-ghost btn-sm" onclick="navigate('alert-channels')">${t('automation.test_channels')}</button>
        <button class="btn btn-ghost btn-sm" onclick="navigate('alerts')">${t('automation.edit_routing')}</button>
        <button class="btn btn-ghost btn-sm" onclick="_auExportYaml()">${t('automation.export_yaml')}</button>
        <button class="btn btn-ghost btn-sm" onclick="_auImportYaml()">${t('automation.import_yaml')}</button>
      </div>
    </div>
    <input type="file" id="au-import-file" accept=".yaml,.yml" style="display:none">`;
  document.getElementById('au-import-file').onchange = _auImportYamlFile;
};

function _auDot(status) {
  if (['failed', 'interrupted'].includes(status)) return 'err';
  if (['silenced', 'cancelled', 'stopped'].includes(status)) return 'idle';
  if (['waiting', 'waiting_approval', 'waiting_child', 'running', 'rejected'].includes(status)) return 'warn';
  return '';
}

// Export/Import GitOps : flux, canaux et mises en sourdine en un document YAML.
window._auExportYaml = async function() {
  try {
    const res = await fetch('/api/v1/automation/export', { headers: { Authorization: 'Bearer ' + state.token } });
    if (!res.ok) throw new Error('HTTP ' + res.status);
    const blob = new Blob([await res.text()], { type: 'application/x-yaml' });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = 'automation.yaml';
    a.click();
    URL.revokeObjectURL(a.href);
  } catch (e) { toast(e.message, 'error'); }
};

window._auImportYaml = function() { document.getElementById('au-import-file')?.click(); };

window._auImportYamlFile = async function(ev) {
  const file = ev.target.files?.[0];
  if (!file) return;
  ev.target.value = '';
  try {
    const res = await fetch('/api/v1/automation/import', {
      method: 'POST',
      headers: { Authorization: 'Bearer ' + state.token, 'Content-Type': 'application/x-yaml' },
      body: await file.text(),
    });
    if (!res.ok) throw new Error(await res.text().catch(() => 'HTTP ' + res.status));
    const s = await res.json();
    toast(t('flow.import_summary', { fc: s.flows_created, fu: s.flows_updated, fr: s.flows_rejected,
      cc: s.channels_created, cu: s.channels_updated, sc: s.silences_created }), s.flows_rejected ? 'error' : 'success');
    (s.errors || []).forEach(e => toast(e, 'error'));
    pages.automation();
  } catch (e) { toast(e.message, 'error'); }
};

// ── Journal des exécutions ─────────────────────────────────────────────

const _auFilters = {
  all: null,
  completed: ['completed'],
  failed: ['failed', 'interrupted'],
  waiting: ['waiting', 'waiting_approval', 'waiting_child', 'running'],
  stopped: ['stopped', 'rejected', 'cancelled'],
  silenced: ['silenced'],
};

pages['automation-history'] = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = '';
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;
  window._auJournalFilter = window._auJournalFilter || 'all';
  window._flHistoryFlow = null;
  const f = window._auJournalFilter;
  const q = new URLSearchParams({ limit: '200' });
  if (_auFilters[f]) q.set('status', _auFilters[f].join(','));
  if (f === 'edge') q.set('source', 'edge');
  let runs = [];
  try {
    await FlowCatalog.load();
    runs = await api('GET', '/automation/runs?' + q) || [];
  } catch (e) { toast(e.message, 'error'); }
  const filters = Object.keys(_auFilters).concat('edge');
  content.innerHTML = `
    <p style="margin:0 0 14px;font-size:13px;color:var(--text2)">${t('flow.journal_hint')}</p>
    <div style="display:flex;gap:6px;margin-bottom:14px;flex-wrap:wrap">${filters.map(v =>
      `<button class="btn btn-sm${f === v ? ' btn-primary' : ' btn-ghost'}" onclick="_auSetFilter('${v}')">${t('flow.f_' + v)}</button>`).join('')}</div>
    ${flowRunsTable(runs, false)}`;
};

window._auSetFilter = function(f) {
  window._auJournalFilter = f;
  pages['automation-history']();
};

// ── Mises en sourdine ──────────────────────────────────────────────────
// Suspendent les déclenchements des flux et le routage des alertes sur une fenêtre de temps, pour tout ou
// pour une liste de flux et de règles d'alerte.

pages['automation-silences'] = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-primary btn-sm" onclick="_asOpenModal()">${t('automation.new_silence')}</button>`;
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;
  try {
    const [silences, flows, alertRules] = await Promise.all([
      api('GET', '/automation/silences'),
      api('GET', '/automation/flows').catch(() => []),
      api('GET', '/alert-rules').catch(() => []),
    ]);
    window._asSilences = silences || [];
    window._asFlows = flows || [];
    window._asAlertRules = alertRules || [];
  } catch (e) { toast(e.message, 'error'); window._asSilences = []; window._asFlows = []; window._asAlertRules = []; }
  _asRender();
};

function _asRender() {
  const now = new Date();
  const name = id => (window._asFlows || []).find(r => r.id === id)?.name || (window._asAlertRules || []).find(r => r.id === id)?.name || id;
  const edgeIds = new Set((window._asFlows || []).filter(f => f.placement === 'edge').map(f => f.id));
  const rows = window._asSilences || [];
  document.getElementById('content').innerHTML = `
    <p style="margin:0 0 14px;font-size:13px;color:var(--text2)">${t('flow.silences_hint')}</p>
    ${rows.length ? `<div style="display:flex;flex-direction:column;gap:10px">${rows.map(s => {
      const starts = new Date(s.starts_at), ends = new Date(s.ends_at);
      const st = now < starts ? 'pending' : (now > ends ? 'past' : 'active');
      const tag = { active: 'tag-green', pending: 'tag-accent', past: 'tag-neutral' }[st];
      const label = { active: t('automation.silence_active'), pending: t('automation.silence_pending'), past: t('automation.silence_past') }[st];
      const ids = s.rule_ids || [];
      const scope = ids.length ? ids.map(name).join(', ') : t('flow.silence_all');
      const edge = ids.length ? ids.some(id => edgeIds.has(id)) : edgeIds.size > 0;
      return `<div class="card blueprint" style="padding:14px 16px;display:flex;align-items:flex-start;gap:12px">
        <div style="flex:1;min-width:0">
          <div style="display:flex;align-items:center;gap:8px;flex-wrap:wrap">
            <span style="font-weight:600;font-size:13.5px">${esc(s.name)}</span>
            <span class="tag ${tag}" style="font-size:10px">${label}</span>
            ${edge && st !== 'past' ? `<span class="tag tag-yellow" style="font-size:10px" title="${esc(t('flow.silence_edge_hint'))}">${t('flow.silence_edge')}</span>` : ''}
          </div>
          <div style="font-size:11.5px;color:var(--text2);margin-top:6px">${fmtDate(s.starts_at)} → ${fmtDate(s.ends_at)}</div>
          <div style="font-size:11.5px;color:var(--text3);margin-top:2px">${t('automation.silence_scope')}: ${esc(scope)}</div>
        </div>
        <button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="_asDelete('${esc(s.id)}','${esc(s.name)}')" title="${t('common.delete')}">✕</button>
      </div>`;
    }).join('')}</div>` : `<div class="empty"><p>${t('automation.no_silences')}</p></div>`}`;
}

window._asOpenModal = function() {
  const flows = window._asFlows || [];
  const alertRules = window._asAlertRules || [];
  const pad = n => String(n).padStart(2, '0');
  const toLocal = d => `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
  const now = new Date();
  const box = (title, list) => list.length ? `<div style="font-size:10.5px;text-transform:uppercase;letter-spacing:.06em;color:var(--text3);margin:6px 0 4px">${title}</div>
    ${list.map(r => `<label style="display:flex;align-items:center;gap:8px;font-size:12.5px;padding:3px 0"><input type="checkbox" class="as-rule" value="${esc(r.id)}"> ${esc(r.name)}</label>`).join('')}` : '';
  modal(t('automation.new_silence'), `
    <div class="field"><label class="field-label">${t('common.name')}</label><input id="as-name" class="input" placeholder="${esc(t('automation.silence_name_ph'))}"></div>
    <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px">
      <div class="field"><label class="field-label">${t('automation.starts_at')}</label><input id="as-starts" type="datetime-local" class="input" value="${toLocal(now)}"></div>
      <div class="field"><label class="field-label">${t('automation.ends_at')}</label><input id="as-ends" type="datetime-local" class="input" value="${toLocal(new Date(now.getTime() + 3600e3))}"></div>
    </div>
    <div class="field"><label class="field-label">${t('automation.silence_scope')}</label>
      <select id="as-scope" class="input" style="height:32px" onchange="document.getElementById('as-rules-wrap').style.display=this.value==='some'?'block':'none'">
        <option value="all">${t('flow.silence_all')}</option><option value="some">${t('flow.silence_pick')}</option></select></div>
    <div id="as-rules-wrap" style="display:none;max-height:240px;overflow:auto;border:1px solid var(--border);border-radius:8px;padding:8px">
      ${box(t('flow.silence_group_flows'), flows)}${box(t('automation.silence_group_alert_rules'), alertRules)}
    </div>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="_asSave()">${t('common.save')}</button>`);
};

window._asSave = async function() {
  const name = document.getElementById('as-name')?.value?.trim();
  const starts = document.getElementById('as-starts')?.value;
  const ends = document.getElementById('as-ends')?.value;
  if (!name || !starts || !ends) { toast(t('automation.silence_fields_required'), 'error'); return; }
  if (new Date(ends) <= new Date(starts)) { toast(t('automation.silence_bad_range'), 'error'); return; }
  const ids = document.getElementById('as-scope')?.value === 'some' ? [...document.querySelectorAll('.as-rule:checked')].map(c => c.value) : [];
  try {
    await api('POST', '/automation/silences', { name, starts_at: new Date(starts).toISOString(), ends_at: new Date(ends).toISOString(), rule_ids: ids });
    closeModal();
    toast(t('common.saved'), 'success');
    pages['automation-silences']();
  } catch (e) { toast(e.message, 'error'); }
};

window._asDelete = async function(id, name) {
  if (!confirm(t('flow.delete_confirm', { name }))) return;
  try {
    await api('DELETE', `/automation/silences/${id}`);
    toast(t('flow.deleted'), 'success');
    pages['automation-silences']();
  } catch (e) { toast(e.message, 'error'); }
};
