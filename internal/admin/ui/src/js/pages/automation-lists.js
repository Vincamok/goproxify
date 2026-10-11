// ── PAGES: Règles, Planifications, Playbooks ──────────────────────────────────────────────────
// Trois vues des flux, filtrées par déclencheur : Règles (condition, événement), Planifications (horaire),
// Playbooks (manuel). Créer passe par l'éditeur ou par un modèle ; rééditer passe par l'éditeur, ou par les
// paramètres du modèle pour un flux qui en est issu.

const _flTabs = {
  'security-rules': { tab: 'rules', kinds: ['condition', 'event'], newKind: 'condition' },
  'automation-schedules': { tab: 'schedules', kinds: ['schedule'], newKind: 'schedule' },
  'automation-playbooks': { tab: 'playbooks', kinds: ['manual'], newKind: 'manual' },
};

Object.keys(_flTabs).forEach(page => { pages[page] = () => renderFlowList(page); });

async function renderFlowList(page) {
  const cfg = _flTabs[page];
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = `
    <button class="btn btn-ghost btn-sm" onclick="window._storeKind='${cfg.tab}';navigate('rules-store')">${t('flow.from_template_btn')}</button>
    <button class="btn btn-primary btn-sm" onclick="window._flowSel='new';window._flowNewKind='${cfg.newKind}';navigate('automation-flow')">+ ${t('flow.new_' + cfg.tab)}</button>`;
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;
  let flows = [], metrics = null;
  try {
    const [list, sum] = await Promise.all([
      api('GET', '/automation/flows?trigger=' + cfg.kinds.join(',')),
      cfg.tab === 'rules' ? api('GET', '/metrics/summary').catch(() => null) : Promise.resolve(null),
      FlowCatalog.load(),
      FlowTemplates.load().catch(() => null),
    ]);
    flows = list || [];
    metrics = sum?.automation;
  } catch (e) { toast(e.message, 'error'); }
  window._flList = flows;
  window._flPage = page;
  const band = metrics ? `<div class="sec-tiles" style="display:grid;grid-template-columns:repeat(auto-fill,minmax(170px,1fr));gap:10px;margin-bottom:14px">
      ${[[t('flow.m_active'), metrics.active_flows], [t('flow.m_evals'), metrics.evals_per_minute != null ? Number(metrics.evals_per_minute).toFixed(1) : '—'],
        [t('flow.m_duration'), metrics.avg_duration_ms != null ? Number(metrics.avg_duration_ms).toFixed(1) + ' ms' : '—'], [t('flow.m_actions'), metrics.actions_total]]
        .map(([l, v]) => `<div class="sec-tile"><div class="sec-tile-label">${l}</div><div class="sec-tile-value" style="font-size:20px">${esc(String(v ?? '—'))}</div></div>`).join('')}
    </div>` : '';
  content.innerHTML = `
    <p style="margin:0 0 14px;font-size:13px;color:var(--text2)">${t('flow.list_hint_' + cfg.tab)}</p>
    ${band}
    ${flows.length ? `<div style="display:flex;flex-direction:column;gap:10px">${flows.map(_flTile).join('')}</div>`
      : `<div class="empty"><p>${t('flow.empty_' + cfg.tab)}</p></div>`}`;
}

function _flTile(f) {
  const st = f.state || {};
  const kind = f.trigger?.kind;
  const tpl = f.origin?.kind === 'template';
  const stats = [];
  if (kind === 'schedule') {
    stats.push(`<code>${esc(f.trigger.schedule?.cron || '')}</code>`);
    stats.push(st.next_run_at ? t('flow.next_run', { at: fmtDate(st.next_run_at) }) : t('flow.no_next_run'));
  }
  if (kind === 'condition' || kind === 'event') {
    stats.push(t('flow.fired', { n: st.fire_count || 0 }));
    stats.push(t('flow.cooldown_n', { n: f.guard?.cooldown_sec || 300 }));
  }
  if (kind === 'manual') {
    const inputs = f.trigger.manual?.inputs || [];
    stats.push(inputs.length ? t('flow.inputs_n', { list: inputs.map(i => i.label || i.key).join(', ') }) : t('flow.no_inputs'));
    stats.push(t('flow.runs_n', { n: st.fire_count || 0 }));
  }
  if (st.last_fired_at) stats.push(t('flow.last_run', { at: fmtDate(st.last_fired_at) }) + (st.last_run_status ? ' ' + flowRunStatusTag(st.last_run_status) : ''));
  if (st.waiting) stats.push(`<a href="#" onclick="event.preventDefault();_flHistory('${esc(f.id)}')">${t('flow.waiting_n', { n: st.waiting })}</a>`);
  const runBtn = kind === 'manual' || kind === 'schedule'
    ? `<button class="btn btn-ghost btn-sm" onclick="_flRun('${esc(f.id)}')" title="${esc(t('flow.run_now'))}">▶</button>` : '';
  return `<div class="card blueprint" style="padding:14px 16px">
    <div style="display:flex;align-items:flex-start;gap:12px;flex-wrap:wrap">
      <div style="flex:1;min-width:220px">
        <div style="display:flex;align-items:center;gap:6px;flex-wrap:wrap">
          <span style="font-weight:600;font-size:14px">${esc(f.name)}</span>
          <span class="tag ${f.enabled ? 'tag-green' : 'tag-neutral'}" style="font-size:10px">${f.enabled ? t('flow.enabled') : t('flow.disabled')}</span>
          <span class="tag tag-neutral" style="font-size:10px" title="${esc(tpl ? FlowTemplates.name(f.origin.template_id) : '')}">${tpl ? t('flow.origin_template') : t('flow.origin_editor')}</span>
          ${f.template?.outdated ? `<span class="tag tag-yellow" style="font-size:10px" title="${esc(t('flow.template_outdated', { from: f.origin.template_version || 0, to: f.template.current_version }))}">${t('flow.template_updated')}</span>` : ''}
          ${f.template?.missing ? `<span class="tag tag-red" style="font-size:10px" title="${esc(t('flow.template_missing'))}">${t('flow.template_gone')}</span>` : ''}
          ${kind === 'condition' ? flowPlacementBadge(f) : ''}
          ${FlowCatalog.hasApproval(f) ? `<span class="tag tag-accent" style="font-size:10px">${t('flow.with_approval')}</span>` : ''}
        </div>
        ${f.description ? `<div style="font-size:12px;color:var(--text2);margin-top:4px">${esc(f.description)}</div>` : ''}
        <div style="font-size:12.5px;margin-top:8px"><b>${esc(FlowCatalog.triggerText(f))}</b> → ${esc(FlowCatalog.stepsText(f.steps))}</div>
        <div style="font-size:11.5px;color:var(--text3);margin-top:6px;display:flex;gap:12px;flex-wrap:wrap">${stats.map(s => `<span>${s}</span>`).join('')}</div>
      </div>
      <div style="display:flex;gap:4px;align-items:center">
        <label class="toggle" title="${esc(f.enabled ? t('flow.disable') : t('flow.enable'))}"><input type="checkbox" ${f.enabled ? 'checked' : ''} onchange="_flToggle('${esc(f.id)}',this.checked)"><span class="toggle-slider"></span></label>
        ${runBtn}
        <button class="btn btn-ghost btn-sm" onclick="_flSimulate('${esc(f.id)}')" title="${esc(t('flow.simulate'))}">${t('flow.simulate')}</button>
        <button class="btn btn-ghost btn-sm" onclick="_flHistory('${esc(f.id)}')">${t('flow.history')}</button>
        <button class="btn btn-ghost btn-sm" onclick="_flEdit('${esc(f.id)}')">${t('common.edit')}</button>
        <button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="_flDelete('${esc(f.id)}')" title="${esc(t('common.delete'))}">✕</button>
      </div>
    </div></div>`;
}

const _flFind = id => (window._flList || []).find(f => f.id === id);

window._flEdit = function(id) {
  const f = _flFind(id);
  if (f?.origin?.kind === 'template' && !f.template?.missing) { FlowTemplates.open(f.origin.template_id, id); return; }
  window._flowSel = id;
  navigate('automation-flow');
};

window._flToggle = async function(id, enabled) {
  try {
    await api('PATCH', `/automation/flows/${id}`, { enabled });
    toast(enabled ? t('flow.enabled_ok') : t('flow.disabled_ok'), 'success');
    renderFlowList(window._flPage);
  } catch (e) { toast(e.message, 'error'); renderFlowList(window._flPage); }
};

window._flDelete = async function(id) {
  const f = _flFind(id);
  if (!confirm(t('flow.delete_confirm', { name: f?.name || id }))) return;
  try {
    await api('DELETE', `/automation/flows/${id}`);
    toast(t('flow.deleted'), 'success');
    renderFlowList(window._flPage);
  } catch (e) { toast(e.message, 'error'); }
};

// Lance un flux à la main ; un playbook demande d'abord ses paramètres.
window._flRun = function(id) {
  const f = _flFind(id);
  const inputs = f?.trigger?.manual?.inputs || [];
  window._flRunCtx = { id, inputs };
  modal(t('flow.run_title', { name: esc(f?.name || '') }),
    inputs.length ? `<div id="fl-run-inputs">${ManifestForm.render('flrun', inputs, {})}</div>` : `<p style="margin:0;font-size:13px">${t('flow.run_confirm')}</p>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="_flRunGo()">▶ ${t('flow.run_now')}</button>`);
  const el = document.getElementById('fl-run-inputs');
  if (el) ManifestForm.hydrate(el);
};

window._flRunGo = async function() {
  const { id, inputs } = window._flRunCtx;
  const { config, errors } = ManifestForm.collect('flrun', inputs, {});
  if (errors.length) { toast(errors[0], 'error'); return; }
  try {
    const res = await api('POST', `/automation/flows/${id}/run`, { inputs: config });
    closeModal();
    if (res && !res.matched) { toast(t('flow.sim_no_match'), 'info'); return; }
    toast(t('flow.run_started'), 'success');
    setTimeout(() => _flHistory(id), 600);
  } catch (e) { toast(e.message, 'error'); }
};

window._flSimulate = async function(id) {
  try {
    const res = await api('POST', `/automation/flows/${id}/run`, { dry_run: true });
    const lines = !res.matched ? [`· ${t('flow.sim_no_match')}`] : [
      `✓ ${t('flow.sim_matched')}`, ...(res.silenced ? [`· ${t('flow.sim_silenced')}`] : []),
      `  ${res.placement === 'edge' ? t('flow.sim_edge') : t('flow.sim_admin')}`,
      ...(res.trace || []).map(l => `${{ failed: '✗', skipped: '·' }[l.status] || '✓'} ${l.flow ? '[' + l.flow + '] ' : ''}${l.step_id} ${t('flow.sim_' + l.status)}${l.detail ? ' — ' + l.detail : ''}`),
    ];
    if (res.detail && Object.keys(res.detail).length) lines.push('', 'detail = ' + JSON.stringify(res.detail, null, 2));
    modal(t('flow.simulate'), `<div class="fl-console" style="width:100%">${esc(lines.join('\n'))}</div>`,
      `<button class="btn btn-secondary" onclick="closeModal()">${t('common.close')}</button>`, true);
  } catch (e) { toast(e.message, 'error'); }
};

// Historique d'un flux : exécutions, décisions d'approbation, détail des étapes.
window._flHistory = async function(id) {
  const f = _flFind(id);
  let runs = [];
  try { runs = await api('GET', `/automation/runs?flow_id=${encodeURIComponent(id)}&limit=50`) || []; }
  catch (e) { toast(e.message, 'error'); return; }
  modal(t('flow.history_title', { name: esc(f?.name || id) }), flowRunsTable(runs, true),
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.close')}</button>`, true);
  window._flHistoryFlow = id;
};

// Tableau d'exécutions partagé (historique d'un flux, journal).
function flowRunsTable(runs, compact) {
  if (!runs.length) return `<div class="empty"><p>${t('flow.no_runs')}</p></div>`;
  return `<div class="table-wrap"><table><thead><tr><th>${t('common.date')}</th>${compact ? '' : `<th>${t('flow.flow')}</th>`}<th>${t('flow.source')}</th>
    <th>${t('flow.status')}</th><th>${t('flow.detail')}</th><th></th></tr></thead><tbody>${runs.map(r => `<tr>
      <td style="font-size:11px;white-space:nowrap">${fmtDate(r.started_at)}</td>
      ${compact ? '' : `<td style="font-size:12px">${esc(r.flow_name)}</td>`}
      <td style="font-size:11px;color:var(--text2)">${esc(_flSource(r.source))}</td>
      <td>${flowRunStatusTag(r.status)}</td>
      <td style="font-size:11px;color:var(--text2);max-width:320px">${esc(r.pending?.message || r.error || '')}</td>
      <td style="white-space:nowrap">${_flRunActions(r)}</td></tr>
      <tr id="fl-run-${esc(r.id)}" hidden><td colspan="${compact ? 5 : 6}"></td></tr>`).join('')}</tbody></table></div>`;
}

function _flSource(src) {
  if (!src || src === 'admin') return t('flow.src_admin');
  const [k, v] = src.split(/:(.*)/);
  return t('flow.src_' + k, { v: v || '' });
}

function _flRunActions(r) {
  const id = esc(r.id);
  const out = [`<button class="btn btn-ghost btn-sm" onclick="_flRunSteps('${id}')">${t('flow.steps')}</button>`];
  if (r.status === 'waiting_approval') {
    out.push(`<button class="btn btn-primary btn-sm" onclick="_flDecide('${id}',true,this)">${t('flow.approve')}</button>`,
      `<button class="btn btn-ghost btn-sm" onclick="_flDecide('${id}',false,this)">${t('flow.reject')}</button>`);
  }
  if (['running', 'waiting', 'waiting_approval', 'waiting_child'].includes(r.status)) {
    out.push(`<button class="btn btn-ghost btn-sm" onclick="_flCancel('${id}',this)">${t('flow.cancel')}</button>`);
  }
  if (['failed', 'interrupted', 'cancelled', 'rejected'].includes(r.status)) {
    out.push(`<button class="btn btn-ghost btn-sm" onclick="_flReplay('${id}',this)">${t('flow.replay')}</button>`);
  }
  return out.join('');
}

window._flRunSteps = async function(id) {
  const row = document.getElementById('fl-run-' + id);
  if (!row) return;
  if (!row.hidden) { row.hidden = true; return; }
  try {
    const r = await api('GET', `/automation/runs/${id}`);
    row.firstElementChild.innerHTML = `<div style="font-size:11.5px;display:flex;flex-direction:column;gap:3px;padding:4px 0">${(r.steps || []).map(s =>
      `<div><code>${esc(s.step_id)}</code> ${esc(FlowCatalog.label('steps', s.type))} — <b>${esc(t('flow.sim_' + s.status))}</b>${s.actor ? ' · ' + esc(s.actor) : ''}${s.detail ? ' · ' + esc(s.detail) : ''}${s.output && Object.keys(s.output).length ? ` <span style="color:var(--text3)">${esc(JSON.stringify(s.output))}</span>` : ''}</div>`).join('')
      || t('flow.no_steps')}
      ${r.context?.detail && Object.keys(r.context.detail).length ? `<div style="color:var(--text3)">detail = ${esc(JSON.stringify(r.context.detail))}</div>` : ''}</div>`;
    row.hidden = false;
  } catch (e) { toast(e.message, 'error'); }
};

async function _flAfterRunAction() {
  if (window._flHistoryFlow && document.getElementById('modal-overlay')) await _flHistory(window._flHistoryFlow);
  else if (pages[state.page]) pages[state.page]();
}

window._flDecide = async function(id, approve, btn) {
  btn.disabled = true;
  try {
    await api('POST', `/automation/runs/${id}/${approve ? 'approve' : 'reject'}`);
    toast(approve ? t('flow.approved') : t('flow.rejected'), 'success');
    await _flAfterRunAction();
  } catch (e) { toast(e.message, 'error'); btn.disabled = false; }
};

window._flCancel = async function(id, btn) {
  if (!confirm(t('flow.cancel_confirm'))) return;
  btn.disabled = true;
  try {
    await api('POST', `/automation/runs/${id}/cancel`);
    toast(t('flow.cancelled'), 'success');
    await _flAfterRunAction();
  } catch (e) { toast(e.message, 'error'); btn.disabled = false; }
};

window._flReplay = async function(id, btn) {
  btn.disabled = true;
  try {
    await api('POST', `/automation/runs/${id}/replay`);
    toast(t('flow.replayed'), 'success');
    setTimeout(_flAfterRunAction, 500);
  } catch (e) { toast(e.message, 'error'); btn.disabled = false; }
};
