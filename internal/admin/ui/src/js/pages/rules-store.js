// ── PAGE: Modèles de flux ─────────────────────────────────────────────────────────────────────
// Les modèles (GET /automation/templates) sont des flux paramétrables. Le même formulaire sert à installer
// un modèle et à rééditer un flux qui en est issu (paramètres du modèle, aperçu à jour). Un flux issu d'un
// modèle se détache depuis l'éditeur pour aller au-delà des paramètres.

const FlowTemplates = (() => {
  let list = null;

  async function load(force) {
    if (!list || force) list = await api('GET', '/automation/templates') || [];
    return list;
  }

  const get = id => (list || []).find(tp => tp.id === id);
  const name = id => get(id)?.name || id;

  // Ouvre le formulaire d'un modèle : installation (flowId vide) ou réédition d'un flux issu du modèle.
  async function open(tplId, flowId) {
    await Promise.all([load(), FlowCatalog.load()]);
    const tpl = get(tplId);
    if (!tpl) { toast(t('flow.template_missing'), 'error'); return; }
    let flow = null;
    if (flowId) {
      try { flow = await api('GET', `/automation/flows/${flowId}`); } catch (e) { toast(e.message, 'error'); return; }
    }
    const params = flow?.origin?.params || {};
    window._tplCtx = { tpl, flow };
    modal(esc(tpl.name), `
      <p style="margin:0 0 12px;font-size:12.5px;color:var(--text2)">${esc(tpl.description)}</p>
      ${flow?.template?.outdated ? `<div class="au-banner" style="padding:8px 12px"><span>⚠</span><div style="flex:1;font-size:12.5px">${t('flow.template_outdated', { from: flow.origin.template_version || 0, to: tpl.version })}</div></div>` : ''}
      <div class="field"><label class="field-label">${t('flow.name')}</label>
        <input id="tpl-name" class="input" value="${esc(flow?.name || tpl.name)}"></div>
      <label style="display:flex;align-items:center;gap:6px;font-size:12.5px;margin-bottom:10px">
        <input type="checkbox" id="tpl-enabled" ${flow ? (flow.enabled ? 'checked' : '') : 'checked'}>${t('flow.enabled')}</label>
      ${tpl.params.length ? `<div class="fl-sub">${t('flow.template_params')}</div>` : ''}
      <div id="tpl-params" style="display:grid;grid-template-columns:1fr 1fr;gap:10px" onchange="FlowTemplates.preview()">${ManifestForm.render('tpl', tpl.params, params)}</div>
      <div class="fl-sub" style="margin-top:10px">${t('flow.preview')}</div>
      <div id="tpl-preview" class="fl-help" style="min-height:36px"></div>`,
      `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
       <button class="btn btn-primary" onclick="FlowTemplates.submit()">${flow ? t('common.save') : t('flow.install')}</button>`);
    ManifestForm.hydrate(document.getElementById('tpl-params'));
    preview();
  }

  function collect() {
    const { tpl } = window._tplCtx;
    return ManifestForm.collect('tpl', tpl.params, {});
  }

  async function preview() {
    const el = document.getElementById('tpl-preview');
    if (!el) return;
    const { config, errors } = collect();
    if (errors.length) { el.textContent = errors[0]; return; }
    try {
      const { tpl, flow } = window._tplCtx;
      const f = await api('POST', `/automation/templates/${tpl.id}/preview`, { params: config, flow_id: flow?.id || '' });
      el.innerHTML = `${flowPlacementBadge(f)} ${esc(FlowCatalog.triggerText(f))} → ${esc(FlowCatalog.stepsText(f.steps))}`
        + (flow ? `<div class="fl-sub" style="margin-top:8px">${t('flow.changes_on_save')}</div>${flowChangesHTML(f.changes)}` : '');
    } catch (e) { el.textContent = e.message; }
  }

  async function submit() {
    const { tpl, flow } = window._tplCtx;
    const { config, errors } = collect();
    if (errors.length) { toast(errors[0], 'error'); return; }
    const body = {
      name: document.getElementById('tpl-name').value.trim(),
      enabled: document.getElementById('tpl-enabled').checked,
      params: config,
    };
    try {
      if (flow) {
        await api('PUT', `/automation/flows/${flow.id}`, { ...body, description: flow.description, origin: { kind: 'template', params: config } });
      } else {
        await api('POST', `/automation/templates/${tpl.id}/install`, body);
      }
      closeModal();
      toast(flow ? t('common.saved') : t('flow.installed'), 'success');
      if (!flow) window._flowSel = '';
      navigate(state.page || 'rules-store');
    } catch (e) { toast(e.message, 'error'); }
  }

  return { load, get, name, open, preview, submit };
})();
window.FlowTemplates = FlowTemplates;

const _tplTabs = { condition: 'rules', event: 'rules', schedule: 'schedules', manual: 'playbooks' };

pages['rules-store'] = async function() {
  const content = document.getElementById('content');
  const kind = window._storeKind || '';
  document.getElementById('topbar-actions').innerHTML = '';
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;
  let templates = [];
  try {
    await FlowCatalog.load();
    templates = await FlowTemplates.load(true);
  } catch (e) { toast(e.message, 'error'); }
  const filters = [['', t('flow.all')], ['rules', t('flow.tab_rules')], ['schedules', t('flow.tab_schedules')], ['playbooks', t('flow.tab_playbooks')]];
  const shown = templates.filter(tp => !kind || _tplTabs[tp.kind] === kind);
  const byCategory = {};
  shown.forEach(tp => (byCategory[tp.category] ||= []).push(tp));
  content.innerHTML = `
    <p style="margin:0 0 14px;font-size:13px;color:var(--text2)">${t('flow.store_hint')}</p>
    <div style="display:flex;gap:6px;margin-bottom:6px;flex-wrap:wrap">${filters.map(([v, l]) =>
      `<button class="btn btn-sm${kind === v ? ' btn-primary' : ' btn-ghost'}" onclick="window._storeKind='${v}';pages['rules-store']()">${l}</button>`).join('')}</div>
    ${Object.keys(byCategory).length ? Object.entries(byCategory).map(([cat, tpls]) => `
      <h6 style="margin:20px 0 10px;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${esc(t('flow.cat_' + cat))}</h6>
      <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(280px,1fr));gap:12px">
        ${tpls.map(tp => `
          <div class="card" style="padding:16px 18px;display:flex;flex-direction:column;gap:10px">
            <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap">
              <span style="font-weight:600;font-size:14px;flex:1">${esc(tp.name)}</span>
              <span class="tag tag-neutral" style="font-size:10px">${esc(t('flow.tab_' + (_tplTabs[tp.kind] || 'rules')))}</span>
            </div>
            <p style="margin:0;font-size:12px;color:var(--text2);line-height:1.5;flex:1">${esc(tp.description)}</p>
            <div style="font-size:11.5px;color:var(--text3)">${tp.params.map(p => esc(p.label)).join(' · ') || t('flow.no_params')}</div>
            <div style="display:flex;align-items:center;justify-content:space-between;gap:8px">
              <span style="font-size:11.5px;color:var(--text3)">${tp.installed ? t('flow.installed_n', { n: tp.installed }) : ''}</span>
              <button class="btn btn-sm btn-primary" onclick="FlowTemplates.open('${esc(tp.id)}')">${t('flow.install')}</button>
            </div>
          </div>`).join('')}
      </div>`).join('') : `<div class="empty"><p>${t('flow.no_templates')}</p></div>`}`;
};
