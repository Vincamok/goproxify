// ── PAGE: Éditeur de flux ─────────────────────────────────────────────────────────────────────
// Construit un flux : un déclencheur (condition, événement, horaire, manuel), un garde-fou, puis des
// étapes qu'on ajoute avec « + » (actions, attente, si/sinon, approbation, appel d'un playbook, arrêt).
// Tout ce qui se configure vient du catalogue (FlowCatalog) : chaque brique est un manifeste rendu par
// ManifestForm. Le brouillon (_fe.flow) est un objet modifié en place ; les formulaires y écrivent à chaque
// changement, la page se redessine quand la structure change.

const _fe = { flow: null, flows: [], refs: [], focus: null, ro: false };

function _feClone(v) { return JSON.parse(JSON.stringify(v)); }

function _feDefaults(manifest) {
  const c = {};
  (manifest?.fields || []).forEach(f => { if (f.default !== undefined) c[f.key] = f.default; });
  return c;
}

function _feNewLeaf() {
  const m = FlowCatalog.list('conditions')[0];
  return { type: m?.type || '', config: _feDefaults(m) };
}

function _feNewFlow(kind) {
  const trigger = { kind };
  if (kind === 'condition') trigger.condition = _feNewLeaf();
  if (kind === 'event') trigger.event = { event: FlowCatalog.list('events')[0]?.type || '' };
  if (kind === 'schedule') trigger.schedule = { cron: '0 3 * * *' };
  if (kind === 'manual') trigger.manual = { inputs: [] };
  const notify = FlowCatalog.find('actions', 'notify');
  return { name: '', description: '', enabled: true, trigger, guard: {}, origin: { kind: 'manual' },
    steps: [{ id: 's1', type: 'action', action: { type: 'notify', config: _feDefaults(notify) } }] };
}

pages['automation-flow'] = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = '';
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;
  try {
    await Promise.all([FlowCatalog.load(), FlowTemplates.load().catch(() => null)]);
    _fe.flows = await api('GET', '/automation/flows') || [];
  } catch (e) { toast(e.message, 'error'); _fe.flows = []; }
  let sel = window._flowSel;
  if (!sel) sel = _fe.flows[0]?.id || 'new';
  const saved = sel !== 'new' && _fe.flows.find(f => f.id === sel);
  _fe.flow = saved ? _feClone(saved) : _feNewFlow(window._flowNewKind || 'condition');
  window._flowSel = saved ? saved.id : 'new';
  window._flowNewKind = null;
  _feRender();
};

function _feSaved() { return _fe.flows.find(f => f.id === _fe.flow.id); }

function _ref(obj) { _fe.refs.push(obj); return _fe.refs.length - 1; }

// Formulaire d'un manifeste qui écrit dans target. redraw : redessine la page après un changement (le choix
// influe sur le reste : playbook appelé, événement…).
function _feForm(target, fields, redraw) {
  if (!fields?.length) return '';
  const r = _ref({ target, fields, redraw });
  return `<div class="fl-grid" onchange="_feSync(${r})">${ManifestForm.render('fe' + r, fields, target)}</div>`;
}

window._feSync = function(r) {
  const e = _fe.refs[r];
  if (!e?.fields) return;
  const { config } = ManifestForm.collect('fe' + r, e.fields, e.target);
  for (const f of e.fields) {
    if (f.key in config) e.target[f.key] = config[f.key];
    else delete e.target[f.key];
  }
  if (e.redraw) _feRender();
};

function _feSyncAll() {
  _fe.refs.forEach((e, r) => { if (e?.fields && document.getElementById(`fe${r}-${e.fields[0].key.replace(/\./g, '__')}`)) _feSync(r); });
}

function _feRender() {
  const content = document.getElementById('content');
  const scroll = content.scrollTop;
  _fe.refs = [];
  const f = _fe.flow;
  const saved = _feSaved();
  _fe.ro = f.origin?.kind === 'template';
  const tpl = _fe.ro ? (f.origin.template_id || '') : '';
  const groups = [['rules', ['condition', 'event']], ['schedules', ['schedule']], ['playbooks', ['manual']]];
  const picker = groups.map(([g, kinds]) => `<optgroup label="${esc(t('flow.tab_' + g))}">${_fe.flows.filter(x => kinds.includes(x.trigger?.kind))
    .map(x => `<option value="${esc(x.id)}"${x.id === f.id ? ' selected' : ''}>${esc(x.name)}</option>`).join('')}</optgroup>`).join('')
    + `<optgroup label="${esc(t('flow.new'))}">${['condition', 'event', 'schedule', 'manual'].map(k =>
      `<option value="new:${k}"${!f.id && f.trigger.kind === k ? ' selected' : ''}>+ ${esc(FlowCatalog.label('triggers', k))}</option>`).join('')}</optgroup>`;
  content.innerHTML = `
    <p style="margin:0 0 14px;font-size:13px;color:var(--text2)">${t('flow.hint')}</p>
    <div class="fl-head">
      <select class="input" style="height:32px;max-width:260px" onchange="_feSelect(this.value)">${picker}</select>
      <input id="fe-name" class="input" style="height:32px;flex:1;min-width:180px" value="${esc(f.name)}" placeholder="${esc(t('flow.name_ph'))}" onchange="_fe.flow.name=this.value" ${_fe.ro ? 'disabled' : ''}>
      <label style="display:flex;align-items:center;gap:6px;font-size:12.5px"><input type="checkbox" ${f.enabled ? 'checked' : ''} onchange="_fe.flow.enabled=this.checked" ${_fe.ro ? 'disabled' : ''}>${t('flow.enabled')}</label>
      <button class="btn btn-ghost btn-sm" id="fe-sim" onclick="_feSimulate()">▶ ${t('flow.simulate')}</button>
      ${_fe.ro ? '' : `<button class="btn btn-primary btn-sm" onclick="_feSave()">${t('common.save')}</button>`}
      ${f.id ? `<button class="btn btn-ghost btn-sm" onclick="_feVersions()">${t('flow.versions')}</button>
      <button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="_feDelete()">${t('common.delete')}</button>` : ''}
    </div>
    <input class="input" style="height:30px;margin-bottom:12px;font-size:12.5px" value="${esc(f.description || '')}" placeholder="${esc(t('flow.description_ph'))}" onchange="_fe.flow.description=this.value" ${_fe.ro ? 'disabled' : ''}>
    ${_fe.ro ? `<div class="au-banner" style="border-color:var(--accent)"><span>◆</span><div style="flex:1">${t('flow.from_template', { name: esc(FlowTemplates.name(tpl)) })}</div>
      <button class="btn btn-primary btn-sm" onclick="FlowTemplates.open('${esc(tpl)}','${esc(f.id)}')">${t('flow.edit_params')}</button>
      <button class="btn btn-ghost btn-sm" onclick="_feDetach()">${t('flow.detach')}</button></div>` : ''}
    <div class="fl-canvas${_fe.ro ? ' fl-ro' : ''}" id="flow-canvas">
      ${_feTriggerNode()}
      <div class="fl-wire"></div>
      ${_feGuardNode(saved)}
      ${_feSteps(f.steps, 1)}
      <div class="fl-end">${t('flow.end')}</div>
      <div class="fl-console" id="flow-console" hidden></div>
    </div>`;
  const canvas = document.getElementById('flow-canvas');
  if (_fe.ro) canvas.querySelectorAll('input,select,textarea,button').forEach(el => { el.disabled = true; });
  ['focusin', 'click', 'keyup'].forEach(ev => canvas.addEventListener(ev, e => {
    if (e.target.matches('input[type=text],input:not([type]),textarea')) _fe.focus = e.target;
  }));
  ManifestForm.hydrate(canvas);
  content.scrollTop = scroll;
}

window._feSelect = function(v) {
  if (v.startsWith('new:')) { window._flowSel = 'new'; window._flowNewKind = v.slice(4); }
  else window._flowSel = v;
  pages['automation-flow']();
};

// ── Déclencheur ────────────────────────────────────────────────────────

const _feCronPresets = [['0 3 * * *', 'flow.cron_daily_3am'], ['0 * * * *', 'flow.cron_hourly'], ['*/15 * * * *', 'flow.cron_15min'],
  ['0 8 * * 1', 'flow.cron_monday_8am'], ['0 0 1 * *', 'flow.cron_monthly']];

function _feTriggerNode() {
  const tr = _fe.flow.trigger;
  const man = FlowCatalog.find('triggers', tr.kind);
  const kinds = FlowCatalog.list('triggers').map(m => `<option value="${esc(m.type)}"${m.type === tr.kind ? ' selected' : ''}>${esc(m.label)}</option>`).join('');
  let body = '';
  if (tr.kind === 'condition') {
    tr.condition = tr.condition || _feNewLeaf();
    body = _feForm(tr, man?.fields) + _feCond(tr, 'condition', 1, false);
  } else if (tr.kind === 'event') {
    tr.event = tr.event || { event: '' };
    const r = _ref(tr.event);
    const match = Object.entries(tr.event.match || {}).map(([k, v]) => `${k}=${v}`).join('\n');
    body = _feForm(tr.event, man?.fields, true) + `
      <div class="field"><label class="field-label">${t('flow.event_match')}</label>
        <textarea class="input" rows="2" placeholder="ip=10.*&#10;reason=sshd*" onchange="_feEventMatch(${r},this.value)">${esc(match)}</textarea>
        <div class="fl-help">${t('flow.event_match_help')}</div></div>`;
  } else if (tr.kind === 'schedule') {
    tr.schedule = tr.schedule || { cron: '' };
    const saved = _feSaved();
    const next = saved?.state?.next_run_at && saved.trigger?.schedule?.cron === tr.schedule.cron ? fmtDate(saved.state.next_run_at) : '';
    body = `<select class="input" style="height:30px;margin-bottom:8px" onchange="if(this.value){_fe.flow.trigger.schedule.cron=this.value;_feRender()}">
        <option value="">${t('flow.cron_presets')}</option>${_feCronPresets.map(([v, k]) => `<option value="${v}">${t(k)}</option>`).join('')}</select>
      ${_feForm(tr.schedule, man?.fields, true)}
      <div class="fl-help">${t('flow.cron_local')}${next ? ' · ' + t('flow.next_run', { at: next }) : ''}</div>`;
  } else if (tr.kind === 'manual') {
    tr.manual = tr.manual || { inputs: [] };
    body = _feInputsEditor(tr.manual);
  }
  return `<div class="fl-node t"><div class="fl-k"><span>${t('flow.node_trigger')}</span></div>
    <select class="input" style="height:32px;margin-bottom:10px" onchange="_feTriggerKind(this.value)">${kinds}</select>${body}</div>`;
}

window._feTriggerKind = function(kind) {
  const steps = _fe.flow.steps;
  const fresh = _feNewFlow(kind);
  _fe.flow.trigger = fresh.trigger;
  _fe.flow.steps = steps;
  _feRender();
};

window._feEventMatch = function(r, text) {
  const ev = _fe.refs[r];
  const m = {};
  text.split('\n').forEach(line => {
    const i = line.indexOf('=');
    if (i > 0) m[line.slice(0, i).trim()] = line.slice(i + 1).trim();
  });
  if (Object.keys(m).length) ev.match = m; else delete ev.match;
};

const _feInputKinds = [['text', 'flow.kind_text'], ['number', 'flow.kind_number'], ['bool', 'flow.kind_bool'], ['duration', 'flow.kind_duration'],
  ['src:proxies', 'flow.kind_proxy'], ['src:nodes', 'flow.kind_node'], ['src:domains', 'flow.kind_domain']];

function _feInputsEditor(manual) {
  const inputs = manual.inputs = manual.inputs || [];
  const r = _ref(inputs);
  return `<div class="fl-sub">${t('flow.inputs')}</div><div class="fl-help" style="margin-bottom:6px">${t('flow.inputs_help')}</div>
    ${inputs.map((inp, i) => {
      const kind = inp.kind === 'select' && inp.source ? 'src:' + inp.source : inp.kind;
      return `<div class="fl-input-row">
        <input class="input" value="${esc(inp.key || '')}" placeholder="${esc(t('flow.input_key'))}" onchange="_feInputSet(${r},${i},'key',this.value)">
        <input class="input" value="${esc(inp.label || '')}" placeholder="${esc(t('flow.input_label'))}" onchange="_feInputSet(${r},${i},'label',this.value)">
        <select class="input" onchange="_feInputSet(${r},${i},'kind',this.value)">${_feInputKinds.map(([v, k]) => `<option value="${v}"${v === kind ? ' selected' : ''}>${t(k)}</option>`).join('')}</select>
        <input class="input" value="${esc(inp.default ?? '')}" placeholder="${esc(t('flow.input_default'))}" onchange="_feInputSet(${r},${i},'default',this.value)">
        <label class="fl-not"><input type="checkbox" ${inp.required ? 'checked' : ''} onchange="_feInputSet(${r},${i},'required',this.checked)">${t('flow.required')}</label>
        <button type="button" class="fl-x" onclick="_feInputDel(${r},${i})">✕</button></div>`;
    }).join('')}
    <button type="button" class="btn btn-ghost btn-sm" onclick="_feInputAdd(${r})">+ ${t('flow.add_input')}</button>`;
}

window._feInputAdd = function(r) { _fe.refs[r].push({ key: '', label: '', kind: 'text' }); _feRender(); };
window._feInputDel = function(r, i) { _fe.refs[r].splice(i, 1); _feRender(); };
window._feInputSet = function(r, i, prop, value) {
  const inp = _fe.refs[r][i];
  if (prop === 'kind') {
    delete inp.source;
    if (value.startsWith('src:')) { inp.kind = 'select'; inp.source = value.slice(4); } else inp.kind = value;
  } else if (prop === 'default') {
    if (value === '') delete inp.default;
    else inp.default = inp.kind === 'number' && !isNaN(Number(value)) ? Number(value) : (inp.kind === 'bool' ? value === 'true' : value);
  } else if (prop === 'key') {
    inp.key = value.trim();
    if (!inp.label) inp.label = inp.key;
  } else inp[prop] = value;
  if (prop === 'key' || prop === 'kind') _feRender();
};

// ── Garde-fou ──────────────────────────────────────────────────────────

function _feGuardNode(saved) {
  const g = _fe.flow.guard = _fe.flow.guard || {};
  const kind = _fe.flow.trigger.kind;
  const fields = [];
  if (kind === 'condition' || kind === 'event') {
    fields.push({ key: 'cooldown_sec', label: t('flow.cooldown'), kind: 'number', placeholder: '300', help: t('flow.cooldown_help') },
      { key: 'cooldown_key', label: t('flow.cooldown_key'), kind: 'text', placeholder: '{{detail.ip}}', help: t('flow.cooldown_key_help') });
  }
  fields.push({ key: 'max_concurrent', label: t('flow.max_concurrent'), kind: 'number', placeholder: '1' });
  if (kind === 'condition') {
    fields.push({ key: 'placement', label: t('flow.placement'), kind: 'select', options: [
      { value: 'auto', label: t('flow.placement_auto') }, { value: 'admin', label: t('flow.placement_force_admin') }] });
  }
  const badge = saved && saved.trigger?.kind === kind ? `<div class="fl-help" style="margin-top:6px">${flowPlacementBadge(saved)} ${esc(saved.placement === 'edge' ? t('flow.placement_edge_hint') : saved.placement_reason || '')}</div>` : '';
  return `<div class="fl-node g"><div class="fl-k"><span>${t('flow.node_guard')}</span></div>${_feForm(g, fields)}${badge}</div>`;
}

// ── Conditions (simples, groupes et / ou, négation) ────────────────────

function _feCond(holder, key, depth, removable) {
  const c = holder[key];
  const hr = _ref({ holder, key });
  const neg = !!c.not;
  const body = neg ? c.not : c;
  const bhr = _ref({ holder: neg ? c : holder, key: neg ? 'not' : key });
  const tools = `<label class="fl-not"><input type="checkbox" ${neg ? 'checked' : ''} onchange="_feCondNot(${hr},this.checked)">${t('flow.not')}</label>`
    + (removable ? `<button type="button" class="fl-x" title="${esc(t('common.delete'))}" onclick="_feCondRemove(${hr})">✕</button>` : '');
  if (body.all || body.any) {
    const mode = body.all ? 'all' : 'any';
    const items = body[mode];
    return `<div class="fl-group${neg ? ' neg' : ''}"><div class="fl-group-head">
        <select class="input" onchange="_feGroupMode(${bhr},this.value)">
          <option value="all"${mode === 'all' ? ' selected' : ''}>${t('flow.group_all')}</option>
          <option value="any"${mode === 'any' ? ' selected' : ''}>${t('flow.group_any')}</option></select>${tools}</div>
      ${items.map((_, i) => _feCond(items, i, depth + 1, true)).join('')}
      <div class="fl-group-add">
        <button type="button" class="btn btn-ghost btn-sm" onclick="_feCondAdd(${bhr},'leaf')">+ ${t('flow.condition')}</button>
        ${depth < 4 ? `<button type="button" class="btn btn-ghost btn-sm" onclick="_feCondAdd(${bhr},'group')">+ ${t('flow.group')}</button>` : ''}
      </div></div>`;
  }
  body.config = body.config || {};
  const man = FlowCatalog.find('conditions', body.type);
  const opts = FlowCatalog.list('conditions').map(m => `<option value="${esc(m.type)}"${m.type === body.type ? ' selected' : ''}>${esc(m.label)}</option>`).join('');
  return `<div class="fl-leaf${neg ? ' neg' : ''}"><div class="fl-leaf-head">
      <select class="input" onchange="_feLeafType(${bhr},this.value)">${opts}</select>${tools}
      ${removable ? '' : `<button type="button" class="btn btn-ghost btn-sm" onclick="_feCondWrap(${hr})">+ ${t('flow.condition')}</button>`}
    </div>${man?.attrs?.edge ? '' : `<div class="fl-help">${t('flow.admin_condition')}</div>`}${_feForm(body.config, man?.fields)}</div>`;
}

window._feCondNot = function(r, on) {
  const { holder, key } = _fe.refs[r];
  holder[key] = on ? { not: holder[key] } : holder[key].not;
  _feRender();
};
window._feCondRemove = function(r) {
  const { holder, key } = _fe.refs[r];
  if (holder.length <= 1) { toast(t('flow.group_needs_one'), 'error'); return; }
  holder.splice(key, 1);
  _feRender();
};
window._feGroupMode = function(r, mode) {
  const { holder, key } = _fe.refs[r];
  holder[key] = { [mode]: holder[key].all || holder[key].any };
  _feRender();
};
window._feCondAdd = function(r, kind) {
  const { holder, key } = _fe.refs[r];
  const g = holder[key];
  (g.all || g.any).push(kind === 'group' ? { any: [_feNewLeaf()] } : _feNewLeaf());
  _feRender();
};
window._feLeafType = function(r, type) {
  const { holder, key } = _fe.refs[r];
  holder[key] = { type, config: _feDefaults(FlowCatalog.find('conditions', type)) };
  _feRender();
};
window._feCondWrap = function(r) {
  const { holder, key } = _fe.refs[r];
  holder[key] = { all: [holder[key], _feNewLeaf()] };
  _feRender();
};

// ── Étapes ─────────────────────────────────────────────────────────────

function _feSteps(list, depth) {
  const lr = _ref(list);
  let html = _feAdder(lr, 0);
  list.forEach((st, i) => { html += _feStep(list, lr, i, depth) + _feAdder(lr, i + 1); });
  return html;
}

function _feAdder(lr, idx) {
  return `<div class="fl-add"><button type="button" onclick="_fePalette(${lr},${idx})" title="${esc(t('flow.add_step'))}">+</button></div>`;
}

const _feStepClass = { action: 'a', if: 'i', wait: 'w', approval: 'p', call: 'c', stop: 's' };

function _feStep(list, lr, i, depth) {
  const st = list[i];
  const sr = _ref(st);
  const stepMan = FlowCatalog.find('steps', st.type);
  let title = stepMan?.label || st.type;
  let body = '';
  if (st.type === 'action') {
    st.action = st.action || { type: 'notify', config: {} };
    st.action.config = st.action.config || {};
    const man = FlowCatalog.find('actions', st.action.type);
    title = man?.label || st.action.type;
    const opts = FlowCatalog.list('actions').map(m => `<option value="${esc(m.type)}"${m.type === st.action.type ? ' selected' : ''}>${esc(m.label)}</option>`).join('');
    body = `<select class="input" style="height:30px;margin-bottom:8px" onchange="_feActionType(${sr},this.value)">${opts}</select>
      ${man?.attrs?.edge ? '' : `<div class="fl-help">${t('flow.admin_action')}</div>`}
      ${_feForm(st.action.config, man?.fields)}${_feOnError(sr, st)}`;
  } else if (st.type === 'if') {
    st.condition = st.condition || _feNewLeaf();
    st.then = st.then || [];
    st.else = st.else || [];
    body = _feCond(st, 'condition', 1, false) + `<div class="fl-branch">
      <div class="fl-col"><div class="fl-blabel">${t('flow.then')}</div>${_feSteps(st.then, depth + 1)}</div>
      <div class="fl-col"><div class="fl-blabel">${t('flow.else')}</div>${_feSteps(st.else, depth + 1)}</div></div>`;
  } else {
    st.config = st.config || {};
    body = _feForm(st.config, stepMan?.fields, st.type === 'call');
    if (st.type === 'call') {
      const target = _fe.flows.find(f => f.id === st.config.flow_id);
      const inputs = target?.trigger?.manual?.inputs || [];
      if (inputs.length) {
        st.config.inputs = st.config.inputs || {};
        // Saisis en texte : un paramètre reçoit souvent une variable ({{detail.proxy_id}}), qu'une liste ne propose pas.
        const fields = inputs.map(f => ({ ...f, kind: f.kind === 'select' ? 'text' : f.kind, placeholder: f.placeholder || (f.source ? `{{detail.${f.key}}}` : ''), required: false }));
        body += `<div class="fl-sub">${t('flow.call_inputs', { name: esc(target.name) })}</div>${_feForm(st.config.inputs, fields)}`;
      }
      body += _feOnError(sr, st);
    }
  }
  const vars = st.type === 'wait' ? [] : FlowCatalog.variablesAt(_fe.flow, st.id);
  return `<div class="fl-node ${_feStepClass[st.type] || 'a'}" data-step="${esc(st.id)}">
    <div class="fl-k"><span>${esc(title)} <code class="fl-id">${esc(st.id)}</code></span><span class="fl-tools">
      <button type="button" title="${esc(t('flow.move_up'))}" onclick="_feMove(${lr},${i},-1)">↑</button>
      <button type="button" title="${esc(t('flow.move_down'))}" onclick="_feMove(${lr},${i},1)">↓</button>
      <button type="button" title="${esc(t('flow.duplicate'))}" onclick="_feDup(${lr},${i})">⧉</button>
      <button type="button" title="${esc(t('common.delete'))}" onclick="_feDel(${lr},${i})">✕</button></span></div>
    ${body}
    ${vars.length ? `<details class="fl-vars"><summary>${t('flow.variables')}</summary>${vars.map(v =>
      `<button type="button" class="fl-var" onclick="_feInsertVar('${esc(v)}')">{{${esc(v)}}}</button>`).join('')}</details>` : ''}
  </div>`;
}

function _feOnError(sr, st) {
  return `<label class="fl-not" style="margin-top:6px"><input type="checkbox" ${st.on_error === 'continue' ? 'checked' : ''}
    onchange="_fe.refs[${sr}].on_error=this.checked?'continue':undefined">${t('flow.on_error_continue')}</label>`;
}

window._feActionType = function(r, type) {
  const st = _fe.refs[r];
  st.action = { type, config: _feDefaults(FlowCatalog.find('actions', type)) };
  _feRender();
};

window._fePalette = function(lr, idx) {
  const btn = (kind, type, label) => `<button type="button" class="fl-pal" onclick="_feInsert(${lr},${idx},'${kind}','${esc(type)}')">${esc(label)}</button>`;
  const logic = FlowCatalog.list('steps').filter(m => m.type !== 'action');
  modal(t('flow.add_step'), `
    <div class="fl-sub">${t('flow.palette_actions')}</div>
    <div class="fl-palette">${FlowCatalog.list('actions').map(m => btn('action', m.type, m.label)).join('')}</div>
    <div class="fl-sub" style="margin-top:12px">${t('flow.palette_logic')}</div>
    <div class="fl-palette">${logic.map(m => btn('step', m.type, m.label)).join('')}</div>`, '');
};

window._feInsert = function(lr, idx, kind, type) {
  const id = FlowCatalog.newStepId(_fe.flow);
  let st;
  if (kind === 'action') st = { id, type: 'action', action: { type, config: _feDefaults(FlowCatalog.find('actions', type)) } };
  else if (type === 'if') st = { id, type: 'if', condition: _feNewLeaf(), then: [], else: [] };
  else st = { id, type, config: _feDefaults(FlowCatalog.find('steps', type)) };
  _fe.refs[lr].splice(idx, 0, st);
  closeModal();
  _feRender();
};

window._feMove = function(lr, i, dir) {
  const list = _fe.refs[lr];
  const j = i + dir;
  if (j < 0 || j >= list.length) return;
  [list[i], list[j]] = [list[j], list[i]];
  _feRender();
};

window._feDup = function(lr, i) {
  const list = _fe.refs[lr];
  const copy = _feClone(list[i]);
  FlowCatalog.walk([copy], s => { s.id = null; });
  list.splice(i + 1, 0, copy);
  FlowCatalog.walk([copy], s => { s.id = FlowCatalog.newStepId(_fe.flow); });
  _feRender();
};

window._feDel = function(lr, i) {
  _fe.refs[lr].splice(i, 1);
  _feRender();
};

// Insère une variable dans le dernier champ texte utilisé, sinon la copie.
window._feInsertVar = function(v) {
  const text = `{{${v}}}`;
  const el = _fe.focus;
  if (el && document.body.contains(el) && !el.disabled) {
    const s = el.selectionStart ?? el.value.length, e = el.selectionEnd ?? el.value.length;
    el.value = el.value.slice(0, s) + text + el.value.slice(e);
    el.focus();
    el.selectionStart = el.selectionEnd = s + text.length;
    el.dispatchEvent(new Event('change', { bubbles: true }));
    return;
  }
  navigator.clipboard?.writeText(text).catch(() => {});
  toast(t('flow.var_copied', { v: text }), 'info');
};

// ── Enregistrement, simulation, versions ───────────────────────────────

function _fePayload() {
  _feSyncAll();
  const f = _feClone(_fe.flow);
  ['state', 'placement', 'placement_reason', 'created_at', 'updated_at', 'created_by', 'version'].forEach(k => delete f[k]);
  return f;
}

window._feSave = async function() {
  const payload = _fePayload();
  if (!payload.name?.trim()) { toast(t('flow.name_required'), 'error'); document.getElementById('fe-name')?.focus(); return; }
  try {
    const res = payload.id
      ? await api('PUT', `/automation/flows/${payload.id}`, payload)
      : await api('POST', '/automation/flows', payload);
    toast(t('common.saved'), 'success');
    window._flowSel = res?.id || payload.id;
    pages['automation-flow']();
  } catch (e) { toast(e.message, 'error'); }
};

window._feDelete = async function() {
  const f = _fe.flow;
  if (!confirm(t('flow.delete_confirm', { name: f.name }))) return;
  try {
    await api('DELETE', `/automation/flows/${f.id}`);
    toast(t('flow.deleted'), 'success');
    window._flowSel = '';
    pages['automation-flow']();
  } catch (e) { toast(e.message, 'error'); }
};

window._feDetach = async function() {
  if (!confirm(t('flow.detach_confirm'))) return;
  try {
    await api('POST', `/automation/flows/${_fe.flow.id}/detach`);
    toast(t('flow.detached'), 'success');
    pages['automation-flow']();
  } catch (e) { toast(e.message, 'error'); }
};

window._feSimulate = function() {
  const flow = _fePayload();
  const inputs = flow.trigger.kind === 'manual' ? (flow.trigger.manual?.inputs || []) : [];
  if (!inputs.length) { _feRunSimulation(flow, {}); return; }
  window._feSimFlow = flow;
  modal(t('flow.simulate'), `<div id="fe-sim-inputs">${ManifestForm.render('fesim', inputs, {})}</div>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="_feSimInputs()">▶ ${t('flow.simulate')}</button>`);
  ManifestForm.hydrate(document.getElementById('fe-sim-inputs'));
};

window._feSimInputs = function() {
  const flow = window._feSimFlow;
  const { config, errors } = ManifestForm.collect('fesim', flow.trigger.manual.inputs, {});
  if (errors.length) { toast(errors[0], 'error'); return; }
  closeModal();
  _feRunSimulation(flow, config);
};

async function _feRunSimulation(flow, inputs) {
  const con = document.getElementById('flow-console');
  const btn = document.getElementById('fe-sim');
  if (!con) return;
  btn.disabled = true;
  con.hidden = false;
  con.textContent = `$ ${t('flow.sim_header')}\n`;
  const canvas = document.getElementById('flow-canvas');
  canvas.querySelectorAll('.fl-node').forEach(n => n.classList.remove('done', 'run', 'skip', 'err'));
  const mark = async (node, cls) => {
    if (!node) return;
    node.classList.add('run');
    await new Promise(ok => setTimeout(ok, 280));
    node.classList.remove('run');
    node.classList.add(cls);
  };
  try {
    const res = await api('POST', '/automation/simulate', { flow, inputs });
    await mark(canvas.querySelector('.fl-node.t'), res.matched ? 'done' : 'skip');
    con.textContent += `${res.matched ? '✓' : '·'} ${res.matched ? t('flow.sim_matched') : t('flow.sim_no_match')}\n`;
    if (!res.matched) return;
    await mark(canvas.querySelector('.fl-node.g'), res.silenced ? 'skip' : 'done');
    if (res.silenced) con.textContent += `· ${t('flow.sim_silenced')}\n`;
    con.textContent += `  ${res.placement === 'edge' ? t('flow.sim_edge') : t('flow.sim_admin')}\n`;
    for (const l of res.trace || []) {
      const cls = { failed: 'err', skipped: 'skip' }[l.status] || 'done';
      if (!l.flow) await mark(canvas.querySelector(`.fl-node[data-step="${CSS.escape(l.step_id)}"]`), cls);
      const sym = { failed: '✗', skipped: '·', approved: '✓' }[l.status] || '✓';
      con.textContent += `${sym} ${l.flow ? '[' + l.flow + '] ' : ''}${l.step_id} ${t('flow.sim_' + l.status)}${l.detail ? ' — ' + l.detail : ''}\n`;
      if (l.output && Object.keys(l.output).length) con.textContent += '    ' + JSON.stringify(l.output) + '\n';
    }
    if (res.detail && Object.keys(res.detail).length) con.textContent += `\ndetail = ${JSON.stringify(res.detail, null, 2)}`;
  } catch (e) { con.textContent += '✗ ' + e.message; }
  finally { btn.disabled = false; }
}

window._feVersions = async function() {
  const f = _fe.flow;
  let versions = [];
  try { versions = await api('GET', `/automation/flows/${f.id}/versions`) || []; }
  catch (e) { toast(e.message, 'error'); return; }
  const body = versions.length
    ? `<div style="display:flex;flex-direction:column;gap:8px;max-height:420px;overflow:auto">${versions.map((v, i) => `
        <div class="card" style="padding:10px 12px;display:flex;align-items:center;gap:10px">
          <div style="flex:1;min-width:0">
            <b>v${v.version}</b>${i === 0 ? ` <span class="tag tag-green" style="font-size:10px">${t('flow.version_current')}</span>` : ''}
            <div style="font-size:11.5px;color:var(--text2)">${fmtDate(v.created_at)}${v.created_by ? ' · ' + esc(v.created_by) : ''}</div>
            <div style="font-size:11.5px;color:var(--text3)">${esc(FlowCatalog.triggerText(v.flow))} → ${esc(FlowCatalog.stepsText(v.flow?.steps))}</div>
          </div>
          ${i === 0 ? '' : `<button class="btn btn-ghost btn-sm" onclick="_feRestore(${v.version})">${t('flow.restore')}</button>`}
        </div>`).join('')}</div>`
    : `<p style="font-size:12.5px;color:var(--text3)">${t('flow.no_versions')}</p>`;
  modal(t('flow.versions'), body, `<button class="btn btn-secondary" onclick="closeModal()">${t('common.close')}</button>`);
};

window._feRestore = async function(version) {
  if (!confirm(t('flow.restore_confirm', { v: version }))) return;
  try {
    await api('POST', `/automation/flows/${_fe.flow.id}/versions/${version}/restore`);
    closeModal();
    toast(t('flow.restored', { v: version }), 'success');
    pages['automation-flow']();
  } catch (e) { toast(e.message, 'error'); }
};
