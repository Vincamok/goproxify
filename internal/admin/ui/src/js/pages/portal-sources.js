// ── Sources de destinations du portail Access (ADR 0024) : onglet « Sources » du catalogue.
// La passerelle interroge l'API d'une plateforme (Proxmox…) et remonte ses machines comme candidates ;
// rien n'est visible des utilisateurs avant la publication.

const PortalSources = (() => {
  const STATES = ['new', 'published', 'ignored', 'missing'];
  let typesCache = null;

  const when = (s) => {
    if (!s) return '—';
    const d = new Date(String(s).replace(' ', 'T') + (/[zZ]|[+-]\d\d:?\d\d$/.test(s) ? '' : 'Z'));
    return isNaN(d) ? esc(s) : esc(d.toLocaleString());
  };

  async function loadTypes() {
    if (!typesCache) typesCache = ((await api('GET', '/portal/dest-sources/types')).types || []);
    return typesCache;
  }

  // Un champ de manifeste → un contrôle. data-key porte la clé ; collectConfig relit selon le genre.
  function fieldHTML(f, value) {
    const id = 'psf-' + f.key;
    const label = `<label class="field-label" for="${id}">${esc(f.label)}${f.required ? ' *' : ''}</label>`;
    const help = f.help ? `<div style="font-size:11px;color:var(--text2);margin-top:3px">${esc(f.help)}</div>` : '';
    const v = value !== undefined && value !== null ? value : (f.default !== undefined ? f.default : '');
    let ctl;
    if (f.kind === 'bool') {
      return `<div class="field" style="margin-bottom:10px"><label style="display:flex;gap:8px;align-items:center;font-size:13px">
        <input type="checkbox" id="${id}" data-key="${esc(f.key)}" data-kind="bool" ${v === true || v === 'true' ? 'checked' : ''}/> ${esc(f.label)}</label>${help}</div>`;
    }
    if (f.kind === 'select') {
      ctl = `<select class="input" id="${id}" data-key="${esc(f.key)}" data-kind="select">${(f.options || []).map(o => `<option value="${esc(o.value)}" ${String(v) === o.value ? 'selected' : ''}>${esc(o.label)}</option>`).join('')}</select>`;
    } else if (f.multiline) {
      ctl = `<textarea class="input" id="${id}" data-key="${esc(f.key)}" data-kind="text" rows="4" style="font-family:ui-monospace,monospace;font-size:11px">${esc(v)}</textarea>`;
    } else {
      const type = f.kind === 'password' ? 'password' : (f.kind === 'number' ? 'number' : 'text');
      const shown = f.kind === 'list' && Array.isArray(v) ? v.join(', ') : v;
      ctl = `<input class="input" id="${id}" type="${type}" data-key="${esc(f.key)}" data-kind="${esc(f.kind)}" value="${esc(shown)}" placeholder="${esc(f.placeholder || '')}" autocomplete="off"/>`;
    }
    return `<div class="field" style="margin-bottom:10px">${label}${ctl}${help}</div>`;
  }

  function collectConfig(root) {
    const cfg = {};
    root.querySelectorAll('[data-key]').forEach(el => {
      const key = el.getAttribute('data-key');
      const kind = el.getAttribute('data-kind');
      if (kind === 'bool') { cfg[key] = el.checked; return; }
      const raw = (el.value || '').trim();
      if (raw === '') return;
      if (kind === 'number') cfg[key] = Number(raw);
      else if (kind === 'list') cfg[key] = raw.split(',').map(x => x.trim()).filter(Boolean);
      else cfg[key] = el.tagName === 'TEXTAREA' ? el.value : raw;
    });
    return cfg;
  }

  const csv = (s) => String(s || '').split(',').map(x => x.trim()).filter(Boolean);

  async function openSourceEditor(src, o, reload) {
    const types = await loadTypes();
    if (!types.length) throw new Error('Aucun type de source');
    const isNew = !src;
    const cur = src || { type: types[0].type, name: '', config: {}, interval_s: 300, enabled: true, extra_tags: [], auto_publish: false, edge_name: o.scopeEdge() };
    const typeOf = (id) => types.find(x => x.type === id) || types[0];
    const edgeSel = o.isAdmin && isNew
      ? `<div class="field" style="margin-bottom:10px"><label class="field-label">${esc(t('pusers.edge') || 'Passerelle')}</label>
          <select class="input" id="ps-edge">${o.edges.map(c => { const nn = c.node_name || c.id; return `<option value="${esc(nn)}" ${nn === cur.edge_name ? 'selected' : ''}>${esc(c.display_name || nn)}</option>`; }).join('')}</select></div>` : '';
    const typeSel = isNew
      ? `<div class="field" style="margin-bottom:10px"><label class="field-label">${esc(t('psrc.f_type'))}</label>
          <select class="input" id="ps-type">${types.map(x => `<option value="${esc(x.type)}" ${x.type === cur.type ? 'selected' : ''}>${esc(x.label)}</option>`).join('')}</select></div>`
      : `<div style="font-size:12px;color:var(--text2);margin-bottom:10px">${esc(typeOf(cur.type).label)} · ${esc(cur.edge_name)}</div>`;

    const ov = PortalUI.modal({
      title: esc(isNew ? t('psrc.add') : cur.name),
      width: 600,
      body: `${edgeSel}${typeSel}
        <div class="field" style="margin-bottom:10px"><label class="field-label">${esc(t('psrc.f_name'))} *</label><input class="input" id="ps-name" value="${esc(cur.name)}"/></div>
        <div id="ps-fields"></div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
          <div class="field"><label class="field-label">${esc(t('psrc.f_interval'))}</label><input class="input" id="ps-interval" type="number" min="60" value="${esc(cur.interval_s || 300)}"/></div>
          <div class="field"><label class="field-label">${esc(t('psrc.f_tags'))}</label><input class="input" id="ps-tags" value="${esc((cur.extra_tags || []).join(', '))}" placeholder="proxmox, lab"/></div>
        </div>
        <label style="display:flex;gap:8px;align-items:flex-start;font-size:13px;margin-bottom:6px"><input type="checkbox" id="ps-auto" ${cur.auto_publish ? 'checked' : ''}/>
          <span>${esc(t('psrc.f_auto'))}<div style="font-size:11px;color:var(--text2)">${esc(t('psrc.f_auto_help'))}</div></span></label>
        <label style="display:flex;gap:8px;align-items:center;font-size:13px"><input type="checkbox" id="ps-enabled" ${cur.enabled !== false ? 'checked' : ''}/> ${esc(t('psrc.f_enabled'))}</label>
        <div id="ps-test-out" style="font-size:12px;margin-top:10px"></div>`,
      extraButtons: `<button type="button" class="btn btn-secondary" id="ps-test">${esc(t('psrc.test'))}</button>`,
      onOk: async (m) => {
        const body = {
          name: m.querySelector('#ps-name').value.trim(),
          config: collectConfig(m.querySelector('#ps-fields')),
          interval_s: Number(m.querySelector('#ps-interval').value) || 0,
          extra_tags: csv(m.querySelector('#ps-tags').value),
          auto_publish: m.querySelector('#ps-auto').checked,
          enabled: m.querySelector('#ps-enabled').checked,
        };
        if (isNew) {
          body.type = m.querySelector('#ps-type').value;
          body.edge_name = m.querySelector('#ps-edge')?.value || cur.edge_name;
          await api('POST', '/portal/dest-sources', body);
        } else {
          await api('PUT', '/portal/dest-sources/' + encodeURIComponent(cur.id), body);
        }
        reload();
      },
    });
    const type = () => (isNew ? ov.querySelector('#ps-type').value : cur.type);
    const paint = () => {
      const man = typeOf(type());
      ov.querySelector('#ps-fields').innerHTML = man.fields.map(f => fieldHTML(f, type() === cur.type ? cur.config[f.key] : undefined)).join('');
      ov.querySelector('#ps-test-out').textContent = '';
    };
    paint();
    if (isNew) ov.querySelector('#ps-type').onchange = paint;
    ov.querySelector('#ps-test').onclick = async (e) => {
      const out = ov.querySelector('#ps-test-out');
      e.target.disabled = true;
      out.style.color = 'var(--text2)';
      out.textContent = t('psrc.testing');
      try {
        const r = await api('POST', '/portal/dest-sources/test', {
          edge_name: ov.querySelector('#ps-edge')?.value || cur.edge_name,
          type: type(), source_id: isNew ? '' : cur.id,
          config: collectConfig(ov.querySelector('#ps-fields')),
        });
        if (r.ok) {
          out.style.color = 'var(--green,#3a9a5b)';
          out.textContent = t('psrc.test_ok', { n: r.count }) + (r.machines && r.machines.length ? ' — ' + r.machines.slice(0, 5).map(x => x.name).join(', ') + (r.count > 5 ? '…' : '') : '');
        } else {
          out.style.color = 'var(--danger,#c45c5c)';
          out.textContent = r.error || t('psrc.test_fail');
        }
      } catch (err) {
        out.style.color = 'var(--danger,#c45c5c)';
        out.textContent = err.message || String(err);
      }
      e.target.disabled = false;
    };
  }

  function openPublish(cands, reload) {
    const one = cands.length === 1 ? cands[0] : null;
    PortalUI.modal({
      title: esc(t('psrc.publish')),
      width: 480,
      okLabel: t('psrc.publish'),
      body: `<div style="font-size:12px;color:var(--text2);margin-bottom:10px">${esc(t('psrc.publish_help'))}</div>
        ${one ? `<div class="field" style="margin-bottom:10px"><label class="field-label">${esc(t('psrc.c_name'))}</label><input class="input" id="pp-name" value="${esc(one.name)}"/></div>
        <div style="display:grid;grid-template-columns:2fr 1fr;gap:10px;margin-bottom:10px">
          <div class="field"><label class="field-label">${esc(t('psrc.c_host'))}</label><input class="input" id="pp-host" value="${esc(one.host || '')}" placeholder="${one.host ? '' : esc(t('psrc.no_addr'))}"/></div>
          <div class="field"><label class="field-label">Port</label><input class="input" id="pp-port" type="number" value="${esc(one.port || 22)}"/></div></div>` : `<div style="font-size:13px;margin-bottom:10px">${esc(t('psrc.publish_n', { n: cands.length }))}</div>`}
        <div class="field"><label class="field-label">${esc(t('psrc.f_tags'))}</label><input class="input" id="pp-tags" placeholder="prod, ops"/></div>`,
      onOk: async (m) => {
        const tags = csv(m.querySelector('#pp-tags').value);
        if (one) {
          await api('POST', '/portal/dest-candidates/' + encodeURIComponent(one.id) + '/publish', {
            name: m.querySelector('#pp-name').value.trim(), host: m.querySelector('#pp-host').value.trim(),
            port: Number(m.querySelector('#pp-port').value) || 0, tags,
          });
        } else {
          const r = await api('POST', '/portal/dest-candidates/publish', { ids: cands.map(c => c.id), tags });
          if ((r.skipped || []).length) alert(t('psrc.publish_result', { p: r.published, s: r.skipped.length }) + '\n\n' + r.skipped.map(s => '• ' + s.reason).join('\n'));
        }
        reload();
      },
    });
  }

  async function mount(host, o) {
    host.innerHTML = '<p style="color:var(--text2)">' + esc(t('common.loading')) + '</p>';
    const st = o.state || (o.state = { cstate: 'new', q: '', selected: new Set() });
    const q = () => { const e = o.edgeFilter(); return e ? '?edge=' + encodeURIComponent(e) : ''; };
    const reload = () => mount(host, o);
    let sources = [], cands = [];
    try {
      const [s, c] = await Promise.all([
        api('GET', '/portal/dest-sources' + q()),
        api('GET', '/portal/dest-candidates' + q()),
      ]);
      sources = s.sources || [];
      cands = c.candidates || [];
    } catch (e) {
      host.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`;
      return;
    }
    const typeLabel = (id) => (typesCache || []).find(x => x.type === id)?.label || id;
    if (!typesCache) await loadTypes().catch(() => {});

    const counts = {};
    STATES.forEach(s => { counts[s] = cands.filter(c => c.state === s).length; });
    const shown = cands.filter(c => c.state === st.cstate && (!st.q || [c.name, c.host, c.source_name, ...(c.tags || [])].join(' ').toLowerCase().includes(st.q.toLowerCase())));
    st.selected.forEach(id => { if (!shown.some(c => c.id === id)) st.selected.delete(id); });

    const srcRow = (s) => {
      const ok = s.status === 'ok';
      const chip = s.status === ''
        ? `<span class="tag tag-neutral" style="font-size:10px">${esc(t('psrc.status_never'))}</span>`
        : `<span class="tag ${ok ? 'tag-accent' : 'tag-danger'}" style="font-size:10px" title="${esc(s.status_msg || '')}">${esc(ok ? t('psrc.status_ok') : t('psrc.status_error'))}</span>`;
      return `<tr style="border-top:1px solid var(--border)">
        <td style="padding:10px 14px"><b>${esc(s.name)}</b>${s.enabled ? '' : ` <span class="tag tag-neutral" style="font-size:10px">${esc(t('psrc.disabled'))}</span>`}
          <div style="font-size:11px;color:var(--text2)">${esc(typeLabel(s.type))}${o.isAdmin ? ' · ' + esc(s.edge_name) : ''}${s.auto_publish ? ' · ' + esc(t('psrc.auto_on')) : ''}</div></td>
        <td style="padding:10px 14px">${chip}${!ok && s.status_msg ? `<div style="font-size:11px;color:var(--danger,#c45c5c);max-width:340px;word-break:break-word">${esc(s.status_msg)}</div>` : ''}</td>
        <td style="padding:10px 14px;font-size:12px;color:var(--text2)">${when(s.last_sync_at)}<div>${esc(t('psrc.machines_n', { n: s.machine_count || 0 }))}</div></td>
        <td style="padding:10px 14px;text-align:right;white-space:nowrap">
          <button type="button" class="btn btn-ghost btn-sm" data-sync="${esc(s.id)}">${esc(t('psrc.sync_now'))}</button>
          <button type="button" class="btn btn-ghost btn-sm" data-sedit="${esc(s.id)}">${esc(t('common.edit'))}</button>
          <button type="button" class="btn btn-ghost btn-sm" data-sdel="${esc(s.id)}" style="color:var(--danger,#c45c5c)">${esc(t('common.delete'))}</button></td></tr>`;
    };

    const candRow = (c) => {
      const addr = c.host ? `${esc(c.host)}:${c.port || 22}` : `<span style="color:var(--danger,#c45c5c)">${esc(t('psrc.no_addr'))}</span>`;
      const dot = `<span title="${esc(c.running ? t('psrc.running') : t('psrc.stopped'))}" style="display:inline-block;width:8px;height:8px;border-radius:50%;background:${c.running ? 'var(--green,#3a9a5b)' : 'var(--text2)'};margin-right:6px"></span>`;
      const detail = Object.entries(c.detail || {}).filter(([k]) => k !== 'vmid').map(([k, v]) => esc(k + ': ' + v)).join(' · ');
      let actions = '';
      if (c.state === 'new') actions = `<button type="button" class="btn btn-primary btn-sm" data-cpub="${esc(c.id)}">${esc(t('psrc.publish'))}</button>
          <button type="button" class="btn btn-ghost btn-sm" data-cign="${esc(c.id)}">${esc(t('psrc.ignore'))}</button>`;
      else if (c.state === 'ignored') actions = `<button type="button" class="btn btn-ghost btn-sm" data-crest="${esc(c.id)}">${esc(t('psrc.restore'))}</button>
          <button type="button" class="btn btn-ghost btn-sm" data-cpub="${esc(c.id)}">${esc(t('psrc.publish'))}</button>`;
      return `<tr style="border-top:1px solid var(--border)">
        <td style="padding:10px 14px;width:28px">${c.state === 'new' ? `<input type="checkbox" data-csel="${esc(c.id)}" ${st.selected.has(c.id) ? 'checked' : ''}/>` : ''}</td>
        <td style="padding:10px 14px">${dot}<b>${esc(c.name)}</b><div style="font-size:11px;color:var(--text2)">${esc(c.source_name || '')}${detail ? ' · ' + detail : ''}</div></td>
        <td style="padding:10px 14px;font-family:ui-monospace,monospace;font-size:12px">${addr}</td>
        <td style="padding:10px 14px">${(c.tags || []).map(tg => `<span class="tag tag-neutral" style="font-size:10px">${esc(tg)}</span>`).join(' ')}</td>
        <td style="padding:10px 14px;text-align:right;white-space:nowrap">${actions}</td></tr>`;
    };

    const stateChip = (s) => `<button type="button" class="chip" data-cstate="${s}" style="cursor:pointer;${st.cstate === s ? 'border-color:var(--accent);color:var(--accent);font-weight:600' : ''}">${esc(t('psrc.state_' + s))} <span style="opacity:.7">${counts[s]}</span></button>`;

    host.innerHTML = `
      <p style="margin:0 0 14px;font-size:13px;color:var(--text2);max-width:760px">${esc(t('psrc.intro'))}</p>
      <h2 style="font-size:15px;margin:0 0 8px">${esc(t('psrc.sources'))}</h2>
      ${sources.length ? `<div class="card blueprint" style="padding:0;overflow:hidden;margin-bottom:22px"><div class="table-wrap"><table style="width:100%;border-collapse:collapse;font-size:13px"><tbody>${sources.map(srcRow).join('')}</tbody></table></div></div>`
        : `<div style="padding:22px;text-align:center;color:var(--text2);border:1px dashed var(--border);border-radius:8px;margin-bottom:22px">${esc(t('psrc.empty_sources'))}</div>`}
      <h2 style="font-size:15px;margin:0 0 8px">${esc(t('psrc.machines'))}</h2>
      <div style="display:flex;flex-wrap:wrap;gap:8px;align-items:center;margin-bottom:10px">
        ${STATES.map(stateChip).join('')}
        <input class="input" id="ps-q" placeholder="${esc(t('pcatalog.search'))}" value="${esc(st.q)}" style="max-width:200px;margin-left:auto"/>
        ${st.cstate === 'new' ? `<button type="button" class="btn btn-primary btn-sm" id="ps-pub-sel" ${st.selected.size ? '' : 'disabled'}>${esc(t('psrc.publish_sel', { n: st.selected.size }))}</button>` : ''}
      </div>
      ${shown.length ? `<div class="card blueprint" style="padding:0;overflow:hidden"><div class="table-wrap"><table style="width:100%;border-collapse:collapse;font-size:13px">
        <thead><tr style="text-align:left;color:var(--text2)"><th style="padding:8px 14px">${st.cstate === 'new' ? '<input type="checkbox" id="ps-all"/>' : ''}</th><th style="padding:8px 14px">${esc(t('psrc.c_name'))}</th><th style="padding:8px 14px">${esc(t('psrc.c_host'))}</th><th style="padding:8px 14px">Tags</th><th></th></tr></thead>
        <tbody>${shown.map(candRow).join('')}</tbody></table></div></div>`
        : `<div style="padding:22px;text-align:center;color:var(--text2);border:1px dashed var(--border);border-radius:8px">${esc(t('psrc.empty_' + st.cstate))}</div>`}`;

    const byId = (list, id) => list.find(x => x.id === id);
    const run = async (fn) => { try { await fn(); } catch (e) { alert(e.message || e); } };

    host.querySelectorAll('[data-cstate]').forEach(b => { b.onclick = () => { st.cstate = b.getAttribute('data-cstate'); st.selected.clear(); reload(); }; });
    host.querySelector('#ps-q').oninput = (e) => { st.q = e.target.value; clearTimeout(st._t); st._t = setTimeout(reload, 250); };
    host.querySelectorAll('[data-csel]').forEach(b => { b.onchange = () => { b.checked ? st.selected.add(b.getAttribute('data-csel')) : st.selected.delete(b.getAttribute('data-csel')); const bt = host.querySelector('#ps-pub-sel'); if (bt) { bt.disabled = !st.selected.size; bt.textContent = t('psrc.publish_sel', { n: st.selected.size }); } }; });
    const all = host.querySelector('#ps-all');
    if (all) all.onchange = () => { shown.filter(c => c.state === 'new').forEach(c => all.checked ? st.selected.add(c.id) : st.selected.delete(c.id)); reload(); };
    const pubSel = host.querySelector('#ps-pub-sel');
    if (pubSel) pubSel.onclick = () => openPublish(shown.filter(c => st.selected.has(c.id)), () => { st.selected.clear(); reload(); });
    host.querySelectorAll('[data-cpub]').forEach(b => { b.onclick = () => { const c = byId(cands, b.getAttribute('data-cpub')); if (c) openPublish([c], reload); }; });
    host.querySelectorAll('[data-cign]').forEach(b => { b.onclick = () => run(async () => { await api('POST', '/portal/dest-candidates/' + encodeURIComponent(b.getAttribute('data-cign')) + '/ignore'); reload(); }); });
    host.querySelectorAll('[data-crest]').forEach(b => { b.onclick = () => run(async () => { await api('POST', '/portal/dest-candidates/' + encodeURIComponent(b.getAttribute('data-crest')) + '/restore'); reload(); }); });
    host.querySelectorAll('[data-sync]').forEach(b => { b.onclick = () => run(async () => { await api('POST', '/portal/dest-sources/' + encodeURIComponent(b.getAttribute('data-sync')) + '/sync'); PortalUI.toast(t('psrc.sync_asked')); setTimeout(reload, 4000); }); });
    host.querySelectorAll('[data-sedit]').forEach(b => { b.onclick = () => run(() => openSourceEditor(byId(sources, b.getAttribute('data-sedit')), o, reload)); });
    host.querySelectorAll('[data-sdel]').forEach(b => { b.onclick = () => run(async () => {
      if (!confirm(t('psrc.confirm_del'))) return;
      await api('DELETE', '/portal/dest-sources/' + encodeURIComponent(b.getAttribute('data-sdel')));
      reload();
    }); });
    o.onAdd = () => run(() => openSourceEditor(null, o, reload));
  }

  return { mount };
})();
