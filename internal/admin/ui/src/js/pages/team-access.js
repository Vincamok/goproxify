// ── Accès d'équipe (ADR 0022) ─────────────────────────────────────────────
// Un accès = un périmètre (critères tous requis) et un niveau par service. Les libellés des services et des niveaux
// viennent du catalogue de l'API (GET /rights/catalog).

let _rightsCatalog = null;
async function rightsCatalog() {
  if (!_rightsCatalog) _rightsCatalog = await api('GET', '/rights/catalog');
  window._rightsCatalogCache = _rightsCatalog;
  return _rightsCatalog;
}

const PERIMETER_FIELDS = [
  ['domain', 'users.pm_domain', '*.corp.io'],
  ['proxy', 'users.pm_proxy', 'alpha-*  |  re:^alpha-\\d+$'],
  ['backend', 'users.pm_backend', 'http://10.0.0.*'],
  ['group_name', 'users.pm_group', 'paris-*'],
  ['group_environment', 'users.pm_environment', 'prod'],
  ['group_region', 'users.pm_region', 'paris'],
  ['group_tag', 'users.pm_tag', 'lan'],
  ['labels', 'users.pm_labels', 'env=prod,projet=alpha'],
];

function perimeterSummaryHtml(p) {
  const parts = [];
  if (p.domain) parts.push(`${t('users.pm_domain')} <code>${esc(p.domain)}</code>`);
  if (p.proxy) parts.push(`${t('users.pm_proxy')} <code>${esc(p.proxy)}</code>`);
  if (p.backend) parts.push(`${t('users.pm_backend')} <code>${esc(p.backend)}</code>`);
  const g = p.group || {};
  if (g.name) parts.push(`${t('users.pm_group')} <code>${esc(g.name)}</code>`);
  if (g.environment) parts.push(`${t('users.pm_environment')} <code>${esc(g.environment)}</code>`);
  if (g.region) parts.push(`${t('users.pm_region')} <code>${esc(g.region)}</code>`);
  if (g.tag) parts.push(`${t('users.pm_tag')} <code>${esc(g.tag)}</code>`);
  Object.entries(p.labels || {}).forEach(([k, v]) => parts.push(`<code>${esc(k)}=${esc(v)}</code>`));
  return parts.length ? parts.join(` ${t('users.pm_and')} `) : esc(t('users.access_everything'));
}

function accessSummaryHtml(a, catalog) {
  const labels = Object.fromEntries((catalog?.services || []).map(s => [s.id, s]));
  const levels = Object.entries(a.levels || {}).map(([svc, lvl]) => {
    const s = labels[svc];
    const l = s?.levels?.find(x => x.id === lvl);
    return `<span class="tag tag-neutral" style="font-size:10px;margin:1px 2px 1px 0;">${esc(s?.label || svc)} : ${esc(l?.label || lvl)}</span>`;
  }).join('');
  const perms = (a.permissions || []).map(p => `<span class="tag tag-accent" style="font-size:10px;margin:1px 2px 1px 0;">${esc(p)}</span>`).join('');
  return `<div style="font-size:12px;opacity:0.75;">${perimeterSummaryHtml(a.perimeter || {})}</div>
    <div style="margin-top:4px;">${levels || `<span style="font-size:11px;opacity:0.5;">${esc(t('users.level_none'))}</span>`}${perms}</div>`;
}

// Section « Accès » de la fenêtre d'équipe : liste, ajout, modification, suppression (enregistrés aussitôt).
async function renderTeamAccesses(teamId) {
  const el = document.getElementById('tm-accesses');
  if (!el) return;
  if (!teamId) { el.innerHTML = `<p style="margin:0;font-size:12px;opacity:0.6;">${esc(t('users.access_team_first'))}</p>`; return; }
  let list = [];
  let catalog = null;
  try { [list, catalog] = await Promise.all([api('GET', `/teams/${teamId}/accesses`), rightsCatalog()]); } catch (e) { el.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; return; }
  window._teamAccesses = list || [];
  el.innerHTML = (list || []).length
    ? list.map((a, i) => `<div style="border:1px solid var(--border);padding:8px 10px;display:flex;gap:8px;align-items:flex-start;">
        <div style="flex:1;min-width:0;"><div style="font-size:13px;font-weight:600;">${esc(a.name || t('users.access_unnamed'))}</div>${accessSummaryHtml(a, catalog)}</div>
        <button class="btn btn-ghost btn-icon" onclick="openAccessModal('${esc(teamId)}', ${i})" title="${esc(t('common.edit'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
        <button class="btn btn-ghost btn-icon" onclick="removeTeamAccess('${esc(teamId)}', '${esc(a.id)}')" title="${esc(t('common.delete'))}"><svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg></button>
      </div>`).join('')
    : `<span style="font-size:12px;opacity:0.45;">${esc(t('users.no_access'))}</span>`;
}

window.removeTeamAccess = function(teamId, accessId) {
  confirm_(t('users.access_delete_confirm'), async () => {
    try { await api('DELETE', `/teams/${teamId}/accesses/${accessId}`); toast(t('users.access_removed'), 'success'); renderTeamAccesses(teamId); refreshUsers(); }
    catch (e) { toast(e.message, 'error'); }
  });
};

function perimeterFromForm() {
  const v = id => (document.getElementById('ac-' + id)?.value || '').trim();
  const p = {};
  ['domain', 'proxy', 'backend'].forEach(k => { if (v(k)) p[k] = v(k); });
  const group = {};
  if (v('group_name')) group.name = v('group_name');
  if (v('group_environment')) group.environment = v('group_environment');
  if (v('group_region')) group.region = v('group_region');
  if (v('group_tag')) group.tag = v('group_tag');
  if (Object.keys(group).length) p.group = group;
  if (v('labels')) {
    p.labels = {};
    v('labels').split(',').forEach(kv => {
      const [k, ...rest] = kv.trim().split('=');
      if (k) p.labels[k.trim()] = rest.join('=').trim();
    });
  }
  return p;
}

function levelsFromForm() {
  const levels = {};
  document.querySelectorAll('select[name="ac-level"]').forEach(sel => { if (sel.value) levels[sel.dataset.service] = sel.value; });
  return levels;
}

function applyProfile(catalog, id) {
  const profile = (catalog.profiles || []).find(p => p.id === id);
  document.querySelectorAll('select[name="ac-level"]').forEach(sel => { sel.value = profile?.levels?.[sel.dataset.service] || ''; });
  document.querySelectorAll('input[name="ac-perm"]').forEach(cb => { cb.checked = !!profile && (profile.permissions || []).includes(cb.value); });
  const nameEl = document.getElementById('ac-name');
  if (profile && nameEl && !nameEl.value.trim()) nameEl.value = profile.label;
}

window.openAccessModal = async function(teamId, index) {
  let catalog;
  try { catalog = await rightsCatalog(); } catch (e) { toast(e.message, 'error'); return; }
  const access = index == null ? null : (window._teamAccesses || [])[index];
  const p = access?.perimeter || {};
  const g = p.group || {};
  const values = {
    domain: p.domain || '', proxy: p.proxy || '', backend: p.backend || '',
    group_name: g.name || '', group_environment: g.environment || '', group_region: g.region || '', group_tag: g.tag || '',
    labels: Object.entries(p.labels || {}).map(([k, v]) => `${k}=${v}`).join(','),
  };
  const levels = access?.levels || {};
  const permissions = access?.permissions || [];
  // Services regroupés comme le menu de l'Admin ; l'écriture des objets partagés (classe « platform ») n'est jamais proposée.
  const groups = {};
  (catalog.services || []).forEach(s => {
    if (s.id === 'gdpr') return;
    (groups[s.group] = groups[s.group] || []).push(s);
  });
  const notGrantable = ['users:write', 'teams:write'];
  const gridHtml = Object.entries(groups).map(([group, services]) => `
    <div style="font-size:11px;text-transform:uppercase;letter-spacing:0.07em;opacity:0.5;margin-top:8px;">${esc(t('users.group_' + group))}</div>
    ${services.map(s => {
      const lv = (s.levels || []).filter(l => l.class !== 'platform');
      const explicits = (s.explicits || []).filter(e => !notGrantable.includes(e.id));
      if (!lv.length && !explicits.length) return '';
      return `<div style="display:flex;flex-wrap:wrap;align-items:center;gap:6px 10px;padding:4px 0;border-bottom:1px solid var(--border);">
        <span style="flex:1;min-width:160px;font-size:12.5px;">${esc(s.label)}</span>
        ${lv.length ? `<select name="ac-level" data-service="${esc(s.id)}" style="font-size:12px;padding:3px 6px;border:1px solid var(--border);border-radius:4px;background:var(--input-bg,var(--bg2));color:var(--text);">
          <option value="">${esc(t('users.level_none'))}</option>
          ${lv.map(l => `<option value="${esc(l.id)}" ${levels[s.id] === l.id ? 'selected' : ''}>${esc(l.label)}</option>`).join('')}
        </select>` : ''}
        ${explicits.map(e => `<label style="display:inline-flex;align-items:center;gap:4px;font-size:11.5px;" title="${esc(t('users.access_sensitive'))}">
          <input type="checkbox" name="ac-perm" value="${esc(e.id)}" ${permissions.includes(e.id) ? 'checked' : ''}> ${esc(e.label)}</label>`).join('')}
      </div>`;
    }).join('')}`).join('');

  document.getElementById('access-modal-backdrop')?.remove();
  document.body.insertAdjacentHTML('beforeend', `
    <div id="access-modal-backdrop" class="dialog-backdrop" style="background:rgba(0,0,0,0.6);z-index:10002;">
      <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(720px,96vw);max-width:none;max-height:92vh;overflow:auto;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="dialog-title">${access ? t('users.access_edit') : t('users.access_add')}</div>
        <div class="dialog-body" style="display:flex;flex-direction:column;gap:14px;">
          <div class="field"><label>${t('users.access_name')}</label><input class="input" id="ac-name" value="${esc(access?.name || '')}" placeholder="Exploitation prod"></div>
          <div class="field"><label>${t('users.access_profile')}</label>
            <select id="ac-profile" style="font-size:12.5px;padding:5px 8px;border:1px solid var(--border);border-radius:4px;background:var(--input-bg,var(--bg2));color:var(--text);">
              <option value="">—</option>
              ${(catalog.profiles || []).map(pr => `<option value="${esc(pr.id)}">${esc(pr.label)} — ${esc(pr.audience)}</option>`).join('')}
            </select>
          </div>
          <div style="display:flex;flex-direction:column;gap:6px;">
            <label style="font-size:13px;font-weight:500;">${t('users.access_perimeter')}</label>
            <p style="margin:0;font-size:11px;opacity:0.55;">${esc(t('users.access_perimeter_hint'))}</p>
            <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(220px,1fr));gap:8px;">
              ${PERIMETER_FIELDS.map(([key, label, ph]) => `<div class="field" style="margin:0;"><label style="font-size:11.5px;">${esc(t(label))}</label><input class="input" id="ac-${key}" value="${esc(values[key])}" placeholder="${esc(ph)}" autocomplete="off"></div>`).join('')}
            </div>
            <div style="display:flex;align-items:center;gap:10px;">
              <button type="button" class="btn btn-secondary" onclick="previewAccessPerimeter()">${esc(t('users.access_preview'))}</button>
              <span id="ac-preview" style="font-size:12px;opacity:0.8;"></span>
            </div>
          </div>
          <div style="display:flex;flex-direction:column;gap:2px;">
            <label style="font-size:13px;font-weight:500;">${t('users.access_grid')}</label>
            <p style="margin:0;font-size:11px;opacity:0.55;">${esc(t('users.access_grid_hint'))}</p>
            ${gridHtml}
          </div>
        </div>
        <div class="dialog-actions">
          <button class="btn btn-secondary blueprint" onclick="document.getElementById('access-modal-backdrop').remove()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('common.cancel')}</button>
          <button class="btn btn-primary blueprint" onclick="saveTeamAccess('${esc(teamId)}', '${esc(access?.id || '')}')"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('common.save')}</button>
        </div>
      </div>
    </div>`);
  document.getElementById('ac-profile').addEventListener('change', e => applyProfile(catalog, e.target.value));
};

window.previewAccessPerimeter = async function() {
  const out = document.getElementById('ac-preview');
  out.textContent = '…';
  try {
    const r = await api('POST', '/rights/preview', { perimeter: perimeterFromForm() });
    out.textContent = t('users.access_preview_n', { n: r.count, total: r.total });
    out.title = (r.proxies || []).map(x => x.name).join('\n');
  } catch (e) { out.textContent = e.message; }
};

window.saveTeamAccess = async function(teamId, accessId) {
  const body = {
    name: document.getElementById('ac-name').value.trim(),
    perimeter: perimeterFromForm(),
    levels: levelsFromForm(),
    permissions: [...document.querySelectorAll('input[name="ac-perm"]:checked')].map(cb => cb.value),
  };
  try {
    if (accessId) await api('PUT', `/teams/${teamId}/accesses/${accessId}`, body);
    else await api('POST', `/teams/${teamId}/accesses`, body);
    toast(t('users.access_saved'), 'success');
    document.getElementById('access-modal-backdrop')?.remove();
    renderTeamAccesses(teamId);
    refreshUsers();
  } catch (e) { toast(e.message, 'error'); }
};
