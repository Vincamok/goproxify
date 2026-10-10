// ── PAGE: Fournisseurs d'authentification (SSO) ────────────────────────────────────────────────────
// Les types (OIDC, GitHub, LDAP, SAML, Basic, forward-auth…) et leurs champs viennent des manifestes du
// serveur (GET /auth-provider-types) : un type ajouté côté serveur apparaît ici sans modifier ce fichier.
// Les secrets sont renvoyés masqués par l'API ; les laisser tels quels les conserve.
// Textes : clés `ssop.*` de shared/i18n.js (en, fr, es, de).

let _apTypes = null;
let _apEditing = null;

async function apLoadTypes() {
  if (_apTypes) return _apTypes;
  try { _apTypes = await api('GET', '/auth-provider-types') || []; } catch { return []; }
  return _apTypes;
}

pages['auth-providers'] = async function() {
  document.getElementById('topbar-actions').innerHTML = Role.isAdmin()
    ? `<button class="btn btn-primary" onclick="openAuthProviderModal()">${esc(t('ssop.add'))}</button>` : '';
  await refreshAuthProviders();
};

async function refreshAuthProviders() {
  const content = document.getElementById('content');
  try {
    const [list, types] = await Promise.all([api('GET', '/auth-providers'), apLoadTypes()]);
    const label = ty => (types.find(m => m.type === ty) || {}).label || ty;
    const rows = (list || []).map(p => `<tr>
      <td><b>${esc(p.name)}</b></td>
      <td><span class="tag tag-neutral">${esc(label(p.provider))}</span></td>
      <td>${p.enabled ? `<span class="tag tag-green">${esc(t('ssop.state.on'))}</span>` : `<span class="tag tag-neutral">${esc(t('ssop.state.off'))}</span>`}</td>
      <td>${fmtDate(p.updated_at)}</td>
      <td>${Role.isAdmin() ? `
        <button class="btn btn-ghost btn-sm" onclick="toggleAuthProvider('${esc(p.id)}', ${p.enabled ? 'false' : 'true'})">${esc(p.enabled ? t('ssop.disable') : t('ssop.enable'))}</button>
        <button class="btn btn-ghost btn-sm" onclick="openAuthProviderModal('${esc(p.id)}')">${esc(t('common.edit'))}</button>
        <button class="btn btn-ghost btn-sm" onclick="deleteAuthProvider('${esc(p.id)}')">${esc(t('common.delete'))}</button>` : ''}
      </td></tr>`).join('');
    content.innerHTML = `
      <div class="card blueprint"><div class="table-wrap"><table>
        <thead><tr><th>${esc(t('ssop.col.name'))}</th><th>${esc(t('ssop.col.type'))}</th><th>${esc(t('ssop.col.state'))}</th><th>${esc(t('ssop.col.updated'))}</th><th></th></tr></thead>
        <tbody>${rows || `<tr><td colspan="5" class="empty"><p>${esc(t('ssop.empty'))}</p></td></tr>`}</tbody>
      </table></div></div>
      <p style="font-size:12px;color:var(--text2);margin-top:10px">${esc(t('ssop.note'))}</p>`;
  } catch (e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
}

function renderAuthProviderFields(type) {
  const wrap = document.getElementById('ap-fields');
  if (!wrap) return;
  const man = (_apTypes || []).find(m => m.type === type);
  const base = _apEditing && _apEditing.provider === type ? (_apEditing.config || {}) : {};
  // `enabled` et `provider` sont portés par le fournisseur lui-même : ils n'ont pas de champ ici.
  const fields = (man?.fields || []).filter(f => f.key !== 'enabled' && f.key !== 'provider');
  wrap.innerHTML = ManifestForm.render('ap', fields, base);
}

window.openAuthProviderModal = async function(id) {
  await apLoadTypes();
  _apEditing = null;
  if (id) { try { _apEditing = await api('GET', `/auth-providers/${id}`); } catch (e) { toast(e.message, 'error'); return; } }
  const cur = _apEditing?.provider || (_apTypes[0] && _apTypes[0].type) || '';
  modal(id ? t('ssop.modal.edit') : t('ssop.modal.new'), `
    <div class="form-row">
      <div class="field"><label class="field-label">${esc(t('ssop.name'))}</label>
        <input id="ap-name" class="input" value="${esc(_apEditing?.name || '')}"></div>
      <div class="field"><label class="field-label">${esc(t('ssop.type'))}</label>
        <select id="ap-type" class="input" ${id ? 'disabled' : ''} onchange="renderAuthProviderFields(this.value)">
          ${_apTypes.map(m => `<option value="${esc(m.type)}" ${m.type === cur ? 'selected' : ''}>${esc(m.label)}</option>`).join('')}
        </select></div>
    </div>
    <div id="ap-fields"></div>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="saveAuthProvider('${esc(id || '')}')">${t('common.save')}</button>`);
  renderAuthProviderFields(cur);
};
window.renderAuthProviderFields = renderAuthProviderFields;

window.saveAuthProvider = async function(id) {
  const provider = document.getElementById('ap-type').value;
  const man = (_apTypes || []).find(m => m.type === provider);
  const fields = (man?.fields || []).filter(f => f.key !== 'enabled' && f.key !== 'provider');
  const base = _apEditing && _apEditing.provider === provider ? (_apEditing.config || {}) : {};
  const res = ManifestForm.collect('ap', fields, base);
  const name = document.getElementById('ap-name').value.trim();
  if (!name) { toast(t('ssop.name_required'), 'error'); return; }
  if (res.errors.length) { toast(res.errors.join(' · '), 'error'); return; }
  const payload = { name, provider, config: res.config, enabled: _apEditing ? _apEditing.enabled : true };
  try {
    if (id) await api('PUT', `/auth-providers/${id}`, payload);
    else await api('POST', '/auth-providers', payload);
    toast(t('ssop.saved'), 'success');
    closeModal();
    refreshAuthProviders();
  } catch (e) { toast(e.message, 'error'); }
};

window.toggleAuthProvider = async function(id, enabled) {
  try { await api('PATCH', `/auth-providers/${id}`, { enabled }); refreshAuthProviders(); }
  catch (e) { toast(e.message, 'error'); }
};

window.deleteAuthProvider = function(id) {
  confirm_(t('ssop.delete_confirm'), async () => {
    try { await api('DELETE', `/auth-providers/${id}`); toast(t('ssop.deleted'), 'success'); refreshAuthProviders(); }
    catch (e) { toast(e.message, 'error'); }
  });
};
