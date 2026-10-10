// ── PAGE: Plugins WebAssembly ───────────────────────────────────────────────────────────────────────
// Plugins exécutés par les passerelles dans une sandbox (ADR 0008, docs/plugins.md). Installer un plugin
// fait exécuter du code sur les passerelles : réservé aux administrateurs. Le module est envoyé avec son
// empreinte SHA-256 (calculée ici) et, si des clés de confiance sont enregistrées, sa signature Ed25519.
// Textes : clés `plug.*` de shared/i18n.js (en, fr, es, de).

function plBytesToBase64(buf) {
  let bin = '';
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

async function plSha256Hex(buf) {
  if (!(window.crypto && crypto.subtle)) throw new Error(t('plug.err.sha'));
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

pages.plugins = async function() {
  document.getElementById('topbar-actions').innerHTML = Role.isAdmin()
    ? `<button class="btn btn-primary" onclick="openPluginModal()">${esc(t('plug.add'))}</button>` : '';
  await refreshPlugins();
};

async function refreshPlugins() {
  const content = document.getElementById('content');
  try {
    const [list, keys, repos] = await Promise.all([api('GET', '/plugins'), api('GET', '/plugin-keys'), api('GET', '/plugin-repos')]);
    const admin = Role.isAdmin();
    const rows = (list || []).map(p => `<tr>
      <td><b>${esc(p.name)}</b></td>
      <td>${esc(p.version)}</td>
      <td>${(p.hooks || []).map(h => `<span class="tag tag-neutral">${esc(h)}</span>`).join(' ')}</td>
      <td>${p.on_error === 'allow' ? `<span class="tag tag-red">${esc(t('plug.onerror.allow'))}</span>` : `<span class="tag tag-green">${esc(t('plug.onerror.deny'))}</span>`}</td>
      <td>${p.signed_by ? `<span class="tag tag-green" title="${esc(t('plug.signed_key', { id: p.signed_by }))}">${esc(t('plug.signed'))}</span>` : `<span class="tag tag-neutral">${esc(t('plug.unsigned'))}</span>`}</td>
      <td title="${esc(p.sha256)}"><code>${esc((p.sha256 || '').slice(0, 12))}…</code> · ${Math.round((p.size || 0) / 1024)} Kio</td>
      <td>${fmtDate(p.updated_at)}</td>
      <td>${admin ? `<button class="btn btn-ghost btn-sm" onclick="openPluginModal('${esc(p.name)}')">${esc(t('plug.replace'))}</button>
        <button class="btn btn-ghost btn-sm" onclick="deletePlugin('${esc(p.name)}')">${esc(t('common.delete'))}</button>` : ''}</td></tr>`).join('');
    const keyRows = (keys || []).map(k => `<tr><td><b>${esc(k.name)}</b></td><td><code>${esc(k.id)}</code></td>
      <td>${admin ? `<button class="btn btn-ghost btn-sm" onclick="deletePluginKey('${esc(k.id)}')">${esc(t('common.delete'))}</button>` : ''}</td></tr>`).join('');
    const repoRows = (repos || []).map(r => `<tr><td><b>${esc(r.name)}</b></td><td><code>${esc(r.url)}</code></td>
      <td>${admin ? `<button class="btn btn-ghost btn-sm" onclick="deletePluginRepo('${esc(r.id)}')">${esc(t('common.delete'))}</button>` : ''}</td></tr>`).join('');
    content.innerHTML = `
      <div class="card blueprint"><div class="table-wrap"><table>
        <thead><tr><th>${esc(t('plug.col.name'))}</th><th>${esc(t('plug.col.version'))}</th><th>${esc(t('plug.col.hooks'))}</th><th>${esc(t('plug.col.onerror'))}</th><th>${esc(t('plug.col.signature'))}</th><th>${esc(t('plug.col.module'))}</th><th>${esc(t('plug.col.updated'))}</th><th></th></tr></thead>
        <tbody>${rows || `<tr><td colspan="8" class="empty"><p>${esc(t('plug.empty'))}</p></td></tr>`}</tbody>
      </table></div></div>
      <p style="font-size:12px;color:var(--text2);margin:10px 0 24px">${t('plug.attach_hint')}</p>

      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
        <div><b>${esc(t('plug.keys.title'))}</b>
          <div style="font-size:12px;color:var(--text2)">${esc((keys || []).length ? t('plug.keys.required') : t('plug.keys.none'))}</div></div>
        ${admin ? `<button class="btn btn-secondary btn-sm" onclick="openPluginKeyModal()">${esc(t('plug.keys.add'))}</button>` : ''}
      </div>
      <div class="card blueprint"><div class="table-wrap"><table>
        <thead><tr><th>${esc(t('plug.keys.col.name'))}</th><th>${esc(t('plug.keys.col.id'))}</th><th></th></tr></thead>
        <tbody>${keyRows || `<tr><td colspan="3" class="empty"><p>${esc(t('plug.keys.empty'))}</p></td></tr>`}</tbody>
      </table></div></div>

      <div style="display:flex;align-items:center;justify-content:space-between;margin:24px 0 8px">
        <b>${esc(t('plug.repos.title'))}</b>
        ${admin ? `<button class="btn btn-secondary btn-sm" onclick="openPluginRepoModal()">${esc(t('plug.repos.add'))}</button>` : ''}
      </div>
      <div class="card blueprint"><div class="table-wrap"><table>
        <thead><tr><th>${esc(t('plug.repos.col.name'))}</th><th>${esc(t('plug.repos.col.url'))}</th><th></th></tr></thead>
        <tbody>${repoRows || `<tr><td colspan="3" class="empty"><p>${esc(t('plug.repos.empty'))}</p></td></tr>`}</tbody>
      </table></div></div>

      <div style="display:flex;align-items:center;justify-content:space-between;margin:24px 0 8px">
        <b>${esc(t('plug.catalog.title'))}</b>
        ${(repos || []).length ? `<button class="btn btn-secondary btn-sm" onclick="loadPluginCatalog()">${esc(t('plug.catalog.load'))}</button>` : ''}
      </div>
      <div id="pl-catalog"></div>`;
  } catch (e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
}

const PL_MANIFEST_EXAMPLE = `{
  "name": "mon-plugin",
  "version": "1.0.0",
  "api_version": 1,
  "hooks": ["request"],
  "on_error": "deny",
  "limits": { "memory_pages": 16, "timeout_ms": 50 },
  "fields": []
}`;

window.openPluginModal = async function(name) {
  let manifestText = PL_MANIFEST_EXAMPLE;
  if (name) {
    try {
      const p = await api('GET', `/plugins/${encodeURIComponent(name)}`);
      const { sha256, size, signed_by, updated_at, ...manifest } = p;
      manifestText = JSON.stringify(manifest, null, 2);
    } catch (e) { toast(e.message, 'error'); return; }
  }
  modal(name ? t('plug.modal.replace', { name }) : t('plug.modal.new'), `
    <div class="field"><label class="field-label">${esc(t('plug.manifest'))}</label>
      <textarea id="pl-manifest" class="input" rows="11" style="font-family:monospace">${esc(manifestText)}</textarea></div>
    <div class="field"><label class="field-label">${esc(t('plug.wasm'))}</label>
      <input id="pl-wasm" class="input" type="file" accept=".wasm,application/wasm"></div>
    <div class="field"><label class="field-label">${esc(t('plug.sig'))}</label>
      <textarea id="pl-sig" class="input" rows="2" placeholder="${esc(t('plug.sig_ph'))}"></textarea></div>
    <p style="font-size:12px;color:var(--text2)">${esc(t('plug.warn'))}</p>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="savePlugin('${esc(name || '')}')">${t('common.save')}</button>`);
};

window.savePlugin = async function(name) {
  let manifest;
  try { manifest = JSON.parse(document.getElementById('pl-manifest').value); }
  catch (e) { toast(t('plug.err.manifest', { msg: e.message }), 'error'); return; }
  const file = document.getElementById('pl-wasm').files[0];
  if (!file) { toast(t('plug.err.nofile'), 'error'); return; }
  try {
    const buf = await file.arrayBuffer();
    const payload = { manifest, sha256: await plSha256Hex(buf), wasm: plBytesToBase64(buf) };
    const sig = document.getElementById('pl-sig').value.trim();
    if (sig) payload.signature = sig;
    if (name) await api('PUT', `/plugins/${encodeURIComponent(name)}`, payload);
    else await api('POST', '/plugins', payload);
    toast(t('plug.installed'), 'success');
    closeModal();
    refreshPlugins();
  } catch (e) { toast(e.message, 'error'); }
};

window.deletePlugin = function(name) {
  confirm_(t('plug.delete_confirm', { name }), async () => {
    try { await api('DELETE', `/plugins/${encodeURIComponent(name)}`); toast(t('plug.deleted'), 'success'); refreshPlugins(); }
    catch (e) { toast(e.message, 'error'); }
  });
};

window.openPluginKeyModal = function() {
  modal(t('plug.key.modal'), `
    <div class="field"><label class="field-label">${esc(t('plug.key.name'))}</label><input id="plk-name" class="input" placeholder="${esc(t('plug.key.name_ph'))}"></div>
    <div class="field"><label class="field-label">${esc(t('plug.key.value'))}</label>
      <input id="plk-key" class="input" placeholder="6yi+zAMz…"></div>
    <p style="font-size:12px;color:var(--text2)">${esc(t('plug.key.note'))}</p>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="savePluginKey()">${t('common.save')}</button>`);
};

window.savePluginKey = async function() {
  const name = document.getElementById('plk-name').value.trim();
  const public_key = document.getElementById('plk-key').value.trim();
  if (!name || !public_key) { toast(t('plug.key.required'), 'error'); return; }
  try {
    await api('POST', '/plugin-keys', { name, public_key });
    toast(t('plug.key.saved'), 'success');
    closeModal();
    refreshPlugins();
  } catch (e) { toast(e.message, 'error'); }
};

window.deletePluginKey = function(id) {
  confirm_(t('plug.key.delete_confirm'), async () => {
    try { await api('DELETE', `/plugin-keys/${encodeURIComponent(id)}`); toast(t('plug.key.deleted'), 'success'); refreshPlugins(); }
    catch (e) { toast(e.message, 'error'); }
  });
};

// ── Dépôts et catalogue ────────────────────────────────────────────────────────────────────────────

window.openPluginRepoModal = function() {
  modal(t('plug.repo.modal'), `
    <div class="field"><label class="field-label">${esc(t('plug.repo.name'))}</label><input id="plr-name" class="input"></div>
    <div class="field"><label class="field-label">${esc(t('plug.repo.url'))}</label>
      <input id="plr-url" class="input" placeholder="https://plugins.example.com/index.json"></div>
    <div class="field"><label class="field-label" style="display:flex;align-items:center;gap:8px">
      <input type="checkbox" id="plr-private"> ${esc(t('plug.repo.private'))}</label></div>
    <p style="font-size:12px;color:var(--text2)">${esc(t('plug.repo.note'))}</p>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="savePluginRepo()">${t('common.save')}</button>`);
};

window.savePluginRepo = async function() {
  const name = document.getElementById('plr-name').value.trim();
  const url = document.getElementById('plr-url').value.trim();
  if (!name || !url) { toast(t('plug.repo.required'), 'error'); return; }
  try {
    await api('POST', '/plugin-repos', { name, url, allow_private: document.getElementById('plr-private').checked });
    toast(t('plug.repo.saved'), 'success');
    closeModal();
    refreshPlugins();
  } catch (e) { toast(e.message, 'error'); }
};

window.deletePluginRepo = function(id) {
  confirm_(t('plug.repo.delete_confirm'), async () => {
    try { await api('DELETE', `/plugin-repos/${encodeURIComponent(id)}`); toast(t('plug.repo.deleted'), 'success'); refreshPlugins(); }
    catch (e) { toast(e.message, 'error'); }
  });
};

// Le catalogue interroge les dépôts sur le réseau : il ne se charge qu'à la demande.
window.loadPluginCatalog = async function() {
  const host = document.getElementById('pl-catalog');
  if (!host) return;
  host.innerHTML = `<p style="font-size:12.5px;color:var(--text3)">${esc(t('plug.catalog.loading'))}</p>`;
  try {
    const res = await api('GET', '/plugin-repos/catalog');
    const admin = Role.isAdmin();
    const errors = (res.errors || []).map(e => `<p style="font-size:12px;color:var(--red)">${esc(t('plug.catalog.error', { name: e.repo_name, error: e.error }))}</p>`).join('');
    const rows = (res.entries || []).map(e => {
      const state = e.installed_version
        ? esc(t(e.update_available ? 'plug.catalog.update_available' : 'plug.catalog.up_to_date', { version: e.installed_version }))
        : '—';
      const action = e.installed_version && !e.update_available ? '' : `<button class="btn btn-secondary btn-sm"
          onclick="installFromCatalog('${esc(e.repo_id)}','${esc(e.name)}','${esc(e.version)}')">${esc(t(e.installed_version ? 'plug.catalog.update' : 'plug.catalog.install'))}</button>`;
      return `<tr><td><b>${esc(e.name)}</b><div style="font-size:11px;color:var(--text3)">${esc(e.description || '')}</div></td>
        <td>${esc(e.version)}</td><td>${(e.hooks || []).map(h => `<span class="tag tag-neutral">${esc(h)}</span>`).join(' ')}</td>
        <td>${esc(t(e.signed ? 'plug.yes' : 'plug.no'))}</td><td>${state}</td><td>${esc(e.repo_name)}</td>
        <td>${admin ? action : ''}</td></tr>`;
    }).join('');
    host.innerHTML = errors + `<div class="card blueprint"><div class="table-wrap"><table>
      <thead><tr><th>${esc(t('plug.col.name'))}</th><th>${esc(t('plug.col.version'))}</th><th>${esc(t('plug.col.hooks'))}</th><th>${esc(t('plug.catalog.col.signed'))}</th><th>${esc(t('plug.catalog.col.state'))}</th><th>${esc(t('plug.catalog.col.repo'))}</th><th></th></tr></thead>
      <tbody>${rows || `<tr><td colspan="7" class="empty"><p>${esc(t('plug.catalog.empty'))}</p></td></tr>`}</tbody></table></div></div>`;
  } catch (e) { host.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
};

window.installFromCatalog = async function(repoId, name, version) {
  try {
    await api('POST', '/plugin-repos/install', { repo_id: repoId, name, version });
    toast(t('plug.catalog.done', { name, version }), 'success');
    await refreshPlugins();
    loadPluginCatalog();
  } catch (e) { toast(e.message, 'error'); }
};
