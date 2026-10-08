// ── PAGE: Plugins WebAssembly ───────────────────────────────────────────────────────────────────────
// Plugins exécutés par les passerelles dans une sandbox (ADR 0008, docs/plugins.md). Installer un plugin
// fait exécuter du code sur les passerelles : réservé aux administrateurs. Le module est envoyé avec son
// empreinte SHA-256 (calculée ici) et, si des clés de confiance sont enregistrées, sa signature Ed25519.

function plBytesToBase64(buf) {
  let bin = '';
  const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i += 0x8000) bin += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(bin);
}

async function plSha256Hex(buf) {
  if (!(window.crypto && crypto.subtle)) throw new Error('SHA-256 indisponible : ouvrez l\'Admin en HTTPS');
  const digest = await crypto.subtle.digest('SHA-256', buf);
  return Array.from(new Uint8Array(digest)).map(b => b.toString(16).padStart(2, '0')).join('');
}

pages.plugins = async function() {
  document.getElementById('topbar-actions').innerHTML = Role.isAdmin()
    ? `<button class="btn btn-primary" onclick="openPluginModal()">+ Plugin</button>` : '';
  await refreshPlugins();
};

async function refreshPlugins() {
  const content = document.getElementById('content');
  try {
    const [list, keys] = await Promise.all([api('GET', '/plugins'), api('GET', '/plugin-keys')]);
    const admin = Role.isAdmin();
    const rows = (list || []).map(p => `<tr>
      <td><b>${esc(p.name)}</b></td>
      <td>${esc(p.version)}</td>
      <td>${(p.hooks || []).map(h => `<span class="tag tag-neutral">${esc(h)}</span>`).join(' ')}</td>
      <td>${p.on_error === 'allow' ? '<span class="tag tag-red">laisse passer</span>' : '<span class="tag tag-green">refuse (503)</span>'}</td>
      <td>${p.signed_by ? `<span class="tag tag-green" title="Clé ${esc(p.signed_by)}">signé</span>` : '<span class="tag tag-neutral">non signé</span>'}</td>
      <td title="${esc(p.sha256)}"><code>${esc((p.sha256 || '').slice(0, 12))}…</code> · ${Math.round((p.size || 0) / 1024)} Kio</td>
      <td>${fmtDate(p.updated_at)}</td>
      <td>${admin ? `<button class="btn btn-ghost btn-sm" onclick="openPluginModal('${esc(p.name)}')">Remplacer</button>
        <button class="btn btn-ghost btn-sm" onclick="deletePlugin('${esc(p.name)}')">${esc(t('common.delete'))}</button>` : ''}</td></tr>`).join('');
    const keyRows = (keys || []).map(k => `<tr><td><b>${esc(k.name)}</b></td><td><code>${esc(k.id)}</code></td>
      <td>${admin ? `<button class="btn btn-ghost btn-sm" onclick="deletePluginKey('${esc(k.id)}')">${esc(t('common.delete'))}</button>` : ''}</td></tr>`).join('');
    content.innerHTML = `
      <div class="card blueprint"><div class="table-wrap"><table>
        <thead><tr><th>Nom</th><th>Version</th><th>Hooks</th><th>En cas d'échec</th><th>Signature</th><th>Module</th><th>Modifié</th><th></th></tr></thead>
        <tbody>${rows || '<tr><td colspan="8" class="empty"><p>Aucun plugin installé</p></td></tr>'}</tbody>
      </table></div></div>
      <p style="font-size:12px;color:var(--text2);margin:10px 0 24px">Un plugin s'attache à une route avec <code>"plugins": [{"name": "…", "config": {…}}]</code>. Un plugin supprimé ou en échec fait refuser le trafic de la route (503). Voir <code>docs/plugins.md</code>.</p>

      <div style="display:flex;align-items:center;justify-content:space-between;margin-bottom:8px">
        <div><b>Clés de confiance</b>
          <div style="font-size:12px;color:var(--text2)">${(keys || []).length
            ? 'Tout plugin installé ou remplacé doit être signé par l\'une de ces clés.'
            : 'Aucune clé : la signature des plugins est facultative. Ajoutez une clé pour l\'exiger.'}</div></div>
        ${admin ? `<button class="btn btn-secondary btn-sm" onclick="openPluginKeyModal()">+ Clé publique</button>` : ''}
      </div>
      <div class="card blueprint"><div class="table-wrap"><table>
        <thead><tr><th>Nom</th><th>Identifiant</th><th></th></tr></thead>
        <tbody>${keyRows || '<tr><td colspan="3" class="empty"><p>Aucune clé de confiance</p></td></tr>'}</tbody>
      </table></div></div>`;
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
  modal(name ? `Remplacer ${name}` : 'Nouveau plugin', `
    <div class="field"><label class="field-label">Manifeste (JSON)</label>
      <textarea id="pl-manifest" class="input" rows="11" style="font-family:monospace">${esc(manifestText)}</textarea></div>
    <div class="field"><label class="field-label">Module (.wasm, 2 Mio au plus)</label>
      <input id="pl-wasm" class="input" type="file" accept=".wasm,application/wasm"></div>
    <div class="field"><label class="field-label">Signature Ed25519 (base64, <code>goproxify plugin sign</code>)</label>
      <textarea id="pl-sig" class="input" rows="2" placeholder="Facultative tant qu'aucune clé de confiance n'est enregistrée"></textarea></div>
    <p style="font-size:12px;color:var(--text2)">Le plugin sera exécuté par toutes les passerelles. N'installez que du code relu.</p>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="savePlugin('${esc(name || '')}')">${t('common.save')}</button>`);
};

window.savePlugin = async function(name) {
  let manifest;
  try { manifest = JSON.parse(document.getElementById('pl-manifest').value); }
  catch (e) { toast('Manifeste JSON invalide : ' + e.message, 'error'); return; }
  const file = document.getElementById('pl-wasm').files[0];
  if (!file) { toast('Sélectionnez le module .wasm', 'error'); return; }
  try {
    const buf = await file.arrayBuffer();
    const payload = { manifest, sha256: await plSha256Hex(buf), wasm: plBytesToBase64(buf) };
    const sig = document.getElementById('pl-sig').value.trim();
    if (sig) payload.signature = sig;
    if (name) await api('PUT', `/plugins/${encodeURIComponent(name)}`, payload);
    else await api('POST', '/plugins', payload);
    toast('Plugin installé et envoyé aux passerelles', 'success');
    closeModal();
    refreshPlugins();
  } catch (e) { toast(e.message, 'error'); }
};

window.deletePlugin = function(name) {
  confirm_(`Supprimer le plugin « ${name} » ? Les routes qui l'utilisent refuseront le trafic (503).`, async () => {
    try { await api('DELETE', `/plugins/${encodeURIComponent(name)}`); toast('Plugin supprimé', 'success'); refreshPlugins(); }
    catch (e) { toast(e.message, 'error'); }
  });
};

window.openPluginKeyModal = function() {
  modal('Clé publique de confiance', `
    <div class="field"><label class="field-label">Nom</label><input id="plk-name" class="input" placeholder="Éditeur du plugin"></div>
    <div class="field"><label class="field-label">Clé publique Ed25519 (base64, 32 octets)</label>
      <input id="plk-key" class="input" placeholder="6yi+zAMz…"></div>
    <p style="font-size:12px;color:var(--text2)">Dès qu'une clé est enregistrée, tout plugin installé ou remplacé doit être signé par l'une des clés de confiance. Les plugins déjà installés restent en place.</p>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="savePluginKey()">${t('common.save')}</button>`);
};

window.savePluginKey = async function() {
  const name = document.getElementById('plk-name').value.trim();
  const public_key = document.getElementById('plk-key').value.trim();
  if (!name || !public_key) { toast('Nom et clé requis', 'error'); return; }
  try {
    await api('POST', '/plugin-keys', { name, public_key });
    toast('Clé enregistrée', 'success');
    closeModal();
    refreshPlugins();
  } catch (e) { toast(e.message, 'error'); }
};

window.deletePluginKey = function(id) {
  confirm_('Retirer cette clé de confiance ? Les plugins déjà installés restent en place.', async () => {
    try { await api('DELETE', `/plugin-keys/${encodeURIComponent(id)}`); toast('Clé retirée', 'success'); refreshPlugins(); }
    catch (e) { toast(e.message, 'error'); }
  });
};
