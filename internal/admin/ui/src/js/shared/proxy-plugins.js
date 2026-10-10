// ── Onglet « Plugins » de la sécurité d'une route ──────────────────────────────────────────────────
// Attache des plugins WebAssembly installés (GET /plugins) à une route HTTP, dans l'ordre, avec leur
// configuration. Les champs de configuration viennent du manifeste du plugin (ManifestForm). Textes :
// clés `rtplug.*` de shared/i18n.js (en, fr, es, de).

window._psecPlug = { installed: [], attached: [] }; // attached : [{ name, config }]

function psecPlugManifest(name) {
  return window._psecPlug.installed.find(p => p.name === name);
}

// Relit la configuration saisie dans le DOM vers l'état, avant tout nouveau rendu.
function psecPlugSync() {
  const st = window._psecPlug;
  for (const a of st.attached) {
    const man = psecPlugManifest(a.name);
    if (!man || !document.getElementById('psec-plug-' + a.name)) continue;
    a.config = ManifestForm.collect('pp-' + a.name, man.fields || [], a.config || {}).config;
  }
}

window.psecPluginsInit = function(installed, cfgPlugins) {
  window._psecPlug.installed = Array.isArray(installed) ? installed : [];
  window._psecPlug.attached = (Array.isArray(cfgPlugins) ? cfgPlugins : [])
    .filter(p => p && p.name).map(p => ({ name: p.name, config: p.config || {} }));
  psecPluginsRender();
};

window.psecPluginsRender = function() {
  const host = document.getElementById('psec-plugins-list');
  if (!host) return;
  const st = window._psecPlug;
  const attachedNames = new Set(st.attached.map(a => a.name));
  const hooksTag = hooks => (hooks || []).map(h => `<span class="tag tag-neutral">${esc(h)}</span>`).join(' ');
  const l4Only = man => (man.hooks || []).length > 0 && (man.hooks || []).every(h => h === 'connect');

  const attachedHtml = st.attached.map((a, i) => {
    const man = psecPlugManifest(a.name);
    const head = `<div style="display:flex;align-items:center;gap:8px;justify-content:space-between">
        <div><b>${esc(a.name)}</b>${man ? ` <span style="color:var(--text3);font-size:11px">v${esc(man.version)}</span> ${hooksTag(man.hooks)}` : ''}</div>
        <div style="display:flex;gap:4px">
          <button class="btn btn-ghost btn-sm" ${i === 0 ? 'disabled' : ''} onclick="psecPluginMove('${esc(a.name)}',-1)" title="${esc(t('rtplug.up'))}">↑</button>
          <button class="btn btn-ghost btn-sm" ${i === st.attached.length - 1 ? 'disabled' : ''} onclick="psecPluginMove('${esc(a.name)}',1)" title="${esc(t('rtplug.down'))}">↓</button>
          <button class="btn btn-ghost btn-sm" onclick="psecPluginToggle('${esc(a.name)}',false)">${esc(t('rtplug.detach'))}</button>
        </div></div>`;
    if (!man) {
      return `<div class="card" style="padding:12px 14px;margin-bottom:8px;border-color:var(--red)">${head}
        <div style="font-size:12px;color:var(--red);margin-top:6px">${esc(t('rtplug.missing', { name: a.name }))}</div></div>`;
    }
    const warn = l4Only(man) ? `<div style="font-size:12px;color:var(--yellow,#f59e0b);margin-top:6px">${esc(t('rtplug.l4_only'))}</div>` : '';
    return `<div class="card" id="psec-plug-${esc(a.name)}" style="padding:12px 14px;margin-bottom:8px">${head}${warn}
      <div style="margin-top:8px">${ManifestForm.render('pp-' + a.name, man.fields || [], a.config || {})}</div></div>`;
  }).join('');

  const available = st.installed.filter(p => !attachedNames.has(p.name));
  const availableHtml = available.map(p => `<div style="display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 0;border-bottom:1px solid var(--border)">
      <div><b>${esc(p.name)}</b> <span style="color:var(--text3);font-size:11px">v${esc(p.version)}</span> ${hooksTag(p.hooks)}</div>
      <button class="btn btn-secondary btn-sm" onclick="psecPluginToggle('${esc(p.name)}',true)">${esc(t('rtplug.attach'))}</button></div>`).join('');

  host.innerHTML = `
    <p style="font-size:12px;color:var(--text2);margin:0 0 12px">${esc(t('rtplug.intro'))}</p>
    ${st.attached.length ? `<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin-bottom:8px">${esc(t('rtplug.attached'))}</div>${attachedHtml}` : ''}
    ${available.length ? `<div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);margin:14px 0 4px">${esc(t('rtplug.available'))}</div>${availableHtml}` : ''}
    ${!st.installed.length && !st.attached.length ? `<p style="font-size:12.5px;color:var(--text3)">${esc(t('rtplug.none'))}</p>` : ''}`;
};

window.psecPluginToggle = function(name, on) {
  psecPlugSync();
  const st = window._psecPlug;
  if (on && !st.attached.some(a => a.name === name)) st.attached.push({ name, config: {} });
  if (!on) st.attached = st.attached.filter(a => a.name !== name);
  psecPluginsRender();
  psecPluginsBadge();
};

window.psecPluginMove = function(name, dir) {
  psecPlugSync();
  const list = window._psecPlug.attached;
  const i = list.findIndex(a => a.name === name), j = i + dir;
  if (i < 0 || j < 0 || j >= list.length) return;
  [list[i], list[j]] = [list[j], list[i]];
  psecPluginsRender();
};

// Plugins attachés pour _psecBuildConfig : [{ name, config? }] (config omise si vide).
window.psecGetPlugins = function() {
  psecPlugSync();
  return window._psecPlug.attached.map(a => {
    const out = { name: a.name };
    if (a.config && Object.keys(a.config).length) out.config = a.config;
    return out;
  });
};

window.psecPluginsBadge = function() {
  const el = document.querySelector('#psec-tabs [data-stab="plugins"] .psec-count');
  if (!el) return;
  const n = window._psecPlug.attached.length;
  el.textContent = n || '';
  el.style.display = n ? 'inline-flex' : 'none';
};
