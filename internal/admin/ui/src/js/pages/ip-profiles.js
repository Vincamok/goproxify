// ── PAGE: IP Profiles
// Extrait de pages-all.js — phase 4.

// ── PAGE: IP Profiles ──────────────────────────────────────────────────────

const IPPROF_MODE_KEYS = { deny: 'ipprof.mode.deny', allow: 'ipprof.mode.allow' };
const IPPROF_MODE_BADGE = { deny: 'tag-red', allow: 'tag-green' };
const IPPROF_FORMAT_KEYS = {
  plain: 'ipprof.format.plain',
  'json-aws': 'ipprof.format.json_aws',
  'json-gcp': 'ipprof.format.json_gcp',
  'json-fastly': 'ipprof.format.json_fastly',
  'tsv-dshield': 'ipprof.format.tsv_dshield',
};
const IPPROF_FORMAT_SHORT_KEYS = {
  plain: 'ipprof.format.plain',
  'json-aws': 'ipprof.format.json_aws_short',
  'json-gcp': 'ipprof.format.json_gcp_short',
  'json-fastly': 'ipprof.format.json_fastly_short',
  'tsv-dshield': 'ipprof.format.tsv_dshield',
};

function ipprofFormatLabel(fmt, short) {
  const keys = short ? IPPROF_FORMAT_SHORT_KEYS : IPPROF_FORMAT_KEYS;
  return t(keys[fmt] || fmt);
}

pages['ip-profiles'] = async function() {
  document.getElementById('page-title').textContent = t('ipprof.page_title');
  const content = document.getElementById('content');
  content.innerHTML = `<div style="display:flex;align-items:center;gap:12px;margin-bottom:18px">
    <h2 style="margin:0;flex:1">${t('ipprof.heading')}</h2>
    <button class="btn btn-primary" onclick="ipProfileCreate()">${t('ipprof.new')}</button>
  </div>
  <p style="color:var(--text2);margin-bottom:20px">${t('ipprof.intro')}</p>
  <div id="ip-profiles-list"><div class="spinner"></div></div>`;

  await ipProfilesLoad();
};

let ipprofCache = [];

async function ipProfilesLoad() {
  const box = document.getElementById('ip-profiles-list');
  if (!box) return;
  let profiles;
  try { profiles = await api('GET', '/ip-profiles'); ipprofCache = profiles; } catch(e) { box.innerHTML = `<div class="alert alert-danger">${t('ipprof.error', { msg: e.message })}</div>`; return; }

  if (!profiles.length) {
    box.innerHTML = `<div style="text-align:center;padding:40px;color:var(--text2)">${t('ipprof.empty')}</div>`;
    return;
  }

  box.innerHTML = `<table class="table">
    <thead><tr><th>${t('ipprof.col.name')}</th><th>${t('ipprof.col.type')}</th><th>${t('ipprof.col.mode')}</th><th>${t('ipprof.col.format')}</th><th>${t('ipprof.col.cidrs')}</th><th>${t('ipprof.col.updated')}</th><th>${t('ipprof.col.active')}</th><th></th></tr></thead>
    <tbody>${profiles.map(p => `<tr>
      <td><strong>${esc(p.name)}</strong></td>
      <td><span class="tag tag-neutral">${esc(p.profile_type||'custom')}</span></td>
      <td><span class="tag ${IPPROF_MODE_BADGE[p.mode]||'tag-neutral'}">${t(IPPROF_MODE_KEYS[p.mode]||p.mode)}</span></td>
      <td style="font-size:12px;color:var(--text2)">${(p.feed_urls||[]).length ? esc(ipprofFormatLabel(p.feed_format)) : esc(t('ipprof.source.manual_short'))}</td>
      <td>${(p.cidrs||[]).length.toLocaleString()}</td>
      <td style="font-size:12px;color:var(--text2)">${p.last_updated_at ? new Date(p.last_updated_at).toLocaleString(typeof gpxBCP47==='function'?gpxBCP47():'en-US') : '—'}${p.consecutive_failures ? `<br><span class="tag tag-red" title="${esc(p.last_error||'')}">${esc(t('ipprof.failing', { n: p.consecutive_failures }))}</span>` : ''}</td>
      <td><label class="toggle" title="${esc(t('ipprof.toggle_title'))}">
        <input type="checkbox" ${p.enabled?'checked':''} onchange="ipProfileToggle('${p.id}',this.checked,${JSON.stringify(p).replace(/"/g,'&quot;')})">
        <span class="toggle-slider"></span>
      </label></td>
      <td style="display:flex;gap:6px">
        <button class="btn btn-sm" onclick="ipProfileEdit('${p.id}')" title="${esc(t('common.edit'))}">✎</button>
        ${(p.feed_urls||[]).length ? `<button class="btn btn-sm" onclick="ipProfileRefresh('${p.id}','${esc(p.name)}')" title="${esc(t('ipprof.refresh_title'))}">↻</button>` : ''}
        <button class="btn btn-sm btn-danger" onclick="ipProfileDelete('${p.id}','${esc(p.name)}')">✕</button>
      </td>
    </tr>`).join('')}</tbody>
  </table>`;
}

async function ipProfileRefresh(id, name) {
  try {
    await api('POST', `/ip-profiles/${id}/refresh`);
    toast(t('ipprof.refreshed', { name }), 'success');
    await ipProfilesLoad();
  } catch(e) { toast(e.message, 'error'); }
}

async function ipProfileToggle(id, enabled, profile) {
  try {
    await api('PUT', `/ip-profiles/${id}`, {
      name: profile.name, mode: profile.mode,
      feed_urls: profile.feed_urls, feed_format: profile.feed_format,
      refresh_interval_h: profile.refresh_interval_h, enabled,
    });
  } catch(e) { toast(e.message, 'error'); await ipProfilesLoad(); }
}

async function ipProfileDelete(id, name) {
  if (!confirm(t('ipprof.delete_confirm', { name }))) return;
  await api('DELETE', `/ip-profiles/${id}`);
  toast(t('ipprof.deleted'), 'success');
  await ipProfilesLoad();
}

const IPPROF_PRESETS = {
  bogons: { name: 'Bogons (Team Cymru)', type: 'bogons', mode: 'deny', format: 'plain', interval: 24, url: 'https://www.team-cymru.org/Services/Bogons/fullbogons-ipv4.txt' },
  blocklist_de: { name: 'blocklist.de', type: 'blocklist-de', mode: 'deny', format: 'plain', interval: 12, url: 'https://lists.blocklist.de/lists/all.txt' },
  cins: { name: 'CINS Army', type: 'cins-army', mode: 'deny', format: 'plain', interval: 12, url: 'https://cinsscore.com/list/ci-badguys.txt' },
};

function ipProfileCreate() { ipProfileForm(null); }

function ipProfileEdit(id) {
  const p = ipprofCache.find(x => x.id === id);
  if (p) ipProfileForm(p);
}

// p === null : création ; sinon édition (la source feed/manuelle d'un profil ne change pas).
function ipProfileForm(p) {
  const manual = !!p && !(p.feed_urls || []).length;
  const modal = document.createElement('div');
  modal.className = 'modal-overlay';
  modal.innerHTML = `<div class="modal" style="max-width:520px">
    <h3 style="margin-top:0">${t(p ? 'ipprof.edit_modal' : 'ipprof.new_modal')}</h3>
    <input type="hidden" id="np-id" value="${p ? esc(p.id) : ''}">
    <div class="field"><label>${t('ipprof.name')}</label><input id="np-name" class="input" placeholder="${esc(t('ipprof.name_ph'))}" value="${p ? esc(p.name) : ''}"></div>
    <div class="field"><label>${t('ipprof.mode')}</label>
      <select id="np-mode" class="input">
        <option value="deny">${t('ipprof.mode.deny_opt')}</option>
        <option value="allow"${p && p.mode === 'allow' ? ' selected' : ''}>${t('ipprof.mode.allow_opt')}</option>
      </select>
      <div style="font-size:12px;color:var(--text2);margin-top:4px">${t('ipprof.mode_hint')}</div></div>
    <div class="field"${p ? ' style="display:none"' : ''}><label>${t('ipprof.source')}</label>
      <select id="np-source" class="input" onchange="ipProfileSourceChange()">
        <option value="feed">${t('ipprof.source.feed')}</option>
        <option value="manual"${manual ? ' selected' : ''}>${t('ipprof.source.manual')}</option>
      </select></div>
    <div id="np-feed-box"${manual ? ' style="display:none"' : ''}>
      <div class="field"${p ? ' style="display:none"' : ''}><label>${t('ipprof.preset')}</label>
        <select id="np-preset" class="input" onchange="ipProfilePreset()">
          <option value="">${t('ipprof.preset.none')}</option>
          ${Object.entries(IPPROF_PRESETS).map(([k, x]) => `<option value="${k}">${esc(x.name)}</option>`).join('')}
        </select>
        <div style="font-size:12px;color:var(--text2);margin-top:4px">${t('ipprof.preset_hint')}</div></div>
      <div class="field"><label>${t('ipprof.feed_urls')}</label><textarea id="np-urls" class="input" rows="3" placeholder="https://...">${p ? esc((p.feed_urls || []).join('\n')) : ''}</textarea></div>
      <div class="field"><label>${t('ipprof.format')}</label>
        <select id="np-format" class="input">
          ${[['plain', 'ipprof.format.plain'], ['json-aws', 'ipprof.format.json_aws_short'], ['json-gcp', 'ipprof.format.json_gcp_short'],
             ['json-fastly', 'ipprof.format.json_fastly_short'], ['tsv-dshield', 'ipprof.format.tsv_dshield']]
            .map(([v, k]) => `<option value="${v}"${p && p.feed_format === v ? ' selected' : ''}>${t(k)}</option>`).join('')}
        </select></div>
      <div class="field"><label>${t('ipprof.refresh_interval')}</label>
        <input id="np-interval" class="input" type="number" value="${p ? p.refresh_interval_h || 24 : 24}" min="1"></div>
    </div>
    <div id="np-manual-box"${manual ? '' : ' style="display:none"'}>
      <div class="field"><label>${t('ipprof.cidrs')}</label>
        <textarea id="np-cidrs" class="input mono" rows="5" placeholder="203.0.113.0/24&#10;198.51.100.7">${p && manual ? esc((p.cidrs || []).join('\n')) : ''}</textarea>
        <div style="font-size:12px;color:var(--text2);margin-top:4px">${t('ipprof.cidrs_hint')}</div></div>
    </div>
    <div style="display:flex;gap:8px;justify-content:flex-end;margin-top:16px">
      <button class="btn" onclick="this.closest('.modal-overlay').remove()">${t('common.cancel')}</button>
      <button class="btn btn-primary" onclick="ipProfileSave(this)">${t(p ? 'common.save' : 'common.create')}</button>
    </div>
  </div>`;
  document.body.appendChild(modal);
}

function ipProfileSourceChange() {
  const manual = document.getElementById('np-source').value === 'manual';
  document.getElementById('np-feed-box').style.display = manual ? 'none' : '';
  document.getElementById('np-manual-box').style.display = manual ? '' : 'none';
}

function ipProfilePreset() {
  const p = IPPROF_PRESETS[document.getElementById('np-preset').value];
  if (!p) return;
  const name = document.getElementById('np-name');
  if (!name.value.trim()) name.value = p.name;
  document.getElementById('np-mode').value = p.mode;
  document.getElementById('np-urls').value = p.url;
  document.getElementById('np-format').value = p.format;
  document.getElementById('np-interval').value = p.interval;
}

async function ipProfileSave(btn) {
  const lines = id => document.getElementById(id).value.split('\n').map(u => u.trim()).filter(Boolean);
  const id = document.getElementById('np-id').value;
  const manual = document.getElementById('np-source').value === 'manual';
  const body = {
    name: document.getElementById('np-name').value.trim(),
    mode: document.getElementById('np-mode').value,
    enabled: true,
  };
  if (manual) {
    body.cidrs = lines('np-cidrs');
    body.feed_urls = [];
  } else {
    body.feed_urls = lines('np-urls');
    body.feed_format = document.getElementById('np-format').value;
    body.refresh_interval_h = parseInt(document.getElementById('np-interval').value) || 24;
  }
  if (!(manual ? body.cidrs : body.feed_urls).length) { toast(t('ipprof.err.need_source'), 'error'); return; }
  try {
    if (id) {
      body.enabled = ipprofCache.find(x => x.id === id)?.enabled ?? true;
      await api('PUT', `/ip-profiles/${id}`, body);
      if (!manual) await api('POST', `/ip-profiles/${id}/refresh`).catch(e => toast(e.message, 'error'));
      toast(t('ipprof.updated'), 'success');
    } else {
      body.profile_type = manual ? 'custom' : (IPPROF_PRESETS[document.getElementById('np-preset').value]?.type || 'custom');
      await api('POST', '/ip-profiles', body);
      toast(t('ipprof.created'), 'success');
    }
    btn.closest('.modal-overlay').remove();
    await ipProfilesLoad();
  } catch(e) { toast(e.message, 'error'); }
}
