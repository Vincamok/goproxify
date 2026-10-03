// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Section « Encrypted Client Hello » du tiroir Paramètres de « Domaines & certificats ».
// ECH chiffre le nom du site (SNI) dans le handshake TLS : un observateur réseau ne voit que
// le nom public ci-dessous. Les clés sont poussées aux passerelles, qui les gardent en local.

window.echLoad = async function () {
  const el = document.getElementById('ech-section');
  if (!el) return;
  const st = await api('GET', '/ech').catch(() => null);
  if (!st) { el.innerHTML = ''; return; }

  const keys = (st.keys || []).map(k => `
    <tr>
      <td style="padding:4px 8px;font-size:11px;font-family:monospace;">${esc(String(k.config_id))}</td>
      <td style="padding:4px 8px;font-size:11px;">${esc(k.public_name)}</td>
      <td style="padding:4px 8px;font-size:11px;opacity:0.7;">${k.retired ? t('ech.key_retired') : t('ech.key_active')}</td>
      <td style="text-align:right;padding:4px 8px;">${k.retired
        ? `<button class="btn btn-ghost" style="padding:2px 6px;font-size:11px;" onclick="echDeleteKey('${esc(k.id)}')">${t('common.delete')}</button>` : ''}</td>
    </tr>`).join('');
  const warn = (st.warnings || []).includes('no_certificate_for_public_name')
    ? `<p style="margin:8px 0 0;font-size:11px;color:var(--warning,#d9a400);">${t('ech.warn_no_cert')}</p>` : '';

  el.innerHTML = `
    <div style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:16px 20px;box-sizing:border-box;">
      <span style="font-size:13px;font-weight:600;">${t('ech.title')}</span>
      <p style="margin:2px 0 12px;font-size:11px;opacity:0.5;">${t('ech.subtitle')}</p>
      <label style="display:flex;align-items:center;gap:8px;font-size:12px;margin-bottom:10px;cursor:pointer;">
        <input type="checkbox" id="ech-enabled" ${st.enabled ? 'checked' : ''}> ${t('ech.enable')}
      </label>
      <div class="field">
        <label>${t('ech.public_name')}</label>
        <input class="input" id="ech-public-name" placeholder="ech.example.com" value="${esc(st.public_name || '')}">
        <div style="font-size:11px;opacity:0.5;margin-top:4px;">${t('ech.public_name_hint')}</div>
      </div>
      <div style="margin-top:10px;"><button class="btn btn-primary btn-sm" onclick="echSave()">${t('common.save')}</button></div>
      ${warn}
      ${st.enabled && st.https_record ? `
        <div style="margin-top:14px;">
          <div style="font-size:11px;font-weight:600;margin-bottom:4px;">${t('ech.dns_record')}</div>
          <div style="font-size:11px;opacity:0.6;margin-bottom:6px;">${t('ech.dns_hint')}</div>
          <textarea class="input" id="ech-record" rows="3" readonly style="font-family:monospace;font-size:11px;">${esc(st.https_record)}</textarea>
          <div style="margin-top:6px;display:flex;gap:6px;">
            <button class="btn btn-ghost btn-sm" onclick="copyText(document.getElementById('ech-record').value)">${t('ech.copy')}</button>
            <button class="btn btn-ghost btn-sm" onclick="echRotate()">${t('ech.rotate')}</button>
          </div>
        </div>
        <table style="width:100%;border-collapse:collapse;margin-top:12px;">
          <thead><tr style="text-align:left;">
            <th style="padding:4px 8px;font-size:10px;opacity:0.5;font-weight:500;">${t('ech.col_id')}</th>
            <th style="padding:4px 8px;font-size:10px;opacity:0.5;font-weight:500;">${t('ech.public_name')}</th>
            <th style="padding:4px 8px;font-size:10px;opacity:0.5;font-weight:500;">${t('ech.col_state')}</th><th></th>
          </tr></thead>
          <tbody>${keys}</tbody>
        </table>` : ''}
    </div>`;
};

window.echSave = async function () {
  const enabled = document.getElementById('ech-enabled').checked;
  const public_name = document.getElementById('ech-public-name').value.trim();
  try {
    await api('PUT', '/ech', { enabled, public_name });
    toast(t('ech.saved'), 'success');
    echLoad();
  } catch (e) {
    toast(e.message || t('ech.error'), 'error');
  }
};

window.echRotate = async function () {
  try {
    await api('POST', '/ech/rotate');
    toast(t('ech.rotated'), 'success');
    echLoad();
  } catch (e) {
    toast(e.message || t('ech.error'), 'error');
  }
};

window.echDeleteKey = async function (id) {
  try {
    await api('DELETE', '/ech/keys/' + encodeURIComponent(id));
    echLoad();
  } catch (e) {
    toast(e.message || t('ech.error'), 'error');
  }
};
