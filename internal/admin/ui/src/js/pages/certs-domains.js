// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Page « Domaines & certificats » : vue unique des certificats publics (ACME, importés)
// et locaux (CA interne), avec les actions en bout de ligne. Les réglages ACME,
// les fournisseurs DNS et les CA internes vivent dans le tiroir « Paramètres ».
// Les modales et formulaires sont dans acme-monitor.js, domains.js et internal-ca.js.

let _dcTimer = null;
const _dc = { rows: [], cas: [], filter: 'all', q: '' };

const DC_ICONS = {
  renew:    '<polyline points="23 4 23 10 17 10"/><polyline points="1 20 1 14 7 14"/><path d="M3.51 9a9 9 0 0 1 14.85-3.36L23 10M1 14l4.64 4.36A9 9 0 0 0 20.49 15"/>',
  deploy:   '<polyline points="16 16 12 12 8 16"/><line x1="12" y1="12" x2="12" y2="21"/><path d="M20.39 18.39A5 5 0 0 0 18 9h-1.26A8 8 0 1 0 3 16.3"/>',
  details:  '<path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/>',
  edit:     '<path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/>',
  copy:     '<rect x="9" y="9" width="13" height="13" rx="2"/><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"/>',
  download: '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/>',
  upload:   '<path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="17 8 12 3 7 8"/><line x1="12" y1="3" x2="12" y2="15"/>',
  shield:   '<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>',
  trash:    '<polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/>',
  ban:      '<circle cx="12" cy="12" r="10"/><line x1="4.93" y1="4.93" x2="19.07" y2="19.07"/>',
  globe:    '<circle cx="12" cy="12" r="10"/><line x1="2" y1="12" x2="22" y2="12"/><path d="M12 2a15.3 15.3 0 0 1 4 10 15.3 15.3 0 0 1-4 10 15.3 15.3 0 0 1-4-10 15.3 15.3 0 0 1 4-10z"/>',
  home:     '<path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/>',
};

function dcIcon(name, size = 15) {
  return `<svg width="${size}" height="${size}" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">${DC_ICONS[name]}</svg>`;
}

pages['acme-monitor'] = async function () {
  if (_dcTimer) { clearInterval(_dcTimer); _dcTimer = null; }
  const root = document.getElementById('content');
  root.innerHTML = `
    <div id="dc-root" class="dc-page">
      <div style="margin-bottom:16px;">
        <h2 style="margin:0;font-size:20px;">${t('acme_monitor.title')}</h2>
        <p style="margin:4px 0 0;font-size:13px;opacity:0.55;">${t('dc.subtitle')}</p>
      </div>
      <div id="dc-kpis" class="dc-kpis"></div>
      <div class="dc-toolbar">
        <div id="dc-filters" class="dc-filters"></div>
        <input id="dc-search" placeholder="${esc(t('dc.search'))}" class="input dc-search" oninput="dcSetQuery(this.value)">
        <span style="flex:1"></span>
        <button class="btn btn-ghost btn-sm" onclick="openImportCertModal()">${dcIcon('upload', 13)} ${t('dc.import')}</button>
        <button class="btn btn-ghost btn-sm" onclick="dcOpenSettings()">${t('dc.settings')}</button>
        <button class="btn btn-primary btn-sm" onclick="dcOpenWizard()">+ ${t('dc.add')}</button>
      </div>
      <div id="dc-list" class="card blueprint"></div>
    </div>
    <div id="dc-drawer" class="sent-drawer" aria-hidden="true">
      <div class="sent-drawer-head" style="display:flex;align-items:center;justify-content:space-between;">
        <b style="font-size:14px;">${t('dc.settings')}</b>
        <button class="btn btn-ghost btn-icon btn-sm" aria-label="${esc(t('common.close'))}" onclick="dcCloseSettings()"><svg width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M12 4 4 12M4 4l8 8"/></svg></button>
      </div>
      <div class="sent-drawer-body" style="display:flex;flex-direction:column;gap:16px;padding-top:16px;">
        <div id="acme-config-section"></div>
        <div id="acme-providers-section"></div>
        <div id="acme-internal-ca-section"></div>
      </div>
    </div>`;
  await Promise.all([acmeConfigLoad(), acmeProvidersLoad(), acmeInternalCALoad(), acmeMonitorLoad()]);
  _dcTimer = setInterval(acmeMonitorLoad, 60_000);
  const obs = new MutationObserver(() => {
    if (!document.getElementById('dc-root')) {
      clearInterval(_dcTimer); _dcTimer = null; obs.disconnect();
    }
  });
  obs.observe(root, { childList: true });
};

document.addEventListener('keydown', e => { if (e.key === 'Escape') window.dcCloseSettings?.(); });

window.dcOpenSettings = function () {
  const d = document.getElementById('dc-drawer');
  if (!d) return;
  d.classList.add('open');
  d.setAttribute('aria-hidden', 'false');
};

window.dcCloseSettings = function () {
  const d = document.getElementById('dc-drawer');
  if (!d) return;
  d.classList.remove('open');
  d.setAttribute('aria-hidden', 'true');
};

function dcDaysLeft(iso) {
  return Math.ceil((new Date(iso).getTime() - Date.now()) / 86400000);
}

function dcStatusOf(days) {
  return days < 0 ? 'expired' : days <= 7 ? 'critical' : days <= 30 ? 'warning' : 'ok';
}

function dcFmtDate(iso) {
  return new Date(iso).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
}

window.acmeMonitorLoad = async function () {
  const list = document.getElementById('dc-list');
  if (!list) return;
  const [mon, cas] = await Promise.all([
    api('GET', '/certs/acme-monitor').catch(() => null),
    api('GET', '/internal-ca').catch(() => []),
  ]);
  if (!document.getElementById('dc-list')) return;
  if (!mon) {
    list.innerHTML = `<p style="opacity:0.5;text-align:center;padding:40px 0;">${t('acme_monitor.load_error')}</p>`;
    return;
  }
  _dc.cas = cas || [];
  const localLists = await Promise.all(_dc.cas.map(ca =>
    api('GET', `/internal-ca/${ca.id}/certs`).catch(() => []).then(l => (l || []).map(c => ({ c, ca })))));

  const rows = [];
  for (const c of mon.certs) {
    const imported = c.issuer === 'custom' || c.cert_method === 'manual';
    const prov = c.dns_provider && c.dns_provider !== 'none' ? `DNS-01 ${PROVIDER_LABELS[c.dns_provider] || c.dns_provider}` : 'HTTP-01';
    rows.push({
      kind: imported ? 'import' : 'public', domain: c.domain, cert: c,
      days: c.days_left, status: c.status,
      sub: imported ? `${t('dc.imported')} · ${dcFmtDate(c.expires_at)}` : `${c.issuer} · ${prov} · ${dcFmtDate(c.expires_at)}`,
    });
  }
  for (const { c, ca } of localLists.flat()) {
    const days = dcDaysLeft(c.not_after);
    rows.push({
      kind: 'local', domain: c.common_name, cert: c, ca,
      days, status: c.revoked ? 'revoked' : dcStatusOf(days),
      sub: `${ca.name} · ${c.usage} · ${dcFmtDate(c.not_after)}`,
    });
  }
  _dc.rows = rows;
  dcRender();
};

function dcRender() {
  const count = { total: 0, ok: 0, warning: 0, critical: 0, expired: 0 };
  for (const r of _dc.rows) {
    if (r.status === 'revoked') continue;
    count.total++;
    count[r.status]++;
  }
  const kpis = [
    [t('acme_monitor.kpi_total'), count.total, 'var(--text)'],
    [t('acme_monitor.kpi_ok'), count.ok, '#22c55e'],
    [t('acme_monitor.kpi_warning'), count.warning, '#f59e0b'],
    [t('acme_monitor.kpi_critical'), count.critical, '#ef4444'],
    [t('acme_monitor.kpi_expired'), count.expired, '#6b7280'],
  ];
  document.getElementById('dc-kpis').innerHTML = kpis.map(([l, v, col]) =>
    `<div class="dc-kpi"><b style="color:${col}">${v}</b>${l}</div>`).join('');

  const nPublic = _dc.rows.filter(r => r.kind !== 'local').length;
  const nLocal = _dc.rows.length - nPublic;
  const filters = [['all', t('dc.filter_all'), _dc.rows.length], ['public', t('dc.filter_public'), nPublic], ['local', t('dc.filter_local'), nLocal]];
  document.getElementById('dc-filters').innerHTML = filters.map(([id, label, n]) =>
    `<button class="btn btn-sm ${_dc.filter === id ? 'btn-primary' : 'btn-ghost'}" onclick="dcSetFilter('${id}')">${label} · ${n}</button>`).join('');

  const q = _dc.q.trim().toLowerCase();
  const visible = _dc.rows.map((r, i) => [r, i]).filter(([r]) =>
    (_dc.filter === 'all' || (_dc.filter === 'local') === (r.kind === 'local')) &&
    (!q || r.domain.toLowerCase().includes(q)));

  document.getElementById('dc-list').innerHTML = visible.length
    ? visible.map(([r, i]) => dcRowHTML(r, i)).join('')
    : `<p style="opacity:0.5;text-align:center;padding:40px 0;">${t('acme_monitor.no_certs')}</p>`;
}

function dcRowHTML(r, i) {
  const local = r.kind === 'local';
  const badge = r.status === 'revoked'
    ? `<span class="dc-pill" style="background:#fee2e2;color:#991b1b;">${t('internal_ca.revoked')}</span>`
    : statusBadge(r.status, r.days);
  const kindTag = local ? `<span class="dc-pill" style="background:color-mix(in srgb,var(--accent) 14%,transparent);color:var(--accent);">${t('dc.tag_local')}</span>` : '';
  const btn = (act, icon, title, extra = '') =>
    `<button class="btn btn-ghost btn-icon btn-sm dc-act ${extra}" title="${esc(title)}" aria-label="${esc(title)}" onclick="dcAct('${act}',${i})">${dcIcon(icon)}</button>`;
  const spacer = `<span class="dc-act" aria-hidden="true"></span>`;

  const renew = r.kind === 'import' ? btn('replace', 'upload', t('dc.replace')) : btn('renew', 'renew', local ? t('dc.reissue') : t('acme_monitor.renew'));
  const second = local ? btn('caroot', 'shield', t('dc.download_ca')) : btn('deploy', 'deploy', t('acme_monitor.deploy'));
  const edit = !local && r.cert.domain_id ? btn('edit', 'edit', t('acme_monitor.edit')) : spacer;
  const del = local
    ? (r.cert.revoked ? spacer : btn('delete', 'ban', t('internal_ca.revoke'), 'dc-danger'))
    : btn('delete', 'trash', t('acme_monitor.delete'), 'dc-danger');

  return `<div class="dc-row">
    <span style="color:${local ? 'var(--accent)' : 'var(--text2)'};display:flex">${dcIcon(local ? 'home' : r.kind === 'import' ? 'upload' : 'globe', 18)}</span>
    <div class="dc-name"><b>${esc(r.domain)}</b><span>${esc(r.sub)}</span></div>
    ${kindTag}${badge}
    <div class="dc-actions">
      ${renew}${second}${btn('details', 'details', t('dc.details'))}${edit}${btn('copy', 'copy', t('dc.copy'))}${btn('download', 'download', t('dc.download'))}${del}
    </div>
  </div>`;
}

window.dcSetFilter = function (f) { _dc.filter = f; dcRender(); };
window.dcSetQuery = function (q) { _dc.q = q; dcRender(); };

async function dcGetPEM(r) {
  if (r.kind === 'local') return r.cert.cert_pem;
  const res = await fetch('/api/v1/certs/' + encodeURIComponent(r.domain) + '/pem', {
    headers: { 'Authorization': 'Bearer ' + state.token },
  });
  if (!res.ok) throw new Error(await res.text().catch(() => res.statusText));
  return res.text();
}

function dcSaveFile(name, text) {
  const url = URL.createObjectURL(new Blob([text], { type: 'application/x-pem-file' }));
  const a = document.createElement('a');
  a.href = url; a.download = name;
  document.body.appendChild(a); a.click(); a.remove();
  URL.revokeObjectURL(url);
}

const dcFileBase = s => s.replace(/^\*\./, 'wildcard.').replace(/[^a-zA-Z0-9._-]/g, '_');

window.dcAct = async function (act, i) {
  const r = _dc.rows[i];
  if (!r) return;
  try {
    switch (act) {
      case 'renew':
        if (r.kind === 'local') await dcReissue(r); else acmeRenew(r.domain);
        break;
      case 'replace': openImportCertModal(); break;
      case 'deploy': openCertDeployPanel(r.cert.id, r.domain); break;
      case 'caroot': dcDownloadCARoot(r.ca.id); break;
      case 'details': dcDetails(r); break;
      case 'edit': openDomainModal(r.cert.domain_id); break;
      case 'copy': copyText(await dcGetPEM(r), t('dc.copied')); break;
      case 'download': dcSaveFile(dcFileBase(r.domain) + '.pem', await dcGetPEM(r)); break;
      case 'delete':
        if (r.kind === 'local') revokeInternalCert(r.ca.id, r.cert.id); else acmeDeleteCert(r.domain);
        break;
    }
  } catch (e) {
    toast(e.message || t('common.error'), 'error');
  }
};

async function dcReissue(r) {
  await api('POST', `/internal-ca/${r.ca.id}/certs`, {
    common_name: r.cert.common_name, sans: r.cert.sans || [], usage: r.cert.usage, validity_days: 397,
  });
  toast(t('dc.reissued'), 'success');
  acmeMonitorLoad();
}

window.dcDownloadCARoot = function (caId) {
  const ca = _dc.cas.find(c => c.id === caId);
  if (!ca?.cert_pem) { toast(t('common.error'), 'error'); return; }
  dcSaveFile(dcFileBase(ca.name) + '-root.pem', ca.cert_pem);
};

function dcDetails(r) {
  const c = r.cert;
  const fields = r.kind === 'local'
    ? [[t('acme_monitor.col_status'), r.status === 'revoked' ? t('internal_ca.revoked') : statusBadge(r.status, r.days)],
       [t('dc.authority'), esc(r.ca.name)], ['SAN', esc((c.sans || []).join(', ') || '—')],
       [t('internal_ca.cert_usage'), esc(c.usage)], ['Serial', `<code>${esc(c.serial)}</code>`],
       [t('acme_monitor.col_expires'), dcFmtDate(c.not_after)]]
    : [[t('acme_monitor.col_status'), statusBadge(r.status, r.days)],
       [t('acme_monitor.col_issuer'), esc(c.issuer)],
       [t('acme_monitor.col_provider'), esc(PROVIDER_LABELS[c.dns_provider] || c.dns_provider || 'HTTP-01')],
       [t('acme_monitor.col_expires'), dcFmtDate(c.expires_at)],
       [t('acme_monitor.col_renewed'), dcFmtDate(c.updated_at)]];
  modal(r.domain, `<div style="display:flex;flex-direction:column;gap:8px;font-size:13px;">${fields.map(([k, v]) =>
    `<div style="display:flex;justify-content:space-between;gap:12px;padding:8px 12px;background:var(--bg2);border-radius:8px;"><span style="opacity:0.6;">${k}</span><span style="text-align:right;word-break:break-all;">${v}</span></div>`).join('')}</div>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.close')}</button>`);
}

// ── Assistant d'ajout ────────────────────────────────────────────────────────

window.dcOpenWizard = function () {
  const card = (act, icon, title, desc) => `
    <button type="button" class="dc-card" onclick="${act}">
      <span style="color:var(--accent)">${dcIcon(icon, 22)}</span>
      <b>${title}</b><span>${desc}</span>
    </button>`;
  modal(t('dc.wizard_title'), `
    <div class="dc-cards">
      ${card('dcWizardPick(\'public\')', 'globe', t('dc.type_public'), t('dc.type_public_desc'))}
      ${card('dcWizardPick(\'local\')', 'home', t('dc.type_local'), t('dc.type_local_desc'))}
      ${card('dcWizardPick(\'import\')', 'upload', t('dc.type_import'), t('dc.type_import_desc'))}
    </div>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>`);
};

window.dcWizardPick = function (type) {
  closeModal();
  if (type === 'public') openDomainModal();
  else if (type === 'import') openImportCertModal();
  else dcOpenLocalModal();
};

window.dcOpenLocalModal = function () {
  if (!_dc.cas.length) {
    toast(t('dc.no_ca'), 'info');
    dcOpenSettings();
    openInternalCAModal();
    return;
  }
  modal(t('dc.local_title'), `
    <div style="display:flex;flex-direction:column;gap:14px;">
      <div class="field">
        <label class="field-label">${t('dc.authority')}</label>
        <select class="input" id="dcl-ca">${_dc.cas.map(ca => `<option value="${esc(ca.id)}">${esc(ca.name)}</option>`).join('')}</select>
      </div>
      <div class="field">
        <label class="field-label">${t('internal_ca.cert_common_name')}</label>
        <input class="input" id="dcl-cn" placeholder="nas.home.lan">
      </div>
      <div class="field">
        <label class="field-label">${t('internal_ca.cert_sans')} <span style="opacity:0.5;font-size:11px;">(${t('common.optional')})</span></label>
        <input class="input" id="dcl-sans" placeholder="*.home.lan, 192.168.1.10">
      </div>
      <div class="field">
        <label class="field-label">${t('internal_ca.cert_validity_days')}</label>
        <input class="input" id="dcl-days" type="number" min="1" max="3650" value="397">
      </div>
      <div style="display:flex;align-items:center;gap:10px;padding:10px 12px;background:var(--bg2);border-radius:8px;font-size:12px;">
        <span style="flex:1;opacity:0.75;">${t('dc.install_hint')}</span>
        <button type="button" class="btn btn-ghost btn-sm" onclick="dcDownloadCARoot(document.getElementById('dcl-ca').value)">${dcIcon('shield', 13)} ${t('dc.download_ca')}</button>
      </div>
    </div>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-primary" onclick="dcSubmitLocal()">${t('internal_ca.issue_submit')}</button>`);
};

window.dcSubmitLocal = async function () {
  const caId = document.getElementById('dcl-ca')?.value;
  const common_name = document.getElementById('dcl-cn')?.value.trim() || '';
  const sansRaw = document.getElementById('dcl-sans')?.value.trim() || '';
  const validity_days = parseInt(document.getElementById('dcl-days')?.value, 10) || 397;
  if (!common_name) { toast(t('internal_ca.err_cn_required'), 'error'); return; }
  const sans = sansRaw ? sansRaw.split(',').map(s => s.trim()).filter(Boolean) : [];
  try {
    await api('POST', `/internal-ca/${caId}/certs`, { common_name, sans, usage: 'server', validity_days });
    closeModal();
    toast(t('internal_ca.issued'), 'success');
    acmeMonitorLoad();
  } catch (e) {
    toast(e.message || t('common.error'), 'error');
  }
};
