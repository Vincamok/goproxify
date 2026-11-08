// ── PAGE: Compte (profil + PAT + WebAuthn)
// Extrait de pages-all.js — phase 4.

// ── PAGE: Mon profil ───────────────────────────────────────────────────────
pages.profile = async function() {
  const content = document.getElementById('content');
  content.innerHTML = '<p style="color:var(--text2)">' + t('common.loading') + '</p>';

  let me = null, mfaData = null;
  try {
    [me, mfaData] = await Promise.all([
      api('GET', '/me').catch(() => null),
      api('GET', '/auth/mfa').catch(() => null),
    ]);
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; return; }

  const email     = me?.email || state.user?.email || '—';
  const role      = me?.role  || state.user?.role  || '—';
  const createdAt = me?.created_at ? fmtDate(me.created_at) : '—';
  const activeSet = new Set((mfaData?.methods || []).filter(m => m.verified).map(m => m.method));
  const backupLeft = mfaData?.backup_codes_left ?? 0;

  content.innerHTML = `
    <div style="margin-bottom:20px">
      <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('profile.title')}</h1>
      <p style="margin:0;opacity:0.65;font-size:14px;">${t('profile.subtitle')} <strong id="profile-email-title">${esc(email)}</strong>.</p>
    </div>

    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(320px,100%),1fr));gap:16px;margin-bottom:28px;">

      <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0;">${t('profile.account')}</h6>
        <div class="field">
          <label for="me-email">${t('profile.email')}</label>
          <input class="input" id="me-email" type="email" value="${esc(email)}">
        </div>
        <div class="field">
          <label>${t('profile.role')}</label>
          <input class="input" value="${esc(role)}" readonly style="opacity:0.6;cursor:default;">
        </div>
        <div class="field">
          <label>${t('profile.created')}</label>
          <input class="input" value="${esc(createdAt)}" readonly style="opacity:0.6;cursor:default;">
        </div>
        <div class="field">
          <label for="me-locale">${t('profile.language')}</label>
          <select class="input" id="me-locale" onchange="profileSetLocale(this.value)">
            <option value="auto"${!gpxHasLocaleOverride() ? ' selected' : ''}>${t('profile.lang_auto')}</option>
            <option value="en"${gpxHasLocaleOverride() && gpxResolveLocale()==='en' ? ' selected' : ''}>${t('lang.en')}</option>
            <option value="fr"${gpxHasLocaleOverride() && gpxResolveLocale()==='fr' ? ' selected' : ''}>${t('lang.fr')}</option>
            <option value="es"${gpxHasLocaleOverride() && gpxResolveLocale()==='es' ? ' selected' : ''}>${t('lang.es')}</option>
            <option value="de"${gpxHasLocaleOverride() && gpxResolveLocale()==='de' ? ' selected' : ''}>${t('lang.de')}</option>
          </select>
          <div style="font-size:11.5px;opacity:.55;margin-top:4px;">${t('profile.language_hint')}</div>
        </div>
        <div id="me-email-msg" style="font-size:12.5px;display:none;"></div>
        <button class="btn btn-primary blueprint" style="align-self:flex-start;" onclick="saveEmail()">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          ${t('common.save')}
        </button>
      </div>

      <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0;">${t('account.password')}</h6>
        <div class="field"><label for="pw-current">${t('account.password_current')}</label><input class="input" id="pw-current" type="password" placeholder="••••••••"></div>
        <div class="field"><label for="pw-new">${t('users.new_password')}</label><input class="input" id="pw-new" type="password" placeholder="••••••••"></div>
        <div class="field"><label for="pw-confirm">${t('account.password_confirm')}</label><input class="input" id="pw-confirm" type="password" placeholder="••••••••"></div>
        <div id="pw-msg" style="font-size:12.5px;display:none;"></div>
        <button class="btn btn-primary blueprint" style="align-self:flex-start;" onclick="savePassword()">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          ${t('account.password_update')}
        </button>
      </div>

      <div class="card blueprint" style="padding:20px;display:flex;flex-direction:column;gap:14px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0;">${t('account.pat_title')}</h6>
        <p style="margin:0;font-size:13px;color:var(--text2);line-height:1.45">
          ${t('account.pat_desc')}
        </p>
        <button class="btn btn-primary blueprint" style="align-self:flex-start;" onclick="navigate('api-tokens')">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          ${t('account.pat_manage')}
        </button>
      </div>
    </div>

    <h6 style="margin:0 0 12px;">${t('account.mfa_title')}</h6>
    <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(280px,100%),1fr));gap:12px;">

      <div class="card blueprint" style="display:flex;flex-direction:column;gap:12px;padding:18px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div>
          <div class="card-title" style="font-size:15px;">${t('account.mfa_totp')}</div>
          <div class="card-meta">${t('account.mfa_totp_meta')}</div>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
          <span class="tag ${activeSet.has('totp') ? 'tag-green' : 'tag-neutral'}">${activeSet.has('totp') ? t('account.mfa_active') : t('account.mfa_not_configured')}</span>
          <div style="display:flex;gap:6px;">
            <button class="btn btn-ghost btn-sm" onclick="setupTOTP()">
              ${activeSet.has('totp') ? t('account.mfa_reconfigure') : t('account.mfa_configure')}
            </button>
            ${activeSet.has('totp') ? `<button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="deleteMFA('totp')">${t('common.delete')}</button>` : ''}
          </div>
        </div>
      </div>

      <div class="card blueprint" style="display:flex;flex-direction:column;gap:12px;padding:18px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div>
          <div class="card-title" style="font-size:15px;">${t('account.mfa_webauthn')}</div>
          <div class="card-meta">${t('account.mfa_webauthn_meta')}</div>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
          <span class="tag ${activeSet.has('webauthn') ? 'tag-green' : 'tag-neutral'}">${activeSet.has('webauthn') ? t('account.mfa_active') : t('account.mfa_not_configured')}</span>
          <div style="display:flex;gap:6px;">
            <button class="btn btn-ghost btn-sm" onclick="setupWebAuthn()">
              ${activeSet.has('webauthn') ? t('account.mfa_reconfigure') : t('account.mfa_register')}
            </button>
            ${activeSet.has('webauthn') ? `<button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="deleteMFA('webauthn')">${t('common.delete')}</button>` : ''}
          </div>
        </div>
      </div>

      <div class="card blueprint" style="display:flex;flex-direction:column;gap:12px;padding:18px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div>
          <div class="card-title" style="font-size:15px;">${t('account.mfa_backup')}</div>
          <div class="card-meta">${t('account.mfa_backup_meta')}</div>
        </div>
        <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
          <span class="tag ${backupLeft > 0 ? 'tag-green' : 'tag-neutral'}" id="backup-tag">
            ${backupLeft > 0 ? t('account.mfa_backup_remaining', { n: backupLeft }) : t('account.mfa_backup_not_generated')}
          </span>
          <div style="display:flex;gap:6px;">
            <button class="btn btn-ghost btn-sm" onclick="generateBackupCodes()">${backupLeft > 0 ? t('account.mfa_regenerate') : t('account.mfa_generate')}</button>
            ${backupLeft > 0 ? `<button class="btn btn-ghost btn-sm" style="color:var(--red)" onclick="deleteMFA('backup')">${t('common.delete')}</button>` : ''}
          </div>
        </div>
      </div>

    </div>

    <div style="margin:28px 0 12px;display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap;">
      <div>
        <h6 style="margin:0 0 4px;">${t('account.trusted_title')}</h6>
        <p style="margin:0;opacity:0.65;font-size:13px;max-width:640px;">${t('account.trusted_meta')}</p>
      </div>
      <button class="btn btn-ghost btn-sm" style="color:var(--red)" id="trusted-revoke-all" onclick="revokeAllTrustedDevices()">${t('account.trusted_revoke_all')}</button>
    </div>
    <div class="card" style="overflow-x:auto" id="trusted-devices"></div>`;

  function renderTrustedDevices(devices) {
    const box = document.getElementById('trusted-devices');
    if (!box) return;
    document.getElementById('trusted-revoke-all').style.display = devices.length ? '' : 'none';
    const now = new Date();
    const rows = devices.map(d => {
      const expired = d.expires_at && new Date(d.expires_at) < now;
      return `<tr>
        <td style="max-width:360px;word-break:break-word">${esc(d.name || '—')}</td>
        <td style="font-size:12px;white-space:nowrap">${esc(fmtDate(d.created_at))}</td>
        <td style="font-size:12px;white-space:nowrap">${expired ? `<span class="tag tag-neutral">${t('account.trusted_expired')}</span>` : esc(fmtDate(d.expires_at))}</td>
        <td style="white-space:nowrap;text-align:right"><button class="btn btn-sm btn-danger" onclick="revokeTrustedDevice('${esc(d.id)}')">${t('account.trusted_revoke')}</button></td>
      </tr>`;
    }).join('') || `<tr><td colspan="4" style="opacity:0.5">${t('account.trusted_empty')}</td></tr>`;
    box.innerHTML = `<table class="table" style="width:100%;table-layout:auto">
      <thead><tr><th>${t('account.trusted_col_name')}</th><th>${t('account.trusted_col_created')}</th><th>${t('account.trusted_col_expires')}</th><th></th></tr></thead>
      <tbody>${rows}</tbody>
    </table>`;
  }

  async function refreshTrustedDevices() {
    renderTrustedDevices(await api('GET', '/auth/mfa/trusted-devices').catch(() => []) || []);
  }
  refreshTrustedDevices();

  window.revokeTrustedDevice = function(id) {
    confirm_(t('account.trusted_revoke_confirm'), async () => {
      try {
        await api('DELETE', `/auth/mfa/trusted-devices/${encodeURIComponent(id)}`);
        toast(t('account.trusted_revoked'), 'success');
        await refreshTrustedDevices();
      } catch(e) { toast(e.message, 'error'); }
    });
  };

  window.revokeAllTrustedDevices = function() {
    confirm_(t('account.trusted_revoke_all_confirm'), async () => {
      try {
        await api('DELETE', '/auth/mfa/trusted-devices');
        toast(t('account.trusted_all_revoked'), 'success');
        await refreshTrustedDevices();
      } catch(e) { toast(e.message, 'error'); }
    });
  };

  window.saveEmail = async function() {
    const el  = document.getElementById('me-email');
    const msg = document.getElementById('me-email-msg');
    msg.style.display = 'none';
    const emailVal = el?.value?.trim();
    if (!emailVal) { msg.textContent = t('account.email_invalid'); msg.style.color = 'var(--red)'; msg.style.display = ''; return; }
    try {
      await api('PATCH', '/me', { email: emailVal });
      msg.textContent = t('account.email_updated'); msg.style.color = 'var(--text2)'; msg.style.display = '';
      document.getElementById('profile-email-title').textContent = emailVal;
      updateSidebarUser({ email: emailVal, role });
    } catch(e) { msg.textContent = e.message; msg.style.color = 'var(--red)'; msg.style.display = ''; }
  };

  window.savePassword = async function() {
    const cur  = document.getElementById('pw-current')?.value;
    const next = document.getElementById('pw-new')?.value;
    const conf = document.getElementById('pw-confirm')?.value;
    const msg  = document.getElementById('pw-msg');
    msg.style.display = 'none';
    if (!cur || !next) { msg.textContent = t('account.password_fill'); msg.style.color='var(--red)'; msg.style.display=''; return; }
    if (next !== conf) { msg.textContent = t('setup.err.match'); msg.style.color='var(--red)'; msg.style.display=''; return; }
    try {
      const res = await api('POST', '/me/change-password', { current_password: cur, new_password: next });
      // Les autres sessions sont révoquées ; celle-ci reçoit un jeton neuf pour rester ouverte.
      if (res && res.token) { state.token = res.token; localStorage.setItem('gpx_token', res.token); }
      msg.textContent = t('account.password_updated'); msg.style.color='var(--text2)'; msg.style.display='';
      document.getElementById('pw-current').value = '';
      document.getElementById('pw-new').value = '';
      document.getElementById('pw-confirm').value = '';
      refreshTrustedDevices();
    } catch(e) { msg.textContent = e.message; msg.style.color='var(--red)'; msg.style.display=''; }
  };

  window.deleteMFA = async function(method) {
    if (!confirm(t('account.mfa_delete_confirm', { method }))) return;
    try {
      await api('DELETE', `/auth/mfa/${method}`);
      toast(t('account.mfa_deleted'), 'success');
      pages.profile();
    } catch(e) { toast(e.message, 'error'); }
  };

  window.setupTOTP = async function() {
    let secret, uri, qrCode;
    try {
      const r = await api('POST', '/auth/mfa/totp/setup');
      secret = r.secret; uri = r.provision_uri; qrCode = r.qr_code;
    } catch(e) { toast(e.message, 'error'); return; }

    const body = `
      <p style="margin:0 0 14px;font-size:13.5px;opacity:0.8;">${t('account.mfa_totp_setup_hint')}</p>
      <div style="display:flex;justify-content:center;margin-bottom:14px;">
        <img src="${esc(qrCode)}" alt="${esc(t('account.mfa_totp_qr_alt'))}" width="256" height="256" style="display:block;background:#fff;padding:8px;">
      </div>
      <div style="margin-bottom:14px;">
        <a href="${esc(uri)}" style="display:inline-block;padding:8px 14px;background:var(--surface2);font-size:13px;word-break:break-all;" target="_blank">
          ${t('account.mfa_totp_open_app')}
        </a>
      </div>
      <div class="field" style="margin-bottom:14px;">
        <label style="font-size:12px;opacity:0.7;">${t('account.mfa_totp_secret')}</label>
        <div style="display:flex;gap:6px;align-items:center;">
          <input class="input" id="totp-secret-display" value="${esc(secret)}" readonly style="font-family:monospace;font-size:13px;letter-spacing:1px;flex:1;">
          <button class="btn btn-ghost btn-sm" onclick="copyText('${esc(secret)}','${esc(t('account.mfa_secret_copied'))}')">${t('account.mfa_copy_secret')}</button>
        </div>
      </div>
      <div class="field">
        <label for="totp-code">${t('account.mfa_totp_code')}</label>
        <input class="input" id="totp-code" type="text" inputmode="numeric" maxlength="6" placeholder="123456" autocomplete="one-time-code">
      </div>
      <div id="totp-msg" style="font-size:12.5px;color:var(--red);display:none;margin-top:8px;"></div>`;

    const footer = `
      <button class="btn btn-ghost" onclick="closeModal()">${t('common.cancel')}</button>
      <button class="btn btn-primary blueprint" onclick="verifyTOTP()">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        ${t('account.mfa_verify_activate')}
      </button>`;
    modal(t('account.mfa_totp_setup_title'), body, footer);
    setTimeout(() => document.getElementById('totp-code')?.focus(), 100);
  };

  window.verifyTOTP = async function() {
    const code = document.getElementById('totp-code')?.value?.trim();
    const msg  = document.getElementById('totp-msg');
    msg.style.display = 'none';
    if (!code || code.length !== 6) { msg.textContent = t('account.mfa_code_6digits'); msg.style.display=''; return; }
    try {
      await api('POST', '/auth/mfa/totp/verify', { code });
      closeModal();
      toast(t('account.mfa_totp_activated'), 'success');
      pages.profile();
    } catch(e) { msg.textContent = e.message || t('account.mfa_invalid_code'); msg.style.display=''; }
  };

  window.setupWebAuthn = async function() {
    if (!window.PublicKeyCredential) {
      toast(t('account.mfa_webauthn_unavailable'), 'error'); return;
    }
    try {
      const { options, challenge_id: challengeID } = await api('POST', '/auth/mfa/webauthn/register/begin');

      const pk = options.publicKey;
      pk.challenge = b64url(pk.challenge);
      pk.user.id   = b64url(pk.user.id);
      if (pk.excludeCredentials) {
        pk.excludeCredentials = pk.excludeCredentials.map(c => ({ ...c, id: b64url(c.id) }));
      }

      const cred = await navigator.credentials.create({ publicKey: pk });
      if (!cred) { toast(t('account.mfa_webauthn_cancelled'), 'info'); return; }

      const resp = {
        id: cred.id, rawId: b64encode(cred.rawId), type: cred.type,
        response: {
          attestationObject: b64encode(cred.response.attestationObject),
          clientDataJSON:    b64encode(cred.response.clientDataJSON),
        },
      };
      await api('POST', `/auth/mfa/webauthn/register/finish?challenge=${encodeURIComponent(challengeID)}`, resp);
      toast(t('account.mfa_webauthn_activated'), 'success');
      pages.profile();
    } catch(e) { toast(e.message || t('account.mfa_webauthn_error'), 'error'); }
  };

  window.generateBackupCodes = async function() {
    const alreadyHas = backupLeft > 0;
    if (alreadyHas && !confirm(t('account.mfa_backup_regen_confirm'))) return;
    try {
      const r = await api('POST', '/auth/mfa/backup-codes/generate');
      const codes = r.codes || [];
      const body = `
        <div style="margin-bottom:12px;">
          <div class="alert alert-warning" style="font-size:13px;">
            ${t('account.mfa_backup_warning')}
          </div>
        </div>
        <div class="gp-cols-2" style="gap:6px;font-family:monospace;font-size:14px;letter-spacing:1px;margin-bottom:14px;">
          ${codes.map(c => `<div style="background:var(--surface2);padding:7px 10px;min-width:0;overflow-wrap:anywhere;">${esc(c)}</div>`).join('')}
        </div>
        <div style="display:flex;gap:8px;flex-wrap:wrap;">
          <button class="btn btn-ghost btn-sm" onclick="copyText('${esc(codes.join('\\n'))}','${esc(t('account.mfa_codes_copied'))}')">${t('account.mfa_backup_copy_all')}</button>
          <button class="btn btn-ghost btn-sm" onclick="window.print()">${t('account.mfa_backup_print')}</button>
        </div>`;
      const footer = `<button class="btn btn-primary blueprint" onclick="closeModal();pages.profile();">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        ${t('account.mfa_backup_saved')}
      </button>`;
      modal(t('account.mfa_backup_title'), body, footer);
    } catch(e) { toast(e.message, 'error'); }
  };
};

// ── PAGE: Mes tokens API (PAT) ─────────────────────────────────────────────
pages['api-tokens'] = async function() {
  const content = document.getElementById('content');
  content.innerHTML = `<p style="color:var(--text2)">${t('common.loading')}</p>`;

  let tokens = [], scopes = [];
  try {
    [tokens, scopes] = await Promise.all([
      api('GET', '/me/tokens').catch(() => []),
      api('GET', '/me/tokens/scopes').catch(() => []),
    ]);
  } catch(e) {
    content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`;
    return;
  }

  const available = (scopes || []).filter(s => s.available)
    .map(s => ({ ...s, tools: s.tools || [], grp: s.id.split(':')[0] }));
  const DAY = 86400000;
  const $ = id => document.getElementById(id);
  const pt = (k, v) => t(`account.pat_${k}`, v);
  const ui = { q: '', f: 'all', aud: 'all', col: 'created', dir: 'desc', sel: new Set(), open: new Set(), last: null };

  const audOf = k => k.audience || 'both';
  const serves = (k, usage) => audOf(k) === 'both' || audOf(k) === usage;
  const stateOf = k => k.revoked ? 'revoked' : (k.expires_at && new Date(k.expires_at) < new Date() ? 'expired' : 'active');
  const activeIds = () => tokens.filter(k => stateOf(k) === 'active').map(k => k.id);
  const inactiveIds = () => tokens.filter(k => stateOf(k) !== 'active').map(k => k.id);
  const FILTERS = {
    all: () => true,
    active: k => stateOf(k) === 'active',
    expired: k => stateOf(k) === 'expired',
    revoked: k => stateOf(k) === 'revoked',
    unused: k => stateOf(k) === 'active' && !k.last_used_at,
    stale: k => stateOf(k) === 'active' && Date.now() - new Date(k.last_used_at || k.created_at) > 90 * DAY,
    expiring: k => stateOf(k) === 'active' && !!k.expires_at && new Date(k.expires_at) - Date.now() < 30 * DAY,
  };
  const SORT = {
    label: k => (k.label || '').toLowerCase(),
    aud: k => audOf(k),
    status: k => ({ active: 0, expired: 1, revoked: 2 })[stateOf(k)],
    expires: k => k.expires_at ? new Date(k.expires_at).getTime() : Infinity,
    used: k => k.last_used_at ? new Date(k.last_used_at).getTime() : -1,
    created: k => new Date(k.created_at).getTime(),
  };

  const chip = (on, label, n, fn) =>
    `<button type="button" class="chip${on ? ' active' : ''}" onclick="${fn}">${label}${n == null ? '' : ` <span style="opacity:.7;font-variant-numeric:tabular-nums">${n}</span>`}</button>`;
  const audTag = a => `<span class="tag ${a === 'mcp' ? 'tag-accent' : a === 'api' ? 'tag-blue' : 'tag-neutral'}">${esc(pt('aud_' + a))}</span>`;

  async function refresh() {
    tokens = await api('GET', '/me/tokens').catch(() => []);
    paint();
  }

  function visible() {
    const words = ui.q.trim().toLowerCase().split(/\s+/).filter(Boolean);
    const list = tokens.filter(k => {
      if (!FILTERS[ui.f](k)) return false;
      if (ui.aud !== 'all' && !serves(k, ui.aud)) return false;
      const hay = [k.label, k.prefix, audOf(k), ...(k.scopes || [])].join(' ').toLowerCase();
      return words.every(w => hay.includes(w));
    });
    const val = SORT[ui.col];
    list.sort((a, b) => {
      const x = val(a), y = val(b);
      const c = x < y ? -1 : x > y ? 1 : 0;
      return ui.dir === 'asc' ? c : -c;
    });
    return list;
  }

  function chipsHTML() {
    const stat = Object.keys(FILTERS).map(f => {
      const n = tokens.filter(FILTERS[f]).length;
      if (f !== 'all' && !n && ui.f !== f) return '';
      return chip(ui.f === f, pt('f_' + f), n, `patFilter('${f}')`);
    }).join('');
    const aud = ['all', 'api', 'mcp'].map(a =>
      chip(ui.aud === a, a === 'all' ? t('account.pat_f_all') : pt('aud_' + a),
        a === 'all' ? tokens.length : tokens.filter(k => serves(k, a)).length, `patAud('${a}')`)).join('');
    return `${stat}<span style="font-size:11px;color:var(--text3);margin-left:8px">${t('account.pat_col_usage')}</span>${aud}`;
  }

  function sortTh(col, label) {
    const on = ui.col === col;
    return `<th onclick="patSort('${col}')" style="cursor:pointer;user-select:none;white-space:nowrap${on ? ';color:var(--accent)' : ''}">${label}${on ? (ui.dir === 'asc' ? ' &uarr;' : ' &darr;') : ''}</th>`;
  }

  function rowHTML(k) {
    const st = stateOf(k);
    const status = st === 'revoked' ? `<span class="tag tag-neutral">${t('account.pat_revoked')}</span>`
      : st === 'expired' ? `<span class="tag tag-neutral">${t('account.pat_expired')}</span>`
      : `<span class="tag tag-green">${t('account.pat_status_active')}</span>`;
    const exp = k.expires_at ? fmtDate(k.expires_at) : t('account.pat_never');
    const used = k.last_used_at ? fmtDate(k.last_used_at) : '—';
    const all = k.scopes || [];
    const open = ui.open.has(k.id);
    const shown = open ? all : all.slice(0, 6);
    const scopeTags = shown.map(s =>
      `<span class="tag tag-neutral" style="font-family:monospace;font-size:10px;font-weight:500;white-space:nowrap">${esc(s)}</span>`).join('');
    const more = all.length > 6
      ? `<button type="button" class="tag tag-neutral" style="cursor:pointer;border:0" data-id="${esc(k.id)}" onclick="patToggleScopes(this.dataset.id)">${open ? '&minus;' : '+' + (all.length - 6)}</button>` : '';
    const sel = ui.sel.has(k.id);
    return `<tr style="${st !== 'active' ? 'opacity:.6;' : ''}${sel ? 'background:color-mix(in srgb,var(--accent) 8%,transparent)' : ''}">
      <td style="width:28px;vertical-align:top"><input type="checkbox" ${sel ? 'checked' : ''} data-id="${esc(k.id)}" onclick="patPick(event,this.dataset.id)" aria-label="${esc(t('account.pat_select_row', { label: k.label }))}"></td>
      <td style="min-width:120px;max-width:180px;vertical-align:top">
        <strong>${esc(k.label)}</strong>
        <div style="font-size:11px;opacity:0.55;font-family:monospace;word-break:break-all">${esc(k.prefix)}</div>
      </td>
      <td style="vertical-align:top;white-space:nowrap">${audTag(audOf(k))}</td>
      <td style="vertical-align:top">
        <div style="display:flex;flex-wrap:wrap;gap:4px;max-width:420px">${scopeTags || '—'}${more}</div>
      </td>
      <td style="white-space:nowrap;vertical-align:top">${status}</td>
      <td style="font-size:12px;white-space:nowrap;vertical-align:top">${esc(exp)}</td>
      <td style="font-size:12px;white-space:nowrap;vertical-align:top">${esc(used)}</td>
      <td style="font-size:12px;white-space:nowrap;vertical-align:top;opacity:.7">${esc(fmtDate(k.created_at))}</td>
      <td style="white-space:nowrap;vertical-align:top">
        ${st === 'active'
          ? `<button class="btn btn-sm btn-danger" data-id="${esc(k.id)}" onclick="revokeApiToken(this.dataset.id)">${t('account.pat_revoke')}</button>`
          : `<button class="btn btn-sm btn-ghost" data-id="${esc(k.id)}" onclick="patDeleteOne(this.dataset.id)">${t('account.pat_delete')}</button>`}
      </td>
    </tr>`;
  }

  function bodyHTML(list) {
    if (!list.length) {
      return `<div class="empty" style="padding:30px 20px"><p>${tokens.length ? t('account.pat_no_match') : t('account.pat_empty')}</p></div>`;
    }
    const selectable = list;
    const allOn = selectable.length > 0 && selectable.every(k => ui.sel.has(k.id));
    return `<table class="table" style="width:100%;table-layout:auto">
      <thead><tr>
        <th style="width:28px"><input type="checkbox" id="pat-all" ${allOn ? 'checked' : ''} ${selectable.length ? '' : 'disabled'} onchange="patPickAll(this.checked)" aria-label="${esc(t('account.pat_select_all'))}"></th>
        ${sortTh('label', t('account.pat_col_label'))}${sortTh('aud', t('account.pat_col_usage'))}<th>${t('account.pat_col_scopes')}</th>${sortTh('status', t('account.pat_col_status'))}${sortTh('expires', t('account.pat_col_expires'))}${sortTh('used', t('account.pat_col_last_used'))}${sortTh('created', t('account.pat_col_created'))}<th></th>
      </tr></thead>
      <tbody>${list.map(rowHTML).join('')}</tbody>
    </table>`;
  }

  function paint() {
    const alive = new Set(tokens.map(k => k.id));
    [...ui.sel].forEach(id => { if (!alive.has(id)) ui.sel.delete(id); });
    const list = visible();
    const selectable = list;
    const toolbar = $('pat-toolbar');
    if (!toolbar) return;
    toolbar.style.display = tokens.length ? '' : 'none';
    $('pat-chips').innerHTML = chipsHTML();

    const pending = selectable.filter(k => !ui.sel.has(k.id)).length;
    const filtered = ui.q || ui.f !== 'all' || ui.aud !== 'all';
    $('pat-count').innerHTML = (list.length === tokens.length
      ? t('account.pat_count_all', { n: tokens.length })
      : t('account.pat_count_some', { shown: list.length, total: tokens.length }))
      + (filtered && pending ? ` <button type="button" class="btn btn-ghost btn-sm" onclick="patPickAll(true)">${t('account.pat_select_matching', { n: pending })}</button>` : '')
      + (inactiveIds().length ? ` <button type="button" class="btn btn-ghost btn-sm" onclick="patPurgeInactive()">${t('account.pat_purge_inactive', { n: inactiveIds().length })}</button>` : '');

    const nActive = [...ui.sel].filter(id => activeIds().includes(id)).length;
    const nInactive = ui.sel.size - nActive;
    $('pat-bulk').innerHTML = ui.sel.size
      ? `<div class="bn-bulk"><b>${t('account.pat_selected', { n: ui.sel.size })}</b>
          <span style="margin-left:auto;display:flex;gap:6px;align-items:center">
            ${nActive ? `<button type="button" class="btn btn-sm btn-danger" onclick="patBulkRevoke()">${t('account.pat_bulk_revoke_n', { n: nActive })}</button>` : ''}
            ${nInactive ? `<button type="button" class="btn btn-sm btn-danger" onclick="patDeleteSelected()">${t('account.pat_bulk_delete_n', { n: nInactive })}</button>` : ''}
            <button type="button" class="btn btn-ghost btn-sm" onclick="patClearSel()">${t('common.cancel')}</button>
          </span></div>`
      : '';

    $('pat-body').innerHTML = bodyHTML(list);
    const all = $('pat-all');
    if (all) {
      const n = selectable.filter(k => ui.sel.has(k.id)).length;
      all.indeterminate = n > 0 && n < selectable.length;
    }
  }

  window.patSearch = v => { ui.q = v; paint(); };
  window.patFilter = f => { ui.f = f; paint(); };
  window.patAud = a => { ui.aud = a; paint(); };
  window.patSort = col => {
    if (ui.col === col) ui.dir = ui.dir === 'asc' ? 'desc' : 'asc';
    else { ui.col = col; ui.dir = ['used', 'created'].includes(col) ? 'desc' : 'asc'; }
    paint();
  };
  window.patToggleScopes = id => { ui.open.has(id) ? ui.open.delete(id) : ui.open.add(id); paint(); };
  window.patPick = (e, id) => {
    const on = e.target.checked;
    const ids = visible().map(k => k.id);
    if (e.shiftKey && ui.last && ids.includes(ui.last) && ids.includes(id)) {
      const a = ids.indexOf(ui.last), b = ids.indexOf(id);
      ids.slice(Math.min(a, b), Math.max(a, b) + 1).forEach(x => on ? ui.sel.add(x) : ui.sel.delete(x));
    } else {
      on ? ui.sel.add(id) : ui.sel.delete(id);
    }
    ui.last = id;
    paint();
  };
  window.patPickAll = on => {
    visible().forEach(k => on ? ui.sel.add(k.id) : ui.sel.delete(k.id));
    paint();
  };
  window.patClearSel = () => { ui.sel.clear(); paint(); };

  window.revokeApiToken = function(id) {
    confirm_(t('account.pat_revoke_confirm'), async () => {
      try {
        await api('DELETE', `/me/tokens/${id}`);
        toast(t('account.pat_revoked_toast'), 'success');
        await refresh();
      } catch(e) { toast(e.message, 'error'); }
    });
  };

  // Révocation (token actif) et suppression définitive (token révoqué ou expiré) : même DELETE, `?purge=1` pour supprimer.
  let batch = { ids: [], purge: false };
  function confirmBatch(ids, purge) {
    if (!ids.length) return;
    batch = { ids, purge };
    modal((purge ? t('account.pat_delete_title') : t('account.pat_bulk_title')),
      `<p style="margin:0;font-size:13.5px;opacity:.8">${esc(purge ? t('account.pat_delete_confirm', { n: ids.length }) : t('account.pat_bulk_confirm', { n: ids.length }))}</p>`,
      `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
       <button class="btn btn-danger" onclick="patBatchGo()">${purge ? t('account.pat_delete') : t('account.pat_revoke')}</button>`);
  }
  window.patBulkRevoke = () => confirmBatch([...ui.sel].filter(id => activeIds().includes(id)), false);
  window.patDeleteSelected = () => confirmBatch([...ui.sel].filter(id => inactiveIds().includes(id)), true);
  window.patDeleteOne = id => confirmBatch([id], true);
  window.patPurgeInactive = () => confirmBatch(inactiveIds(), true);
  window.patBatchGo = async function() {
    closeModal();
    const { ids, purge } = batch;
    const suffix = purge ? '?purge=1' : '';
    let ok = 0, ko = 0;
    for (let i = 0; i < ids.length; i += 5) {
      const res = await Promise.allSettled(ids.slice(i, i + 5).map(id => api('DELETE', `/me/tokens/${id}${suffix}`)));
      res.forEach(r => r.status === 'fulfilled' ? ok++ : ko++);
    }
    ids.forEach(id => ui.sel.delete(id));
    toast(ko ? t('account.pat_bulk_partial', { ok, ko }) : (purge ? t('account.pat_deleted_toast', { n: ok }) : t('account.pat_bulk_done', { n: ok })), ko ? 'error' : 'success');
    await refresh();
  };

  // ── Création : usage (API / MCP), recherche, filtres et sélection de masse des scopes
  const m = { q: '', kind: 'all', aud: 'api', sel: new Set(), open: new Set() };
  const kindOf = id => id.endsWith(':read') ? 'read' : 'write';
  const grpLabel = g => { const k = 'account.pat_grp_' + g; const v = t(k); return v === k ? g : v; };
  const pool = () => m.aud === 'mcp' ? available.filter(s => s.tools.length) : available;
  const hay = s => s._hay || (s._hay = [s.id, s.description, grpLabel(s.grp), ...s.tools].join(' ').toLowerCase());
  const scopeTag = s => {
    if (kindOf(s.id) === 'read') return `<span class="tag tag-neutral">${t('account.pat_k_read')}</span>`;
    if (s.grp === 'gdpr') return `<span class="tag tag-red">${t('account.pat_k_gdpr')}</span>`;
    if (s.id.endsWith(':delete')) return `<span class="tag tag-red">${t('account.pat_k_delete')}</span>`;
    return `<span class="tag tag-yellow">${t('account.pat_k_write')}</span>`;
  };

  function matching() {
    const words = m.q.trim().toLowerCase().split(/\s+/).filter(Boolean);
    return pool().filter(s => {
      if (m.kind === 'read' && kindOf(s.id) !== 'read') return false;
      if (m.kind === 'write' && kindOf(s.id) === 'read') return false;
      if (m.kind === 'selected' && !m.sel.has(s.id)) return false;
      const h = hay(s);
      return words.every(w => h.includes(w));
    });
  }

  function scopeItemHTML(s) {
    const open = m.open.has(s.id);
    const tools = m.aud !== 'api' && s.tools.length;
    return `<div style="padding:6px 10px 6px 28px;border-bottom:1px solid var(--border)">
      <div style="display:flex;align-items:flex-start;gap:8px">
        <label style="display:flex;align-items:flex-start;gap:8px;flex:1;min-width:0;cursor:pointer;font-size:13px">
          <input type="checkbox" data-id="${esc(s.id)}" ${m.sel.has(s.id) ? 'checked' : ''} onchange="patScopeToggle(this.dataset.id,this.checked)" style="margin-top:3px">
          <span style="min-width:0"><code>${esc(s.id)}</code> ${scopeTag(s)}<div style="opacity:.6;font-size:12px">${esc(s.description || '')}</div></span>
        </label>
        ${tools ? `<button type="button" class="btn btn-ghost btn-sm" style="white-space:nowrap" data-id="${esc(s.id)}" onclick="patToolsToggle(this.dataset.id)">${t('account.pat_tools_count', { n: s.tools.length })}</button>` : ''}
      </div>
      ${tools && open ? `<div style="display:flex;flex-wrap:wrap;gap:4px;margin:6px 0 0 24px">${s.tools.map(x => `<span class="tag tag-neutral" style="font-family:monospace;font-size:10px">${esc(x)}</span>`).join('')}</div>` : ''}
    </div>`;
  }

  function paintScopes() {
    const list = matching();
    const pl = pool();
    const nRead = pl.filter(s => kindOf(s.id) === 'read').length;
    $('pat-kinds').innerHTML = [['all', pl.length], ['read', nRead], ['write', pl.length - nRead], ['selected', m.sel.size]]
      .map(([k, n]) => chip(m.kind === k, pt('k_' + k), n, `patKind('${k}')`)).join('');

    const wn = [...m.sel].filter(id => kindOf(id) !== 'read').length;
    $('pat-ssum').textContent = t('account.pat_sel_count', { n: m.sel.size, total: pl.length })
      + (wn ? ' · ' + t('account.pat_write_count', { n: wn }) : '');
    $('pat-sactions').innerHTML = list.length
      ? `<button type="button" class="btn btn-ghost btn-sm" onclick="patSelVisible(true)">${t('account.pat_sel_visible', { n: list.length })}</button>
         <button type="button" class="btn btn-ghost btn-sm" onclick="patSelVisible(false)">${t('account.pat_unsel_visible')}</button>` : '';

    const groups = [];
    list.forEach(s => {
      let g = groups.find(x => x.id === s.grp);
      if (!g) groups.push(g = { id: s.grp, items: [] });
      g.items.push(s);
    });
    const box = $('pat-slist');
    const top = box.scrollTop;
    box.innerHTML = groups.map(g => {
      const on = g.items.filter(s => m.sel.has(s.id)).length;
      return `<div style="position:sticky;top:0;z-index:1;display:flex;align-items:center;gap:8px;padding:6px 10px;background:var(--bg3);border-bottom:1px solid var(--border);font-size:12px;font-weight:600">
        <input type="checkbox" data-grp="${esc(g.id)}" ${on === g.items.length ? 'checked' : ''} onchange="patGroupToggle(this.dataset.grp,this.checked)" aria-label="${esc(grpLabel(g.id))}">
        <span>${esc(grpLabel(g.id))}</span><span style="opacity:.55;font-weight:400">${on}/${g.items.length}</span></div>`
        + g.items.map(scopeItemHTML).join('');
    }).join('') || `<p style="opacity:.6;padding:12px;margin:0">${pl.length ? t('account.pat_no_scope_match') : t('account.pat_no_scopes')}</p>`;
    box.querySelectorAll('input[data-grp]').forEach(cb => {
      const g = groups.find(x => x.id === cb.dataset.grp);
      const on = g.items.filter(s => m.sel.has(s.id)).length;
      cb.indeterminate = on > 0 && on < g.items.length;
    });
    box.scrollTop = top;
  }

  window.patScopeSearch = v => { m.q = v; paintScopes(); };
  window.patKind = k => { m.kind = k; paintScopes(); };
  window.patScopeToggle = (id, on) => { on ? m.sel.add(id) : m.sel.delete(id); paintScopes(); };
  window.patGroupToggle = (g, on) => {
    matching().filter(s => s.grp === g).forEach(s => on ? m.sel.add(s.id) : m.sel.delete(s.id));
    paintScopes();
  };
  window.patSelVisible = on => { matching().forEach(s => on ? m.sel.add(s.id) : m.sel.delete(s.id)); paintScopes(); };
  window.patToolsToggle = id => { m.open.has(id) ? m.open.delete(id) : m.open.add(id); paintScopes(); };
  window.patPreset = p => {
    m.sel.clear();
    pool().forEach(s => { if (p === 'all' || (p === 'read' && kindOf(s.id) === 'read')) m.sel.add(s.id); });
    m.kind = 'all';
    m.q = '';
    const input = $('pat-sq');
    if (input) input.value = '';
    paintScopes();
  };
  window.patAudience = a => {
    m.aud = a;
    const ok = new Set(pool().map(s => s.id));
    [...m.sel].forEach(id => { if (!ok.has(id)) m.sel.delete(id); });
    $('pat-aud-hint').textContent = pt('aud_hint_' + a);
    paintScopes();
  };
  window.patExpiryIn = days => {
    const el = $('pat-expires');
    if (!el) return;
    if (!days) { el.value = ''; return; }
    const d = new Date(Date.now() + days * DAY), p = n => String(n).padStart(2, '0');
    el.value = `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())}T${p(d.getHours())}:${p(d.getMinutes())}`;
  };

  window.createApiTokenModal = function() {
    m.q = ''; m.kind = 'all'; m.aud = 'api'; m.sel.clear(); m.open.clear();
    const audOpts = ['api', 'mcp', 'both'].map(a =>
      `<label class="seg-opt"><input type="radio" name="pat-aud" value="${a}" ${a === m.aud ? 'checked' : ''} onchange="patAudience(this.value)">${esc(pt('aud_' + a))}</label>`).join('');
    const expChips = [[30, t('account.pat_exp_30')], [90, t('account.pat_exp_90')], [365, t('account.pat_exp_365')], [0, t('account.pat_never')]]
      .map(([d, label]) => `<button type="button" class="chip" style="cursor:pointer" onclick="patExpiryIn(${d})">${esc(label)}</button>`).join('');

    const body = `
      <div class="field"><label>${t('account.pat_label')}</label>
        <input class="input" id="pat-label" placeholder="${esc(t('account.pat_label_ph'))}">
      </div>
      <div class="field"><label>${t('account.pat_col_usage')}</label>
        <div class="seg">${audOpts}</div>
        <div id="pat-aud-hint" style="font-size:11px;opacity:0.65;margin-top:6px">${pt('aud_hint_' + m.aud)}</div>
      </div>
      <div class="field"><label>${t('account.pat_expires')}</label>
        <input class="input" id="pat-expires" type="datetime-local">
        <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:6px">${expChips}</div>
        <div style="font-size:11px;opacity:0.55;margin-top:4px">${t('account.pat_expires_hint')}</div>
      </div>
      <div class="field"><label>${t('account.pat_scopes')}</label>
        <div style="display:flex;flex-direction:column;gap:8px">
          <input id="pat-sq" class="input" placeholder="${esc(t('account.pat_scope_search_ph'))}" oninput="patScopeSearch(this.value)">
          <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center">
            <span id="pat-kinds" style="display:inline-flex;gap:6px;flex-wrap:wrap"></span>
            <span style="margin-left:auto;display:inline-flex;gap:6px;flex-wrap:wrap">
              <button type="button" class="btn btn-ghost btn-sm" onclick="patPreset('read')">${t('account.pat_preset_read')}</button>
              <button type="button" class="btn btn-ghost btn-sm" onclick="patPreset('all')">${t('account.pat_preset_all')}</button>
              <button type="button" class="btn btn-ghost btn-sm" onclick="patPreset('none')">${t('account.pat_preset_none')}</button>
            </span>
          </div>
          <div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center;font-size:12px;color:var(--text2)">
            <span id="pat-ssum"></span>
            <span id="pat-sactions" style="margin-left:auto;display:inline-flex;gap:6px"></span>
          </div>
          <div id="pat-slist" style="max-height:320px;overflow:auto;border:1px solid var(--border);border-radius:6px"></div>
        </div>
      </div>`;
    const footer = `<button class="btn btn-primary" onclick="submitApiToken()">${t('common.create')}</button>`;
    modal(t('account.pat_new_modal'), body, footer, true);
    paintScopes();
  };

  window.submitApiToken = async function() {
    const label = document.getElementById('pat-label')?.value?.trim();
    const expEl = document.getElementById('pat-expires')?.value;
    const selected = [...m.sel];
    if (!label) { toast(t('account.pat_label_required'), 'error'); return; }
    if (!selected.length) { toast(t('account.pat_scope_required'), 'error'); return; }
    const payload = { label, audience: m.aud, scopes: selected };
    if (expEl) {
      payload.expires_at = new Date(expEl).toISOString();
    }
    try {
      const res = await api('POST', '/me/tokens', payload);
      closeModal();
      const token = res.token || '';
      window.__lastPatSecret = token;
      const body = `
        <div class="alert alert-warning" style="font-size:13px;margin-bottom:12px">
          ${t('account.pat_copy_warning')}
        </div>
        <div style="font-family:monospace;font-size:13px;word-break:break-all;background:var(--surface2);padding:12px;border-radius:6px;margin-bottom:12px">${esc(token)}</div>
        <button class="btn btn-ghost btn-sm" onclick="copyText(window.__lastPatSecret||'','${esc(t('account.pat_token_copied'))}')">${t('account.pat_copy')}</button>`;
      modal(t('account.pat_created_title'), body, `<button class="btn btn-primary" onclick="closeModal()">${t('account.pat_closed')}</button>`);
      await refresh();
    } catch(e) { toast(e.message, 'error'); }
  };

  content.innerHTML = `
    <div style="margin-bottom:20px;display:flex;align-items:flex-start;justify-content:space-between;gap:12px;flex-wrap:wrap">
      <div>
        <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('account.pat_page_title')}</h1>
        <p style="margin:0;opacity:0.65;font-size:14px;">${t('account.pat_page_sub')}</p>
      </div>
      <button class="btn btn-primary" onclick="createApiTokenModal()">${t('account.pat_new')}</button>
    </div>
    <div class="card blueprint" style="padding:0">
      <div id="pat-toolbar" class="sec-bans-toolbar" style="padding-top:12px">
        <div class="sec-bans-toolbar-row">
          <input id="pat-search" class="input search-input" placeholder="${esc(t('account.pat_search_ph'))}" oninput="patSearch(this.value)" style="max-width:300px">
          <span id="pat-count" class="sec-bans-count" style="margin-left:auto"></span>
        </div>
        <div class="sec-bans-toolbar-row" id="pat-chips"></div>
      </div>
      <div id="pat-bulk"></div>
      <div id="pat-body" style="overflow-x:auto"></div>
    </div>`;
  paint();
};

// ── Helpers WebAuthn base64
function b64url(v) {
  if (typeof v === 'string') {
    const b = atob(v.replace(/-/g,'+').replace(/_/g,'/'));
    const a = new Uint8Array(b.length);
    for (let i=0;i<b.length;i++) a[i]=b.charCodeAt(i);
    return a.buffer;
  }
  return v;
}
function b64encode(buf) {
  const b = new Uint8Array(buf);
  return btoa(String.fromCharCode(...b)).replace(/\+/g,'-').replace(/\//g,'_').replace(/=/g,'');
}


function profileSetLocale(val) {
  if (val === 'auto') gpxClearLocaleOverride();
  else gpxSetLocale(val);
  gpxRefreshUILocale();
}
