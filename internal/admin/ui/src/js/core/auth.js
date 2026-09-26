// ── Authentification ───────────────────────────────────────────────────────
let _mfaToken = '';
let _mfaMethod = '';

async function doLogin() {
  const email = document.getElementById('login-email').value;
  const pass  = document.getElementById('login-pass').value;
  try {
    const res = await fetch('/api/v1/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email, password: pass }),
    });
    if (!res.ok) { toast(t('login.bad_creds'), 'error'); return; }
    const data = await res.json();
    if (res.status === 202 && data.mfa_required) {
      _mfaToken = data.mfa_token || '';
      const methods = data.methods || [];
      _mfaMethod = methods.length > 0 ? (methods[0].method || methods[0].type || '') : 'totp';
      const selector = document.getElementById('mfa-method-selector');
      const hint = document.getElementById('mfa-hint');
      if (selector && methods.length > 1) {
        selector.style.display = 'flex';
        selector.innerHTML = methods.map(m => {
          const label = t('mfa.method.' + (m.method||m.type||'')) !== ('mfa.method.' + (m.method||m.type||''))
            ? t('mfa.method.' + (m.method||m.type||''))
            : (m.method||m.type||'');
          return `<button class="btn btn-secondary" style="font-size:12px;" onclick="_selectMFAMethod('${esc(m.method||m.type||'')}',this)">${esc(label)}</button>`;
        }).join('');
      } else if (selector) {
        selector.style.display = 'none';
      }
      if (hint) {
        const hk = 'mfa.hint.' + _mfaMethod;
        hint.textContent = t(hk) !== hk ? t(hk) : t('mfa.hint.default');
      }
      const codeEl = document.getElementById('mfa-code');
      if (codeEl) codeEl.value = '';
      const codeField = codeEl?.closest('.field');
      if (codeField) codeField.style.display = _mfaMethod === 'webauthn' ? 'none' : '';
      document.getElementById('mfa-backdrop').style.display = 'flex';
      if (_mfaMethod === 'webauthn') {
        doWebAuthnLogin();
        return;
      }
      setTimeout(() => codeEl?.focus(), 50);
      return;
    }
    state.token = data.token;
    localStorage.setItem('gpx_token', data.token);
    await afterLogin();
  } catch(e) { toast(e.message, 'error'); }
}

function _selectMFAMethod(method, btn) {
  _mfaMethod = method;
  const selector = document.getElementById('mfa-method-selector');
  if (selector) selector.querySelectorAll('button').forEach(b => b.classList.toggle('btn-primary', b === btn));
  const hint = document.getElementById('mfa-hint');
  if (hint) {
    const hk = 'mfa.hint.' + method;
    hint.textContent = t(hk) !== hk ? t(hk) : t('mfa.hint.default');
  }
  const codeField = document.getElementById('mfa-code')?.closest('.field');
  if (codeField) codeField.style.display = method === 'webauthn' ? 'none' : '';
  if (method === 'webauthn') {
    doWebAuthnLogin();
  }
}

async function doMFAChallenge() {
  if (_mfaMethod === 'webauthn') {
    await doWebAuthnLogin();
    return;
  }
  const code  = document.getElementById('mfa-code')?.value?.trim();
  const trust = document.getElementById('mfa-trust')?.checked || false;
  if (!code) return;
  try {
    const res = await fetch('/api/v1/auth/mfa/challenge', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ mfa_token: _mfaToken, method: _mfaMethod, code, trust_device: trust }),
    });
    if (!res.ok) { toast(t('login.mfa_invalid'), 'error'); return; }
    const data = await res.json();
    document.getElementById('mfa-backdrop').style.display = 'none';
    state.token = data.token;
    localStorage.setItem('gpx_token', data.token);
    await afterLogin();
  } catch(e) { toast(e.message, 'error'); }
}

async function doWebAuthnLogin() {
  if (!window.PublicKeyCredential) {
    toast(t('account.mfa_webauthn_unavailable'), 'error');
    return;
  }
  if (!_mfaToken) {
    toast(t('login.mfa_invalid'), 'error');
    return;
  }
  try {
    const beginRes = await fetch('/api/v1/auth/mfa/webauthn/login/begin', {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json',
        'Authorization': 'Bearer ' + _mfaToken,
      },
      body: JSON.stringify({ mfa_token: _mfaToken }),
    });
    if (!beginRes.ok) { toast(t('login.mfa_invalid'), 'error'); return; }
    const begin = await beginRes.json();
    const options = begin.options || begin;
    const pk = options.publicKey || options;
    const challengeID = begin.challenge_id || '';
    pk.challenge = b64url(pk.challenge);
    if (pk.allowCredentials) {
      pk.allowCredentials = pk.allowCredentials.map(c => ({ ...c, id: b64url(c.id) }));
    }
    const cred = await navigator.credentials.get({ publicKey: pk });
    if (!cred) { toast(t('account.mfa_webauthn_cancelled'), 'info'); return; }
    const trust = document.getElementById('mfa-trust')?.checked || false;
    const finishRes = await fetch('/api/v1/auth/mfa/webauthn/login/finish', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        mfa_token: _mfaToken,
        user_id: begin.user_id,
        challenge_id: challengeID,
        trust_device: trust,
        response: {
          id: cred.id,
          rawId: b64encode(cred.rawId),
          type: cred.type,
          response: {
            authenticatorData: b64encode(cred.response.authenticatorData),
            clientDataJSON: b64encode(cred.response.clientDataJSON),
            signature: b64encode(cred.response.signature),
            userHandle: cred.response.userHandle ? b64encode(cred.response.userHandle) : undefined,
          },
        },
      }),
    });
    if (!finishRes.ok) { toast(t('login.mfa_invalid'), 'error'); return; }
    const data = await finishRes.json();
    document.getElementById('mfa-backdrop').style.display = 'none';
    state.token = data.token;
    localStorage.setItem('gpx_token', data.token);
    await afterLogin();
  } catch(e) { toast(e.message || t('account.mfa_webauthn_error'), 'error'); }
}

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

function showForgotPassword() {
  document.getElementById('forgot-backdrop').style.display = 'flex';
  setTimeout(() => document.getElementById('forgot-email')?.focus(), 50);
}

async function doForgotPassword() {
  const email = document.getElementById('forgot-email')?.value;
  if (!email) return;
  try {
    await fetch('/api/v1/auth/reset-password', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email }),
    });
    toast(t('login.reset_sent'), 'success');
  } catch { toast(t('login.reset_err'), 'error'); }
  document.getElementById('forgot-backdrop').style.display = 'none';
}

function showPairingLogin() {
  document.getElementById('pairing-backdrop').style.display = 'flex';
  setTimeout(() => document.getElementById('pairing-token')?.focus(), 50);
}

async function doPairingLogin() {
  const token = document.getElementById('pairing-token')?.value?.trim();
  if (!token) return;
  state.token = token;
  localStorage.setItem('gpx_token', token);
  document.getElementById('pairing-backdrop').style.display = 'none';
  try { await afterLogin(); } catch {
    toast('Token invalide', 'error');
    state.token = '';
    localStorage.removeItem('gpx_token');
  }
}

function doLogout() {
  localStorage.removeItem('gpx_token');
  state.token = '';
  try {
    document.cookie = '_gpx_device=; path=/; Max-Age=0; SameSite=Lax';
  } catch (_) { /* ignore */ }
  showLogin();
}

function showLogin() {
  document.getElementById('login-page').style.display = 'flex';
  document.getElementById('app').style.display = 'none';
  if (typeof applyStaticI18n === 'function') applyStaticI18n();
}

function showApp() {
  document.getElementById('login-page').style.display = 'none';
  document.getElementById('app').style.display = 'flex';
  initSkin();
  updateThemeLabel();
  api('GET', '/auth/me').then(u => {
    state.user = u;
    updateSidebarUser(u);
    renderNav(u);
  }).catch(() => { state.user = null; renderNav(null); });
}

async function afterLogin() {
  showApp();
  startTopbarClock();
  if (typeof checkNeedOnboarding === 'function' && await checkNeedOnboarding()) {
    onb.step = 0; onb.mode = null; onb.infra = null; onb.token = null;
    onb.withAgent = false; onb.withLanding = false; onb.dnsProvider = 'none';
    onb.backupData = null; onb.backupSummary = null; onb.configProxies = null;
    navigate('onboarding');
    return;
  }
  // Deep-link depuis les pages d'erreur passerelle : /?gpx_page=logs&search=<request-id>&component=edge
  const params = new URLSearchParams(location.search);
  if (params.get('gpx_page') === 'logs') {
    history.replaceState(null, '', location.pathname || '/');
    const search = params.get('search') || '';
    const component = params.get('component') || 'edge';
    const kind = params.get('kind') || 'access';
    if (typeof openLogs === 'function') {
      logsFilters.search = search;
      logsFilters.level = '';
      logsFilters.domain = '';
      logsFilters.ip = '';
      logsFilters.method = '';
      logsFilters.status = '';
      logsFilters.path = '';
      logsFilters.date_from = '';
      logsFilters.date_to = '';
      openLogs({ kind, component, keepFilters: true });
      state.page = 'logs';
      if (window.innerWidth <= 768) closeSidebar();
      syncNavActive('logs');
      const titles = APP_CONFIG.pageTitles || {};
      const pt = document.getElementById('page-title');
      if (pt) pt.textContent = titles.logs || 'Logs';
      return;
    }
    navigate('logs');
    return;
  }
  navigate(pageFromHash() || 'dashboard');
}

function updateSidebarUser(u) {
  if (!u) return;
  const avatarEl = document.getElementById('sidebar-avatar');
  const nameEl   = document.getElementById('sidebar-user-name');
  const roleEl   = document.getElementById('sidebar-user-role');
  const initials = (u.name || u.email || '?').split(/\s+/).map(w => w[0]).join('').toUpperCase().slice(0,2);
  if (avatarEl) avatarEl.textContent = initials;
  if (nameEl)   nameEl.textContent   = u.name || u.email || '—';
  if (roleEl)   roleEl.textContent   = u.role  || '';
}


// ── Helpers ────────────────────────────────────────────────────────────────
function modal(title, bodyHtml, footerHtml, large = false, headerRight = '') {
  closeModal();
  const ov = document.createElement('div');
  ov.className = 'dialog-backdrop';
  ov.id = 'modal-overlay';
  ov.onclick = e => { if (e.target === ov) closeModal(); };
  ov.innerHTML = `
    <div class="dialog blueprint${large?' modal-lg':''}">
      <div class="modal-header" style="padding:20px 24px 16px;display:flex;align-items:center;justify-content:space-between;border-bottom:1px solid var(--border);">
        <span class="dialog-title" style="padding:0;">${title}</span>
        <div style="display:flex;align-items:center;gap:12px;">
          ${headerRight}
          <button class="btn btn-ghost btn-icon" onclick="closeModal()">
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><line x1="18" y1="6" x2="6" y2="18"/><line x1="6" y1="6" x2="18" y2="18"/></svg>
          </button>
        </div>
      </div>
      <div class="dialog-body">${bodyHtml}</div>
      ${footerHtml ? `<div class="dialog-actions">${footerHtml}</div>` : ''}
    </div>`;
  document.body.append(ov);
}
function closeModal() { document.getElementById('modal-overlay')?.remove(); }

document.addEventListener('keydown', e => {
  if (e.key !== 'Escape') return;
  closeModal();
  ['trafic-modal-container','proxies-modal-container','user-modal-container','team-modal-container'].forEach(id => {
    const el = document.getElementById(id);
    if (el) el.innerHTML = '';
  });
});

let _confirmCb = null;
function confirm_(msg, fn) {
  _confirmCb = fn;
  modal(t('common.confirm'), `<p style="margin:0;font-size:13.5px;opacity:.8;">${esc(msg)}</p>`,
    `<button class="btn btn-secondary" onclick="closeModal()">${t('common.cancel')}</button>
     <button class="btn btn-danger" onclick="closeModal();if(_confirmCb){const f=_confirmCb;_confirmCb=null;f();}">${t('common.delete')}</button>`);
}

function fmtDate(iso) {
  if (!iso) return '—';
  const loc = typeof gpxBCP47 === 'function' ? gpxBCP47() : 'en-US';
  const opts = { dateStyle:'short', timeStyle:'short' };
  if (state.timezone) opts.timeZone = state.timezone;
  try {
    return new Date(iso).toLocaleString(loc, opts);
  } catch {
    return new Date(iso).toLocaleString(loc, { dateStyle:'short', timeStyle:'short' });
  }
}

function typeBadge(type) {
  const m = { http:'tag-blue', https:'tag-green', tcp:'tag-orange', udp:'tag-accent' };
  return `<span class="tag ${m[type]||'tag-neutral'}">${esc(String(type||'?').toUpperCase())}</span>`;
}
function statusBadge(ok, declared) {
  if (declared) return '<span class="tag" style="background:var(--bg3);color:var(--text2);opacity:.7;">○ Non connecté</span>';
  return ok
    ? '<span class="tag tag-green">● Actif</span>'
    : '<span class="tag tag-red">● Inactif</span>';
}

// ── PAGE: Dashboard ────────────────────────────────────────────────────────
