// ── PAGE: Users & Teams
// Grants = (type, value, access_mode read|write) sur user et/ou team.

pages.users = async function() {
  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = '';
  await refreshUsers(content);
};

async function refreshUsers(content) {
  content = content || document.getElementById('content');
  try {
    const [users, teams] = await Promise.all([
      api('GET', '/users').catch(() => []),
      api('GET', '/teams').catch(() => []),
    ]);
    const list = users || [];
    const teamList = teams || [];

    function roleTag(r) {
      if (r === 'admin' || r === 'superadmin') return 'tag-accent';
      return 'tag-neutral';
    }
    // Membre de l'équipe DPO (ou d'une équipe qui porte une capacité RGPD) : badge « DPO ».
    const revealBadge = u => (u.effective_permissions || []).length && u.role !== 'superadmin'
      ? ` <span class="tag tag-outline" style="font-size:10px;" title="${esc(t('users.reveal_badge_title'))}">${esc(t('users.reveal_badge'))}</span>` : '';
    const canDeleteUser = u => u.role !== 'superadmin' && (Role.isSuperAdmin() || !(u.effective_permissions || []).length);
    const teamHasCaps = team => (team.permissions || []).length > 0;
    const teamBadge = team => team.builtin
      ? ` <span class="tag tag-outline" style="font-size:10px;">${esc(t('users.team_builtin'))}</span>`
      : (teamHasCaps(team) ? ` <span class="tag tag-outline" style="font-size:10px;">${esc(t('users.team_caps'))}</span>` : '');
    const canDeleteTeam = team => !team.builtin && (!teamHasCaps(team) || Role.isSuperAdmin());
    function teamNames(u) {
      return u.team_names || '—';
    }

    content.innerHTML = `
      <div style="display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;margin-bottom:20px">
        <div>
          <h1 style="margin:0 0 4px;font-size:28px;font-family:var(--font-heading);font-weight:600;">${t('users.title')}</h1>
          <p style="margin:0;opacity:0.65;font-size:14px;">${t('users.subtitle')}</p>
        </div>
        <button class="btn btn-primary blueprint" onclick="openUserModal()">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
          ${t('users.new')}
        </button>
      </div>

      <div class="card blueprint" style="padding:18px 20px;margin-bottom:16px;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <h6 style="margin:0 0 8px;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('users.model')}</h6>
        <p style="margin:0 0 12px;font-size:12.5px;line-height:1.55;opacity:0.75;">${t('users.model_p1')}</p>
        <h6 style="margin:0 0 10px;font-size:11px;text-transform:uppercase;letter-spacing:0.09em;opacity:0.5;">${t('users.platform_role')}</h6>
        <table class="table">
          <thead><tr><th>${t('users.col.role')}</th><th>${t('users.col.users_tokens')}</th><th>${t('users.col.proxies')}</th></tr></thead>
          <tbody>
            <tr>
              <td><span class="tag tag-accent">admin</span></td>
              <td>${t('users.yes')}</td>
              <td>${t('users.admin_proxies')}</td>
            </tr>
            <tr>
              <td><span class="tag tag-neutral">user</span></td>
              <td>${t('users.no')}</td>
              <td>${t('users.user_proxies')}</td>
            </tr>
          </tbody>
        </table>
        <p style="margin:10px 0 0;font-size:11.5px;opacity:0.5;line-height:1.45;">${t('users.team_inherit')}</p>
        <p style="margin:6px 0 0;font-size:11.5px;opacity:0.5;line-height:1.45;">${esc(t('users.reveal_note'))}</p>
      </div>

      <div style="display:flex;flex-direction:column;gap:10px;margin-bottom:24px;">
        <h6 style="margin:0;">${t('users.accounts')}</h6>
        <div class="card blueprint" style="overflow:hidden;">
          <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
          <div class="table-wrap">
          <table class="table">
            <thead><tr><th>${t('users.col.email')}</th><th>${t('users.col.role')}</th><th>${t('users.col.teams')}</th><th>${t('users.col.created')}</th><th></th></tr></thead>
            <tbody>
              ${list.length ? list.map(u => `<tr>
                <td style="font-weight:500;font-family:monospace;font-size:13px;">${esc(u.email)}</td>
                <td><span class="tag ${roleTag(u.role)}">${esc(u.role||'user')}</span>${revealBadge(u)}</td>
                <td style="opacity:0.7;font-size:12px;">${esc(teamNames(u))}</td>
                <td style="opacity:0.6;font-size:12px;">${fmtDate(u.created_at)}</td>
                <td style="text-align:right;"><div style="display:inline-flex;gap:6px;">
                  <button class="btn btn-ghost btn-icon" onclick="openUserModal('${esc(u.id)}')" title="${esc(t('common.edit'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
                  ${!canDeleteUser(u)?'':`<button class="btn btn-ghost btn-icon" onclick="deleteUser('${esc(u.id)}')" title="${esc(t('common.delete'))}"><svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg></button>`}
                </div></td>
              </tr>`).join('') : `<tr><td colspan="5" class="empty"><p>${t('users.empty')}</p></td></tr>`}
            </tbody>
          </table>
          </div>
        </div>
      </div>

      <div style="display:flex;flex-direction:column;gap:10px;">
        <div style="display:flex;align-items:center;justify-content:space-between;gap:12px;">
          <div>
            <h6 style="margin:0 0 2px;">${t('users.teams_title')}</h6>
            <p style="margin:0;font-size:12px;opacity:0.55;">${t('users.teams_sub')}</p>
          </div>
          <button class="btn btn-secondary blueprint" onclick="openTeamModal()">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            <svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><line x1="12" y1="5" x2="12" y2="19"/><line x1="5" y1="12" x2="19" y2="12"/></svg>
            ${t('users.new_team')}
          </button>
        </div>
        <div style="display:grid;grid-template-columns:repeat(auto-fill,minmax(min(260px,100%),1fr));gap:12px;" id="teams-grid">
          ${teamList.length ? teamList.map(team => `
          <div class="card blueprint" style="display:flex;flex-direction:column;gap:0;padding:0;overflow:hidden;">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;padding:14px 16px 12px;">
              <div class="card-title" style="font-size:14px;font-weight:600;">${esc(team.name)}${teamBadge(team)}</div>
              <div style="display:inline-flex;gap:4px;flex-shrink:0;">
                <button class="btn btn-ghost btn-icon" onclick="openTeamModal('${esc(team.id)}')" title="${esc(t('common.edit'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg></button>
                ${!canDeleteTeam(team) ? '' : `<button class="btn btn-ghost btn-icon" onclick="deleteTeam('${esc(team.id)}')" title="${esc(t('common.delete'))}"><svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.5"><path d="M3 6h18"/><path d="M8 6V4a2 2 0 0 1 2-2h4a2 2 0 0 1 2 2v2"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/></svg></button>`}
              </div>
            </div>
            <div style="display:flex;gap:0;border-top:1px solid var(--border);">
              <div style="flex:1;display:flex;flex-direction:column;align-items:center;padding:10px 8px;gap:2px;border-right:1px solid var(--border);">
                <span style="font-size:18px;font-weight:700;line-height:1;">${team.member_count||0}</span>
                <span style="font-size:10px;opacity:0.5;text-transform:uppercase;letter-spacing:0.07em;">${(team.member_count||0)!==1?t('users.members_lbl'):t('users.member_lbl')}</span>
              </div>
              <div style="flex:1;display:flex;flex-direction:column;align-items:center;padding:10px 8px;gap:2px;">
                <span style="font-size:18px;font-weight:700;line-height:1;">${team.access_count||0}</span>
                <span style="font-size:10px;opacity:0.5;text-transform:uppercase;letter-spacing:0.07em;">${(team.access_count||0)!==1?t('users.accesses_lbl'):t('users.access_lbl')}</span>
              </div>
            </div>
          </div>`).join('') : `
          <div class="card blueprint" style="padding:28px;text-align:center;grid-column:1/-1;">
            <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
            <p style="margin:0;opacity:0.6;font-size:13px;line-height:1.5;">${t('users.no_team_html')}</p>
          </div>`}
        </div>
      </div>
`;
  } catch(e) { content.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`; }
}

// Capacités qu'une équipe peut porter (rbac.KnownPermissions) : elles ne portent sur aucune ressource.
const TEAM_CAPS = ['gdpr:reveal', 'gdpr:export', 'gdpr:erase', 'gdpr:hold'];
function teamCapLabel(p) {
  return {
    'gdpr:reveal': t('users.cap_reveal'), 'gdpr:export': t('users.cap_export'),
    'gdpr:erase': t('users.cap_erase'), 'gdpr:hold': t('users.cap_hold'),
  }[p] || p;
}

// Équipe intégrée (DPO) : en lecture seule. Elle ne se renomme ni ne se supprime, ne porte aucun accès et ses capacités
// sont fixes ; sa composition se règle depuis la fiche du compte, par le superadmin.
function openBuiltinTeamModal(team) {
  document.getElementById('team-modal-backdrop')?.remove();
  document.body.insertAdjacentHTML('beforeend', `
    <div id="team-modal-backdrop" class="dialog-backdrop" style="background:rgba(0,0,0,0.55);">
      <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(520px,96vw);max-width:none;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="dialog-title">${esc(team.name)} <span class="tag tag-outline" style="font-size:10px;">${esc(t('users.team_builtin'))}</span></div>
        <div class="dialog-body" style="display:flex;flex-direction:column;gap:14px;">
          <p style="margin:0;font-size:12.5px;line-height:1.5;opacity:0.8;">${esc(t('users.team_builtin_hint'))}</p>
          <div style="display:flex;flex-direction:column;gap:6px;">
            <label style="font-size:13px;font-weight:500;">${t('users.team_caps')}</label>
            ${(team.permissions || []).map(p => `<div style="font-size:13px;padding:6px 10px;border:1px solid var(--border);border-radius:6px;">${esc(teamCapLabel(p))}</div>`).join('')}
          </div>
        </div>
        <div class="dialog-actions">
          <button class="btn btn-secondary blueprint" onclick="document.getElementById('team-modal-backdrop').remove()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('common.close')}</button>
        </div>
      </div>
    </div>`);
}

window.openUserModal = async function(id) {
  let u = null;
  let access = null;
  let teams = [];
  try {
    if (id) u = await api('GET', `/users/${id}`);
    if (id) access = await api('GET', `/users/${id}/access`).catch(() => null);
    window._rightsCatalogCache = await rightsCatalog().catch(() => null);
    teams = await api('GET', '/teams').catch(() => []) || [];
  } catch {}
  const userTeams = u?.teams || [];
  window._userOrigTeams = userTeams;
  let role = u?.role || 'user';
  if (role === 'operator' || role === 'viewer' || role === 'dpo') role = 'user';
  const isSuper = role === 'superadmin';
  // Les capacités RGPD s'obtiennent en entrant dans l'équipe DPO : seul le superadmin compose une équipe qui en porte,
  // et un compte qui en détient (ou le superadmin) n'est modifiable que par lui (rbac.IsProtectedAccount).
  const actorSuper = Role.isSuperAdmin();
  const locked = !actorSuper && (isSuper || (u?.effective_permissions || []).length > 0);
  const roleOpt = (value, desc) => `
              <label style="display:flex;align-items:flex-start;gap:10px;cursor:pointer;font-size:13px;padding:8px 10px;border:1px solid var(--border);border-radius:6px;${role===value?'border-color:var(--accent);background:var(--accent-alpha,rgba(58,134,255,0.06));':''}">
                <input type="radio" name="um-role" value="${value}" ${role===value?'checked':''} style="margin-top:2px;">
                <div><strong>${value}</strong> — ${desc}</div>
              </label>`;

  const roleField = isSuper
    ? `<div class="field"><label>${t('users.platform_role')}</label>
        <div style="padding:8px 10px;border:1px solid var(--border);border-radius:6px;font-size:13px;">
          <span class="tag tag-accent">superadmin</span>
          <span style="margin-left:8px;opacity:0.6;font-size:12px;">${t('users.role_protected')}</span>
        </div>
      </div>`
    : `<div class="field"><label>${t('users.platform_role')}</label>
            <div style="display:flex;flex-direction:column;gap:6px;margin-top:2px;">
              ${roleOpt('admin', t('users.role_admin_desc'))}
              ${roleOpt('user', t('users.role_user_desc'))}
            </div>
          </div>`;

  // Accès effectif : lecture seule, calculé par le serveur (rbac.EffectiveAccess) avec l'origine de chaque droit.
  const rowStyle = 'display:flex;align-items:center;gap:8px;font-size:12.5px;padding:6px 10px;border:1px solid var(--border);';
  const grantRows = !access ? '' : access.global
    ? `<div style="${rowStyle}">${esc(t('users.access_global'))}</div>`
    : ((access.teams || []).some(tm => (tm.accesses || []).length)
      ? access.teams.flatMap(tm => (tm.accesses || []).map(a => `<div style="${rowStyle}flex-direction:column;align-items:flex-start;">
          <div style="font-size:12.5px;font-weight:600;">${esc(a.name || t('users.access_unnamed'))} <span style="font-size:11px;font-weight:400;opacity:0.55;">${esc(t('users.access_via', { teams: tm.name }))}</span></div>
          ${typeof accessSummaryHtml === 'function' ? accessSummaryHtml(a, window._rightsCatalogCache) : ''}
        </div>`)).join('')
      : `<span style="font-size:12px;opacity:0.55;">${esc(t('users.access_none'))}</span>`);
  const capRows = (access?.permissions || []).map(p => {
    const via = [];
    if (p.via_role) via.push(t('users.access_via_role', { role: p.via_role }));
    if ((p.via_teams || []).length) via.push(t('users.access_via', { teams: p.via_teams.join(', ') }));
    return `<div style="${rowStyle}"><span style="flex:1;">${esc(teamCapLabel(p.permission))}</span><span style="font-size:11px;opacity:0.55;">${esc(via.join(' · '))}</span></div>`;
  }).join('');
  const accessField = !access ? '' : `<div class="field"><label>${t('users.access_effective')}</label>
            <div style="display:flex;flex-direction:column;gap:4px;margin-top:4px;">
              ${grantRows}
              ${capRows ? `<div style="font-size:11px;text-transform:uppercase;letter-spacing:0.07em;opacity:0.5;margin-top:6px;">${esc(t('users.access_caps'))}</div>${capRows}` : ''}
            </div>
          </div>`;

  document.getElementById('user-modal-backdrop')?.remove();
  document.body.insertAdjacentHTML('beforeend', `
    <div id="user-modal-backdrop" class="dialog-backdrop" style="background:rgba(0,0,0,0.55);">
      <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(560px,96vw);max-width:none;max-height:92vh;overflow:auto;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="dialog-title">${id ? t('users.edit_user') : t('users.new_user')}</div>
        <div class="dialog-body" style="display:flex;flex-direction:column;gap:16px;">
          ${locked ? `<p style="margin:0;padding:8px 10px;border:1px solid var(--border);border-radius:6px;font-size:12.5px;">${esc(t('users.protected_note'))}</p>` : ''}
          <div class="field"><label>${t('users.col.email')}</label><input class="input" id="u-email" type="email" placeholder="alice@corp.io" value="${esc(u?.email||'')}"></div>
          <div class="field"><label>${id ? (t('users.new_password') + ' <span style="opacity:0.5;font-weight:400;">' + t('users.pass_unchanged') + '</span>') : t('users.password')}</label><input class="input" id="u-pass" type="password" placeholder="••••••••" autocomplete="new-password"></div>
          ${roleField}
          ${teams.length ? `<div class="field"><label>${t('users.col.teams')}</label>
            <div style="display:flex;flex-direction:column;gap:6px;margin-top:2px;">
              ${teams.map(team => {
                const checked = !!userTeams.find(ut => ut.team_id === team.id);
                const caps = (team.permissions || []).length > 0;
                const off = caps && !actorSuper;
                const badge = team.builtin ? t('users.team_builtin') : (caps ? t('users.team_caps') : '');
                return `<label style="display:flex;align-items:center;gap:10px;padding:8px 10px;border:1px solid var(--border);border-radius:6px;cursor:${off ? 'not-allowed' : 'pointer'};font-size:13px;${off ? 'opacity:0.55;' : ''}">
                  <input type="checkbox" name="um-team" value="${esc(team.id)}" ${checked?'checked':''} ${off ? 'disabled' : ''} style="flex-shrink:0;">
                  <span style="flex:1;font-weight:500;">${esc(team.name)}${badge ? ` <span class="tag tag-outline" style="font-size:10px;">${esc(badge)}</span>` : ''}</span>
                  <span style="font-size:11px;opacity:0.45;">${team.access_count||0} ${(team.access_count||0)!==1?t('users.accesses_lbl'):t('users.access_lbl')}</span>
                </label>`;
              }).join('')}
            </div>
            <p style="margin:6px 0 0;font-size:11px;opacity:0.55;">${t('users.team_inherit_modal')}</p>
          </div>` : ''}
          ${accessField}
        </div>
        <div class="dialog-actions">
          <button class="btn btn-secondary blueprint" onclick="document.getElementById('user-modal-backdrop').remove()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('common.cancel')}</button>
          ${locked ? '' : `<button class="btn btn-primary blueprint" onclick="saveUser('${esc(id||'')}', ${isSuper})"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${id ? t('common.save') : t('common.create')}</button>`}
        </div>
      </div>
    </div>`);
};

window.saveUser = async function(id, isSuper) {
  const payload = {
    email: document.getElementById('u-email').value.trim(),
    role: isSuper ? 'admin' : (document.querySelector('input[name="um-role"]:checked')?.value || 'user'),
    password: document.getElementById('u-pass').value,
  };
  // Le backend ignore le rôle demandé pour un superadmin ; on envoie quand même un rôle valide.
  if (!payload.password && id) delete payload.password;
  try {
    let uid = id;
    if (id) {
      await api('PUT', `/users/${id}`, payload);
    } else {
      const created = await api('POST', '/users', payload);
      uid = created.id;
    }

    // Équipes : une case désactivée (équipe portant un droit, hors superadmin) n'est pas touchée.
    const failed = [];
    const teamName = tid => document.querySelector(`input[name="um-team"][value="${tid}"]`)?.closest('label')?.querySelector('span')?.textContent?.trim() || tid;
    const origIds = new Set((window._userOrigTeams || []).map(o => o.team_id));
    for (const cb of document.querySelectorAll('input[name="um-team"]:not(:disabled)')) {
      if (cb.checked === origIds.has(cb.value)) continue;
      try {
        if (cb.checked) await api('POST', `/teams/${cb.value}/members`, { user_id: uid });
        else await api('DELETE', `/teams/${cb.value}/members/${uid}`);
      } catch { failed.push(teamName(cb.value)); }
    }
    if (failed.length) toast(t('users.member_errors', { teams: failed.join(', ') }), 'error');

    toast(t('users.saved'), 'success');
    document.getElementById('user-modal-backdrop')?.remove();
    refreshUsers();
  } catch(e) { toast(e.message, 'error'); }
};

window.deleteUser = function(id) {
  confirm_(t('users.delete_confirm'), async () => {
    try { await api('DELETE', `/users/${id}`); toast(t('users.deleted'),'success'); refreshUsers(); }
    catch(e) { toast(e.message,'error'); }
  });
};

window.openTeamModal = async function(id) {
  let team = null;
  if (id) { try { team = await api('GET', `/teams/${id}`); } catch {} }
  if (team?.builtin) { openBuiltinTeamModal(team); return; }
  const teamCaps = team?.permissions || [];
  window._teamCapsOrig = [...teamCaps];
  const actorSuper = Role.isSuperAdmin();

  document.getElementById('team-modal-backdrop')?.remove();
  document.body.insertAdjacentHTML('beforeend', `
    <div id="team-modal-backdrop" class="dialog-backdrop" style="background:rgba(0,0,0,0.55);">
      <div class="dialog blueprint" role="dialog" aria-modal="true" style="width:min(560px,96vw);max-width:none;max-height:92vh;overflow:auto;">
        <i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>
        <div class="dialog-title">${id ? t('users.edit_team') : t('users.new_team')}</div>
        <div class="dialog-body" style="display:flex;flex-direction:column;gap:14px;">
          <div class="field"><label>${t('users.team_name')}</label><input class="input" id="tm-name" placeholder="Backend" value="${esc(team?.name||'')}"></div>
          <div style="display:flex;flex-direction:column;gap:6px;">
            <label style="font-size:13px;font-weight:500;">${t('users.team_caps')}</label>
            <p style="margin:0;font-size:11px;opacity:0.55;">${esc(t('users.team_caps_hint'))}</p>
            ${TEAM_CAPS.map(p => `<label style="display:flex;align-items:center;gap:10px;font-size:13px;padding:6px 10px;border:1px solid var(--border);border-radius:6px;cursor:${actorSuper ? 'pointer' : 'not-allowed'};${actorSuper ? '' : 'opacity:0.55;'}">
              <input type="checkbox" name="tm-cap" value="${p}" ${teamCaps.includes(p) ? 'checked' : ''} ${actorSuper ? '' : 'disabled'}>
              <span>${esc(teamCapLabel(p))}</span>
            </label>`).join('')}
          </div>
          <div style="display:flex;flex-direction:column;gap:8px;">
            <div style="display:flex;align-items:center;justify-content:space-between;gap:8px;">
              <label style="font-size:13px;font-weight:500;">${t('users.accesses_title')}</label>
              ${id ? `<button type="button" class="btn btn-secondary" onclick="openAccessModal('${esc(id)}')">${esc(t('users.access_add'))}</button>` : ''}
            </div>
            <p style="margin:0;font-size:11px;opacity:0.55;">${esc(t('users.accesses_hint'))}</p>
            <div id="tm-accesses" style="display:flex;flex-direction:column;gap:6px;"></div>
          </div>
        </div>
        <div class="dialog-actions">
          <button class="btn btn-secondary blueprint" onclick="document.getElementById('team-modal-backdrop').remove()"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${t('common.cancel')}</button>
          <button class="btn btn-primary blueprint" onclick="saveTeam('${esc(id||'')}')"><i class="corner tl"></i><i class="corner tr"></i><i class="corner bl"></i><i class="corner br"></i>${id ? t('common.save') : t('common.create')}</button>
        </div>
      </div>
    </div>`);
  renderTeamAccesses(id);
};

window.saveTeam = async function(id) {
  const name = document.getElementById('tm-name').value.trim();
  if (!name) { toast(t('users.name_required'), 'error'); return; }
  try {
    let tid = id;
    if (id) {
      await api('PUT', `/teams/${id}`, { name });
    } else {
      const created = await api('POST', '/teams', { name });
      tid = created.id;
    }

    const caps = [...document.querySelectorAll('input[name="tm-cap"]:checked')].map(cb => cb.value);
    const origCaps = window._teamCapsOrig || [];
    if (Role.isSuperAdmin() && (caps.length !== origCaps.length || caps.some(p => !origCaps.includes(p)))) {
      await api('PUT', `/teams/${tid}/permissions`, { permissions: caps });
    }

    toast(t('users.team_saved'), 'success');
    document.getElementById('team-modal-backdrop')?.remove();
    refreshUsers();
    // Les accès d'une équipe se composent une fois l'équipe créée : on rouvre la fenêtre pour les ajouter.
    if (!id) openTeamModal(tid);
  } catch(e) { toast(e.message, 'error'); }
};

window.deleteTeam = function(id) {
  confirm_(t('users.team_delete_confirm'), async () => {
    try { await api('DELETE', `/teams/${id}`); toast(t('users.team_deleted'),'success'); refreshUsers(); }
    catch(e) { toast(e.message,'error'); }
  });
};
