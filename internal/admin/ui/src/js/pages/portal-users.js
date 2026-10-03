// ── PAGE PARTAGÉE: Users et groupes du portail Access (Admin + Passerelle)
async function renderPortalUsersPage(ctx) {
  const mode = ctx.mode || 'admin';
  const isAdmin = mode === 'admin';
  const edge = isAdmin ? null : state.selectedEdge;
  const edgeName = edge?.node_name || '';
  const edgeLabel = edge ? (edge.display_name || edgeName || '—') : '';

  const content = document.getElementById('content');
  document.getElementById('topbar-actions').innerHTML = '';
  content.innerHTML = `<div style="display:flex;align-items:center;gap:10px;color:var(--text2);padding:32px 0">
    <svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="animation:spin 1s linear infinite"><path d="M12 2v4M12 18v4M4.93 4.93l2.83 2.83M16.24 16.24l2.83 2.83M2 12h4M18 12h4M4.93 19.07l2.83-2.83M16.24 7.76l2.83-2.83"/></svg>
    ${esc(t('common.loading') || 'Chargement…')}
  </div>`;

  if (!isAdmin && !edgeName) {
    content.innerHTML = `<div class="empty"><p>${esc(t('portal.need_edge') || 'Sélectionnez une passerelle')}</p></div>`;
    return;
  }

  try {
    const path = isAdmin ? '/portal/users' : '/portal/users?edge=' + encodeURIComponent(edgeName);
    const [usersRes, nodesRes] = await Promise.all([
      api('GET', path).catch(() => ({ users: [] })),
      isAdmin ? api('GET', '/nodes').catch(() => []) : Promise.resolve([]),
    ]);
    let users = usersRes.users || [];
    if (!Array.isArray(users)) users = [];
    const edges = (nodesRes || []).filter(n => n.role === 'edge');

    // Groupes : une requête par passerelle (les groupes sont propres à la passerelle ou à son groupe HA).
    const groupEdges = isAdmin ? edges.map(n => n.node_name || n.id) : [edgeName];
    const groupRes = await Promise.all(groupEdges.map(e => api('GET', '/portal/groups?edge=' + encodeURIComponent(e)).catch(() => ({ groups: [] }))));
    const seen = new Set();
    const groups = [];
    groupRes.forEach(r => (r.groups || []).forEach(g => { if (!seen.has(g.id)) { seen.add(g.id); groups.push(g); } }));

    window._portalUsersAll = users;
    window._portalGroupsAll = groups;
    window._portalUsersEdges = edges;
    if (!window._puFilter) window._puFilter = { edge: '', status: '', q: '' };
    if (!window._puTab) window._puTab = 'users';

    const groupsOf = (scope) => (window._portalGroupsAll || []).filter(g => g.edge_name === scope);
    const groupName = (id) => (window._portalGroupsAll || []).find(g => g.id === id)?.name || id;
    const edgeLabelOf = (scope) => {
      const n = edges.find(e => (e.node_name || e.id) === scope);
      return n ? (n.display_name || n.node_name || n.id) : scope;
    };
    const edgeOptions = (selected) => edges.map(c => {
      const nn = c.node_name || c.id;
      return `<option value="${esc(nn)}" ${nn === selected ? 'selected' : ''}>${esc(c.display_name || nn)}</option>`;
    }).join('');

    const filtered = () => {
      const f = window._puFilter;
      return (window._portalUsersAll || []).filter(u => {
        if (f.edge && u.home_edge !== f.edge) return false;
        if (f.status && u.status !== f.status) return false;
        if (f.q) {
          const hay = [u.email, u.home_edge, ...(u.tags || []), ...(u.groups || []).map(groupName)].join(' ').toLowerCase();
          if (!hay.includes(f.q.toLowerCase())) return false;
        }
        return true;
      });
    };
    const filteredGroups = () => {
      const f = window._puFilter;
      return (window._portalGroupsAll || []).filter(g => {
        if (f.edge && g.edge_name !== f.edge) return false;
        if (f.q && !(g.name + ' ' + (g.description || '') + ' ' + (g.members || []).join(' ')).toLowerCase().includes(f.q.toLowerCase())) return false;
        return true;
      });
    };

    const statusBadge = (st) => {
      const colors = { active: 'var(--accent)', invited: 'var(--warn, #b45309)', disabled: 'var(--text2)' };
      const c = colors[st] || 'var(--text2)';
      return `<span class="badge" style="border:1px solid ${c};color:${c};font-size:11px;padding:2px 8px;border-radius:999px">${esc(st)}</span>`;
    };
    const ICON = {
      edit: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M11 4H4a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h14a2 2 0 0 0 2-2v-7"/><path d="M18.5 2.5a2.121 2.121 0 0 1 3 3L12 15l-4 1 1-4 9.5-9.5z"/></svg>',
      mail: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><path d="M4 4h16c1.1 0 2 .9 2 2v12c0 1.1-.9 2-2 2H4c-1.1 0-2-.9-2-2V6c0-1.1.9-2 2-2z"/><polyline points="22,6 12,13 2,6"/></svg>',
      del: '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2"><polyline points="3 6 5 6 21 6"/><path d="M19 6l-1 14a2 2 0 0 1-2 2H8a2 2 0 0 1-2-2L5 6"/><path d="M10 11v6"/><path d="M14 11v6"/><path d="M9 6V4a1 1 0 0 1 1-1h4a1 1 0 0 1 1 1v2"/></svg>',
    };
    const iconBtn = (attr, id, title, svg, danger) => `<button type="button" class="btn btn-ghost btn-icon btn-sm" ${attr}="${esc(id)}" title="${esc(title)}"${danger ? ' style="color:var(--danger,#c45c5c)"' : ''}>${svg}</button>`;

    const render = () => {
      const tab = window._puTab;
      document.getElementById('topbar-actions').innerHTML = tab === 'groups'
        ? `<button class="btn btn-primary" id="pu-new-group">${esc(t('pgroups.new') || 'Nouveau groupe')}</button>`
        : `<button class="btn btn-primary" id="pu-invite">${esc(t('pusers.invite') || 'Inviter')}</button>`;

      const chips = isAdmin ? edges.map(c => {
        const nn = c.node_name || c.id;
        const active = window._puFilter.edge === nn;
        return `<button type="button" class="chip" data-edge="${esc(nn)}" style="cursor:pointer;${active ? 'border-color:var(--accent);color:var(--accent)' : ''}">${esc(c.display_name || nn)}</button>`;
      }).join('') : '';
      const tabBtn = (id, label, n) => `<button type="button" class="chip" data-tab="${id}" style="cursor:pointer;padding:5px 14px;font-size:13px;${tab === id ? 'border-color:var(--accent);color:var(--accent);font-weight:600' : ''}">${esc(label)} <span style="opacity:.7">${n}</span></button>`;

      const usersTable = () => {
        const items = filtered();
        return `<div class="card blueprint" style="padding:0;overflow:hidden"><div class="table-wrap">
          <table style="width:100%;border-collapse:collapse;font-size:13px">
            <thead><tr style="text-align:left;border-bottom:1px solid var(--border);color:var(--text2)">
              <th style="padding:10px 14px">Email</th>
              ${isAdmin ? '<th style="padding:10px 14px">Passerelle</th>' : ''}
              <th style="padding:10px 14px">${esc(t('pgroups.groups') || 'Groupes')}</th>
              <th style="padding:10px 14px">Tags</th>
              <th style="padding:10px 14px">Status</th>
              <th style="padding:10px 14px"></th>
            </tr></thead>
            <tbody>
              ${items.length ? items.map(u => `
                <tr style="border-bottom:1px solid var(--border);cursor:pointer" data-row="${esc(u.id)}">
                  <td style="padding:10px 14px;font-weight:500">${esc(u.email)}</td>
                  ${isAdmin ? `<td style="padding:10px 14px;color:var(--text2)">${esc(edgeLabelOf(u.home_edge))}</td>` : ''}
                  <td style="padding:10px 14px">${(u.groups || []).map(id => `<span class="chip" style="font-size:11px;border-color:var(--accent);color:var(--accent)">${esc(groupName(id))}</span>`).join(' ') || '—'}</td>
                  <td style="padding:10px 14px">${(u.tags || []).map(tg => `<span class="chip" style="font-size:11px">${esc(tg)}</span>`).join(' ') || '—'}</td>
                  <td style="padding:10px 14px">${statusBadge(u.status)}</td>
                  <td style="padding:10px 14px;text-align:right;white-space:nowrap">
                    ${iconBtn('data-edit', u.id, t('common.edit') || 'Modifier', ICON.edit)}
                    ${u.status !== 'active' ? iconBtn('data-resend', u.id, t('pusers.resend') || 'Renvoyer', ICON.mail) : ''}
                    ${iconBtn('data-del', u.id, t('common.delete') || 'Supprimer', ICON.del, true)}
                  </td>
                </tr>`).join('') : `<tr><td colspan="${isAdmin ? 6 : 5}" style="padding:40px 24px;text-align:center">
                  <p style="margin:0 0 12px;color:var(--text2);font-size:13px">${esc(t('pusers.empty') || 'Aucun utilisateur portal')}</p>
                  <button type="button" class="btn btn-primary btn-sm" id="pu-empty-invite">${esc(t('pusers.invite') || 'Inviter le premier utilisateur')}</button>
                </td></tr>`}
            </tbody>
          </table></div></div>`;
      };

      const groupsTable = () => {
        const items = filteredGroups();
        return `<div class="card blueprint" style="padding:0;overflow:hidden"><div class="table-wrap">
          <table style="width:100%;border-collapse:collapse;font-size:13px">
            <thead><tr style="text-align:left;border-bottom:1px solid var(--border);color:var(--text2)">
              <th style="padding:10px 14px">${esc(t('pgroups.name') || 'Groupe')}</th>
              ${isAdmin ? '<th style="padding:10px 14px">Passerelle</th>' : ''}
              <th style="padding:10px 14px">${esc(t('pgroups.members') || 'Membres')}</th>
              <th style="padding:10px 14px"></th>
            </tr></thead>
            <tbody>
              ${items.length ? items.map(g => `
                <tr style="border-bottom:1px solid var(--border);cursor:pointer" data-grow="${esc(g.id)}">
                  <td style="padding:10px 14px"><div style="font-weight:500">${esc(g.name)}</div>${g.description ? `<div style="font-size:12px;color:var(--text2)">${esc(g.description)}</div>` : ''}</td>
                  ${isAdmin ? `<td style="padding:10px 14px;color:var(--text2)">${esc(edgeLabelOf(g.edge_name))}</td>` : ''}
                  <td style="padding:10px 14px"><span class="chip" style="font-size:11px">${(g.members || []).length}</span> <span style="font-size:12px;color:var(--text2)">${esc((g.members || []).slice(0, 3).join(', '))}${(g.members || []).length > 3 ? '…' : ''}</span></td>
                  <td style="padding:10px 14px;text-align:right;white-space:nowrap">
                    ${iconBtn('data-gedit', g.id, t('common.edit') || 'Modifier', ICON.edit)}
                    ${iconBtn('data-gdel', g.id, t('common.delete') || 'Supprimer', ICON.del, true)}
                  </td>
                </tr>`).join('') : `<tr><td colspan="${isAdmin ? 4 : 3}" style="padding:40px 24px;text-align:center">
                  <p style="margin:0 0 12px;color:var(--text2);font-size:13px">${esc(t('pgroups.empty') || 'Aucun groupe. Un groupe rassemble des utilisateurs pour leur donner des droits sur une entrée du portail.')}</p>
                  <button type="button" class="btn btn-primary btn-sm" id="pu-empty-group">${esc(t('pgroups.new') || 'Nouveau groupe')}</button>
                </td></tr>`}
            </tbody>
          </table></div></div>`;
      };

      content.innerHTML = `
        <div style="margin-bottom:16px">
          <h1 style="margin:0 0 4px;font-size:22px;font-family:var(--font-heading);font-weight:600">${esc(t('pusers.title') || 'Users Access')}</h1>
          <p style="margin:0;font-size:13px;color:var(--text2)">
            ${isAdmin
              ? esc(t('pusers.sub_admin') || 'Comptes portail — invitation par email (SMTP requis).')
              : (t('pusers.sub_edge') || 'Comptes de {name}.').replace('{name}', '<strong>' + esc(edgeLabel) + '</strong>')}
          </p>
        </div>
        <div style="display:flex;gap:8px;margin-bottom:12px">
          ${tabBtn('users', t('pusers.tab_users') || 'Utilisateurs', filtered().length)}
          ${tabBtn('groups', t('pusers.tab_groups') || 'Groupes', filteredGroups().length)}
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:8px;margin-bottom:14px;align-items:center">
          <input class="input" id="pu-q" placeholder="${esc(t('pusers.search') || 'Rechercher…')}" value="${esc(window._puFilter.q)}" style="max-width:220px"/>
          ${tab === 'users' ? `<select class="input" id="pu-status" style="max-width:140px">
            <option value="">${esc(t('pusers.all_status') || 'Tous statuts')}</option>
            ${['invited', 'active', 'disabled'].map(s => `<option value="${s}" ${window._puFilter.status === s ? 'selected' : ''}>${s}</option>`).join('')}
          </select>` : ''}
          ${isAdmin ? `<div style="display:flex;flex-wrap:wrap;gap:6px;align-items:center">
            <button type="button" class="chip" data-edge="" style="cursor:pointer;${!window._puFilter.edge ? 'border-color:var(--accent);color:var(--accent)' : ''}">${esc(t('pcatalog.all_edges') || 'Tous')}</button>
            ${chips}
          </div>` : ''}
        </div>
        ${tab === 'users' ? usersTable() : groupsTable()}`;

      // Filtrage : on ne reconstruit que le tableau pour garder le focus du champ de recherche.
      const q = document.getElementById('pu-q');
      q.oninput = (e) => {
        window._puFilter.q = e.target.value;
        const pos = e.target.selectionStart;
        render();
        const nq = document.getElementById('pu-q');
        nq.focus();
        nq.setSelectionRange(pos, pos);
      };
      const st = document.getElementById('pu-status');
      if (st) st.onchange = (e) => { window._puFilter.status = e.target.value; render(); };
      content.querySelectorAll('[data-tab]').forEach(btn => { btn.onclick = () => { window._puTab = btn.getAttribute('data-tab'); render(); }; });
      content.querySelectorAll('[data-edge]').forEach(btn => {
        btn.onclick = () => { window._puFilter.edge = btn.getAttribute('data-edge') || ''; render(); };
      });
      const bind = (id, fn) => { const el = document.getElementById(id); if (el) el.onclick = fn; };
      bind('pu-invite', () => openInviteModal());
      bind('pu-empty-invite', () => openInviteModal());
      bind('pu-new-group', () => openGroupModal(null));
      bind('pu-empty-group', () => openGroupModal(null));

      const userById = (id) => (window._portalUsersAll || []).find(x => x.id === id);
      const groupById = (id) => (window._portalGroupsAll || []).find(x => x.id === id);
      content.querySelectorAll('[data-row]').forEach(row => {
        row.onclick = (e) => { if (e.target.closest('button')) return; const u = userById(row.getAttribute('data-row')); if (u) openUserModal(u); };
      });
      content.querySelectorAll('[data-edit]').forEach(btn => { btn.onclick = () => { const u = userById(btn.getAttribute('data-edit')); if (u) openUserModal(u); }; });
      content.querySelectorAll('[data-resend]').forEach(btn => {
        btn.onclick = async () => {
          try {
            await api('POST', '/portal/users/' + btn.getAttribute('data-resend') + '/resend');
            PortalUI.toast(t('pusers.resent') || 'Invitation renvoyée.');
            renderPortalUsersPage(ctx);
          } catch (e) { PortalUI.toast(e.message || e, true); }
        };
      });
      content.querySelectorAll('[data-del]').forEach(btn => {
        btn.onclick = async () => {
          if (!confirm(t('pusers.confirm_del') || 'Supprimer cet utilisateur ?')) return;
          try { await api('DELETE', '/portal/users/' + btn.getAttribute('data-del')); renderPortalUsersPage(ctx); }
          catch (e) { PortalUI.toast(e.message || e, true); }
        };
      });
      content.querySelectorAll('[data-grow]').forEach(row => {
        row.onclick = (e) => { if (e.target.closest('button')) return; const g = groupById(row.getAttribute('data-grow')); if (g) openGroupModal(g); };
      });
      content.querySelectorAll('[data-gedit]').forEach(btn => { btn.onclick = () => { const g = groupById(btn.getAttribute('data-gedit')); if (g) openGroupModal(g); }; });
      content.querySelectorAll('[data-gdel]').forEach(btn => {
        btn.onclick = async () => {
          if (!confirm(t('pgroups.confirm_del') || 'Supprimer ce groupe ? Il sera retiré des entrées du portail.')) return;
          try { await api('DELETE', '/portal/groups/' + btn.getAttribute('data-gdel')); renderPortalUsersPage(ctx); }
          catch (e) { PortalUI.toast(e.message || e, true); }
        };
      });
    };

    // ── Invitation
    function openInviteModal() {
      const defaultEdge = isAdmin ? (window._puFilter.edge || (edges[0] && (edges[0].node_name || edges[0].id)) || '') : edgeName;
      const edgeField = isAdmin
        ? `<select class="input" id="pu-edge">${edgeOptions(defaultEdge)}</select>`
        : `<select class="input" id="pu-edge"><option value="${esc(edgeName)}">${esc(edgeLabel)}</option></select>`;
      const groupsHTML = () => PortalUI.picker('groups', groupsOf(document.getElementById('pu-edge')?.value || defaultEdge).map(g => ({ value: g.id, label: g.name })), [], t('pgroups.none_for_edge') || 'Aucun groupe pour cette passerelle.');
      const ov = PortalUI.modal({
        title: esc(t('pusers.invite') || 'Inviter'),
        width: 480,
        okLabel: t('pusers.send') || 'Envoyer',
        body: `
          <div class="field" style="margin-bottom:10px"><label class="field-label">Email</label><input class="input" id="pu-email" type="email"/></div>
          <div class="field" style="margin-bottom:10px"><label class="field-label">Passerelle</label>${edgeField}</div>
          <div class="field" style="margin-bottom:10px"><label class="field-label">${esc(t('pgroups.groups') || 'Groupes')}</label><div id="pu-groups">${groupsHTML()}</div></div>
          <div class="field" style="margin-bottom:6px"><label class="field-label">Tags</label><input class="input" id="pu-tags" placeholder="prod, ops"/>
            <div style="font-size:11px;color:var(--text2);margin-top:4px">${esc(t('pusers.tags_hint') || 'Les tags filtrent les destinations visibles sur le portail principal.')}</div></div>`,
        onOk: async (o) => {
          await api('POST', '/portal/users/invite', {
            email: o.querySelector('#pu-email').value.trim(),
            tags: PortalUI.split(o.querySelector('#pu-tags').value),
            groups: PortalUI.picked(o, 'groups'),
            home_edge: o.querySelector('#pu-edge').value,
          });
          PortalUI.toast(t('pusers.invited') || 'Invitation envoyée.');
          renderPortalUsersPage(ctx);
        },
      });
      const sel = ov.querySelector('#pu-edge');
      sel.onchange = () => { ov.querySelector('#pu-groups').innerHTML = groupsHTML(); PortalUI.bindPickers(ov); };
    }

    // ── Fiche utilisateur : identité, statut, groupes, tags, accès effectifs, actions
    async function openUserModal(u) {
      const scope = u.home_edge;
      const [cfg, destRes] = await Promise.all([
        api('GET', '/portal?edge=' + encodeURIComponent(scope)).catch(() => ({})),
        api('GET', '/portal/destinations?edge=' + encodeURIComponent(scope)).catch(() => ({})),
      ]);
      const dests = (destRes.destinations || []).filter(d => d.enabled !== false);
      const myGroups = new Set(u.groups || []);
      const scopeGroups = groupsOf(scope);
      const ident = String(u.email || '').toLowerCase();

      // Accès : pour chaque entrée, pourquoi l'utilisateur y a accès (ou non) et quelles destinations il y trouve.
      const accessRows = (root) => {
        const curGroups = new Set(root ? PortalUI.picked(root, 'groups') : myGroups);
        const curTags = (root ? PortalUI.split(root.querySelector('#pu-etags').value) : (u.tags || [])).map(x => x.toLowerCase());
        const visTags = (d) => !(d.tags || []).length || (d.tags || []).some(tg => curTags.includes(tg));
        const rows = [];
        const host = cfg.public_host || '';
        const main = dests.filter(visTags);
        rows.push({ url: 'https://' + (host || '…') + '/', name: t('pusers.main_portal') || 'Portail principal', why: t('pusers.why_all') || 'tous les comptes', ok: true, dests: main.map(d => d.name), note: t('pusers.dest_by_tags') || 'destinations selon les tags' });
        (cfg.views || []).forEach(v => {
          const direct = (v.users || []).map(x => x.toLowerCase()).includes(ident);
          const viaGroups = (v.groups || []).filter(id => curGroups.has(id)).map(groupName);
          const open = !(v.users || []).length && !(v.groups || []).length;
          const ok = open || direct || viaGroups.length > 0;
          const why = open ? (t('pusers.why_open') || 'entrée ouverte à tous')
            : ok ? [direct ? (t('pusers.why_direct') || 'accès direct') : '', ...viaGroups.map(g => (t('pusers.why_group') || 'groupe') + ' ' + g)].filter(Boolean).join(', ')
              : (t('pusers.why_none') || 'aucun droit');
          const list = (v.target_ids || []).length ? dests.filter(d => v.target_ids.includes(d.id)) : main;
          rows.push({ url: 'https://' + (v.host || host || '…') + (v.slug ? '/' + v.slug : '/'), name: v.name || v.slug || v.host, why, ok, dests: ok ? list.map(d => d.name) : [], note: '' });
        });
        return rows;
      };
      const accessHTML = (root) => accessRows(root).map(r => `
        <div style="border:1px solid var(--border);border-radius:8px;padding:8px 10px;margin-bottom:6px;${r.ok ? '' : 'opacity:.55'}">
          <div style="display:flex;justify-content:space-between;gap:8px;flex-wrap:wrap;font-size:13px">
            <span><b>${esc(r.name)}</b> <code style="font-size:11px;color:var(--text2)">${esc(r.url)}</code></span>
            <span style="font-size:11px;color:${r.ok ? 'var(--accent)' : 'var(--danger,#c45c5c)'}">${r.ok ? '✓' : '✗'} ${esc(r.why)}</span>
          </div>
          ${r.ok ? `<div style="font-size:11px;color:var(--text2);margin-top:4px">${r.dests.length ? esc(r.dests.join(', ')) : esc(t('pusers.no_dest') || 'aucune destination')}${r.note ? ' — ' + esc(r.note) : ''}</div>` : ''}
        </div>`).join('');

      const ov = PortalUI.modal({
        title: esc(u.email),
        width: 620,
        body: `
          <div style="display:flex;gap:14px;flex-wrap:wrap;align-items:center;font-size:12px;color:var(--text2);margin:-6px 0 12px">
            ${statusBadge(u.status)}
            <span>${esc(t('pusers.edge') || 'Passerelle')} : <b>${esc(edgeLabelOf(u.home_edge))}</b></span>
            ${u.created_at ? `<span>${esc(t('pusers.created') || 'Créé le')} ${esc(String(u.created_at).slice(0, 10))}</span>` : ''}
            ${u.status === 'invited' && u.invite_expires ? `<span>${esc(t('pusers.invite_exp') || 'Invitation expire le')} ${esc(String(u.invite_expires).slice(0, 10))}</span>` : ''}
          </div>
          <div class="gp-cols-2">
            <div class="field"><label class="field-label">Status</label>
              <select class="input" id="pu-estatus">
                ${['invited', 'active', 'disabled'].map(s => `<option value="${s}" ${u.status === s ? 'selected' : ''}>${s}</option>`).join('')}
              </select></div>
            ${isAdmin ? `<div class="field"><label class="field-label">${esc(t('pusers.edge') || 'Passerelle')}</label><select class="input" id="pu-eedge">${edgeOptions(u.home_edge)}</select></div>` : ''}
          </div>
          <div class="field" style="margin-top:12px"><label class="field-label">${esc(t('pgroups.groups') || 'Groupes')}</label>
            <div style="font-size:11px;color:var(--text2);margin:-2px 0 6px">${esc(t('pusers.groups_hint') || 'Les groupes donnent accès aux entrées du portail (Réglages › Entrées dédiées).')}</div>
            ${PortalUI.picker('groups', scopeGroups.map(g => ({ value: g.id, label: g.name, sub: (g.members || []).length + ' ' + (t('portal.members') || 'membre(s)') })), [...myGroups], t('pgroups.none_for_edge') || 'Aucun groupe pour cette passerelle — créez-en dans l’onglet Groupes.')}
          </div>
          <div class="field" style="margin-top:12px"><label class="field-label">Tags</label>
            <input class="input" id="pu-etags" value="${esc((u.tags || []).join(', '))}"/>
            <div style="font-size:11px;color:var(--text2);margin-top:4px">${esc(t('pusers.tags_hint') || 'Les tags filtrent les destinations visibles sur le portail principal.')}</div></div>
          <div class="field" style="margin-top:14px"><label class="field-label">${esc(t('pusers.access') || 'Accès effectifs')}</label><div id="pu-access">${accessHTML()}</div></div>`,
        extraButtons: `
          ${u.status !== 'active' ? `<button type="button" class="btn btn-secondary" id="pu-m-resend">${esc(t('pusers.resend') || 'Renvoyer')}</button>` : ''}
          <button type="button" class="btn btn-secondary" id="pu-m-del" style="color:var(--danger,#c45c5c);margin-right:auto">${esc(t('common.delete') || 'Supprimer')}</button>`,
        onOk: async (o) => {
          const body = {
            tags: PortalUI.split(o.querySelector('#pu-etags').value),
            status: o.querySelector('#pu-estatus').value,
            groups: PortalUI.picked(o, 'groups'),
          };
          const ne = o.querySelector('#pu-eedge');
          if (ne && ne.value !== u.home_edge) body.home_edge = ne.value;
          await api('PUT', '/portal/users/' + u.id, body);
          renderPortalUsersPage(ctx);
        },
      });
      const refreshAccess = () => { const box = ov.querySelector('#pu-access'); if (box) box.innerHTML = accessHTML(ov); };
      ov.addEventListener('change', refreshAccess);
      ov.querySelector('#pu-etags').addEventListener('input', refreshAccess);
      const rs = ov.querySelector('#pu-m-resend');
      if (rs) rs.onclick = async () => {
        try { await api('POST', '/portal/users/' + u.id + '/resend'); PortalUI.toast(t('pusers.resent') || 'Invitation renvoyée.'); }
        catch (e) { ov.querySelector('.pm-err').textContent = e.message || String(e); }
      };
      ov.querySelector('#pu-m-del').onclick = async () => {
        if (!confirm(t('pusers.confirm_del') || 'Supprimer cet utilisateur ?')) return;
        try { await api('DELETE', '/portal/users/' + u.id); ov.close(); renderPortalUsersPage(ctx); }
        catch (e) { ov.querySelector('.pm-err').textContent = e.message || String(e); }
      };
    }

    // ── Groupe : nom, description, membres (comptes du portail + identifiants libres), entrées concernées
    async function openGroupModal(g) {
      const scope = g ? g.edge_name : (isAdmin ? (window._puFilter.edge || (edges[0] && (edges[0].node_name || edges[0].id)) || '') : edgeName);
      const cfg = g ? await api('GET', '/portal?edge=' + encodeURIComponent(scope)).catch(() => ({})) : {};
      const used = (cfg.views || []).filter(v => (v.groups || []).includes(g?.id));
      const known = new Set((window._portalUsersAll || []).map(u => String(u.email).toLowerCase()));
      const members = (g?.members || []);
      const extra = members.filter(m => !known.has(m));
      const userItems = (window._portalUsersAll || []).filter(u => !isAdmin || u.home_edge === scope).map(u => ({ value: String(u.email).toLowerCase(), label: u.email, sub: u.status === 'active' ? '' : u.status }));
      PortalUI.modal({
        title: esc(g ? g.name : (t('pgroups.new') || 'Nouveau groupe')),
        width: 560,
        body: `
          ${!g && isAdmin ? `<div class="field" style="margin-bottom:10px"><label class="field-label">${esc(t('pusers.edge') || 'Passerelle')}</label><select class="input" id="pg-edge">${edgeOptions(scope)}</select></div>` : ''}
          <div class="field" style="margin-bottom:10px"><label class="field-label">${esc(t('pgroups.name') || 'Groupe')}</label><input class="input" id="pg-name" value="${esc(g?.name || '')}" placeholder="Prestataires"/></div>
          <div class="field" style="margin-bottom:10px"><label class="field-label">Description</label><input class="input" id="pg-desc" value="${esc(g?.description || '')}"/></div>
          <div class="field" style="margin-bottom:10px"><label class="field-label">${esc(t('pgroups.members') || 'Membres')}</label>
            ${PortalUI.picker('members', userItems, members, t('pusers.empty') || 'Aucun utilisateur portal')}
            <textarea class="input" id="pg-extra" rows="2" style="margin-top:6px" placeholder="${esc(t('portal.view_users_extra') || 'Autres identifiants (annuaire LDAP/OIDC), un par ligne')}">${esc(extra.join('\n'))}</textarea></div>
          ${g ? `<div class="field"><label class="field-label">${esc(t('pgroups.used_by') || 'Entrées utilisant ce groupe')}</label>
            <div style="font-size:12px;color:var(--text2)">${used.length ? used.map(v => esc(v.name || PortalUI.formatURL(v))).join(', ') : esc(t('pgroups.unused') || 'Aucune — à associer dans Réglages › Entrées dédiées.')}</div></div>` : ''}`,
        onOk: async (o) => {
          const body = {
            name: o.querySelector('#pg-name').value.trim(),
            description: o.querySelector('#pg-desc').value.trim(),
            members: [...new Set([...PortalUI.picked(o, 'members'), ...PortalUI.split(o.querySelector('#pg-extra').value).map(x => x.toLowerCase())])],
          };
          if (g) await api('PUT', '/portal/groups/' + g.id, body);
          else await api('POST', '/portal/groups?edge=' + encodeURIComponent(o.querySelector('#pg-edge')?.value || scope), body);
          window._puTab = 'groups';
          renderPortalUsersPage(ctx);
        },
      });
    }

    render();
  } catch (e) {
    content.innerHTML = `<div class="err">${esc(e.message || e)}</div>`;
  }
}

pages['admin-portal-users'] = async function() {
  await renderPortalUsersPage({ mode: 'admin' });
};
pages['edge-portal-users'] = async function() {
  await renderPortalUsersPage({ mode: 'edge' });
};
