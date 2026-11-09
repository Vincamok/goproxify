// ── Logins préconfigurés du portail Access (ADR 0025) : onglet « Logins » du catalogue.
// Un login est un compte partagé (root, deploy…) lié à des destinations. Son secret est chiffré ICI, dans le navigateur, avec
// la clé publique de la passerelle : l'Admin ne stocke et ne relaie que l'enveloppe chiffrée, il ne la lit jamais.

const PortalLogins = (() => {
  const enc = new TextEncoder();
  const b64 = (bytes) => btoa(String.fromCharCode.apply(null, Array.from(bytes)));
  const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
  const SEAL_INFO = 'goproxify-portal-login-seal/v1';

  // ECIES : ECDH P-256 (clé éphémère) → HKDF-SHA256 (sel = clé éphémère) → AES-256-GCM. Même schéma que la passerelle
  // (internal/edge/portal/loginseal.go) et que la CLI ; le vecteur de test croisé est dans loginseal_test.go.
  async function sealSecret(pubB64, secret) {
    if (!window.crypto || !crypto.subtle) throw new Error(t('plog.err_webcrypto'));
    const srv = await crypto.subtle.importKey('raw', unb64(pubB64), { name: 'ECDH', namedCurve: 'P-256' }, false, []);
    const eph = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, ['deriveBits']);
    const shared = await crypto.subtle.deriveBits({ name: 'ECDH', public: srv }, eph.privateKey, 256);
    const epk = new Uint8Array(await crypto.subtle.exportKey('raw', eph.publicKey));
    const hk = await crypto.subtle.importKey('raw', shared, 'HKDF', false, ['deriveKey']);
    const aes = await crypto.subtle.deriveKey(
      { name: 'HKDF', hash: 'SHA-256', salt: epk, info: enc.encode(SEAL_INFO) },
      hk, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
    const nonce = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv: nonce }, aes, enc.encode(JSON.stringify(secret))));
    return JSON.stringify({ v: 1, epk: b64(epk), nonce: b64(nonce), ct: b64(ct) });
  }

  const csv = (s) => String(s || '').split(',').map((x) => x.trim()).filter(Boolean);

  async function openEditor(login, o, reload) {
    const isNew = !login;
    const edges = o.edges || [];
    const cur = login || { edge_name: o.scopeEdge(), name: '', username: '', all_users: false, groups: [], tags: [], dest_ids: [], dest_groups: [], enabled: true };
    const scopeOf = () => (document.getElementById('pl-edge') ? document.getElementById('pl-edge').value : cur.edge_name);
    const destItems = (sc) => (window._portalCatalogAll || []).filter((d) => d.edge_name === sc && d.kind !== 'docker')
      .map((d) => ({ value: d.id, label: d.name, sub: d.host || '' }));
    const dgItems = (sc) => (window._portalDestGroups || []).filter((g) => g.edge_name === sc).map((g) => ({ value: g.id, label: g.name }));
    const loadGroups = async (sc) => {
      const r = await api('GET', '/portal/groups?edge=' + encodeURIComponent(sc)).catch(() => ({ groups: [] }));
      return (r.groups || []).map((g) => ({ value: g.id, label: g.name, sub: (g.members || []).length + '' }));
    };
    const edgeSel = o.isAdmin && isNew
      ? `<div class="field" style="margin-bottom:10px"><label class="field-label">${esc(t('pusers.edge') || 'Passerelle')}</label>
          <select class="input" id="pl-edge">${edges.map((c) => { const nn = c.node_name || c.id; return `<option value="${esc(nn)}" ${nn === cur.edge_name ? 'selected' : ''}>${esc(c.display_name || nn)}</option>`; }).join('')}</select></div>` : '';
    const secretHelp = isNew ? '' : `<div style="font-size:11px;color:var(--text2);margin-bottom:6px">${esc(login.has_secret ? t('plog.f_secret_kept') : t('plog.secret_no'))}</div>`;
    const groupItems = await loadGroups(cur.edge_name);

    const ov = PortalUI.modal({
      title: esc(isNew ? t('plog.add') : cur.name),
      width: 620,
      body: `${edgeSel}
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:10px">
          <div class="field"><label class="field-label">${esc(t('plog.f_name'))}</label><input class="input" id="pl-name" value="${esc(cur.name)}"/></div>
          <div class="field"><label class="field-label">${esc(t('plog.f_user'))} *</label><input class="input" id="pl-user" value="${esc(cur.username)}" placeholder="root, deploy…" autocomplete="off"/></div>
        </div>
        ${secretHelp}
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:10px;margin-bottom:6px">
          <div class="field"><label class="field-label">${esc(t('plog.f_pass'))}</label><input class="input" id="pl-pass" type="password" autocomplete="new-password"/></div>
          <div class="field"><label class="field-label">${esc(t('plog.f_key'))}</label><textarea class="input" id="pl-key" rows="2" style="font-family:ui-monospace,monospace;font-size:11px"></textarea></div>
        </div>
        ${!isNew && login.has_secret ? `<label style="display:flex;gap:8px;align-items:center;font-size:12px;margin-bottom:6px"><input type="checkbox" id="pl-clear"/> ${esc(t('plog.f_secret_clear'))}</label>` : ''}
        <div style="font-size:11px;color:var(--text2);margin-bottom:12px">🔒 ${esc(t('plog.sealing_note'))}</div>

        <div class="field-label" style="margin-bottom:4px">${esc(t('plog.f_usage'))}</div>
        <label style="display:flex;gap:8px;align-items:center;font-size:13px;margin-bottom:6px"><input type="checkbox" id="pl-all" ${cur.all_users ? 'checked' : ''}/> ${esc(t('plog.f_all'))}</label>
        <div class="field" style="margin-bottom:8px"><label class="field-label">${esc(t('plog.f_groups'))}</label><div id="pl-groups">${PortalUI.picker('groups', groupItems, cur.groups, t('plog.no_groups'))}</div></div>
        <div class="field" style="margin-bottom:12px"><label class="field-label">${esc(t('plog.f_tags'))}</label><input class="input" id="pl-tags" value="${esc((cur.tags || []).join(', '))}" placeholder="ops, dba"/></div>

        <div class="field" style="margin-bottom:8px"><label class="field-label">${esc(t('plog.f_dests'))}</label><div id="pl-dests">${PortalUI.picker('dests', destItems(cur.edge_name), cur.dest_ids, t('plog.no_dests'))}</div></div>
        <div class="field" style="margin-bottom:10px"><label class="field-label">${esc(t('plog.f_dgroups'))}</label><div id="pl-dgroups">${PortalUI.picker('dgroups', dgItems(cur.edge_name), cur.dest_groups, t('plog.no_dests'))}</div></div>
        <label style="display:flex;gap:8px;align-items:center;font-size:13px"><input type="checkbox" id="pl-enabled" ${cur.enabled !== false ? 'checked' : ''}/> ${esc(t('plog.f_enabled'))}</label>`,
      onOk: async (m) => {
        const scope = scopeOf();
        const body = {
          name: m.querySelector('#pl-name').value.trim(),
          username: m.querySelector('#pl-user').value.trim(),
          all_users: m.querySelector('#pl-all').checked,
          groups: PortalUI.picked(m, 'groups'),
          tags: csv(m.querySelector('#pl-tags').value),
          dest_ids: PortalUI.picked(m, 'dests'),
          dest_groups: PortalUI.picked(m, 'dgroups'),
          enabled: m.querySelector('#pl-enabled').checked,
        };
        const password = m.querySelector('#pl-pass').value;
        const privateKey = m.querySelector('#pl-key').value;
        if (m.querySelector('#pl-clear') && m.querySelector('#pl-clear').checked && !password && !privateKey) {
          body.sealed = '';
        } else if (password || privateKey) {
          let pub;
          try { pub = (await api('GET', '/portal/logins/pubkey?edge=' + encodeURIComponent(scope))).public_key; }
          catch (e) { throw new Error(t('plog.err_nokey') + ' : ' + (e.message || e)); }
          body.sealed = await sealSecret(pub, { password, private_key: privateKey });
          body.has_password = !!password;
          body.has_private_key = !!privateKey;
        }
        if (isNew) { body.edge_name = scope; await api('POST', '/portal/logins', body); }
        else await api('PUT', '/portal/logins/' + encodeURIComponent(cur.id), body);
        reload();
      },
    });
    const sel = ov.querySelector('#pl-edge');
    if (sel) {
      sel.onchange = async () => {
        const sc = sel.value;
        ov.querySelector('#pl-groups').innerHTML = PortalUI.picker('groups', await loadGroups(sc), [], t('plog.no_groups'));
        ov.querySelector('#pl-dests').innerHTML = PortalUI.picker('dests', destItems(sc), [], t('plog.no_dests'));
        ov.querySelector('#pl-dgroups').innerHTML = PortalUI.picker('dgroups', dgItems(sc), [], t('plog.no_dests'));
        PortalUI.bindPickers(ov);
      };
    }
  }

  async function mount(host, o) {
    host.innerHTML = '<p style="color:var(--text2)">' + esc(t('common.loading')) + '</p>';
    const reload = () => mount(host, o);
    const scope = o.edgeFilter();
    let logins = [];
    try {
      logins = (await api('GET', '/portal/logins' + (scope ? '?edge=' + encodeURIComponent(scope) : ''))).logins || [];
    } catch (e) {
      host.innerHTML = `<p style="color:var(--red)">${esc(e.message)}</p>`;
      return;
    }
    const destName = (id) => ((window._portalCatalogAll || []).find((d) => d.id === id) || {}).name || id;
    const dgName = (id) => ((window._portalDestGroups || []).find((g) => g.id === id) || {}).name || id;

    const usage = (l) => {
      if (l.all_users) return esc(t('plog.usage_all'));
      const parts = [];
      if ((l.groups || []).length) parts.push(esc(t('plog.f_groups')) + ' ×' + l.groups.length);
      (l.tags || []).forEach((tg) => parts.push(`<span class="tag tag-neutral" style="font-size:10px">${esc(tg)}</span>`));
      return parts.length ? parts.join(' ') : `<span style="color:var(--danger,#c45c5c)">${esc(t('plog.usage_none'))}</span>`;
    };
    const row = (l) => `<tr style="border-top:1px solid var(--border)">
      <td style="padding:10px 14px"><b>${esc(l.name)}</b>${l.enabled ? '' : ` <span class="tag tag-neutral" style="font-size:10px">${esc(t('plog.disabled'))}</span>`}
        <div style="font-size:11px;color:var(--text2)">${esc(l.username)}${o.isAdmin ? ' · ' + esc(l.edge_name) : ''}</div>
        <div style="font-size:11px;color:${l.has_secret ? 'var(--text2)' : 'var(--danger,#c45c5c)'}">${esc(l.has_secret ? '🔒 ' + t('plog.secret_yes') : t('plog.secret_no'))}</div></td>
      <td style="padding:10px 14px;font-size:12px">${usage(l)}</td>
      <td style="padding:10px 14px;font-size:12px">${[...(l.dest_ids || []).map(destName), ...(l.dest_groups || []).map((g) => dgName(g) + ' ⊞')].map((n) => `<span class="chip" style="font-size:11px">${esc(n)}</span>`).join(' ') || '—'}</td>
      <td style="padding:10px 14px;text-align:right;white-space:nowrap">
        <button type="button" class="btn btn-ghost btn-sm" data-ledit="${esc(l.id)}">${esc(t('common.edit'))}</button>
        <button type="button" class="btn btn-ghost btn-sm" data-ldel="${esc(l.id)}" style="color:var(--danger,#c45c5c)">${esc(t('common.delete'))}</button></td></tr>`;

    host.innerHTML = `
      <p style="margin:0 0 14px;font-size:13px;color:var(--text2);max-width:780px">${esc(t('plog.intro'))}</p>
      ${logins.length ? `<div class="card blueprint" style="padding:0;overflow:hidden"><div class="table-wrap"><table style="width:100%;border-collapse:collapse;font-size:13px">
        <thead><tr style="text-align:left;color:var(--text2)"><th style="padding:8px 14px">${esc(t('plog.col_login'))}</th><th style="padding:8px 14px">${esc(t('plog.col_usage'))}</th><th style="padding:8px 14px">${esc(t('plog.col_dests'))}</th><th></th></tr></thead>
        <tbody>${logins.map(row).join('')}</tbody></table></div></div>`
        : `<div style="padding:22px;text-align:center;color:var(--text2);border:1px dashed var(--border);border-radius:8px">${esc(t('plog.empty'))}</div>`}`;

    const run = async (fn) => { try { await fn(); } catch (e) { alert(e.message || e); } };
    host.querySelectorAll('[data-ledit]').forEach((b) => { b.onclick = () => run(() => openEditor(logins.find((x) => x.id === b.getAttribute('data-ledit')), o, reload)); });
    host.querySelectorAll('[data-ldel]').forEach((b) => { b.onclick = () => run(async () => {
      if (!confirm(t('plog.confirm_del'))) return;
      await api('DELETE', '/portal/logins/' + encodeURIComponent(b.getAttribute('data-ldel')));
      reload();
    }); });
    o.onAdd = () => run(() => openEditor(null, o, reload));
  }

  return { mount, sealSecret };
})();
