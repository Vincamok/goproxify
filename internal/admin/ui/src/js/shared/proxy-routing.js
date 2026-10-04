// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Options de routage avancé d'un proxy (onglet Avancé de la modale) : split, maintenance, URLs signées,
// GraphQL, hedge, gRPC-Web, débit, masquage JSON, fichiers statiques, schéma de requête.
// _proutRender(cfg) rend les cartes, _proutCollect(prev) lit les champs et renvoie { clé: valeur | undefined }.

(function () {
  const e = v => (typeof esc === 'function' ? esc(v) : String(v ?? ''));
  const card = (key, title, desc, on, body) => `
    <details class="prout-card" data-prout="${key}" ${on ? 'open' : ''} style="background:var(--bg2);border:1px solid var(--border);border-radius:10px;padding:12px 16px;">
      <summary style="cursor:pointer;display:flex;align-items:center;gap:8px;list-style:none;">
        <span style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);flex:1;">${title}</span>
        <span class="tag ${on ? 'tag-accent' : 'tag-neutral'}" id="prout-${key}-tag">${on ? 'Actif' : 'Inactif'}</span>
      </summary>
      <div style="font-size:11px;color:var(--text3);margin:8px 0 10px;">${desc}</div>
      ${body}
    </details>`;
  const toggle = (id, label, checked) => `
    <label style="display:flex;align-items:center;gap:8px;cursor:pointer;margin-bottom:10px;">
      <label class="toggle"><input type="checkbox" id="${id}" ${checked ? 'checked' : ''} onchange="_proutTag(this)"><span class="toggle-slider"></span></label>
      <span style="font-size:13px;font-weight:500;">${label}</span>
    </label>`;
  const field = (id, label, value, attrs = '', grow = true) => `
    <div class="field" style="${grow ? 'flex:1;min-width:140px;' : ''}margin:0;"><label class="field-label" style="font-size:11px">${label}</label><input id="${id}" class="input" value="${e(value ?? '')}" ${attrs}></div>`;
  const area = (id, label, value, attrs = '', rows = 3) => `
    <div class="field" style="margin:8px 0 0;"><label class="field-label" style="font-size:11px">${label}</label><textarea id="${id}" class="input" rows="${rows}" style="font-size:12px;font-family:monospace;" ${attrs}>${e(value ?? '')}</textarea></div>`;
  const row = inner => `<div style="display:flex;gap:10px;flex-wrap:wrap;">${inner}</div>`;
  const lines = s => (s || '').split('\n').map(x => x.trim()).filter(Boolean);
  const csv = s => (s || '').split(',').map(x => x.trim()).filter(Boolean);
  const num = id => parseInt(document.getElementById(id)?.value, 10) || 0;
  const val = id => document.getElementById(id)?.value.trim() || '';
  const checked = id => !!document.getElementById(id)?.checked;

  window._proutTag = function (input) {
    const key = input.closest('[data-prout]')?.dataset.prout;
    const tag = document.getElementById(`prout-${key}-tag`);
    if (!tag) return;
    const first = input.closest('[data-prout]').querySelector('input[type=checkbox]');
    tag.textContent = first.checked ? 'Actif' : 'Inactif';
    tag.className = 'tag ' + (first.checked ? 'tag-accent' : 'tag-neutral');
  };

  window._proutAddVariant = function (v = {}) {
    const list = document.getElementById('prout-split-list');
    if (!list) return;
    const div = document.createElement('div');
    div.className = 'prout-variant';
    div.style.cssText = 'display:flex;gap:6px;margin-bottom:6px;align-items:center;';
    div.innerHTML = `
      <input class="input prout-v-name" style="width:110px" placeholder="nom (v2)" value="${e(v.name || '')}">
      <input class="input prout-v-backend" style="flex:1" placeholder="http://10.0.0.6:3000" value="${e(v.backend || '')}">
      <input class="input prout-v-weight" style="width:70px" type="number" min="1" placeholder="Poids" value="${e(v.weight || '')}">
      <button type="button" class="btn-icon" title="Supprimer" onclick="this.closest('.prout-variant').remove()">×</button>`;
    list.appendChild(div);
  };

  window._proutRender = function (cfg) {
    cfg = cfg || {};
    const sp = cfg.split, mt = cfg.maintenance, su = cfg.signed_url, gq = cfg.graphql, hg = cfg.hedge;
    const bw = cfg.bandwidth, rj = cfg.redact_json, st = cfg.static, rs = cfg.request_schema;
    const variants = sp?.variants?.length ? sp.variants : [{}, {}];
    setTimeout(() => { variants.forEach(v => window._proutAddVariant(v)); }, 0);
    return `
      <div style="font-size:10px;font-weight:700;text-transform:uppercase;letter-spacing:.07em;color:var(--text3);">Routage avancé</div>
      ${card('split', 'Split pondéré (A/B)', 'Répartit le trafic entre plusieurs backends nommés au prorata de leur poids. Un cookie d\'affectation garde la variante d\'un visiteur ; l\'override force le choix par header ou cookie.', !!sp?.variants?.length,
        toggle('prout-split-on', 'Activer le split', !!sp?.variants?.length) +
        `<div id="prout-split-list"></div><button type="button" class="btn btn-secondary btn-sm" onclick="_proutAddVariant()">+ Variante</button>` +
        `<div style="margin-top:10px;">${row(field('prout-split-cookie', 'Cookie d\'affectation (sticky)', sp?.sticky_cookie, 'placeholder="gpx_ab"') + field('prout-split-override', 'Override (header ou cookie)', sp?.override, 'placeholder="X-Variant"'))}</div>`)}
      ${card('maintenance', 'Mode maintenance', 'Coupe la route avec une page 503 sans la supprimer. Les CIDR et l\'en-tête de contournement laissent passer les équipes qui testent.', !!mt?.enabled,
        toggle('prout-mt-on', 'Route en maintenance', mt?.enabled) +
        row(field('prout-mt-msg', 'Message', mt?.message, 'placeholder="Retour dans quelques minutes"') + field('prout-mt-retry', 'Retry-After (s)', mt?.retry_after_sec || '', 'type="number" min="0" placeholder="120"', false)) +
        `<div style="margin-top:10px;">${row(field('prout-mt-cidrs', 'CIDR autorisés (virgules)', (mt?.bypass_cidrs || []).join(', '), 'placeholder="10.0.0.0/8"') + field('prout-mt-header', 'En-tête de contournement', mt?.bypass_header, 'placeholder="X-Bypass: secret"'))}</div>` +
        area('prout-mt-html', 'Page HTML (optionnelle)', mt?.html))}
      ${card('signed_url', 'URLs signées', 'N\'accepte que les URLs portant une signature HMAC-SHA256 valide et non expirée (chemin + expiration).', !!su?.enabled,
        toggle('prout-su-on', 'Exiger une signature', su?.enabled) +
        row(field('prout-su-secret', 'Secret', su?.secret, 'type="password" autocomplete="new-password"') + field('prout-su-sig', 'Paramètre signature', su?.param_sig, 'placeholder="sig"') + field('prout-su-exp', 'Paramètre expiration', su?.param_expires, 'placeholder="expires"')) +
        `<div style="margin-top:10px;">${field('prout-su-paths', 'Préfixes protégés (virgules, vide = toute la route)', (su?.paths || []).join(', '), 'placeholder="/download/, /private/"')}</div>`)}
      ${card('graphql', 'Garde-fous GraphQL', 'Borne la profondeur et le nombre d\'alias des requêtes GraphQL, et peut bloquer l\'introspection.', !!gq?.enabled,
        toggle('prout-gq-on', 'Activer', gq?.enabled) +
        row(field('prout-gq-depth', 'Profondeur max (0 = illimitée)', gq?.max_depth || '', 'type="number" min="0"') + field('prout-gq-alias', 'Alias max (0 = illimité)', gq?.max_aliases || '', 'type="number" min="0"')) +
        `<label style="display:flex;align-items:center;gap:6px;font-size:12px;margin-top:10px;cursor:pointer;"><input type="checkbox" id="prout-gq-intro" ${gq?.block_introspection ? 'checked' : ''}> Bloquer l'introspection</label>`)}
      ${card('hedge', 'Requêtes « hedged »', 'Un GET/HEAD sans corps dont le backend tarde à répondre est doublé vers un autre backend ; la première réponse est gardée.', !!hg,
        toggle('prout-hg-on', 'Activer', !!hg) +
        row(field('prout-hg-delay', 'Délai avant doublon (ms)', hg?.delay_ms || '', 'type="number" min="1" placeholder="200"') + field('prout-hg-extra', 'Tentatives supplémentaires', hg?.max_extra || '', 'type="number" min="1" placeholder="1"')))}
      ${card('grpc_web', 'gRPC-Web', 'Traduit gRPC-Web (navigateurs) en gRPC vers le backend, qui doit parler HTTP/2.', !!cfg.grpc_web,
        toggle('prout-gw-on', 'Activer la traduction gRPC-Web', !!cfg.grpc_web))}
      ${card('bandwidth', 'Plafond de débit', 'Limite le débit de chaque réponse, par connexion.', !!bw?.bytes_per_sec,
        toggle('prout-bw-on', 'Activer', !!bw?.bytes_per_sec) +
        field('prout-bw-bps', 'Octets par seconde', bw?.bytes_per_sec || '', 'type="number" min="1" placeholder="1048576"', false))}
      ${card('redact_json', 'Masquage de champs JSON', 'Masque des champs des réponses JSON avant envoi au client : un nom de clé (à toute profondeur) ou un chemin a.b.c par ligne.', !!rj?.fields?.length,
        toggle('prout-rj-on', 'Activer', !!rj?.fields?.length) +
        area('prout-rj-fields', 'Champs (un par ligne)', (rj?.fields || []).join('\n'), 'placeholder="password\nuser.ssn"') +
        `<div style="margin-top:10px;max-width:200px;">${field('prout-rj-mask', 'Valeur de remplacement', rj?.mask, 'placeholder="***"', false)}</div>`)}
      ${card('static', 'Fichiers statiques', 'Sert un dossier de la passerelle sans backend. Le repli SPA renvoie l\'index pour les chemins de page introuvables.', !!st?.enabled,
        toggle('prout-st-on', 'Servir un dossier', st?.enabled) +
        row(field('prout-st-root', 'Dossier (sur la passerelle)', st?.root, 'placeholder="/var/www/app"') + field('prout-st-index', 'Index', st?.index, 'placeholder="index.html"') + field('prout-st-cache', 'Cache max-age (s)', st?.cache_max_age || '', 'type="number" min="0"', false)) +
        `<label style="display:flex;align-items:center;gap:6px;font-size:12px;margin-top:10px;cursor:pointer;"><input type="checkbox" id="prout-st-spa" ${st?.spa_fallback ? 'checked' : ''}> Repli SPA vers l'index</label>`)}
      ${card('request_schema', 'Validation JSON Schema des requêtes', 'Valide le corps JSON des requêtes. Chaque règle : { "methods": [..], "path_prefix": "/api", "schema": {…} } — la première qui correspond s\'applique.', !!rs?.enabled,
        toggle('prout-rs-on', 'Activer', rs?.enabled) +
        row(`<div class="field" style="flex:1;min-width:140px;margin:0;"><label class="field-label" style="font-size:11px">Mode</label><select id="prout-rs-mode" class="input"><option value="block" ${rs?.mode !== 'detect' ? 'selected' : ''}>Bloquer (422)</option><option value="detect" ${rs?.mode === 'detect' ? 'selected' : ''}>Détecter (métrique seule)</option></select></div>` +
          field('prout-rs-max', 'Corps max lu (octets)', rs?.max_body || '', 'type="number" min="0" placeholder="1048576"')) +
        area('prout-rs-rules', 'Règles (JSON)', rs?.rules ? JSON.stringify(rs.rules, null, 2) : '[]', 'spellcheck="false"', 8))}`;
  };

  // Lit les cartes et renvoie les options à poser. Une option sans interrupteur actif est retirée,
  // sauf celles qui portent un `enabled` et existaient déjà (on garde leurs réglages désactivés).
  window._proutCollect = function (prev) {
    prev = prev || {};
    if (!document.getElementById('prout-split-on')) {
      const keep = {};
      for (const k of ['split', 'maintenance', 'signed_url', 'graphql', 'hedge', 'grpc_web', 'bandwidth', 'redact_json', 'static', 'request_schema'])
        if (prev[k] !== undefined) keep[k] = prev[k];
      return keep;
    }
    const out = {};
    if (checked('prout-split-on')) {
      const variants = [...document.querySelectorAll('.prout-variant')].map(r => ({
        name: r.querySelector('.prout-v-name').value.trim(),
        backend: r.querySelector('.prout-v-backend').value.trim(),
        weight: parseInt(r.querySelector('.prout-v-weight').value, 10) || 1,
      })).filter(v => v.name || v.backend);
      if (variants.length < 2) throw new Error('Split : au moins deux variantes sont nécessaires');
      if (variants.some(v => !v.name || !/^https?:\/\/.+/.test(v.backend))) throw new Error('Split : chaque variante exige un nom et une URL http(s)');
      out.split = { variants, ...(val('prout-split-cookie') ? { sticky_cookie: val('prout-split-cookie') } : {}), ...(val('prout-split-override') ? { override: val('prout-split-override') } : {}) };
    }
    if (checked('prout-mt-on') || prev.maintenance) {
      out.maintenance = {
        enabled: checked('prout-mt-on'),
        ...(val('prout-mt-msg') ? { message: val('prout-mt-msg') } : {}),
        ...(document.getElementById('prout-mt-html')?.value.trim() ? { html: document.getElementById('prout-mt-html').value } : {}),
        ...(num('prout-mt-retry') > 0 ? { retry_after_sec: num('prout-mt-retry') } : {}),
        ...(csv(val('prout-mt-cidrs')).length ? { bypass_cidrs: csv(val('prout-mt-cidrs')) } : {}),
        ...(val('prout-mt-header') ? { bypass_header: val('prout-mt-header') } : {}),
      };
    }
    if (checked('prout-su-on') || prev.signed_url) {
      if (checked('prout-su-on') && !val('prout-su-secret')) throw new Error('URLs signées : le secret est obligatoire');
      out.signed_url = {
        enabled: checked('prout-su-on'),
        secret: val('prout-su-secret'),
        ...(val('prout-su-sig') ? { param_sig: val('prout-su-sig') } : {}),
        ...(val('prout-su-exp') ? { param_expires: val('prout-su-exp') } : {}),
        ...(csv(val('prout-su-paths')).length ? { paths: csv(val('prout-su-paths')) } : {}),
      };
    }
    if (checked('prout-gq-on') || prev.graphql) {
      out.graphql = {
        enabled: checked('prout-gq-on'),
        ...(num('prout-gq-depth') > 0 ? { max_depth: num('prout-gq-depth') } : {}),
        ...(num('prout-gq-alias') > 0 ? { max_aliases: num('prout-gq-alias') } : {}),
        ...(checked('prout-gq-intro') ? { block_introspection: true } : {}),
      };
    }
    if (checked('prout-hg-on')) {
      if (num('prout-hg-delay') <= 0) throw new Error('Hedge : le délai (ms) est obligatoire');
      out.hedge = { delay_ms: num('prout-hg-delay'), ...(num('prout-hg-extra') > 0 ? { max_extra: num('prout-hg-extra') } : {}) };
    }
    if (checked('prout-gw-on')) out.grpc_web = true;
    if (checked('prout-bw-on')) {
      if (num('prout-bw-bps') <= 0) throw new Error('Plafond de débit : indiquer des octets par seconde');
      out.bandwidth = { bytes_per_sec: num('prout-bw-bps') };
    }
    if (checked('prout-rj-on')) {
      const fields = lines(document.getElementById('prout-rj-fields')?.value);
      if (!fields.length) throw new Error('Masquage JSON : indiquer au moins un champ');
      out.redact_json = { fields, ...(val('prout-rj-mask') ? { mask: val('prout-rj-mask') } : {}) };
    }
    if (checked('prout-st-on') || prev.static) {
      if (checked('prout-st-on') && !val('prout-st-root')) throw new Error('Fichiers statiques : le dossier est obligatoire');
      out.static = {
        enabled: checked('prout-st-on'),
        root: val('prout-st-root'),
        ...(val('prout-st-index') ? { index: val('prout-st-index') } : {}),
        ...(checked('prout-st-spa') ? { spa_fallback: true } : {}),
        ...(num('prout-st-cache') > 0 ? { cache_max_age: num('prout-st-cache') } : {}),
      };
    }
    if (checked('prout-rs-on') || prev.request_schema) {
      let rules;
      try { rules = JSON.parse(document.getElementById('prout-rs-rules')?.value || '[]'); } catch (err) { throw new Error('Schéma de requête : règles JSON invalides (' + err.message + ')'); }
      if (!Array.isArray(rules)) throw new Error('Schéma de requête : les règles doivent former un tableau');
      out.request_schema = {
        enabled: checked('prout-rs-on'),
        mode: val('prout-rs-mode') === 'detect' ? 'detect' : 'block',
        ...(num('prout-rs-max') > 0 ? { max_body: num('prout-rs-max') } : {}),
        rules,
      };
    }
    return out;
  };
})();
