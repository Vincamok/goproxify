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

  window._proutGtSrc = function () {
    const set = document.getElementById('prout-gt-src')?.value === 'set';
    const p = document.getElementById('prout-gt-proto'), s = document.getElementById('prout-gt-set');
    if (p) p.style.display = set ? 'none' : 'block';
    if (s) s.style.display = set ? 'block' : 'none';
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
    const bw = cfg.bandwidth, rj = cfg.redact_json, st = cfg.static, rs = cfg.request_schema, oa = cfg.openapi, gt = cfg.grpc_transcode;
    const gtFiles = Object.keys(gt?.proto || {});
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
        area('prout-rs-rules', 'Règles (JSON)', rs?.rules ? JSON.stringify(rs.rules, null, 2) : '[]', 'spellcheck="false"', 8))}
      ${card('openapi', 'Validation OpenAPI', 'Valide chemins, méthodes, paramètres (chemin, requête, en-tête, cookie) et corps JSON contre une spécification OpenAPI 3.0 ou 3.1 (YAML ou JSON, références « #/… » uniquement). Commencer en mode « détecter » pour roder la spécification avant de refuser.', !!oa?.enabled,
        toggle('prout-oa-on', 'Activer', oa?.enabled) +
        row(`<div class="field" style="flex:1;min-width:140px;margin:0;"><label class="field-label" style="font-size:11px">Mode</label><select id="prout-oa-mode" class="input"><option value="block" ${oa?.mode !== 'detect' ? 'selected' : ''}>Bloquer (400 / 422)</option><option value="detect" ${oa?.mode === 'detect' ? 'selected' : ''}>Détecter (métrique seule)</option></select></div>` +
          `<div class="field" style="flex:1;min-width:140px;margin:0;"><label class="field-label" style="font-size:11px">Chemins absents de la spécification</label><select id="prout-oa-unknown" class="input"><option value="allow" ${oa?.unknown_paths !== 'block' ? 'selected' : ''}>Laisser passer</option><option value="block" ${oa?.unknown_paths === 'block' ? 'selected' : ''}>Refuser (404 / 405)</option></select></div>`) +
        `<div style="margin-top:10px;">${row(field('prout-oa-prefix', 'Préfixe retiré avant la recherche', oa?.strip_prefix, 'placeholder="/api/v1"') + field('prout-oa-max', 'Corps max lu (octets)', oa?.max_body || '', 'type="number" min="0" placeholder="1048576"', false))}</div>` +
        `<div style="display:flex;gap:14px;flex-wrap:wrap;margin-top:10px;font-size:12px;"><span style="color:var(--text3);">Ne pas contrôler :</span>${[['path', 'chemin'], ['query', 'requête'], ['header', 'en-têtes'], ['cookie', 'cookies'], ['body', 'corps']].map(([k, l]) => `<label style="display:flex;align-items:center;gap:5px;cursor:pointer;"><input type="checkbox" class="prout-oa-skip" value="${k}" ${(oa?.skip || []).includes(k) ? 'checked' : ''}> ${l}</label>`).join('')}</div>` +
        area('prout-oa-spec', 'Spécification (YAML ou JSON)', typeof oa?.spec === 'string' ? oa.spec : (oa?.spec ? JSON.stringify(oa.spec, null, 2) : ''), 'spellcheck="false" placeholder="openapi: 3.0.3&#10;paths:&#10;  /users/{id}: …"', 14))}
      ${card('grpc_transcode', 'Transcodage REST ↔ gRPC', 'Expose un backend gRPC unaire en REST/JSON : chaque méthode est publiée selon ses annotations google.api.http (get, post, body, response_body…). Le backend doit parler gRPC en HTTP/2 (h2c accepté en http://). Flux serveur : NDJSON ; flux client : corps en suite de valeurs JSON.', !!gt?.enabled,
        toggle('prout-gt-on', 'Activer', gt?.enabled) +
        (gtFiles.length > 1
          ? `<div style="font-size:12px;color:var(--text3);margin-bottom:8px;">${gtFiles.length} fichiers .proto enregistrés (${esc(gtFiles.join(', '))}) : à modifier par la CLI ou l'éditeur YAML — ils sont conservés tels quels.</div>`
          : row(`<div class="field" style="flex:1;min-width:160px;margin:0;"><label class="field-label" style="font-size:11px">Source des descripteurs</label><select id="prout-gt-src" class="input" onchange="_proutGtSrc()"><option value="proto" ${!gt?.descriptor_set ? 'selected' : ''}>Fichier .proto</option><option value="set" ${gt?.descriptor_set ? 'selected' : ''}>FileDescriptorSet (base64)</option></select></div>`)) +
        (gtFiles.length > 1 ? '' :
          `<div id="prout-gt-proto" style="display:${gt?.descriptor_set ? 'none' : 'block'}">${area('prout-gt-protosrc', 'Contenu du .proto (imports google/api/*, google/protobuf/* fournis)', gtFiles.length ? gt.proto[gtFiles[0]] : '', 'spellcheck="false" placeholder="syntax = &quot;proto3&quot;;&#10;import &quot;google/api/annotations.proto&quot;;&#10;service Users { rpc Get(Req) returns (Res) { option (google.api.http) = { get: &quot;/v1/users/{id}&quot; }; } }"', 12)}</div>` +
          `<div id="prout-gt-set" style="display:${gt?.descriptor_set ? 'block' : 'none'}">${area('prout-gt-setsrc', 'FileDescriptorSet en base64 (protoc --include_imports --descriptor_set_out=…)', gt?.descriptor_set || '', 'spellcheck="false"', 6)}</div>`) +
        `<div style="margin-top:10px;">${field('prout-gt-services', 'Services publiés (noms complets, virgules ; vide = tous)', (gt?.services || []).join(', '), 'placeholder="demo.v1.Users"')}</div>` +
        `<div style="display:flex;gap:16px;flex-wrap:wrap;margin-top:10px;font-size:12px;">${[['prout-gt-auto', 'Publier aussi les méthodes sans annotation en POST /paquet.Service/Méthode', gt?.auto_mapping], ['prout-gt-defaults', 'Écrire les champs à valeur par défaut', gt?.emit_defaults], ['prout-gt-names', 'Garder les noms de champs du .proto', gt?.proto_field_names]].map(([id, l, c]) => `<label style="display:flex;align-items:center;gap:5px;cursor:pointer;"><input type="checkbox" id="${id}" ${c ? 'checked' : ''}> ${l}</label>`).join('')}</div>`)}`;
  };

  // Lit les cartes et renvoie les options à poser. Une option sans interrupteur actif est retirée,
  // sauf celles qui portent un `enabled` et existaient déjà (on garde leurs réglages désactivés).
  window._proutCollect = function (prev) {
    prev = prev || {};
    if (!document.getElementById('prout-split-on')) {
      const keep = {};
      for (const k of ['split', 'maintenance', 'signed_url', 'graphql', 'hedge', 'grpc_web', 'bandwidth', 'redact_json', 'static', 'request_schema', 'openapi', 'grpc_transcode'])
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
    if (checked('prout-oa-on') || prev.openapi) {
      const spec = document.getElementById('prout-oa-spec')?.value || '';
      if (checked('prout-oa-on') && !spec.trim()) throw new Error('OpenAPI : la spécification est obligatoire');
      const skip = [...document.querySelectorAll('.prout-oa-skip:checked')].map(c => c.value);
      out.openapi = {
        enabled: checked('prout-oa-on'),
        spec,
        mode: val('prout-oa-mode') === 'detect' ? 'detect' : 'block',
        ...(val('prout-oa-unknown') === 'block' ? { unknown_paths: 'block' } : {}),
        ...(val('prout-oa-prefix') ? { strip_prefix: val('prout-oa-prefix') } : {}),
        ...(num('prout-oa-max') > 0 ? { max_body: num('prout-oa-max') } : {}),
        ...(skip.length ? { skip } : {}),
      };
    }
    if (checked('prout-gt-on') || prev.grpc_transcode) {
      const prevGt = prev.grpc_transcode || {};
      const multi = Object.keys(prevGt.proto || {}).length > 1;
      const useSet = !multi && val('prout-gt-src') === 'set';
      const protoText = document.getElementById('prout-gt-protosrc')?.value || '';
      const setText = val('prout-gt-setsrc');
      const gt = { enabled: checked('prout-gt-on') };
      if (multi) gt.proto = prevGt.proto;
      else if (useSet) gt.descriptor_set = setText;
      else if (protoText.trim()) gt.proto = { [Object.keys(prevGt.proto || {})[0] || 'service.proto']: protoText };
      if (checked('prout-gt-on') && !gt.proto && !gt.descriptor_set) throw new Error('Transcodage gRPC : renseigner un fichier .proto ou un FileDescriptorSet');
      if (csv(val('prout-gt-services')).length) gt.services = csv(val('prout-gt-services'));
      if (checked('prout-gt-auto')) gt.auto_mapping = true;
      if (checked('prout-gt-defaults')) gt.emit_defaults = true;
      if (checked('prout-gt-names')) gt.proto_field_names = true;
      for (const k of ['max_request_body', 'max_response_body']) if (prevGt[k]) gt[k] = prevGt[k];
      out.grpc_transcode = gt;
    }
    return out;
  };
})();
