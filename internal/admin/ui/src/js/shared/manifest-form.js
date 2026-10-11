// ── Formulaire piloté par un manifeste de module (internal/modules.Manifest) ───────────────────────
// Un manifeste décrit les champs d'une configuration : clé (chemin pointé pour les sections
// imbriquées, ex. `oidc.client_secret`), genre (text|password|number|list|bool), secret, requis.
// Ce fichier en tire un formulaire et relit les valeurs, sans connaître le type de module : un module
// ajouté côté serveur apparaît dans l'interface sans modifier le JavaScript.
//
// Les clés absentes du manifeste, présentes dans la configuration existante, sont conservées. Un secret
// reste affiché masqué (`••••••••`) : renvoyé tel quel, le serveur garde la valeur enregistrée.

const ManifestForm = (() => {
  const idOf = (prefix, key) => `${prefix}-${key.replace(/\./g, '__')}`;

  function getPath(obj, path) {
    return path.split('.').reduce((o, k) => (o && typeof o === 'object' ? o[k] : undefined), obj);
  }

  function setPath(obj, path, value) {
    const keys = path.split('.');
    let o = obj;
    for (let i = 0; i < keys.length - 1; i++) {
      if (!o[keys[i]] || typeof o[keys[i]] !== 'object') o[keys[i]] = {};
      o = o[keys[i]];
    }
    o[keys[keys.length - 1]] = value;
  }

  function delPath(obj, path) {
    const keys = path.split('.');
    const parents = [obj];
    let o = obj;
    for (let i = 0; i < keys.length - 1; i++) {
      o = o && o[keys[i]];
      if (!o || typeof o !== 'object') return;
      parents.push(o);
    }
    delete o[keys[keys.length - 1]];
    // Une section devenue vide disparaît : le serveur refuse une section sans champ renseigné.
    for (let i = keys.length - 2; i >= 0; i--) {
      if (Object.keys(parents[i + 1]).length) break;
      delete parents[i][keys[i]];
    }
  }

  // Une liste de chaînes se saisit une entrée par ligne ; une liste d'objets (règles, utilisateurs)
  // se saisit en JSON.
  const isObjectList = (f, v) => !!f.item_key || (Array.isArray(v) && v.some(e => e && typeof e === 'object'));

  function fieldHtml(prefix, f, value) {
    const id = idOf(prefix, f.key);
    const label = `${esc(f.label)}${f.required ? ' *' : ''}`;
    const ph = esc(f.placeholder || '');
    let input;
    if (f.kind === 'bool') {
      return `<div class="field"><label class="field-label" style="display:flex;align-items:center;gap:8px">
        <input type="checkbox" id="${id}" ${value === true ? 'checked' : ''}> ${label}</label></div>`;
    }
    if (f.kind === 'select') {
      const opts = (f.options || []).slice();
      if (value != null && value !== '' && !opts.some(o => o.value === String(value))) opts.push({ value: String(value), label: String(value) });
      input = `<select id="${id}" class="input"${f.source ? ` data-source="${esc(f.source)}"` : ''}>
        ${f.required ? '' : '<option value="">—</option>'}
        ${opts.map(o => `<option value="${esc(o.value)}"${String(value ?? '') === o.value ? ' selected' : ''}>${esc(o.label)}</option>`).join('')}</select>`;
    } else if (f.kind === 'list') {
      const json = isObjectList(f, value);
      const text = json
        ? (value == null ? '' : JSON.stringify(value, null, 2))
        : (Array.isArray(value) ? value.join('\n') : '');
      input = `<textarea id="${id}" class="input" rows="${json ? 6 : 3}" data-json="${json ? 1 : ''}" placeholder="${json ? '[ … ] (JSON)' : ph}">${esc(text)}</textarea>`;
    } else if (f.multiline) {
      input = `<textarea id="${id}" class="input" rows="5" placeholder="${ph}">${esc(value ?? '')}</textarea>`;
    } else {
      // Une variable ({{detail.x}}) se saisit aussi dans un champ numérique.
      const variable = typeof value === 'string' && value.includes('{{');
      const type = f.kind === 'password' ? 'password' : (f.kind === 'number' && !variable ? 'number' : 'text');
      const durPh = f.kind === 'duration' && !ph ? '5m, 1h, 30s' : ph;
      input = `<input id="${id}" class="input" type="${type}" autocomplete="off" placeholder="${durPh}" value="${esc(value ?? '')}">`;
    }
    const help = f.help ? `<div style="font-size:11.5px;color:var(--text3);margin-top:3px">${esc(f.help)}</div>` : '';
    return `<div class="field"><label class="field-label">${label}</label>${input}${help}</div>`;
  }

  // Formulaire des champs d'un manifeste, valeurs prises dans `cfg` (configuration existante) ; un champ
  // absent reprend la valeur par défaut du manifeste.
  function render(prefix, fields, cfg) {
    return (fields || []).map(f => {
      let v = getPath(cfg || {}, f.key);
      if (v === undefined && f.default !== undefined) v = f.default;
      return fieldHtml(prefix, f, v);
    }).join('');
  }

  // Complète les listes à source dynamique (data-source) sous `root`. loadOptions(source) est fourni par la
  // page (ex. FlowCatalog) et retourne une promesse de [{value,label}] ; la valeur choisie est conservée.
  const optionCache = {};
  let loadOptions = null;
  async function hydrate(root) {
    if (!loadOptions || !root) return;
    for (const sel of root.querySelectorAll('select[data-source]')) {
      const src = sel.dataset.source;
      try {
        optionCache[src] = optionCache[src] || loadOptions(src);
        const opts = await optionCache[src];
        const cur = sel.value;
        const known = new Map([...sel.options].map(o => [o.value, o]));
        for (const o of opts || []) {
          // La valeur enregistrée est rendue avant le chargement, avec elle-même pour libellé.
          if (known.has(o.value)) { known.get(o.value).textContent = o.label; continue; }
          sel.insertAdjacentHTML('beforeend', `<option value="${esc(o.value)}">${esc(o.label)}</option>`);
        }
        // Un champ requis n'a pas d'option vide : la première valeur affichée doit aussi être celle relue.
        if (!cur && sel.options.length && !sel.querySelector('option[value=""]')) {
          sel.value = sel.options[0].value;
          sel.dispatchEvent(new Event('change', { bubbles: true }));
        } else sel.value = cur;
      } catch (e) { delete optionCache[src]; }
    }
  }
  function setOptionsLoader(fn) {
    loadOptions = fn;
    for (const k of Object.keys(optionCache)) delete optionCache[k];
  }

  // Relit les champs. Retourne { config, errors } : `config` repart de `base` (clés hors manifeste
  // conservées) ; `errors` liste les champs requis vides et les JSON illisibles.
  function collect(prefix, fields, base) {
    const config = JSON.parse(JSON.stringify(base || {}));
    const errors = [];
    for (const f of fields || []) {
      const el = document.getElementById(idOf(prefix, f.key));
      if (!el) continue;
      let v;
      if (f.kind === 'bool') {
        v = el.checked;
        if (!v && getPath(config, f.key) === undefined) continue;
      } else if (f.kind === 'list') {
        const raw = el.value.trim();
        if (!raw) v = undefined;
        else if (el.dataset.json) {
          try { v = JSON.parse(raw); } catch (e) { errors.push(`${f.label} : JSON invalide`); continue; }
        } else v = raw.split('\n').map(s => s.trim()).filter(Boolean);
      } else if (f.kind === 'number') {
        v = el.value.trim() === '' ? undefined : Number(el.value);
      } else {
        v = el.value.trim() === '' ? undefined : (f.multiline ? el.value : el.value.trim());
      }
      if (v === undefined || (Array.isArray(v) && !v.length)) {
        delPath(config, f.key);
        if (f.required) errors.push(`${f.label} requis`);
      } else {
        setPath(config, f.key, v);
      }
    }
    return { config, errors };
  }

  return { render, collect, hydrate, setOptionsLoader };
})();
window.ManifestForm = ManifestForm;
