// ── Composants partagés des pages Portail Access (entrées, groupes, utilisateurs)
const PortalUI = {
  // « presta.domaine.fr », « domaine.fr/prestataire », « /prestataire » → { host, slug }.
  parseURL(raw) {
    let s = String(raw || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/+$/, '');
    if (!s) return { error: 'URL requise' };
    let host = '';
    let path = '';
    if (s.startsWith('/')) {
      path = s.slice(1);
    } else {
      const i = s.indexOf('/');
      host = i < 0 ? s : s.slice(0, i);
      path = i < 0 ? '' : s.slice(i + 1);
    }
    if (path.includes('/')) return { error: 'un seul niveau de chemin est géré (ex. /prestataire)' };
    if (host && (!host.includes('.') || /[\s:]/.test(host))) return { error: 'hôte invalide : ' + host };
    if (!host && !path) return { error: 'URL requise' };
    return { host, slug: path };
  },
  formatURL(v) {
    return (v.host || '') + (v.slug ? '/' + v.slug : '');
  },

  // Liste à cocher recherchable. items : [{ value, label, sub }].
  picker(id, items, selected, emptyText) {
    const sel = new Set(selected || []);
    const rows = (items || []).map((it) => `
      <label class="pk-item" data-text="${esc((it.label + ' ' + (it.sub || '')).toLowerCase())}" style="display:flex;align-items:center;gap:8px;padding:3px 2px;font-size:13px;cursor:pointer">
        <input type="checkbox" value="${esc(it.value)}" ${sel.has(it.value) ? 'checked' : ''}/>
        <span>${esc(it.label)}</span>${it.sub ? `<span style="color:var(--text2);font-size:11px">${esc(it.sub)}</span>` : ''}
      </label>`).join('');
    if (!rows) return `<div class="pk-empty" style="font-size:12px;color:var(--text2)">${esc(emptyText || '—')}</div>`;
    return `<div class="pk" data-pk="${esc(id)}">
      ${(items || []).length > 6 ? `<input class="input pk-q" placeholder="${esc(t('common.search') || 'Rechercher…')}" style="margin-bottom:6px"/>` : ''}
      <div class="pk-list" style="max-height:150px;overflow:auto;border:1px solid var(--border);border-radius:8px;padding:4px 8px">${rows}</div>
      <div class="pk-count" style="font-size:11px;color:var(--text2);margin-top:4px"></div>
    </div>`;
  },
  bindPickers(root) {
    root.querySelectorAll('.pk').forEach((pk) => {
      const count = () => {
        const n = pk.querySelectorAll('input[type=checkbox]:checked').length;
        pk.querySelector('.pk-count').textContent = n + ' ' + (t('portal.selected') || 'sélectionné(s)');
      };
      pk.addEventListener('change', count);
      const q = pk.querySelector('.pk-q');
      if (q) {
        q.addEventListener('input', () => {
          const needle = q.value.trim().toLowerCase();
          pk.querySelectorAll('.pk-item').forEach((it) => { it.style.display = !needle || it.dataset.text.includes(needle) ? 'flex' : 'none'; });
        });
      }
      count();
    });
  },
  picked(root, id) {
    const pk = root.querySelector(`.pk[data-pk="${id}"]`);
    return pk ? [...pk.querySelectorAll('input[type=checkbox]:checked')].map((i) => i.value) : [];
  },
  split(s) {
    return String(s || '').split(/[\n,;]+/).map((x) => x.trim()).filter(Boolean);
  },

  // Champ d'étiquettes : une pastille par étiquette (× pour la retirer), un champ pour en ajouter.
  // Entrée, virgule, point-virgule ou la perte du focus ajoutent ; Retour arrière sur un champ vide retire la dernière.
  // suggestions : étiquettes déjà connues, proposées à la saisie. Brancher ensuite avec bindTagInput, lire avec tagValues.
  tagInput(id, tags, opts) {
    const o = opts || {};
    const chip = (tg) => `<span class="chip" data-tag="${esc(tg)}">${esc(tg)}<button type="button" class="chip-x" aria-label="${esc(o.removeLabel || 'Remove')} ${esc(tg)}" title="${esc(o.removeLabel || 'Remove')}">×</button></span>`;
    const sugg = [...new Set((o.suggestions || []).filter(Boolean))].sort((a, b) => a.localeCompare(b));
    return `<div class="tagbox" data-tagbox="${esc(id)}" data-remove="${esc(o.removeLabel || 'Remove')}">${(tags || []).map(chip).join('')}<input class="tagbox-in" type="text" autocomplete="off" list="${esc(id)}-dl" placeholder="${esc(o.placeholder || '')}" aria-label="${esc(o.label || 'Tags')}"/></div>
      <datalist id="${esc(id)}-dl">${sugg.map((s) => `<option value="${esc(s)}"></option>`).join('')}</datalist>`;
  },
  bindTagInput(root, id) {
    const box = root.querySelector(`.tagbox[data-tagbox="${id}"]`);
    if (!box) return;
    const input = box.querySelector('.tagbox-in');
    const has = (tg) => [...box.querySelectorAll('[data-tag]')].some((c) => c.dataset.tag.toLowerCase() === tg.toLowerCase());
    const add = (raw) => {
      for (const tg of PortalUI.split(raw)) {
        if (has(tg)) continue;
        const span = document.createElement('span');
        span.className = 'chip';
        span.dataset.tag = tg;
        span.append(tg);
        const x = document.createElement('button');
        x.type = 'button';
        x.className = 'chip-x';
        x.textContent = '×';
        x.setAttribute('aria-label', box.dataset.remove + ' ' + tg);
        x.title = box.dataset.remove;
        span.append(x);
        box.insertBefore(span, input);
      }
      input.value = '';
    };
    input.addEventListener('keydown', (e) => {
      if (e.key === 'Enter') {
        e.preventDefault();
        if (input.value.trim()) add(input.value);
      } else if (e.key === 'Backspace' && !input.value) {
        box.querySelector('[data-tag]:nth-last-child(2)')?.remove();
      }
    });
    input.addEventListener('input', () => { if (/[,;]/.test(input.value)) add(input.value); });
    input.addEventListener('blur', () => { if (input.value.trim()) add(input.value); });
    box.addEventListener('click', (e) => {
      if (e.target.closest('.chip-x')) e.target.closest('[data-tag]').remove();
      else input.focus();
    });
  },
  tagValues(root, id) {
    const box = root.querySelector(`.tagbox[data-tagbox="${id}"]`);
    if (!box) return [];
    const out = [...box.querySelectorAll('[data-tag]')].map((c) => c.dataset.tag);
    for (const tg of PortalUI.split(box.querySelector('.tagbox-in').value)) {
      if (!out.some((x) => x.toLowerCase() === tg.toLowerCase())) out.push(tg);
    }
    return out;
  },

  // Modale. opts : { title, body (HTML), okLabel, width, onOk(overlay) -> Promise, extraButtons (HTML) }.
  modal(opts) {
    const overlay = document.createElement('div');
    overlay.style.cssText = 'position:fixed;inset:0;background:rgba(0,0,0,.4);z-index:1000;display:flex;align-items:center;justify-content:center;padding:16px';
    overlay.innerHTML = `
      <div class="card blueprint" style="width:min(${opts.width || 560}px,100%);max-height:92vh;overflow:auto;padding:18px 20px;background:var(--bg)">
        <div style="font-weight:700;font-size:16px;margin-bottom:12px">${opts.title}</div>
        <div class="pm-body">${opts.body}</div>
        <div class="pm-err" style="font-size:12px;color:var(--danger,#c45c5c);min-height:1.2em;margin:8px 0"></div>
        <div style="display:flex;gap:8px;justify-content:flex-end;align-items:center;flex-wrap:wrap">
          ${opts.extraButtons || ''}
          <button type="button" class="btn btn-secondary pm-cancel">${esc(t('common.cancel') || 'Annuler')}</button>
          ${opts.onOk ? `<button type="button" class="btn btn-primary pm-ok">${esc(opts.okLabel || t('common.save') || 'Enregistrer')}</button>` : ''}
        </div>
      </div>`;
    document.body.appendChild(overlay);
    const close = () => overlay.remove();
    overlay.querySelector('.pm-cancel').onclick = close;
    overlay.onclick = (e) => { if (e.target === overlay) close(); };
    PortalUI.bindPickers(overlay);
    const ok = overlay.querySelector('.pm-ok');
    if (ok) {
      ok.onclick = async () => {
        const err = overlay.querySelector('.pm-err');
        err.textContent = '';
        ok.disabled = true;
        try {
          await opts.onOk(overlay);
          close();
        } catch (e) {
          err.textContent = e.message || String(e);
          ok.disabled = false;
        }
      };
    }
    overlay.close = close;
    return overlay;
  },
  toast(msg, err) {
    const el = document.createElement('div');
    el.textContent = msg;
    el.style.cssText = 'position:fixed;bottom:20px;right:20px;padding:10px 14px;border-radius:8px;z-index:9999;font-size:13px;background:' + (err ? 'var(--danger,#c45c5c)' : 'var(--accent)') + ';color:#fff';
    document.body.appendChild(el);
    setTimeout(() => el.remove(), 3200);
  },
};
