// ── Couche HTTP ────────────────────────────────────────────────────────────
async function api(method, path, body, fetchOpts) {
  const opts = {
    method,
    headers: {
      'Content-Type': 'application/json',
      'Authorization': 'Bearer ' + state.token,
      'X-Locale': (typeof gpxResolveLocale === 'function' ? gpxResolveLocale() : 'en'),
    },
    ...fetchOpts,
  };
  if (body !== undefined) opts.body = JSON.stringify(body);
  const res = await fetch('/api/v1' + path, opts);
  if (res.status === 401) { doLogout(); return null; }
  if (!res.ok) {
    const txt = await res.text().catch(() => res.statusText);
    // Une page d'erreur de la passerelle (502/503/504) est du HTML : inutilisable dans un toast.
    const isHTML = /^\s*<(!doctype|html)/i.test(txt);
    throw new Error(!txt || isHTML ? 'Erreur ' + res.status + (res.statusText ? ' ' + res.statusText : '') : txt);
  }
  if (res.status === 204) return null;
  return res.json().catch(() => null);
}

// ── Utilitaires UI ─────────────────────────────────────────────────────────
function toast(msg, type = 'info') {
  const el = document.createElement('div');
  el.className = `toast toast-${type}`;
  el.innerHTML = `<span>${esc(msg)}</span>`;
  document.getElementById('toasts').append(el);
  setTimeout(() => el.remove(), 3500);
}

function esc(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
}

function tryJSON(s) {
  try { return JSON.parse(s); } catch { return null; }
}

function copyText(text, successMsg) {
  const msg = successMsg || 'Copié';
  if (navigator.clipboard?.writeText) {
    navigator.clipboard.writeText(text).then(() => toast(msg, 'success')).catch(() => toast('Erreur copie', 'error'));
  } else {
    try {
      const ta = document.createElement('textarea');
      ta.value = text; ta.style.position = 'fixed'; ta.style.opacity = '0';
      document.body.appendChild(ta); ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      toast(msg, 'success');
    } catch { toast('Erreur copie', 'error'); }
  }
}
