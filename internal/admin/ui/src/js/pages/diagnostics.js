// ── PAGE: Diagnostic (Paramètres › Système)
// État du runtime de l'Admin et profilage (CPU, tas, goroutines) activable depuis l'interface.
pages.diagnostics = async function() {
  document.getElementById('topbar-actions').innerHTML =
    `<button class="btn btn-secondary" id="diag-refresh">${esc(t('common.refresh'))}</button>`;
  const content = document.getElementById('content');
  content.innerHTML = `<div class="muted">${esc(t('common.loading'))}</div>`;
  document.getElementById('diag-refresh').onclick = () => pages.diagnostics();

  const mb = (n) => (n / 1048576).toFixed(1) + ' ' + t('diag.unit_mb');
  const dur = (s) => {
    const d = Math.floor(s / 86400), h = Math.floor(s % 86400 / 3600), m = Math.floor(s % 3600 / 60);
    return (d ? d + 'j ' : '') + (h || d ? h + 'h ' : '') + m + 'min';
  };
  const row = (label, value, hint) => `
    <div style="display:flex;justify-content:space-between;gap:16px;padding:9px 0;border-bottom:1px solid var(--border)">
      <span style="font-size:12px;color:var(--text2)" title="${esc(hint || '')}">${esc(label)}</span>
      <span style="font-size:12px;font-family:monospace;font-weight:600">${esc(String(value))}</span>
    </div>`;

  try {
    const d = await api('GET', '/settings/diagnostics') || {};
    const r = d.runtime || {};
    const on = !!d.profiling_enabled;
    content.innerHTML = `
      <div class="card blueprint" style="padding:16px 18px;max-width:640px;margin-bottom:16px">
        <div style="font-family:var(--font-heading);font-size:18px;font-weight:700;margin-bottom:4px">${esc(t('diag.title'))}</div>
        <p style="font-size:13px;color:var(--text2);margin:0 0 14px;line-height:1.45">${esc(t('diag.desc'))}</p>
        <label style="display:flex;align-items:center;gap:10px;font-size:13px;cursor:pointer">
          <input type="checkbox" id="diag-toggle" ${on ? 'checked' : ''}/>
          <span>${esc(t('diag.enable'))}</span>
        </label>
        <p style="font-size:12px;color:var(--text2);margin:8px 0 0;line-height:1.45">${esc(t('diag.enable_hint'))}</p>
        <div id="diag-actions" style="display:${on ? 'flex' : 'none'};flex-wrap:wrap;gap:8px;margin-top:14px">
          <button class="btn btn-secondary" data-prof="heap" data-fmt="text">${esc(t('diag.heap_text'))}</button>
          <button class="btn btn-secondary" data-prof="goroutine" data-fmt="text">${esc(t('diag.goroutine_text'))}</button>
          <button class="btn btn-secondary" data-prof="heap">${esc(t('diag.heap_file'))}</button>
          <button class="btn btn-secondary" data-prof="cpu">${esc(t('diag.cpu_file'))}</button>
        </div>
        <div id="diag-msg" style="font-size:13px;min-height:1.2em;margin-top:10px"></div>
        <pre id="diag-out" style="display:none;max-height:320px;overflow:auto;font-size:11px;margin-top:10px;padding:10px;border:1px solid var(--border);border-radius:6px;white-space:pre-wrap"></pre>
      </div>
      <div class="card" style="padding:4px 16px;max-width:640px">
        ${row(t('diag.uptime'), dur(r.uptime_seconds || 0))}
        ${row(t('diag.sys'), mb(r.sys_bytes || 0), t('diag.sys_hint'))}
        ${row(t('diag.heap_inuse'), mb(r.heap_inuse_bytes || 0), t('diag.heap_inuse_hint'))}
        ${row(t('diag.heap_idle'), mb(r.heap_idle_bytes || 0), t('diag.heap_idle_hint'))}
        ${row(t('diag.heap_released'), mb(r.heap_released_bytes || 0), t('diag.heap_released_hint'))}
        ${row(t('diag.stack'), mb(r.stack_bytes || 0))}
        ${row(t('diag.next_gc'), mb(r.next_gc_bytes || 0))}
        ${row(t('diag.mem_limit'), r.mem_limit_bytes ? mb(r.mem_limit_bytes) : t('diag.none'), t('diag.mem_limit_hint'))}
        ${row(t('diag.goroutines'), r.goroutines || 0)}
        ${row(t('diag.gc_cycles'), r.num_gc || 0)}
        ${row(t('diag.gc_cpu'), ((r.gc_cpu_fraction || 0) * 100).toFixed(2) + ' %', t('diag.gc_cpu_hint'))}
        ${row(t('diag.cpus'), (r.gomaxprocs || 0) + ' / ' + (r.num_cpu || 0))}
        ${row(t('diag.go_version'), r.go_version || '—')}
      </div>`;

    const msg = (text, ok) => {
      const el = document.getElementById('diag-msg');
      el.textContent = text;
      el.style.color = ok ? 'var(--accent)' : 'var(--danger, #c45c5c)';
    };
    document.getElementById('diag-toggle').onchange = async (e) => {
      try {
        await api('PUT', '/settings/diagnostics', { profiling_enabled: e.target.checked });
        document.getElementById('diag-actions').style.display = e.target.checked ? 'flex' : 'none';
        msg(t('diag.saved'), true);
      } catch (err) {
        e.target.checked = !e.target.checked;
        msg(err.message || String(err), false);
      }
    };
    document.querySelectorAll('#diag-actions [data-prof]').forEach((btn) => {
      btn.onclick = async () => {
        const type = btn.dataset.prof, text = btn.dataset.fmt === 'text';
        const out = document.getElementById('diag-out');
        out.style.display = 'none';
        document.querySelectorAll('#diag-actions button').forEach((b) => { b.disabled = true; });
        msg(t(type === 'cpu' ? 'diag.cpu_running' : 'diag.working'), true);
        try {
          const res = await fetch('/api/v1/settings/diagnostics/profile?type=' + type + (text ? '&format=text' : ''), {
            headers: { 'Authorization': 'Bearer ' + state.token },
          });
          if (res.status === 401) { doLogout(); return; }
          if (!res.ok) throw new Error(await res.text() || ('Erreur ' + res.status));
          if (text) {
            out.textContent = await res.text();
            out.style.display = 'block';
          } else {
            const a = document.createElement('a');
            a.href = URL.createObjectURL(await res.blob());
            a.download = 'goproxify-admin-' + type + '.pb.gz';
            a.click();
            setTimeout(() => URL.revokeObjectURL(a.href), 10000);
          }
          msg(t(text ? 'diag.done_text' : 'diag.done_file'), true);
        } catch (err) {
          msg(err.message || String(err), false);
        } finally {
          document.querySelectorAll('#diag-actions button').forEach((b) => { b.disabled = false; });
        }
      };
    });
  } catch (e) {
    content.innerHTML = `<div class="err">${esc(e.message || e)}</div>`;
  }
};
