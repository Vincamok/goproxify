// Page Traçage IP : parcours complet d'une IP ou d'un CIDR (requêtes, détections, bans, débans)
// sur une longue période. Données : GET /security/ip-trace.

const TR_PAGE = 300;
const TR_PERIODS = { '24h': 1, '7d': 7, '30d': 30, '90d': 90, '365d': 365, all: 0 };
const TR_KIND = {
  activity: { color: 'var(--accent)', icon: '↔' },
  ban: { color: 'var(--red)', icon: '⛔' },
  unban: { color: 'var(--green)', icon: '✓' },
  threat: { color: 'var(--orange,#d97706)', icon: '⚠' },
  system: { color: 'var(--text3)', icon: '•' },
};

const _tr = { target: '', period: '30d', from: '', to: '', order: 'desc', data: null, steps: [], loading: false };

function trDay(iso) {
  const opts = { dateStyle: 'full' };
  if (state.timezone) opts.timeZone = state.timezone;
  try { return new Date(iso).toLocaleDateString(typeof gpxBCP47 === 'function' ? gpxBCP47() : 'en-US', opts); } catch { return iso.slice(0, 10); }
}

function trTime(iso) {
  const opts = { timeStyle: 'medium' };
  if (state.timezone) opts.timeZone = state.timezone;
  try { return new Date(iso).toLocaleTimeString(typeof gpxBCP47 === 'function' ? gpxBCP47() : 'en-US', opts); } catch { return iso; }
}

function trDuration(a, b) {
  const s = Math.max(0, Math.round((Date.parse(b) - Date.parse(a)) / 1000));
  if (s < 60) return s + ' s';
  if (s < 3600) return Math.round(s / 60) + ' min';
  return (s / 3600).toFixed(1).replace(/\.0$/, '') + ' h';
}

function trQuery(offset) {
  const q = new URLSearchParams({ target: _tr.target, order: _tr.order, limit: TR_PAGE, offset });
  if (_tr.period === 'custom') {
    if (_tr.from) q.set('from', _tr.from);
    if (_tr.to) q.set('to', _tr.to);
  } else if (_tr.period === 'all') {
    q.set('from', '2000-01-01');
  } else {
    q.set('from', new Date(Date.now() - TR_PERIODS[_tr.period] * 864e5).toISOString());
  }
  return '/security/ip-trace?' + q;
}

function trChips(list, color) {
  return (list || []).map(c => `<span class="tr-chip"${color ? ` style="color:${color}"` : ''}>${esc(c.value ?? c)}${c.count != null ? ` <i>×${c.count}</i>` : ''}</span>`).join('');
}

function trStepHTML(s) {
  const k = TR_KIND[s.kind] || TR_KIND.system;
  let title, body = '';
  if (s.kind === 'activity') {
    const b = s.burst;
    title = t('trace.step.activity', { n: b.requests });
    const meta = [];
    if (b.blocked) meta.push(`<b style="color:var(--red)">${t('trace.step.blocked', { n: b.blocked })}</b>`);
    meta.push(trDuration(s.ts, s.end));
    if (b.ip_count > 1) meta.push(t('trace.step.ips', { n: b.ip_count }));
    const st = Object.entries(b.statuses || {}).sort().map(([c, n]) => `${esc(c)} <i>×${n}</i>`).join(' · ');
    body = `<div class="tr-meta">${meta.join(' · ')}${st ? ' · ' + st : ''}</div>
      ${b.ip_count > 1 ? `<div class="tr-row">${trChips(b.ips)}${b.ip_count > b.ips.length ? '<span class="tr-chip">…</span>' : ''}</div>` : ''}
      <div class="tr-row">${trChips(b.domains)}</div>
      <div class="tr-row tr-mono">${trChips(b.top_paths)}</div>
      ${b.waf_matches?.length ? `<div class="tr-row">${trChips(b.waf_matches, 'var(--red)')}</div>` : ''}
      ${b.threat_signals?.length ? `<div class="tr-row">${trChips(b.threat_signals, 'var(--orange,#d97706)')}</div>` : ''}`;
  } else {
    title = t('trace.step.' + s.kind);
    const src = s.source ? (typeof _secSourceLabel === 'function' ? _secSourceLabel(s.source) : s.source) : '';
    body = `<div class="tr-meta">${[s.ip && `<span class="tr-mono">${esc(s.ip)}</span>`, s.domain && esc(s.domain), src && esc(src), s.occurrences > 1 && `×${s.occurrences}`].filter(Boolean).join(' · ')}</div>
      ${s.reason ? `<div class="tr-row">${esc(s.reason)}</div>` : ''}`;
  }
  return `<div class="tr-step"><span class="tr-dot" style="background:${k.color}">${k.icon}</span>
    <div class="tr-card"><div class="tr-head"><b style="color:${k.color}">${esc(title)}</b><time>${esc(trTime(s.ts))}</time></div>${body}</div></div>`;
}

function trTimelineHTML() {
  if (!_tr.steps.length) return `<p class="tr-empty">${esc(t('trace.no_events'))}</p>`;
  let day = '', out = '';
  for (const s of _tr.steps) {
    const d = trDay(s.ts);
    if (d !== day) { day = d; out += `<div class="tr-day">${esc(d)}</div>`; }
    out += trStepHTML(s);
  }
  const more = _tr.data.has_more
    ? `<button class="btn btn-secondary btn-sm" onclick="trLoadMore()">${esc(t('trace.load_more', { n: _tr.data.total_steps - _tr.steps.length }))}</button>` : '';
  return `<div class="tr-line">${out}</div><div style="text-align:center;margin-top:12px">${more}</div>`;
}

function trDaysChart(days) {
  if (!days.length) return '';
  const max = Math.max(...days.map(d => d.requests));
  const bars = days.map(d => {
    const h = Math.max(2, Math.round(d.requests / max * 56));
    const bh = d.blocked ? Math.max(2, Math.round(d.blocked / max * 56)) : 0;
    return `<span class="tr-bar" title="${esc(d.day)} · ${d.requests} req · ${d.blocked} ${esc(t('trace.blocked_short'))}"><i style="height:${h}px"></i>${bh ? `<u style="height:${bh}px"></u>` : ''}</span>`;
  }).join('');
  return `<div class="tr-chart">${bars}</div><div class="tr-axis"><span>${esc(days[0].day)}</span><span>${esc(days[days.length - 1].day)}</span></div>`;
}

function trSummaryHTML() {
  const d = _tr.data, s = d.summary;
  const tile = (v, label, color) => `<div class="bn-kpi"><b style="color:${color || 'var(--text1)'}">${v}</b><span>${esc(label)}</span></div>`;
  const state_ = [
    ...s.active_bans.map(b => `<span class="tr-badge" style="--c:var(--red)">⛔ ${esc(t('trace.state.banned'))} · ${esc(b.ip)}${b.expires_at ? '' : ' · ' + esc(t('trace.state.permanent'))}</span>`),
    ...s.profiles.map(p => `<span class="tr-badge" style="--c:var(--orange,#d97706)">${esc(t('trace.state.profile'))} · ${esc(p.name)} (${esc(p.mode)})</span>`),
  ].join('');
  const list = (title, items, mono) => items?.length ? `<div class="tr-list"><h4>${esc(title)}</h4>${items.map(i => `<div><span${mono ? ' class="tr-mono"' : ''}>${esc(i.value)}</span><b>${i.count}</b></div>`).join('')}</div>` : '';
  return `<div class="bn-kpis">
      ${tile(s.requests, t('trace.kpi.requests'))}
      ${tile(s.blocked, t('trace.kpi.blocked'), s.blocked ? 'var(--red)' : '')}
      ${tile(s.ip_count, t('trace.kpi.ips'))}
      ${tile(s.episodes, t('trace.kpi.episodes'))}
      ${tile(`${s.bans} / ${s.unbans}`, t('trace.kpi.bans'), s.bans ? 'var(--orange,#d97706)' : '')}
      ${tile(s.threats, t('trace.kpi.threats'), s.threats ? 'var(--orange,#d97706)' : '')}
    </div>
    <div class="card blueprint" style="padding:16px;margin-bottom:16px">
      <div class="tr-meta" style="margin-bottom:8px">${esc(t('trace.first_seen'))} <b>${esc(fmtDate(s.first_seen))}</b> · ${esc(t('trace.last_seen'))} <b>${esc(fmtDate(s.last_seen))}</b>${d.kind === 'cidr' ? ' · ' + esc(t('trace.kind_cidr')) : ''}</div>
      ${state_ ? `<div class="tr-row" style="margin-bottom:10px">${state_}</div>` : ''}
      ${trDaysChart(s.days)}
      <div class="tr-lists">
        ${d.kind === 'cidr' ? list(t('trace.top_ips'), s.top_ips, true) : ''}
        ${list(t('trace.top_domains'), s.top_domains)}
        ${list(t('trace.top_paths'), s.top_paths, true)}
        ${list(t('trace.top_waf'), s.waf_matches)}
        ${list(t('trace.top_signals'), s.threat_signals)}
        ${list(t('trace.top_countries'), s.countries)}
      </div>
      ${s.scan_limited ? `<p class="tr-meta" style="color:var(--orange,#d97706);margin-top:10px">${esc(t('trace.scan_limited'))}</p>` : ''}
    </div>`;
}

function trFormHTML() {
  const opt = p => `<option value="${p}"${_tr.period === p ? ' selected' : ''}>${esc(t('trace.period.' + p))}</option>`;
  return `<form class="tr-form" onsubmit="trSubmit(event)">
    <input id="tr-target" class="input tr-mono" placeholder="${esc(t('trace.placeholder'))}" value="${esc(_tr.target)}" autocomplete="off" spellcheck="false" style="flex:1;min-width:220px">
    <select id="tr-period" class="input" onchange="trPeriod(this.value)">${[...Object.keys(TR_PERIODS), 'custom'].map(opt).join('')}</select>
    <span id="tr-custom" style="display:${_tr.period === 'custom' ? 'inline-flex' : 'none'};gap:6px">
      <input id="tr-from" type="date" class="input" value="${esc(_tr.from)}"><input id="tr-to" type="date" class="input" value="${esc(_tr.to)}">
    </span>
    <button class="btn btn-primary" type="submit">${esc(t('trace.go'))}</button>
  </form>`;
}

function trPaint(body) {
  const content = document.getElementById('content');
  if (!content) return;
  content.innerHTML = `<div class="tr-page"><p class="tr-meta" style="margin:0 0 10px">${esc(t('trace.subtitle'))}</p>${trFormHTML()}${body}</div>`;
}

function trPaintResult() {
  const d = _tr.data;
  const order = `<button class="btn btn-ghost btn-sm" onclick="trToggleOrder()">${esc(t(_tr.order === 'desc' ? 'trace.order_desc' : 'trace.order_asc'))}</button>`;
  trPaint(`<h3 class="tr-title"><span class="tr-mono">${esc(d.target)}</span></h3>${trSummaryHTML()}
    <div class="card blueprint" style="padding:16px"><div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">
      <h4 style="margin:0">${esc(t('trace.timeline'))} <span class="tr-meta">(${d.total_steps})</span></h4>${order}</div>${trTimelineHTML()}</div>`);
}

async function trRun() {
  trPaint(`<p style="color:var(--text2)">${esc(t('common.loading'))}</p>`);
  try {
    _tr.data = await api('GET', trQuery(0));
    _tr.steps = _tr.data.steps;
    trPaintResult();
  } catch (e) { toast(e.message, 'error'); trPaint(''); }
}

window.trSubmit = function(ev) {
  ev.preventDefault();
  _tr.target = document.getElementById('tr-target').value.trim();
  _tr.from = document.getElementById('tr-from')?.value || '';
  _tr.to = document.getElementById('tr-to')?.value || '';
  if (_tr.target) trRun();
};

window.trPeriod = function(v) {
  _tr.period = v;
  const c = document.getElementById('tr-custom');
  if (c) c.style.display = v === 'custom' ? 'inline-flex' : 'none';
};

window.trToggleOrder = function() {
  _tr.order = _tr.order === 'desc' ? 'asc' : 'desc';
  trRun();
};

window.trLoadMore = async function() {
  try {
    const more = await api('GET', trQuery(_tr.steps.length));
    _tr.steps = _tr.steps.concat(more.steps);
    _tr.data = { ...more, summary: _tr.data.summary, steps: _tr.steps };
    trPaintResult();
  } catch (e) { toast(e.message, 'error'); }
};

// Ouvre le parcours d'une IP/CIDR depuis une autre page (liste des bans, historique d'une IP).
window.openIPTrace = function(target, period) {
  window._traceInit = { target, period };
  closeModal?.();
  navigate('security-trace');
};

pages['security-trace'] = () => {
  const ta = document.getElementById('topbar-actions');
  if (ta) ta.innerHTML = '';
  const init = window._traceInit;
  window._traceInit = null;
  if (init?.target) {
    Object.assign(_tr, { target: init.target, period: init.period || '90d' });
    return trRun();
  }
  if (_tr.data) return trPaintResult();
  trPaint(`<p class="tr-empty">${esc(t('trace.empty_hint'))}</p>`);
};
