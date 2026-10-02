// ── Recherche de fonctionnalités (Ctrl/Cmd+K ou « / ») ──────────────────────────
// Index construit à l'exécution : titres de pages (APP_CONFIG.pageTitles, traduits
// via gpxPageLabel) + mots-clés (APP_CONFIG.searchKeywords). Les pages réservées aux
// admins ou nécessitant une passerelle sont filtrées / redirigées comme dans la nav.

const SEARCH_NO_ADMIN_GUARD = new Set(['snippets', 'api-tokens', 'prism', 'proxy-inspector', 'profile']);

let _searchResults = [];
let _searchSel = 0;
let _searchPendingPage = null;

function _searchNorm(s) {
  return String(s || '').toLowerCase().normalize('NFD').replace(/[̀-ͯ]/g, '');
}

function _searchNeedsEdge(page) {
  return EDGE_PAGES.has(page) && !SETTINGS_PAGES.has(page);
}

function _searchNavMeta() {
  const meta = {};
  const walk = (items, scope) => (items || []).forEach(it => {
    meta[it.page] = meta[it.page] || { guard: it.guard, scope };
    (it.children || []).forEach(c => {
      meta[c.page] = meta[c.page] || { guard: c.guard || it.guard, scope, parent: it.labelPage || it.page };
    });
  });
  walk(APP_CONFIG.nav, 'admin');
  walk(APP_CONFIG.edgeNav, 'edge');
  (APP_CONFIG.pageTabs || []).forEach(g => g.tabs.forEach(tab => {
    meta[tab.page] = meta[tab.page] || {};
    if (tab.page !== g.root) meta[tab.page].parent = meta[tab.page].parent || g.root;
  }));
  return meta;
}

function _searchIndex() {
  const titles = APP_CONFIG.pageTitles || {};
  const kw = APP_CONFIG.searchKeywords || {};
  const meta = _searchNavMeta();
  const user = state.user;
  const hasEdge = !!state.selectedEdge;
  const entries = [];
  Object.keys(titles).forEach(page => {
    if (typeof pages === 'undefined' || !pages[page] || page === 'architecture') return;
    const m = meta[page] || {};
    const needsEdge = _searchNeedsEdge(page);
    if (m.guard) {
      const ok = m.scope === 'edge'
        ? m.guard({ hasEdgeScope: state.selectedEdge ? Role.hasEdgeScope(state.selectedEdge.node_name || state.selectedEdge.id || '') : Role.isAdmin() })
        : m.guard(user);
      if (!ok) return;
    } else if (SETTINGS_PAGES.has(page) && !needsEdge && !SEARCH_NO_ADMIN_GUARD.has(page) && !Role.isAdmin()) {
      return;
    }
    const label = gpxPageLabel(page, titles[page]);
    const parentLabel = m.parent ? gpxPageLabel(m.parent, titles[m.parent]) : '';
    entries.push({
      page, label, needsEdge, hasEdge,
      group: parentLabel,
      scope: needsEdge ? 'edge' : 'admin',
      norm: _searchNorm(label),
      hay: _searchNorm([label, parentLabel, page, kw[page] || ''].join(' ')),
    });
  });
  return entries;
}

function _searchScore(e, tokens, whole) {
  let score = 0;
  if (e.norm === whole) score += 100;
  else if (e.norm.startsWith(whole)) score += 60;
  else if (e.norm.includes(whole)) score += 40;
  for (const tk of tokens) {
    if (!e.hay.includes(tk)) return -1;
    score += e.norm.includes(tk) ? 10 : 3;
  }
  if (e.needsEdge && !e.hasEdge) score -= 1;
  return score;
}

function _searchRun(q) {
  const entries = _searchIndex();
  const whole = _searchNorm(q).trim();
  if (!whole) {
    return entries.filter(e => e.scope === (state.selectedEdge ? 'edge' : 'admin')).slice(0, 12);
  }
  const tokens = whole.split(/\s+/);
  return entries
    .map(e => ({ e, s: _searchScore(e, tokens, whole) }))
    .filter(x => x.s >= 0)
    .sort((a, b) => b.s - a.s || a.e.label.localeCompare(b.e.label))
    .slice(0, 30)
    .map(x => x.e);
}

function _searchRender() {
  const list = document.getElementById('search-list');
  if (!list) return;
  if (_searchPendingPage) {
    const edges = window._navEdges || [];
    list.innerHTML = `<div class="search-section">${esc(t('search.pick_edge'))}</div>` + edges.map((c, i) => `
      <div class="search-item${i === _searchSel ? ' active' : ''}" data-i="${i}" onmousemove="searchHover(${i})" onclick="searchPickEdge(${i})">
        <span class="space-dot-inline ${c.status === 'online' ? 'online' : 'offline'}" aria-hidden="true"></span>
        <span class="search-item-label">${esc(c.display_name || c.node_name || c.id || '—')}</span>
      </div>`).join('');
    return;
  }
  if (!_searchResults.length) {
    list.innerHTML = `<div class="search-empty">${esc(t('search.empty'))}</div>`;
    return;
  }
  list.innerHTML = _searchResults.map((e, i) => `
    <div class="search-item${i === _searchSel ? ' active' : ''}" data-i="${i}" role="option" onmousemove="searchHover(${i})" onclick="searchOpen(${i})">
      <span class="search-item-label">${esc(e.label)}</span>
      ${e.group ? `<span class="search-item-group">${esc(e.group)}</span>` : ''}
      <span class="search-badge ${e.scope}">${esc(t('search.scope.' + e.scope))}</span>
    </div>`).join('');
  list.querySelector('.search-item.active')?.scrollIntoView({ block: 'nearest' });
}

function _searchCount() {
  return _searchPendingPage ? (window._navEdges || []).length : _searchResults.length;
}

window.openSearch = function() {
  if (!state.token) return;
  const box = document.getElementById('search-modal');
  if (!box) return;
  _searchPendingPage = null;
  box.hidden = false;
  const input = document.getElementById('search-input');
  input.value = '';
  _searchResults = _searchRun('');
  _searchSel = 0;
  _searchRender();
  input.focus();
};

window.closeSearch = function() {
  const box = document.getElementById('search-modal');
  if (box) box.hidden = true;
  _searchPendingPage = null;
};

window.searchInput = function(q) {
  _searchPendingPage = null;
  _searchResults = _searchRun(q);
  _searchSel = 0;
  _searchRender();
};

window.searchHover = function(i) {
  if (i === _searchSel) return;
  _searchSel = i;
  document.querySelectorAll('#search-list .search-item').forEach((el, j) => el.classList.toggle('active', j === i));
};

window.searchOpen = function(i) {
  const e = _searchResults[i];
  if (!e) return;
  if (e.needsEdge && !state.selectedEdge) {
    const edges = window._navEdges || [];
    if (!edges.length) { toast(t('common.edges_none'), 'error'); return; }
    if (edges.length === 1) { closeSearch(); selectEdge(edges[0], e.page); return; }
    _searchPendingPage = e.page;
    _searchSel = 0;
    _searchRender();
    return;
  }
  closeSearch();
  navigate(e.page);
};

window.searchPickEdge = function(i) {
  const edge = (window._navEdges || [])[i];
  const page = _searchPendingPage;
  if (!edge || !page) return;
  closeSearch();
  selectEdge(edge, page);
};

function _searchKeydown(e) {
  const box = document.getElementById('search-modal');
  const open = box && !box.hidden;
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    if (!state.token) return;
    e.preventDefault();
    open ? closeSearch() : openSearch();
    return;
  }
  if (!open) {
    const tag = (e.target.tagName || '').toLowerCase();
    const typing = tag === 'input' || tag === 'textarea' || tag === 'select' || e.target.isContentEditable;
    if (e.key === '/' && !typing && !e.ctrlKey && !e.metaKey && !e.altKey) {
      e.preventDefault();
      openSearch();
    }
    return;
  }
  const n = _searchCount();
  if (e.key === 'Escape') { e.preventDefault(); e.stopPropagation(); closeSearch(); }
  else if (e.key === 'ArrowDown' && n) { e.preventDefault(); searchHover((_searchSel + 1) % n); document.querySelector('#search-list .search-item.active')?.scrollIntoView({ block: 'nearest' }); }
  else if (e.key === 'ArrowUp' && n) { e.preventDefault(); searchHover((_searchSel - 1 + n) % n); document.querySelector('#search-list .search-item.active')?.scrollIntoView({ block: 'nearest' }); }
  else if (e.key === 'Enter' && n) { e.preventDefault(); _searchPendingPage ? searchPickEdge(_searchSel) : searchOpen(_searchSel); }
}

document.addEventListener('keydown', _searchKeydown, true);
