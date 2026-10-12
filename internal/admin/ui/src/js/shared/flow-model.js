// ── Flux d'automatisation : catalogue et résumés ──────────────────────────────────────────────
// Le catalogue (GET /automation/catalog) décrit déclencheurs, conditions, actions et types d'étape par
// leurs manifestes : l'éditeur, les listes et les modèles s'en servent au lieu de listes écrites ici. Un
// module ajouté côté serveur apparaît donc partout sans modifier le JavaScript.

const FlowCatalog = (() => {
  let cache = null;
  let pending = null;

  async function load(force) {
    if (cache && !force) return cache;
    if (!pending || force) {
      pending = api('GET', '/automation/catalog').then(c => { cache = c || {}; return cache; }).finally(() => { pending = null; });
    }
    return pending;
  }

  const list = name => (cache && cache[name]) || [];
  const find = (name, type) => list(name).find(m => m.type === type);
  const label = (name, type) => find(name, type)?.label || type || '';
  const eventLabel = type => list('events').find(e => e.type === type)?.label || type || '';

  // Texte d'une condition (arbre et / ou / non).
  function condText(c) {
    if (!c) return '';
    if (c.all?.length) return c.all.map(condText).join(` ${t('flow.and')} `);
    if (c.any?.length) return '(' + c.any.map(condText).join(` ${t('flow.or')} `) + ')';
    if (c.not) return `${t('flow.not')} ${condText(c.not)}`;
    return label('conditions', c.type);
  }

  function triggerText(f) {
    const tr = f?.trigger || {};
    switch (tr.kind) {
      case 'condition': return condText(tr.condition);
      case 'event': return t('flow.on_event', { event: eventLabel(tr.event?.event) });
      case 'schedule': return t('flow.at_cron', { cron: tr.schedule?.cron || '' });
      case 'manual': return t('flow.manual_trigger');
    }
    // Ancien format (règle : condition à plat).
    return label('conditions', f?.condition?.type) || '';
  }

  function stepText(st) {
    if (st.type === 'action') return label('actions', st.action?.type);
    if (st.type === 'if') return `${t('flow.if')} ${condText(st.condition)}`;
    return label('steps', st.type);
  }

  function stepsText(steps) {
    return (steps || []).map(stepText).join(' → ');
  }

  function walk(steps, fn) {
    (steps || []).forEach(st => { fn(st); walk(st.then, fn); walk(st.else, fn); });
  }

  function hasApproval(f) {
    let found = false;
    walk(f?.steps, st => { if (st.type === 'approval') found = true; });
    return found;
  }

  function newStepId(f) {
    const used = new Set();
    walk(f?.steps, st => used.add(st.id));
    for (let n = 1; ; n++) if (!used.has('s' + n)) return 's' + n;
  }

  // Sorties d'un déclencheur : variables {{detail.x}}.
  function triggerOutputs(f) {
    const tr = f?.trigger || {};
    const out = new Set();
    const leaves = c => {
      if (!c) return;
      (c.all || []).forEach(leaves);
      (c.any || []).forEach(leaves);
      leaves(c.not);
      if (c.type) (find('conditions', c.type)?.attrs?.outputs || []).forEach(o => out.add(o));
    };
    if (tr.kind === 'condition') leaves(tr.condition);
    if (tr.kind === 'event') (list('events').find(e => e.type === tr.event?.event)?.outputs || []).forEach(o => out.add(o));
    if (tr.kind === 'schedule') out.add('scheduled_at');
    if (tr.kind === 'manual') (tr.manual?.inputs || []).forEach(i => out.add(i.key));
    return [...out];
  }

  function stepOutputs(st) {
    if (st.type === 'action') return find('actions', st.action?.type)?.attrs?.outputs || [];
    if (st.type === 'if') {
      const out = new Set(['matched']);
      const leaves = c => { if (!c) return; (c.all || []).forEach(leaves); (c.any || []).forEach(leaves); if (c.type) (find('conditions', c.type)?.attrs?.outputs || []).forEach(o => out.add(o)); };
      leaves(st.condition);
      return [...out];
    }
    return find('steps', st.type)?.attrs?.outputs || [];
  }

  // Variables disponibles pour l'étape stepId : sorties du déclencheur, des étapes exécutées avant elle
  // (pas celles d'une branche refermée), du « si » qui la contient, et du flux.
  function variablesAt(f, stepId) {
    const vars = triggerOutputs(f).map(o => 'detail.' + o);
    const visit = (steps, avail) => {
      for (const st of steps || []) {
        if (st.id === stepId) return avail;
        if (st.type === 'if') {
          const inner = avail.concat(stepOutputs(st).map(o => `steps.${st.id}.${o}`));
          const found = visit(st.then, inner) || visit(st.else, inner);
          if (found) return found;
        }
        avail = avail.concat(stepOutputs(st).map(o => `steps.${st.id}.${o}`));
      }
      return null;
    };
    return vars.concat(visit(f?.steps, []) || [], list('variables'));
  }

  // Les listes à source dynamique des formulaires (proxies, nœuds, playbooks…) viennent de l'API.
  // Les métriques que chaque passerelle calcule aussi portent une marque : un flux qui en surveille une peut
  // s'exécuter sur les passerelles.
  if (window.ManifestForm) ManifestForm.setOptionsLoader(async src => {
    const opts = await api('GET', '/automation/options/' + encodeURIComponent(src));
    if (src !== 'metrics' || !Array.isArray(opts)) return opts;
    const edge = new Set(list('metrics').filter(m => m.edge).map(m => m.key));
    return opts.map(o => edge.has(o.value) ? { ...o, label: `${o.label} · ${t('flow.metric_edge_mark')}` } : o);
  });

  return { load, list, find, label, eventLabel, condText, triggerText, stepText, stepsText, hasApproval, newStepId, walk, variablesAt, triggerOutputs };
})();
window.FlowCatalog = FlowCatalog;

// Badges communs aux listes et à l'éditeur.
function flowPlacementBadge(f) {
  if (!f?.placement) return '';
  const edge = f.placement === 'edge';
  return `<span class="tag ${edge ? 'tag-green' : 'tag-neutral'}" style="font-size:10px" title="${esc(edge ? t('flow.placement_edge_hint') : (f.placement_reason || ''))}">${edge ? t('flow.placement_edge') : t('flow.placement_admin')}</span>`;
}

function flowRunStatusTag(status) {
  const cls = { completed: 'tag-green', failed: 'tag-red', interrupted: 'tag-red', rejected: 'tag-yellow', cancelled: 'tag-neutral',
    stopped: 'tag-neutral', silenced: 'tag-neutral', running: 'tag-blue', waiting: 'tag-blue', waiting_approval: 'tag-accent', waiting_child: 'tag-blue' }[status] || 'tag-neutral';
  return `<span class="tag ${cls}" style="font-size:10px">${esc(t('flow.status_' + status))}</span>`;
}

// Différences entre deux versions d'un flux (champ changes des versions et de l'aperçu d'un modèle).
function flowChangesHTML(changes) {
  if (!changes?.length) return `<div class="fl-help">${t('flow.ch_none')}</div>`;
  const what = d => FlowCatalog.find('actions', d)?.label || FlowCatalog.find('steps', d)?.label || d || '';
  const key = c => c.kind === 'enabled' ? 'flow.ch_enabled_' + c.detail : 'flow.ch_' + c.kind;
  return `<ul class="fl-changes">${changes.map(c => `<li>${esc(t(key(c), {
    step: c.step_id || '', what: what(c.detail), detail: c.detail || '',
  }))}</li>`).join('')}</ul>`;
}
