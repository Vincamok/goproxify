// ── État global de l'application ───────────────────────────────────────────
const state = {
  token:        localStorage.getItem('gpx_token') || '',
  page:         'dashboard',
  selectedEdge: null,
  user:         null, // rempli après login : { id, email, role, is_super, teams, granted, permissions }
  timezone:     localStorage.getItem('gpx_tz') || '', // IANA (ex. Europe/Paris) — sync via /health
};

// ── Helpers de rôle (utilisent state.user) ────────────────────────────────
const Role = {
  isSuperAdmin: () => state.user?.role === 'superadmin',
  isAdmin:      () => state.user?.role === 'admin' || state.user?.role === 'superadmin',
  isOperator:   () => ['superadmin','admin','operator'].includes(state.user?.role),
  isViewer:     () => !!state.user,

  // Un administrateur voit toute la plateforme : ses équipes ne le limitent jamais (ADR 0021).
  isGlobalAdmin: () => Role.isAdmin(),

  // L'utilisateur peut-il supprimer ?
  canDelete: () => Role.isAdmin(),

  // L'utilisateur peut-il écrire (créer/modifier/désactiver) ?
  canWrite: () => Role.isOperator(),

  // RGPD : révéler l'IP réelle d'une entrée pseudonymisée (superadmin ou membre d'une équipe qui porte gdpr:reveal, ex. l'équipe DPO).
  canRevealIP: () => (state.user?.permissions || []).includes('gdpr:reveal'),

  // Snippets : admin, ou user dont une équipe donne l'exploitation des proxys (rbac.RequireOperator côté API).
  canWriteSnippets: () => Role.isAdmin() || (state.user?.granted || []).includes('proxies:operate'),

  // Les droits se donnent sur des groupes de passerelles (ADR 0022), que le navigateur ne résout pas : l'API fait le
  // filtrage fin, la navigation montre les passerelles à qui a un droit de lecture sur l'infrastructure ou les proxys.
  hasEdgeScope: () => Role.hasAccessToEdge(),

  hasAccessToEdge: () => {
    if (Role.isGlobalAdmin() || Role.isSuperAdmin()) return true;
    const granted = state.user?.granted || [];
    return granted.includes('infra:read') || granted.includes('proxies:read');
  },
};
