// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"fmt"
	"slices"
)

// Catalogue des droits (ADR 0022, annexe §2) : les services de GoProxify, leurs niveaux cumulatifs et leurs
// permissions explicites. Chaque route, outil MCP et commande CLI déclare le service et la permission qu'elle exige
// (internal/admin/rights.go, internal/admin/mcp/rights.go, cmd/goproxify/rights.go) ; un test échoue pour toute
// route, tout outil ou toute commande sans déclaration. Le catalogue ne change aucun contrôle d'accès : il nomme ce
// que les livraisons suivantes feront appliquer.

// Nature dit si les permissions d'un service s'appliquent à une ressource bornée par un périmètre, ou à toute la plateforme.
type Nature string

const (
	NatureResource Nature = "resource"
	NaturePlatform Nature = "platform"
)

// Criterion est un critère de périmètre : un accès d'équipe combine ceux que son service accepte (ET).
type Criterion string

const (
	CriterionDomain  Criterion = "domain"
	CriterionProxy   Criterion = "proxy"
	CriterionBackend Criterion = "backend"
	CriterionGateway Criterion = "gateway"
	CriterionLabel   Criterion = "label"
)

// Class range les permissions : courante, destructive (dans « Gestion »), sensible (case à part, jamais impliquée
// par un niveau), ou réservée à la plateforme (écriture d'un objet partagé).
type Class string

const (
	ClassOrdinary    Class = "ordinary"
	ClassDestructive Class = "destructive"
	ClassSensitive   Class = "sensitive"
	ClassPlatform    Class = "platform"
)

// Level est un échelon d'un service ; les échelons sont cumulatifs de gauche à droite. PAT liste les scopes de jeton
// API actuels qui lui correspondent.
type Level struct {
	ID    string   `json:"id"`
	Label string   `json:"label"`
	Class Class    `json:"class"`
	PAT   []string `json:"pat,omitempty"`
}

// Explicit est une permission qu'aucun niveau n'implique.
type Explicit struct {
	ID    string   `json:"id"`
	Label string   `json:"label"`
	PAT   []string `json:"pat,omitempty"`
}

type Service struct {
	ID        string      `json:"id"`
	Label     string      `json:"label"`
	Group     string      `json:"group"`
	Nature    Nature      `json:"nature"`
	Criteria  []Criterion `json:"criteria,omitempty"`
	Levels    []Level     `json:"levels"`
	Explicits []Explicit  `json:"explicits"`
}

// Permission est une entrée du catalogue à plat : « service:niveau » ou une permission explicite.
type Permission struct {
	ID      string
	Service string
	Label   string
	Class   Class
	PAT     []string
}

const (
	GroupTraffic       = "trafic"
	GroupObservability = "observabilite"
	GroupSecurity      = "securite"
	GroupPlatform      = "plateforme"
	GroupPortal        = "portail"
	GroupAdmin         = "administration"
	GroupGDPR          = "rgpd"
)

var (
	allCriteria   = []Criterion{CriterionDomain, CriterionProxy, CriterionBackend, CriterionGateway, CriterionLabel}
	byDomain      = []Criterion{CriterionDomain}
	byGateway     = []Criterion{CriterionGateway}
	byDomainGate  = []Criterion{CriterionDomain, CriterionGateway}
	byProxy       = []Criterion{CriterionProxy, CriterionDomain, CriterionLabel}
	byContainer   = []Criterion{CriterionDomain, CriterionBackend, CriterionGateway}
	byPortalAsset = []Criterion{CriterionGateway, CriterionLabel}
)

func lvl(id, label string, pat ...string) Level {
	return Level{ID: id, Label: label, Class: ClassOrdinary, PAT: pat}
}
func gestion(id, label string, pat ...string) Level {
	return Level{ID: id, Label: label, Class: ClassDestructive, PAT: pat}
}
func platformWrite(pat ...string) Level {
	return Level{ID: "write", Label: "Écriture (plateforme)", Class: ClassPlatform, PAT: pat}
}
func exp(id, label string, pat ...string) Explicit { return Explicit{ID: id, Label: label, PAT: pat} }

// Services est le catalogue, dans l'ordre d'affichage de la grille d'équipe.
var Services = []Service{
	// Trafic
	{ID: "proxies", Label: "Proxys et routage", Group: GroupTraffic, Nature: NatureResource, Criteria: allCriteria,
		Levels:    []Level{lvl("read", "Lecture", ScopeProxiesRead), lvl("operate", "Exploitation", ScopeProxiesWrite), gestion("manage", "Gestion", ScopeProxiesDelete)},
		Explicits: []Explicit{exp("proxies:import", "Import de configuration tierce", ScopeImportWrite, ScopeAuditRead)}},
	{ID: "proxy_sections", Label: "Proxys : affiner par section", Group: GroupTraffic, Nature: NatureResource, Criteria: byProxy,
		Levels:    []Level{lvl("read", "Lecture"), lvl("edit", "Modification")},
		Explicits: []Explicit{exp("proxy_sections:plugins", "Plugins WASM d'une route")}},
	{ID: "containers", Label: "Conteneurs découverts", Group: GroupTraffic, Nature: NatureResource, Criteria: byContainer,
		Levels: []Level{lvl("read", "Lecture", ScopeNodesRead, ScopeProxiesRead), lvl("operate", "Exploitation", ScopeProxiesWrite, ScopeNodesWrite)}},
	{ID: "surface", Label: "Surface applicative", Group: GroupTraffic, Nature: NatureResource, Criteria: byProxy,
		Levels:    []Level{lvl("read", "Lecture", ScopeAuditRead), lvl("learn", "Apprentissage", ScopeSecurityWrite)},
		Explicits: []Explicit{exp("surface:enforce", "Passage en block", ScopeSecurityWrite)}},
	{ID: "domains", Label: "Domaines", Group: GroupTraffic, Nature: NatureResource, Criteria: byDomain,
		Levels:    []Level{lvl("read", "Lecture", ScopeDomainsRead), gestion("manage", "Gestion", ScopeDomainsWrite)},
		Explicits: []Explicit{exp("domains:delegate", "Délégation de domaine", ScopeDomainsWrite)}},
	{ID: "certs", Label: "Certificats", Group: GroupTraffic, Nature: NatureResource, Criteria: byDomain,
		Levels: []Level{lvl("read", "Lecture", ScopeCertsRead), gestion("manage", "Gestion", ScopeCertsWrite)},
		Explicits: []Explicit{exp("certs:deploy", "Déploiement (webhook, ssh_exec)", ScopeCertsWrite),
			exp("certs:export_key", "Export de clé privée et jetons de récupération", ScopeCertsWrite)}},
	{ID: "domain_watch", Label: "Surveillance des domaines", Group: GroupTraffic, Nature: NatureResource, Criteria: byDomain,
		Levels:    []Level{lvl("read", "Lecture", ScopeAuditRead), lvl("ack", "Acquittement", ScopeSecurityWrite)},
		Explicits: []Explicit{exp("domain_watch:configure", "Configuration (envoie des noms à l'extérieur)", ScopeSecurityWrite)}},

	// Observabilité
	{ID: "logs", Label: "Logs d'accès", Group: GroupObservability, Nature: NatureResource, Criteria: byDomainGate,
		Levels: []Level{lvl("read", "Lecture", ScopeLogsRead), lvl("export", "Export", ScopeLogsWrite)}},
	{ID: "system_logs", Label: "Logs système et conteneurs", Group: GroupObservability, Nature: NatureResource, Criteria: byGateway,
		Levels: []Level{lvl("read", "Lecture", ScopeLogsRead)}},
	{ID: "dashboard", Label: "Tableau de bord, Prism, métriques, carte", Group: GroupObservability, Nature: NatureResource, Criteria: byDomainGate,
		Levels: []Level{lvl("read", "Lecture", ScopeMetricsRead, ScopeLogsRead), lvl("manage", "Gestion (objectif de disponibilité)", ScopeMetricsRead)}},
	{ID: "alerts", Label: "Alertes", Group: GroupObservability, Nature: NatureResource, Criteria: byDomainGate,
		Levels: []Level{lvl("read", "Lecture", ScopeAlertsRead), lvl("ack", "Acquittement", ScopeAlertsWrite), lvl("rules", "Gestion des règles", ScopeAlertsWrite)}},
	{ID: "alert_channels", Label: "Canaux de notification", Group: GroupObservability, Nature: NaturePlatform,
		Levels:    []Level{lvl("read", "Lecture", ScopeAlertsRead), gestion("manage", "Gestion", ScopeAlertsWrite)},
		Explicits: []Explicit{exp("alert_channels:test", "Message de test vers l'extérieur", ScopeAlertsWrite)}},
	{ID: "audit", Label: "Journal d'audit", Group: GroupObservability, Nature: NaturePlatform,
		Levels: []Level{lvl("read", "Lecture", ScopeAuditRead)}},

	// Sécurité
	{ID: "netsec", Label: "Sécurité réseau", Group: GroupSecurity, Nature: NatureResource, Criteria: []Criterion{CriterionGateway, CriterionProxy, CriterionDomain},
		Levels:    []Level{lvl("read", "Lecture", ScopeAuditRead), lvl("analyse", "Analyse", ScopeLogsRead), lvl("respond", "Réponse", ScopeSecurityWrite)},
		Explicits: []Explicit{exp("bans:import", "Import de bannissements en masse", ScopeSecurityWrite)}},
	{ID: "engines", Label: "Moteurs adaptatifs (WAF, Ephor)", Group: GroupSecurity, Nature: NatureResource, Criteria: byGateway,
		Levels:    []Level{lvl("read", "Lecture", ScopeAuditRead), lvl("simulate", "Simulation", ScopeLogsRead), lvl("tune", "Réglage", ScopeSecurityWrite)},
		Explicits: []Explicit{exp("engines:enforce", "Passage d'un signal en block", ScopeSecurityWrite)}},
	{ID: "attack_ref", Label: "Référentiel des attaques", Group: GroupSecurity, Nature: NaturePlatform,
		Levels: []Level{lvl("read", "Lecture (dossiers par IP bannie, entrées)", ScopeAuditRead), platformWrite(ScopeSecurityWrite)}},
	{ID: "snippets", Label: "Snippets et détecteurs", Group: GroupSecurity, Nature: NaturePlatform,
		Levels: []Level{lvl("read", "Lecture", ScopeSnippetsRead), platformWrite(ScopeSnippetsWrite)}},
	{ID: "ip_profiles", Label: "Profils IP", Group: GroupSecurity, Nature: NaturePlatform,
		Levels: []Level{lvl("read", "Lecture", ScopeAuditRead), platformWrite(ScopeSecurityWrite)}},
	{ID: "auth_providers", Label: "Fournisseurs d'authentification", Group: GroupSecurity, Nature: NaturePlatform,
		Levels: []Level{lvl("read", "Lecture", ScopeAuditRead), platformWrite(ScopeSecurityWrite)}},
	{ID: "error_pages", Label: "Modèles de pages d'erreur", Group: GroupSecurity, Nature: NaturePlatform,
		Levels: []Level{lvl("read", "Lecture"), platformWrite()}},

	// Plateforme
	{ID: "infra", Label: "Infrastructure", Group: GroupPlatform, Nature: NatureResource, Criteria: byGateway,
		Levels: []Level{lvl("read", "Lecture", ScopeNodesRead), lvl("classify", "Classement", ScopeNodesWrite)},
		Explicits: []Explicit{exp("nodes:approve", "Approuver une passerelle ou un Agent", ScopeNodesWrite),
			exp("nodes:update", "Mise à jour ou retour arrière d'une passerelle", ScopeNodesWrite),
			exp("nodes:configure", "Configuration d'une passerelle", ScopeNodesWrite),
			exp("nodes:delete", "Suppression d'une passerelle", ScopeNodesWrite),
			exp("enrol:create", "Billets d'enrôlement et secret d'appairage", ScopePairingRead, ScopeNodesWrite),
			exp("architecture:write", "Nœuds déclarés et assistant d'architecture", ScopeNodesWrite)}},
	{ID: "gateway_scope", Label: "Périmètre des passerelles", Group: GroupPlatform, Nature: NatureResource, Criteria: byGateway,
		Levels: []Level{lvl("read", "Lecture", ScopeNodesRead)},
		Explicits: []Explicit{exp("tokens:manage", "Jetons d'appairage et routes servies", ScopeUsersRead),
			exp("tokens:rotate", "Rotation de jeton")}},
	{ID: "ha", Label: "Haute disponibilité", Group: GroupPlatform, Nature: NatureResource, Criteria: byGateway,
		Levels: []Level{lvl("read", "Lecture", ScopeNodesRead), platformWrite(ScopeNodesWrite)}},
	{ID: "gateway_settings", Label: "Réglages de la passerelle", Group: GroupPlatform, Nature: NatureResource, Criteria: byGateway,
		Levels:    []Level{lvl("read", "Lecture", ScopeNodesRead), lvl("tune", "Réglage", ScopeNodesWrite)},
		Explicits: []Explicit{exp("nodes:tunnel", "Tunnel mTLS entre passerelles", ScopeNodesWrite)}},
	{ID: "discovery", Label: "Sources de découverte", Group: GroupPlatform, Nature: NatureResource, Criteria: byGateway,
		Levels:    []Level{lvl("read", "Lecture", ScopeNodesRead)},
		Explicits: []Explicit{exp("discovery:write", "Accès à un orchestrateur", ScopeNodesWrite)}},
	{ID: "automation", Label: "Automatisation", Group: GroupPlatform, Nature: NaturePlatform,
		Levels: []Level{lvl("read", "Lecture", ScopeAuditRead), lvl("edit", "Édition", ScopeSecurityWrite)},
		Explicits: []Explicit{exp("automation:run", "Exécuter des actions", ScopeSecurityWrite),
			exp("automation:approve", "Décider une exécution en attente", ScopeSecurityWrite)}},

	// Portail Access
	{ID: "portal_requests", Label: "Portail : demandes d'accès temporaires", Group: GroupPortal, Nature: NatureResource, Criteria: byPortalAsset,
		Levels: []Level{lvl("read", "Lecture", ScopePortalRead), lvl("decide", "Décision", ScopePortalWrite)}},
	{ID: "portal_sessions", Label: "Portail : sessions en direct", Group: GroupPortal, Nature: NatureResource, Criteria: byPortalAsset,
		Levels:    []Level{lvl("read", "Lecture", ScopePortalRead), lvl("cut", "Coupure", ScopePortalWrite)},
		Explicits: []Explicit{exp("portal_sessions:observe", "Sortie du terminal en direct", ScopePortalWrite)}},
	{ID: "portal_recordings", Label: "Portail : enregistrements", Group: GroupPortal, Nature: NatureResource, Criteria: byPortalAsset,
		Levels: []Level{lvl("list", "Liste", ScopePortalRead)},
		Explicits: []Explicit{exp("portal_recordings:replay", "Rejeu du contenu", ScopePortalWrite),
			exp("portal_recordings:delete", "Suppression", ScopePortalWrite)}},
	{ID: "portal_catalog", Label: "Portail : catalogue", Group: GroupPortal, Nature: NatureResource, Criteria: byPortalAsset,
		Levels:    []Level{lvl("read", "Lecture", ScopePortalRead), gestion("manage", "Gestion", ScopePortalWrite)},
		Explicits: []Explicit{exp("portal_catalog:sources", "Sources de destinations : identifiants d'API des fournisseurs", ScopePortalWrite)}},
	{ID: "portal_users", Label: "Portail : utilisateurs et groupes", Group: GroupPortal, Nature: NatureResource, Criteria: byPortalAsset,
		Levels: []Level{lvl("read", "Lecture", ScopePortalRead), gestion("manage", "Gestion", ScopePortalWrite)}},
	{ID: "portal_policies", Label: "Portail : politiques", Group: GroupPortal, Nature: NatureResource, Criteria: byPortalAsset,
		Levels: []Level{lvl("read", "Lecture", ScopePortalRead), lvl("manage", "Gestion", ScopePortalWrite)}},
	{ID: "portal_audit", Label: "Portail : audit", Group: GroupPortal, Nature: NatureResource, Criteria: byPortalAsset,
		Levels: []Level{lvl("read", "Lecture", ScopePortalRead)}},
	{ID: "portal_templates", Label: "Portail : modèles, réglages, poussée", Group: GroupPortal, Nature: NatureResource, Criteria: byPortalAsset,
		Levels: []Level{lvl("read", "Lecture", ScopePortalRead), lvl("manage", "Gestion", ScopePortalWrite)}},

	// Administration (plateforme, aucun périmètre)
	{ID: "backups", Label: "Sauvegardes", Group: GroupAdmin, Nature: NaturePlatform,
		Levels: []Level{lvl("list", "Liste", ScopeBackupsRead)},
		Explicits: []Explicit{exp("backups:create", "Créer une sauvegarde", ScopeBackupsRead),
			exp("backups:restore", "Restaurer (remplace tout)", ScopeBackupsRead)}},
	{ID: "pki", Label: "Autorité interne, ECH, ACME et clés DNS", Group: GroupAdmin, Nature: NaturePlatform,
		Levels:    []Level{lvl("read", "Lecture", ScopeCertsRead)},
		Explicits: []Explicit{exp("pki:write", "Clés de signature et identifiants DNS", ScopeCertsWrite)}},
	{ID: "plugins", Label: "Plugins WASM", Group: GroupAdmin, Nature: NaturePlatform,
		Levels:    []Level{lvl("read", "Lecture", ScopeAuditRead)},
		Explicits: []Explicit{exp("plugins:write", "Code exécuté dans le plan de données", ScopeSecurityWrite)}},
	{ID: "logs_settings", Label: "Réglages des logs, SIEM", Group: GroupAdmin, Nature: NaturePlatform,
		Levels: []Level{lvl("read", "Lecture", ScopeLogsRead)},
		Explicits: []Explicit{exp("logs_settings:write", "Réglages des logs", ScopeLogsWrite),
			exp("siem:write", "Jetons et adresses SIEM", ScopeLogsWrite)}},
	{ID: "accounts", Label: "Comptes, équipes, accès MCP", Group: GroupAdmin, Nature: NaturePlatform,
		Levels: []Level{lvl("read", "Lecture", ScopeUsersRead, ScopeTeamsRead)},
		Explicits: []Explicit{exp("users:write", "Gestion des comptes", ScopeUsersRead),
			exp("teams:write", "Accorder des droits", ScopeTeamsRead)}},
	{ID: "settings", Label: "Paramètres", Group: GroupAdmin, Nature: NaturePlatform,
		Levels:    []Level{lvl("read", "Lecture")},
		Explicits: []Explicit{exp("settings:write", "MFA, SMTP, adresse publique, apparence")}},

	// RGPD : quatre capacités, pas de niveaux
	{ID: "gdpr", Label: "RGPD (équipe intégrée DPO)", Group: GroupGDPR, Nature: NaturePlatform,
		Explicits: []Explicit{
			exp(PermGDPRReveal, "Révéler l'IP réelle", ScopeGDPRReveal),
			exp(PermGDPRExport, "Export d'accès et de portabilité", ScopeGDPRExport),
			exp(PermGDPRErase, "Effacement par IP ou par utilisateur", ScopeGDPRErase),
			exp(PermGDPRHold, "Gel légal et export signé")}},
}

// Permissions déplie le catalogue : « service:niveau » pour chaque niveau, puis les permissions explicites.
func Permissions() []Permission {
	var out []Permission
	for _, s := range Services {
		for _, l := range s.Levels {
			out = append(out, Permission{ID: s.ID + ":" + l.ID, Service: s.ID, Label: l.Label, Class: l.Class, PAT: l.PAT})
		}
		for _, e := range s.Explicits {
			out = append(out, Permission{ID: e.ID, Service: s.ID, Label: e.Label, Class: ClassSensitive, PAT: e.PAT})
		}
	}
	return out
}

// PermissionByID cherche une permission du catalogue.
func PermissionByID(id string) (Permission, bool) {
	for _, p := range Permissions() {
		if p.ID == id {
			return p, true
		}
	}
	return Permission{}, false
}

// ServiceByID cherche un service du catalogue.
func ServiceByID(id string) (Service, bool) {
	for _, s := range Services {
		if s.ID == id {
			return s, true
		}
	}
	return Service{}, false
}

// CoversPATScope dit si la permission correspond au scope de jeton donné ; une permission sans scope n'a pas de
// jeton équivalent aujourd'hui.
func (p Permission) CoversPATScope(scope string) bool { return slices.Contains(p.PAT, scope) }

// ValidateCatalog vérifie la cohérence interne du catalogue : identifiants uniques, périmètre déclaré pour une
// ressource et absent pour la plateforme, et chaque scope de jeton rattaché à une permission.
func ValidateCatalog() error {
	seenService := map[string]bool{}
	seenPerm := map[string]string{}
	for _, s := range Services {
		if s.ID == "" || s.Label == "" || s.Group == "" {
			return fmt.Errorf("service %q : identifiant, libellé et groupe obligatoires", s.ID)
		}
		if seenService[s.ID] {
			return fmt.Errorf("service %q déclaré deux fois", s.ID)
		}
		seenService[s.ID] = true
		switch s.Nature {
		case NatureResource:
			if len(s.Criteria) == 0 {
				return fmt.Errorf("service %q : une ressource déclare les critères de périmètre qu'elle accepte", s.ID)
			}
		case NaturePlatform:
			if len(s.Criteria) > 0 {
				return fmt.Errorf("service %q : un service de plateforme n'a pas de périmètre", s.ID)
			}
		default:
			return fmt.Errorf("service %q : nature %q inconnue", s.ID, s.Nature)
		}
		if len(s.Levels) == 0 && len(s.Explicits) == 0 {
			return fmt.Errorf("service %q : aucun niveau ni permission", s.ID)
		}
	}
	for _, p := range Permissions() {
		if prev, dup := seenPerm[p.ID]; dup {
			return fmt.Errorf("permission %q déclarée par %q et %q", p.ID, prev, p.Service)
		}
		seenPerm[p.ID] = p.Service
	}
	for _, scope := range AllPATScopes {
		covered := false
		for _, p := range Permissions() {
			if p.CoversPATScope(scope) {
				covered = true
				break
			}
		}
		if !covered {
			return fmt.Errorf("le scope de jeton %q ne correspond à aucune permission du catalogue", scope)
		}
	}
	return nil
}
