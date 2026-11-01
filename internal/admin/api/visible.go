// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// Les handlers de lecture filtrent ce qu'ils renvoient d'après les accès de l'appelant (ADR 0022). La garde
// (rbac.Gate) a rangé l'appelant dans le contexte ; sans garde (appel direct, test), rien n'est restreint.

// visibility rend ce que l'appelant voit pour la permission ; ok est faux quand il n'a pas de garde à appliquer.
func visibility(r *http.Request, permission string) (v rbac.Visibility, restricted bool) {
	c := rbac.CallerFrom(r.Context())
	if c == nil || c.IsAdmin() {
		return rbac.Visibility{}, false
	}
	return rbac.VisibilityFor(r.Context(), c, permission), true
}

// visibleCerts rend le test de visibilité d'un certificat par son nom.
func visibleCerts(r *http.Request) func(name string) bool {
	v, restricted := visibility(r, "certs:read")
	if !restricted {
		return func(string) bool { return true }
	}
	return v.CertName
}

// visibleAlertEvents ne garde que les événements dont le domaine est visible ; un événement sans domaine (état d'une
// passerelle, du moteur…) n'est visible que d'un accès sans critère.
func visibleAlertEvents(r *http.Request, events []map[string]any) []map[string]any {
	v, restricted := visibility(r, "alerts:read")
	if !restricted || v.All() {
		return events
	}
	out := make([]map[string]any, 0, len(events))
	for _, e := range events {
		detail, _ := e["detail"].(map[string]any)
		for _, key := range []string{"domain", "host"} {
			if domain, _ := detail[key].(string); domain != "" && v.Host(domain) {
				out = append(out, e)
				break
			}
		}
	}
	return out
}

// visibleAlertRule rend le test de visibilité d'une règle d'après son périmètre : une règle limitée à un domaine que
// l'appelant voit ; une règle sans domaine (toutes les passerelles) n'est visible que d'un accès sans critère.
func visibleAlertRule(r *http.Request) func(scope any) bool {
	v, restricted := visibility(r, "alerts:read")
	if !restricted || v.All() {
		return func(any) bool { return true }
	}
	return func(scope any) bool {
		m, _ := scope.(map[string]any)
		glob, _ := m["domain_glob"].(string)
		return v.Pattern(glob)
	}
}

// requireUnrestricted refuse (403) à un accès à périmètre une lecture qui agrège toute la plateforme (totaux, analyses
// de trafic) et ne se découpe pas par hôte : elle est réservée aux administrateurs et aux accès sans critère.
func requireUnrestricted(w http.ResponseWriter, r *http.Request, permission string) bool {
	v, restricted := visibility(r, permission)
	if restricted && !v.All() {
		http.Error(w, "vue globale réservée aux accès sans périmètre", http.StatusForbidden)
		return false
	}
	return true
}

// Les écritures des services appliqués (alertes, certificats, domaines) sont ouvertes à un accès qui porte la permission
// d'écriture, sur les objets de son périmètre ; la garde (rbac.Gate) a déjà vérifié qu'il la porte. Sans appelant posé
// (appel direct, administrateur), tout est permis.

// writeVisibility rend ce que l'appelant voit pour la permission d'écriture, et false quand rien n'est à restreindre.
func writeVisibility(r *http.Request, permission string) (rbac.Visibility, bool) {
	return visibility(r, permission)
}

// mayManageCert dit si l'appelant gère un certificat de ce nom (certs:manage).
func mayManageCert(r *http.Request, name string) bool {
	v, restricted := writeVisibility(r, "certs:manage")
	return !restricted || v.CertName(name)
}

// mayManageDomain dit si l'appelant gère ce domaine (domains:manage).
func mayManageDomain(r *http.Request, domain string) bool {
	v, restricted := writeVisibility(r, "domains:manage")
	return !restricted || v.Host(domain) || v.CertName(domain)
}

// mayManageDomainID juge le domaine déjà enregistré sous cet identifiant ; un identifiant inconnu n'a rien à protéger.
func mayManageDomainID(r *http.Request, db *sql.DB, id string) bool {
	if _, restricted := writeVisibility(r, "domains:manage"); !restricted {
		return true
	}
	var domain string
	if err := db.QueryRowContext(r.Context(), `SELECT domain FROM domains WHERE id=?`, id).Scan(&domain); err != nil {
		return true
	}
	return mayManageDomain(r, domain)
}

// mayDelegate : déléguer un domaine à une autre passerelle crée des proxys implicites ailleurs ; c'est la permission
// explicite domains:delegate, jamais le niveau Gestion.
func mayDelegate(r *http.Request, req domainRequest) bool {
	if req.DelegatedToEdgeID == "" && req.DelegatedEndpoint == "" && (req.DelegationMode == "" || req.DelegationMode == "passthrough") {
		return true
	}
	c := rbac.CallerFrom(r.Context())
	return c == nil || c.IsAdmin() || !c.Filter("domains:delegate").None()
}

// mayAckAlertEvent dit si l'appelant acquitte cet événement : son domaine est visible ; sans domaine, accès sans critère.
func mayAckAlertEvent(r *http.Request, db *sql.DB, id string) bool {
	v, restricted := writeVisibility(r, "alerts:ack")
	if !restricted || v.All() {
		return true
	}
	var detailJSON string
	if err := db.QueryRowContext(r.Context(), `SELECT detail FROM alert_events WHERE id=?`, id).Scan(&detailJSON); err != nil {
		return true
	}
	var detail map[string]any
	_ = json.Unmarshal([]byte(detailJSON), &detail)
	for _, key := range []string{"domain", "host"} {
		if domain, _ := detail[key].(string); domain != "" && v.Host(domain) {
			return true
		}
	}
	return false
}

// mayWriteAlertRule juge une règle créée (id vide), remplacée (id) ou supprimée (id, sans nouveau périmètre) : son
// domaine, avant et après, doit être dans le périmètre de l'appelant ; une règle sans domaine vise toutes les
// passerelles et n'est permise qu'à un accès sans critère.
func mayWriteAlertRule(r *http.Request, db *sql.DB, id, newGlob string, hasNew bool) bool {
	v, restricted := writeVisibility(r, "alerts:rules")
	if !restricted || v.All() {
		return true
	}
	if hasNew && !v.Pattern(newGlob) {
		return false
	}
	if id == "" {
		return true
	}
	var scopeJSON string
	if err := db.QueryRowContext(r.Context(), `SELECT scope FROM alert_rules WHERE id=?`, id).Scan(&scopeJSON); err != nil {
		return true
	}
	var scope struct {
		DomainGlob string `json:"domain_glob"`
	}
	_ = json.Unmarshal([]byte(scopeJSON), &scope)
	return v.Pattern(scope.DomainGlob)
}
