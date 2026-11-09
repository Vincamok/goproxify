// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"net/http"
	"net/url"
)

// Logins préconfigurés du portail Access (ADR 0025). Aucun outil ne reçoit un mot de passe ou une clé en clair : un secret
// n'entre que scellé pour la passerelle (champ `sealed`), ce que fait l'interface d'Admin ou `goproxify access logins`. L'outil
// crée et lie le login ; sans secret scellé, il existe mais la passerelle ne le propose pas.

func portalLoginTools() []map[string]any {
	return []map[string]any{
		{
			"name":        "list_portal_logins",
			"description": "Liste les logins préconfigurés du portail Access (nom, identifiant SSH, droit d'usage, destinations liées). Aucun secret : seulement has_secret / has_password / has_private_key.",
			"inputSchema": schema(opt("edge", "string", "Filtrer par passerelle (ou groupe HA)")),
		},
		{
			"name":        "create_portal_login",
			"description": "Crée un login préconfigurable et le lie à des destinations. Le secret n'est jamais accepté en clair : `sealed` est une enveloppe déjà chiffrée pour la passerelle (interface d'Admin ou `goproxify access logins`). Sans droit d'usage (all_users, groups, tags), personne ne peut l'employer.",
			"inputSchema": schema(
				req("edge_name", "string", "Passerelle (ou groupe HA) qui porte le login"),
				req("username", "string", "Identifiant SSH du compte"),
				opt("name", "string", "Nom affiché (défaut : l'identifiant)"),
				opt("sealed", "string", "Secret scellé pour la passerelle (JSON) ; jamais un mot de passe en clair"),
				opt("has_password", "boolean", "Le secret scellé contient un mot de passe"),
				opt("has_private_key", "boolean", "Le secret scellé contient une clé privée"),
				opt("all_users", "boolean", "Utilisable par tout utilisateur qui voit la destination"),
				opt("groups", "array", "Identifiants de groupes Access autorisés"),
				opt("tags", "array", "Tags d'utilisateur autorisés"),
				opt("dest_ids", "array", "Destinations liées (identifiants du catalogue)"),
				opt("dest_groups", "array", "Groupes de destinations liés"),
				opt("enabled", "boolean", "Actif (défaut oui)"),
			),
		},
		{
			"name":        "update_portal_login",
			"description": "Modifie un login préconfigurable : liaisons, droit d'usage, identifiant. Un secret scellé absent est conservé ; `sealed` vide le retire.",
			"inputSchema": schema(
				req("id", "string", "Identifiant du login"),
				opt("name", "string", "Nom affiché"),
				opt("username", "string", "Identifiant SSH"),
				opt("sealed", "string", "Nouveau secret scellé pour la passerelle (JSON), ou chaîne vide pour le retirer"),
				opt("has_password", "boolean", "Le secret scellé contient un mot de passe"),
				opt("has_private_key", "boolean", "Le secret scellé contient une clé privée"),
				opt("all_users", "boolean", "Utilisable par tout utilisateur qui voit la destination"),
				opt("groups", "array", "Groupes Access autorisés (remplace la liste)"),
				opt("tags", "array", "Tags d'utilisateur autorisés (remplace la liste)"),
				opt("dest_ids", "array", "Destinations liées (remplace la liste)"),
				opt("dest_groups", "array", "Groupes de destinations liés (remplace la liste)"),
				opt("enabled", "boolean", "Actif / inactif"),
			),
		},
		{
			"name":        "delete_portal_login",
			"description": "Supprime un login préconfigurable ; il n'est plus proposé aux utilisateurs dès la prochaine poussée.",
			"inputSchema": schema(req("id", "string", "Identifiant du login")),
		},
	}
}

// callPortalLoginTool exécute un des outils ci-dessus ; handled=false : l'outil n'est pas de cette famille.
func (h *Handler) callPortalLoginTool(r *http.Request, name string, args map[string]any) (result any, handled bool, err error) {
	switch name {
	case "list_portal_logins":
		path := "/api/v1/portal/logins"
		if edge := argStr(args, "edge"); edge != "" {
			path += "?edge=" + url.QueryEscape(edge)
		}
		result, err = h.callPortal(r, http.MethodGet, path, nil)
	case "create_portal_login", "update_portal_login":
		body := map[string]any{}
		for _, k := range []string{"edge_name", "name", "username", "sealed", "has_password", "has_private_key", "all_users", "groups", "tags", "dest_ids", "dest_groups", "enabled"} {
			if v, ok := args[k]; ok {
				body[k] = v
			}
		}
		if name == "create_portal_login" {
			if argStr(args, "edge_name") == "" || argStr(args, "username") == "" {
				return nil, true, fmt.Errorf("edge_name et username requis")
			}
			result, err = h.callPortal(r, http.MethodPost, "/api/v1/portal/logins", body)
			break
		}
		id := argStr(args, "id")
		if id == "" {
			return nil, true, fmt.Errorf("id requis")
		}
		result, err = h.callPortal(r, http.MethodPut, "/api/v1/portal/logins/"+url.PathEscape(id), body)
	case "delete_portal_login":
		id := argStr(args, "id")
		if id == "" {
			return nil, true, fmt.Errorf("id requis")
		}
		result, err = h.callPortal(r, http.MethodDelete, "/api/v1/portal/logins/"+url.PathEscape(id), nil)
	default:
		return nil, false, nil
	}
	return result, true, err
}
