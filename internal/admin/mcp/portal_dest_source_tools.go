// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"net/http"
	"net/url"
)

// Sources de destinations du portail Access (ADR 0024) : des plateformes (Proxmox…) que la passerelle interroge pour proposer
// leurs machines comme destinations. Une machine découverte reste une candidate tant qu'elle n'est pas publiée.

func portalDestSourceTools() []map[string]any {
	return []map[string]any{
		{
			"name":        "list_portal_dest_source_types",
			"description": "Types de sources de destinations disponibles (Proxmox VE…) avec leurs champs de configuration ; les champs secrets sont signalés.",
			"inputSchema": schema(),
		},
		{
			"name":        "list_portal_dest_sources",
			"description": "Liste les sources de destinations du portail Access (état de la dernière synchronisation, nombre de candidates par état). Les secrets sont masqués.",
			"inputSchema": schema(opt("edge", "string", "Filtrer par passerelle (ou groupe HA)")),
		},
		{
			"name":        "create_portal_dest_source",
			"description": "Crée une source de destinations : la passerelle interroge l'API du fournisseur et remonte ses machines comme candidates (rien n'est visible des utilisateurs avant publication, sauf auto_publish).",
			"inputSchema": schema(
				req("edge_name", "string", "Passerelle (ou groupe HA) qui exécute la source"),
				req("type", "string", "Type de source (voir list_portal_dest_source_types), ex. proxmox"),
				req("name", "string", "Nom de la source"),
				req("config", "object", "Configuration du type : champs du manifeste, secrets compris"),
				opt("interval_s", "number", "Intervalle de synchronisation en secondes (défaut 300, minimum 60)"),
				opt("enabled", "boolean", "Active la source (défaut oui)"),
				opt("extra_tags", "array", "Étiquettes ajoutées aux destinations publiées depuis cette source"),
				opt("auto_publish", "boolean", "Publie sans validation les machines découvertes (défaut non)"),
			),
		},
		{
			"name":        "update_portal_dest_source",
			"description": "Modifie une source. Un secret laissé vide ou masqué est conservé. Le type et la passerelle ne changent pas.",
			"inputSchema": schema(
				req("id", "string", "Identifiant de la source"),
				opt("name", "string", "Nom"),
				opt("config", "object", "Configuration complète du type"),
				opt("interval_s", "number", "Intervalle en secondes"),
				opt("enabled", "boolean", "Active / désactive"),
				opt("extra_tags", "array", "Étiquettes ajoutées aux destinations publiées"),
				opt("auto_publish", "boolean", "Publication sans validation"),
			),
		},
		{
			"name":        "delete_portal_dest_source",
			"description": "Supprime une source et ses candidates. Les destinations déjà publiées restent dans le catalogue.",
			"inputSchema": schema(req("id", "string", "Identifiant de la source")),
		},
		{
			"name":        "test_portal_dest_source",
			"description": "Lit une fois le fournisseur depuis la passerelle, avec la configuration donnée, sans rien enregistrer. Renvoie le nombre de machines et un aperçu.",
			"inputSchema": schema(
				req("edge_name", "string", "Passerelle qui exécute l'essai"),
				req("type", "string", "Type de source"),
				req("config", "object", "Configuration à essayer"),
				opt("source_id", "string", "Source existante dont reprendre les secrets laissés vides"),
			),
		},
		{
			"name":        "sync_portal_dest_source",
			"description": "Demande à la passerelle un passage immédiat de la source.",
			"inputSchema": schema(req("id", "string", "Identifiant de la source")),
		},
		{
			"name":        "list_portal_dest_candidates",
			"description": "Liste les machines découvertes par les sources : état new (à publier), published, ignored ou missing (disparue du fournisseur).",
			"inputSchema": schema(
				opt("edge", "string", "Filtrer par passerelle (ou groupe HA)"),
				opt("state", "string", "new, published, ignored ou missing"),
				opt("source", "string", "Identifiant de source"),
			),
		},
		{
			"name":        "publish_portal_dest_candidates",
			"description": "Publie des machines découvertes : chacune devient une destination SSH du catalogue (étiquettes du fournisseur + celles de la source + tags). Une machine sans adresse est refusée.",
			"inputSchema": schema(
				req("ids", "array", "Identifiants de candidates"),
				opt("tags", "array", "Étiquettes ajoutées à chaque destination"),
			),
		},
		{
			"name":        "ignore_portal_dest_candidate",
			"description": "Écarte une machine découverte de la file à publier.",
			"inputSchema": schema(req("id", "string", "Identifiant de la candidate")),
		},
		{
			"name":        "restore_portal_dest_candidate",
			"description": "Remet dans la file une machine précédemment ignorée.",
			"inputSchema": schema(req("id", "string", "Identifiant de la candidate")),
		},
	}
}

// callPortalDestSourceTool exécute un des outils ci-dessus ; handled=false : l'outil n'est pas de cette famille.
func (h *Handler) callPortalDestSourceTool(r *http.Request, name string, args map[string]any) (result any, handled bool, err error) {
	handled = true
	switch name {
	case "list_portal_dest_source_types":
		result, err = h.callPortal(r, http.MethodGet, "/api/v1/portal/dest-sources/types", nil)
	case "list_portal_dest_sources":
		path := "/api/v1/portal/dest-sources"
		if edge := argStr(args, "edge"); edge != "" {
			path += "?edge=" + url.QueryEscape(edge)
		}
		result, err = h.callPortal(r, http.MethodGet, path, nil)
	case "create_portal_dest_source":
		body := map[string]any{
			"edge_name": argStr(args, "edge_name"), "type": argStr(args, "type"), "name": argStr(args, "name"),
			"config": args["config"], "interval_s": argInt(args, "interval_s", 0), "extra_tags": argStringSlice(args, "extra_tags"),
		}
		if b := argBoolPtr(args, "enabled"); b != nil {
			body["enabled"] = *b
		}
		if b := argBoolPtr(args, "auto_publish"); b != nil {
			body["auto_publish"] = *b
		}
		if body["edge_name"] == "" || body["type"] == "" || body["name"] == "" {
			return nil, true, fmt.Errorf("edge_name, type et name requis")
		}
		result, err = h.callPortal(r, http.MethodPost, "/api/v1/portal/dest-sources", body)
	case "update_portal_dest_source":
		id := argStr(args, "id")
		if id == "" {
			return nil, true, fmt.Errorf("id requis")
		}
		body := map[string]any{}
		for _, k := range []string{"name", "config", "interval_s", "enabled", "extra_tags", "auto_publish"} {
			if v, ok := args[k]; ok {
				body[k] = v
			}
		}
		result, err = h.callPortal(r, http.MethodPut, "/api/v1/portal/dest-sources/"+url.PathEscape(id), body)
	case "delete_portal_dest_source":
		id := argStr(args, "id")
		if id == "" {
			return nil, true, fmt.Errorf("id requis")
		}
		result, err = h.callPortal(r, http.MethodDelete, "/api/v1/portal/dest-sources/"+url.PathEscape(id), nil)
	case "test_portal_dest_source":
		body := map[string]any{"edge_name": argStr(args, "edge_name"), "type": argStr(args, "type"), "config": args["config"], "source_id": argStr(args, "source_id")}
		result, err = h.callPortal(r, http.MethodPost, "/api/v1/portal/dest-sources/test", body)
	case "sync_portal_dest_source":
		id := argStr(args, "id")
		if id == "" {
			return nil, true, fmt.Errorf("id requis")
		}
		result, err = h.callPortal(r, http.MethodPost, "/api/v1/portal/dest-sources/"+url.PathEscape(id)+"/sync", nil)
	case "list_portal_dest_candidates":
		q := url.Values{}
		for _, k := range []string{"edge", "state", "source"} {
			if v := argStr(args, k); v != "" {
				q.Set(k, v)
			}
		}
		path := "/api/v1/portal/dest-candidates"
		if len(q) > 0 {
			path += "?" + q.Encode()
		}
		result, err = h.callPortal(r, http.MethodGet, path, nil)
	case "publish_portal_dest_candidates":
		ids := argStringSlice(args, "ids")
		if len(ids) == 0 {
			return nil, true, fmt.Errorf("ids requis")
		}
		result, err = h.callPortal(r, http.MethodPost, "/api/v1/portal/dest-candidates/publish",
			map[string]any{"ids": ids, "tags": argStringSlice(args, "tags")})
	case "ignore_portal_dest_candidate", "restore_portal_dest_candidate":
		id := argStr(args, "id")
		if id == "" {
			return nil, true, fmt.Errorf("id requis")
		}
		action := "ignore"
		if name == "restore_portal_dest_candidate" {
			action = "restore"
		}
		result, err = h.callPortal(r, http.MethodPost, "/api/v1/portal/dest-candidates/"+url.PathEscape(id)+"/"+action, nil)
	default:
		return nil, false, nil
	}
	return result, handled, err
}
