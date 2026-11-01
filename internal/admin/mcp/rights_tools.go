// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"net/http"
	"net/url"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

func rightsTools() []map[string]any {
	return []map[string]any{
		{
			"name":        "get_rights_catalog",
			"description": "Catalogue des droits (ADR 0022) : les services de GoProxify avec leurs niveaux cumulatifs (ex. proxies : read → operate → manage), les permissions sensibles à cocher à part, les critères de périmètre que chaque service accepte, et les profils d'équipe (préréglages de la grille). C'est le vocabulaire de set_team_access.",
			"inputSchema": schema(),
		},
		{
			"name":        "list_team_accesses",
			"description": "Liste les accès d'une équipe : chacun a un périmètre (domaine, proxy, backend, groupe de passerelles, étiquettes), un niveau par service (levels) et des permissions sensibles cochées (permissions). Les droits des accès d'une équipe s'additionnent.",
			"inputSchema": schema(req("team", "string", "Identifiant de l'équipe")),
		},
		{
			"name":        "set_team_access",
			"description": "Crée un accès d'équipe, ou remplace entièrement celui dont l'identifiant est donné. Un accès = un périmètre (tous les critères posés sont requis ; vide = tout) et un niveau par service. Refusé : écriture des objets partagés (snippets, profils IP…), capacités RGPD et permissions qui accordent des droits. `profile` part d'un profil du catalogue (levels et permissions s'y ajoutent ou le remplacent service par service).",
			"inputSchema": schema(
				req("team", "string", "Identifiant de l'équipe"),
				opt("access", "string", "Identifiant de l'accès à remplacer ; vide = en créer un"),
				opt("name", "string", "Nom de l'accès (ex. « Exploitation prod »)"),
				opt("profile", "string", "Identifiant d'un profil de get_rights_catalog (ex. operations, soc)"),
				opt("perimeter", "object", "Périmètre : {domain: glob, proxy: id | glob sur le nom | \"re:<RE2>\", backend: glob sur l'URL, group: {name: glob, environment, region, tag}, labels: {clé: valeur}}"),
				opt("levels", "object", "Niveau par service : {\"proxies\": \"operate\", \"logs\": \"read\"}"),
				opt("permissions", "array", "Permissions sensibles cochées (ex. [\"certs:deploy\"])"),
			),
		},
		{
			"name":        "delete_team_access",
			"description": "Supprime un accès d'une équipe.",
			"inputSchema": schema(
				req("team", "string", "Identifiant de l'équipe"),
				req("access", "string", "Identifiant de l'accès"),
			),
		},
		{
			"name":        "preview_perimeter",
			"description": "Liste les proxys qu'un périmètre couvre (« ce périmètre couvre N proxys ») avant d'en faire un accès : count est exact, la liste est bornée à 200.",
			"inputSchema": schema(
				req("perimeter", "object", "Périmètre, comme pour set_team_access"),
			),
		},
	}
}

func (h *Handler) teamsHandler() *api.TeamsHandler {
	return &api.TeamsHandler{DB: h.DB, Log: h.Log}
}

func (h *Handler) rightsHandler() *api.RightsHandler {
	proxies := &api.ProxiesHandler{DB: h.DB, Log: h.Log}
	rh := &api.RightsHandler{Log: h.Log, Routes: proxies.AllRoutes}
	if h.ArchStore != nil {
		rh.Groups = rbac.ArchitectureGroups{Store: h.ArchStore}.Snapshot
	}
	return rh
}

func (h *Handler) toolGetRightsCatalog(r *http.Request) (any, error) {
	return h.callHandler(r, h.rightsHandler(), http.MethodGet, "/api/v1/rights/catalog", nil)
}

func (h *Handler) toolListTeamAccesses(r *http.Request, args map[string]any) (any, error) {
	team := argStr(args, "team")
	if team == "" {
		return nil, fmt.Errorf("team requis")
	}
	return h.callHandler(r, h.teamsHandler(), http.MethodGet, "/api/v1/teams/"+url.PathEscape(team)+"/accesses", nil)
}

func (h *Handler) toolSetTeamAccess(r *http.Request, args map[string]any) (any, error) {
	team := argStr(args, "team")
	if team == "" {
		return nil, fmt.Errorf("team requis")
	}
	body := map[string]any{}
	if profile := argStr(args, "profile"); profile != "" {
		var found *rbac.Profile
		for i := range rbac.Profiles {
			if rbac.Profiles[i].ID == profile {
				found = &rbac.Profiles[i]
			}
		}
		if found == nil {
			return nil, fmt.Errorf("profil %q inconnu (voir get_rights_catalog)", profile)
		}
		a := found.Access()
		body["name"], body["levels"], body["permissions"] = a.Name, a.Levels, a.Permissions
	}
	if name := argStr(args, "name"); name != "" {
		body["name"] = name
	}
	if levels, ok := args["levels"].(map[string]any); ok {
		merged, _ := body["levels"].(map[string]string)
		if merged == nil {
			merged = map[string]string{}
		}
		for service, level := range levels {
			s, isString := level.(string)
			if !isString {
				return nil, fmt.Errorf("levels.%s : texte attendu", service)
			}
			merged[service] = s
		}
		body["levels"] = merged
	}
	if perms := argStringSlice(args, "permissions"); perms != nil {
		body["permissions"] = perms
	}
	if perimeter, ok := args["perimeter"].(map[string]any); ok {
		body["perimeter"] = perimeter
	}
	method, path := http.MethodPost, "/api/v1/teams/"+url.PathEscape(team)+"/accesses"
	if access := argStr(args, "access"); access != "" {
		method, path = http.MethodPut, path+"/"+url.PathEscape(access)
	}
	return h.callHandler(r, h.teamsHandler(), method, path, body)
}

func (h *Handler) toolDeleteTeamAccess(r *http.Request, args map[string]any) (any, error) {
	team, access := argStr(args, "team"), argStr(args, "access")
	if team == "" || access == "" {
		return nil, fmt.Errorf("team et access requis")
	}
	return h.callHandler(r, h.teamsHandler(), http.MethodDelete, "/api/v1/teams/"+url.PathEscape(team)+"/accesses/"+url.PathEscape(access), nil)
}

func (h *Handler) toolPreviewPerimeter(r *http.Request, args map[string]any) (any, error) {
	perimeter, ok := args["perimeter"].(map[string]any)
	if !ok {
		return nil, fmt.Errorf("perimeter requis (objet)")
	}
	return h.callHandler(r, h.rightsHandler(), http.MethodPost, "/api/v1/rights/preview", map[string]any{"perimeter": perimeter})
}
