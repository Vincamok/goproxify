// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package k8s

import (
	"context"
	"net/url"
	"sort"
	"strings"
)

// serviceTarget désigne le Service dont les pods servent une route : c'est par lui qu'on retrouve l'image (ADR 0017).
// selector est celui du Service quand l'Agent l'a déjà lu (route d'un Service) ; nil pour un Ingress, dont le Service
// se lit à la demande.
type serviceTarget struct {
	ns, name string
	selector map[string]string
}

type k8sContainer struct {
	Name  string `json:"name"`
	Image string `json:"image"`
}

type k8sPodList struct {
	Items []struct {
		Metadata k8sMeta `json:"metadata"`
		Spec     struct {
			Containers []k8sContainer `json:"containers"`
		} `json:"spec"`
	} `json:"items"`
}

// defaultContainerAnnotation : le conteneur que `kubectl logs` et `kubectl exec` choisissent par défaut.
const defaultContainerAnnotation = "kubectl.kubernetes.io/default-container"

// meshSidecars : conteneurs injectés par un maillage, qui ne sont jamais l'application (Istio les met parfois en tête).
var meshSidecars = map[string]bool{"istio-proxy": true, "linkerd-proxy": true}

// routeImage rend l'image du conteneur principal des pods qui servent la route, ou vide : route sans Service (étiquette
// backend), Service sans sélecteur, pas de pod en marche, ou droit de lecture absent. Ne pas savoir n'est pas une erreur,
// la route n'a simplement pas d'image et ses réponses restent la seule source de version. cache évite de relire les pods
// d'un même Service pour chaque route d'un état complet ; nil : pas de cache.
func (d *Discovery) routeImage(ctx context.Context, t *serviceTarget, cache map[string]string) string {
	if t == nil || t.name == "" {
		return ""
	}
	key := t.ns + "/" + t.name
	if img, ok := cache[key]; ok {
		return img
	}
	img := d.serviceImage(ctx, *t)
	if cache != nil {
		cache[key] = img
	}
	return img
}

func (d *Discovery) serviceImage(ctx context.Context, t serviceTarget) string {
	selector := t.selector
	if selector == nil {
		var svc k8sService
		if err := d.getJSON(ctx, "/api/v1/namespaces/"+url.PathEscape(t.ns)+"/services/"+url.PathEscape(t.name), &svc); err != nil {
			d.log.Debug("k8s discovery: Service illisible, pas d'image", "service", t.ns+"/"+t.name, "err", err)
			return ""
		}
		selector = svc.Spec.Selector
	}
	if len(selector) == 0 {
		return ""
	}
	var pods k8sPodList
	path := "/api/v1/namespaces/" + url.PathEscape(t.ns) + "/pods?fieldSelector=" + url.QueryEscape("status.phase=Running") +
		"&labelSelector=" + url.QueryEscape(selectorString(selector))
	if err := d.getJSON(ctx, path, &pods); err != nil {
		d.log.Debug("k8s discovery: pods illisibles, pas d'image", "service", t.ns+"/"+t.name, "err", err)
		return ""
	}
	// Pendant une mise à jour progressive, deux images coexistent : celle de la majorité des pods décrit ce qui sert.
	count := map[string]int{}
	for _, p := range pods.Items {
		if img := mainContainerImage(p.Metadata.Annotations, p.Spec.Containers); img != "" {
			count[img]++
		}
	}
	best, n := "", 0
	for img, c := range count {
		if c > n || (c == n && img < best) {
			best, n = img, c
		}
	}
	return best
}

// mainContainerImage : le conteneur désigné par l'annotation default-container, sinon le premier qui n'est pas un
// sidecar de maillage, sinon le premier.
func mainContainerImage(ann map[string]string, containers []k8sContainer) string {
	if want := ann[defaultContainerAnnotation]; want != "" {
		for _, c := range containers {
			if c.Name == want {
				return c.Image
			}
		}
	}
	for _, c := range containers {
		if !meshSidecars[c.Name] {
			return c.Image
		}
	}
	if len(containers) > 0 {
		return containers[0].Image
	}
	return ""
}

// selectorString : un sélecteur d'étiquettes « clé=valeur,… » dans un ordre stable.
func selectorString(sel map[string]string) string {
	keys := make([]string, 0, len(sel))
	for k := range sel {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, k := range keys {
		parts = append(parts, k+"="+sel[k])
	}
	return strings.Join(parts, ",")
}
