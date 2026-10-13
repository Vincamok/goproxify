// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"net/http"
	"net/url"
	"sort"
	"strings"
)

// NomadConfig est la configuration de la source Nomad.
type NomadConfig struct {
	Address   string
	Token     string
	Namespace string
	Region    string
	CACert    string
	Prefix    string
}

// Nomad liste les services du catalogue natif de Nomad dont un tag vaut « goproxify.enable=true ». Les étiquettes de
// route sont les tags « goproxify.clé=valeur » : Nomad n'a pas de métadonnées par service.
type Nomad struct {
	cfg    NomadConfig
	client *http.Client
}

func NewNomad(cfg NomadConfig) (*Nomad, error) {
	cfg.Address = strings.TrimRight(strings.TrimSpace(cfg.Address), "/")
	if cfg.Address == "" {
		cfg.Address = "http://127.0.0.1:4646"
	}
	if cfg.Namespace == "" {
		cfg.Namespace = "*"
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "goproxify."
	}
	c, err := newHTTPClient(cfg.CACert)
	if err != nil {
		return nil, err
	}
	return &Nomad{cfg: cfg, client: c}, nil
}

type nomadListing struct {
	Namespace string `json:"Namespace"`
	Services  []struct {
		ServiceName string   `json:"ServiceName"`
		Tags        []string `json:"Tags"`
	} `json:"Services"`
}

type nomadService struct {
	ID          string   `json:"ID"`
	ServiceName string   `json:"ServiceName"`
	Namespace   string   `json:"Namespace"`
	Tags        []string `json:"Tags"`
	Address     string   `json:"Address"`
	Port        int      `json:"Port"`
}

func (n *Nomad) query(ns string) string {
	q := url.Values{}
	q.Set("namespace", ns)
	if n.cfg.Region != "" {
		q.Set("region", n.cfg.Region)
	}
	return q.Encode()
}

func (n *Nomad) List(ctx context.Context) ([]Instance, error) {
	hdr := map[string]string{"X-Nomad-Token": n.cfg.Token}
	var listings []nomadListing
	if _, err := doJSON(ctx, n.client, http.MethodGet, n.cfg.Address+"/v1/services?"+n.query(n.cfg.Namespace), hdr, nil, &listings); err != nil {
		return nil, err
	}
	type target struct{ ns, name string }
	var targets []target
	for _, l := range listings {
		for _, s := range l.Services {
			if hasEnableTag(s.Tags, n.cfg.Prefix) {
				targets = append(targets, target{l.Namespace, s.ServiceName})
			}
		}
	}
	sort.Slice(targets, func(i, j int) bool {
		if targets[i].ns != targets[j].ns {
			return targets[i].ns < targets[j].ns
		}
		return targets[i].name < targets[j].name
	})

	var out []Instance
	for _, t := range targets {
		var regs []nomadService
		if _, err := doJSON(ctx, n.client, http.MethodGet, n.cfg.Address+"/v1/service/"+url.PathEscape(t.name)+"?"+n.query(t.ns), hdr, nil, &regs); err != nil {
			return nil, err
		}
		for _, r := range regs {
			labels := labelsFromTags(r.Tags, n.cfg.Prefix)
			be := backendURL(labels, n.cfg.Prefix, r.Address, r.Port)
			if be == "" {
				continue
			}
			out = append(out, Instance{Key: t.ns + "/" + r.ID, Name: r.ServiceName + " (" + shortAddr(be) + ")", Backend: be, Labels: labels})
		}
	}
	return out, nil
}
