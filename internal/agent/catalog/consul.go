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

// ConsulConfig est la configuration de la source Consul.
type ConsulConfig struct {
	Address    string
	Token      string
	Datacenter string
	Namespace  string
	CACert     string
	Prefix     string
}

// Consul liste les services du catalogue Consul dont un tag vaut « goproxify.enable=true », avec leurs instances
// saines (checks au vert). Les étiquettes de route sont les tags « goproxify.clé=valeur » et les métadonnées du
// service ; le tag d'activation doit être un tag, car le catalogue ne présente pas les métadonnées.
type Consul struct {
	cfg    ConsulConfig
	client *http.Client
}

func NewConsul(cfg ConsulConfig) (*Consul, error) {
	cfg.Address = strings.TrimRight(strings.TrimSpace(cfg.Address), "/")
	if cfg.Address == "" {
		cfg.Address = "http://127.0.0.1:8500"
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "goproxify."
	}
	c, err := newHTTPClient(cfg.CACert)
	if err != nil {
		return nil, err
	}
	return &Consul{cfg: cfg, client: c}, nil
}

func (c *Consul) query() string {
	q := url.Values{}
	if c.cfg.Datacenter != "" {
		q.Set("dc", c.cfg.Datacenter)
	}
	if c.cfg.Namespace != "" {
		q.Set("ns", c.cfg.Namespace)
	}
	return q.Encode()
}

type consulHealth struct {
	Node struct {
		Node    string `json:"Node"`
		Address string `json:"Address"`
	} `json:"Node"`
	Service struct {
		ID      string            `json:"ID"`
		Service string            `json:"Service"`
		Address string            `json:"Address"`
		Port    int               `json:"Port"`
		Tags    []string          `json:"Tags"`
		Meta    map[string]string `json:"Meta"`
	} `json:"Service"`
}

func (c *Consul) List(ctx context.Context) ([]Instance, error) {
	hdr := map[string]string{"X-Consul-Token": c.cfg.Token}
	catalogURL := c.cfg.Address + "/v1/catalog/services"
	if q := c.query(); q != "" {
		catalogURL += "?" + q
	}
	var services map[string][]string
	if _, err := doJSON(ctx, c.client, http.MethodGet, catalogURL, hdr, nil, &services); err != nil {
		return nil, err
	}
	names := make([]string, 0, len(services))
	for name, tags := range services {
		if hasEnableTag(tags, c.cfg.Prefix) {
			names = append(names, name)
		}
	}
	sort.Strings(names)

	var out []Instance
	for _, name := range names {
		healthURL := c.cfg.Address + "/v1/health/service/" + url.PathEscape(name) + "?passing=1"
		if q := c.query(); q != "" {
			healthURL += "&" + q
		}
		var entries []consulHealth
		if _, err := doJSON(ctx, c.client, http.MethodGet, healthURL, hdr, nil, &entries); err != nil {
			return nil, err
		}
		for _, e := range entries {
			labels := labelsFromTags(e.Service.Tags, c.cfg.Prefix)
			for k, v := range e.Service.Meta {
				if strings.HasPrefix(k, c.cfg.Prefix) {
					labels[k] = v
				}
			}
			addr := e.Service.Address
			if addr == "" {
				addr = e.Node.Address
			}
			be := backendURL(labels, c.cfg.Prefix, addr, e.Service.Port)
			if be == "" {
				continue
			}
			id := e.Service.ID
			if id == "" {
				id = e.Service.Service
			}
			out = append(out, Instance{Key: id + "@" + e.Node.Node, Name: e.Service.Service + " (" + shortAddr(be) + ")", Backend: be, Labels: labels})
		}
	}
	return out, nil
}
