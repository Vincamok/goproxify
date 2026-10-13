// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
)

// EtcdConfig est la configuration de la source etcd.
type EtcdConfig struct {
	Endpoints []string
	// KeyPrefix est le préfixe des clés qui portent les services (« /goproxify/services/ » par défaut).
	KeyPrefix string
	Username  string
	Password  string
	CACert    string
	Prefix    string
}

// Etcd lit des enregistrements de services dans etcd (API v3, passerelle JSON). etcd n'est pas un annuaire de services :
// chaque clé sous KeyPrefix décrit une instance, par exemple
//
//	/goproxify/services/web-1 = {"host":"app.example.com","backend":"http://10.0.0.5:8080","labels":{"goproxify.tls":"true"}}
//
// Plusieurs clés portant le même hôte forment le pool de la route. Une clé présente est une instance active : la retirer
// (ou laisser expirer son bail) retire le backend.
type Etcd struct {
	cfg    EtcdConfig
	client *http.Client

	mu    sync.Mutex
	token string
	last  int // endpoint qui a répondu en dernier
}

func NewEtcd(cfg EtcdConfig) (*Etcd, error) {
	var eps []string
	for _, e := range cfg.Endpoints {
		if e = strings.TrimRight(strings.TrimSpace(e), "/"); e != "" {
			eps = append(eps, e)
		}
	}
	if len(eps) == 0 {
		eps = []string{"http://127.0.0.1:2379"}
	}
	cfg.Endpoints = eps
	if cfg.KeyPrefix == "" {
		cfg.KeyPrefix = "/goproxify/services/"
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "goproxify."
	}
	c, err := newHTTPClient(cfg.CACert)
	if err != nil {
		return nil, err
	}
	return &Etcd{cfg: cfg, client: c}, nil
}

type etcdRange struct {
	KVs []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"kvs"`
}

type etcdValue struct {
	Host    string            `json:"host"`
	Backend string            `json:"backend"`
	Labels  map[string]string `json:"labels"`
}

// prefixEnd est la borne haute d'une plage de préfixe : le préfixe dont le dernier octet est incrémenté.
func prefixEnd(p string) string {
	b := []byte(p)
	for i := len(b) - 1; i >= 0; i-- {
		if b[i] < 0xff {
			b[i]++
			return string(b[:i+1])
		}
	}
	return "\x00"
}

func (e *Etcd) authenticate(ctx context.Context, ep string) (string, error) {
	var out struct {
		Token string `json:"token"`
	}
	if _, err := doJSON(ctx, e.client, http.MethodPost, ep+"/v3/auth/authenticate", nil,
		map[string]string{"name": e.cfg.Username, "password": e.cfg.Password}, &out); err != nil {
		return "", err
	}
	if out.Token == "" {
		return "", fmt.Errorf("etcd : authentification sans jeton")
	}
	return out.Token, nil
}

// rangeFrom interroge un endpoint, en se ré-authentifiant une fois si le jeton a expiré.
func (e *Etcd) rangeFrom(ctx context.Context, ep string) (*etcdRange, error) {
	body := map[string]string{
		"key":       base64.StdEncoding.EncodeToString([]byte(e.cfg.KeyPrefix)),
		"range_end": base64.StdEncoding.EncodeToString([]byte(prefixEnd(e.cfg.KeyPrefix))),
	}
	for attempt := 0; attempt < 2; attempt++ {
		e.mu.Lock()
		tok := e.token
		e.mu.Unlock()
		if e.cfg.Username != "" && tok == "" {
			t, err := e.authenticate(ctx, ep)
			if err != nil {
				return nil, err
			}
			e.mu.Lock()
			e.token = t
			e.mu.Unlock()
			tok = t
		}
		var out etcdRange
		status, err := doJSON(ctx, e.client, http.MethodPost, ep+"/v3/kv/range", map[string]string{"Authorization": tok}, body, &out)
		if err == nil {
			return &out, nil
		}
		// Jeton périmé : etcd répond 401 (ou 400 « invalid auth token ») ; on repart d'une authentification neuve.
		if e.cfg.Username != "" && attempt == 0 && (status == http.StatusUnauthorized || status == http.StatusBadRequest) {
			e.mu.Lock()
			e.token = ""
			e.mu.Unlock()
			continue
		}
		return nil, err
	}
	return nil, fmt.Errorf("etcd : authentification refusée")
}

func (e *Etcd) List(ctx context.Context) ([]Instance, error) {
	var res *etcdRange
	var lastErr error
	n := len(e.cfg.Endpoints)
	e.mu.Lock()
	start := e.last
	e.mu.Unlock()
	for i := 0; i < n; i++ {
		idx := (start + i) % n
		r, err := e.rangeFrom(ctx, e.cfg.Endpoints[idx])
		if err != nil {
			lastErr = err
			continue
		}
		res = r
		e.mu.Lock()
		e.last = idx
		e.mu.Unlock()
		break
	}
	if res == nil {
		return nil, lastErr
	}

	var out []Instance
	for _, kv := range res.KVs {
		key, err := base64.StdEncoding.DecodeString(kv.Key)
		if err != nil {
			continue
		}
		raw, err := base64.StdEncoding.DecodeString(kv.Value)
		if err != nil {
			continue
		}
		var v etcdValue
		if json.Unmarshal(raw, &v) != nil || v.Host == "" || v.Backend == "" {
			continue
		}
		if u, err := url.Parse(v.Backend); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			continue
		}
		labels := map[string]string{}
		for k, val := range v.Labels {
			if strings.HasPrefix(k, e.cfg.Prefix) {
				labels[k] = val
			} else {
				labels[e.cfg.Prefix+k] = val
			}
		}
		// Une clé présente est une instance active : elle s'active et porte son hôte elle-même.
		labels[e.cfg.Prefix+"enable"] = "true"
		labels[e.cfg.Prefix+"host"] = v.Host
		k := strings.TrimPrefix(string(key), e.cfg.KeyPrefix)
		out = append(out, Instance{Key: string(key), Name: k, Backend: v.Backend, Labels: labels})
	}
	return out, nil
}
