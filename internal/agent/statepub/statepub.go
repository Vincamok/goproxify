// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package statepub envoie à la passerelle l'état complet d'une source de découverte (ADR 0014, étape 2). Les POST et
// DELETE d'un conteneur ne disent que ce qui change : un retrait manqué laisse une route obsolète pour toujours. À la
// fin d'un scan complet l'Agent envoie tout ce que la source publie, et la passerelle retire ce qu'elle gardait de cet
// Agent et qui n'y est plus.
package statepub

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Path est l'appel de la passerelle qui reçoit l'état complet.
const Path = "/internal/v1/agent/state"

// Result dit ce qu'est devenu un envoi.
type Result int

const (
	// Sent : la passerelle a pris l'état (ou l'a ignoré parce qu'un plus récent l'avait précédé).
	Sent Result = iota
	// Unsupported : la passerelle ne connaît pas l'appel (version ancienne) ; l'Agent publie route par route.
	Unsupported
	// Failed : l'envoi n'a pas abouti ; l'état publié est peut-être en retard.
	Failed
)

// Publisher envoie des états complets et tient la génération qui les ordonne.
type Publisher struct {
	agent  string
	path   string
	client *http.Client

	mu   sync.Mutex
	last int64
}

// New crée un Publisher. path est le fichier où la dernière génération est conservée : un Agent redémarré ne
// repart pas en dessous de ce que la passerelle a déjà vu. Vide : en mémoire seulement.
func New(agent, path string) *Publisher {
	p := &Publisher{agent: agent, path: path, client: &http.Client{Timeout: 30 * time.Second}}
	if path != "" {
		if b, err := os.ReadFile(path); err == nil {
			p.last, _ = strconv.ParseInt(strings.TrimSpace(string(b)), 10, 64)
		}
	}
	return p
}

// next rend une génération strictement supérieure à toutes les précédentes, y compris celles d'avant un redémarrage
// (l'horloge sert de plancher).
func (p *Publisher) next() int64 {
	p.mu.Lock()
	defer p.mu.Unlock()
	gen := time.Now().UnixMilli()
	if gen <= p.last {
		gen = p.last + 1
	}
	p.last = gen
	if p.path != "" {
		_ = os.MkdirAll(filepath.Dir(p.path), 0o755)
		tmp := p.path + ".tmp"
		if os.WriteFile(tmp, []byte(strconv.FormatInt(gen, 10)), 0o600) == nil {
			_ = os.Rename(tmp, p.path)
		}
	}
	return gen
}

// Put envoie l'état complet d'une source (et d'un scope : l'endpoint Portainer) à la passerelle. routes sont les
// mêmes charges utiles que celles du POST d'un conteneur.
func (p *Publisher) Put(ctx context.Context, edgeEndpoint, token, source, scope string, routes []map[string]any) (Result, error) {
	return p.PutState(ctx, edgeEndpoint, token, source, scope, routes, nil)
}

// PutState est Put avec les conteneurs inactifs de la source (arrêtés, en pause, qui redémarrent). Ils partent dans un
// champ à part : une passerelle qui ne le connaît pas l'ignore, alors qu'elle ferait une route d'une entrée de routes.
func (p *Publisher) PutState(ctx context.Context, edgeEndpoint, token, source, scope string, routes, inactive []map[string]any) (Result, error) {
	if routes == nil {
		routes = []map[string]any{}
	}
	payload := map[string]any{
		"agent_name": p.agent, "source": source, "scope": scope, "generation": p.next(), "routes": routes,
	}
	if len(inactive) > 0 {
		payload["inactive"] = inactive
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return Failed, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPut, strings.TrimRight(edgeEndpoint, "/")+Path, bytes.NewReader(body))
	if err != nil {
		return Failed, err
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return Failed, err
	}
	defer resp.Body.Close()
	switch {
	case resp.StatusCode == http.StatusOK, resp.StatusCode == http.StatusConflict:
		return Sent, nil
	case resp.StatusCode == http.StatusNotFound, resp.StatusCode == http.StatusMethodNotAllowed:
		return Unsupported, nil
	}
	msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
	return Failed, fmt.Errorf("état complet refusé : %d %s", resp.StatusCode, strings.TrimSpace(string(msg)))
}
