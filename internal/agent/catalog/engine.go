// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package catalog fait de n'importe quel annuaire de services (Consul, Nomad, etcd, ECS…) une source de découverte de
// l'Agent. Une source n'a qu'à lister ses instances (adresse, nom, étiquettes) ; le moteur de ce paquet interroge
// l'annuaire à intervalle régulier, convertit chaque instance en route comme le font les étiquettes Docker (même
// parseur, mêmes options de sécurité) et ne pousse à la passerelle que ce qui a changé.
//
// Autonomie (ADR 0006) : une annuaire injoignable ne retire rien — le moteur ne supprime une route que sur une liste
// obtenue avec succès. Les routes déjà poussées restent servies par la passerelle, qui les garde chiffrées.
package catalog

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/agent/docker"
	"github.com/vincamok/goproxify/internal/agent/statepub"
)

// Instance est une instance de service telle que la voit l'annuaire.
type Instance struct {
	// Key identifie l'instance de façon stable dans la source (identifiant de service, de tâche, clé etcd).
	Key string
	// Name est le nom lisible (journaux, arrêt côté passerelle).
	Name string
	// Backend est l'URL de base de l'instance (http://10.0.0.5:8080).
	Backend string
	// Labels sont les étiquettes de l'instance, sous leur forme publiée : le préfixe configuré est ramené à
	// « goproxify. » par le moteur.
	Labels map[string]string
	// Inactive est l'état d'une instance que l'annuaire connaît sans qu'elle serve (contrôle de santé en échec, tâche pas
	// encore démarrée) : critical, warning, pending, unhealthy… Vide : l'instance sert. Une instance inactive n'a pas de
	// route ; elle part dans l'inventaire des inactifs que l'Admin affiche.
	Inactive string
}

// Lister liste les instances que l'annuaire publie, étiquetées pour GoProxify. Une erreur signifie « je ne sais pas » :
// le moteur ne retire alors aucune route.
type Lister interface {
	List(ctx context.Context) ([]Instance, error)
}

// Engine interroge un Lister et tient la passerelle à jour.
type Engine struct {
	source    string
	lister    Lister
	interval  time.Duration
	prefix    string
	agentName string
	adminURL  string
	log       *slog.Logger
	client    *http.Client

	tokMu sync.RWMutex
	token string

	epMu       sync.RWMutex
	endpointFn func() string

	resync chan struct{}

	mu         sync.Mutex
	published  map[string]published // identifiant de conteneur → ce qui est parti à la passerelle
	force      bool
	reconciled bool
	inactives  string // empreinte des instances inactives parties avec le dernier état complet

	state       *statepub.Publisher // état complet de la source ; nil = publication instance par instance seulement
	lastFull    time.Time           // dernier état complet pris par la passerelle
	noStateFrom string              // passerelle qui a répondu ne pas connaître l'état complet
	noStateAt   time.Time
}

// stateRefresh est le délai après lequel l'état complet est renvoyé même si l'annuaire n'a pas changé : une passerelle
// qui a perdu ses routes sans que l'Agent s'en aperçoive les retrouve, et une instance restée là par erreur est retirée.
const stateRefresh = 10 * time.Minute

type published struct {
	host string
	name string
	hash string
}

// New crée un moteur. prefix est le préfixe d'étiquettes de la source (« goproxify. » par défaut).
func New(source string, lister Lister, interval time.Duration, prefix, adminURL, token, agentName string, log *slog.Logger) *Engine {
	if interval <= 0 {
		interval = 30 * time.Second
	}
	if prefix == "" {
		prefix = "goproxify."
	}
	return &Engine{
		source: source, lister: lister, interval: interval, prefix: prefix,
		adminURL: adminURL, token: token, agentName: agentName, log: log,
		client:    &http.Client{Timeout: 10 * time.Second},
		resync:    make(chan struct{}, 1),
		published: map[string]published{},
	}
}

// SetToken remplace le jeton d'agent (appairage obtenu après la construction).
func (e *Engine) SetToken(token string) {
	e.tokMu.Lock()
	e.token = token
	e.tokMu.Unlock()
}

// SetStatePublisher active l'envoi de l'état complet de la source après chaque liste réussie de l'annuaire.
func (e *Engine) SetStatePublisher(p *statepub.Publisher) {
	e.mu.Lock()
	e.state = p
	e.mu.Unlock()
}

// SetEndpointFunc fait suivre au moteur la passerelle courante de l'Agent (bascule HA).
func (e *Engine) SetEndpointFunc(fn func() string) {
	e.epMu.Lock()
	e.endpointFn = fn
	e.epMu.Unlock()
}

func (e *Engine) endpoint() string {
	e.epMu.RLock()
	fn := e.endpointFn
	e.epMu.RUnlock()
	if fn != nil {
		if ep := fn(); ep != "" {
			return ep
		}
	}
	return e.adminURL
}

func (e *Engine) authToken() string {
	e.tokMu.RLock()
	defer e.tokMu.RUnlock()
	return e.token
}

// Resync republie toutes les routes à la passerelle courante (nouvelle passerelle, reconnexion) sans attendre un
// changement de l'annuaire.
func (e *Engine) Resync(context.Context) {
	e.mu.Lock()
	e.force = true
	e.mu.Unlock()
	select {
	case e.resync <- struct{}{}:
	default:
	}
}

// Start boucle jusqu'à l'annulation du contexte.
func (e *Engine) Start(ctx context.Context) {
	e.log.Info("découverte : démarrage", "source", e.source, "intervalle", e.interval.String())
	e.cycle(ctx)
	t := time.NewTicker(e.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		case <-e.resync:
		}
		e.cycle(ctx)
	}
}

type desired struct {
	id      string
	name    string
	host    string
	payload map[string]any
	hash    string
}

// containerID est l'identifiant sous lequel la passerelle connaît une instance. La passerelle retire un backend d'après
// les 12 premiers caractères de l'identifiant : ils doivent être uniques, donc issus d'une empreinte et non d'un nom qui
// partage un préfixe avec ses voisins. Le suffixe « @source » signale à la passerelle une instance venue d'un annuaire :
// le battement de cœur d'un Agent sans runtime Docker ne doit pas purger ces routes (agenthandlers.go).
func containerID(source, key string) string {
	sum := sha256.Sum256([]byte(source + "\x00" + key))
	return hex.EncodeToString(sum[:])[:32] + "@" + source
}

// publishState envoie à la passerelle tout ce que l'annuaire publie : elle retire les instances de cette source qu'elle
// gardait et qui n'y sont plus, ce que la réconciliation du démarrage ne faisait qu'une fois. Rien ne part tant que
// l'annuaire n'a pas changé (sauf après un Resync, un changement de passerelle ou stateRefresh). Faux : la passerelle
// ne connaît pas l'appel, l'Agent publie instance par instance.
func (e *Engine) publishState(ctx context.Context, want map[string]desired, inactive []map[string]any) bool {
	endpoint := e.endpoint()
	e.mu.Lock()
	pub, force, last := e.state, e.force, e.lastFull
	if pub == nil || (e.noStateFrom == endpoint && time.Since(e.noStateAt) < stateRefresh) {
		e.mu.Unlock()
		return false
	}
	rawInactive, _ := json.Marshal(inactive)
	inactiveSum := sha256.Sum256(rawInactive)
	inactiveHash := hex.EncodeToString(inactiveSum[:])
	changed := len(e.published) != len(want) || e.inactives != inactiveHash
	for id, w := range want {
		if p, ok := e.published[id]; !ok || p.hash != w.hash || p.host != w.host {
			changed = true
			break
		}
	}
	e.mu.Unlock()
	if !changed && !force && !last.IsZero() && time.Since(last) < stateRefresh {
		return true
	}

	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	routes := make([]map[string]any, 0, len(ids))
	for _, id := range ids {
		routes = append(routes, want[id].payload)
	}
	res, err := pub.PutState(ctx, endpoint, e.authToken(), e.source, "", routes, inactive)
	e.mu.Lock()
	defer e.mu.Unlock()
	switch res {
	case statepub.Sent:
		e.published = make(map[string]published, len(want))
		for id, w := range want {
			e.published[id] = published{host: w.host, name: w.name, hash: w.hash}
		}
		e.force, e.lastFull, e.noStateFrom = false, time.Now(), ""
		e.inactives = inactiveHash
		e.log.Info("découverte : état complet envoyé", "source", e.source, "instances", len(want), "inactifs", len(inactive))
		return true
	case statepub.Failed:
		e.force = true // réessayé au prochain cycle
		e.log.Warn("découverte : état complet non envoyé", "source", e.source, "err", err)
		return true
	}
	e.noStateFrom, e.noStateAt = endpoint, time.Now()
	return false
}

func (e *Engine) cycle(ctx context.Context) {
	insts, err := e.lister.List(ctx)
	if err != nil {
		if ctx.Err() == nil {
			e.log.Warn("découverte : annuaire injoignable, routes conservées", "source", e.source, "err", err)
		}
		return
	}
	want, inactive := e.build(insts)
	if e.publishState(ctx, want, inactive) {
		return
	}
	e.reconcile(ctx, want)

	e.mu.Lock()
	force := e.force
	e.force = false
	current := make(map[string]published, len(e.published))
	for id, p := range e.published {
		current[id] = p
	}
	e.mu.Unlock()

	// Retraits d'abord : une instance disparue, ou qui change d'hôte, quitte son ancienne route.
	for id, p := range current {
		if w, ok := want[id]; ok && w.host == p.host {
			continue
		}
		if e.stop(ctx, id, p.name) {
			e.mu.Lock()
			delete(e.published, id)
			e.mu.Unlock()
			e.log.Info("découverte : instance retirée", "source", e.source, "host", p.host, "instance", p.name)
		}
	}

	ids := make([]string, 0, len(want))
	for id := range want {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	for _, id := range ids {
		w := want[id]
		e.mu.Lock()
		prev, had := e.published[id]
		e.mu.Unlock()
		if had && prev.hash == w.hash && !force {
			continue
		}
		if e.push(ctx, w) {
			e.mu.Lock()
			e.published[id] = published{host: w.host, name: w.name, hash: w.hash}
			e.mu.Unlock()
		}
	}
}

// reconcile retire de la passerelle les instances de cette source qu'elle garde alors que l'annuaire ne les publie plus :
// une instance disparue pendant que l'Agent était arrêté n'a laissé aucune trace ici pour la retirer. Une fois par
// démarrage, dès que la passerelle répond.
func (e *Engine) reconcile(ctx context.Context, want map[string]desired) {
	e.mu.Lock()
	done := e.reconciled
	e.mu.Unlock()
	if done {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, e.endpoint()+"/internal/v1/agent/containers?agent="+url.QueryEscape(e.agentName), nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+e.authToken())
	resp, err := e.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	var routes []struct {
		ContainerIDs []string `json:"container_ids"`
	}
	if json.NewDecoder(io.LimitReader(resp.Body, 8<<20)).Decode(&routes) != nil {
		return
	}
	suffix := "@" + e.source
	for _, r := range routes {
		for _, id := range r.ContainerIDs {
			if !strings.HasSuffix(id, suffix) {
				continue
			}
			if _, live := want[id]; live {
				continue
			}
			if e.stop(ctx, id, "") {
				e.log.Info("découverte : instance périmée retirée de la passerelle", "source", e.source)
			}
		}
	}
	e.mu.Lock()
	e.reconciled = true
	e.mu.Unlock()
}

// build convertit les instances en routes, et celles que l'annuaire dit inactives en entrées d'inventaire sans route. Une
// instance sans étiquette d'activation ou sans hôte est ignorée ; un hôte invalide est signalé sans bloquer les autres.
func (e *Engine) build(insts []Instance) (map[string]desired, []map[string]any) {
	out := map[string]desired{}
	var inactive []map[string]any
	for _, in := range insts {
		labels := make(map[string]string, len(in.Labels)+3)
		for k, v := range in.Labels {
			if rest, ok := strings.CutPrefix(k, e.prefix); ok {
				labels["goproxify."+rest] = v
			}
		}
		if !strings.EqualFold(labels["goproxify.enable"], "true") && !strings.EqualFold(labels["goproxify.enabled"], "true") {
			continue
		}
		if labels[docker.LabelHost] == "" || in.Backend == "" {
			continue
		}
		labels[docker.LabelEnable] = "true"
		// L'adresse découverte l'emporte sur une étiquette : c'est elle qui désigne l'instance.
		labels[docker.LabelBackendURL] = in.Backend
		id := containerID(e.source, in.Key)
		spec := docker.ParseLabels(e.source+":"+in.Key, in.Name, "", "", labels, nil, "")
		if spec == nil {
			e.log.Warn("découverte : étiquettes invalides, instance ignorée", "source", e.source, "instance", in.Name)
			continue
		}
		if in.Inactive != "" {
			inactive = append(inactive, map[string]any{
				"id": e.source + ":" + id[:12] + ":" + spec.Host, "host": spec.Host, "aliases": spec.Aliases,
				"container_id": id, "name": in.Name, "state": strings.ToLower(in.Inactive),
			})
			continue
		}
		payload := map[string]any{
			"host":         spec.Host,
			"aliases":      spec.Aliases,
			"paths":        spec.Paths,
			"route_type":   spec.Type,
			"backends":     []string{in.Backend},
			"tls_enabled":  spec.TLS,
			"passthrough":  spec.Passthrough,
			"source":       e.source,
			"container_id": id,
			"agent_name":   e.agentName,
			"role":         spec.Role,
		}
		if spec.Role == docker.RoleCanary {
			payload["canary_weight"] = spec.CanaryWeight
		}
		docker.AttachSecurityPayload(payload, spec)
		raw, _ := json.Marshal(payload)
		sum := sha256.Sum256(raw)
		out[id] = desired{id: id, name: in.Name, host: spec.Host, payload: payload, hash: hex.EncodeToString(sum[:])}
	}
	sort.Slice(inactive, func(i, j int) bool { return inactive[i]["container_id"].(string) < inactive[j]["container_id"].(string) })
	return out, inactive
}

func (e *Engine) push(ctx context.Context, w desired) bool {
	body, _ := json.Marshal(w.payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint()+"/internal/v1/agent/containers", bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.authToken())
	resp, err := e.client.Do(req)
	if err != nil {
		e.log.Warn("découverte : envoi à la passerelle", "source", e.source, "host", w.host, "err", err)
		return false
	}
	resp.Body.Close()
	switch {
	case resp.StatusCode >= 500:
		e.log.Warn("découverte : la passerelle a échoué", "source", e.source, "host", w.host, "status", resp.StatusCode)
		return false
	case resp.StatusCode >= 300:
		// Refus définitif (étiquettes de sécurité invalides…) : inutile de renvoyer tant que rien ne change.
		e.log.Error("découverte : route refusée par la passerelle", "source", e.source, "host", w.host, "status", resp.StatusCode)
		return true
	}
	e.log.Info("découverte : route enregistrée", "source", e.source, "host", w.host, "backend", fmt.Sprint(w.payload["backends"]))
	return true
}

func (e *Engine) stop(ctx context.Context, id, name string) bool {
	body, _ := json.Marshal(map[string]any{"container_id": id, "name": name, "action": "stop"})
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete, e.endpoint()+"/internal/v1/agent/containers", bytes.NewReader(body))
	if err != nil {
		return false
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+e.authToken())
	resp, err := e.client.Do(req)
	if err != nil {
		e.log.Warn("découverte : retrait auprès de la passerelle", "source", e.source, "instance", name, "err", err)
		return false
	}
	resp.Body.Close()
	return resp.StatusCode < 500
}
