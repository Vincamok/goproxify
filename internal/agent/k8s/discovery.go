// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package k8s fournit la découverte de services Kubernetes pour l'Agent Goproxify.
// Il surveille les Services et Ingress annotés et les enregistre comme routes proxy.
package k8s

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vincamok/goproxify/internal/agent/docker"
	"github.com/vincamok/goproxify/internal/agent/statepub"
	"github.com/vincamok/goproxify/internal/config"
)

const (
	inClusterAPIServer = "https://kubernetes.default.svc"
	inClusterTokenFile = "/var/run/secrets/kubernetes.io/serviceaccount/token"
	inClusterCAFile    = "/var/run/secrets/kubernetes.io/serviceaccount/ca.crt"
)

// Discovery surveille les Services et Ingress Kubernetes portant le label
// goproxify.enabled=true et pousse les routes correspondantes vers la passerelle.
type Discovery struct {
	cfg         *config.AgentConfig
	adminURL    string
	authToken   string
	tokMu       sync.RWMutex // protège authToken : le jeton peut être obtenu après la construction (appairage)
	epMu        sync.RWMutex
	endpointFn  func() string     // passerelle courante de l'Agent (bascule HA) ; nil = adminURL fixe
	resync      chan struct{}     // demande de réannonce : relance les watches, qui renvoient l'état complet
	dirty       atomic.Bool       // un envoi vers la passerelle a échoué : l'état publié est peut-être en retard
	pendingDel  map[string]string // routes dont la suppression a échoué (ID → hôte), à réessayer
	labelPrefix string
	log         *slog.Logger
	client      *http.Client
	apiServer   string
	k8sToken    string

	// hostByKey mappe "namespace/name" → host courant pour permettre la suppression.
	mu        sync.Mutex
	hostByKey map[string]string
	// idle : les Services (« namespace/nom ») dont l'objet Endpoints existe sans aucune adresse prête, d'après le dernier
	// état complet. Ils n'ont pas de route ; la passerelle les affiche comme inactifs.
	idle map[string]bool
	state     *statepub.Publisher // état complet de la source ; nil = routes une à une et watch sans liste

	stateOK    atomic.Bool // la passerelle a pris le dernier état complet : un événement en provoque un nouveau
	stateTimer *time.Timer // regroupe les événements rapprochés en un seul état complet
}

// New crée une Discovery K8s. Retourne une erreur si la configuration est invalide.
func New(cfg *config.AgentConfig, log *slog.Logger) (*Discovery, error) {
	d := &Discovery{
		cfg:         cfg,
		adminURL:    cfg.ControlPlane.EdgeEndpoint,
		authToken:   cfg.ControlPlane.AuthToken,
		labelPrefix: cfg.Kubernetes.LabelPrefix,
		log:         log,
		hostByKey:   make(map[string]string),
		resync:      make(chan struct{}, 1),
	}
	if d.labelPrefix == "" {
		d.labelPrefix = cfg.Docker.LabelPrefix
	}
	if d.labelPrefix == "" {
		d.labelPrefix = "goproxify."
	}

	apiServer := cfg.Kubernetes.APIServer
	token := cfg.Kubernetes.Token
	caData := cfg.Kubernetes.CACert

	// In-cluster autodetect
	if apiServer == "" {
		apiServer = inClusterAPIServer
		if b, err := os.ReadFile(inClusterTokenFile); err == nil {
			token = strings.TrimSpace(string(b))
		}
		if caData == "" {
			caData = inClusterCAFile
		}
	}

	d.apiServer = apiServer
	d.k8sToken = token

	tlsCfg := &tls.Config{}
	if caData != "" {
		var caBytes []byte
		if _, err := os.Stat(caData); err == nil {
			caBytes, _ = os.ReadFile(caData)
		} else {
			caBytes = []byte(caData)
		}
		if len(caBytes) > 0 {
			pool := x509.NewCertPool()
			pool.AppendCertsFromPEM(caBytes)
			tlsCfg.RootCAs = pool
		}
	}
	d.client = &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsCfg},
		Timeout:   10 * time.Second,
	}
	return d, nil
}

// Start lance la boucle de surveillance et bloque jusqu'à ctx.Done().
func (d *Discovery) Start(ctx context.Context) {
	d.log.Info("k8s discovery: démarrage", "api_server", d.apiServer)
	go d.retryLoop(ctx)
	for {
		if err := d.watchAll(ctx); err != nil {
			if ctx.Err() != nil {
				return
			}
			d.log.Warn("k8s discovery: watch interrompu, retry dans 15s", "err", err)
			select {
			case <-ctx.Done():
				return
			case <-time.After(15 * time.Second):
			}
		}
	}
}

// --- Types K8s minimaux -------------------------------------------------------

type k8sServiceList struct {
	Items []k8sService `json:"items"`
}

// k8sListMeta : la version de la liste, d'où un watch reprend sans rien manquer ni rien rejouer.
type k8sListMeta struct {
	ResourceVersion string `json:"resourceVersion"`
}

type k8sServiceItems struct {
	Metadata k8sListMeta  `json:"metadata"`
	Items    []k8sService `json:"items"`
}

type k8sIngressItems struct {
	Metadata k8sListMeta  `json:"metadata"`
	Items    []k8sIngress `json:"items"`
}

type k8sService struct {
	Metadata k8sMeta `json:"metadata"`
	Spec     struct {
		ClusterIP string    `json:"clusterIP"`
		Ports     []k8sPort `json:"ports"`
	} `json:"spec"`
}

// k8sEndpointsItems : les objets Endpoints des Services annotés. Kubernetes leur recopie les labels du Service, le même
// sélecteur les trouve.
type k8sEndpointsItems struct {
	Items []struct {
		Metadata k8sMeta `json:"metadata"`
		Subsets  []struct {
			Addresses []json.RawMessage `json:"addresses"`
		} `json:"subsets"`
	} `json:"items"`
}

type k8sPort struct {
	Port     int    `json:"port"`
	Protocol string `json:"protocol"`
}

type k8sMeta struct {
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace"`
	Annotations map[string]string `json:"annotations"`
	Labels      map[string]string `json:"labels"`
}

type k8sWatchEvent struct {
	Type   string          `json:"type"` // ADDED | MODIFIED | DELETED
	Object json.RawMessage `json:"object"`
}

// k8sIngress représente un Ingress Kubernetes minimal.
type k8sIngress struct {
	Metadata k8sMeta     `json:"metadata"`
	Spec     ingressSpec `json:"spec"`
}

type ingressSpec struct {
	Rules []ingressRule `json:"rules"`
	TLS   []ingressTLS  `json:"tls"`
}

type ingressRule struct {
	Host string     `json:"host"`
	HTTP *httpPaths `json:"http"`
}

type httpPaths struct {
	Paths []ingressPath `json:"paths"`
}

type ingressPath struct {
	Path    string         `json:"path"`
	Backend ingressBackend `json:"backend"`
}

type ingressBackend struct {
	Service *ingressService `json:"service"`
}

type ingressService struct {
	Name string         `json:"name"`
	Port ingressSvcPort `json:"port"`
}

type ingressSvcPort struct {
	Number int `json:"number"`
}

type ingressTLS struct {
	Hosts []string `json:"hosts"`
}

// watchAll surveille Services et Ingress en parallèle.
// Si l'un des watchers se termine (erreur ou ctx annulé), l'autre est annulé aussi.
func (d *Discovery) watchAll(ctx context.Context) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	// L'état complet part d'abord : la passerelle retire ce que les watches n'ont pas vu disparaître. Les watches
	// reprennent alors de la version de la liste ; sans état envoyé ils rejouent l'existant, comme avant.
	svcRV, ingRV := d.snapshot(ctx)
	errCh := make(chan error, 2)
	go func() { errCh <- d.watchServices(ctx, svcRV) }()
	go func() { errCh <- d.watchIngresses(ctx, ingRV) }()
	go d.watchEndpoints(ctx)

	// La première erreur annule l'autre goroutine via cancel(). Une demande de réannonce relance
	// les deux watches : sans resourceVersion, l'API Kubernetes renvoie d'abord l'état courant sous
	// forme d'événements ADDED, donc toutes les routes sont republiées.
	select {
	case err := <-errCh:
		return err
	case <-d.resync:
		d.log.Info("k8s discovery: réannonce demandée — watches relancés")
		return nil
	}
}

// Resync republie toutes les routes (nouvelle passerelle, reconnexion) sans attendre un
// changement côté cluster : un Service ou un Ingress inchangé ne génère aucun événement.
func (d *Discovery) Resync(context.Context) {
	select {
	case d.resync <- struct{}{}:
	default: // une demande est déjà en attente
	}
}

// SetStatePublisher active l'envoi de l'état complet avant chaque démarrage des watches.
func (d *Discovery) SetStatePublisher(p *statepub.Publisher) {
	d.mu.Lock()
	d.state = p
	d.mu.Unlock()
}

// SetEndpointFunc fait suivre à la découverte la passerelle courante de l'Agent (bascule HA) au lieu
// de l'adresse fixée à la création.
func (d *Discovery) SetEndpointFunc(fn func() string) {
	d.epMu.Lock()
	d.endpointFn = fn
	d.epMu.Unlock()
}

func (d *Discovery) endpoint() string {
	d.epMu.RLock()
	fn := d.endpointFn
	d.epMu.RUnlock()
	if fn != nil {
		if ep := fn(); ep != "" {
			return ep
		}
	}
	return d.adminURL
}

// watchServices utilise le watch API K8s pour maintenir la liste à jour.
func (d *Discovery) watchServices(ctx context.Context, resourceVersion string) error {
	return d.watchStream(ctx, d.servicesPath(watchQuery(resourceVersion)), func(ev k8sWatchEvent) {
		var svc k8sService
		if err := json.Unmarshal(ev.Object, &svc); err != nil {
			return
		}
		switch ev.Type {
		case "ADDED", "MODIFIED":
			d.upsertService(ctx, svc)
		case "DELETED":
			d.deleteByKey(ctx, svcKey(svc.Metadata))
		}
		d.scheduleState(ctx)
	})
}

// watchEndpoints renvoie l'état complet quand les adresses prêtes d'un Service annoté changent : un pod qui démarre ou
// s'arrête ne modifie pas le Service, donc aucun de ses événements ne le dirait. Sans le droit de lire les Endpoints, ou
// sur une erreur, il réessaie plus tard sans gêner les watches des Services et des Ingress.
func (d *Discovery) watchEndpoints(ctx context.Context) {
	for ctx.Err() == nil {
		err := d.watchStream(ctx, d.endpointsPath(watchQuery("")), func(k8sWatchEvent) { d.scheduleState(ctx) })
		if ctx.Err() != nil {
			return
		}
		d.log.Debug("k8s discovery: watch des Endpoints interrompu", "err", err)
		select {
		case <-ctx.Done():
			return
		case <-time.After(60 * time.Second):
		}
	}
}

// watchIngresses surveille les Ingress annotés goproxify.enabled=true.
func (d *Discovery) watchIngresses(ctx context.Context, resourceVersion string) error {
	return d.watchStream(ctx, d.ingressesPath(watchQuery(resourceVersion)), func(ev k8sWatchEvent) {
		var ing k8sIngress
		if err := json.Unmarshal(ev.Object, &ing); err != nil {
			return
		}
		switch ev.Type {
		case "ADDED", "MODIFIED":
			d.upsertIngress(ctx, ing)
		case "DELETED":
			d.deleteByKey(ctx, ingKey(ing.Metadata))
		}
		d.scheduleState(ctx)
	})
}

// watchStream ouvre un watch stream K8s et appelle fn pour chaque événement.
func (d *Discovery) watchStream(ctx context.Context, path string, fn func(k8sWatchEvent)) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.apiServer+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.k8sToken)

	watchClient := &http.Client{Transport: d.client.Transport}
	resp, err := watchClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("k8s watch %s: %d %s", path, resp.StatusCode, b)
	}

	dec := json.NewDecoder(resp.Body)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		var ev k8sWatchEvent
		if err := dec.Decode(&ev); err != nil {
			return err
		}
		fn(ev)
	}
}

// k8sRoute est ce qu'une ressource Kubernetes demande à la passerelle : une route.
type k8sRoute struct {
	key     string
	ann     map[string]string
	host    string
	backend string
	tls     bool
}

// upsertService traduit un Service K8s en route proxy et la pousse à la passerelle.
func (d *Discovery) upsertService(ctx context.Context, svc k8sService) {
	d.mu.Lock()
	idle := d.idle[svcKey(svc.Metadata)]
	d.mu.Unlock()
	if idle {
		return
	}
	if r, ok := d.serviceRoute(svc); ok {
		d.pushRoute(ctx, r.key, r.ann, r.host, r.backend, r.tls)
	}
}

// serviceRoute traduit un Service en route ; faux s'il n'en demande pas (pas d'hôte).
func (d *Discovery) serviceRoute(svc k8sService) (k8sRoute, bool) {
	ann := svc.Metadata.Annotations
	if ann == nil {
		ann = map[string]string{}
	}
	p := d.labelPrefix

	host := ann[p+"host"]
	if host == "" {
		host = ann[p+"domain"]
	}
	if host == "" {
		return k8sRoute{}, false
	}

	backendPort := 80
	if len(svc.Spec.Ports) > 0 {
		backendPort = svc.Spec.Ports[0].Port
	}
	if ann[p+"port"] != "" {
		fmt.Sscanf(ann[p+"port"], "%d", &backendPort)
	}
	backendURL := fmt.Sprintf("http://%s:%d", svc.Spec.ClusterIP, backendPort)
	if ann[p+"backend"] != "" {
		backendURL = ann[p+"backend"]
	}

	return k8sRoute{key: svcKey(svc.Metadata), ann: ann, host: host, backend: backendURL, tls: ann[p+"tls"] == "true"}, true
}

// upsertIngress traduit un Ingress K8s en routes proxy et les pousse à la passerelle.
func (d *Discovery) upsertIngress(ctx context.Context, ing k8sIngress) {
	for _, r := range d.ingressRoutes(ing) {
		d.pushRoute(ctx, r.key, r.ann, r.host, r.backend, r.tls)
	}
}

// ingressRoutes traduit un Ingress en routes, une par règle d'hôte.
func (d *Discovery) ingressRoutes(ing k8sIngress) []k8sRoute {
	var out []k8sRoute
	ann := ing.Metadata.Annotations
	if ann == nil {
		ann = map[string]string{}
	}
	p := d.labelPrefix

	// Ensemble des hosts TLS déclarés dans spec.tls[].hosts
	tlsHosts := map[string]bool{}
	for _, t := range ing.Spec.TLS {
		for _, h := range t.Hosts {
			tlsHosts[h] = true
		}
	}

	// Override TLS global via annotation
	tlsForced := ann[p+"tls"] == "true"

	for _, rule := range ing.Spec.Rules {
		host := rule.Host
		if host == "" {
			continue
		}
		tls := tlsForced || tlsHosts[host]

		// Backend : annotation > première règle HTTP
		backendURL := ann[p+"backend"]
		if backendURL == "" && rule.HTTP != nil && len(rule.HTTP.Paths) > 0 {
			svcName := ""
			svcPort := 80
			if be := rule.HTTP.Paths[0].Backend.Service; be != nil {
				svcName = be.Name
				if be.Port.Number > 0 {
					svcPort = be.Port.Number
				}
			}
			if svcName != "" {
				ns := ing.Metadata.Namespace
				if ns == "" {
					ns = "default"
				}
				backendURL = fmt.Sprintf("http://%s.%s.svc.cluster.local:%d", svcName, ns, svcPort)
			}
		}
		if backendURL == "" {
			continue
		}

		out = append(out, k8sRoute{key: ingKey(ing.Metadata) + ":" + host, ann: ann, host: host, backend: backendURL, tls: tls})
	}
	return out
}

// routePayload construit le payload Agent→Passerelle d'une route. Les annotations suivent exactement la
// sémantique des labels Docker (waf, rate_limit, jwt, mtls, backpressure…) : elles passent par le même
// parseur, préfixe configurable normalisé vers "goproxify.". Retourne nil si l'hôte est invalide.
func (d *Discovery) routePayload(key string, ann map[string]string, host, backendURL string, tls bool) (map[string]any, *docker.ProxySpec) {
	labels := make(map[string]string, len(ann)+4)
	for k, v := range ann {
		if rest, ok := strings.CutPrefix(k, d.labelPrefix); ok {
			labels["goproxify."+rest] = v
		}
	}
	// Les valeurs déduites de la ressource K8s l'emportent sur les annotations.
	labels[docker.LabelEnable] = "true"
	labels[docker.LabelHost] = host
	labels[docker.LabelBackendURL] = backendURL
	if tls {
		labels[docker.LabelTLS] = "true"
	}
	spec := docker.ParseLabels("k8s:"+key, key, "", "", labels, nil, "")
	if spec == nil {
		return nil, nil
	}
	payload := map[string]any{
		"host":         spec.Host,
		"aliases":      spec.Aliases,
		"paths":        spec.Paths,
		"route_type":   spec.Type,
		"backends":     []string{backendURL},
		"tls_enabled":  spec.TLS,
		"passthrough":  spec.Passthrough,
		"source":       "k8s",
		"container_id": "k8s:" + key,
		"agent_name":   d.cfg.Identity.NodeName,
		"role":         spec.Role,
	}
	if spec.Role == docker.RoleCanary {
		payload["canary_weight"] = spec.CanaryWeight
	}
	docker.AttachSecurityPayload(payload, spec)
	return payload, spec
}

// pushRoute envoie un payload agentContainerPayload compatible à la passerelle.
func (d *Discovery) pushRoute(ctx context.Context, key string, ann map[string]string, host, backendURL string, tls bool) {
	payload, spec := d.routePayload(key, ann, host, backendURL, tls)
	if payload == nil {
		d.log.Warn("k8s discovery: hôte invalide, route ignorée", "host", host, "key", key)
		return
	}
	d.mu.Lock()
	d.hostByKey[key] = spec.Host
	delete(d.pendingDel, "docker-host:"+spec.Host) // la route est de nouveau voulue
	d.mu.Unlock()
	host = spec.Host
	tls = spec.TLS
	body, _ := json.Marshal(payload)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		d.endpoint()+"/internal/v1/agent/containers", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+d.token())
	resp, err := d.client.Do(req)
	if err != nil {
		d.log.Warn("k8s discovery: push route", "host", host, "err", err)
		d.dirty.Store(true)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		d.dirty.Store(true)
	}
	d.log.Info("k8s discovery: route enregistrée", "host", host, "backend", backendURL, "tls", tls)
}

// deleteByKey supprime la route associée à une clé namespace/name.
func (d *Discovery) deleteByKey(ctx context.Context, key string) {
	d.mu.Lock()
	host := d.hostByKey[key]
	delete(d.hostByKey, key)
	// Supprimer aussi les sous-clés Ingress (key + ":" + host)
	for k := range d.hostByKey {
		if strings.HasPrefix(k, key+":") {
			if h := d.hostByKey[k]; h != "" && host == "" {
				host = h
			}
			delete(d.hostByKey, k)
		}
	}
	d.mu.Unlock()

	if host == "" {
		return
	}
	// La passerelle génère l'ID de route "docker-host:{host}" via handleAgentContainerStart.
	routeID := "docker-host:" + host
	req, err := http.NewRequestWithContext(ctx, http.MethodDelete,
		d.endpoint()+"/internal/v1/routes/"+url.PathEscape(routeID), nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+d.token())
	resp, err := d.client.Do(req)
	if err != nil {
		d.log.Warn("k8s discovery: suppression route", "host", host, "err", err)
		d.rememberFailedDelete(routeID, host)
		return
	}
	resp.Body.Close()
	if resp.StatusCode >= 500 {
		d.rememberFailedDelete(routeID, host)
		return
	}
	d.log.Info("k8s discovery: route supprimée", "host", host)
}

// servicesPath et ingressesPath : le chemin de la liste (query vide) ou du watch, avec le même sélecteur et le même
// namespace.
func (d *Discovery) servicesPath(query string) string {
	base := "/api/v1/services"
	if ns := d.cfg.Kubernetes.Namespace; ns != "" {
		base = "/api/v1/namespaces/" + ns + "/services"
	}
	return base + "?" + query + "labelSelector=" + labelSelectorEscape(d.labelPrefix+"enabled=true")
}

func (d *Discovery) endpointsPath(query string) string {
	base := "/api/v1/endpoints"
	if ns := d.cfg.Kubernetes.Namespace; ns != "" {
		base = "/api/v1/namespaces/" + ns + "/endpoints"
	}
	return base + "?" + query + "labelSelector=" + labelSelectorEscape(d.labelPrefix+"enabled=true")
}

func (d *Discovery) ingressesPath(query string) string {
	base := "/apis/networking.k8s.io/v1/ingresses"
	if ns := d.cfg.Kubernetes.Namespace; ns != "" {
		base = "/apis/networking.k8s.io/v1/namespaces/" + ns + "/ingresses"
	}
	return base + "?" + query + "labelSelector=" + labelSelectorEscape(d.labelPrefix+"enabled=true")
}

func watchQuery(resourceVersion string) string {
	if resourceVersion == "" {
		return "watch=1&"
	}
	return "watch=1&resourceVersion=" + url.QueryEscape(resourceVersion) + "&"
}

func (d *Discovery) getJSON(ctx context.Context, path string, into any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, d.apiServer+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+d.k8sToken)
	resp, err := d.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("k8s liste %s: %d %s", path, resp.StatusCode, b)
	}
	return json.NewDecoder(resp.Body).Decode(into)
}

// snapshot liste les Services et les Ingress annotés, envoie l'état complet à la passerelle et rend les versions d'où
// démarrer les watches. Vides : l'état n'est pas parti (pas de publication d'état, liste en échec, passerelle ancienne
// ou en échec) et les watches rejouent l'existant. Il faut les deux listes : un état partiel retirerait les routes de
// la ressource qu'on n'a pas pu lire.
func (d *Discovery) snapshot(ctx context.Context) (svcRV, ingRV string) {
	d.mu.Lock()
	pub := d.state
	d.mu.Unlock()
	if pub == nil {
		return "", ""
	}
	var svcs k8sServiceItems
	if err := d.getJSON(ctx, d.servicesPath(""), &svcs); err != nil {
		d.log.Warn("k8s discovery: liste des Services", "err", err)
		return "", ""
	}
	var ings k8sIngressItems
	if err := d.getJSON(ctx, d.ingressesPath(""), &ings); err != nil {
		d.log.Warn("k8s discovery: liste des Ingress", "err", err)
		return "", ""
	}

	idle := d.idleServices(ctx)

	var wanted []k8sRoute
	for _, svc := range svcs.Items {
		if r, ok := d.serviceRoute(svc); ok {
			wanted = append(wanted, r)
		}
	}
	for _, ing := range ings.Items {
		wanted = append(wanted, d.ingressRoutes(ing)...)
	}
	routes := make([]map[string]any, 0, len(wanted))
	var inactive []map[string]any
	hosts := make(map[string]string, len(wanted))
	for _, r := range wanted {
		payload, spec := d.routePayload(r.key, r.ann, r.host, r.backend, r.tls)
		if payload == nil {
			d.log.Warn("k8s discovery: hôte invalide, route ignorée", "host", r.host, "key", r.key)
			continue
		}
		if idle[r.key] {
			inactive = append(inactive, map[string]any{
				"id": "k8s:" + r.key, "host": spec.Host, "aliases": spec.Aliases,
				"container_id": "k8s:" + r.key, "name": r.key, "state": "no-endpoints",
			})
			continue
		}
		routes = append(routes, payload)
		hosts[r.key] = spec.Host
	}

	res, err := pub.PutState(ctx, d.endpoint(), d.token(), "k8s", "", routes, inactive)
	switch res {
	case statepub.Sent:
		d.mu.Lock()
		d.idle = idle
		d.hostByKey = hosts
		for _, h := range hosts {
			delete(d.pendingDel, "docker-host:"+h) // la route est de nouveau voulue
		}
		d.mu.Unlock()
		d.stateOK.Store(true)
		d.log.Info("k8s discovery: état complet envoyé", "routes", len(routes), "inactifs", len(inactive))
		return svcs.Metadata.ResourceVersion, ings.Metadata.ResourceVersion
	case statepub.Failed:
		d.dirty.Store(true)
		d.log.Warn("k8s discovery: état complet non envoyé", "err", err)
	}
	d.stateOK.Store(false)
	return "", ""
}

// idleServices rend les Services dont l'objet Endpoints n'a aucune adresse prête (« namespace/nom »). Un Service sans
// objet Endpoints (ExternalName) ou une liste impossible à lire (droit absent, erreur) ne rend personne inactif : ne pas
// savoir n'est pas être arrêté.
func (d *Discovery) idleServices(ctx context.Context) map[string]bool {
	var eps k8sEndpointsItems
	if err := d.getJSON(ctx, d.endpointsPath(""), &eps); err != nil {
		d.log.Debug("k8s discovery: liste des Endpoints impossible, aucun Service n'est donné inactif", "err", err)
		return nil
	}
	idle := map[string]bool{}
	for _, ep := range eps.Items {
		ready := false
		for _, s := range ep.Subsets {
			if len(s.Addresses) > 0 {
				ready = true
				break
			}
		}
		if !ready {
			idle[svcKey(ep.Metadata)] = true
		}
	}
	return idle
}

// stateAfterEventDelay regroupe les événements rapprochés (un déploiement) en un seul état complet.
const stateAfterEventDelay = 3 * time.Second

// scheduleState renvoie l'état complet peu après un événement : la passerelle qui reçoit directement l'Agent a déjà la
// route par le POST ou le DELETE, c'est cet état qui atteint les autres membres du groupe HA. Sans effet tant que la
// passerelle n'a pas pris d'état complet. Les watches ne sont pas relancés.
func (d *Discovery) scheduleState(ctx context.Context) {
	if !d.stateOK.Load() {
		return
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	if d.stateTimer != nil {
		return
	}
	d.stateTimer = time.AfterFunc(stateAfterEventDelay, func() {
		d.mu.Lock()
		d.stateTimer = nil
		d.mu.Unlock()
		if ctx.Err() == nil {
			d.snapshot(ctx)
		}
	})
}

func svcKey(m k8sMeta) string {
	return m.Namespace + "/" + m.Name
}

func ingKey(m k8sMeta) string {
	return "ing:" + m.Namespace + "/" + m.Name
}

func labelSelectorEscape(s string) string {
	return strings.ReplaceAll(s, " ", "%20")
}

// SetToken remplace le jeton d'agent utilisé auprès de la passerelle. Il est appelé quand
// l'appairage aboutit après la construction de la découverte : sans cela, un agent appairé à
// l'exécution (sans jeton statique en configuration) envoyait ses routes Kubernetes sans
// authentification.
func (d *Discovery) SetToken(token string) {
	d.tokMu.Lock()
	d.authToken = token
	d.tokMu.Unlock()
}

func (d *Discovery) token() string {
	d.tokMu.RLock()
	defer d.tokMu.RUnlock()
	return d.authToken
}

// retryInterval est le délai entre deux contrôles des envois échoués.
const retryInterval = 20 * time.Second

func (d *Discovery) rememberFailedDelete(routeID, host string) {
	d.mu.Lock()
	if d.pendingDel == nil {
		d.pendingDel = map[string]string{}
	}
	d.pendingDel[routeID] = host
	d.mu.Unlock()
}

// retryLoop rejoue ce qui n'est pas parti : les suppressions échouées, puis — si un envoi de route a
// échoué — la réannonce complète. Sans cela, une passerelle injoignable un instant laissait une route
// manquante (ou périmée) jusqu'à la prochaine bascule, reconnexion ou expiration du watch.
func (d *Discovery) retryLoop(ctx context.Context) {
	t := time.NewTicker(retryInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.retryOnce(ctx)
		}
	}
}

func (d *Discovery) retryOnce(ctx context.Context) {
	d.mu.Lock()
	pending := make(map[string]string, len(d.pendingDel))
	for id, host := range d.pendingDel {
		pending[id] = host
	}
	d.mu.Unlock()
	for id, host := range pending {
		req, err := http.NewRequestWithContext(ctx, http.MethodDelete, d.endpoint()+"/internal/v1/routes/"+url.PathEscape(id), nil)
		if err != nil {
			continue
		}
		req.Header.Set("Authorization", "Bearer "+d.token())
		resp, err := d.client.Do(req)
		if err != nil {
			continue
		}
		resp.Body.Close()
		if resp.StatusCode < 500 {
			d.mu.Lock()
			delete(d.pendingDel, id)
			d.mu.Unlock()
			d.log.Info("k8s discovery: suppression rejouée", "host", host)
		}
	}
	if d.dirty.Swap(false) {
		d.log.Info("k8s discovery: réannonce après envoi en échec")
		d.Resync(ctx)
	}
}
