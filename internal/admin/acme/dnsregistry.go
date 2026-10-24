// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/plugins"
	"github.com/vincamok/goproxify/internal/modules"
)

// DNSFactory construit un fournisseur DNS depuis ses paramètres.
type DNSFactory func(params map[string]string) (DNSProvider, error)

// dnsRegistry range les fournisseurs DNS ACME (modules de la famille « DNS », ADR 0007). Le
// manifeste d'un fournisseur décrit ses paramètres, la variable d'environnement qui fournit
// chacun par défaut, ceux qui sont secrets et ceux qui sont requis ; NewProvider,
// ProviderConfigFromEnv, la validation des fournisseurs nommés, l'API et les formulaires de
// l'Admin en découlent. Ajouter un fournisseur = un appel à registerDNS depuis init().
var dnsRegistry = modules.NewRegistry[DNSFactory]()

func registerDNS(m modules.Manifest, f DNSFactory) { dnsRegistry.Register(m, f) }

// DNSProviderManifests retourne les manifestes des fournisseurs DNS, dans l'ordre d'affichage.
func DNSProviderManifests() []modules.Manifest { return dnsRegistry.Manifests() }

// DNSProviderManifest retourne le manifeste d'un type de fournisseur DNS.
func DNSProviderManifest(typ string) (modules.Manifest, bool) {
	_, m, ok := dnsRegistry.Lookup(typ)
	return m, ok
}

// Masked retourne l'entrée avec ses paramètres secrets masqués selon le manifeste du type. Un type
// inconnu (entrée ancienne) est renvoyé tel quel : on ne sait pas quels champs sont secrets.
func (e ProviderEntry) Masked() ProviderEntry {
	m, ok := DNSProviderManifest(e.Type)
	if !ok {
		return e
	}
	params := make(map[string]string, len(e.Params))
	for k, v := range e.Params {
		params[k] = v
	}
	for _, f := range m.Fields {
		if f.Secret && params[f.Key] != "" {
			params[f.Key] = modules.Masque
		}
	}
	e.Params = params
	return e
}

// DNSStatusNotImplemented marque un fournisseur déclaré mais dont l'émission échoue
// (attribut « status » du manifeste).
const DNSStatusNotImplemented = "not_implemented"

func init() {
	param := func(key, label, placeholder, env string, required bool) modules.Field {
		return modules.Field{Key: key, Label: label, Placeholder: placeholder, Kind: modules.KindText, Env: env, Required: required}
	}
	secret := func(key, label, placeholder, env string, required bool) modules.Field {
		return modules.Field{Key: key, Label: label, Placeholder: placeholder, Kind: modules.KindPassword, Secret: true, Env: env, Required: required}
	}

	registerDNS(modules.Manifest{Type: "ovh", Label: "OVH", Fields: []modules.Field{
		param("endpoint", "Endpoint", "https://eu.api.ovh.com/1.0", "OVH_ENDPOINT", false),
		secret("app_key", "Application Key", "", "OVH_APPLICATION_KEY", true),
		secret("app_secret", "Application Secret", "", "OVH_APPLICATION_SECRET", true),
		secret("consumer_key", "Consumer Key", "", "OVH_CONSUMER_KEY", true),
		param("zone", "DNS zone", "example.com", "OVH_ZONE", true),
	}}, newOVHProvider)

	registerDNS(modules.Manifest{Type: "cloudflare", Label: "Cloudflare", Fields: []modules.Field{
		secret("api_token", "API Token", "Cloudflare API token", "CF_API_TOKEN", true),
		param("zone_id", "Zone ID", "Optional — resolved automatically when empty", "CF_ZONE_ID", false),
	}}, newCloudflareProvider)

	registerDNS(modules.Manifest{Type: "route53", Label: "AWS Route 53", Fields: []modules.Field{
		param("hosted_zone_id", "Hosted Zone ID", "Z1234567890", "AWS_HOSTED_ZONE_ID", true),
		secret("access_key_id", "Access Key ID", "AKIA…", "AWS_ACCESS_KEY_ID", true),
		secret("secret_access_key", "Secret Access Key", "", "AWS_SECRET_ACCESS_KEY", true),
		secret("session_token", "Session token (temporary credentials)", "", "AWS_SESSION_TOKEN", false),
	}}, newRoute53Provider)

	registerDNS(modules.Manifest{Type: "hetzner", Label: "Hetzner", Fields: []modules.Field{
		secret("api_token", "API Token", "Hetzner DNS token", "HETZNER_API_KEY", true),
		param("zone_id", "Zone ID", "Hetzner zone ID", "HETZNER_ZONE_ID", true),
	}}, newHetznerProvider)

	registerDNS(modules.Manifest{Type: "gandi", Label: "Gandi", Fields: []modules.Field{
		secret("api_key", "API Key", "Gandi LiveDNS API key", "GANDI_API_KEY", true),
	}}, newGandiProvider)
}

// NewProvider instancie le bon fournisseur selon le type.
func NewProvider(cfg ProviderConfig) (DNSProvider, error) {
	f, _, ok := dnsRegistry.Lookup(cfg.Type)
	if !ok {
		return nil, fmt.Errorf("acme: fournisseur DNS inconnu %q", cfg.Type)
	}
	return f(cfg.Params)
}

// ProviderConfigFromEnv construit un ProviderConfig depuis les variables d'environnement
// déclarées par le manifeste du fournisseur. Les paramètres absents de l'environnement restent
// présents, vides : mergeProviderParams s'en sert pour compléter les identifiants d'un domaine.
func ProviderConfigFromEnv(dnsType string) ProviderConfig {
	params := map[string]string{}
	if m, ok := DNSProviderManifest(dnsType); ok {
		for _, f := range m.Fields {
			if f.Env != "" {
				params[f.Key] = os.Getenv(f.Env)
			}
		}
	}
	return ProviderConfig{Type: dnsType, Params: params}
}

// ValidateDNSParams contrôle ce que le manifeste ne sait pas dire : l'endpoint OVH est une URL libre, vers laquelle
// partent la clé d'application et la clé consommateur ; il doit désigner une API en HTTPS, pas un service interne.
func ValidateDNSParams(typ string, params map[string]any) error {
	if typ != "ovh" {
		return validateLibdnsParams(typ, params)
	}
	ep, _ := params["endpoint"].(string)
	ep = strings.TrimSpace(ep)
	if ep == "" {
		return nil
	}
	if _, named := ovhEndpoints[strings.ToLower(ep)]; named {
		return nil
	}
	u, err := url.Parse(ep)
	if err != nil || u.Scheme != "https" || u.Hostname() == "" {
		return fmt.Errorf("endpoint OVH %q : un nom (ovh-eu, ovh-ca, ovh-us) ou une URL https est requis", ep)
	}
	host := strings.ToLower(u.Hostname())
	if host == "localhost" || strings.HasSuffix(host, ".localhost") || plugins.BlockedHost(host) {
		return fmt.Errorf("endpoint OVH %q : adresse interne refusée", ep)
	}
	return nil
}

// DefaultProviderConfig résout le fournisseur DNS par défaut de l'Admin. dnsType est un type (`ovh`, `cloudflare`…) ou,
// parce que l'écran Infrastructure y enregistre ce qu'on choisit dans sa liste, l'identifiant d'un fournisseur nommé :
// celui-ci apporte alors son type et ses paramètres. configured : paramètres posés dans la configuration de l'Admin, qui
// remplacent ceux de l'environnement pour un type.
func DefaultProviderConfig(dnsType string, configured map[string]string, named *ProviderStore) ProviderConfig {
	if named != nil {
		if e, err := named.Get(dnsType); err == nil && e != nil {
			return ProviderConfig{Type: e.Type, Params: e.Params}
		}
	}
	cfg := ProviderConfigFromEnv(dnsType)
	if len(configured) > 0 {
		cfg.Params = configured
	}
	return cfg
}
