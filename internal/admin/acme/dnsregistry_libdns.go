// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/libdns/azure"
	"github.com/libdns/bunny"
	"github.com/libdns/cloudns"
	"github.com/libdns/desec"
	"github.com/libdns/digitalocean"
	"github.com/libdns/dnsimple"
	"github.com/libdns/duckdns"
	"github.com/libdns/dynu"
	"github.com/libdns/easydns"
	"github.com/libdns/gcore"
	"github.com/libdns/godaddy"
	"github.com/libdns/googleclouddns"
	"github.com/libdns/he"
	"github.com/libdns/infomaniak"
	"github.com/libdns/inwx"
	"github.com/libdns/ionos"
	"github.com/libdns/libdns"
	"github.com/libdns/linode"
	"github.com/libdns/loopia"
	"github.com/libdns/luadns"
	"github.com/libdns/namecheap"
	"github.com/libdns/namedotcom"
	"github.com/libdns/netcup"
	"github.com/libdns/netlify"
	"github.com/libdns/njalla"
	"github.com/libdns/porkbun"
	"github.com/libdns/powerdns"
	"github.com/libdns/scaleway"
	"github.com/libdns/vercel"
	"golang.org/x/net/publicsuffix"

	"github.com/vincamok/goproxify/internal/modules"
	"github.com/vincamok/goproxify/internal/ssrf"
)

// Fournisseurs DNS issus de libdns (https://github.com/libdns) : un module Go par fournisseur, une interface commune
// (ajout et suppression d'enregistrements dans une zone). Un adaptateur unique en fait des DNSProvider ; chaque
// fournisseur n'est qu'une ligne de tableau (manifeste + constructeur). Les paramètres du manifeste portent le nom de
// l'étiquette JSON du fournisseur : ils sont décodés directement dans sa structure de configuration.

type libdnsAPI interface {
	libdns.RecordAppender
	libdns.RecordDeleter
}

type ldField struct {
	key, label, placeholder string
	secret, required        bool
	// url : le paramètre est une adresse d'API (validée comme l'endpoint OVH, avant tout envoi d'identifiants).
	url bool
}

type ldSpec struct {
	typ, label string
	fields     []ldField
	build      func() libdnsAPI
	// ttl : durée des TXT de challenge (certains fournisseurs refusent moins de 600 s).
	ttl time.Duration
	// privateURL : l'adresse d'API peut être un réseau interne (fournisseur auto-hébergé).
	privateURL bool
}

const libdnsTXTTTL = 300 * time.Second

func ldText(key, label string, required bool) ldField {
	return ldField{key: key, label: label, required: required}
}
func ldSecret(key, label string, required bool) ldField {
	return ldField{key: key, label: label, required: required, secret: true}
}
func ldURL(key, label, placeholder string) ldField {
	return ldField{key: key, label: label, placeholder: placeholder, url: true}
}

var libdnsSpecs = []ldSpec{
	{typ: "azure", label: "Azure DNS", build: func() libdnsAPI { return &azure.Provider{} }, fields: []ldField{
		ldText("subscription_id", "Subscription ID", true), ldText("resource_group_name", "Resource group", true),
		ldText("tenant_id", "Tenant ID", false), ldText("client_id", "Client ID", false), ldSecret("client_secret", "Client secret", false)}},
	{typ: "bunny", label: "Bunny DNS", build: func() libdnsAPI { return &bunny.Provider{} }, fields: []ldField{ldSecret("access_key", "Access key", true)}},
	{typ: "cloudns", label: "ClouDNS", build: func() libdnsAPI { return &cloudns.Provider{} }, fields: []ldField{
		ldText("auth_id", "Auth ID", false), ldText("sub_auth_id", "Sub-auth ID", false), ldText("sub_auth_user", "Sub-auth user", false), ldSecret("auth_password", "Auth password", true)}},
	{typ: "desec", label: "deSEC", build: func() libdnsAPI { return &desec.Provider{} }, fields: []ldField{ldSecret("token", "API token", true)}},
	{typ: "digitalocean", label: "DigitalOcean", build: func() libdnsAPI { return &digitalocean.Provider{} }, fields: []ldField{ldSecret("auth_token", "API token", true)}},
	{typ: "dnsimple", label: "DNSimple", build: func() libdnsAPI { return &dnsimple.Provider{} }, fields: []ldField{
		ldSecret("api_access_token", "API access token", true), ldText("account_id", "Account ID", false), ldURL("api_url", "API URL", "https://api.dnsimple.com")}},
	{typ: "duckdns", label: "DuckDNS", build: func() libdnsAPI { return &duckdns.Provider{} }, fields: []ldField{
		ldSecret("api_token", "Token", true), ldText("override_domain", "Domain override", false)}},
	{typ: "dynu", label: "Dynu", build: func() libdnsAPI { return &dynu.Provider{} }, fields: []ldField{
		ldSecret("api_token", "API token", true), ldText("own_domain", "Own domain", false)}},
	{typ: "easydns", label: "EasyDNS", build: func() libdnsAPI { return &easydns.Provider{} }, fields: []ldField{
		ldSecret("api_token", "API token", true), ldSecret("api_key", "API key", true), ldURL("api_url", "API URL", "")}},
	{typ: "gcore", label: "Gcore", build: func() libdnsAPI { return &gcore.Provider{} }, fields: []ldField{ldSecret("api_key", "API key", true)}},
	{typ: "godaddy", label: "GoDaddy", build: func() libdnsAPI { return &godaddy.Provider{} }, ttl: 600 * time.Second, fields: []ldField{
		ldSecret("api_token", "API token (key:secret)", true)}},
	{typ: "googleclouddns", label: "Google Cloud DNS", build: func() libdnsAPI { return &googleclouddns.Provider{} }, fields: []ldField{
		ldText("gcp_project", "Project ID", true), {key: "gcp_application_default", label: "Service account JSON file (path on the Admin host)"}}},
	{typ: "he", label: "Hurricane Electric", build: func() libdnsAPI { return &he.Provider{} }, fields: []ldField{ldSecret("api_key", "API key", true)}},
	{typ: "infomaniak", label: "Infomaniak", build: func() libdnsAPI { return &infomaniak.Provider{} }, fields: []ldField{ldSecret("api_token", "API token", true)}},
	{typ: "inwx", label: "INWX", build: func() libdnsAPI { return &inwx.Provider{} }, fields: []ldField{
		ldText("username", "Username", true), ldSecret("password", "Password", true), ldSecret("shared_secret", "2FA shared secret", false), ldURL("endpoint_url", "Endpoint URL", "")}},
	{typ: "ionos", label: "IONOS", build: func() libdnsAPI { return &ionos.Provider{} }, fields: []ldField{ldSecret("auth_api_token", "API token", true)}},
	{typ: "linode", label: "Linode / Akamai", build: func() libdnsAPI { return &linode.Provider{} }, fields: []ldField{
		ldSecret("api_token", "API token", true), ldURL("api_url", "API URL", ""), ldText("api_version", "API version", false)}},
	{typ: "loopia", label: "Loopia", build: func() libdnsAPI { return &loopia.Provider{} }, fields: []ldField{
		ldText("username", "Username", true), ldSecret("password", "Password", true), ldText("customer", "Customer number", false)}},
	{typ: "luadns", label: "LuaDNS", build: func() libdnsAPI { return &luadns.Provider{} }, fields: []ldField{
		ldText("email", "Email", true), ldSecret("api_key", "API key", true)}},
	{typ: "namecheap", label: "Namecheap", build: func() libdnsAPI { return &namecheap.Provider{} }, fields: []ldField{
		ldSecret("api_key", "API key", true), ldText("user", "User", true), ldURL("api_endpoint", "API endpoint", ""), ldText("client_ip", "Whitelisted client IP", false)}},
	{typ: "namedotcom", label: "Name.com", build: func() libdnsAPI { return &namedotcom.Provider{} }, fields: []ldField{
		ldSecret("api_token", "API token", true), ldText("user", "User", true), ldURL("server", "API server", "")}},
	{typ: "netcup", label: "netcup", build: func() libdnsAPI { return &netcup.Provider{} }, fields: []ldField{
		ldText("customer_number", "Customer number", true), ldSecret("api_key", "API key", true), ldSecret("api_password", "API password", true)}},
	{typ: "netlify", label: "Netlify", build: func() libdnsAPI { return &netlify.Provider{} }, fields: []ldField{ldSecret("personal_access_token", "Personal access token", true)}},
	{typ: "njalla", label: "Njalla", build: func() libdnsAPI { return &njalla.Provider{} }, fields: []ldField{ldSecret("api_token", "API token", true)}},
	{typ: "porkbun", label: "Porkbun", build: func() libdnsAPI { return &porkbun.Provider{} }, fields: []ldField{
		ldSecret("api_key", "API key", true), ldSecret("api_secret_key", "Secret API key", true)}},
	{typ: "powerdns", label: "PowerDNS", build: func() libdnsAPI { return &powerdns.Provider{} }, privateURL: true, fields: []ldField{
		{key: "server_url", label: "Server URL", placeholder: "https://pdns.example.com:8081", required: true, url: true},
		ldSecret("api_token", "API key", true), ldText("server_id", "Server ID", false)}},
	{typ: "scaleway", label: "Scaleway", build: func() libdnsAPI { return &scaleway.Provider{} }, fields: []ldField{
		ldSecret("secret_key", "Secret key", true), ldText("organization_id", "Project / organization ID", false)}},
	{typ: "vercel", label: "Vercel", build: func() libdnsAPI { return &vercel.Provider{} }, fields: []ldField{ldSecret("auth_api_token", "API token", true)}},
}

func init() {
	for _, s := range libdnsSpecs {
		m := modules.Manifest{Type: s.typ, Label: s.label, Attrs: map[string]any{"engine": "libdns"}}
		for _, p := range s.fields {
			kind := modules.KindText
			if p.secret {
				kind = modules.KindPassword
			}
			m.Fields = append(m.Fields, modules.Field{
				Key: p.key, Label: p.label, Placeholder: p.placeholder, Kind: kind, Secret: p.secret, Required: p.required,
				Env: strings.ToUpper(s.typ + "_" + p.key),
			})
		}
		m.Fields = append(m.Fields, modules.Field{
			Key: "zone", Label: "DNS zone", Placeholder: "Optional — deduced from the domain (registrable domain) when empty",
			Kind: modules.KindText, Env: strings.ToUpper(s.typ + "_zone"),
		})
		registerDNS(m, newLibdnsFactory(s))
	}
}

func newLibdnsFactory(s ldSpec) DNSFactory {
	return func(params map[string]string) (DNSProvider, error) {
		cfg := map[string]string{}
		for _, p := range s.fields {
			v := strings.TrimSpace(params[p.key])
			if v == "" {
				if p.required {
					return nil, fmt.Errorf("%s: %s requis", s.typ, p.key)
				}
				continue
			}
			cfg[p.key] = v
		}
		raw, _ := json.Marshal(cfg)
		prov := s.build()
		if err := json.Unmarshal(raw, prov); err != nil {
			return nil, fmt.Errorf("%s: configuration invalide: %w", s.typ, err)
		}
		ttl := s.ttl
		if ttl == 0 {
			ttl = libdnsTXTTTL
		}
		return &libdnsProvider{typ: s.typ, api: prov, zone: strings.TrimSpace(params["zone"]), ttl: ttl, set: map[string][]string{}}, nil
	}
}

// libdnsProvider adapte un fournisseur libdns à DNSProvider.
type libdnsProvider struct {
	typ  string
	api  libdnsAPI
	zone string
	ttl  time.Duration

	mu  sync.Mutex
	set map[string][]string // nom relatif → valeurs posées par cette instance, pour ne retirer que les siennes
}

// zoneFor retourne la zone et le nom relatif de l'enregistrement de challenge pour domain.
func (p *libdnsProvider) zoneFor(domain string) (zone, label string, err error) {
	domain = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(strings.TrimPrefix(domain, "*."))), ".")
	zone = strings.TrimSuffix(strings.ToLower(p.zone), ".")
	if zone == "" {
		zone, err = publicsuffix.EffectiveTLDPlusOne(domain)
		if err != nil {
			return "", "", fmt.Errorf("%s: zone introuvable pour %q (renseignez le paramètre zone): %w", p.typ, domain, err)
		}
	}
	if domain != zone && !strings.HasSuffix(domain, "."+zone) {
		return "", "", fmt.Errorf("%s: %q n'est pas dans la zone %q", p.typ, domain, zone)
	}
	return zone + ".", challengeLabel(domain, zone), nil
}

func (p *libdnsProvider) SetTXTRecord(ctx context.Context, domain, value string) error {
	zone, label, err := p.zoneFor(domain)
	if err != nil {
		return err
	}
	if _, err := p.api.AppendRecords(ctx, zone, []libdns.Record{libdns.TXT{Name: label, Text: value, TTL: p.ttl}}); err != nil {
		return fmt.Errorf("%s: %w", p.typ, err)
	}
	p.mu.Lock()
	p.set[zone+label] = append(p.set[zone+label], value)
	p.mu.Unlock()
	return nil
}

// DeleteTXTRecord retire les TXT que cette instance a posés (valeur exacte, TTL libre) ; sans rien de posé (nettoyage
// avant une commande), tout TXT du nom de challenge, comme les autres fournisseurs.
func (p *libdnsProvider) DeleteTXTRecord(ctx context.Context, domain string) error {
	zone, label, err := p.zoneFor(domain)
	if err != nil {
		return err
	}
	key := zone + label
	p.mu.Lock()
	values := p.set[key]
	delete(p.set, key)
	p.mu.Unlock()

	var recs []libdns.Record
	for _, v := range values {
		recs = append(recs, libdns.TXT{Name: label, Text: v})
	}
	if len(recs) == 0 {
		recs = []libdns.Record{libdns.RR{Name: label, Type: "TXT"}}
	}
	if _, err := p.api.DeleteRecords(ctx, zone, recs); err != nil && !errors.Is(err, context.Canceled) {
		return fmt.Errorf("%s: %w", p.typ, err)
	}
	return nil
}

// validateLibdnsParams contrôle les adresses d'API saisies : les identifiants partent vers cette adresse, qui doit donc
// être une API en HTTPS et non un service interne (sauf pour un fournisseur auto-hébergé, qui accepte un réseau privé).
func validateLibdnsParams(typ string, params map[string]any) error {
	for _, s := range libdnsSpecs {
		if s.typ != typ {
			continue
		}
		for _, p := range s.fields {
			if !p.url {
				continue
			}
			raw, _ := params[p.key].(string)
			raw = strings.TrimSpace(raw)
			if raw == "" {
				continue
			}
			if !s.privateURL && !strings.HasPrefix(strings.ToLower(raw), "https://") {
				return fmt.Errorf("%s %q : une URL https est requise", s.label, p.key)
			}
			if err := ssrf.ValidateHTTPURL(raw, s.privateURL); err != nil {
				return fmt.Errorf("%s %q : %w", s.label, p.key, err)
			}
		}
	}
	return nil
}
