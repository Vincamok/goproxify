// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"log/slog"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/modules"
)

// SSOFactory construit le middleware d'un fournisseur d'authentification.
type SSOFactory func(cfg *router.SSOConfig, next http.Handler) http.Handler

// ssoRegistry range les fournisseurs d'authentification (modules de la famille « AuthProvider »,
// ADR 0007), un module par nom de fournisseur. Le manifeste décrit la configuration attendue dans
// SSOConfig — champs imbriqués compris (`oidc.client_secret`), secrets, champs requis — et sert à
// valider, masquer et afficher les fournisseurs côté Admin. Un nom absent du registre n'est jamais
// transmis au backend : voir SSOAuth.
var ssoRegistry = modules.NewRegistry[SSOFactory]()

// RegisterSSO déclare un fournisseur. Les champs communs de SSOConfig (`enabled`, `provider`) sont
// ajoutés au manifeste : une configuration de fournisseur est un SSOConfig sérialisé, qui peut les
// contenir.
func RegisterSSO(m modules.Manifest, f SSOFactory) {
	m.Fields = append(m.Fields,
		ssoKind("enabled", "Enabled", modules.KindBool),
		ssoText("provider", "Provider name", "", false))
	ssoRegistry.Register(m, f)
}

// SSOProviders retourne les manifestes des fournisseurs, dans l'ordre d'affichage.
func SSOProviders() []modules.Manifest { return ssoRegistry.Manifests() }

// SSOProviderManifest retourne le manifeste d'un fournisseur.
func SSOProviderManifest(provider string) (modules.Manifest, bool) {
	_, m, ok := ssoRegistry.Lookup(provider)
	return m, ok
}

// failClosed répond 503 à toute requête : une authentification mal configurée ne doit jamais ouvrir
// l'accès au backend.
func failClosed(provider, reason string) http.Handler {
	slog.Error("sso: fournisseur inutilisable, accès refusé", "provider", provider, "reason", reason)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "SSO: "+reason, http.StatusServiceUnavailable)
	})
}

// sessionSecretOrRandom retourne le secret de session configuré, ou un secret aléatoire propre à ce
// processus s'il est vide : une clé HMAC vide permettrait à n'importe qui de fabriquer un cookie de
// session valide. Les sessions ne survivent alors pas à un redémarrage ni ne se partagent entre
// passerelles — d'où l'avertissement : renseignez session_secret.
func sessionSecretOrRandom(provider, secret string) string {
	if strings.TrimSpace(secret) != "" {
		return secret
	}
	slog.Warn("sso: session_secret vide — secret aléatoire utilisé, les sessions ne survivent pas à un redémarrage", "provider", provider)
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// MatchBasicPassword compare un mot de passe saisi à celui enregistré : bcrypt ($2a$/$2b$/$2y$) ou,
// pour les anciennes configurations, texte clair (comparaison à temps constant). Un mot de passe
// enregistré vide ne correspond jamais.
func MatchBasicPassword(stored, password string) bool {
	stored = strings.TrimSpace(stored)
	if stored == "" {
		return false
	}
	if strings.HasPrefix(stored, "$2a$") || strings.HasPrefix(stored, "$2b$") || strings.HasPrefix(stored, "$2y$") {
		return bcrypt.CompareHashAndPassword([]byte(stored), []byte(password)) == nil
	}
	return subtle.ConstantTimeCompare([]byte(stored), []byte(password)) == 1
}

// Champs de manifeste communs. Les clés sont des chemins dans SSOConfig.
func ssoText(key, label, placeholder string, required bool) modules.Field {
	return modules.Field{Key: key, Label: label, Placeholder: placeholder, Kind: modules.KindText, Required: required}
}

func ssoSecret(key, label string, required bool) modules.Field {
	return modules.Field{Key: key, Label: label, Kind: modules.KindPassword, Secret: true, Required: required}
}

func ssoKind(key, label, kind string) modules.Field {
	return modules.Field{Key: key, Label: label, Kind: kind}
}

func forwardFields() []modules.Field {
	return []modules.Field{
		ssoText("forward_auth_url", "Authentication service URL", "http://authelia:9091/api/verify", true),
		ssoKind("forward_auth_timeout_ms", "Timeout (ms)", modules.KindNumber),
		ssoText("forward_auth_signin_url", "Sign-in URL (on 401)", "https://auth.example.com/oauth2/start", false),
		ssoKind("headers_to_forward", "Headers to forward", modules.KindList),
	}
}

func oidcFields(issuerRequired bool) []modules.Field {
	return []modules.Field{
		ssoText("oidc.issuer_url", "Issuer URL", "https://id.example.com", issuerRequired),
		ssoText("oidc.client_id", "Client ID", "", true),
		ssoSecret("oidc.client_secret", "Client secret", true),
		ssoText("oidc.redirect_url", "Redirect URL", "https://app.example.com/_gpx/oidc/callback", true),
		ssoKind("oidc.scopes", "Scopes", modules.KindList),
		ssoText("oidc.username_claim", "Username claim", "preferred_username", false),
		ssoSecret("oidc.session_secret", "Session secret (HMAC key)", true),
		ssoKind("oidc.session_max_age", "Session max age (s)", modules.KindNumber),
	}
}

func ldapFields() []modules.Field {
	return []modules.Field{
		ssoText("ldap.url", "Directory URL", "ldaps://dc.corp.local:636", true),
		ssoText("ldap.bind_dn", "Bind DN", "CN=svc,DC=corp,DC=local", false),
		ssoSecret("ldap.bind_password", "Bind password", false),
		ssoText("ldap.base_dn", "Base DN", "DC=corp,DC=local", true),
		ssoText("ldap.user_filter", "User filter", "(sAMAccountName=%s)", false),
		ssoText("ldap.group_filter", "Group filter", "", false),
		ssoKind("ldap.allowed_groups", "Allowed groups", modules.KindList),
		ssoText("ldap.username_attr", "Username attribute", "", false),
		ssoText("ldap.email_attr", "Email attribute", "mail", false),
		ssoKind("ldap.tls_skip_verify", "Skip TLS verification", modules.KindBool),
		ssoSecret("ldap.session_secret", "Session secret (HMAC key)", true),
		ssoKind("ldap.session_max_age", "Session max age (s)", modules.KindNumber),
	}
}

func init() {
	// Services d'authentification externes (forward-auth / ext_authz).
	for _, p := range []struct{ id, label string }{
		{"forward", "Forward auth (generic)"}, {"authentik", "Authentik"}, {"authelia", "Authelia"}, {"oauth2_proxy", "oauth2-proxy"},
	} {
		RegisterSSO(modules.Manifest{Type: p.id, Label: p.label, Fields: forwardFields(), Attrs: map[string]any{"section": "forward"}},
			func(cfg *router.SSOConfig, next http.Handler) http.Handler {
				if strings.TrimSpace(cfg.ForwardAuthURL) == "" {
					return failClosed(cfg.Provider, "forward_auth_url manquant")
				}
				return forwardAuthMiddleware(cfg, next)
			})
	}

	RegisterSSO(modules.Manifest{Type: "basic", Label: "Basic auth", Attrs: map[string]any{"section": "basic"}, Fields: []modules.Field{
		ssoText("realm", "Realm", "Goproxify", false),
		{Key: "basic_users", Label: "Users", Kind: modules.KindList, Required: true, ItemKey: "username", ItemSecret: "password"},
	}}, func(cfg *router.SSOConfig, next http.Handler) http.Handler {
		if len(cfg.BasicUsers) == 0 {
			return failClosed(cfg.Provider, "aucun utilisateur Basic configuré")
		}
		return basicAuthMiddleware(cfg, next)
	})

	// OIDC : un module par fournisseur, tous configurés par la section « oidc ». Les préréglages
	// connaissent l'URL de l'émetteur (avec ses paramètres à remplacer) ; « oidc » et « pocket_id »
	// exigent de la saisir.
	for _, p := range []struct {
		id, label string
		issuerReq bool
	}{
		{"oidc", "OpenID Connect (generic)", true}, {"pocket_id", "Pocket ID", true}, {"google", "Google", false},
		{"microsoft", "Microsoft Entra ID", false}, {"entra", "Microsoft Entra ID (alias)", false}, {"auth0", "Auth0", false},
		{"okta", "Okta", false}, {"keycloak", "Keycloak", false}, {"zitadel", "ZITADEL", false}, {"casdoor", "Casdoor", false}, {"dex", "Dex", false},
	} {
		RegisterSSO(modules.Manifest{Type: p.id, Label: p.label, Fields: oidcFields(p.issuerReq), Attrs: map[string]any{"section": "oidc", "issuer_preset": oidcPresets[p.id]}},
			func(cfg *router.SSOConfig, next http.Handler) http.Handler {
				if cfg.OIDC == nil {
					return failClosed(cfg.Provider, "configuration oidc manquante")
				}
				c := *cfg.OIDC
				c.SessionSecret = sessionSecretOrRandom(cfg.Provider, c.SessionSecret)
				if c.IssuerURL == "" {
					c.IssuerURL = oidcPresets[cfg.Provider]
				}
				cc := *cfg
				cc.OIDC = &c
				return OIDCAuth(&cc)(next)
			})
	}

	RegisterSSO(modules.Manifest{Type: "github", Label: "GitHub OAuth", Attrs: map[string]any{"section": "github"}, Fields: []modules.Field{
		ssoText("github.client_id", "Client ID", "", true),
		ssoSecret("github.client_secret", "Client secret", true),
		ssoText("github.redirect_url", "Redirect URL", "https://app.example.com/_gpx/github/callback", true),
		ssoKind("github.allowed_orgs", "Allowed organizations", modules.KindList),
		ssoKind("github.allowed_teams", "Allowed teams (org/team)", modules.KindList),
		ssoSecret("github.session_secret", "Session secret (HMAC key)", true),
		ssoKind("github.session_max_age", "Session max age (s)", modules.KindNumber),
	}}, func(cfg *router.SSOConfig, next http.Handler) http.Handler {
		if cfg.GitHub == nil {
			return failClosed(cfg.Provider, "configuration github manquante")
		}
		c := *cfg.GitHub
		c.SessionSecret = sessionSecretOrRandom(cfg.Provider, c.SessionSecret)
		return GitHubOAuth(&c)(next)
	})

	for _, p := range []struct{ id, label string }{{"ldap", "LDAP"}, {"ldap_ad", "Active Directory"}} {
		RegisterSSO(modules.Manifest{Type: p.id, Label: p.label, Fields: ldapFields(), Attrs: map[string]any{"section": "ldap"}},
			func(cfg *router.SSOConfig, next http.Handler) http.Handler {
				if cfg.LDAP == nil {
					return failClosed(cfg.Provider, "configuration ldap manquante")
				}
				c := *cfg.LDAP
				c.SessionSecret = sessionSecretOrRandom(cfg.Provider, c.SessionSecret)
				return LDAPAuth(&c)(next)
			})
	}

	RegisterSSO(modules.Manifest{Type: "saml", Label: "SAML 2.0", Attrs: map[string]any{"section": "saml"}, Fields: []modules.Field{
		ssoText("saml.entity_id", "SP entity ID", "https://app.example.com/saml/metadata", true),
		ssoText("saml.acs_path", "ACS path", "/saml/acs", false),
		ssoText("saml.metadata_path", "Metadata path", "/saml/metadata", false),
		{Key: "saml.cert_pem", Label: "SP certificate (PEM)", Kind: modules.KindText, Required: true, Multiline: true},
		{Key: "saml.key_pem", Label: "SP private key (PEM)", Kind: modules.KindPassword, Secret: true, Required: true, Multiline: true},
		ssoText("saml.idp_metadata_url", "IdP metadata URL", "", false),
		{Key: "saml.idp_metadata_xml", Label: "IdP metadata (XML)", Kind: modules.KindText, Multiline: true},
		ssoText("saml.username_attr", "Username attribute", "", false),
		ssoText("saml.email_attr", "Email attribute", "", false),
		ssoText("saml.groups_attr", "Groups attribute", "", false),
		ssoKind("saml.allowed_groups", "Allowed groups", modules.KindList),
		ssoSecret("saml.session_secret", "Session secret (HMAC key)", true),
		ssoKind("saml.session_max_age", "Session max age (s)", modules.KindNumber),
	}}, func(cfg *router.SSOConfig, next http.Handler) http.Handler {
		if cfg.SAML == nil {
			return failClosed(cfg.Provider, "configuration saml manquante")
		}
		c := *cfg.SAML
		c.SessionSecret = sessionSecretOrRandom(cfg.Provider, c.SessionSecret)
		return SAMLAuth(&c)(next)
	})
}
