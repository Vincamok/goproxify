// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/modules"
)

func newAuthProvidersHandler(t *testing.T) *AuthProvidersHandler {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "authp.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &AuthProvidersHandler{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func apCall(h *AuthProvidersHandler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

const oidcBody = `{"name":"corp","provider":"oidc","config":{"enabled":true,"oidc":{"issuer_url":"https://id.example.com","client_id":"cid","client_secret":"CLIENT-SECRET","redirect_url":"https://app/cb","session_secret":"SESSION-SECRET"}}}`

func createAP(t *testing.T, h *AuthProvidersHandler, body string) string {
	t.Helper()
	rec := apCall(h, http.MethodPost, "/api/v1/auth-providers", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("création : %d %s", rec.Code, rec.Body.String())
	}
	var out struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.ID
}

func TestAuthProviders_CreateValidates(t *testing.T) {
	h := newAuthProvidersHandler(t)
	for name, body := range map[string]string{
		"fournisseur inconnu":     `{"name":"x","provider":"azure","config":{}}`,
		"oidc sans client_secret": `{"name":"x","provider":"oidc","config":{"oidc":{"issuer_url":"https://i","client_id":"c","redirect_url":"https://r","session_secret":"s"}}}`,
		"clé imbriquée inconnue":  `{"name":"x","provider":"oidc","config":{"oidc":{"issuer_url":"https://i","client_id":"c","client_secret":"s","redirect_url":"https://r","session_secret":"s","client_secrt":"typo"}}}`,
		"ldap sans section":       `{"name":"x","provider":"ldap","config":{}}`,
		"basic sans utilisateur":  `{"name":"x","provider":"basic","config":{}}`,
		"forward sans URL":        `{"name":"x","provider":"authelia","config":{}}`,
		"config non objet":        `{"name":"x","provider":"basic","config":"nope"}`,
	} {
		if rec := apCall(h, http.MethodPost, "/api/v1/auth-providers", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s : code %d (attendu 400)", name, rec.Code)
		}
	}
	createAP(t, h, oidcBody)
	createAP(t, h, `{"name":"b","provider":"basic","config":{"realm":"r","basic_users":[{"username":"alice","password":"pw"}]}}`)
	createAP(t, h, `{"name":"f","provider":"authelia","config":{"forward_auth_url":"http://authelia:9091/api/verify"}}`)
}

// La liste et le détail renvoyaient la configuration brute : secrets client, clés de session, mot de passe
// de liaison LDAP et mots de passe Basic à tout appelant autorisé à lire les fournisseurs.
func TestAuthProviders_ReadsMaskEverySecret(t *testing.T) {
	h := newAuthProvidersHandler(t)
	oidcID := createAP(t, h, oidcBody)
	createAP(t, h, `{"name":"d","provider":"ldap","config":{"ldap":{"url":"ldaps://dc","base_dn":"DC=x","bind_password":"BIND-PW","session_secret":"LDAP-SESSION"}}}`)
	createAP(t, h, `{"name":"b","provider":"basic","config":{"basic_users":[{"username":"alice","password":"ALICE-PW"},{"username":"bob","password":"$2a$10$HASHHASHHASH"}]}}`)

	for _, path := range []string{"/api/v1/auth-providers", "/api/v1/auth-providers/" + oidcID} {
		body := apCall(h, http.MethodGet, path, "").Body.String()
		for _, leaked := range []string{"CLIENT-SECRET", "SESSION-SECRET"} {
			if strings.Contains(body, leaked) {
				t.Errorf("%s expose %s", path, leaked)
			}
		}
		if !strings.Contains(body, "cid") || !strings.Contains(body, modules.Masque) {
			t.Errorf("%s : champs non secrets absents ou secrets non masqués : %s", path, body)
		}
	}
	all := apCall(h, http.MethodGet, "/api/v1/auth-providers", "").Body.String()
	for _, leaked := range []string{"BIND-PW", "LDAP-SESSION", "ALICE-PW", "HASHHASHHASH"} {
		if strings.Contains(all, leaked) {
			t.Errorf("liste : %s exposé", leaked)
		}
	}
	if !strings.Contains(all, "alice") || !strings.Contains(all, "bob") {
		t.Error("les noms d'utilisateurs Basic doivent rester visibles")
	}
	// La réponse de création ne renvoie pas non plus le secret.
	rec := apCall(h, http.MethodPost, "/api/v1/auth-providers", strings.Replace(oidcBody, `"corp"`, `"corp2"`, 1))
	if strings.Contains(rec.Body.String(), "CLIENT-SECRET") {
		t.Error("la réponse de création renvoie le secret")
	}
	// La base, elle, garde les vraies valeurs : c'est ce qui est poussé aux passerelles.
	var raw string
	_ = h.DB.QueryRow(`SELECT config FROM auth_providers WHERE id=?`, oidcID).Scan(&raw)
	if !strings.Contains(raw, "CLIENT-SECRET") {
		t.Fatal("secret non conservé en base")
	}
}

func TestAuthProviders_UpdateKeepsMaskedAndOmittedSecrets(t *testing.T) {
	h := newAuthProvidersHandler(t)
	id := createAP(t, h, oidcBody)
	// Le formulaire renvoie ce que la liste lui a donné : secrets masqués.
	body := `{"name":"corp","provider":"oidc","config":{"enabled":true,"oidc":{"issuer_url":"https://new.example.com","client_id":"cid","client_secret":"` + modules.Masque + `","redirect_url":"https://app/cb","session_secret":"` + modules.Masque + `"}}}`
	if rec := apCall(h, http.MethodPut, "/api/v1/auth-providers/"+id, body); rec.Code != http.StatusNoContent {
		t.Fatalf("code %d %s", rec.Code, rec.Body.String())
	}
	var raw string
	_ = h.DB.QueryRow(`SELECT config FROM auth_providers WHERE id=?`, id).Scan(&raw)
	if !strings.Contains(raw, "CLIENT-SECRET") || !strings.Contains(raw, "SESSION-SECRET") || !strings.Contains(raw, "new.example.com") || strings.Contains(raw, modules.Masque) {
		t.Fatalf("config = %s", raw)
	}
}

func TestAuthProviders_UpdateKeepsBasicPasswordsByUsername(t *testing.T) {
	h := newAuthProvidersHandler(t)
	id := createAP(t, h, `{"name":"b","provider":"basic","config":{"basic_users":[{"username":"alice","password":"ALICE-PW"},{"username":"bob","password":"BOB-PW"}]}}`)
	body := `{"config":{"basic_users":[{"username":"bob","password":"` + modules.Masque + `"},{"username":"alice","password":"NEW-ALICE"},{"username":"carol","password":"CAROL-PW"}]}}`
	if rec := apCall(h, http.MethodPut, "/api/v1/auth-providers/"+id, body); rec.Code != http.StatusNoContent {
		t.Fatalf("code %d %s", rec.Code, rec.Body.String())
	}
	var raw string
	_ = h.DB.QueryRow(`SELECT config FROM auth_providers WHERE id=?`, id).Scan(&raw)
	for _, want := range []string{"BOB-PW", "NEW-ALICE", "CAROL-PW"} {
		if !strings.Contains(raw, want) {
			t.Errorf("%s absent de %s", want, raw)
		}
	}
	if strings.Contains(raw, `"ALICE-PW"`) || strings.Contains(raw, modules.Masque) {
		t.Errorf("config = %s", raw)
	}
	// Le type et le nom ne sont plus effacés par une requête qui ne les renseigne pas.
	var provider, name string
	_ = h.DB.QueryRow(`SELECT provider, name FROM auth_providers WHERE id=?`, id).Scan(&provider, &name)
	if provider != "basic" || name != "b" {
		t.Fatalf("provider=%q name=%q", provider, name)
	}
}

func TestAuthProviders_UpdateValidatesAndHandlesMissing(t *testing.T) {
	h := newAuthProvidersHandler(t)
	id := createAP(t, h, oidcBody)
	// Changer de type : les secrets de l'ancien ne sont pas repris, la validation refuse.
	if rec := apCall(h, http.MethodPut, "/api/v1/auth-providers/"+id, `{"provider":"github","config":{}}`); rec.Code != http.StatusBadRequest {
		t.Errorf("changement de type sans config : %d", rec.Code)
	}
	if rec := apCall(h, http.MethodPut, "/api/v1/auth-providers/"+id, `{"provider":"inconnu","config":{}}`); rec.Code != http.StatusBadRequest {
		t.Errorf("type inconnu : %d", rec.Code)
	}
	if rec := apCall(h, http.MethodPut, "/api/v1/auth-providers/nope", `{"config":{}}`); rec.Code != http.StatusNotFound {
		t.Errorf("fournisseur inconnu : %d", rec.Code)
	}
}

func TestAuthProviders_PatchEnabled(t *testing.T) {
	h := newAuthProvidersHandler(t)
	id := createAP(t, h, oidcBody)
	if rec := apCall(h, http.MethodPatch, "/api/v1/auth-providers/"+id, `{"enabled":false}`); rec.Code != http.StatusNoContent {
		t.Fatalf("code %d", rec.Code)
	}
	var en int
	var raw string
	_ = h.DB.QueryRow(`SELECT enabled, config FROM auth_providers WHERE id=?`, id).Scan(&en, &raw)
	if en != 0 || !strings.Contains(raw, "CLIENT-SECRET") {
		t.Fatalf("enabled=%d config=%s", en, raw)
	}
	if rec := apCall(h, http.MethodPatch, "/api/v1/auth-providers/"+id, `{}`); rec.Code != http.StatusBadRequest {
		t.Errorf("sans enabled : %d", rec.Code)
	}
	if rec := apCall(h, http.MethodPatch, "/api/v1/auth-providers/nope", `{"enabled":true}`); rec.Code != http.StatusNotFound {
		t.Errorf("inconnu : %d", rec.Code)
	}
}

// Une ligne dont le type n'est plus connu garde un masquage par nom de clé.
func TestMaskAuthConfig_UnknownTypeFallsBack(t *testing.T) {
	got := string(maskAuthConfig("retired", json.RawMessage(`{"oidc":{"client_secret":"S","client_id":"cid"},"users":[{"password":"P","name":"n"}]}`)))
	if strings.Contains(got, `"S"`) || strings.Contains(got, `"P"`) || !strings.Contains(got, "cid") || !strings.Contains(got, `"n"`) {
		t.Fatalf("masquage = %s", got)
	}
}

func TestAuthProviderTypes_Endpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	AuthProviderTypesHandler{}.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/auth-provider-types", nil))
	var got []modules.Manifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 20 {
		t.Fatalf("manifestes = %d, %v", len(got), err)
	}
	rec = httptest.NewRecorder()
	AuthProviderTypesHandler{}.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/auth-provider-types", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST : %d", rec.Code)
	}
}
