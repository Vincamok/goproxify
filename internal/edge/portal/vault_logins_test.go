// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"encoding/base64"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
)

const testMaster = "test-secret"

type vaultEnv struct {
	t     *testing.T
	h     *HTTPServer
	store *Store
	tok   string
}

func newVaultEnv(t *testing.T, tags []string, cfg Config) *vaultEnv {
	t.Helper()
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), testMaster)
	hash, _ := HashPassword("password1")
	_ = store.CreateUser(UserRecord{
		ID: "u1", Username: "a@b.c", PasswordHash: hash, Tags: tags,
		Status: UserStatusActive, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	_ = store.SetCatalog([]CatalogTarget{
		{ID: "c1", Name: "web", Kind: TargetSSH, Host: "10.0.0.1", Port: 22},
		{ID: "c2", Name: "db", Kind: TargetSSH, Host: "10.0.0.2", Port: 22},
		{ID: "c3", Name: "secret", Kind: TargetSSH, Host: "10.0.0.3", Port: 22, Tags: []string{"prod"}},
		{ID: "d1", Name: "ct", Kind: TargetDocker, AgentName: "ag", Container: "nginx"},
	})
	cfg.Enabled = true
	cfg.PublicHost = "access.test"
	h := NewHTTPServer(&cfg, store, NewSessionManager(), slog.New(slog.NewTextHandler(io.Discard, nil)), func(e AuditEvent) { _ = store.AppendAudit(e) })
	h.masterSecret = testMaster
	return &vaultEnv{t: t, h: h, store: store, tok: loginToken(t, h, "a@b.c", "password1")}
}

func (e *vaultEnv) call(method, path, body string) *httptest.ResponseRecorder {
	e.t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+e.tok)
	rr := httptest.NewRecorder()
	e.h.Handler().ServeHTTP(rr, req)
	return rr
}

func (e *vaultEnv) session(dest, loginID string) *httptest.ResponseRecorder {
	body := `{"target_id":"` + dest + `","source":"catalog","facade":"ssh"`
	if loginID != "" {
		body += `,"login_id":"` + loginID + `"`
	}
	return e.call(http.MethodPost, "/api/sessions", body+"}")
}

func (e *vaultEnv) dialOf(rr *httptest.ResponseRecorder) dialTarget {
	e.t.Helper()
	if rr.Code != http.StatusCreated {
		e.t.Fatalf("session: %d %s", rr.Code, rr.Body.String())
	}
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	sess, ok := e.h.sessions.Peek(out["uuid"].(string))
	if !ok {
		e.t.Fatal("session introuvable")
	}
	return sess.Target
}

func (e *vaultEnv) personal(body string) VaultLoginMeta {
	e.t.Helper()
	rr := e.call(http.MethodPost, "/api/vault/logins", body)
	if rr.Code != http.StatusCreated {
		e.t.Fatalf("create login: %d %s", rr.Code, rr.Body.String())
	}
	var m VaultLoginMeta
	_ = json.Unmarshal(rr.Body.Bytes(), &m)
	return m
}

func (e *vaultEnv) shared(l SharedLogin, secret LoginSecret) {
	e.t.Helper()
	pub, err := LoginSealPublicKey(testMaster)
	if err != nil {
		e.t.Fatal(err)
	}
	sealed, err := SealLoginSecret(pub, secret)
	if err != nil {
		e.t.Fatal(err)
	}
	l.Sealed = sealed
	cur := e.store.SharedLogins()
	if err := e.store.SetSharedLogins(append(cur, l)); err != nil {
		e.t.Fatal(err)
	}
}

func TestLoginSealRoundTripAndRotation(t *testing.T) {
	pub, err := LoginSealPublicKey("maitre-1")
	if err != nil {
		t.Fatal(err)
	}
	if again, _ := LoginSealPublicKey("maitre-1"); again != pub {
		t.Fatal("la clé publique doit être déterministe : tous les membres d'un groupe HA doivent ouvrir les mêmes secrets")
	}
	if other, _ := LoginSealPublicKey("maitre-2"); other == pub {
		t.Fatal("deux clés maîtres ne donnent pas la même paire")
	}
	raw, _ := base64.StdEncoding.DecodeString(pub)
	if len(raw) != 65 || raw[0] != 4 {
		t.Fatalf("point P-256 non compressé attendu (65 octets), obtenu %d", len(raw))
	}

	sealed, err := SealLoginSecret(pub, LoginSecret{Password: "p4ss", PrivateKey: "KEY"})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sealed, "p4ss") || strings.Contains(sealed, "KEY") {
		t.Fatal("l'enveloppe ne doit contenir aucun secret en clair")
	}
	if err := ValidSealedSecret(sealed); err != nil {
		t.Fatalf("l'Admin doit pouvoir contrôler la forme : %v", err)
	}
	got, err := OpenLoginSecret([]string{"maitre-1"}, sealed)
	if err != nil || got.Password != "p4ss" || got.PrivateKey != "KEY" {
		t.Fatalf("ouverture : %+v %v", got, err)
	}
	if _, err := OpenLoginSecret([]string{"maitre-2"}, sealed); err == nil {
		t.Fatal("une autre clé maître ne doit pas ouvrir le secret")
	}
	if got, err := OpenLoginSecret([]string{"maitre-2", "maitre-1"}, sealed); err != nil || got.Password != "p4ss" {
		t.Fatalf("après rotation, l'ancienne clé doit encore ouvrir : %v", err)
	}

	again, _ := SealLoginSecret(pub, LoginSecret{Password: "p4ss"})
	if again == sealed {
		t.Fatal("deux scellements du même secret doivent différer (clé éphémère et nonce)")
	}

	var env SealedSecret
	_ = json.Unmarshal([]byte(sealed), &env)
	ct, _ := base64.StdEncoding.DecodeString(env.CT)
	ct[0] ^= 0xff
	env.CT = base64.StdEncoding.EncodeToString(ct)
	tampered, _ := json.Marshal(env)
	if _, err := OpenLoginSecret([]string{"maitre-1"}, string(tampered)); err == nil {
		t.Fatal("une enveloppe altérée doit être refusée")
	}

	for name, bad := range map[string]string{"vide": "", "pas du json": "x", "version": `{"v":9}`, "point": `{"v":1,"epk":"AAAA","nonce":"AAAA","ct":"AAAA"}`} {
		if ValidSealedSecret(bad) == nil {
			t.Errorf("%s : enveloppe invalide acceptée", name)
		}
	}
	if _, err := SealLoginSecret(pub, LoginSecret{}); err == nil {
		t.Fatal("un secret vide ne se scelle pas")
	}
	if _, err := SealLoginSecret("pas-une-cle", LoginSecret{Password: "x"}); err == nil {
		t.Fatal("une clé publique invalide doit être refusée")
	}
}

func TestLoginSealSecretsIncludePreviousPairingSecrets(t *testing.T) {
	t.Setenv(edgecache.PreviousSecretsEnv, "ancien-1, ancien-2 ,"+testMaster)
	got := loginSealSecrets(testMaster)
	if len(got) != 3 || got[0] != testMaster || got[1] != "ancien-1" || got[2] != "ancien-2" {
		t.Fatalf("clés d'ouverture : %v", got)
	}
}

func TestPersonalLoginLinksToSeveralDestinationsAndNeverLeaks(t *testing.T) {
	e := newVaultEnv(t, nil, Config{})

	m := e.personal(`{"name":"ubuntu","username":"ubuntu","password":"s3cret","private_key":"KEYDATA","dest_ids":["c1","c2"]}`)
	if m.ID == "" || !m.HasPassword || !m.HasPrivateKey || len(m.DestIDs) != 2 {
		t.Fatalf("meta : %+v", m)
	}
	for _, rr := range []*httptest.ResponseRecorder{e.call(http.MethodGet, "/api/vault", ""), e.call(http.MethodGet, "/api/targets/c1/logins", "")} {
		if body := rr.Body.String(); strings.Contains(body, "s3cret") || strings.Contains(body, "KEYDATA") {
			t.Fatalf("un secret a fuité : %s", body)
		}
	}

	for _, dest := range []string{"c1", "c2"} {
		if d := e.dialOf(e.session(dest, "")); d.Username != "ubuntu" || d.Password != "s3cret" || d.PrivateKey != "KEYDATA" {
			t.Fatalf("session %s : %+v", dest, d)
		}
	}
	if rr := e.session("c3", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("destination invisible : %d", rr.Code)
	}

	// Modifier sans ressaisir le secret le conserve ; les liaisons ne changent que si dest_ids est fourni.
	if rr := e.call(http.MethodPut, "/api/vault/logins/"+m.ID, `{"name":"ubuntu-2"}`); rr.Code != 200 {
		t.Fatalf("update : %d %s", rr.Code, rr.Body.String())
	}
	if d := e.dialOf(e.session("c2", "")); d.Password != "s3cret" {
		t.Fatalf("le secret doit survivre à une modification de métadonnées : %+v", d)
	}
	if rr := e.call(http.MethodPut, "/api/vault/logins/"+m.ID, `{"dest_ids":["c1"]}`); rr.Code != 200 {
		t.Fatalf("délier : %d", rr.Code)
	}
	if rr := e.session("c2", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("c2 n'est plus liée : %d %s", rr.Code, rr.Body.String())
	}
	// Retirer le mot de passe garde la clé ; tout retirer est refusé.
	if rr := e.call(http.MethodPut, "/api/vault/logins/"+m.ID, `{"clear_password":true}`); rr.Code != 200 {
		t.Fatalf("clear password : %d", rr.Code)
	}
	if d := e.dialOf(e.session("c1", "")); d.Password != "" || d.PrivateKey != "KEYDATA" {
		t.Fatalf("après clear_password : %+v", d)
	}
	if rr := e.call(http.MethodPut, "/api/vault/logins/"+m.ID, `{"clear_private_key":true}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("un login sans secret doit être refusé : %d", rr.Code)
	}

	for name, body := range map[string]string{
		"destination inconnue":  `{"username":"x","password":"y","dest_ids":["nope"]}`,
		"destination invisible": `{"username":"x","password":"y","dest_ids":["c3"]}`,
		"sans identifiant":      `{"password":"y"}`,
		"sans secret":           `{"username":"x"}`,
	} {
		if rr := e.call(http.MethodPost, "/api/vault/logins", body); rr.Code != http.StatusBadRequest {
			t.Errorf("%s : %d %s", name, rr.Code, rr.Body.String())
		}
	}
	if rr := e.call(http.MethodPut, "/api/vault/logins/absent", `{"username":"x"}`); rr.Code != http.StatusNotFound {
		t.Errorf("login absent : %d", rr.Code)
	}

	if rr := e.call(http.MethodDelete, "/api/vault/logins/"+m.ID, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("delete : %d", rr.Code)
	}
	if rr := e.session("c1", ""); rr.Code != http.StatusBadRequest || !strings.Contains(rr.Body.String(), "aucun login") {
		t.Fatalf("sans login lié : %d %s", rr.Code, rr.Body.String())
	}
}

func TestSessionRefusedWithoutAnyLinkedLogin(t *testing.T) {
	e := newVaultEnv(t, nil, Config{})
	rr := e.session("c1", "")
	if rr.Code != http.StatusBadRequest || strings.Contains(rr.Body.String(), "a@b.c") && !strings.Contains(rr.Body.String(), "pas l'email") {
		t.Fatalf("%d %s", rr.Code, rr.Body.String())
	}
	// Un login qui existe mais n'est lié à aucune destination n'est jamais choisi d'office.
	e.personal(`{"username":"root","password":"x"}`)
	if rr := e.session("c1", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("login non lié : %d", rr.Code)
	}
}

func TestDockerDestinationsNeedNoLogin(t *testing.T) {
	e := newVaultEnv(t, nil, Config{})
	d := e.dialOf(e.session("d1", ""))
	if d.Kind != TargetDocker || d.Username != "" || d.Password != "" {
		t.Fatalf("docker : %+v", d)
	}
}

func TestSharedLoginIsUsedWithoutEverRevealingItsSecret(t *testing.T) {
	e := newVaultEnv(t, []string{"ops"}, Config{})
	e.shared(SharedLogin{ID: "s1", Name: "root-prod", Username: "root", Tags: []string{"OPS"}, DestIDs: []string{"c1", "c3"}}, LoginSecret{Password: "TopSecret!", PrivateKey: "PRIVKEY"})

	d := e.dialOf(e.session("c1", ""))
	if d.Username != "root" || d.Password != "TopSecret!" || d.PrivateKey != "PRIVKEY" {
		t.Fatalf("la passerelle ouvre le secret scellé : %+v", d)
	}
	for _, rr := range []*httptest.ResponseRecorder{
		e.call(http.MethodGet, "/api/vault", ""), e.call(http.MethodGet, "/api/targets/c1/logins", ""),
		e.call(http.MethodGet, "/api/targets", ""), e.call(http.MethodGet, "/api/audit", ""),
	} {
		if b := rr.Body.String(); strings.Contains(b, "TopSecret!") || strings.Contains(b, "PRIVKEY") {
			t.Fatalf("le secret d'un login préconfiguré a fuité : %s", b)
		}
	}

	var v struct {
		Shared []SharedLoginMeta `json:"shared"`
	}
	_ = json.Unmarshal(e.call(http.MethodGet, "/api/vault", "").Body.Bytes(), &v)
	if len(v.Shared) != 1 || v.Shared[0].Name != "root-prod" || v.Shared[0].Username != "root" {
		t.Fatalf("login préconfiguré listé : %+v", v.Shared)
	}
	if len(v.Shared[0].DestIDs) != 1 || v.Shared[0].DestIDs[0] != "c1" {
		t.Fatalf("seules les destinations visibles sont listées (c3 exige le tag prod) : %v", v.Shared[0].DestIDs)
	}
	// c3 est liée mais invisible : le login ne l'ouvre pas.
	if rr := e.session("c3", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("destination invisible : %d", rr.Code)
	}

	found := false
	for _, ev := range e.store.ListAuditForUser("a@b.c", 50) {
		found = found || strings.Contains(ev.Detail, "coffre=root-prod (shared)")
	}
	if !found {
		t.Fatal("l'audit doit retenir quel login a servi (nom et origine)")
	}
}

func TestSharedLoginUsageRights(t *testing.T) {
	cases := []struct {
		name  string
		tags  []string
		login SharedLogin
		want  bool
	}{
		{"aucun droit : personne", []string{"ops"}, SharedLogin{DestIDs: []string{"c1"}}, false},
		{"tout utilisateur", nil, SharedLogin{AllUsers: true, DestIDs: []string{"c1"}}, true},
		{"membre d'un groupe", nil, SharedLogin{Members: []string{"A@B.C"}, DestIDs: []string{"c1"}}, true},
		{"autre membre", nil, SharedLogin{Members: []string{"x@y.z"}, DestIDs: []string{"c1"}}, false},
		{"tag partagé", []string{"ops", "dev"}, SharedLogin{Tags: []string{"dev"}, DestIDs: []string{"c1"}}, true},
		{"tag absent", []string{"ops"}, SharedLogin{Tags: []string{"dba"}, DestIDs: []string{"c1"}}, false},
		{"utilisateur sans tag", nil, SharedLogin{Tags: []string{"dba"}, DestIDs: []string{"c1"}}, false},
		{"autre destination", nil, SharedLogin{AllUsers: true, DestIDs: []string{"c2"}}, false},
	}
	for _, c := range cases {
		e := newVaultEnv(t, c.tags, Config{})
		c.login.ID, c.login.Name, c.login.Username = "s1", "svc", "root"
		e.shared(c.login, LoginSecret{Password: "x"})
		rr := e.session("c1", "")
		if got := rr.Code == http.StatusCreated; got != c.want {
			t.Errorf("%s : session=%d (attendu ouvert=%v) %s", c.name, rr.Code, c.want, rr.Body.String())
		}
	}
}

func TestSeveralLoginsAskThenRememberTheDefault(t *testing.T) {
	e := newVaultEnv(t, nil, Config{})
	e.shared(SharedLogin{ID: "s1", Name: "root", Username: "root", AllUsers: true, DestIDs: []string{"c1"}}, LoginSecret{Password: "sh"})
	mine := e.personal(`{"name":"moi","username":"alice","password":"pe","dest_ids":["c1"]}`)

	rr := e.session("c1", "")
	if rr.Code != http.StatusConflict {
		t.Fatalf("deux logins applicables : l'interface doit choisir (%d %s)", rr.Code, rr.Body.String())
	}
	var ask struct {
		Error  string        `json:"error"`
		Logins []LoginChoice `json:"logins"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &ask)
	if ask.Error != "login_required" || len(ask.Logins) != 2 || ask.Logins[0].Origin != LoginShared || ask.Logins[1].Origin != LoginPersonal {
		t.Fatalf("choix proposés (préconfiguré d'abord) : %+v", ask)
	}
	if strings.Contains(rr.Body.String(), "sh\"") && strings.Contains(rr.Body.String(), "pe\"") {
		t.Fatal("la liste des choix ne porte aucun secret")
	}

	if d := e.dialOf(e.session("c1", LoginRef(LoginPersonal, mine.ID))); d.Username != "alice" || d.Password != "pe" {
		t.Fatalf("login personnel choisi : %+v", d)
	}
	if d := e.dialOf(e.session("c1", LoginRef(LoginShared, "s1"))); d.Username != "root" || d.Password != "sh" {
		t.Fatalf("login préconfiguré choisi : %+v", d)
	}
	for _, bad := range []string{"shared:absent", "personal:absent", "n'importe quoi", "shared:s1 "} {
		if rr := e.session("c1", bad); rr.Code != http.StatusBadRequest {
			t.Errorf("référence %q : %d", bad, rr.Code)
		}
	}
	if rr := e.session("c2", LoginRef(LoginShared, "s1")); rr.Code != http.StatusBadRequest {
		t.Fatalf("un login ne s'applique pas à une destination qui ne lui est pas liée : %d", rr.Code)
	}

	if rr := e.call(http.MethodPut, "/api/vault/defaults/c1", `{"login":"shared:absent"}`); rr.Code != http.StatusBadRequest {
		t.Fatalf("un favori doit être applicable : %d", rr.Code)
	}
	if rr := e.call(http.MethodPut, "/api/vault/defaults/c1", `{"login":"`+LoginRef(LoginPersonal, mine.ID)+`"}`); rr.Code != http.StatusNoContent {
		t.Fatalf("favori : %d %s", rr.Code, rr.Body.String())
	}
	if d := e.dialOf(e.session("c1", "")); d.Username != "alice" {
		t.Fatalf("le favori est utilisé sans demander : %+v", d)
	}
	var list struct {
		Logins []LoginChoice `json:"logins"`
	}
	_ = json.Unmarshal(e.call(http.MethodGet, "/api/targets/c1/logins", "").Body.Bytes(), &list)
	if len(list.Logins) != 2 || !list.Logins[0].Default || list.Logins[0].Username != "alice" {
		t.Fatalf("le favori est proposé en premier : %+v", list.Logins)
	}
	if rr := e.call(http.MethodGet, "/api/targets/c3/logins", ""); rr.Code != http.StatusNotFound {
		t.Fatalf("logins d'une destination invisible : %d", rr.Code)
	}

	// Supprimer le login favori oublie le favori.
	e.call(http.MethodDelete, "/api/vault/logins/"+mine.ID, "")
	if d := e.dialOf(e.session("c1", "")); d.Username != "root" {
		t.Fatalf("il reste le seul login préconfiguré : %+v", d)
	}
	if rr := e.call(http.MethodPut, "/api/vault/defaults/c1", `{"login":""}`); rr.Code != http.StatusNoContent {
		t.Fatalf("effacer le favori : %d", rr.Code)
	}
}

func TestSharedLoginSealedForAnotherKeyIsReportedNotUsed(t *testing.T) {
	e := newVaultEnv(t, nil, Config{})
	pub, _ := LoginSealPublicKey("autre-cle")
	sealed, _ := SealLoginSecret(pub, LoginSecret{Password: "x"})
	_ = e.store.SetSharedLogins([]SharedLogin{{ID: "s1", Name: "root", Username: "root", Sealed: sealed, AllUsers: true, DestIDs: []string{"c1"}}})
	rr := e.session("c1", "")
	if rr.Code != http.StatusBadGateway || !strings.Contains(rr.Body.String(), "ressaisir") {
		t.Fatalf("secret illisible : %d %s", rr.Code, rr.Body.String())
	}
}

func TestPersonalTargetSecretsBecomeALinkedLoginAndAreCleanedUp(t *testing.T) {
	e := newVaultEnv(t, nil, Config{AllowPersonalTargets: true})
	rr := e.call(http.MethodPost, "/api/targets", `{"name":"nas","kind":"ssh","host":"192.168.1.9","port":22,"username":"admin","password":"nas-pw"}`)
	if rr.Code != 200 {
		t.Fatalf("target : %d %s", rr.Code, rr.Body.String())
	}
	var tgt PersonalTarget
	_ = json.Unmarshal(rr.Body.Bytes(), &tgt)

	rr = e.call(http.MethodPost, "/api/sessions", `{"target_id":"`+tgt.ID+`","source":"personal","facade":"ssh"}`)
	if d := e.dialOf(rr); d.Username != "admin" || d.Password != "nas-pw" || d.Host != "192.168.1.9" {
		t.Fatalf("cible personnelle : %+v", d)
	}
	var v struct {
		Personal []VaultLoginMeta `json:"personal"`
	}
	_ = json.Unmarshal(e.call(http.MethodGet, "/api/vault", "").Body.Bytes(), &v)
	if len(v.Personal) != 1 || v.Personal[0].Name != "nas" || len(v.Personal[0].DestIDs) != 1 {
		t.Fatalf("login créé avec la cible : %+v", v.Personal)
	}
	// Ce login peut aussi être lié à d'autres destinations.
	if rr := e.call(http.MethodPut, "/api/vault/logins/"+v.Personal[0].ID, `{"dest_ids":["`+tgt.ID+`","c1"]}`); rr.Code != 200 {
		t.Fatalf("lier à une destination du catalogue : %d %s", rr.Code, rr.Body.String())
	}
	if d := e.dialOf(e.session("c1", "")); d.Username != "admin" {
		t.Fatalf("même login sur le catalogue : %+v", d)
	}

	if rr := e.call(http.MethodDelete, "/api/targets/"+tgt.ID, ""); rr.Code != http.StatusNoContent {
		t.Fatalf("delete target : %d", rr.Code)
	}
	v.Personal = nil
	_ = json.Unmarshal(e.call(http.MethodGet, "/api/vault", "").Body.Bytes(), &v)
	if len(v.Personal) != 0 {
		t.Fatalf("le login créé avec la cible disparaît avec elle : %+v", v.Personal)
	}
}

func TestVaultsAreIsolatedBetweenUsersAndOldShapeReadsEmpty(t *testing.T) {
	key := DeriveVaultKey("u1", "password1")
	old, err := encryptWithKey([]byte(`{"c1":{"username":"root","password":"x"}}`), key)
	if err != nil {
		t.Fatal(err)
	}
	p, err := OpenVault(key, old)
	if err != nil || len(p.Logins) != 0 {
		t.Fatalf("l'ancienne forme du coffre se relit vide, sans erreur : %+v %v", p, err)
	}

	e := newVaultEnv(t, nil, Config{})
	e.personal(`{"username":"root","password":"mine","dest_ids":["c1"]}`)
	hash, _ := HashPassword("password2")
	_ = e.store.CreateUser(UserRecord{ID: "u2", Username: "z@b.c", PasswordHash: hash, Status: UserStatusActive, CreatedAt: time.Now().UTC().Format(time.RFC3339)})
	other := &vaultEnv{t: t, h: e.h, store: e.store, tok: loginToken(t, e.h, "z@b.c", "password2")}
	if rr := other.session("c1", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("le login d'un autre utilisateur ne sert pas : %d", rr.Code)
	}
}

func TestSharedLoginsSurviveStoreReload(t *testing.T) {
	path := filepath.Join(t.TempDir(), "p.gpx")
	s := NewStore(path, testMaster)
	pub, _ := LoginSealPublicKey(testMaster)
	sealed, _ := SealLoginSecret(pub, LoginSecret{Password: "keep"})
	if err := s.SetSharedLogins([]SharedLogin{{ID: "s1", Name: "root", Username: "root", Sealed: sealed, AllUsers: true, DestIDs: []string{"c1"}}}); err != nil {
		t.Fatal(err)
	}
	s2 := NewStore(path, testMaster)
	if err := s2.Load(); err != nil {
		t.Fatal(err)
	}
	l, ok := s2.FindSharedLogin("s1")
	if !ok || l.Name != "root" {
		t.Fatalf("après rechargement : %+v", s2.SharedLogins())
	}
	got, err := OpenLoginSecret(loginSealSecrets(testMaster), l.Sealed)
	if err != nil || got.Password != "keep" {
		t.Fatalf("le secret scellé survit à un redémarrage sans l'Admin : %v %+v", err, got)
	}
}
