// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"encoding/xml"
	"html"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// testIdP : un fournisseur d'identité SAML en mémoire (celui de la bibliothèque), qui connaît le SP de test.
type testIdP struct {
	idp *saml.IdentityProvider
	sp  *saml.EntityDescriptor
}

func (t *testIdP) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	if id == t.sp.EntityID {
		return t.sp, nil
	}
	return nil, os.ErrNotExist
}

type fixedSession struct{ groups []string }

func (f fixedSession) GetSession(_ http.ResponseWriter, _ *http.Request, _ *saml.IdpAuthnRequest) *saml.Session {
	return &saml.Session{ID: "s1", CreateTime: time.Now(), ExpireTime: time.Now().Add(time.Hour), Index: "i1",
		NameID: "alice", UserName: "alice", UserEmail: "alice@example.fr", Groups: f.groups}
}

func selfSigned(t *testing.T, cn string) (certPEM, keyPEM string, cert *x509.Certificate, key *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ = x509.ParseCertificate(der)
	certPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)}))
	return
}

// samlFixture monte un SP (le middleware) et un IdP en mémoire qui se connaissent.
func samlFixture(t *testing.T, groups []string, allowed []string) (http.Handler, *testIdP) {
	t.Helper()
	spCert, spKey, _, _ := selfSigned(t, "sp")
	idpCertPEM, _, idpCert, idpKey := selfSigned(t, "idp")
	_ = idpCertPEM

	idp := &saml.IdentityProvider{
		Key: idpKey, Certificate: idpCert,
		MetadataURL: url.URL{Scheme: "https", Host: "idp.example.fr", Path: "/metadata"},
		SSOURL:      url.URL{Scheme: "https", Host: "idp.example.fr", Path: "/sso"},
		SessionProvider: fixedSession{groups},
	}
	idpMeta, err := xml.Marshal(idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	cfg := &router.SAMLConfig{
		EntityID: "https://app.example.fr/saml/metadata", ACSPath: "/saml/acs", MetadataPath: "/saml/metadata",
		CertPEM: spCert, KeyPEM: spKey, IDPMetadataXML: string(idpMeta), AllowedGroups: allowed,
		SessionSecret: "0123456789abcdef0123456789abcdef",
		// Nom que la bibliothèque donne à l'attribut des groupes (eduPersonAffiliation).
		GroupsAttr: "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
	}
	h := SAMLAuth(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-User", r.Header.Get("X-Remote-User"))
		_, _ = w.Write([]byte("BACKEND"))
	}))

	// Le SP est connu de l'IdP par ses métadonnées.
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example.fr/saml/metadata", nil))
	var spMeta saml.EntityDescriptor
	if err := xml.Unmarshal(rec.Body.Bytes(), &spMeta); err != nil {
		t.Fatalf("métadonnées du SP illisibles : %v", err)
	}
	tidp := &testIdP{idp: idp, sp: &spMeta}
	idp.ServiceProviderProvider = tidp
	return h, tidp
}

var formField = regexp.MustCompile(`name="(SAMLResponse|RelayState)" value="([^"]*)"`)

// idpAnswer fait répondre l'IdP à la redirection du SP et rend les champs du formulaire auto-posté.
func idpAnswer(t *testing.T, idp *saml.IdentityProvider, redirect string) url.Values {
	t.Helper()
	u, err := url.Parse(redirect)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	idp.ServeSSO(rec, httptest.NewRequest(http.MethodGet, "https://idp.example.fr/sso?"+u.RawQuery, nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("l'IdP a refusé la requête : %d %s", rec.Code, rec.Body.String())
	}
	form := url.Values{}
	for _, m := range formField.FindAllStringSubmatch(rec.Body.String(), -1) {
		form.Set(m[1], html.UnescapeString(m[2]))
	}
	if form.Get("SAMLResponse") == "" {
		t.Fatalf("pas de SAMLResponse dans la page de l'IdP : %s", rec.Body.String())
	}
	return form
}

func cookiesOf(rec *httptest.ResponseRecorder) []*http.Cookie { return rec.Result().Cookies() }

func postACS(h http.Handler, form url.Values, cookies []*http.Cookie) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "https://app.example.fr/saml/acs", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range cookies {
		req.AddCookie(c)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// La connexion SAML initiée par le SP aboutit : requête → IdP → réponse → ACS → session → retour à la page demandée.
func TestSAML_ServiceProviderInitiatedLoginCompletes(t *testing.T) {
	h, tidp := samlFixture(t, nil, nil)

	rec := httptest.NewRecorder()
	first := httptest.NewRequest(http.MethodGet, "https://app.example.fr/secret?x=1", nil)
	first.URL = &url.URL{Path: "/secret", RawQuery: "x=1"} // comme sur un vrai serveur : URL relative
	h.ServeHTTP(rec, first)
	if rec.Code != http.StatusFound {
		t.Fatalf("sans session : %d (attendu une redirection vers l'IdP)", rec.Code)
	}
	trackers := cookiesOf(rec)
	form := idpAnswer(t, tidp.idp, rec.Header().Get("Location"))

	acs := postACS(h, form, trackers)
	if acs.Code != http.StatusFound {
		t.Fatalf("ACS : %d %s (la connexion SAML doit aboutir)", acs.Code, acs.Body.String())
	}
	if loc := acs.Header().Get("Location"); loc != "/secret?x=1" {
		t.Errorf("retour à la page demandée : %q", loc)
	}
	var session *http.Cookie
	for _, c := range cookiesOf(acs) {
		if c.Name == samlSessionCookie && c.Value != "" {
			session = c
		}
	}
	if session == nil {
		t.Fatal("la session n'a pas été posée")
	}

	req := httptest.NewRequest(http.MethodGet, "https://app.example.fr/secret", nil)
	req.AddCookie(session)
	req.Header.Set("X-Remote-Groups", "admins") // forgé
	out := httptest.NewRecorder()
	h.ServeHTTP(out, req)
	if out.Code != http.StatusOK || out.Header().Get("X-Seen-User") != "alice" {
		t.Errorf("avec la session : %d, utilisateur %q", out.Code, out.Header().Get("X-Seen-User"))
	}
}

// Une réponse capturée ne se rejoue pas depuis un autre navigateur : sans le cookie de suivi de la requête
// d'origine, aucune requête ne lui correspond.
func TestSAML_CapturedResponseCannotBeReplayedFromAnotherBrowser(t *testing.T) {
	h, tidp := samlFixture(t, nil, nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example.fr/", nil))
	form := idpAnswer(t, tidp.idp, rec.Header().Get("Location"))

	if acs := postACS(h, form, nil); acs.Code != http.StatusForbidden {
		t.Fatalf("rejeu sans cookie de suivi : %d (attendu 403)", acs.Code)
	}
	// Dans le navigateur d'origine : elle passe une fois ; la requête suivie est close, un second envoi échoue.
	ok := postACS(h, form, cookiesOf(rec))
	if ok.Code != http.StatusFound {
		t.Fatalf("dans le navigateur d'origine : %d", ok.Code)
	}
	var closed []*http.Cookie
	for _, c := range cookiesOf(rec) {
		closed = append(closed, c)
	}
	for _, c := range cookiesOf(ok) { // le cookie de suivi est effacé par la réponse
		for i, orig := range closed {
			if orig.Name == c.Name {
				closed[i] = c
			}
		}
	}
	if again := postACS(h, form, closed); again.Code == http.StatusFound {
		t.Error("une même réponse ne doit pas servir deux fois dans le même navigateur")
	}
}

func TestSAML_GroupRestrictionIsEnforced(t *testing.T) {
	for name, tc := range map[string]struct {
		groups, allowed []string
		want            int
	}{
		"groupe autorisé": {[]string{"CN=staff,DC=x"}, []string{"staff"}, http.StatusFound},
		"hors groupe":     {[]string{"CN=visiteurs,DC=x"}, []string{"staff"}, http.StatusForbidden},
		"sans groupe":     {nil, []string{"staff"}, http.StatusForbidden},
	} {
		h, tidp := samlFixture(t, tc.groups, tc.allowed)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example.fr/", nil))
		form := idpAnswer(t, tidp.idp, rec.Header().Get("Location"))
		if acs := postACS(h, form, cookiesOf(rec)); acs.Code != tc.want {
			t.Errorf("%s : %d, attendu %d (%s)", name, acs.Code, tc.want, acs.Body.String())
		}
	}
}

// L'URL des métadonnées de l'IdP ne mène ni aux métadonnées du cloud ni à un schéma exotique.
func TestSAML_IdPMetadataURLIsGuarded(t *testing.T) {
	spCert, spKey, _, _ := selfSigned(t, "sp")
	for _, u := range []string{"http://169.254.169.254/latest/meta-data/", "file:///etc/passwd", "ftp://idp.example.fr/m.xml", "http://[fe80::1]/m.xml"} {
		cfg := &router.SAMLConfig{EntityID: "https://app.example.fr/saml/metadata", CertPEM: spCert, KeyPEM: spKey, IDPMetadataURL: u, SessionSecret: "0123456789abcdef0123456789abcdef"}
		rec := httptest.NewRecorder()
		SAMLAuth(cfg)(http.NotFoundHandler()).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "https://app.example.fr/", nil))
		if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "refusée") {
			t.Errorf("%s : %d %s (attendu un refus de configuration)", u, rec.Code, rec.Body.String())
		}
	}
}
