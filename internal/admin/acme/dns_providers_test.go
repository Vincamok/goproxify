// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestChallengeLabel(t *testing.T) {
	for _, c := range []struct{ host, zone, want string }{
		{"example.com", "example.com", "_acme-challenge"},
		{"app.example.com", "example.com", "_acme-challenge.app"},
		{"a.b.example.com", "example.com", "_acme-challenge.a.b"},
		{"APP.Example.com.", "example.COM", "_acme-challenge.app"},
		{"other.org", "example.com", "_acme-challenge.other.org"},
		{"notexample.com", "example.com", "_acme-challenge.notexample.com"},
		{"example.com", "", "_acme-challenge.example.com"},
	} {
		if got := challengeLabel(c.host, c.zone); got != c.want {
			t.Errorf("challengeLabel(%q, %q) = %q, attendu %q", c.host, c.zone, got, c.want)
		}
	}
}

// ── OVH ─────────────────────────────────────────────────────────────────────

type fakeOVH struct {
	t        *testing.T
	srv      *httptest.Server
	mu       sync.Mutex
	records  map[int64][2]string // id → {subDomain, target}
	nextID   int64
	refresh  int
	unsigned int // requêtes dont la signature est fausse
}

func newFakeOVH(t *testing.T, secret, consumer string, serverTime int64) *fakeOVH {
	f := &fakeOVH{t: t, records: map[int64][2]string{}, nextID: 100}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.URL.Path == "/1.0/auth/time" {
			fmt.Fprint(w, serverTime)
			return
		}
		body, _ := io.ReadAll(r.Body)
		ts := r.Header.Get("X-Ovh-Timestamp")
		n, _ := strconv.ParseInt(ts, 10, 64)
		want := ovhSignature(secret, consumer, r.Method, f.srv.URL+r.RequestURI, string(body), n)
		if r.Header.Get("X-Ovh-Signature") != want || r.Header.Get("X-Ovh-Application") != "app-key" || r.Header.Get("X-Ovh-Consumer") != consumer {
			f.unsigned++
			http.Error(w, `{"message":"Invalid signature"}`, http.StatusForbidden)
			return
		}
		base := "/1.0/domain/zone/example.com"
		switch {
		case r.Method == http.MethodPost && r.URL.Path == base+"/record":
			var in map[string]any
			_ = json.Unmarshal(body, &in)
			f.nextID++
			f.records[f.nextID] = [2]string{in["subDomain"].(string), in["target"].(string)}
			fmt.Fprintf(w, `{"id":%d}`, f.nextID)
		case r.Method == http.MethodGet && r.URL.Path == base+"/record":
			q := r.URL.Query()
			var ids []int64
			for id, rec := range f.records {
				if q.Get("fieldType") == "TXT" && rec[0] == q.Get("subDomain") {
					ids = append(ids, id)
				}
			}
			sort.Slice(ids, func(i, j int) bool { return ids[i] < ids[j] })
			_ = json.NewEncoder(w).Encode(append([]int64{}, ids...))
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, base+"/record/"):
			id, _ := strconv.ParseInt(strings.TrimPrefix(r.URL.Path, base+"/record/"), 10, 64)
			delete(f.records, id)
		case r.Method == http.MethodPost && r.URL.Path == base+"/refresh":
			f.refresh++
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeOVH) provider() *ovhProvider {
	p, _ := newOVHProvider(map[string]string{
		"endpoint": f.srv.URL + "/1.0", "app_key": "app-key", "app_secret": "app-secret",
		"consumer_key": "consumer", "zone": "example.com",
	})
	o := p.(*ovhProvider)
	o.client = f.srv.Client()
	o.now = func() time.Time { return time.Unix(1000, 0) }
	return o
}

func (f *fakeOVH) subDomains() []string {
	var out []string
	for _, r := range f.records {
		out = append(out, r[0])
	}
	sort.Strings(out)
	return out
}

func TestOVH_SignsRequestsAndUsesRelativeNames(t *testing.T) {
	f := newFakeOVH(t, "app-secret", "consumer", 1100)
	o := f.provider()
	ctx := t.Context()

	if err := o.SetTXTRecord(ctx, "example.com", "v-apex"); err != nil {
		t.Fatal(err)
	}
	if err := o.SetTXTRecord(ctx, "app.example.com", "v-app"); err != nil {
		t.Fatal(err)
	}
	if f.unsigned != 0 {
		t.Fatalf("%d requêtes à la signature invalide", f.unsigned)
	}
	if got := strings.Join(f.subDomains(), ","); got != "_acme-challenge,_acme-challenge.app" {
		t.Fatalf("sous-domaines créés = %s (doivent être relatifs à la zone)", got)
	}
	if f.refresh != 2 {
		t.Fatalf("la zone doit être rafraîchie après chaque ajout, refresh = %d", f.refresh)
	}
	if o.timeDelta != 100 {
		t.Fatalf("décalage d'horloge = %d, attendu 100 (GET /auth/time)", o.timeDelta)
	}
}

func TestOVH_DeleteRemovesOnlyTheChallengeOfThatName(t *testing.T) {
	f := newFakeOVH(t, "app-secret", "consumer", 1000)
	o := f.provider()
	ctx := t.Context()
	_ = o.SetTXTRecord(ctx, "example.com", "wild")
	_ = o.SetTXTRecord(ctx, "example.com", "apex")
	_ = o.SetTXTRecord(ctx, "app.example.com", "other")
	f.records[999] = [2]string{"mail", "keep-me"} // enregistrement étranger, ne doit pas être touché

	if err := o.DeleteTXTRecord(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if got := strings.Join(f.subDomains(), ","); got != "_acme-challenge.app,mail" {
		t.Fatalf("après suppression : %s", got)
	}
	refreshes := f.refresh
	if err := o.DeleteTXTRecord(ctx, "example.com"); err != nil {
		t.Fatalf("la suppression doit être idempotente : %v", err)
	}
	if f.refresh != refreshes {
		t.Fatal("rien à supprimer : pas de rafraîchissement de zone attendu")
	}
	if f.unsigned != 0 {
		t.Fatalf("%d requêtes à la signature invalide", f.unsigned)
	}
}

func TestOVH_WrongSecretIsRejected(t *testing.T) {
	f := newFakeOVH(t, "the-real-secret", "consumer", 1000)
	if err := f.provider().SetTXTRecord(t.Context(), "example.com", "v"); err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}

func TestOVH_EndpointAliases(t *testing.T) {
	for alias, want := range map[string]string{
		"ovh-eu": "https://eu.api.ovh.com/1.0", "OVH-CA": "https://ca.api.ovh.com/1.0",
		"ovh-us": "https://api.us.ovhcloud.com/1.0", "": ovhDefaultEndpoint,
		"https://custom.example/1.0/": "https://custom.example/1.0",
	} {
		p, _ := newOVHProvider(map[string]string{"endpoint": alias})
		if got := p.(*ovhProvider).endpoint; got != want {
			t.Errorf("endpoint %q → %q, attendu %q", alias, got, want)
		}
	}
}

// ── Hetzner ─────────────────────────────────────────────────────────────────

type fakeHetzner struct {
	srv     *httptest.Server
	mu      sync.Mutex
	records []map[string]string
	nextID  int
	badAuth int
}

func newFakeHetzner(t *testing.T) *fakeHetzner {
	f := &fakeHetzner{}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		if r.Header.Get("Auth-API-Token") != "tok" {
			f.badAuth++
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		switch {
		case r.Method == http.MethodGet && r.URL.Path == "/zones/Z1":
			fmt.Fprint(w, `{"zone":{"id":"Z1","name":"example.com"}}`)
		case r.Method == http.MethodPost && r.URL.Path == "/records":
			var in map[string]any
			_ = json.NewDecoder(r.Body).Decode(&in)
			f.nextID++
			f.records = append(f.records, map[string]string{
				"id": fmt.Sprintf("r%d", f.nextID), "type": in["type"].(string),
				"name": in["name"].(string), "value": in["value"].(string),
			})
			fmt.Fprint(w, `{}`)
		case r.Method == http.MethodGet && r.URL.Path == "/records":
			// Pages de 2 enregistrements quel que soit per_page, pour exercer la pagination.
			page, _ := strconv.Atoi(r.URL.Query().Get("page"))
			if page < 1 {
				page = 1
			}
			const size = 2
			last := (len(f.records) + size - 1) / size
			if last == 0 {
				last = 1
			}
			lo, hi := (page-1)*size, page*size
			if lo > len(f.records) {
				lo = len(f.records)
			}
			if hi > len(f.records) {
				hi = len(f.records)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"records": f.records[lo:hi],
				"meta":    map[string]any{"pagination": map[string]any{"last_page": last}},
			})
		case r.Method == http.MethodDelete && strings.HasPrefix(r.URL.Path, "/records/"):
			id := strings.TrimPrefix(r.URL.Path, "/records/")
			for i, rec := range f.records {
				if rec["id"] == id {
					f.records = append(f.records[:i], f.records[i+1:]...)
					break
				}
			}
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeHetzner) provider() *hetznerProvider {
	return &hetznerProvider{apiToken: "tok", zoneID: "Z1", baseURL: f.srv.URL, client: f.srv.Client()}
}

func TestHetzner_RelativeNamesAndDelete(t *testing.T) {
	f := newFakeHetzner(t)
	h := f.provider()
	ctx := t.Context()
	for _, c := range [][2]string{{"example.com", "wild"}, {"example.com", "apex"}, {"app.example.com", "other"}} {
		if err := h.SetTXTRecord(ctx, c[0], c[1]); err != nil {
			t.Fatal(err)
		}
	}
	f.records = append(f.records,
		map[string]string{"id": "x1", "type": "A", "name": "_acme-challenge", "value": "1.2.3.4"}, // même nom, autre type
		map[string]string{"id": "x2", "type": "TXT", "name": "mail", "value": "spf"},
	)
	var names []string
	for _, r := range f.records {
		names = append(names, r["name"])
	}
	if got := strings.Join(names[:3], ","); got != "_acme-challenge,_acme-challenge,_acme-challenge.app" {
		t.Fatalf("noms créés = %s (doivent être relatifs à la zone)", got)
	}

	if err := h.DeleteTXTRecord(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	var left []string
	for _, r := range f.records {
		left = append(left, r["id"])
	}
	// Reste : le TXT de app, l'enregistrement A homonyme et le TXT « mail ». Cinq enregistrements
	// répartis sur trois pages au départ : la pagination est donc traversée.
	if len(f.records) != 3 {
		t.Fatalf("enregistrements restants = %v", f.records)
	}
	if err := h.DeleteTXTRecord(ctx, "example.com"); err != nil {
		t.Fatalf("la suppression doit être idempotente : %v", err)
	}
	if f.badAuth != 0 {
		t.Fatalf("%d requêtes sans jeton valide", f.badAuth)
	}
}

func TestHetzner_ErrorsAreReported(t *testing.T) {
	f := newFakeHetzner(t)
	h := f.provider()
	h.apiToken = "mauvais"
	if err := h.SetTXTRecord(t.Context(), "example.com", "v"); err == nil || !strings.Contains(err.Error(), "401") {
		t.Fatalf("err = %v", err)
	}
}

// ── Route 53 ────────────────────────────────────────────────────────────────

// Vecteur de test « get-vanilla » de la suite officielle AWS Signature Version 4.
func TestSigV4_AWSGetVanillaVector(t *testing.T) {
	ts := time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC)
	headers := map[string]string{"host": "example.amazonaws.com", "x-amz-date": "20150830T123600Z"}
	auth, canonHash := sigV4(http.MethodGet, "/", nil, headers, nil,
		"AKIDEXAMPLE", "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY", "us-east-1", "service", ts)
	if canonHash != "bb579772317eb040ac9ed261061d46c1f17a8133879d6129b6e1c25292927e63" {
		t.Errorf("requête canonique : %s", canonHash)
	}
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, " +
		"SignedHeaders=host;x-amz-date, Signature=5fa00fa31553b73ebf1942676e86291e8372ff2a2260956d9b8aae1d763fbf31"
	if auth != want {
		t.Errorf("Authorization = %s", auth)
	}
}

func TestSigV4_QueryIsSortedAndEncoded(t *testing.T) {
	got := sigV4Query(url.Values{"type": {"TXT"}, "name": {"_acme-challenge.a b.example.com."}, "maxitems": {"1"}})
	want := "maxitems=1&name=_acme-challenge.a%20b.example.com.&type=TXT"
	if got != want {
		t.Errorf("query = %s", got)
	}
}

type fakeRoute53 struct {
	srv     *httptest.Server
	mu      sync.Mutex
	sets    map[string]*r53Record // FQDN → jeu TXT
	changes []string
	badSig  int
}

// r53TestChange décrit la requête ChangeResourceRecordSets telle que l'API réelle l'attend ; il est
// volontairement indépendant des types du fournisseur pour vérifier la structure du XML émis.
type r53TestChange struct {
	XMLName xml.Name `xml:"ChangeResourceRecordSetsRequest"`
	Xmlns   string   `xml:"xmlns,attr"`
	Action  string   `xml:"ChangeBatch>Changes>Change>Action"`
	Name    string   `xml:"ChangeBatch>Changes>Change>ResourceRecordSet>Name"`
	Type    string   `xml:"ChangeBatch>Changes>Change>ResourceRecordSet>Type"`
	TTL     int      `xml:"ChangeBatch>Changes>Change>ResourceRecordSet>TTL"`
	Values  []string `xml:"ChangeBatch>Changes>Change>ResourceRecordSet>ResourceRecords>ResourceRecord>Value"`
}

func newFakeRoute53(t *testing.T) *fakeRoute53 {
	f := &fakeRoute53{sets: map[string]*r53Record{}}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		body, _ := io.ReadAll(r.Body)
		date := r.Header.Get("X-Amz-Date")
		ts, err := time.Parse("20060102T150405Z", date)
		hdr := map[string]string{"host": r.Host, "x-amz-date": date}
		if tok := r.Header.Get("X-Amz-Security-Token"); tok != "" {
			hdr["x-amz-security-token"] = tok
		}
		want, _ := sigV4(r.Method, r.URL.Path, r.URL.Query(), hdr, body, "AK", "SK", route53Region, route53Service, ts)
		if err != nil || r.Header.Get("Authorization") != want {
			f.badSig++
			http.Error(w, "<ErrorResponse><Error><Code>SignatureDoesNotMatch</Code></Error></ErrorResponse>", http.StatusForbidden)
			return
		}
		const zone = "/2013-04-01/hostedzone/Z123/rrset"
		switch {
		case r.Method == http.MethodGet && r.URL.Path == zone:
			name := r.URL.Query().Get("name")
			w.Header().Set("Content-Type", "text/xml")
			fmt.Fprint(w, `<?xml version="1.0"?><ListResourceRecordSetsResponse xmlns="`+route53Namespace+`"><ResourceRecordSets>`)
			if s, ok := f.sets[name]; ok {
				b, _ := xml.Marshal(s)
				w.Write(b)
			}
			fmt.Fprint(w, `</ResourceRecordSets></ListResourceRecordSetsResponse>`)
		case r.Method == http.MethodPost && r.URL.Path == zone+"/":
			var ch r53TestChange
			if err := xml.Unmarshal(body, &ch); err != nil || ch.Xmlns != route53Namespace {
				http.Error(w, "malformed", http.StatusBadRequest)
				return
			}
			f.changes = append(f.changes, ch.Action)
			switch ch.Action {
			case "UPSERT":
				f.sets[ch.Name] = &r53Record{Name: ch.Name, Type: ch.Type, TTL: ch.TTL, Values: ch.Values}
			case "DELETE":
				cur, ok := f.sets[ch.Name]
				if !ok || strings.Join(cur.Values, "|") != strings.Join(ch.Values, "|") || cur.TTL != ch.TTL {
					http.Error(w, "<Error>InvalidChangeBatch: values do not match</Error>", http.StatusBadRequest)
					return
				}
				delete(f.sets, ch.Name)
			}
			fmt.Fprint(w, `<ChangeResourceRecordSetsResponse/>`)
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeRoute53) provider() *route53Provider {
	return &route53Provider{
		hostedZoneID: "Z123", accessKey: "AK", secretKey: "SK",
		baseURL: f.srv.URL, client: f.srv.Client(),
		now: func() time.Time { return time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC) },
	}
}

func TestRoute53_SetMergesValuesAndDeleteReplaysThem(t *testing.T) {
	f := newFakeRoute53(t)
	r := f.provider()
	ctx := t.Context()

	// Wildcard et apex partagent le nom _acme-challenge.example.com : les deux valeurs coexistent.
	if err := r.SetTXTRecord(ctx, "example.com", "wild-value"); err != nil {
		t.Fatal(err)
	}
	if err := r.SetTXTRecord(ctx, "example.com", "apex-value"); err != nil {
		t.Fatal(err)
	}
	if err := r.SetTXTRecord(ctx, "example.com", "apex-value"); err != nil { // rejeu : pas de doublon
		t.Fatal(err)
	}
	name := "_acme-challenge.example.com."
	got := f.sets[name]
	if got == nil || len(got.Values) != 2 || got.TTL != 60 {
		t.Fatalf("jeu TXT = %+v", got)
	}
	sort.Strings(got.Values)
	if got.Values[0] != `"apex-value"` || got.Values[1] != `"wild-value"` {
		t.Fatalf("valeurs = %v (les TXT doivent être entre guillemets)", got.Values)
	}

	if err := r.DeleteTXTRecord(ctx, "example.com"); err != nil {
		t.Fatal(err)
	}
	if len(f.sets) != 0 {
		t.Fatalf("jeu non supprimé : %v", f.sets)
	}
	n := len(f.changes)
	if err := r.DeleteTXTRecord(ctx, "example.com"); err != nil {
		t.Fatalf("la suppression doit être idempotente : %v", err)
	}
	if len(f.changes) != n {
		t.Fatal("rien à supprimer : aucun appel de modification attendu")
	}
	if f.badSig != 0 {
		t.Fatalf("%d requêtes à la signature invalide", f.badSig)
	}
}

func TestRoute53_SessionTokenIsSignedAndSent(t *testing.T) {
	f := newFakeRoute53(t)
	r := f.provider()
	r.sessionToken = "temp-token"
	if err := r.SetTXTRecord(t.Context(), "example.com", "v"); err != nil {
		t.Fatal(err)
	}
	if f.badSig != 0 {
		t.Fatal("signature invalide avec jeton de session")
	}
}

func TestRoute53_BadCredentialsAreReported(t *testing.T) {
	f := newFakeRoute53(t)
	r := f.provider()
	r.secretKey = "mauvais"
	err := r.SetTXTRecord(t.Context(), "example.com", "v")
	if err == nil || !strings.Contains(err.Error(), "403") {
		t.Fatalf("err = %v", err)
	}
}

func TestRoute53_FQDN(t *testing.T) {
	r := &route53Provider{}
	if got := r.fqdn(" App.Example.com. "); got != "_acme-challenge.app.example.com." {
		t.Fatalf("fqdn = %q", got)
	}
}
