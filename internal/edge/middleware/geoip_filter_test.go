// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

var fakeGeo = map[string]string{"1.1.1.1": "fr", "2.2.2.2": "CN", "3.3.3.3": ""}

func fakeOpen() (func(net.IP) string, error) {
	return func(ip net.IP) string { return fakeGeo[ip.String()] }, nil
}

func geoCode(mw func(http.Handler) http.Handler, remote string) int {
	h := mw(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestGeoIPFilter_AllowAndDeny(t *testing.T) {
	allow := geoIPFilter("allow", []string{"FR", " de "}, fakeOpen)
	deny := geoIPFilter("deny", []string{"cn"}, fakeOpen)
	for _, c := range []struct {
		name   string
		mw     func(http.Handler) http.Handler
		remote string
		want   int
	}{
		{"allow: pays listé (casse ignorée)", allow, "1.1.1.1:1", 200},
		{"allow: pays hors liste", allow, "2.2.2.2:1", 403},
		{"allow: pays inconnu refusé", allow, "3.3.3.3:1", 403},
		{"allow: client illisible refusé", allow, "bad", 403},
		{"deny: pays listé", deny, "2.2.2.2:1", 403},
		{"deny: autre pays", deny, "1.1.1.1:1", 200},
		{"deny: pays inconnu passe", deny, "3.3.3.3:1", 200},
	} {
		if got := geoCode(c.mw, c.remote); got != c.want {
			t.Errorf("%s : %d (attendu %d)", c.name, got, c.want)
		}
	}
}

// Une base absente désactivait silencieusement un filtre « allow » (tout le monde passait).
func TestGeoIPFilter_MissingDB(t *testing.T) {
	missing := func() (func(net.IP) string, error) { return nil, errors.New("absent") }
	if got := geoCode(geoIPFilter("allow", []string{"FR"}, missing), "1.1.1.1:1"); got != 503 {
		t.Errorf("allow sans base : %d (attendu 503)", got)
	}
	if got := geoCode(geoIPFilter("deny", []string{"CN"}, missing), "2.2.2.2:1"); got != 200 {
		t.Errorf("deny sans base : %d (attendu 200)", got)
	}
}

// La base téléchargée après la construction de la chaîne est utilisée dès qu'elle apparaît.
func TestGeoIPFilter_DBAppearsLater(t *testing.T) {
	ready := false
	open := func() (func(net.IP) string, error) {
		if !ready {
			return nil, errors.New("pas encore")
		}
		return fakeOpen()
	}
	mw := geoIPFilter("allow", []string{"FR"}, open)
	if got := geoCode(mw, "2.2.2.2:1"); got != 503 {
		t.Fatalf("avant : %d", got)
	}
	ready = true
	if got := geoCode(mw, "2.2.2.2:1"); got != 403 {
		t.Errorf("après : %d (attendu 403)", got)
	}
	if got := geoCode(mw, "1.1.1.1:1"); got != 200 {
		t.Errorf("après, pays autorisé : %d", got)
	}
}

func TestGeoIPFilter_UnknownModeFailsClosed(t *testing.T) {
	if got := geoCode(geoIPFilter("blok", []string{"CN"}, fakeOpen), "1.1.1.1:1"); got != 403 {
		t.Errorf("mode inconnu : %d", got)
	}
	if got := geoCode(geoIPFilter("", nil, fakeOpen), "1.1.1.1:1"); got != 200 {
		t.Errorf("sans restriction : %d", got)
	}
}

func TestGeoIP_EmptyPathIsNoopAndMissingFileUsesFilter(t *testing.T) {
	if got := geoCode(GeoIP("", "allow", []string{"FR"}), "1.1.1.1:1"); got != 200 {
		t.Errorf("sans chemin : %d", got)
	}
	if got := geoCode(GeoIP(filepath.Join(t.TempDir(), "nope.mmdb"), "allow", []string{"FR"}), "1.1.1.1:1"); got != 503 {
		t.Errorf("fichier absent, allow : %d", got)
	}
}
