// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ipprofile

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// Les tests d'actualisation servent leurs sources depuis 127.0.0.1 : on autorise le réseau interne pour eux.
func TestMain(m *testing.M) {
	os.Setenv("GPX_IPPROFILE_ALLOW_PRIVATE", "1")
	os.Exit(m.Run())
}

func TestValidateFeed(t *testing.T) {
	ok := [][]string{{"https://www.cloudflare.com/ips-v4"}, {"http://feeds.example.org/list.txt", "https://a.example.org/x"}, nil}
	for _, urls := range ok {
		if err := ValidateFeed(urls, "plain", false); err != nil {
			t.Errorf("%v refusé : %v", urls, err)
		}
	}
	bad := map[string][]string{
		"schéma file":     {"file:///etc/passwd"},
		"schéma gopher":   {"gopher://x"},
		"sans hôte":       {"http://"},
		"loopback":        {"http://127.0.0.1:8080/x"},
		"métadonnées":     {"http://169.254.169.254/latest/meta-data/"},
		"réseau privé":    {"http://10.0.0.5/list"},
		"localhost":       {"http://localhost/x"},
		"cgnat":           {"http://100.64.0.1/x"},
		"métadonnées gcp": {"http://metadata.google.internal/x"},
		"pas une URL":     {"pas-une-url"},
	}
	for name, urls := range bad {
		if err := ValidateFeed(urls, "plain", false); err == nil {
			t.Errorf("%s : acceptée", name)
		}
		if name != "schéma file" && name != "schéma gopher" && name != "sans hôte" && name != "pas une URL" {
			if err := ValidateFeed(urls, "plain", true); err != nil {
				t.Errorf("%s : doit passer avec GPX_IPPROFILE_ALLOW_PRIVATE : %v", name, err)
			}
		}
	}
	if ValidateFeed(nil, "json-awss", false) == nil {
		t.Error("format inconnu accepté")
	}
	if ValidateFeed(make([]string, MaxFeedURLs+1), "plain", false) == nil {
		t.Error("trop de sources acceptées")
	}
}

// Même si l'URL passe le contrôle de forme, la connexion vers une adresse interne est refusée : c'est ce qui
// protège d'un nom DNS qui pointe vers le réseau interne.
func TestUpdaterRefusesInternalFeedsAtConnectionTime(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits++ }))
	defer srv.Close()
	t.Setenv("GPX_IPPROFILE_ALLOW_PRIVATE", "")
	u := New(nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	_, _, _, err := u.fetch(context.Background(), srv.URL, feedValidators{})
	if err == nil || !strings.Contains(err.Error(), "réseau interne") || hits != 0 {
		t.Fatalf("source interne jointe : err=%v hits=%d", err, hits)
	}
}
