// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestSelfHostedClient_RefusesMetadataButReachesLoopbackAndPrivate(t *testing.T) {
	var hits int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { hits++ }))
	defer srv.Close()
	c := selfHostedClient(2 * time.Second)

	req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, srv.URL, nil)
	resp, err := c.Do(req)
	if err != nil || hits != 1 {
		t.Fatalf("un outil auto-hébergé (ici sur la boucle locale) doit rester joignable : err=%v hits=%d", err, hits)
	}
	resp.Body.Close()

	for _, target := range []string{"http://169.254.169.254/latest/meta-data/", "http://[fe80::1]/x", "http://100.100.100.200/x", "http://[fd00:ec2::254]/x"} {
		req, _ := http.NewRequestWithContext(context.Background(), http.MethodGet, target, nil)
		if _, err := c.Do(req); err == nil || !strings.Contains(err.Error(), "refusée") {
			t.Errorf("%s : %v (attendu : adresse refusée)", target, err)
		}
	}
}

// Un canal GLPI, Gotify… dont l'URL vise les métadonnées cloud échoue sans émettre de requête.
func TestSelfHostedChannels_RefuseMetadataURL(t *testing.T) {
	err := (&GotifySender{URL: "http://169.254.169.254", Token: "t"}).Send(context.Background(), Message{Title: "x"})
	if err == nil || !strings.Contains(err.Error(), "refusée") {
		t.Fatalf("gotify : %v", err)
	}
}
