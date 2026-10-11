// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestCertBundle_SingleUseTokenServedOnce(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "bundle.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`INSERT INTO certs (id, domain, issuer, cert_pem, key_pem, expires_at) VALUES ('c1','a.example.fr','x','CERT','KEY','2099-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	mac := hmac.New(sha256.New, []byte("goproxify-pull"))
	mac.Write([]byte("tok"))
	if _, err := db.Exec(`INSERT INTO cert_pull_tokens (id, cert_id, name, token_hash, max_uses) VALUES ('t1','c1','n',?,1)`, hex.EncodeToString(mac.Sum(nil))); err != nil {
		t.Fatal(err)
	}
	h := &CertBundleHandler{DB: db}

	var served atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rr := httptest.NewRecorder()
			h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/v1/cert-bundle?token=tok", nil))
			if rr.Code == http.StatusOK {
				served.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	if served.Load() != 1 {
		t.Fatalf("un jeton à usage unique a servi la clé privée %d fois", served.Load())
	}
}
