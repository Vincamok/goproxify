package importer

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
)

func fakeGateway(t *testing.T, state map[string][]byte, mu *sync.Mutex) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") != "Bearer tok" {
			http.Error(w, "401", http.StatusUnauthorized)
			return
		}
		mu.Lock()
		defer mu.Unlock()
		switch r.URL.Path {
		case "/internal/v1/backup/export":
			json.NewEncoder(w).Encode(edgeproxy.BackupBundle{Files: state})
		case "/internal/v1/backup/restore":
			var b edgeproxy.BackupBundle
			json.NewDecoder(r.Body).Decode(&b)
			for k, v := range b.Files {
				state[k] = v
			}
			json.NewEncoder(w).Encode(edgeproxy.BackupResult{Written: len(b.Files), RestartRequired: true})
		default:
			http.NotFound(w, r)
		}
	}))
}

func TestGatewayStateIsBackedUpEncryptedAndRestoredByName(t *testing.T) {
	t.Setenv("GPX_BACKUP_KEY", "cle-passerelles")
	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var mu sync.Mutex
	state := map[string][]byte{"proxies/app.yaml": []byte("host: app.fr"), "portal-config.gpx": []byte("chiffre-portail")}
	srv := fakeGateway(t, state, &mu)
	defer srv.Close()
	db.Exec(`INSERT INTO tokens (id, token, role, node_name, node_endpoint) VALUES ('t1','tok','edge','gw-paris',?)`, srv.URL)

	bk := &Backup{}
	warnings, err := AttachSecrets(db, bk, nil, nil)
	if err != nil || len(warnings) != 0 {
		t.Fatalf("collecte : %v %v", warnings, err)
	}
	raw, _ := json.Marshal(bk)
	if strings.Contains(string(raw), "host: app.fr") || strings.Contains(string(raw), "gw-paris") {
		t.Fatal("état de la passerelle lisible dans le snapshot")
	}

	// La passerelle perd son état, puis la restauration le lui rend.
	mu.Lock()
	for k := range state {
		delete(state, k)
	}
	mu.Unlock()
	res := Apply(db, bk, ImportSelection{ImportSecrets: true, AllowPrivileged: true})
	if res.SecretsError != "" || len(res.Gateways) != 1 || res.Gateways[0].Error != "" || res.Gateways[0].Written != 2 || !res.Gateways[0].RestartRequired {
		t.Fatalf("restauration : %+v", res)
	}
	mu.Lock()
	defer mu.Unlock()
	if string(state["proxies/app.yaml"]) != "host: app.fr" {
		t.Fatalf("état non restitué : %v", state)
	}
}

func TestGatewayUnreachableIsReportedNotSilent(t *testing.T) {
	t.Setenv("GPX_BACKUP_KEY", "k")
	db, _ := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	defer db.Close()
	db.Exec(`INSERT INTO tokens (id, token, role, node_name, node_endpoint) VALUES ('t1','tok','edge','gw-down','http://127.0.0.1:1')`)
	warnings, err := AttachSecrets(db, &Backup{}, nil, nil)
	if err != nil || len(warnings) != 1 || !strings.Contains(warnings[0], "gw-down") {
		t.Fatalf("passerelle injoignable non signalée : %v %v", warnings, err)
	}

	// Restauration vers une passerelle qui n'existe pas sur cette instance : erreur explicite.
	plain, _ := json.Marshal(SecretBundle{Files: map[string][]byte{"gateway/gw-inconnue/proxies/a.yaml": []byte("x")}})
	sealed, _ := sealSecrets(plain)
	db2, _ := admindb.Open(filepath.Join(t.TempDir(), "b.db"))
	defer db2.Close()
	res := Apply(db2, &Backup{Secrets: sealed}, ImportSelection{ImportSecrets: true, AllowPrivileged: true})
	if len(res.Gateways) != 1 || !strings.Contains(res.Gateways[0].Error, "non enregistrée") || res.Errors == 0 {
		t.Fatalf("passerelle inconnue non signalée : %+v", res)
	}
}

func TestSummaryExposesGatewaysAndLockedSections(t *testing.T) {
	t.Setenv("GPX_BACKUP_KEY", "cle-resume")
	plain, _ := json.Marshal(SecretBundle{Files: map[string][]byte{
		"gateway/gw-paris/proxies/a.yaml": []byte("x"),
		"gateway/gw%20lyon/edge.json":     []byte("x"),
		"config/admin-ha.json":            []byte("{}"),
	}})
	sealed, _ := sealSecrets(plain)
	raw, _ := json.Marshal(Backup{Version: "1", Secrets: sealed})

	_, sum, err := SummarizeBackup(raw)
	if err != nil || sum.SecretsDetail == nil || sum.SecretsLocked {
		t.Fatalf("résumé : %+v %v", sum, err)
	}
	if got := strings.Join(sum.SecretsDetail.Gateways, ","); got != "gw lyon,gw-paris" {
		t.Fatalf("passerelles : %q", got)
	}
	if len(sum.SecretsDetail.ConfigFiles) != 1 || sum.SecretsDetail.ConfigFiles[0] != "admin-ha.json" {
		t.Fatalf("fichiers de config : %v", sum.SecretsDetail.ConfigFiles)
	}

	t.Setenv("GPX_BACKUP_KEY", "une-autre-cle")
	_, sum, _ = SummarizeBackup(raw)
	if !sum.SecretsLocked || sum.SecretsDetail != nil {
		t.Fatalf("section illisible non signalée : %+v", sum)
	}
}
