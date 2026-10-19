package edge

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// Un poll Portainer ou un resync de l'Agent réannonce tous les conteneurs : sans changement, rien n'est
// écrit au niveau info, sinon chaque annonce devenait une ligne de la base de logs de l'Admin.
func TestReannouncedBackendIsNotLoggedAtInfo(t *testing.T) {
	logFile := filepath.Join(os.TempDir(), "gpx-reannounce-"+strings.ReplaceAll(t.Name(), "/", "_")+".log")
	os.Remove(logFile)
	t.Cleanup(func() { os.Remove(logFile) }) // le logger garde le fichier ouvert : échec toléré sous Windows
	s := &Server{log: edgelog.New("info", "text", logFile), table: &router.Table{}}
	post := func(cid, backend string) {
		b, _ := json.Marshal(map[string]any{
			"id": "docker:" + cid[:12] + ":app.example.fr", "host": "app.example.fr",
			"backends": []string{backend}, "container_id": cid, "agent_name": "ag",
		})
		rr := httptest.NewRecorder()
		s.handleAgentContainerStart(rr, httptest.NewRequest(http.MethodPost, "/internal/v1/agent/containers", bytes.NewReader(b)))
		if rr.Code != http.StatusNoContent {
			t.Fatalf("status = %d", rr.Code)
		}
	}
	count := func(msg string) int {
		data, _ := os.ReadFile(logFile)
		return strings.Count(string(data), msg)
	}

	post("aaaaaaaaaaaa1111", "http://10.0.0.1:80") // crée la route
	post("bbbbbbbbbbbb2222", "http://10.0.0.2:80") // ajoute un backend : changement
	if n := count("agent: backend ajouté au pool"); n != 1 {
		t.Fatalf("après un ajout : %d lignes, attendu 1", n)
	}
	for i := 0; i < 20; i++ {
		post("bbbbbbbbbbbb2222", "http://10.0.0.2:80") // réannonce identique
	}
	if n := count("agent: backend ajouté au pool"); n != 1 {
		t.Fatalf("après 20 réannonces identiques : %d lignes, attendu 1", n)
	}
	post("bbbbbbbbbbbb2222", "http://10.0.0.9:80") // le conteneur change d'adresse : changement
	if n := count("agent: backend ajouté au pool"); n != 2 {
		t.Fatalf("après un changement d'adresse : %d lignes, attendu 2", n)
	}
}
