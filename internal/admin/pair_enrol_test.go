// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/pairing"
	"github.com/vincamok/goproxify/internal/sqltime"
)

// declareAutoAccept déclare un nœud dont l'opérateur a voulu l'acceptation automatique (assistant Infrastructure).
func declareAutoAccept(t *testing.T, db *sql.DB, role, name string) {
	t.Helper()
	if _, err := db.Exec(`INSERT INTO declared_nodes (id, role, name, config) VALUES (?, ?, ?, ?)`,
		uuid.NewString(), role, name, `{"auto_accept": true}`); err != nil {
		t.Fatal(err)
	}
}

type pairFixture struct {
	t    *testing.T
	s    *Server
	db   *sql.DB
	root string
	key  string
	n    int
}

func newPairFixture(t *testing.T) *pairFixture {
	t.Helper()
	const root = "secret-racine-0123456789abcdef"
	t.Setenv("GPX_PAIRING_SECRET", root)
	db, err := admindb.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &pairFixture{t: t, db: db, root: root, key: pairing.AgentKey(root),
		s: &Server{db: db, log: slog.New(slog.NewTextHandler(io.Discard, nil)), loginLimit: newLoginLimiter()}}
}

type pairReply struct {
	code   int
	status string
	token  string
}

func (f *pairFixture) pair(role, name, bearer string) pairReply {
	f.t.Helper()
	f.n++
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/pair",
		strings.NewReader(`{"secret":"`+f.key+`","node_name":"`+name+`","role":"`+role+`"}`))
	req.RemoteAddr = "10.3.0." + string(rune('0'+f.n%9+1)) + ":1"
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	rec := httptest.NewRecorder()
	f.s.handlePair(rec, req)
	var body struct{ Status, Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	return pairReply{rec.Code, body.Status, body.Token}
}

func (f *pairFixture) accept(role, name string) {
	f.t.Helper()
	var id string
	if err := f.db.QueryRow(`SELECT id FROM pending_nodes WHERE node_name=? AND role=?`, name, role).Scan(&id); err != nil {
		f.t.Fatalf("aucune demande en attente pour %s : %v", name, err)
	}
	tok := auth.GenerateToken(role, name)
	stored, hash := auth.PrepareNodeTokenForStore(tok)
	if _, err := f.db.Exec(`UPDATE tokens SET revoked=1 WHERE role=? AND node_name=? AND revoked=0`, role, name); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.db.Exec(`INSERT INTO tokens (id, token, token_hash, role, rbac_role, node_name) VALUES (?, ?, ?, ?, 'admin', ?)`,
		uuid.NewString(), stored, hash, role, name); err != nil {
		f.t.Fatal(err)
	}
	if _, err := f.db.Exec(`UPDATE pending_nodes SET status='accepted', token=? WHERE id=?`, tok, id); err != nil {
		f.t.Fatal(err)
	}
}

// Avoir le secret d'appairage et le nom d'un nœud ne fait plus rendre son jeton : il faut le présenter.
func TestPairDoesNotReturnAnExistingTokenOnTheSecretAlone(t *testing.T) {
	f := newPairFixture(t)
	declareAutoAccept(t, f.db, "agent", "agent-a")

	first := f.pair("agent", "agent-a", "")
	if first.code != http.StatusOK || first.token == "" {
		t.Fatalf("première fois, nœud déclaré : %+v", first)
	}

	// Quelqu'un qui connaît le secret et le nom, mais pas le jeton.
	thief := f.pair("agent", "agent-a", "")
	if thief.token != "" || thief.code != http.StatusAccepted {
		t.Fatalf("le jeton ne doit pas être rendu sur le seul secret : %+v", thief)
	}
	wrong := f.pair("agent", "agent-a", "jeton-faux")
	if wrong.token != "" || wrong.code != http.StatusAccepted {
		t.Fatalf("un faux jeton ne vaut pas preuve : %+v", wrong)
	}

	// Le nœud, lui, présente son jeton et le retrouve.
	again := f.pair("agent", "agent-a", first.token)
	if again.code != http.StatusOK || again.token != first.token {
		t.Fatalf("le nœud qui présente son jeton le retrouve : %+v", again)
	}
}

// Un nœud déclaré qui a déjà un jeton n'est pas accepté une seconde fois automatiquement.
func TestPairDeclaredNodeIsAutoAcceptedOnlyOnce(t *testing.T) {
	f := newPairFixture(t)
	declareAutoAccept(t, f.db, "agent", "agent-a")
	if r := f.pair("agent", "agent-a", ""); r.code != http.StatusOK {
		t.Fatalf("première fois : %+v", r)
	}
	var n int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM tokens WHERE node_name='agent-a' AND revoked=0`).Scan(&n)
	if r := f.pair("agent", "agent-a", ""); r.code == http.StatusOK {
		t.Fatalf("seconde fois sans jeton : %+v", r)
	}
	var after int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM tokens WHERE node_name='agent-a' AND revoked=0`).Scan(&after)
	if after != n {
		t.Fatalf("aucun second jeton ne doit être émis : %d → %d", n, after)
	}
}

// Un jeton approuvé par l'opérateur est remis une fois ; ensuite la même demande attend une nouvelle approbation.
func TestPairApprovedTokenIsDeliveredOnce(t *testing.T) {
	f := newPairFixture(t)
	if r := f.pair("agent", "agent-b", ""); r.code != http.StatusAccepted || r.status != "pending" {
		t.Fatalf("nœud inconnu : %+v", r)
	}
	f.accept("agent", "agent-b")

	got := f.pair("agent", "agent-b", "")
	if got.code != http.StatusOK || got.token == "" {
		t.Fatalf("le nœud approuvé reçoit son jeton : %+v", got)
	}
	// Quelqu'un d'autre redemande : le jeton n'est plus rendu.
	again := f.pair("agent", "agent-b", "")
	if again.token != "" || again.code != http.StatusAccepted {
		t.Fatalf("le jeton n'est remis qu'une fois : %+v", again)
	}
	// Le nœud, qui a son jeton, le retrouve en le présentant.
	if r := f.pair("agent", "agent-b", got.token); r.code != http.StatusOK || r.token != got.token {
		t.Fatalf("avec son jeton : %+v", r)
	}
}

// Le jeton de l'état « accepté » ne se lit pas non plus par /pair/status une seconde fois.
func TestPairStatusDeliversTheTokenOnce(t *testing.T) {
	f := newPairFixture(t)
	r := f.pair("agent", "agent-c", "")
	if r.code != http.StatusAccepted {
		t.Fatalf("%+v", r)
	}
	var pendingID string
	_ = f.db.QueryRow(`SELECT id FROM pending_nodes WHERE node_name='agent-c'`).Scan(&pendingID)
	f.accept("agent", "agent-c")

	status := func() (int, string) {
		req := httptest.NewRequest(http.MethodGet, "/internal/v1/pair/status?pending_id="+pendingID, nil)
		rec := httptest.NewRecorder()
		f.s.handlePairStatus(rec, req)
		var b struct{ Token string }
		_ = json.Unmarshal(rec.Body.Bytes(), &b)
		return rec.Code, b.Token
	}
	if code, tok := status(); code != http.StatusOK || tok == "" {
		t.Fatalf("première lecture : %d %q", code, tok)
	}
	if code, tok := status(); code != http.StatusGone || tok != "" {
		t.Fatalf("seconde lecture : %d %q", code, tok)
	}
}

func createTicket(t *testing.T, db *sql.DB, token string, names []string, ttl time.Duration) {
	t.Helper()
	if _, err := db.Exec(`CREATE TABLE IF NOT EXISTS bootstrap_tickets (
		token TEXT PRIMARY KEY, host_name TEXT NOT NULL DEFAULT '', edge_endpoint TEXT NOT NULL DEFAULT '',
		payload TEXT NOT NULL DEFAULT '{}', expires_at DATETIME NOT NULL, created_at DATETIME NOT NULL DEFAULT CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	payload, _ := json.Marshal(map[string]any{"auto_accept": true, "node_names": names})
	if _, err := db.Exec(`INSERT INTO bootstrap_tickets (token, payload, expires_at) VALUES (?, ?, ?)`,
		token, string(payload), sqltime.Format(time.Now().Add(ttl))); err != nil {
		t.Fatal(err)
	}
}

// Un ticket couvre les noms qu'il liste et sert une fois par nom.
func TestPairTicketIsBoundToItsNamesAndServesOnce(t *testing.T) {
	f := newPairFixture(t)
	createTicket(t, f.db, "tk1", []string{"agent-t1", "agent-t2"}, time.Hour)

	if r := f.pair("agent", "agent-autre", ""); r.code != http.StatusAccepted {
		t.Fatalf("un nom hors du ticket attend l'approbation : %+v", r)
	}
	t1 := f.pair("agent", "agent-t1", "")
	if t1.code != http.StatusOK || t1.token == "" {
		t.Fatalf("un nom du ticket est accepté : %+v", t1)
	}
	// Le ticket a servi pour ce nom : un nœud qui reprend ce nom sans jeton n'est plus accepté.
	if _, err := f.db.Exec(`UPDATE tokens SET revoked=1 WHERE node_name='agent-t1'`); err != nil {
		t.Fatal(err)
	}
	if r := f.pair("agent", "agent-t1", ""); r.code != http.StatusAccepted {
		t.Fatalf("le ticket ne sert qu'une fois pour un nom : %+v", r)
	}
	// L'autre nom du ticket reste utilisable, puis le ticket disparaît.
	if r := f.pair("agent", "agent-t2", ""); r.code != http.StatusOK {
		t.Fatalf("le second nom du ticket : %+v", r)
	}
	var left int
	_ = f.db.QueryRow(`SELECT COUNT(*) FROM bootstrap_tickets WHERE token='tk1'`).Scan(&left)
	if left != 0 {
		t.Fatal("un ticket dont tous les noms ont servi est supprimé")
	}
}

// Un ticket expiré n'accepte plus rien.
func TestPairExpiredTicketAcceptsNothing(t *testing.T) {
	f := newPairFixture(t)
	createTicket(t, f.db, "tk2", []string{"agent-e"}, -time.Hour)
	if r := f.pair("agent", "agent-e", ""); r.code != http.StatusAccepted {
		t.Fatalf("%+v", r)
	}
}
