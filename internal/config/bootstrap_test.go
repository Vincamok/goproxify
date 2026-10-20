// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// edgeIdentity lit juste la section identity d'une passerelle.json pour les assertions.
func edgeIdentity(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	identity, _ := doc["identity"].(map[string]any)
	if identity == nil {
		t.Fatalf("section identity absente de %s", path)
	}
	return identity
}

// TestBootstrapEdgeIdempotent vérifie que BootstrapEdge ne touche plus au
// fichier une fois qu'il existe — c'est la garantie de stabilité de
// l'identité (node_name, token_id) entre deux démarrages du même
// conteneur sur le même volume.
func TestBootstrapEdgeIdempotent(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edge.json")

	t.Setenv("GPX_IDENTITY_EDGE_NODE_NAME", "frontal")
	if err := BootstrapEdge(path); err != nil {
		t.Fatalf("premier bootstrap : %v", err)
	}
	id1 := edgeIdentity(t, path)
	tokenID1, _ := id1["token_id"].(string)
	if tokenID1 == "" {
		t.Fatal("token_id vide après le premier bootstrap")
	}
	if id1["node_name"] != "frontal" {
		t.Fatalf("node_name = %v, attendu frontal", id1["node_name"])
	}

	// Deuxième "démarrage" avec une variable d'environnement différente —
	// reproduit un redéploiement Portainer où EDGE_NODE_NAME a changé.
	t.Setenv("GPX_IDENTITY_EDGE_NODE_NAME", "goproxify-edge")
	if err := BootstrapEdge(path); err != nil {
		t.Fatalf("second bootstrap : %v", err)
	}
	id2 := edgeIdentity(t, path)
	if id2["token_id"] != tokenID1 {
		t.Fatalf("token_id a changé entre deux démarrages : %v -> %v", tokenID1, id2["token_id"])
	}
	if id2["node_name"] != "frontal" {
		t.Fatalf("node_name a changé alors que le fichier existait déjà : %v (attendu frontal, inchangé malgré la nouvelle env var)", id2["node_name"])
	}
}

// TestLoadEdgeNodeNameStableAcrossEnvChange vérifie que LoadEdge ignore
// GPX_IDENTITY_EDGE_NODE_NAME une fois identity.node_name déjà présent
// dans le fichier — c'est la valeur écrite au tout premier bootstrap qui
// fait foi, pas la variable d'environnement du redémarrage courant.
func TestLoadEdgeNodeNameStableAcrossEnvChange(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edge.json")

	t.Setenv("GPX_IDENTITY_EDGE_NODE_NAME", "frontal")
	if err := BootstrapEdge(path); err != nil {
		t.Fatal(err)
	}

	// Le redémarrage suivant arrive avec une valeur différente de la variable.
	t.Setenv("GPX_IDENTITY_EDGE_NODE_NAME", "proxify-edge")
	cfg, err := LoadEdge(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Identity.NodeName != "frontal" {
		t.Fatalf("node_name chargé = %q, attendu frontal (celui du fichier, pas de la nouvelle env var)", cfg.Identity.NodeName)
	}
}

// TestBootstrapAdminSQLiteDSNMatchesHistoricalPath verrouille le chemin de la
// base SQLite générée par BootstrapAdmin : il doit rester exactement celui du
// template services/admin/config.json qui équipait les images jusqu'à
// d25555a (/etc/goproxify/database/goproxify.db). Une régression ici ferait
// pointer un déploiement existant vers une base neuve et vide au premier
// vrai bootstrap, laissant toutes les données (domaines, certs, config ACME,
// utilisateurs…) orphelines sur le volume sans qu'elles soient supprimées ni
// visibles dans l'UI — symptôme observé : "Domaines & certificats" vide.
func TestBootstrapAdminSQLiteDSNMatchesHistoricalPath(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GPX_STORAGE_BASE_PATH", dir)
	path := filepath.Join(dir, "admin.json")
	if err := BootstrapAdmin(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadAdmin(path)
	if err != nil {
		t.Fatal(err)
	}
	want := filepath.Join(dir, "database", "goproxify.db")
	if cfg.Storage.SQLiteDSN != want {
		t.Fatalf("sqlite_dsn = %q, attendu %q (chemin historique)", cfg.Storage.SQLiteDSN, want)
	}
}

// TestBootstrapEdgeLogPathsMatchHistoricalPaths verrouille les chemins de
// logs générés par BootstrapEdge face au même risque de divergence
// silencieuse (fichiers différents du nom historique, logs éparpillés entre
// ancien et nouveau fichier sur le même volume).
func TestBootstrapEdgeLogPathsMatchHistoricalPaths(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GPX_STORAGE_BASE_PATH", dir)
	path := filepath.Join(dir, "edge.json")
	if err := BootstrapEdge(path); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadEdge(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "logs"); cfg.Engine.LogStoreDir != want {
		t.Fatalf("log_store_dir = %q, attendu %q", cfg.Engine.LogStoreDir, want)
	}
	if want := filepath.Join(dir, "logs", "edge_system.log"); cfg.Engine.SystemLogPath != want {
		t.Fatalf("system_log_path = %q, attendu %q", cfg.Engine.SystemLogPath, want)
	}
}

// TestBootstrapEdgeTokenIDStableAcrossManyRestarts simule plusieurs
// redémarrages consécutifs (le scénario réel : le conteneur redémarre
// plusieurs fois) et vérifie que token_id et node_name ne bougent jamais
// une fois le fichier créé.
func TestBootstrapEdgeTokenIDStableAcrossManyRestarts(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edge.json")

	t.Setenv("GPX_IDENTITY_EDGE_NODE_NAME", "frontal")
	if err := BootstrapEdge(path); err != nil {
		t.Fatal(err)
	}
	want := edgeIdentity(t, path)

	for i := 0; i < 5; i++ {
		if err := BootstrapEdge(path); err != nil {
			t.Fatalf("redémarrage %d : %v", i, err)
		}
		got := edgeIdentity(t, path)
		if got["token_id"] != want["token_id"] || got["node_name"] != want["node_name"] {
			t.Fatalf("redémarrage %d : identité changée, got=%v want=%v", i, got, want)
		}
	}
}

func readDoc(t *testing.T, path string) map[string]any {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatal(err)
	}
	return doc
}

// Les variables que posent le chart Helm et la documentation sont lues : GPX_JWT_SECRET (alias), GPX_SERVER_LISTEN_ADDR.
func TestBootstrapAdminHonoursDocumentedEnv(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.json")
	t.Setenv("GPX_SECURITY_JWT_SECRET", "")
	t.Setenv("GPX_JWT_SECRET", "secret-du-chart")
	t.Setenv("GPX_SERVER_LISTEN_ADDR", "127.0.0.1")
	if err := BootstrapAdmin(path); err != nil {
		t.Fatal(err)
	}
	doc := readDoc(t, path)
	if got := doc["security"].(map[string]any)["jwt_secret"]; got != "secret-du-chart" {
		t.Errorf("jwt_secret = %v", got)
	}
	if got := doc["server"].(map[string]any)["listen_addr"]; got != "127.0.0.1" {
		t.Errorf("listen_addr = %v", got)
	}

	// GPX_SECURITY_JWT_SECRET prime sur l'alias ; sans variable, l'adresse d'écoute reste 0.0.0.0.
	path2 := filepath.Join(t.TempDir(), "admin2.json")
	t.Setenv("GPX_SECURITY_JWT_SECRET", "officiel")
	t.Setenv("GPX_SERVER_LISTEN_ADDR", "")
	if err := BootstrapAdmin(path2); err != nil {
		t.Fatal(err)
	}
	doc = readDoc(t, path2)
	if doc["security"].(map[string]any)["jwt_secret"] != "officiel" || doc["server"].(map[string]any)["listen_addr"] != "0.0.0.0" {
		t.Errorf("priorité ou défaut inattendus : %v", doc)
	}
}

// La découverte Kubernetes s'active par GPX_KUBERNETES_ENABLED (chart Helm), à la création comme à la migration.
func TestBootstrapAgentHonoursKubernetesEnv(t *testing.T) {
	t.Setenv("GPX_KUBERNETES_ENABLED", "true")
	t.Setenv("GPX_KUBERNETES_NAMESPACE", "prod")
	path := filepath.Join(t.TempDir(), "agent.json")
	if err := BootstrapAgent(path); err != nil {
		t.Fatal(err)
	}
	k := readDoc(t, path)["kubernetes"].(map[string]any)
	if k["enabled"] != true || k["namespace"] != "prod" {
		t.Errorf("kubernetes = %v", k)
	}

	// Un agent.json existant sans section kubernetes la reçoit (mise à jour transparente).
	old := filepath.Join(t.TempDir(), "old.json")
	if err := os.WriteFile(old, []byte(`{"docker":{"enabled":true},"portainer":{"enabled":false}}`), 0o640); err != nil {
		t.Fatal(err)
	}
	if err := BootstrapAgent(old); err != nil {
		t.Fatal(err)
	}
	if k := readDoc(t, old)["kubernetes"].(map[string]any); k["enabled"] != true {
		t.Errorf("migration : kubernetes = %v", k)
	}

	// Sans variable, rien n'est ajouté à un fichier existant.
	t.Setenv("GPX_KUBERNETES_ENABLED", "")
	same := filepath.Join(t.TempDir(), "same.json")
	_ = os.WriteFile(same, []byte(`{"docker":{"enabled":true},"portainer":{"enabled":false}}`), 0o640)
	if err := BootstrapAgent(same); err != nil {
		t.Fatal(err)
	}
	if _, ok := readDoc(t, same)["kubernetes"]; ok {
		t.Error("sans GPX_KUBERNETES_ENABLED, le fichier existant reste intact")
	}
}
