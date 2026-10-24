// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package pairing

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestAgentKeyIsStableDistinctAndOneWay(t *testing.T) {
	root := "le-secret-racine-0123456789"
	k := AgentKey(root)
	if k == "" || k == root || len(k) != 64 {
		t.Fatalf("clé dérivée invalide : %q", k)
	}
	if k != AgentKey(root) {
		t.Fatal("la dérivation doit être stable")
	}
	if AgentKey(root+"x") == k {
		t.Fatal("deux secrets distincts donnent la même clé")
	}
	if AgentKey("") != "" {
		t.Fatal("un secret vide ne dérive rien")
	}
}

func TestServerAcceptsAgentKeysAndOptionallyRoot(t *testing.T) {
	root := "le-secret-racine-0123456789"
	roots := []Key{{Value: root}}
	keys := AgentKeysFromRoots(roots)
	if ok, viaRoot, _ := ServerAcceptsAgentKeys(keys, roots, AgentKey(root)); !ok || viaRoot {
		t.Fatalf("la clé dérivée doit être acceptée sans passer par la racine : ok=%v viaRoot=%v", ok, viaRoot)
	}
	if ok, viaRoot, _ := ServerAcceptsAgentKeys(keys, roots, root); !ok || !viaRoot {
		t.Fatalf("le secret racine reste accepté (migration) : ok=%v viaRoot=%v", ok, viaRoot)
	}
	t.Setenv("GPX_AGENT_PAIRING_ROOT", "false")
	if ok, _, _ := ServerAcceptsAgentKeys(keys, roots, root); ok {
		t.Fatal("GPX_AGENT_PAIRING_ROOT=false doit refuser le secret racine d'un Agent")
	}
	if ok, _, _ := ServerAcceptsAgentKeys(keys, roots, AgentKey(root)); !ok {
		t.Fatal("la clé dérivée doit rester acceptée")
	}
	if ok, _, _ := ServerAcceptsAgentKeys(keys, roots, ""); ok {
		t.Fatal("un secret vide ne doit jamais être accepté")
	}
	if ok, _, _ := ServerAcceptsAgentKeys(nil, nil, ""); ok {
		t.Fatal("un serveur sans secret n'accepte rien")
	}
}

func TestAgentAcceptsDerivedAndOwnCredential(t *testing.T) {
	root := "le-secret-racine-0123456789"
	key := AgentKey(root)
	legacy := AgentAccepts(root) // Agent qui détient encore la racine
	if legacy[0] != root || legacy[1] != key {
		t.Fatalf("Agent historique : %v", legacy)
	}
	modern := AgentAccepts(key)
	if modern[0] != key {
		t.Fatalf("Agent migré : %v", modern)
	}
}

func TestEdgeChannelKeyIsPerNodeStableAndOneWay(t *testing.T) {
	root := "le-secret-racine-0123456789"
	k := EdgeChannelKey(root, "frontal")
	if k == "" || k == root || len(k) != 64 || k != EdgeChannelKey(root, "frontal") {
		t.Fatalf("clé de canal invalide ou instable : %q", k)
	}
	if k == EdgeChannelKey(root, "backup") {
		t.Fatal("deux passerelles ne partagent pas la même clé : l'une ne peut pas se faire passer pour l'Admin auprès de l'autre")
	}
	if k == AgentKey(root) {
		t.Fatal("la clé de canal et la clé des Agents sont distinctes")
	}
	if EdgeChannelKey("", "frontal") != "" || EdgeChannelKey(root, "") != "" {
		t.Fatal("sans secret ou sans nom, rien n'est dérivé")
	}
}

func TestEdgeSecretsWithoutTheRoot(t *testing.T) {
	root := "le-secret-racine-0123456789"
	t.Setenv("GPX_PAIRING_SECRET", "")
	t.Setenv("GPX_EDGE_CHANNEL_KEY", EdgeChannelKey(root, "dn_frontal"))
	t.Setenv("GPX_AGENT_PAIRING_KEY", AgentKey(root))

	if got := EdgeAdminKeys(); len(got) != 1 || got[0].Value != EdgeChannelKey(root, "dn_frontal") || got[0].Previous {
		t.Fatalf("seule la clé dérivée vérifie l'Admin : %v", got)
	}
	if EdgeAgentKey() != AgentKey(root) {
		t.Fatal("la clé des Agents vient de GPX_AGENT_PAIRING_KEY, sans la racine")
	}
	if ok, viaRoot, _ := ServerAcceptsAgentKeys(EdgeAgentKeys(), RootKeys(), AgentKey(root)); !ok || viaRoot {
		t.Fatal("un Agent s'appaire avec la clé dérivée")
	}
	if ok, _, _ := ServerAcceptsAgentKeys(EdgeAgentKeys(), RootKeys(), root); ok {
		t.Fatal("sans la racine, la passerelle ne peut pas l'accepter d'un Agent")
	}

	// Installation non migrée : la racine seule fait tout, comme avant.
	t.Setenv("GPX_EDGE_CHANNEL_KEY", "")
	t.Setenv("GPX_AGENT_PAIRING_KEY", "")
	t.Setenv("GPX_PAIRING_SECRET", root)
	if got := EdgeAdminKeys(); len(got) != 1 || got[0].Value != root {
		t.Fatalf("la racine vérifie encore l'Admin : %v", got)
	}
	if EdgeAgentKey() != AgentKey(root) {
		t.Fatal("la clé des Agents se dérive de la racine")
	}
}

func TestSecretReadsAnEnvVarOrAFileReReadEachTime(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, []byte("valeur-1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("GPX_TEST_SECRET", "")
	t.Setenv("GPX_TEST_SECRET_FILE", path)
	if got := Secret("GPX_TEST_SECRET"); got != "valeur-1" {
		t.Fatalf("fichier lu, espaces retirés : %q", got)
	}
	if err := os.WriteFile(path, []byte("valeur-2"), 0o600); err != nil {
		t.Fatal(err)
	}
	if got := Secret("GPX_TEST_SECRET"); got != "valeur-2" {
		t.Fatalf("une valeur changée sur disque est prise en compte sans redémarrage : %q", got)
	}
	t.Setenv("GPX_TEST_SECRET", "variable")
	if got := Secret("GPX_TEST_SECRET"); got != "variable" {
		t.Fatalf("la variable prime sur le fichier : %q", got)
	}
	t.Setenv("GPX_TEST_SECRET", "")
	t.Setenv("GPX_TEST_SECRET_FILE", filepath.Join(t.TempDir(), "absent"))
	if got := Secret("GPX_TEST_SECRET"); got != "" {
		t.Fatalf("un fichier illisible ne donne rien : %q", got)
	}
}

func TestKeysListCurrentThenPreviousWithoutDuplicates(t *testing.T) {
	t.Setenv("GPX_TEST_KEY", "nouveau")
	t.Setenv("GPX_TEST_KEY_PREVIOUS", "ancien1, ancien2\nnouveau")
	keys := Keys("GPX_TEST_KEY")
	if len(keys) != 3 || keys[0] != (Key{Value: "nouveau"}) || keys[1] != (Key{Value: "ancien1", Previous: true}) || keys[2] != (Key{Value: "ancien2", Previous: true}) {
		t.Fatalf("clés : %+v", keys)
	}
	if Current(keys) != "nouveau" {
		t.Fatal("la valeur courante est la première")
	}
	// Seule une valeur précédente : elle reste marquée, il n'y a pas de courante.
	t.Setenv("GPX_TEST_KEY", "")
	if got := Keys("GPX_TEST_KEY"); len(got) != 3 || !got[0].Previous || Current(got) != "" {
		t.Fatalf("sans courante : %+v", got)
	}
}

// Pendant une rotation, une passerelle accepte la clé de canal et la clé des Agents courantes et précédentes, et le dit.
func TestRotationAcceptsPreviousKeysAndFlagsThem(t *testing.T) {
	oldRoot, newRoot := "ancien-secret-racine-0123456789", "nouveau-secret-racine-0123456789"
	t.Setenv("GPX_PAIRING_SECRET", "")
	t.Setenv("GPX_EDGE_CHANNEL_KEY", EdgeChannelKey(newRoot, "dn_a"))
	t.Setenv("GPX_EDGE_CHANNEL_KEY_PREVIOUS", EdgeChannelKey(oldRoot, "dn_a"))
	t.Setenv("GPX_AGENT_PAIRING_KEY", AgentKey(newRoot))
	t.Setenv("GPX_AGENT_PAIRING_KEY_PREVIOUS", AgentKey(oldRoot))

	keys := EdgeAdminKeys()
	if len(keys) != 2 || keys[0].Previous || !keys[1].Previous {
		t.Fatalf("clés de canal : %+v", keys)
	}
	ok, _, previous := ServerAcceptsAgentKeys(EdgeAgentKeys(), RootKeys(), AgentKey(newRoot))
	if !ok || previous {
		t.Fatal("la clé courante des Agents n'est pas une clé précédente")
	}
	ok, _, previous = ServerAcceptsAgentKeys(EdgeAgentKeys(), RootKeys(), AgentKey(oldRoot))
	if !ok || !previous {
		t.Fatal("la clé précédente des Agents est acceptée et signalée")
	}
	if ok, _, _ := ServerAcceptsAgentKeys(EdgeAgentKeys(), RootKeys(), AgentKey("autre")); ok {
		t.Fatal("une autre clé est refusée")
	}
	if EdgeAgentKey() != AgentKey(newRoot) {
		t.Fatal("la passerelle envoie la clé courante aux Agents")
	}
}

// Un Agent accepte en Bearer sa clé courante et les précédentes, et leurs dérivées.
func TestAgentBearersIncludePreviousCredentials(t *testing.T) {
	t.Setenv("GPX_PAIRING_SECRET", "")
	t.Setenv("GPX_AGENT_PAIRING_KEY", "cle-nouvelle")
	t.Setenv("GPX_AGENT_PAIRING_KEY_PREVIOUS", "cle-ancienne")
	got := AgentBearers()
	want := map[string]bool{"cle-nouvelle": true, "cle-ancienne": true, AgentKey("cle-nouvelle"): true, AgentKey("cle-ancienne"): true}
	for _, b := range got {
		delete(want, b)
	}
	if len(want) != 0 {
		t.Fatalf("Bearer manquants %v dans %v", want, got)
	}
}

// Une date de fin met fin au recouvrement toute seule ; une date illisible aussi (on ne sait pas jusqu'à quand accepter).
func TestPreviousValuesExpireAtTheirDate(t *testing.T) {
	t.Setenv("GPX_TEST_EXP", "nouveau")
	t.Setenv("GPX_TEST_EXP_PREVIOUS", "ancien")
	if got := Previous("GPX_TEST_EXP"); len(got) != 1 {
		t.Fatalf("sans date, les précédentes restent : %v", got)
	}
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	t.Setenv("GPX_TEST_EXP_PREVIOUS_UNTIL", future)
	if got := Previous("GPX_TEST_EXP"); len(got) != 1 {
		t.Fatalf("avant la date, elles sont acceptées : %v", got)
	}
	past := time.Now().Add(-time.Minute).UTC().Format(time.RFC3339)
	t.Setenv("GPX_TEST_EXP_PREVIOUS_UNTIL", past)
	if got := Previous("GPX_TEST_EXP"); len(got) != 0 {
		t.Fatalf("après la date, elles ne le sont plus : %v", got)
	}
	if keys := Keys("GPX_TEST_EXP"); len(keys) != 1 || keys[0].Value != "nouveau" {
		t.Fatalf("seule la valeur courante reste : %+v", keys)
	}
	t.Setenv("GPX_TEST_EXP_PREVIOUS_UNTIL", "demain")
	if got := Previous("GPX_TEST_EXP"); len(got) != 0 {
		t.Fatalf("une date illisible supprime le recouvrement : %v", got)
	}
}

// Le chart Helm et le démarrage rapide calculent ces clés en shell et en gabarit : ces valeurs de référence les verrouillent.
func TestDerivedKeysMatchTheShellAndHelmRecipes(t *testing.T) {
	if got := EdgeChannelKey("RACINE", "dn_a"); got != "bb982005d9a83516b03d4789293127b88eb08a34fe24c8028fdc85127557fead" {
		t.Fatalf("clé de canal : %s", got)
	}
	if got := AgentKey("RACINE"); got != "1a5365b26924537f5c7af911011c7d17229b4ff4466972881ca2672b2e7b6ce3" {
		t.Fatalf("clé des Agents : %s", got)
	}
}
