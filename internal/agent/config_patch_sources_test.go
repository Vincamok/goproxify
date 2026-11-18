package agent

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Une source ajoutée (`sources.<type>`) garde son secret quand la fenêtre de configuration renvoie le masque ou une
// valeur vide : c'est le cas de chaque enregistrement après le premier.
func TestApplyConfigPatch_SourceSecretIsKept(t *testing.T) {
	p := filepath.Join(t.TempDir(), "agent.json")
	base := `{"portainer":{"enabled":true,"api_key":"ptr_real"},"sources":{"arcane":{"enabled":true,"url":"https://arcane.example.com","api_key":"arc_real","skip_environments":["a"]}}}`
	if err := os.WriteFile(p, []byte(base), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, masked := range []string{"••••••••", ""} {
		patch := `{"portainer":{"enabled":true,"api_key":"` + masked + `"},"sources":{"arcane":{"enabled":true,"url":"https://arcane.example.com/","api_key":"` + masked + `","poll_interval_s":60,"skip_environments":["b"]}}}`
		if err := applyConfigPatch(p, []byte(patch)); err != nil {
			t.Fatal(err)
		}
		var got struct {
			Portainer struct {
				APIKey string `json:"api_key"`
			} `json:"portainer"`
			Sources struct {
				Arcane struct {
					URL    string   `json:"url"`
					APIKey string   `json:"api_key"`
					Poll   int      `json:"poll_interval_s"`
					Skip   []string `json:"skip_environments"`
				} `json:"arcane"`
			} `json:"sources"`
		}
		b, _ := os.ReadFile(p)
		if err := json.Unmarshal(b, &got); err != nil {
			t.Fatal(err)
		}
		if got.Portainer.APIKey != "ptr_real" || got.Sources.Arcane.APIKey != "arc_real" {
			t.Fatalf("secret écrasé avec %q : portainer=%q arcane=%q", masked, got.Portainer.APIKey, got.Sources.Arcane.APIKey)
		}
		if got.Sources.Arcane.URL != "https://arcane.example.com/" || got.Sources.Arcane.Poll != 60 || len(got.Sources.Arcane.Skip) != 1 || got.Sources.Arcane.Skip[0] != "b" {
			t.Fatalf("les autres champs doivent être mis à jour : %+v", got.Sources.Arcane)
		}
	}

	// Une clé réellement saisie remplace l'ancienne.
	if err := applyConfigPatch(p, []byte(`{"sources":{"arcane":{"api_key":"arc_new"}}}`)); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(p)
	var m map[string]map[string]map[string]any
	_ = json.Unmarshal(b, &m)
	if m["sources"]["arcane"]["api_key"] != "arc_new" {
		t.Errorf("clé saisie ignorée : %v", m["sources"]["arcane"])
	}
}
