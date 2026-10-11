// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"runtime"
	"strings"
	"testing"
	"time"

	pt "github.com/vincamok/goproxify/internal/edge/plugins/plugintest"
)

// Modules WASM hostiles, assemblés à la main : chacun tente ce qu'un plugin malveillant ou défaillant ferait pour
// sortir de son bac à sable — lire hors de sa mémoire, épuiser la pile ou la mémoire de la passerelle, bloquer une
// requête. Aucun ne doit planter la passerelle : l'appel échoue proprement (la politique on_error s'applique) et
// l'appel suivant fonctionne.

func hostile(onRequest []byte, alloc []byte, memMin uint64) []byte {
	if alloc == nil {
		alloc = pt.I32(1024)
	}
	return pt.Spec{
		MemMin:    memMin,
		Funcs:     []pt.Fn{{Typ: 0, Body: alloc}, {Typ: 1, Body: onRequest}},
		ExportsFn: map[string]int{"alloc": 0, "on_request": 1},
	}.Build()
}

func mustFail(t *testing.T, name string, wasm []byte, wantInErr string) {
	t.Helper()
	m := manifest()
	m.Limits.TimeoutMs = 200
	p := load(t, m, wasm)
	start := time.Now()
	_, err := p.Call(context.Background(), HookRequest, RequestInput{Path: "/"})
	if err == nil {
		t.Errorf("%s : aucune erreur", name)
		return
	}
	if wantInErr != "" && !strings.Contains(err.Error(), wantInErr) {
		t.Errorf("%s : erreur %q, attendu qu'elle mentionne %q", name, err, wantInErr)
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("%s : l'appel a duré %v pour un plafond de 200 ms", name, d)
	}
	// L'appel suivant, sur le même plugin, doit se comporter de la même façon : pas d'état corrompu.
	if _, err := p.Call(context.Background(), HookRequest, RequestInput{Path: "/"}); err == nil {
		t.Errorf("%s : le second appel n'a pas échoué comme le premier", name)
	}
}

func TestHostile_MemoryAccessOutsideTheSandbox(t *testing.T) {
	// Sortie annoncée hors de la mémoire linéaire (deux pages = 128 Kio).
	mustFail(t, "adresse de sortie hors mémoire", hostile(pt.I64(int64(0x7fffff00)<<32|64), nil, 2), "hors de la mémoire")
	// Sortie dont la longueur dépasse la mémoire entière.
	mustFail(t, "longueur de sortie démesurée", hostile(pt.I64(int64(1024)<<32|0xfffffff0), nil, 2), "")
	// Sortie qui commence dans la mémoire mais en dépasse la fin.
	mustFail(t, "sortie à cheval sur la fin", hostile(pt.I64(int64(2*65536-8)<<32|64), nil, 2), "hors de la mémoire")
	// alloc qui rend une adresse où l'entrée ne tient pas : l'hôte ne doit pas écrire dehors.
	mustFail(t, "alloc hors mémoire", hostile(pt.I64(0), pt.I32(0x7ffffff0), 2), "hors mémoire")
	mustFail(t, "alloc à la dernière page", hostile(pt.I64(0), pt.I32(2*65536-4), 2), "hors mémoire")
}

func TestHostile_ExhaustingTheStack(t *testing.T) {
	// on_request s'appelle lui-même sans fin : la pile d'appels est bornée par le moteur, la passerelle survit.
	mustFail(t, "récursion infinie", hostile([]byte{0x20, 0x00, 0x20, 0x01, 0x10, 0x01}, nil, 2), "")
}

func TestHostile_GrowingMemoryIsCappedByTheManifest(t *testing.T) {
	// loop { memory.grow(16 pages) ; drop ; br 0 } : la mémoire ne dépasse jamais memory_pages, la boucle est
	// interrompue par le délai.
	grow := []byte{0x03, 0x40, 0x41, 0x10, 0x40, 0x00, 0x1a, 0x0c, 0x00, 0x0b, 0x42, 0x00}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	mustFail(t, "memory.grow sans fin", hostile(grow, nil, 2), "")
	runtime.GC()
	runtime.ReadMemStats(&after)
	// Plafond du manifeste de test : 16 pages = 1 Mio. Une marge large, mais loin des gigaoctets d'une boucle libre.
	if grew := int64(after.HeapAlloc) - int64(before.HeapAlloc); grew > 64<<20 {
		t.Errorf("le tas a grossi de %d Mio pendant un memory.grow sans fin", grew>>20)
	}
}

func TestHostile_LoopingStartFunctionIsBoundedByTheTimeout(t *testing.T) {
	// La section « start » d'un module s'exécute à chaque instanciation, donc à chaque appel. Elle ne doit jamais
	// s'exécuter au chargement (l'Admin charge chaque paquet dans le gestionnaire de la requête d'installation, sans
	// délai) ; à l'appel, le délai du manifeste l'interrompt.
	wasm := pt.Spec{
		MemMin:    2,
		Funcs:     []pt.Fn{{Typ: 0, Body: pt.I32(1024)}, {Typ: 1, Body: pt.I64(0)}, {Typ: 7, Body: []byte{0x03, 0x40, 0x0c, 0x00, 0x0b}}},
		ExportsFn: map[string]int{"alloc": 0, "on_request": 1},
		Start:     2,
		HasStart:  true,
	}.Build()
	m := manifest()
	m.Limits.TimeoutMs = 100
	done := make(chan error, 2)
	go func() {
		p, err := Load(context.Background(), m, wasm, "", nil)
		if err != nil {
			done <- err
			return
		}
		defer p.Close(context.Background())
		done <- nil
		_, err = p.Call(context.Background(), HookRequest, RequestInput{})
		done <- err
	}()
	for step, want := range []string{"chargement", "appel"} {
		select {
		case err := <-done:
			if step == 0 && err != nil {
				t.Fatalf("chargement : %v", err)
			}
			if step == 1 && err == nil {
				t.Fatal("un module dont le démarrage boucle ne doit pas répondre")
			}
		case <-time.After(5 * time.Second):
			t.Fatalf("%s : ne rend jamais la main", want)
		}
	}
}

func TestHostile_LogFloodIsBounded(t *testing.T) {
	// Un plugin qui journalise en boucle : le message conservé reste borné (1 Kio), pas un journal sans fond.
	logger, read := capturingLogger()
	m := manifest()
	m.Limits.TimeoutMs = 50
	p := loadWith(t, m, pt.Log(), logger)
	long := strings.Repeat("A", 200000)
	_, _ = p.Call(context.Background(), HookRequest, RequestInput{Path: "/" + long})
	if n := len(read()); n > 16<<10 {
		t.Errorf("%d octets de journal pour un seul appel", n)
	}
}

// http_allow_private ouvre le réseau interne, jamais le lien local ni les métadonnées du cloud : un manifeste qui
// nommerait 169.254.169.254 et demanderait les adresses privées n'y accéderait pas.
func TestHostile_AllowPrivateNeverOpensMetadata(t *testing.T) {
	client := SafeHTTPClient(2*time.Second, true)
	for _, u := range []string{
		"http://169.254.169.254/latest/meta-data/iam/security-credentials/",
		"http://[fe80::1]/",
		"http://[fd00:ec2::254]/",
		"http://100.100.100.200/latest/meta-data/",
		"http://224.0.0.1/",
	} {
		start := time.Now()
		resp, err := client.Get(u)
		if err == nil {
			resp.Body.Close()
			t.Errorf("%s : joignable avec http_allow_private", u)
			continue
		}
		if !strings.Contains(err.Error(), "refusée") {
			t.Errorf("%s : %v (attendu un refus de l'hôte, pas une erreur réseau)", u, err)
		}
		if time.Since(start) > time.Second {
			t.Errorf("%s : refus tardif (%v) : l'hôte a tenté la connexion", u, time.Since(start))
		}
	}
}
