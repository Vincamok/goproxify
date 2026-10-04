package importer

import (
	"encoding/json"
	"runtime"
	"runtime/debug"
	"testing"
	"time"
)

func peakHeap(fn func()) uint64 {
	// Ramasse-miettes agressif : on veut la mémoire réellement retenue, pas les déchets en attente de balayage.
	old := debug.SetGCPercent(5)
	defer debug.SetGCPercent(old)
	runtime.GC()
	var base runtime.MemStats
	runtime.ReadMemStats(&base)
	var max uint64
	stop, done := make(chan struct{}), make(chan struct{})
	go func() {
		defer close(done)
		var m runtime.MemStats
		for {
			runtime.ReadMemStats(&m)
			if m.HeapAlloc > max {
				max = m.HeapAlloc
			}
			select {
			case <-stop:
				return
			case <-time.After(2 * time.Millisecond):
			}
		}
	}()
	fn()
	close(stop)
	<-done
	if max < base.HeapAlloc {
		return 0
	}
	return max - base.HeapAlloc
}

// Ouvrir la fenêtre « Restaurer » ne doit pas décoder le contenu des sections chiffrées.
func TestStreamingSummaryUsesLessMemoryThanFullDecode(t *testing.T) {
	files := map[string][]byte{}
	for i := 0; i < 6; i++ {
		b := make([]byte, 5<<20)
		for j := range b {
			b[j] = byte(j*3 + i)
		}
		files["gateway/gw/f"+string(rune('a'+i))+".bin"] = b
	}
	plain, _ := json.Marshal(SecretBundle{Files: files})

	var streamed *SecretsSummary
	newPeak := peakHeap(func() { streamed, _ = summarizeSecretsPlain(plain) })
	oldPeak := peakHeap(func() {
		var sb SecretBundle
		json.Unmarshal(plain, &sb) //nolint:errcheck
		_ = len(sb.Files)
	})
	t.Logf("section de %d Mo : pic de %d Mo en flux contre %d Mo en décodage complet", len(plain)>>20, newPeak>>20, oldPeak>>20)
	if streamed == nil || streamed.Files != 6 {
		t.Fatalf("résumé : %+v", streamed)
	}
	if newPeak*3 > oldPeak {
		t.Fatalf("le résumé en flux (%d Mo) n'est pas nettement plus léger que le décodage complet (%d Mo)", newPeak>>20, oldPeak>>20)
	}
}
