package logthrottle

import (
	"testing"
	"time"
)

func TestLimiterGroupsRepeats(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(time.Minute)
	l.now = func() time.Time { return now }

	if ok, n := l.Allow("ban|1.2.3.4"); !ok || n != 0 {
		t.Fatalf("première occurrence : ok=%v n=%d", ok, n)
	}
	for i := 0; i < 5; i++ {
		if ok, _ := l.Allow("ban|1.2.3.4"); ok {
			t.Fatal("répétition dans la fenêtre journalisée")
		}
	}
	if ok, _ := l.Allow("ban|5.6.7.8"); !ok {
		t.Fatal("une autre IP doit être journalisée")
	}
	if ok, _ := l.Allow("profil|1.2.3.4"); !ok {
		t.Fatal("un autre motif pour la même IP doit être journalisé")
	}

	now = now.Add(61 * time.Second)
	ok, n := l.Allow("ban|1.2.3.4")
	if !ok || n != 5 {
		t.Fatalf("après la fenêtre : ok=%v n=%d, attendu true et 5", ok, n)
	}
}

func TestLimiterBoundedMemory(t *testing.T) {
	now := time.Unix(1000, 0)
	l := New(time.Minute)
	l.now = func() time.Time { return now }
	for i := 0; i < MaxKeys+100; i++ {
		l.Allow("ban|" + time.Duration(i).String())
	}
	if len(l.seen) > MaxKeys {
		t.Fatalf("table de %d entrées, bornée à %d", len(l.seen), MaxKeys)
	}
	if ok, _ := l.Allow("ban|nouvelle"); !ok {
		t.Fatal("table pleine : l'événement doit être journalisé sans regroupement")
	}
}

func TestNilLimiterLogsEverything(t *testing.T) {
	var l *Limiter
	if ok, _ := l.Allow("x"); !ok {
		t.Fatal("limiteur nil : tout est journalisé")
	}
}
