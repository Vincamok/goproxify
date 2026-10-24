package automation

import (
	"context"
	"testing"
	"time"
)

// La condition « taux d'erreur d'un proxy » est évaluée sur les cumuls par minute que les passerelles envoient.
func TestProxyErrorRateFromTheMinuteAggregates(t *testing.T) {
	e := newEnv(t)
	ctx := context.Background()
	d := e.s.db
	for _, p := range []struct{ id, name, domain string }{{"p1", "api", "api.acme.fr"}, {"p2", "web", "web.acme.fr"}} {
		if _, err := d.Exec(`INSERT INTO proxies (id, name, config, enabled) VALUES (?, ?, ?, 1)`, p.id, p.name, `{"domain":"`+p.domain+`"}`); err != nil {
			t.Fatal(err)
		}
	}
	ins := func(domain string, status, n int, ago time.Duration) {
		if _, err := d.Exec(`INSERT INTO logs_minute (minute, domain, node_name, status, requests) VALUES (?, ?, 'gw-a', ?, ?)
			ON CONFLICT (minute, node_name, domain, status) DO UPDATE SET requests = requests + excluded.requests`,
			time.Now().Add(-ago).UTC().Format("2006-01-02T15:04"), domain, status, n); err != nil {
			t.Fatal(err)
		}
	}
	ins("api.acme.fr", 502, 15, 2*time.Minute) // 50 % de 5xx : le pire
	ins("api.acme.fr", 200, 15, 2*time.Minute)
	ins("web.acme.fr", 503, 3, 2*time.Minute) // 10 % : sous le seuil
	ins("web.acme.fr", 200, 27, 2*time.Minute)
	ins("api.acme.fr", 502, 500, 40*time.Minute) // hors fenêtre

	cfg := map[string]any{"error_rate_window": "5m", "error_rate_threshold": float64(20)}
	ok, detail, err := evalProxyErrorRate(ctx, e.s, cfg)
	if err != nil || !ok || detail["proxy_id"] != "p1" || detail["error_rate"] != 50.0 {
		t.Fatalf("%v %v %v, attendu api à 50 %%", ok, detail, err)
	}

	// Un seuil plus haut que le pire proxy ne déclenche rien.
	cfg["error_rate_threshold"] = float64(60)
	if ok, _, _ := evalProxyErrorRate(ctx, e.s, cfg); ok {
		t.Fatal("un seuil de 60 % ne doit pas se déclencher à 50 %")
	}
}
