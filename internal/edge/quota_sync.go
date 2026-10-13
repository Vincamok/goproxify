package edge

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/middleware"
)

const (
	// rateSyncInterval : cadence des échanges de débit instantané (rate_limit.shared) ; les comptes de quota, qui
	// tolèrent plus de retard, ne sont échangés qu'un tour sur quotaSyncEvery.
	rateSyncInterval = 500 * time.Millisecond
	quotaSyncEvery   = 4 // soit toutes les 2 s
)

// handleQuotaExport expose les comptes de quota partagés de cette passerelle à ses pairs.
func (s *Server) handleQuotaExport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(middleware.ExportQuotas())
}

// handleRateExport expose le débit instantané admis par cette passerelle pour les clés partagées. Route à part de
// l'export des quotas : une passerelle plus ancienne répond 404 et son pair l'ignore, au lieu de recevoir un
// format qu'elle ne sait pas lire.
func (s *Server) handleRateExport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(middleware.ExportRates())
}

// startQuotaSyncLoop récupère auprès des pairs les comptes de quota et les débits partagés tant qu'une limite
// `shared` est active. Sans pair joignable chaque passerelle applique ses propres valeurs : la limite reste
// appliquée, sans l'Admin.
func (s *Server) startQuotaSyncLoop(ctx context.Context) {
	go func() {
		client := &http.Client{Timeout: time.Second}
		t := time.NewTicker(rateSyncInterval)
		defer t.Stop()
		for tick := 0; ; tick++ {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			quotas := tick%quotaSyncEvery == 0 && middleware.HasSharedQuotas()
			rates := middleware.HasSharedRates()
			if !quotas && !rates {
				continue
			}
			var wg sync.WaitGroup
			for _, p := range s.peers.All() {
				if quotas {
					wg.Add(1)
					go func() {
						defer wg.Done()
						var entries []middleware.QuotaEntry
						if fetchPeerJSON(ctx, client, p.Endpoint+"/internal/v1/ratelimit/export", p.Token, &entries) {
							middleware.MergeQuotas(p.Name, entries)
						}
					}()
				}
				if rates {
					wg.Add(1)
					go func() {
						defer wg.Done()
						var entries []middleware.RateEntry
						if fetchPeerJSON(ctx, client, p.Endpoint+"/internal/v1/ratelimit/rates", p.Token, &entries) {
							middleware.MergeRates(p.Name, entries)
						}
					}()
				}
			}
			wg.Wait()
		}
	}()
}

// fetchPeerJSON lit un document JSON d'un pair ; false si le pair est injoignable ou répond autre chose que 200.
func fetchPeerJSON(ctx context.Context, client *http.Client, url, token string, out any) bool {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return false
	}
	return json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(out) == nil
}
