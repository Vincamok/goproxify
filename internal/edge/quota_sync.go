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

const quotaSyncInterval = 2 * time.Second

// handleQuotaExport expose les comptes de quota partagés de cette passerelle à ses pairs.
func (s *Server) handleQuotaExport(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(middleware.ExportQuotas())
}

// startQuotaSyncLoop récupère les comptes des pairs tant qu'un quota `shared` est ouvert. Sans pair
// joignable chaque passerelle applique son compte local : le quota reste appliqué, sans l'Admin.
func (s *Server) startQuotaSyncLoop(ctx context.Context) {
	go func() {
		client := &http.Client{Timeout: time.Second}
		t := time.NewTicker(quotaSyncInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
			if !middleware.HasSharedQuotas() {
				continue
			}
			var wg sync.WaitGroup
			for _, p := range s.peers.All() {
				wg.Add(1)
				go func() {
					defer wg.Done()
					req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+"/internal/v1/ratelimit/export", nil)
					if err != nil {
						return
					}
					req.Header.Set("Authorization", "Bearer "+p.Token)
					resp, err := client.Do(req)
					if err != nil {
						return
					}
					defer resp.Body.Close()
					if resp.StatusCode != http.StatusOK {
						return
					}
					var entries []middleware.QuotaEntry
					if json.NewDecoder(io.LimitReader(resp.Body, 4<<20)).Decode(&entries) == nil {
						middleware.MergeQuotas(p.Name, entries)
					}
				}()
			}
			wg.Wait()
		}
	}()
}
