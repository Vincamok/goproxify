// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"sort"
	"time"
)

const (
	liveWindow      = 60 * time.Second
	liveMinRequests = 20 // en dessous, les taux sont du bruit : ils ne comptent pas dans le risque
)

// nodeLive est l'état temps réel d'un nœud pour la vue topologie.
type nodeLive struct {
	NodeName   string   `json:"node_name"`
	Role       string   `json:"role"`
	Status     string   `json:"status"`
	CPUPCT     *float64 `json:"cpu_pct,omitempty"`
	MemPCT     *float64 `json:"mem_pct,omitempty"`
	Requests   int      `json:"requests"`
	RPS        float64  `json:"rps"`
	BlockedPct float64  `json:"blocked_pct"` // part de 403/429 (refus de sécurité)
	ErrorPct   float64  `json:"error_pct"`   // part de 5xx
	LowTraffic bool     `json:"low_traffic"`
	Risk       int      `json:"risk"`        // 0-100 : le plus élevé des facteurs
	RiskLevel  string   `json:"risk_level"`  // low | medium | high
	RiskFactor string   `json:"risk_factor"` // offline | blocked | errors | resources | none
}

type topologyLive struct {
	WindowSec   int        `json:"window_sec"`
	GeneratedAt time.Time  `json:"generated_at"`
	BansActive  int        `json:"bans_active"`
	Nodes       []nodeLive `json:"nodes"`
}

type trafficCounts struct{ total, blocked, errors int }

func clampPct(v float64) int {
	switch {
	case v < 0:
		return 0
	case v > 100:
		return 100
	}
	return int(v + 0.5)
}

// computeNodeLive calcule taux et score de risque. Le risque est le plus élevé de plusieurs
// facteurs indépendants (pas une somme) pour que la cause soit lisible :
//   - offline   : nœud hors ligne = 100
//   - blocked   : 2 × % de 403/429 (50 % de refus = 100)
//   - errors    : 4 × % de 5xx (25 % d'erreurs = 100)
//   - resources : CPU/mémoire de 70 % (0) à 100 % (100)
func computeNodeLive(n nodeLive, tc trafficCounts, window time.Duration) nodeLive {
	n.Requests = tc.total
	n.RPS = float64(tc.total) / window.Seconds()
	n.LowTraffic = tc.total < liveMinRequests
	if tc.total > 0 {
		n.BlockedPct = 100 * float64(tc.blocked) / float64(tc.total)
		n.ErrorPct = 100 * float64(tc.errors) / float64(tc.total)
	}

	type factor struct {
		name  string
		score int
	}
	factors := []factor{}
	if n.Status != "online" {
		factors = append(factors, factor{"offline", 100})
	}
	if !n.LowTraffic {
		factors = append(factors,
			factor{"blocked", clampPct(2 * n.BlockedPct)},
			factor{"errors", clampPct(4 * n.ErrorPct)})
	}
	peak := 0.0
	for _, p := range []*float64{n.CPUPCT, n.MemPCT} {
		if p != nil && *p > peak {
			peak = *p
		}
	}
	factors = append(factors, factor{"resources", clampPct((peak - 70) / 30 * 100)})

	n.RiskFactor = "none"
	for _, f := range factors {
		if f.score > n.Risk {
			n.Risk, n.RiskFactor = f.score, f.name
		}
	}
	switch {
	case n.Risk >= 60:
		n.RiskLevel = "high"
	case n.Risk >= 25:
		n.RiskLevel = "medium"
	default:
		n.RiskLevel = "low"
	}
	return n
}

// live répond à GET /api/v1/nodes/live : santé, débit et risque de chaque nœud (Passerelles + Agents).
func (h *NodesHandler) live(w http.ResponseWriter, r *http.Request) {
	now := time.Now()
	var nodes []nodeRow
	if rows, err := h.DB.QueryContext(r.Context(), `SELECT `+nodeSelectCols+` FROM nodes WHERE role='edge' ORDER BY node_name`); err == nil {
		defer rows.Close()
		for rows.Next() {
			var n nodeRow
			if scanNode(rows, &n) == nil {
				nodes = append(nodes, n)
			}
		}
	}
	nodes = append(nodes, h.fetchAgentNodesFromEdges(r.Context())...)

	res := topologyLive{WindowSec: int(liveWindow.Seconds()), GeneratedAt: now.UTC(), Nodes: make([]nodeLive, 0, len(nodes))}
	for _, n := range nodes {
		res.Nodes = append(res.Nodes, computeNodeLive(
			nodeLive{NodeName: n.NodeName, Role: n.Role, Status: n.Status, CPUPCT: n.CPUPCT, MemPCT: n.MemPCT},
			h.recentTraffic(n.NodeName), liveWindow))
	}
	sort.Slice(res.Nodes, func(i, j int) bool { return res.Nodes[i].NodeName < res.Nodes[j].NodeName })

	_ = h.DB.QueryRowContext(r.Context(),
		`SELECT COUNT(*) FROM security_bans WHERE expires_at IS NULL OR datetime(expires_at) > CURRENT_TIMESTAMP`).Scan(&res.BansActive)
	jsonOK(w, res)
}

// recentTraffic rend le débit de la dernière minute d'un nœud tel que sa passerelle l'annonce (elle seule voit ses
// accès) ; zéro si elle n'en annonce pas.
func (h *NodesHandler) recentTraffic(node string) trafficCounts {
	if h.Traffic == nil {
		return trafficCounts{}
	}
	req, blocked, errs, ok := h.Traffic(node)
	if !ok {
		return trafficCounts{}
	}
	return trafficCounts{total: int(req), blocked: int(blocked), errors: int(errs)}
}
