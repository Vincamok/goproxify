package fail2ban

import (
	"strings"
	"testing"
)

// Sans INDEXED BY et sans ANALYZE, la requête parcourait toute la table des journaux à chaque tour.
func TestErrorCountsQueryReadsOnlyTheWindow(t *testing.T) {
	_, d := newTestEngine(t)
	rows, err := d.Query(`EXPLAIN QUERY PLAN `+errorCountsQuery, "2026-01-01T00:00:00Z", 5)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail + "\n")
	}
	if !strings.Contains(plan.String(), "SEARCH logs USING INDEX idx_logs_ts") {
		t.Fatalf("plan : %s", plan.String())
	}
}
