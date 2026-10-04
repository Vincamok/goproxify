package middleware

import (
	"strconv"
	"sync"
	"time"
)

// quotaWindow compte les requêtes d'une clé sur une fenêtre alignée sur l'horloge (même fenêtre
// sur toutes les passerelles). remote garde le dernier compte annoncé par chaque pair (compteur G :
// une valeur ne fait que croître), ce qui répartit le quota sans coordinateur.
type quotaWindow struct {
	end    time.Time
	n      int
	shared bool
	remote map[string]int
}

func (w *quotaWindow) total() int {
	t := w.n
	for _, n := range w.remote {
		t += n
	}
	return t
}

type quotaStore struct {
	mu sync.Mutex
	m  map[string]*quotaWindow
}

var quotas = &quotaStore{m: make(map[string]*quotaWindow)}

// QuotaEntry est le compte local d'une fenêtre partagée, échangé entre passerelles d'un groupe HA.
type QuotaEntry struct {
	Key   string `json:"key"`
	EndMs int64  `json:"end_ms"`
	N     int    `json:"n"`
}

func quotaPeriod(p string) time.Duration {
	switch p {
	case "minute":
		return time.Minute
	case "day":
		return 24 * time.Hour
	default:
		return time.Hour
	}
}

func (s *quotaStore) purgeLocked(now time.Time) {
	if len(s.m) <= 50000 {
		return
	}
	for k, w := range s.m {
		if now.After(w.end) {
			delete(s.m, k)
		}
	}
}

// take consomme une requête de la fenêtre courante de key ; renvoie le reste et le délai avant la fenêtre suivante.
// Avec shared, les comptes reçus des pairs (Merge) s'ajoutent au compte local.
func (s *quotaStore) take(key string, limit int, period time.Duration, shared bool) (ok bool, remaining int, retry time.Duration) {
	now := time.Now()
	start := now.Truncate(period)
	full := key + "\x00" + strconv.FormatInt(start.Unix(), 10)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked(now)
	w := s.m[full]
	if w == nil {
		w = &quotaWindow{end: start.Add(period)}
		s.m[full] = w
	}
	w.shared = w.shared || shared
	if t := w.total(); t >= limit {
		return false, 0, w.end.Sub(now)
	}
	w.n++
	return true, max(limit-w.total(), 0), w.end.Sub(now)
}

// ExportQuotas retourne les comptes locaux des fenêtres partagées encore ouvertes.
func ExportQuotas() []QuotaEntry {
	now := time.Now()
	quotas.mu.Lock()
	defer quotas.mu.Unlock()
	var out []QuotaEntry
	for k, w := range quotas.m {
		if w.shared && w.n > 0 && now.Before(w.end) {
			out = append(out, QuotaEntry{Key: k, EndMs: w.end.UnixMilli(), N: w.n})
		}
	}
	return out
}

// MergeQuotas enregistre les comptes annoncés par le pair peer ; une valeur plus ancienne est ignorée.
func MergeQuotas(peer string, entries []QuotaEntry) {
	now := time.Now()
	quotas.mu.Lock()
	defer quotas.mu.Unlock()
	for _, e := range entries {
		end := time.UnixMilli(e.EndMs)
		if now.After(end) || e.N <= 0 {
			continue
		}
		w := quotas.m[e.Key]
		if w == nil {
			w = &quotaWindow{end: end}
			quotas.m[e.Key] = w
		}
		if w.remote == nil {
			w.remote = make(map[string]int)
		}
		w.remote[peer] = max(w.remote[peer], e.N)
	}
}

// HasSharedQuotas dit si une fenêtre partagée est ouverte (inutile d'interroger les pairs sinon).
func HasSharedQuotas() bool {
	now := time.Now()
	quotas.mu.Lock()
	defer quotas.mu.Unlock()
	for _, w := range quotas.m {
		if w.shared && now.Before(w.end) {
			return true
		}
	}
	return false
}
