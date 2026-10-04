package proxy

import (
	"context"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// hedgeable : seules les requêtes sans corps, idempotentes et non longues peuvent être doublées.
func (h *Handler) hedgeable(r *http.Request) bool {
	hc := h.route.Hedge
	if hc == nil || hc.DelayMs <= 0 || h.route.Shadow != nil {
		return false
	}
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return false
	}
	return r.ContentLength <= 0 && len(r.TransferEncoding) == 0 && !isUpgrade(r) && !isGRPC(r)
}

// hedgeState désigne l'unique tentative autorisée à écrire vers le client.
type hedgeState struct{ winner atomic.Pointer[hedgeGate] }

// hedgeGate est le ResponseWriter d'une tentative : la première à écrire ses en-têtes gagne et
// diffuse directement vers le client ; les autres sont annulées et leurs écritures ignorées.
type hedgeGate struct {
	real   http.ResponseWriter
	state  *hedgeState
	cancel context.CancelFunc
	hdr    http.Header
	won    bool
	lost   bool
}

func (g *hedgeGate) Header() http.Header {
	if g.won {
		return g.real.Header()
	}
	return g.hdr
}

func (g *hedgeGate) WriteHeader(code int) {
	if g.won || g.lost {
		return
	}
	if !g.state.winner.CompareAndSwap(nil, g) {
		g.lost = true
		g.cancel()
		return
	}
	g.won = true
	dst := g.real.Header()
	for k, v := range g.hdr {
		dst[k] = v
	}
	g.real.WriteHeader(code)
}

func (g *hedgeGate) Write(p []byte) (int, error) {
	if !g.won && !g.lost {
		g.WriteHeader(http.StatusOK)
	}
	if g.lost {
		return len(p), nil
	}
	return g.real.Write(p)
}

func (g *hedgeGate) Flush() {
	if f, ok := g.real.(http.Flusher); ok && g.won {
		f.Flush()
	}
}

type hedgeResult struct {
	gate     *hedgeGate
	backend  *router.Backend
	err      error
	panicked bool
	ok       bool
}

// serveHedged lance la première tentative puis, si aucune réponse n'a commencé après DelayMs,
// une tentative sur le backend suivant (au plus MaxExtra, défaut 1). La première réponse gagne.
// Retourne false si aucune tentative n'a répondu (rien n'a été écrit : l'appelant écrit l'erreur).
func (h *Handler) serveHedged(w http.ResponseWriter, r *http.Request, attempts []*router.Backend) bool {
	hc := h.route.Hedge
	delay := time.Duration(hc.DelayMs) * time.Millisecond
	maxStarts := 1 + max(hc.MaxExtra, 1)
	state := &hedgeState{}
	results := make(chan hedgeResult, len(attempts))
	var cancels []context.CancelFunc
	defer func() {
		for _, c := range cancels {
			c()
		}
	}()

	started, inFlight := 0, 0
	launch := func() {
		b := attempts[started]
		ctx, cancel := context.WithCancel(r.Context())
		cancels = append(cancels, cancel)
		g := &hedgeGate{real: w, state: state, cancel: cancel, hdr: http.Header{}}
		req := r.Clone(ctx)
		idx := started
		started++
		inFlight++
		go func() {
			res := hedgeResult{gate: g, backend: b}
			defer func() {
				if rec := recover(); rec != nil {
					res.panicked = true
				}
				results <- res
			}()
			res.ok, _, res.err = h.do(g, req, b, idx, false)
		}()
	}

	launch()
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for inFlight > 0 {
		select {
		case <-timer.C:
			if started < len(attempts) && started < maxStarts {
				launch()
				if started < len(attempts) && started < maxStarts {
					timer.Reset(delay)
				}
			}
		case res := <-results:
			inFlight--
			if res.gate.won {
				if res.panicked {
					panic(http.ErrAbortHandler)
				}
				if res.ok {
					h.health.MarkUp(res.backend.URL)
					if h.cb != nil {
						h.cb.RecordSuccess(res.backend.URL)
					}
				}
				return true
			}
			if res.gate.lost {
				continue
			}
			if ttl := quarantineDuration(res.err); ttl > 0 {
				h.health.MarkDown(res.backend.URL, ttl)
			}
			if h.cb != nil {
				h.cb.RecordFailure(res.backend.URL)
			}
			if inFlight == 0 && started < len(attempts) && r.Context().Err() == nil {
				launch()
			}
		}
	}
	return state.winner.Load() != nil
}
