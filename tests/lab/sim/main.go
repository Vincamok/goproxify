// lab-sim : applications simulées derrière la passerelle (source canonique, embarquée par gen-compose.sh).
//
// Plusieurs "instances" d'une même boutique écoutent sur des ports distincts (équilibrage, canary, shadow,
// santé, failover) ; un port de contrôle (9999) pilote leur état sans passer par la passerelle.
package main

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

type instance struct {
	id      string
	port    int
	healthy atomic.Bool
	failN   atomic.Int64 // prochaines requêtes applicatives en 503
	dropN   atomic.Int64 // prochaines requêtes applicatives : connexion coupée sans réponse (panne de transport)
	latency atomic.Int64 // ms ajoutées à chaque requête applicative
	hits    atomic.Int64 // requêtes applicatives (hors /healthz)
	probes  atomic.Int64 // sondes /healthz reçues
	static  atomic.Int64 // hits d'origine sur /static/*
	lastMu  sync.Mutex
	last    map[string]string // dernier en-tête vu par chemin (shadow : preuve de miroir)
	flaky   sync.Map          // clé -> compteur d'échecs restants (/fail-first)
}

var instances = map[string]*instance{}

func intQ(r *http.Request, k string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(k)); err == nil && v >= 0 {
		return v
	}
	return def
}

func (in *instance) handler() http.Handler {
	mux := http.NewServeMux()

	health := func(w http.ResponseWriter, r *http.Request) {
		in.probes.Add(1)
		if !in.healthy.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
	mux.HandleFunc("/healthz", health)
	mux.HandleFunc("/health", health) // chemin sondé par défaut par la passerelle

	var api http.HandlerFunc

	// Page d'accueil : contient l'URL interne du backend (sub_filter, proxy_redirect).
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		// Backend insensible à la casse (IIS/ASP.NET) : /API/V1/ADMIN et /api/v1/Admin atteignent l'API.
		if strings.HasPrefix(strings.ToLower(r.URL.Path), "/api/") {
			api(w, r)
			return
		}
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><html><body><h1>Boutique LAB</h1><p>instance=%s</p>
<a href="http://lab-sim:%d/products">produits</a><p>BACKEND-MARKER</p></body></html>`, in.id, in.port)
	})

	// Contenu dépendant du cookie : détection de fuite par le cache (cache deception).
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		c, _ := r.Cookie("sid")
		user := "anonyme"
		if c != nil {
			user = c.Value
		} else if a := r.Header.Get("Authorization"); a != "" {
			user = a
		}
		// private : l'application signale une réponse personnalisée, qu'un cache partagé ne doit pas resservir.
		w.Header().Set("Cache-Control", "private, max-age=60")
		fmt.Fprintf(w, "user=%s", user)
	})

	// Reflète les en-têtes de routage : empoisonnement de cache par en-tête non clé.
	mux.HandleFunc("/reflect", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "public, max-age=60")
		fmt.Fprintf(w, "xfh=%s host=%s", r.Header.Get("X-Forwarded-Host"), r.Host)
	})

	mux.HandleFunc("/whoami", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, in.id) })

	mux.HandleFunc("/echo", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(io.LimitReader(r.Body, 1<<20))
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"instance": in.id, "method": r.Method, "host": r.Host, "uri": r.RequestURI, "path": r.URL.Path,
			"remote": r.RemoteAddr, "headers": r.Header, "cookies": r.Cookies(), "body_len": len(body),
		})
	})

	api = func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Server", "lab-sim/1.0")
		w.Header().Set("X-Powered-By", "lab-sim")
		fmt.Fprintf(w, `{"instance":%q,"path":%q,"marker":%q,"secret":%q,"items":[{"id":1,"name":"stylo"},{"id":2,"name":"cahier"}]}`, in.id, r.URL.Path, r.Header.Get("X-Lab-Marker"), r.Header.Get("X-Secret-Client"))
	}
	mux.HandleFunc("/api/", api)

	// Session : cookie lié au domaine/chemin interne (proxy_cookie_domain / proxy_cookie_path).
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "s-" + in.id, Domain: "lab-sim", Path: "/app", HttpOnly: true})
		fmt.Fprint(w, "logged-in")
	})

	// Redirection vers l'URL interne (proxy_redirect).
	mux.HandleFunc("/redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, fmt.Sprintf("http://lab-sim:%d/landing", in.port), http.StatusFound)
	})

	// Ressource statique cacheable : X-Origin-Hit ne change pas tant que le cache sert la réponse.
	mux.HandleFunc("/static/", func(w http.ResponseWriter, r *http.Request) {
		n := in.static.Add(1)
		w.Header().Set("Cache-Control", "public, max-age=60")
		w.Header().Set("Content-Type", "application/javascript")
		w.Header().Set("X-Origin-Hit", strconv.FormatInt(n, 10))
		fmt.Fprintf(w, "console.log('lab asset %s');", r.URL.Path)
	})

	mux.HandleFunc("/status/", func(w http.ResponseWriter, r *http.Request) {
		code, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/status/"))
		if err != nil || code < 100 || code > 599 {
			code = http.StatusBadRequest
		}
		w.WriteHeader(code)
		fmt.Fprintf(w, "status %d from %s", code, in.id)
	})

	// Échoue n fois par clé, puis réussit : valide la politique de retry.
	mux.HandleFunc("/fail-first", func(w http.ResponseWriter, r *http.Request) {
		key := r.URL.Query().Get("key")
		v, _ := in.flaky.LoadOrStore(key, new(atomic.Int64))
		c := v.(*atomic.Int64)
		if c.Add(1) <= int64(intQ(r, "n", 2)) {
			http.Error(w, "boom", http.StatusBadGateway)
			return
		}
		fmt.Fprint(w, "recovered")
	})

	mux.HandleFunc("/slow", func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(time.Duration(intQ(r, "ms", 500)) * time.Millisecond)
		fmt.Fprint(w, "slow ok")
	})

	mux.HandleFunc("/bytes", func(w http.ResponseWriter, r *http.Request) {
		n := intQ(r, "n", 1024)
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.Itoa(n))
		chunk := []byte(strings.Repeat("x", 4096))
		for n > 0 {
			c := min(n, len(chunk))
			if _, err := w.Write(chunk[:c]); err != nil {
				return
			}
			n -= c
		}
	})

	mux.HandleFunc("/upload", func(w http.ResponseWriter, r *http.Request) {
		n, _ := io.Copy(io.Discard, r.Body)
		fmt.Fprintf(w, "%d", n)
	})

	mux.HandleFunc("/sse", func(w http.ResponseWriter, r *http.Request) {
		fl, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "no flush", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "text/event-stream")
		for i := 0; i < intQ(r, "n", 10); i++ {
			fmt.Fprintf(w, "data: %d\n\n", i)
			fl.Flush()
			select {
			case <-r.Context().Done():
				return
			case <-time.After(time.Duration(intQ(r, "ms", 200)) * time.Millisecond):
			}
		}
	})

	mux.HandleFunc("/ws", func(w http.ResponseWriter, r *http.Request) { echoWS(w, r, in.id) })

	return in.wrap(mux)
}

// wrap applique latence, pannes simulées et compteurs ; /healthz n'est jamais compté ni ralenti.
func (in *instance) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Instance", in.id)
		if r.URL.Path == "/healthz" || r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		in.hits.Add(1)
		in.lastMu.Lock()
		in.last[r.URL.Path] = r.Header.Get("X-Lab-Marker")
		in.lastMu.Unlock()
		if ms := in.latency.Load(); ms > 0 {
			time.Sleep(time.Duration(ms) * time.Millisecond)
		}
		if in.dropN.Load() > 0 && in.dropN.Add(-1) >= 0 {
			if hj, ok := w.(http.Hijacker); ok {
				if c, _, err := hj.Hijack(); err == nil {
					c.Close()
					return
				}
			}
		}
		if in.failN.Load() > 0 && in.failN.Add(-1) >= 0 {
			http.Error(w, "simulated failure", http.StatusServiceUnavailable)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// echoWS : poignée de main WebSocket minimale + écho des trames texte (charges < 126 octets).
func echoWS(w http.ResponseWriter, r *http.Request, id string) {
	key := r.Header.Get("Sec-WebSocket-Key")
	if !strings.EqualFold(r.Header.Get("Upgrade"), "websocket") || key == "" {
		http.Error(w, "upgrade required", http.StatusUpgradeRequired)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "no hijack", http.StatusInternalServerError)
		return
	}
	conn, rw, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()
	sum := sha1.Sum([]byte(key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"))
	fmt.Fprintf(rw, "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: %s\r\nX-Instance: %s\r\n\r\n",
		base64.StdEncoding.EncodeToString(sum[:]), id)
	rw.Flush()
	for {
		_ = conn.SetReadDeadline(time.Now().Add(30 * time.Second))
		hdr := make([]byte, 2)
		if _, err := io.ReadFull(rw, hdr); err != nil {
			return
		}
		op, n := hdr[0]&0x0f, int(hdr[1]&0x7f)
		if op == 0x8 || n >= 126 {
			return
		}
		var mask [4]byte
		if hdr[1]&0x80 != 0 {
			if _, err := io.ReadFull(rw, mask[:]); err != nil {
				return
			}
		}
		payload := make([]byte, n)
		if _, err := io.ReadFull(rw, payload); err != nil {
			return
		}
		for i := range payload {
			payload[i] ^= mask[i%4]
		}
		reply := append([]byte(id+":"), payload...)
		if len(reply) >= 126 {
			return
		}
		rw.Write(append([]byte{0x81, byte(len(reply))}, reply...))
		rw.Flush()
	}
}

func control() http.Handler {
	mux := http.NewServeMux()
	// /ctl/<id>/<health|fail|latency|reset>?...
	mux.HandleFunc("/jwks.json", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
			"kty": "RSA", "kid": "lab1", "use": "sig", "alg": "RS256",
			"n": b64(jwtKey.N.Bytes()), "e": b64(big.NewInt(int64(jwtKey.E)).Bytes()),
		}}})
	})
	mux.HandleFunc("/ctl/", func(w http.ResponseWriter, r *http.Request) {
		parts := strings.Split(strings.Trim(strings.TrimPrefix(r.URL.Path, "/ctl/"), "/"), "/")
		if parts[0] == "jwt" {
			fmt.Fprint(w, mintJWT(r))
			return
		}
		if parts[0] == "stats" {
			out := map[string]any{}
			for id, in := range instances {
				in.lastMu.Lock()
				last := map[string]string{}
				for k, v := range in.last {
					last[k] = v
				}
				in.lastMu.Unlock()
				out[id] = map[string]any{"hits": in.hits.Load(), "probes": in.probes.Load(), "static": in.static.Load(), "healthy": in.healthy.Load(), "last_marker": last}
			}
			w.Header().Set("Content-Type", "application/json")
			_ = json.NewEncoder(w).Encode(out)
			return
		}
		if parts[0] == "reset" {
			for _, in := range instances {
				in.healthy.Store(true)
				in.failN.Store(0)
				in.dropN.Store(0)
				in.latency.Store(0)
				in.hits.Store(0)
				in.static.Store(0)
				in.flaky.Range(func(k, _ any) bool { in.flaky.Delete(k); return true })
			}
			fmt.Fprint(w, "reset")
			return
		}
		in := instances[parts[0]]
		if in == nil || len(parts) < 2 {
			http.NotFound(w, r)
			return
		}
		switch parts[1] {
		case "health":
			in.healthy.Store(r.URL.Query().Get("up") != "0")
		case "fail":
			in.failN.Store(int64(intQ(r, "n", 1)))
		case "drop":
			in.dropN.Store(int64(intQ(r, "n", 1)))
		case "latency":
			in.latency.Store(int64(intQ(r, "ms", 0)))
		case "reset":
			in.healthy.Store(true)
			in.failN.Store(0)
			in.dropN.Store(0)
			in.latency.Store(0)
		default:
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, "ok")
	})
	return mux
}

func tcpEcho(addr string) {
	l, err := net.Listen("tcp", addr)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	for {
		c, err := l.Accept()
		if err != nil {
			return
		}
		go func() {
			defer c.Close()
			fmt.Fprint(c, "LAB-TCP-BANNER\n")
			io.Copy(c, c)
		}()
	}
}

func main() {
	// a/b/c : pool de la boutique ; canary/shadow/legacy : hors pool ; h1/h2 : sondes de santé (une config de sonde est partagée par URL de backend) ;
	// le port 9009 n'est volontairement pas écouté (backend mort).
	for id, port := range map[string]int{"a": 9001, "b": 9002, "c": 9003, "canary": 9004, "shadow": 9005, "legacy": 9006, "h1": 9007, "h2": 9008} {
		in := &instance{id: id, port: port, last: map[string]string{}}
		in.healthy.Store(true)
		instances[id] = in
		go func() {
			srv := &http.Server{Addr: fmt.Sprintf(":%d", in.port), Handler: in.handler(), ReadHeaderTimeout: 10 * time.Second}
			if err := srv.ListenAndServe(); err != nil {
				fmt.Fprintln(os.Stderr, err)
				os.Exit(1)
			}
		}()
	}
	go tcpEcho(":9100")
	srv := &http.Server{Addr: ":9999", Handler: control(), ReadHeaderTimeout: 10 * time.Second}
	if err := srv.ListenAndServe(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

// ---- JWT de test : clé RSA éphémère, JWKS sur le port de contrôle, jetons forgés à la demande ----
// (la passerelle n'accepte que des clés RSA dans le JWKS)

var jwtKey, _ = rsa.GenerateKey(rand.Reader, 2048)

func b64(b []byte) string { return base64.RawURLEncoding.EncodeToString(b) }

// pubPEM : clé publique PKIX en PEM, utilisée comme secret HMAC dans l'attaque par confusion d'algorithme.
func pubPEM() []byte {
	der, _ := x509.MarshalPKIXPublicKey(&jwtKey.PublicKey)
	return pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
}

// mintJWT : /ctl/jwt?alg=RS256|none|HS256&iss=&aud=&exp=<secondes, négatif = expiré>&sub=&tamper=1
func mintJWT(r *http.Request) string {
	q := r.URL.Query()
	get := func(k, def string) string {
		if v, ok := q[k]; ok {
			return v[0]
		}
		return def
	}
	alg := get("alg", "RS256")
	exp, _ := strconv.Atoi(get("exp", "300"))
	hdr, _ := json.Marshal(map[string]string{"alg": alg, "typ": "JWT", "kid": "lab1"})
	claims := map[string]any{"iss": get("iss", "https://issuer.lab.test"), "aud": get("aud", "lab-api"), "sub": get("sub", "alice"), "exp": time.Now().Add(time.Duration(exp) * time.Second).Unix(), "iat": time.Now().Unix()}
	pl, _ := json.Marshal(claims)
	signing := b64(hdr) + "." + b64(pl)
	var sig []byte
	switch alg {
	case "none":
	case "HS256":
		m := hmac.New(sha256.New, pubPEM())
		m.Write([]byte(signing))
		sig = m.Sum(nil)
	default:
		h := sha256.Sum256([]byte(signing))
		sig, _ = rsa.SignPKCS1v15(rand.Reader, jwtKey, crypto.SHA256, h[:])
	}
	if q.Get("tamper") == "1" {
		claims["sub"] = "admin"
		pl, _ = json.Marshal(claims)
		signing = b64(hdr) + "." + b64(pl)
	}
	return signing + "." + b64(sig)
}
