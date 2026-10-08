// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package grpctrans

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/router"
)

const metadataPrefix = "Grpc-Metadata-"

var errTooLarge = errors.New("réponse trop volumineuse")

// Validate retourne les erreurs de configuration et les routes publiées (dry-run).
func Validate(cfg *router.GRPCTranscodeConfig) (errs []string, routes []string) {
	if cfg == nil || !cfg.Enabled {
		return nil, nil
	}
	if cfg.MaxRequestBody < 0 || cfg.MaxResponseBody < 0 {
		errs = append(errs, "grpc_transcode.max_request_body et max_response_body doivent être positifs")
	}
	t, err := Compile(cfg)
	if err != nil {
		return append(errs, err.Error()), nil
	}
	return errs, t.Routes()
}

// Middleware traduit les requêtes REST/JSON en appels gRPC unaires vers le backend et la réponse gRPC
// en JSON. Une requête gRPC native (Content-Type application/grpc*) traverse sans changement. Une
// requête REST qui ne correspond à aucune route reçoit 404 (ou 405 si le chemin existe pour une autre
// méthode). Une configuration invalide laisse tout passer (le dry-run la refuse à l'enregistrement).
// À placer juste avant le proxy : le cache, les validations et l'authentification voient le REST.
func Middleware(host string, cfg *router.GRPCTranscodeConfig) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if cfg == nil || !cfg.Enabled {
			return next
		}
		t, err := Compile(cfg)
		if err != nil {
			return next
		}
		count := func(result string) { metrics.Routing.GRPCTranscode.WithLabelValues(host, result).Inc() }
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(strings.ToLower(r.Header.Get("Content-Type")), "application/grpc") {
				next.ServeHTTP(w, r)
				return
			}
			b, vars, allow := t.route(r)
			if b == nil {
				if len(allow) > 0 {
					count("method_not_allowed")
					w.Header().Set("Allow", strings.Join(allow, ", "))
					writeStatus(w, http.StatusMethodNotAllowed, 12, "méthode non permise pour cette route")
					return
				}
				count("not_found")
				writeStatus(w, http.StatusNotFound, 5, "aucune méthode gRPC ne correspond à cette route")
				return
			}

			var body []byte
			if b.body != "" {
				raw, err := io.ReadAll(io.LimitReader(r.Body, t.maxRequest+1))
				if err != nil {
					count("bad_request")
					writeStatus(w, http.StatusBadRequest, 3, "corps illisible")
					return
				}
				if int64(len(raw)) > t.maxRequest {
					count("bad_request")
					writeStatus(w, http.StatusRequestEntityTooLarge, 8, "corps de requête trop volumineux")
					return
				}
				body = raw
			}
			var framed []byte
			var err error
			if b.method.IsStreamingClient() {
				framed, err = b.buildClientStream(r, body, vars)
			} else {
				var msg []byte
				if msg, err = b.buildRequest(r, body, vars); err == nil {
					framed = frame(msg)
				}
			}
			if err != nil {
				count("bad_request")
				var br *BadRequest
				if errors.As(err, &br) {
					writeStatus(w, http.StatusBadRequest, 3, br.Msg)
				} else {
					writeStatus(w, http.StatusInternalServerError, 13, err.Error())
				}
				return
			}

			if b.method.IsStreamingServer() {
				sw := &streamWriter{w: w, t: t, b: b, count: count, header: http.Header{}}
				next.ServeHTTP(sw, toGRPC(r, b.grpcPath, framed))
				sw.finish()
				return
			}
			rec := &recorder{header: http.Header{}, max: t.maxResponse}
			next.ServeHTTP(rec, toGRPC(r, b.grpcPath, framed))
			t.finish(w, b, rec, count)
		})
	}
}

// route cherche la route qui correspond : la route elle-même, ou la liste des méthodes permises
// si seul le verbe HTTP diffère.
func (t *Transcoder) route(r *http.Request) (*binding, map[string]string, []string) {
	path := r.URL.EscapedPath()
	if path == "" {
		path = "/"
	}
	var allow []string
	for _, b := range t.bindings {
		vars, ok := b.tpl.match(path)
		if !ok {
			continue
		}
		if b.httpMethod == r.Method || (r.Method == http.MethodHead && b.httpMethod == http.MethodGet) {
			return b, vars, nil
		}
		allow = append(allow, b.httpMethod)
	}
	sort.Strings(allow)
	return nil, nil, dedupe(allow)
}

func dedupe(s []string) []string {
	var out []string
	for i, v := range s {
		if i == 0 || v != s[i-1] {
			out = append(out, v)
		}
	}
	return out
}

// frame ajoute le cadrage gRPC (drapeau de compression + longueur sur 4 octets) à un message.
func frame(msg []byte) []byte {
	out := make([]byte, 5+len(msg))
	binary.BigEndian.PutUint32(out[1:5], uint32(len(msg)))
	copy(out[5:], msg)
	return out
}

// toGRPC réécrit la requête REST en requête gRPC (corps déjà cadré, chemin /paquet.Service/Méthode).
func toGRPC(r *http.Request, grpcPath string, framed []byte) *http.Request {
	r2 := r.Clone(r.Context())
	r2.Method = http.MethodPost
	u := *r.URL
	u.Path, u.RawPath, u.RawQuery, u.ForceQuery = grpcPath, "", "", false
	r2.URL = &u
	r2.RequestURI = grpcPath
	r2.Body = io.NopCloser(bytes.NewReader(framed))
	r2.ContentLength = int64(len(framed))
	r2.GetBody = nil
	for _, h := range []string{"Content-Length", "Content-Encoding", "Accept", "Accept-Encoding", "Range", "If-None-Match", "If-Modified-Since"} {
		r2.Header.Del(h)
	}
	// Grpc-Metadata-<Nom> devient la métadonnée <Nom> (convention de grpc-gateway).
	for k, vs := range r2.Header {
		if len(k) > len(metadataPrefix) && strings.EqualFold(k[:len(metadataPrefix)], metadataPrefix) {
			r2.Header.Del(k)
			for _, v := range vs {
				r2.Header.Add(k[len(metadataPrefix):], v)
			}
		}
	}
	r2.Header.Set("Content-Type", "application/grpc")
	r2.Header.Set("Te", "trailers")
	return r2
}

// recorder met en mémoire la réponse du proxy (en-têtes, corps, trailers) pour la traduire.
type recorder struct {
	header      http.Header
	status      int
	buf         bytes.Buffer
	max         int64
	wroteHeader bool
	overflow    bool
}

func (r *recorder) Header() http.Header { return r.header }

func (r *recorder) WriteHeader(code int) {
	if !r.wroteHeader {
		r.status, r.wroteHeader = code, true
	}
}

func (r *recorder) Write(p []byte) (int, error) {
	r.WriteHeader(http.StatusOK)
	if int64(r.buf.Len()+len(p)) > r.max {
		r.overflow = true
		return 0, errTooLarge
	}
	return r.buf.Write(p)
}

// Flush est sans effet : la réponse est traduite d'un bloc une fois complète.
func (r *recorder) Flush() {}

// trailer lit un trailer de réponse (annoncé par le proxy sous le préfixe « Trailer: »), ou à défaut
// l'en-tête du même nom (réponse « trailers-only »).
func trailer(h http.Header, name string) string {
	for k, vs := range h {
		if len(vs) > 0 && len(k) > len(http.TrailerPrefix) && strings.EqualFold(k[:len(http.TrailerPrefix)], http.TrailerPrefix) &&
			strings.EqualFold(k[len(http.TrailerPrefix):], name) {
			return vs[0]
		}
	}
	return h.Get(name)
}

func (t *Transcoder) finish(w http.ResponseWriter, b *binding, rec *recorder, count func(string)) {
	if rec.overflow {
		count("upstream_error")
		writeStatus(w, http.StatusBadGateway, 8, "réponse du backend trop volumineuse")
		return
	}
	statusText := trailer(rec.header, "Grpc-Status")
	isGRPC := strings.HasPrefix(strings.ToLower(rec.header.Get("Content-Type")), "application/grpc")
	if statusText == "" && !isGRPC {
		// Pas une réponse gRPC (backend injoignable, page d'erreur du proxy…) : transmise telle quelle.
		count("upstream_error")
		passthrough(w, rec)
		return
	}
	code := 2
	if statusText != "" {
		if n, err := strconv.Atoi(statusText); err == nil {
			code = n
		}
	}
	if code != 0 {
		count("grpc_error")
		t.writeGRPCError(w, rec, code)
		return
	}
	out := dynamicpb.NewMessage(b.method.Output())
	msg, err := firstMessage(rec.buf.Bytes(), rec.header.Get("Grpc-Encoding"))
	if err == nil && msg != nil {
		err = proto.Unmarshal(msg, out)
	}
	var js []byte
	if err == nil {
		js, err = t.marshalJSON(b, out)
	}
	if err != nil {
		count("upstream_error")
		writeStatus(w, http.StatusBadGateway, 13, "réponse gRPC illisible : "+err.Error())
		return
	}
	count("ok")
	copyHeaders(w, rec.header)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.Header().Set("Content-Length", strconv.Itoa(len(js)))
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(js)
}

func passthrough(w http.ResponseWriter, rec *recorder) {
	copyHeaders(w, rec.header)
	if ct := rec.header.Get("Content-Type"); ct != "" {
		w.Header().Set("Content-Type", ct)
	}
	st := rec.status
	if st == 0 {
		st = http.StatusBadGateway
	}
	w.WriteHeader(st)
	_, _ = w.Write(rec.buf.Bytes())
}

// copyHeaders recopie les en-têtes du backend, sauf ceux qui décrivent l'encodage gRPC ou la taille.
func copyHeaders(w http.ResponseWriter, h http.Header) {
	for k, vs := range h {
		lk := strings.ToLower(k)
		if strings.HasPrefix(lk, "trailer") || strings.HasPrefix(lk, "grpc-") ||
			lk == "content-type" || lk == "content-length" || lk == "content-encoding" || lk == "te" {
			continue
		}
		for _, v := range vs {
			w.Header().Add(k, v)
		}
	}
}

// firstMessage extrait le premier message d'un corps gRPC cadré (nil si aucun).
func firstMessage(body []byte, encoding string) ([]byte, error) {
	if len(body) == 0 {
		return nil, nil
	}
	if len(body) < 5 {
		return nil, fmt.Errorf("trame tronquée")
	}
	n := int(binary.BigEndian.Uint32(body[1:5]))
	if len(body)-5 < n {
		return nil, fmt.Errorf("trame tronquée")
	}
	msg := body[5 : 5+n]
	if body[0]&1 == 0 {
		return msg, nil
	}
	if !strings.EqualFold(encoding, "gzip") {
		return nil, fmt.Errorf("compression %q non prise en charge", encoding)
	}
	zr, err := gzip.NewReader(bytes.NewReader(msg))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return io.ReadAll(io.LimitReader(zr, 64<<20))
}

// httpStatus : correspondance code gRPC → statut HTTP (celle de google.rpc.Code).
func httpStatus(code int) int {
	switch code {
	case 0:
		return http.StatusOK
	case 1:
		return 499
	case 3, 9, 11:
		return http.StatusBadRequest
	case 4:
		return http.StatusGatewayTimeout
	case 5:
		return http.StatusNotFound
	case 6, 10:
		return http.StatusConflict
	case 7:
		return http.StatusForbidden
	case 8:
		return http.StatusTooManyRequests
	case 12:
		return http.StatusNotImplemented
	case 14:
		return http.StatusServiceUnavailable
	case 16:
		return http.StatusUnauthorized
	}
	return http.StatusInternalServerError
}

// writeGRPCError écrit {"code", "message", "details"} avec le statut HTTP correspondant.
func (t *Transcoder) writeGRPCError(w http.ResponseWriter, rec *recorder, code int) {
	writeGRPCErrorFrom(w, rec.header, code)
}

// grpcErrorBody construit {"code","message","details"} depuis les trailers (ou en-têtes) gRPC.
func grpcErrorBody(h http.Header, code int) map[string]any {
	msg := trailer(h, "Grpc-Message")
	if dec, err := url.PathUnescape(msg); err == nil {
		msg = dec
	}
	out := map[string]any{"code": code, "message": msg, "details": []any{}}
	if raw := trailer(h, "Grpc-Status-Details-Bin"); raw != "" {
		var bin []byte
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding} {
			if b, err := enc.DecodeString(raw); err == nil {
				bin = b
				break
			}
		}
		var st status.Status
		if bin != nil && proto.Unmarshal(bin, &st) == nil {
			if js, err := (protojson.MarshalOptions{}).Marshal(&st); err == nil {
				var m map[string]any
				if json.Unmarshal(js, &m) == nil {
					if d, ok := m["details"]; ok {
						out["details"] = d
					}
					if st.GetMessage() != "" && msg == "" {
						out["message"] = st.GetMessage()
					}
				}
			}
		}
	}
	return out
}

// writeGRPCErrorFrom écrit l'erreur gRPC avec le statut HTTP correspondant.
func writeGRPCErrorFrom(w http.ResponseWriter, h http.Header, code int) {
	copyHeaders(w, h)
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(httpStatus(code))
	_ = json.NewEncoder(w).Encode(grpcErrorBody(h, code))
}

func writeStatus(w http.ResponseWriter, httpCode, grpcCode int, msg string) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(httpCode)
	_ = json.NewEncoder(w).Encode(map[string]any{"code": grpcCode, "message": msg, "details": []any{}})
}
