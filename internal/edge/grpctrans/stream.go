// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package grpctrans

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/dynamicpb"
)

// Flux client : le corps REST est une suite de valeurs JSON (NDJSON, valeurs concaténées, ou un
// tableau JSON) ; chacune devient un message gRPC. Les variables de chemin s'appliquent à chaque
// message. Tous les messages sont envoyés avant de lire la réponse (pas d'échange entrelacé).

// buildClientStream convertit le corps en suite de messages cadrés.
func (b *binding) buildClientStream(r *http.Request, body []byte, vars map[string]string) ([]byte, error) {
	trimmed := bytes.TrimSpace(body)
	var items []json.RawMessage
	switch {
	case len(trimmed) == 0:
	case trimmed[0] == '[':
		if err := json.Unmarshal(trimmed, &items); err != nil {
			return nil, &BadRequest{"corps invalide : " + err.Error()}
		}
	default:
		dec := json.NewDecoder(bytes.NewReader(trimmed))
		for {
			var it json.RawMessage
			err := dec.Decode(&it)
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, &BadRequest{fmt.Sprintf("message %d : %v", len(items)+1, err)}
			}
			items = append(items, it)
		}
	}
	var out []byte
	for i, it := range items {
		msg, err := b.buildRequest(r, it, vars)
		if err != nil {
			var br *BadRequest
			if errors.As(err, &br) {
				return nil, &BadRequest{fmt.Sprintf("message %d : %s", i+1, br.Msg)}
			}
			return nil, err
		}
		out = append(out, frame(msg)...)
	}
	return out, nil
}

// streamWriter traduit au fil de l'eau une réponse gRPC en flux : chaque message devient une ligne
// {"result": …} (NDJSON, comme grpc-gateway) et une erreur de fin de flux une ligne {"error": …}.
// Le statut HTTP n'est écrit qu'au premier message : une erreur gRPC avant tout message garde son
// vrai statut HTTP (404, 403…).
type streamWriter struct {
	w      http.ResponseWriter
	t      *Transcoder
	b      *binding
	count  func(string)
	header http.Header

	status      int
	wroteHeader bool
	mode        streamMode
	committed   bool
	pending     []byte
	failure     error
	sent        int
}

type streamMode int

const (
	modeUndecided streamMode = iota
	modeStream
	modePassthrough
	modeTrailersOnly
)

var errStreamAbort = errors.New("flux interrompu")

func (s *streamWriter) Header() http.Header { return s.header }

func (s *streamWriter) WriteHeader(code int) {
	if s.wroteHeader {
		return
	}
	s.wroteHeader, s.status = true, code
	switch {
	case s.header.Get("Grpc-Status") != "":
		s.mode = modeTrailersOnly
	case !strings.HasPrefix(strings.ToLower(s.header.Get("Content-Type")), "application/grpc"):
		s.mode = modePassthrough
		copyHeaders(s.w, s.header)
		if ct := s.header.Get("Content-Type"); ct != "" {
			s.w.Header().Set("Content-Type", ct)
		}
		s.w.WriteHeader(code)
		s.committed = true
	default:
		s.mode = modeStream
	}
}

func (s *streamWriter) Write(p []byte) (int, error) {
	if !s.wroteHeader {
		s.WriteHeader(http.StatusOK)
	}
	switch s.mode {
	case modePassthrough:
		return s.w.Write(p)
	case modeStream:
		if s.failure != nil {
			return 0, errStreamAbort
		}
		s.pending = append(s.pending, p...)
		if err := s.drain(); err != nil {
			s.failure = err
			return 0, errStreamAbort
		}
	}
	return len(p), nil
}

func (s *streamWriter) Flush() {
	if s.mode == modePassthrough {
		if f, ok := s.w.(http.Flusher); ok {
			f.Flush()
		}
	}
}

// commit écrit le statut 200 et les en-têtes de flux (une seule fois).
func (s *streamWriter) commit() {
	if s.committed {
		return
	}
	s.committed = true
	copyHeaders(s.w, s.header)
	s.w.Header().Set("Content-Type", "application/x-ndjson; charset=utf-8")
	s.w.Header().Del("Content-Length")
	s.w.WriteHeader(http.StatusOK)
	// Un flux peut durer plus que le délai d'écriture du serveur : on le lève pour cette réponse.
	_ = http.NewResponseController(s.w).SetWriteDeadline(time.Time{})
}

func (s *streamWriter) flush() {
	if f, ok := s.w.(http.Flusher); ok {
		f.Flush()
	}
}

// drain décode et écrit tous les messages complets du tampon.
func (s *streamWriter) drain() error {
	for len(s.pending) >= 5 {
		n := int(binary.BigEndian.Uint32(s.pending[1:5]))
		if int64(n) > s.t.maxResponse {
			return fmt.Errorf("message de %d octets au-delà de max_response_body", n)
		}
		if len(s.pending)-5 < n {
			return nil
		}
		flag, payload := s.pending[0], s.pending[5:5+n]
		s.pending = s.pending[5+n:]
		if flag&1 != 0 {
			if !strings.EqualFold(s.header.Get("Grpc-Encoding"), "gzip") {
				return fmt.Errorf("compression %q non prise en charge", s.header.Get("Grpc-Encoding"))
			}
			zr, err := gzip.NewReader(bytes.NewReader(payload))
			if err != nil {
				return err
			}
			payload, err = io.ReadAll(io.LimitReader(zr, s.t.maxResponse))
			zr.Close()
			if err != nil {
				return err
			}
		}
		msg := dynamicpb.NewMessage(s.b.method.Output())
		if err := proto.Unmarshal(payload, msg); err != nil {
			return err
		}
		js, err := s.t.marshalJSON(s.b, msg)
		if err != nil {
			return err
		}
		var line bytes.Buffer
		line.WriteString(`{"result":`)
		if err := json.Compact(&line, js); err != nil {
			return err
		}
		line.WriteString("}\n")
		s.commit()
		if _, err := s.w.Write(line.Bytes()); err != nil {
			return err
		}
		s.flush()
		s.sent++
	}
	return nil
}

// writeErrorLine termine un flux déjà entamé par une ligne {"error": …}.
func (s *streamWriter) writeErrorLine(code int, msg string, body map[string]any) {
	if body == nil {
		body = map[string]any{"code": code, "message": msg, "details": []any{}}
	}
	line, _ := json.Marshal(map[string]any{"error": body})
	_, _ = s.w.Write(append(line, '\n'))
	s.flush()
}

// finish conclut la réponse une fois le proxy terminé : statut gRPC final, erreur éventuelle.
func (s *streamWriter) finish() {
	switch s.mode {
	case modePassthrough:
		s.count("upstream_error")
		return
	case modeUndecided:
		s.count("upstream_error")
		writeStatus(s.w, http.StatusBadGateway, 14, "aucune réponse du backend")
		return
	}
	code := 2
	if st := trailer(s.header, "Grpc-Status"); st != "" {
		if n, err := strconv.Atoi(st); err == nil {
			code = n
		}
	}
	if s.failure != nil {
		s.count("upstream_error")
		if !s.committed {
			writeStatus(s.w, http.StatusBadGateway, 13, "réponse gRPC illisible : "+s.failure.Error())
			return
		}
		s.writeErrorLine(13, "réponse gRPC illisible : "+s.failure.Error(), nil)
		return
	}
	if code != 0 {
		s.count("grpc_error")
		if !s.committed {
			writeGRPCErrorFrom(s.w, s.header, code)
			return
		}
		s.writeErrorLine(code, "", grpcErrorBody(s.header, code))
		return
	}
	s.count("ok")
	s.commit() // flux vide mais réussi : 200 sans ligne
}
