// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package grpctrans

import (
	"bufio"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/vincamok/goproxify/internal/edge/router"
)

const streamProto = `
syntax = "proto3";
package demo.v1;

import "google/api/annotations.proto";

message WatchRequest { string id = 1; int32 count = 2; }
message Event { string id = 1; int32 seq = 2; }
message Chunk { string data = 1; string room = 2; }
message UploadResult { int32 count = 1; string joined = 2; string room = 3; }
message ChatMsg { string text = 1; string room = 2; }

service Streams {
  rpc Watch(WatchRequest) returns (stream Event) {
    option (google.api.http) = { get: "/v1/watch/{id}" };
  }
  rpc WatchBody(WatchRequest) returns (stream Event) {
    option (google.api.http) = { get: "/v1/watch-body/{id}" response_body: "seq" };
  }
  rpc Upload(stream Chunk) returns (UploadResult) {
    option (google.api.http) = { post: "/v1/rooms/{room}/upload" body: "*" };
  }
  rpc Chat(stream ChatMsg) returns (stream ChatMsg) {
    option (google.api.http) = { post: "/v1/chat" body: "*" };
  }
}
`

func streamConfig(mut func(*router.GRPCTranscodeConfig)) *router.GRPCTranscodeConfig {
	c := &router.GRPCTranscodeConfig{Enabled: true, Proto: map[string]string{"streams.proto": streamProto}}
	if mut != nil {
		mut(c)
	}
	return c
}

// splitFrames découpe un corps gRPC en messages.
func splitFrames(raw []byte) [][]byte {
	var out [][]byte
	for len(raw) >= 5 {
		n := int(binary.BigEndian.Uint32(raw[1:5]))
		out = append(out, raw[5:5+n])
		raw = raw[5+n:]
	}
	return out
}

func newStreamBackend(t *testing.T, tr *Transcoder) *httptest.Server {
	t.Helper()
	byPath := map[string]*binding{}
	for _, b := range tr.bindings {
		byPath[b.grpcPath] = b
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := byPath[r.URL.Path]
		raw, _ := io.ReadAll(r.Body)
		if b == nil {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Grpc-Status", "12")
			return
		}
		var inputs []*dynamicpb.Message
		for _, fr := range splitFrames(raw) {
			m := dynamicpb.NewMessage(b.method.Input())
			if err := proto.Unmarshal(fr, m); err != nil {
				w.Header().Set("Content-Type", "application/grpc")
				w.Header().Set("Grpc-Status", "3")
				return
			}
			inputs = append(inputs, m)
		}
		str := func(m *dynamicpb.Message, f string) string {
			return m.Get(m.Descriptor().Fields().ByName(protoreflect.Name(f))).String()
		}
		num := func(m *dynamicpb.Message, f string) int64 {
			return m.Get(m.Descriptor().Fields().ByName(protoreflect.Name(f))).Int()
		}
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		send := func(m proto.Message) {
			p, _ := proto.Marshal(m)
			_, _ = w.Write(frame(p))
			if f, ok := w.(http.Flusher); ok {
				f.Flush()
			}
		}
		finish := func(code, msg string) {
			w.Header().Set("Grpc-Status", code)
			w.Header().Set("Grpc-Message", url.PathEscape(msg))
		}

		switch string(b.method.Name()) {
		case "Watch", "WatchBody":
			in := inputs[0]
			id := str(in, "id")
			if id == "denied" { // refus avant tout message
				finish("7", "accès refusé")
				return
			}
			n := int(num(in, "count"))
			if n == 0 && id != "empty" {
				n = 3
			}
			for i := 1; i <= n; i++ {
				ev := dynamicpb.NewMessage(b.method.Output())
				ev.Set(ev.Descriptor().Fields().ByName("id"), protoreflect.ValueOfString(id))
				ev.Set(ev.Descriptor().Fields().ByName("seq"), protoreflect.ValueOfInt32(int32(i)))
				send(ev)
			}
			if id == "fail" {
				finish("5", "flux interrompu")
				return
			}
			finish("0", "")
		case "Upload":
			out := dynamicpb.NewMessage(b.method.Output())
			var joined []string
			room := ""
			for _, m := range inputs {
				joined = append(joined, str(m, "data"))
				room = str(m, "room")
			}
			set := func(f string, v protoreflect.Value) { out.Set(out.Descriptor().Fields().ByName(protoreflect.Name(f)), v) }
			set("count", protoreflect.ValueOfInt32(int32(len(inputs))))
			set("joined", protoreflect.ValueOfString(strings.Join(joined, "+")))
			set("room", protoreflect.ValueOfString(room))
			send(out)
			finish("0", "")
		case "Chat":
			for _, m := range inputs {
				out := dynamicpb.NewMessage(b.method.Output())
				out.Set(out.Descriptor().Fields().ByName("text"), protoreflect.ValueOfString("echo:"+str(m, "text")))
				out.Set(out.Descriptor().Fields().ByName("room"), protoreflect.ValueOfString(str(m, "room")))
				send(out)
			}
			finish("0", "")
		}
	})
	srv := httptest.NewUnstartedServer(h)
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv.Config.Protocols = &p
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

func newStreamFixture(t *testing.T, cfg *router.GRPCTranscodeConfig) *fixture {
	t.Helper()
	tr, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{h: Middleware("api.example.fr", cfg)(proxyTo(t, newStreamBackend(t, tr)))}
}

func lines(rec *httptest.ResponseRecorder) []string {
	var out []string
	sc := bufio.NewScanner(strings.NewReader(rec.Body.String()))
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) != "" {
			out = append(out, sc.Text())
		}
	}
	return out
}

func TestServerStreamingAsNDJSON(t *testing.T) {
	f := newStreamFixture(t, streamConfig(nil))
	rec := f.do("GET", "/v1/watch/room1?count=3", "", "")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/x-ndjson") {
		t.Fatalf("Content-Type = %q", ct)
	}
	ls := lines(rec)
	if len(ls) != 3 {
		t.Fatalf("%d lignes, attendu 3 : %q", len(ls), rec.Body.String())
	}
	for i, l := range ls {
		var m struct {
			Result map[string]any `json:"result"`
		}
		if err := json.Unmarshal([]byte(l), &m); err != nil || m.Result["id"] != "room1" || m.Result["seq"] != float64(i+1) {
			t.Fatalf("ligne %d : %q (%v)", i, l, err)
		}
	}
}

func TestServerStreamingErrorMidStream(t *testing.T) {
	f := newStreamFixture(t, streamConfig(nil))
	rec := f.do("GET", "/v1/watch/fail", "", "")
	if rec.Code != 200 {
		t.Fatalf("les messages déjà envoyés gardent le statut 200 : %d", rec.Code)
	}
	ls := lines(rec)
	if len(ls) != 4 {
		t.Fatalf("3 messages + 1 ligne d'erreur attendus : %q", ls)
	}
	var last struct {
		Error map[string]any `json:"error"`
	}
	if err := json.Unmarshal([]byte(ls[3]), &last); err != nil || last.Error["code"] != float64(5) || last.Error["message"] != "flux interrompu" {
		t.Fatalf("dernière ligne : %q", ls[3])
	}
}

func TestServerStreamingErrorBeforeAnyMessageKeepsHTTPStatus(t *testing.T) {
	f := newStreamFixture(t, streamConfig(nil))
	rec := f.do("GET", "/v1/watch/denied", "", "")
	if rec.Code != 403 {
		t.Fatalf("PERMISSION_DENIED sans message : %d %s", rec.Code, rec.Body.String())
	}
	var m map[string]any
	if json.Unmarshal(rec.Body.Bytes(), &m) != nil || m["code"] != float64(7) || m["message"] != "accès refusé" {
		t.Fatalf("corps : %s", rec.Body.String())
	}
}

func TestServerStreamingEmptySuccess(t *testing.T) {
	f := newStreamFixture(t, streamConfig(nil))
	rec := f.do("GET", "/v1/watch/empty", "", "")
	if rec.Code != 200 || len(lines(rec)) != 0 {
		t.Fatalf("flux vide : %d %q", rec.Code, rec.Body.String())
	}
}

func TestServerStreamingResponseBody(t *testing.T) {
	f := newStreamFixture(t, streamConfig(nil))
	rec := f.do("GET", "/v1/watch-body/x?count=2", "", "")
	ls := lines(rec)
	if rec.Code != 200 || len(ls) != 2 || ls[0] != `{"result":1}` || ls[1] != `{"result":2}` {
		t.Fatalf("response_body par message : %d %q", rec.Code, ls)
	}
}

func TestClientStreamingFromNDJSONAndArray(t *testing.T) {
	f := newStreamFixture(t, streamConfig(nil))
	rec := f.do("POST", "/v1/rooms/lobby/upload", "application/x-ndjson", "{\"data\":\"a\"}\n{\"data\":\"b\"}\n{\"data\":\"c\"}\n")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	m := jsonOf(t, rec)
	if m["count"] != float64(3) || m["joined"] != "a+b+c" || m["room"] != "lobby" {
		t.Fatalf("réponse : %v (la variable de chemin s'applique à chaque message)", m)
	}
	// tableau JSON
	rec = f.do("POST", "/v1/rooms/r2/upload", "application/json", `[{"data":"x"},{"data":"y"}]`)
	if m := jsonOf(t, rec); m["count"] != float64(2) || m["joined"] != "x+y" {
		t.Fatalf("tableau : %v", m)
	}
	// flux vide
	rec = f.do("POST", "/v1/rooms/r3/upload", "application/json", ``)
	if rec.Code != 200 || jsonOf(t, rec)["room"] != nil {
		t.Fatalf("flux client vide : %d %s", rec.Code, rec.Body.String())
	}
}

func TestClientStreamingRejectsBadMessages(t *testing.T) {
	f := newStreamFixture(t, streamConfig(nil))
	rec := f.do("POST", "/v1/rooms/r/upload", "application/x-ndjson", "{\"data\":\"a\"}\n{\"unknown\":1}\n")
	m := jsonOf(t, rec)
	if rec.Code != 400 || !strings.Contains(m["message"].(string), "message 2") {
		t.Fatalf("le message fautif doit être désigné : %d %v", rec.Code, m)
	}
	if rec := f.do("POST", "/v1/rooms/r/upload", "application/json", `{"data":"a"} {nope`); rec.Code != 400 {
		t.Fatalf("JSON cassé : %d", rec.Code)
	}
	if rec := f.do("POST", "/v1/rooms/r/upload", "application/json", `[1, 2`); rec.Code != 400 {
		t.Fatalf("tableau cassé : %d", rec.Code)
	}
}

func TestBidirectionalStreaming(t *testing.T) {
	f := newStreamFixture(t, streamConfig(nil))
	rec := f.do("POST", "/v1/chat", "application/x-ndjson", "{\"text\":\"un\",\"room\":\"r\"}\n{\"text\":\"deux\"}\n")
	ls := lines(rec)
	if rec.Code != 200 || len(ls) != 2 || !strings.Contains(ls[0], `"echo:un"`) || !strings.Contains(ls[1], `"echo:deux"`) {
		t.Fatalf("flux bidirectionnel : %d %q", rec.Code, ls)
	}
}

func TestStreamingBindingsAreListed(t *testing.T) {
	errs, routes := Validate(streamConfig(nil))
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	joined := strings.Join(routes, "\n")
	for _, want := range []string{"[flux serveur]", "[flux client]", "[flux bidirectionnel]"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%q absent des routes :\n%s", want, joined)
		}
	}
}

func TestClientStreamingRequiresBodyStar(t *testing.T) {
	src := strings.Replace(streamProto, `post: "/v1/rooms/{room}/upload" body: "*"`, `post: "/v1/rooms/{room}/upload" body: "data"`, 1)
	errs, _ := Validate(&router.GRPCTranscodeConfig{Enabled: true, Proto: map[string]string{"s.proto": src}})
	if len(errs) == 0 || !strings.Contains(errs[0], "flux client") {
		t.Fatalf("body autre que * pour un flux client : %v", errs)
	}
}

func TestStreamUpstreamFailurePassedThrough(t *testing.T) {
	h := Middleware("h", streamConfig(nil))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "backend injoignable", http.StatusBadGateway)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/watch/x", nil))
	if rec.Code != 502 || !strings.Contains(rec.Body.String(), "backend injoignable") {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
}

func TestStreamMessageOverLimitAbortsCleanly(t *testing.T) {
	cfg := streamConfig(func(c *router.GRPCTranscodeConfig) { c.MaxResponseBody = 3 })
	f := newStreamFixture(t, cfg)
	rec := f.do("GET", "/v1/watch/overlimit?count=1", "", "")
	if rec.Code != 502 {
		t.Fatalf("message au-delà de la limite avant tout envoi : %d %s", rec.Code, rec.Body.String())
	}
}

// TestServerStreamingIsDeliveredIncrementally vérifie que le premier message atteint le client avant
// que le backend n'ait envoyé le suivant (la réponse n'est pas mise en mémoire jusqu'à la fin).
func TestServerStreamingIsDeliveredIncrementally(t *testing.T) {
	cfg := streamConfig(nil)
	tr, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	var watch *binding
	for _, b := range tr.bindings {
		if string(b.method.Name()) == "Watch" {
			watch = b
		}
	}
	release := make(chan struct{})
	backend := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		w.Header().Set("Content-Type", "application/grpc")
		w.Header().Set("Trailer", "Grpc-Status")
		send := func(seq int32) {
			ev := dynamicpb.NewMessage(watch.method.Output())
			ev.Set(ev.Descriptor().Fields().ByName("seq"), protoreflect.ValueOfInt32(seq))
			p, _ := proto.Marshal(ev)
			_, _ = w.Write(frame(p))
			w.(http.Flusher).Flush()
		}
		send(1)
		select {
		case <-release:
		case <-r.Context().Done():
			return
		}
		send(2)
		w.Header().Set("Grpc-Status", "0")
	}))
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	backend.Config.Protocols = &p
	backend.Start()
	defer backend.Close()

	front := httptest.NewServer(Middleware("h", cfg)(proxyTo(t, backend)))
	defer front.Close()
	resp, err := http.Get(front.URL + "/v1/watch/x")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	br := bufio.NewReader(resp.Body)
	first := make(chan string, 1)
	go func() {
		l, _ := br.ReadString('\n')
		first <- l
	}()
	select {
	case l := <-first:
		if !strings.Contains(l, `"seq":1`) {
			t.Fatalf("premier message : %q", l)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("le premier message n'est pas livré avant la fin du flux : la réponse est mise en mémoire")
	}
	close(release)
	second, err := br.ReadString('\n')
	if err != nil || !strings.Contains(second, `"seq":2`) {
		t.Fatalf("second message : %q %v", second, err)
	}
}
