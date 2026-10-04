// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package grpctrans

import (
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"strings"
	"testing"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
	"google.golang.org/protobuf/types/dynamicpb"

	"github.com/vincamok/goproxify/internal/edge/router"
)

const demoProto = `
syntax = "proto3";
package demo.v1;

import "google/api/annotations.proto";
import "google/protobuf/timestamp.proto";

enum Role { ROLE_UNSPECIFIED = 0; ADMIN = 1; GUEST = 2; }

message User {
  string id = 1;
  string name = 2;
  int32 age = 3;
  Role role = 4;
  google.protobuf.Timestamp created = 5;
  repeated string tags = 6;
}
message GetUserRequest { string id = 1; bool verbose = 2; }
message ListUsersRequest { int32 page_size = 1; repeated string tags = 2; Role role = 3; google.protobuf.Timestamp since = 4; }
message ListUsersResponse { repeated User users = 1; string next = 2; }
message CreateUserRequest { User user = 1; string org = 2; }
message UpdateUserRequest { User user = 1; }
message PingRequest { string who = 1; }
message PingResponse { string pong = 1; }

service Users {
  rpc GetUser(GetUserRequest) returns (User) {
    option (google.api.http) = { get: "/v1/users/{id}" };
  }
  rpc ListUsers(ListUsersRequest) returns (ListUsersResponse) {
    option (google.api.http) = { get: "/v1/users" response_body: "users" };
  }
  rpc CreateUser(CreateUserRequest) returns (User) {
    option (google.api.http) = {
      post: "/v1/users" body: "user"
      additional_bindings { post: "/v1/{org=organizations/*}/users" body: "user" }
    };
  }
  rpc UpdateUser(UpdateUserRequest) returns (User) {
    option (google.api.http) = { patch: "/v1/users/{user.id}" body: "user" };
  }
  rpc Ping(PingRequest) returns (PingResponse);
  rpc Watch(GetUserRequest) returns (stream User) {
    option (google.api.http) = { get: "/v1/watch" };
  }
}
`

func demoConfig(mut func(*router.GRPCTranscodeConfig)) *router.GRPCTranscodeConfig {
	c := &router.GRPCTranscodeConfig{Enabled: true, Proto: map[string]string{"demo.proto": demoProto}, AutoMapping: true}
	if mut != nil {
		mut(c)
	}
	return c
}

// frame écrit un message gRPC cadré.
func frame(msg []byte) []byte {
	out := make([]byte, 5+len(msg))
	binary.BigEndian.PutUint32(out[1:5], uint32(len(msg)))
	copy(out[5:], msg)
	return out
}

// newBackend démarre un faux backend gRPC en h2c : il décode la requête, la republie en JSON dans
// l'en-tête X-Received et répond selon la méthode. Retourne l'URL et le transcodeur (pour les descripteurs).
func newBackend(t *testing.T, tr *Transcoder) *httptest.Server {
	t.Helper()
	byPath := map[string]*binding{}
	for _, b := range tr.bindings {
		byPath[b.grpcPath] = b
	}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := byPath[r.URL.Path]
		raw, _ := io.ReadAll(r.Body)
		if b == nil || r.Header.Get("Content-Type") != "application/grpc" || len(raw) < 5 {
			w.Header().Set("Content-Type", "application/grpc")
			w.Header().Set("Grpc-Status", "12")
			w.Header().Set("Grpc-Message", "inconnu")
			return
		}
		in := dynamicpb.NewMessage(b.method.Input())
		if err := proto.Unmarshal(raw[5:], in); err != nil {
			w.Header().Set("Grpc-Status", "3")
			return
		}
		recv, _ := protojson.Marshal(in)
		w.Header().Set("X-Received", string(recv))
		w.Header().Set("X-Meta-Tenant", r.Header.Get("Tenant"))
		w.Header().Set("Content-Type", "application/grpc")

		out := dynamicpb.NewMessage(b.method.Output())
		fail := func(code string, msg string, details *status.Status) {
			w.Header().Set("Grpc-Status", code)
			w.Header().Set("Grpc-Message", url.PathEscape(msg))
			if details != nil {
				bin, _ := proto.Marshal(details)
				w.Header().Set("Grpc-Status-Details-Bin", base64.RawStdEncoding.EncodeToString(bin))
			}
		}
		set := func(m protoreflect.Message, name string, v protoreflect.Value) {
			m.Set(m.Descriptor().Fields().ByName(protoreflect.Name(name)), v)
		}
		switch string(b.method.Name()) {
		case "GetUser":
			id := in.Get(in.Descriptor().Fields().ByName("id")).String()
			if id == "404" {
				fail("5", "utilisateur 404 introuvable", nil)
				return
			}
			if id == "bad" {
				d, _ := anyBadRequest()
				fail("3", "requête invalide", d)
				return
			}
			set(out, "id", protoreflect.ValueOfString(id))
			set(out, "name", protoreflect.ValueOfString("Ada"))
			set(out, "age", protoreflect.ValueOfInt32(36))
		case "ListUsers":
			users := out.Mutable(out.Descriptor().Fields().ByName("users")).List()
			for _, n := range []string{"a", "b"} {
				u := users.NewElement().Message()
				set(u, "id", protoreflect.ValueOfString(n))
				users.Append(protoreflect.ValueOfMessage(u))
			}
		case "CreateUser", "UpdateUser":
			u := in.Get(in.Descriptor().Fields().ByName("user")).Message()
			out = dynamicpb.NewMessage(b.method.Output())
			proto.Merge(out, u.Interface())
			if org := in.Descriptor().Fields().ByName("org"); org != nil {
				w.Header().Set("X-Org", in.Get(org).String())
			}
		case "Ping":
			set(out, "pong", protoreflect.ValueOfString("pong:"+in.Get(in.Descriptor().Fields().ByName("who")).String()))
		}
		payload, _ := proto.Marshal(out)
		w.Header().Set("Trailer", "Grpc-Status, Grpc-Message")
		_, _ = w.Write(frame(payload))
		w.Header().Set("Grpc-Status", "0")
		w.Header().Set("Grpc-Message", "")
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

func anyBadRequest() (*status.Status, error) {
	d := &errdetails.BadRequest{FieldViolations: []*errdetails.BadRequest_FieldViolation{{Field: "id", Description: "format invalide"}}}
	a, err := anypbNew(d)
	if err != nil {
		return nil, err
	}
	return &status.Status{Code: 3, Message: "requête invalide", Details: a}, nil
}

// proxyTo retourne un ReverseProxy en h2c vers le backend (même mécanique que la passerelle).
func proxyTo(t *testing.T, backend *httptest.Server) http.Handler {
	t.Helper()
	u, _ := url.Parse(backend.URL)
	var p http.Protocols
	p.SetHTTP2(true)
	p.SetUnencryptedHTTP2(true)
	return &httputil.ReverseProxy{
		Rewrite:   func(pr *httputil.ProxyRequest) { pr.SetURL(u) },
		Transport: &http.Transport{Protocols: &p, ForceAttemptHTTP2: true},
	}
}

type fixture struct {
	h http.Handler
}

func newFixture(t *testing.T, cfg *router.GRPCTranscodeConfig) *fixture {
	t.Helper()
	tr, err := Compile(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return &fixture{h: Middleware("api.example.fr", cfg)(proxyTo(t, newBackend(t, tr)))}
}

func (f *fixture) do(method, target, ctype, body string, hdr ...string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, target, strings.NewReader(body))
	if ctype != "" {
		req.Header.Set("Content-Type", ctype)
	}
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func jsonOf(t *testing.T, rec *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatalf("JSON attendu : %v — %q", err, rec.Body.String())
	}
	return m
}

func TestTranscodeGetWithPathAndQuery(t *testing.T) {
	f := newFixture(t, demoConfig(nil))
	rec := f.do("GET", "/v1/users/42?verbose=true&cache_buster=9", "", "", "Grpc-Metadata-Tenant", "acme")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "application/json") {
		t.Fatalf("Content-Type = %q", ct)
	}
	m := jsonOf(t, rec)
	if m["id"] != "42" || m["name"] != "Ada" || m["age"] != float64(36) {
		t.Fatalf("réponse : %v", m)
	}
	if got := rec.Header().Get("X-Received"); !sameJSON(got, `{"id":"42","verbose":true}`) {
		t.Fatalf("le backend a reçu %s", got)
	}
	if rec.Header().Get("X-Meta-Tenant") != "acme" {
		t.Fatalf("métadonnée Grpc-Metadata-Tenant non transmise : %v", rec.Header())
	}
}

func TestTranscodeResponseBodyAndQueryTypes(t *testing.T) {
	f := newFixture(t, demoConfig(nil))
	rec := f.do("GET", "/v1/users?page_size=20&tags=a&tags=b&role=ADMIN&since=2024-01-02T03:04:05Z", "", "")
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	var users []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &users); err != nil || len(users) != 2 || users[0]["id"] != "a" {
		t.Fatalf("response_body users : %v %s", err, rec.Body.String())
	}
	var got map[string]any
	_ = json.Unmarshal([]byte(rec.Header().Get("X-Received")), &got)
	if got["pageSize"] != float64(20) || got["role"] != "ADMIN" || got["since"] != "2024-01-02T03:04:05Z" || len(got["tags"].([]any)) != 2 {
		t.Fatalf("requête reçue : %v", got)
	}
}

func TestTranscodeBodyFieldAndAdditionalBinding(t *testing.T) {
	f := newFixture(t, demoConfig(nil))
	rec := f.do("POST", "/v1/users", "application/json", `{"name":"Bob","age":5,"tags":["x"]}`)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if m := jsonOf(t, rec); m["name"] != "Bob" || m["age"] != float64(5) {
		t.Fatalf("réponse : %v", m)
	}
	if got := rec.Header().Get("X-Received"); !sameJSON(got, `{"user":{"name":"Bob","age":5,"tags":["x"]}}`) {
		t.Fatalf("reçu : %s", got)
	}
	// liaison supplémentaire : la variable {org=organizations/*} capture deux segments
	rec = f.do("POST", "/v1/organizations/acme/users", "application/json", `{"name":"Eve"}`)
	if rec.Code != 200 || rec.Header().Get("X-Org") != "organizations/acme" {
		t.Fatalf("org : %d %q %s", rec.Code, rec.Header().Get("X-Org"), rec.Body.String())
	}
}

func TestTranscodeNestedPathVariable(t *testing.T) {
	f := newFixture(t, demoConfig(nil))
	rec := f.do("PATCH", "/v1/users/7", "application/json", `{"name":"Neo"}`)
	if rec.Code != 200 {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("X-Received"); !sameJSON(got, `{"user":{"id":"7","name":"Neo"}}`) {
		t.Fatalf("user.id doit fusionner avec le corps : %s", got)
	}
}

func TestTranscodeAutoMapping(t *testing.T) {
	f := newFixture(t, demoConfig(nil))
	rec := f.do("POST", "/demo.v1.Users/Ping", "application/json", `{"who":"moi"}`)
	if rec.Code != 200 || jsonOf(t, rec)["pong"] != "pong:moi" {
		t.Fatalf("%d %s", rec.Code, rec.Body.String())
	}
	// sans auto_mapping, la méthode non annotée n'est pas publiée
	g := newFixture(t, demoConfig(func(c *router.GRPCTranscodeConfig) { c.AutoMapping = false }))
	if rec := g.do("POST", "/demo.v1.Users/Ping", "application/json", `{}`); rec.Code != 404 {
		t.Fatalf("sans auto_mapping : %d", rec.Code)
	}
}

func TestTranscodeGRPCErrorsMapToHTTP(t *testing.T) {
	f := newFixture(t, demoConfig(nil))
	rec := f.do("GET", "/v1/users/404", "", "")
	m := jsonOf(t, rec)
	if rec.Code != 404 || m["code"] != float64(5) || m["message"] != "utilisateur 404 introuvable" {
		t.Fatalf("NOT_FOUND : %d %v", rec.Code, m)
	}
	rec = f.do("GET", "/v1/users/bad", "", "")
	m = jsonOf(t, rec)
	details, _ := m["details"].([]any)
	if rec.Code != 400 || len(details) != 1 || !strings.Contains(rec.Body.String(), "BadRequest") || !strings.Contains(rec.Body.String(), "format invalide") {
		t.Fatalf("INVALID_ARGUMENT avec détails : %d %s", rec.Code, rec.Body.String())
	}
}

func TestTranscodeRejectsBadRequests(t *testing.T) {
	f := newFixture(t, demoConfig(nil))
	for name, c := range map[string]struct {
		method, target, ctype, body string
		code                        int
	}{
		"route inconnue":   {"GET", "/v2/nope", "", "", 404},
		"verbe inconnu":    {"DELETE", "/v1/users/1", "", "", 405},
		"JSON cassé":       {"POST", "/v1/users", "application/json", `{nope`, 400},
		"champ inconnu":    {"POST", "/v1/users", "application/json", `{"unknown":1}`, 400},
		"entier invalide":  {"GET", "/v1/users?page_size=abc", "", "", 400},
		"énumération":      {"GET", "/v1/users?role=NOPE", "", "", 400},
		"booléen invalide": {"GET", "/v1/users/1?verbose=peut-etre", "", "", 400},
	} {
		rec := f.do(c.method, c.target, c.ctype, c.body)
		if rec.Code != c.code {
			t.Errorf("%s : %d (attendu %d) %s", name, rec.Code, c.code, rec.Body.String())
		}
		if m := jsonOf(t, rec); m["message"] == nil {
			t.Errorf("%s : pas de message", name)
		}
	}
	if rec := f.do("DELETE", "/v1/users/1", "", ""); rec.Header().Get("Allow") != "GET, PATCH" {
		t.Errorf("Allow = %q", rec.Header().Get("Allow"))
	}
	// un flux n'est pas publié
	if rec := f.do("GET", "/v1/watch", "", ""); rec.Code != 404 {
		t.Errorf("méthode à flux : %d", rec.Code)
	}
}

func TestTranscodeBodyTooLarge(t *testing.T) {
	f := newFixture(t, demoConfig(func(c *router.GRPCTranscodeConfig) { c.MaxRequestBody = 16 }))
	rec := f.do("POST", "/v1/users", "application/json", `{"name":"`+strings.Repeat("a", 100)+`"}`)
	if rec.Code != 413 {
		t.Fatalf("corps trop gros : %d", rec.Code)
	}
}

func TestTranscodeUpstreamFailureIsPassedThrough(t *testing.T) {
	cfg := demoConfig(nil)
	h := Middleware("h", cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "backend injoignable", http.StatusBadGateway)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/users/1", nil))
	if rec.Code != 502 || !strings.Contains(rec.Body.String(), "backend injoignable") {
		t.Fatalf("%d %q", rec.Code, rec.Body.String())
	}
}

func TestNativeGRPCPassesThrough(t *testing.T) {
	var gotPath string
	h := Middleware("h", demoConfig(nil))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.WriteHeader(204)
	}))
	req := httptest.NewRequest("POST", "/demo.v1.Users/GetUser", strings.NewReader("x"))
	req.Header.Set("Content-Type", "application/grpc+proto")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 204 || gotPath != "/demo.v1.Users/GetUser" {
		t.Fatalf("gRPC natif : %d %q", rec.Code, gotPath)
	}
}

func TestResponseTooLarge(t *testing.T) {
	cfg := demoConfig(func(c *router.GRPCTranscodeConfig) { c.MaxResponseBody = 8 })
	tr, _ := Compile(cfg)
	h := Middleware("h", cfg)(proxyTo(t, newBackend(t, tr)))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/v1/users/1", nil))
	if rec.Code != 502 {
		t.Fatalf("réponse trop grosse : %d %s", rec.Code, rec.Body.String())
	}
}

func TestEmitDefaultsAndProtoNames(t *testing.T) {
	f := newFixture(t, demoConfig(func(c *router.GRPCTranscodeConfig) { c.EmitDefaults = true; c.ProtoFieldNames = true }))
	m := jsonOf(t, f.do("GET", "/v1/users/9", "", ""))
	if _, ok := m["created"]; !ok {
		t.Fatalf("emit_defaults doit écrire created : %v", m)
	}
	if m["role"] != "ROLE_UNSPECIFIED" {
		t.Fatalf("role : %v", m["role"])
	}
}

func TestDescriptorSetRoundTrip(t *testing.T) {
	tr, err := Compile(demoConfig(nil))
	if err != nil {
		t.Fatal(err)
	}
	// FileDescriptorSet complet (avec imports) tel que le produit protoc --include_imports
	set := &descriptorpb.FileDescriptorSet{}
	seen := map[string]bool{}
	var add func(fd protoreflect.FileDescriptor)
	add = func(fd protoreflect.FileDescriptor) {
		if seen[fd.Path()] {
			return
		}
		seen[fd.Path()] = true
		imps := fd.Imports()
		for i := 0; i < imps.Len(); i++ {
			add(imps.Get(i).FileDescriptor)
		}
		set.File = append(set.File, protodesc.ToFileDescriptorProto(fd))
	}
	add(tr.bindings[0].method.ParentFile())
	raw, _ := proto.Marshal(set)

	tr2, err := Compile(&router.GRPCTranscodeConfig{Enabled: true, DescriptorSet: base64.StdEncoding.EncodeToString(raw), AutoMapping: true})
	if err != nil {
		t.Fatal(err)
	}
	if a, b := strings.Join(tr.Routes(), "\n"), strings.Join(tr2.Routes(), "\n"); a != b {
		t.Fatalf("routes différentes :\n%s\n---\n%s", a, b)
	}
	// sans --include_imports : google/protobuf et google/api viennent du binaire
	light := &descriptorpb.FileDescriptorSet{File: []*descriptorpb.FileDescriptorProto{set.File[len(set.File)-1]}}
	rawLight, _ := proto.Marshal(light)
	if _, err := Compile(&router.GRPCTranscodeConfig{Enabled: true, DescriptorSet: base64.StdEncoding.EncodeToString(rawLight), AutoMapping: true}); err != nil {
		t.Fatalf("imports bien connus attendus : %v", err)
	}
}

func TestCompileErrors(t *testing.T) {
	_ = protoregistry.GlobalFiles
	cases := map[string]*router.GRPCTranscodeConfig{
		"rien":                  {Enabled: true},
		"proto et set":          {Enabled: true, Proto: map[string]string{"a.proto": demoProto}, DescriptorSet: "AA=="},
		"proto invalide":        {Enabled: true, Proto: map[string]string{"a.proto": "syntax = \"proto3\"; message {"}},
		"base64 invalide":       {Enabled: true, DescriptorSet: "%%%"},
		"descripteur invalide":  {Enabled: true, DescriptorSet: base64.StdEncoding.EncodeToString([]byte("pas un descripteur"))},
		"service introuvable":   demoConfig(func(c *router.GRPCTranscodeConfig) { c.Services = []string{"demo.v1.Nope"} }),
		"aucune route publiée":  demoConfig(func(c *router.GRPCTranscodeConfig) { c.Services = nil; c.AutoMapping = false; c.Proto = map[string]string{"b.proto": "syntax = \"proto3\"; package p; message M {} service S { rpc F(M) returns (M); }"} }),
		"variable inconnue":     {Enabled: true, Proto: map[string]string{"c.proto": strings.Replace(demoProto, "{id}", "{nope}", 1)}},
		"gabarit sans slash":    {Enabled: true, Proto: map[string]string{"d.proto": strings.Replace(demoProto, `"/v1/users/{id}"`, `"v1/users"`, 1)}},
		"response_body inconnu": {Enabled: true, Proto: map[string]string{"e.proto": strings.Replace(demoProto, `"users"`, `"zzz"`, 1)}},
		"taille négative":       demoConfig(func(c *router.GRPCTranscodeConfig) { c.MaxRequestBody = -1 }),
	}
	for name, cfg := range cases {
		if errs, _ := Validate(cfg); len(errs) == 0 {
			t.Errorf("%s : aucune erreur", name)
		}
	}
	errs, routes := Validate(demoConfig(nil))
	if len(errs) != 0 || len(routes) < 5 {
		t.Fatalf("configuration valide : %v %v", errs, routes)
	}
	if errs, _ := Validate(&router.GRPCTranscodeConfig{Enabled: false}); errs != nil {
		t.Fatalf("désactivé : %v", errs)
	}
}

func TestTemplateMatching(t *testing.T) {
	for _, c := range []struct {
		tpl, path string
		ok        bool
		vars      map[string]string
	}{
		{"/v1/users/{id}", "/v1/users/42", true, map[string]string{"id": "42"}},
		{"/v1/users/{id}", "/v1/users/", false, nil},
		{"/v1/users/{id}", "/v1/users/a/b", false, nil},
		{"/v1/{name=projects/*}/items", "/v1/projects/p1/items", true, map[string]string{"name": "projects/p1"}},
		{"/v1/{name=projects/*/locations/*}", "/v1/projects/p/locations/eu", true, map[string]string{"name": "projects/p/locations/eu"}},
		{"/v1/files/{path=**}", "/v1/files/a/b/c.txt", true, map[string]string{"path": "a/b/c.txt"}},
		{"/v1/{name=things/**}:get", "/v1/things/x/y:get", true, map[string]string{"name": "things/x/y"}},
		{"/v1/{name=things/**}:get", "/v1/things/x/y", false, nil},
		{"/v1/users/{id}", "/v1/users/a%2Fb", true, map[string]string{"id": "a/b"}},
		{"/v1/*/ping", "/v1/x/ping", true, map[string]string{}},
		{"/v1/users:search", "/v1/users:search", true, map[string]string{}},
	} {
		tpl, err := parseTemplate(c.tpl)
		if err != nil {
			t.Fatalf("%s : %v", c.tpl, err)
		}
		vars, ok := tpl.match(c.path)
		if ok != c.ok {
			t.Errorf("%s ~ %s : %v, attendu %v", c.tpl, c.path, ok, c.ok)
			continue
		}
		for k, v := range c.vars {
			if vars[k] != v {
				t.Errorf("%s ~ %s : %s = %q, attendu %q", c.tpl, c.path, k, vars[k], v)
			}
		}
	}
	for _, bad := range []string{"users", "/a//b", "/a/{", "/a/{=x}", "/a/{x=}", "/a/{x=b{y}}", "/a/b:"} {
		if _, err := parseTemplate(bad); err == nil {
			t.Errorf("%q devrait être refusé", bad)
		}
	}
}

// sameJSON compare deux documents JSON sans tenir compte de l'espacement (protojson le randomise).
func sameJSON(a, b string) bool {
	var x, y any
	if json.Unmarshal([]byte(a), &x) != nil || json.Unmarshal([]byte(b), &y) != nil {
		return false
	}
	ja, _ := json.Marshal(x)
	jb, _ := json.Marshal(y)
	return string(ja) == string(jb)
}
