// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"sort"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func byBackend(insts []Instance) map[string]Instance {
	m := map[string]Instance{}
	for _, i := range insts {
		m[i.Backend] = i
	}
	return m
}

func TestConsul_ListsHealthyTaggedInstances(t *testing.T) {
	var healthQueries []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Consul-Token") != "acl" {
			http.Error(w, "ACL not found", http.StatusForbidden)
			return
		}
		switch {
		case r.URL.Path == "/v1/catalog/services":
			if r.URL.Query().Get("dc") != "dc1" {
				t.Errorf("datacenter absent : %s", r.URL.RawQuery)
			}
			_ = json.NewEncoder(w).Encode(map[string][]string{
				"web":    {"goproxify.enable=true", "goproxify.host=app.example.com"},
				"db":     {"primary"},
				"hidden": {"goproxify.enable=false"},
			})
		case r.URL.Path == "/v1/health/service/web":
			healthQueries = append(healthQueries, r.URL.RawQuery)
			_, _ = io.WriteString(w, `[
			 {"Node":{"Node":"n1","Address":"10.0.0.1"},"Service":{"ID":"web-1","Service":"web","Address":"10.1.0.1","Port":8080,
			  "Tags":["goproxify.enable=true","goproxify.host=app.example.com"],"Meta":{"goproxify.tls":"true","autre":"x"}}},
			 {"Node":{"Node":"n2","Address":"10.0.0.2"},"Service":{"ID":"web-2","Service":"web","Address":"","Port":8443,
			  "Tags":["goproxify.enable=true","goproxify.host=app.example.com","goproxify.scheme=https"],"Meta":{}}}]`)
		default:
			t.Errorf("appel inattendu : %s", r.URL)
		}
	}))
	defer srv.Close()

	c, err := NewConsul(ConsulConfig{Address: srv.URL + "/", Token: "acl", Datacenter: "dc1"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := c.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	m := byBackend(got)
	if len(got) != 2 || m["http://10.1.0.1:8080"].Key != "web-1@n1" || m["https://10.0.0.2:8443"].Key != "web-2@n2" {
		t.Fatalf("instances = %+v", got)
	}
	if m["http://10.1.0.1:8080"].Labels["goproxify.tls"] != "true" || m["http://10.1.0.1:8080"].Labels["goproxify.host"] != "app.example.com" {
		t.Errorf("étiquettes (tags + méta) = %v", m["http://10.1.0.1:8080"].Labels)
	}
	if len(healthQueries) != 1 || !strings.Contains(healthQueries[0], "passing=1") {
		t.Errorf("seules les instances saines doivent être demandées : %v", healthQueries)
	}

	if _, err := (&Consul{cfg: ConsulConfig{Address: srv.URL, Token: "mauvais", Prefix: "goproxify."}, client: srv.Client()}).List(context.Background()); err == nil || !strings.Contains(err.Error(), "403") {
		t.Errorf("ACL refusée : %v", err)
	}
}

func TestNomad_ListsServicesAcrossNamespaces(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Nomad-Token") != "tok" {
			http.Error(w, "Permission denied", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/v1/services":
			if r.URL.Query().Get("namespace") != "*" {
				t.Errorf("namespace = %q", r.URL.Query().Get("namespace"))
			}
			_, _ = io.WriteString(w, `[{"Namespace":"default","Services":[{"ServiceName":"api","Tags":["goproxify.enable=true","goproxify.host=api.example.com"]},{"ServiceName":"cache","Tags":["x"]}]},
			 {"Namespace":"prod","Services":[{"ServiceName":"api","Tags":["goproxify.enable=true","goproxify.host=api.prod.example.com"]}]}]`)
		case "/v1/service/api":
			ns := r.URL.Query().Get("namespace")
			_, _ = fmt.Fprintf(w, `[{"ID":"_nomad-task-%s-1","ServiceName":"api","Namespace":%q,"Address":"10.2.0.%d","Port":9000,"Tags":["goproxify.enable=true","goproxify.host=api-%s.example.com"]}]`, ns, ns, len(ns), ns)
		default:
			t.Errorf("appel inattendu : %s", r.URL)
		}
	}))
	defer srv.Close()

	n, err := NewNomad(NomadConfig{Address: srv.URL, Token: "tok"})
	if err != nil {
		t.Fatal(err)
	}
	got, err := n.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Key != "default/_nomad-task-default-1" || got[1].Key != "prod/_nomad-task-prod-1" {
		t.Fatalf("instances = %+v", got)
	}
	if got[1].Labels["goproxify.host"] != "api-prod.example.com" {
		t.Errorf("labels = %v", got[1].Labels)
	}
}

func etcdKV(key, value string) map[string]string {
	return map[string]string{"key": base64.StdEncoding.EncodeToString([]byte(key)), "value": base64.StdEncoding.EncodeToString([]byte(value))}
}

func TestEtcd_ReadsServiceRecordsWithAuthAndFailover(t *testing.T) {
	var auths, ranges atomic.Int32
	live := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]string
		_ = json.NewDecoder(r.Body).Decode(&body)
		switch r.URL.Path {
		case "/v3/auth/authenticate":
			if body["name"] != "gpx" || body["password"] != "pw" {
				http.Error(w, `{"error":"etcdserver: authentication failed"}`, http.StatusBadRequest)
				return
			}
			n := auths.Add(1)
			_ = json.NewEncoder(w).Encode(map[string]string{"token": fmt.Sprintf("tok%d", n)})
		case "/v3/kv/range":
			n := ranges.Add(1)
			// Le premier jeton expire avant la deuxième lecture.
			if r.Header.Get("Authorization") == "tok1" && n > 1 {
				http.Error(w, `{"error":"etcdserver: invalid auth token"}`, http.StatusUnauthorized)
				return
			}
			if r.Header.Get("Authorization") == "" {
				http.Error(w, "jeton requis", http.StatusUnauthorized)
				return
			}
			key, _ := base64.StdEncoding.DecodeString(body["key"])
			end, _ := base64.StdEncoding.DecodeString(body["range_end"])
			if string(key) != "/goproxify/services/" || string(end) != "/goproxify/services0" {
				t.Errorf("plage = %q → %q", key, end)
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"kvs": []map[string]string{
				etcdKV("/goproxify/services/web-1", `{"host":"app.example.com","backend":"http://10.3.0.1:80","labels":{"tls":"true","goproxify.waf":"on"}}`),
				etcdKV("/goproxify/services/web-2", `{"host":"app.example.com","backend":"http://10.3.0.2:80"}`),
				etcdKV("/goproxify/services/cassé", `pas du json`),
				etcdKV("/goproxify/services/sans-hote", `{"backend":"http://10.3.0.3:80"}`),
				etcdKV("/goproxify/services/schema", `{"host":"x.example.com","backend":"file:///etc/passwd"}`),
			}})
		}
	}))
	defer live.Close()
	dead := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "down", http.StatusServiceUnavailable) }))
	dead.Close() // refuse les connexions

	e, err := NewEtcd(EtcdConfig{Endpoints: []string{dead.URL, live.URL}, Username: "gpx", Password: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ { // la seconde lecture traverse l'expiration du jeton
		got, err := e.List(context.Background())
		if err != nil {
			t.Fatalf("lecture %d : %v", i+1, err)
		}
		m := byBackend(got)
		if len(got) != 2 {
			t.Fatalf("instances = %+v", got)
		}
		l := m["http://10.3.0.1:80"].Labels
		if l["goproxify.tls"] != "true" || l["goproxify.waf"] != "on" || l["goproxify.host"] != "app.example.com" || l["goproxify.enable"] != "true" {
			t.Errorf("étiquettes = %v", l)
		}
	}
	if auths.Load() != 2 {
		t.Errorf("authentifications = %d (une au début, une après l'expiration)", auths.Load())
	}

	bad, _ := NewEtcd(EtcdConfig{Endpoints: []string{live.URL}, Username: "gpx", Password: "faux"})
	if _, err := bad.List(context.Background()); err == nil {
		t.Error("mauvais mot de passe accepté")
	}
}

func TestEtcd_PrefixEnd(t *testing.T) {
	for in, want := range map[string]string{"/a/": "/a0", "abc": "abd", "a\xff": "b"} {
		if got := prefixEnd(in); got != want {
			t.Errorf("prefixEnd(%q) = %q, attendu %q", in, got, want)
		}
	}
}

// Vecteur « post-vanilla » de la suite de tests officielle de Signature Version 4 (AWS) : si ce calcul dérive, aucune
// requête ECS ne passera.
func TestSigV4_AWSPostVanillaVector(t *testing.T) {
	req, _ := http.NewRequest(http.MethodPost, "https://example.amazonaws.com/", nil)
	req.Header.Set("Host", "example.amazonaws.com")
	c := &awsCreds{key: "AKIDEXAMPLE", secret: "wJalrXUtnFEMI/K7MDENG+bPxRfiCYEXAMPLEKEY"}
	sign(req, nil, c, "us-east-1", "service", []string{"host", "x-amz-date"}, time.Date(2015, 8, 30, 12, 36, 0, 0, time.UTC))
	want := "AWS4-HMAC-SHA256 Credential=AKIDEXAMPLE/20150830/us-east-1/service/aws4_request, SignedHeaders=host;x-amz-date, Signature=5da7c1a2acd57cee7505fc6676e4e544621c30862966e37dddb68e92efbe5d6b"
	if got := req.Header.Get("Authorization"); got != want {
		t.Fatalf("Authorization =\n%s\nattendu\n%s", got, want)
	}
}

func TestECS_ListsRunningTasksWithAnIP(t *testing.T) {
	var defCalls, listCalls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("Authorization"), "AWS4-HMAC-SHA256 Credential=AKIA/") || r.Header.Get("X-Amz-Security-Token") != "sess" {
			http.Error(w, "signature absente", http.StatusForbidden)
			return
		}
		var body map[string]any
		_ = json.NewDecoder(r.Body).Decode(&body)
		if body["cluster"] != "prod" && r.Header.Get("X-Amz-Target") != "AmazonEC2ContainerServiceV20141113.DescribeTaskDefinition" {
			t.Errorf("cluster = %v", body["cluster"])
		}
		switch strings.TrimPrefix(r.Header.Get("X-Amz-Target"), "AmazonEC2ContainerServiceV20141113.") {
		case "ListTasks":
			if listCalls.Add(1) == 1 {
				_, _ = io.WriteString(w, `{"taskArns":["arn:aws:ecs:eu-west-1:1:task/prod/a","arn:aws:ecs:eu-west-1:1:task/prod/b"],"nextToken":"page2"}`)
				return
			}
			if body["nextToken"] != "page2" {
				t.Errorf("nextToken = %v", body["nextToken"])
			}
			_, _ = io.WriteString(w, `{"taskArns":["arn:aws:ecs:eu-west-1:1:task/prod/c","arn:aws:ecs:eu-west-1:1:task/prod/d"]}`)
		case "DescribeTasks":
			if inc, _ := body["include"].([]any); len(inc) != 1 || inc[0] != "TAGS" {
				t.Errorf("include = %v", body["include"])
			}
			tasks := []string{}
			for _, arn := range body["tasks"].([]any) {
				switch name := arn.(string)[strings.LastIndex(arn.(string), "/")+1:]; name {
				case "a": // saine, IP dans l'attachement ENI
					tasks = append(tasks, fmt.Sprintf(`{"taskArn":%q,"taskDefinitionArn":"td:1","lastStatus":"RUNNING","group":"service:web","attachments":[{"type":"ElasticNetworkInterface","details":[{"name":"privateIPv4Address","value":"10.4.0.1"}]}]}`, arn))
				case "b": // IP dans le conteneur, tags qui complètent les étiquettes
					tasks = append(tasks, fmt.Sprintf(`{"taskArn":%q,"taskDefinitionArn":"td:1","lastStatus":"RUNNING","containers":[{"name":"app","networkInterfaces":[{"privateIpv4Address":"10.4.0.2"}]}],"tags":[{"key":"goproxify.tls","value":"true"}]}`, arn))
				case "c": // pas de rôle réseau awsvpc : pas d'IP
					tasks = append(tasks, fmt.Sprintf(`{"taskArn":%q,"taskDefinitionArn":"td:1","lastStatus":"RUNNING"}`, arn))
				case "d": // en échec de santé
					tasks = append(tasks, fmt.Sprintf(`{"taskArn":%q,"taskDefinitionArn":"td:1","lastStatus":"RUNNING","healthStatus":"UNHEALTHY","attachments":[{"type":"ElasticNetworkInterface","details":[{"name":"privateIPv4Address","value":"10.4.0.4"}]}]}`, arn))
				}
			}
			_, _ = fmt.Fprintf(w, `{"tasks":[%s]}`, strings.Join(tasks, ","))
		case "DescribeTaskDefinition":
			defCalls.Add(1)
			_, _ = io.WriteString(w, `{"taskDefinition":{"containerDefinitions":[
			  {"name":"sidecar","dockerLabels":{}},
			  {"name":"app","dockerLabels":{"goproxify.enable":"true","goproxify.host":"app.example.com","autre":"x"},"portMappings":[{"containerPort":3000}]}]}}`)
		}
	}))
	defer srv.Close()

	e, err := NewECS(ECSConfig{Region: "eu-west-1", Cluster: "prod", AccessKeyID: "AKIA", SecretAccessKey: "secret", SessionToken: "sess", endpoint: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	got, err := e.List(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	var backends []string
	for _, g := range got {
		backends = append(backends, g.Backend)
	}
	sort.Strings(backends)
	if strings.Join(backends, " ") != "http://10.4.0.1:3000 http://10.4.0.2:3000" {
		t.Fatalf("backends = %v (la tâche sans IP et la tâche en échec de santé sont écartées)", backends)
	}
	if defCalls.Load() != 1 {
		t.Errorf("la définition de tâche partagée n'est lue qu'une fois par passe : %d", defCalls.Load())
	}
	m := byBackend(got)
	if m["http://10.4.0.2:3000"].Labels["goproxify.tls"] != "true" || m["http://10.4.0.1:3000"].Labels["goproxify.host"] != "app.example.com" {
		t.Errorf("étiquettes = %v", m)
	}
	if !strings.HasPrefix(m["http://10.4.0.1:3000"].Name, "web (") {
		t.Errorf("nom = %q", m["http://10.4.0.1:3000"].Name)
	}

	if _, err := NewECS(ECSConfig{Region: "eu-west-1"}); err == nil {
		t.Error("cluster requis")
	}
}

func TestECS_CredentialsFromEnvironmentAndRefusal(t *testing.T) {
	t.Setenv("AWS_ACCESS_KEY_ID", "")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "")
	t.Setenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI", "")
	e, _ := NewECS(ECSConfig{Region: "eu-west-1", Cluster: "prod"})
	if _, err := e.List(context.Background()); err == nil || !strings.Contains(err.Error(), "identifiant") {
		t.Fatalf("sans identifiants : %v", err)
	}

	t.Setenv("AWS_ACCESS_KEY_ID", "AKIAENV")
	t.Setenv("AWS_SECRET_ACCESS_KEY", "envsecret")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.Contains(r.Header.Get("Authorization"), "Credential=AKIAENV/") {
			t.Errorf("Authorization = %s", r.Header.Get("Authorization"))
		}
		http.Error(w, `{"__type":"AccessDeniedException"}`, http.StatusBadRequest)
	}))
	defer srv.Close()
	e, _ = NewECS(ECSConfig{Region: "eu-west-1", Cluster: "prod", endpoint: srv.URL})
	if _, err := e.List(context.Background()); err == nil || !strings.Contains(err.Error(), "AccessDenied") {
		t.Fatalf("refus d'AWS : %v", err)
	}
}
