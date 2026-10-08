// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// Caractérisation de l'import de configurations tierces. Ce fichier a précédé la migration vers
// le registre de modules : legacyParse et legacyDetect reproduisent à l'identique l'ancien
// aiguillage (switch de ParseConfig, detectImportFormat de la CLI) et servent d'oracle.

func legacyParse(format, content string) ([]DetectedProxy, error) {
	switch format {
	case "nginx":
		return parseNginx(content)
	case "traefik-yaml":
		return parseTraefikYAML(content)
	case "traefik-toml":
		return parseTraefikTOML(content)
	case "caddy":
		return parseCaddy(content)
	case "haproxy":
		return parseHAProxy(content)
	case "goproxify":
		return parseGoproxify(content)
	default:
		return parseGenericJSON(content)
	}
}

func legacyDetect(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))
	switch {
	case ext == ".conf" || strings.Contains(base, "nginx"):
		return "nginx"
	case ext == ".yml" || ext == ".yaml":
		return "traefik-yaml"
	case ext == ".toml":
		return "traefik-toml"
	case base == "caddyfile" || ext == ".caddy":
		return "caddy"
	case ext == ".cfg" || strings.Contains(base, "haproxy"):
		return "haproxy"
	case ext == ".json":
		return "json"
	case strings.HasSuffix(base, ".gpx-admin-backup"):
		return "goproxify"
	default:
		return "json"
	}
}

var dispatchSamples = map[string]string{
	"nginx":        "upstream api {\n  server 10.0.0.1:8080;\n  server 10.0.0.2:8080;\n}\nserver {\n  listen 443 ssl;\n  server_name app.example.com;\n  location / {\n    proxy_pass http://api;\n    proxy_connect_timeout 5;\n    add_header X-Frame-Options \"DENY\";\n  }\n}\nserver {\n  listen 80;\n  server_name blog.example.com;\n  location / { proxy_pass http://127.0.0.1:2368; }\n}\n",
	"traefik-yaml": "http:\n  routers:\n    r1:\n      rule: Host(`app.example.com`)\n      service: s1\n      tls: {}\n  services:\n    s1:\n      loadBalancer:\n        servers:\n          - url: http://10.0.0.1:8080\n",
	"traefik-toml": "[http.routers.r1]\n  rule = \"Host(`app.example.com`)\"\n  service = \"s1\"\n[http.services.s1.loadBalancer]\n  [[http.services.s1.loadBalancer.servers]]\n    url = \"http://10.0.0.1:8080\"\n",
	"caddy":        "app.example.com {\n  reverse_proxy 10.0.0.1:8080 10.0.0.2:8080\n}\n",
	"haproxy":      "frontend fe\n  bind *:443 ssl crt /etc/ssl/x.pem\n  acl host_app hdr(host) -i app.example.com\n  use_backend be_app if host_app\nbackend be_app\n  server s1 10.0.0.1:8080\n  server s2 10.0.0.2:8080\n",
	"goproxify":    `{"proxies":[{"name":"app","config":{"host":"app.example.com","backends":[{"url":"http://10.0.0.1:8080"}]},"enabled":true}]}`,
	"json":         `[{"host":"app.example.com","backends":["http://10.0.0.1:8080"],"tls":true}]`,
}

// ParseConfig doit rendre exactement ce que rendait l'ancien switch, pour chaque format, pour un
// format inconnu (repli sur le JSON générique) et pour un contenu invalide ou vide.
func TestParseConfig_MatchesLegacyDispatch(t *testing.T) {
	formats := []string{"nginx", "traefik-yaml", "traefik-toml", "caddy", "haproxy", "goproxify", "json", "", "inconnu", "NGINX"}
	contents := []string{"", "not a config", "{}", "[]"}
	for _, s := range dispatchSamples {
		contents = append(contents, s)
	}
	for _, f := range formats {
		for _, c := range contents {
			got, gotErr := ParseConfig(f, c)
			want, wantErr := legacyParse(f, c)
			if !reflect.DeepEqual(got, want) || (gotErr == nil) != (wantErr == nil) {
				t.Errorf("format %q contenu %.30q : got (%v, %v) want (%v, %v)", f, c, got, gotErr, want, wantErr)
			}
		}
	}
}

// Les analyseurs eux-mêmes continuent d'extraire l'essentiel de chaque format.
func TestParseConfig_ExtractsHostAndBackends(t *testing.T) {
	cases := map[string]struct {
		host     string
		backends []string
	}{
		"nginx":        {"app.example.com", []string{"http://10.0.0.1:8080", "http://10.0.0.2:8080"}},
		"traefik-yaml": {"app.example.com", []string{"http://10.0.0.1:8080"}},
		"caddy":        {"app.example.com", []string{"10.0.0.1:8080"}},
		"goproxify":    {"app.example.com", []string{"http://10.0.0.1:8080"}},
		"json":         {"app.example.com", []string{"http://10.0.0.1:8080"}},
	}
	for format, want := range cases {
		got, err := ParseConfig(format, dispatchSamples[format])
		if err != nil || len(got) == 0 {
			t.Errorf("%s : %v (%d proxies)", format, err, len(got))
			continue
		}
		if got[0].Host != want.host || !reflect.DeepEqual(got[0].Backends, want.backends) {
			t.Errorf("%s : host %q backends %v", format, got[0].Host, got[0].Backends)
		}
	}
}

var detectPaths = []string{
	"nginx.conf", "/etc/nginx/sites-enabled/app", "site.CONF", "my-nginx-config.txt", "nginx.yaml", "nginx.json",
	"traefik.yml", "dynamic.yaml", "traefik.toml", "Caddyfile", "caddyfile", "site.caddy", "/srv/Caddyfile",
	"haproxy.cfg", "lb.cfg", "haproxy.yaml", "haproxy.json", "config.json", "export.json", "x.gpx-admin-backup",
	"nginx.gpx-admin-backup", "x.gpx-admin-backup.json", "unknown.txt", "noext", "", "C:\\conf\\app.conf",
}

func TestDetectFormat_MatchesLegacyDetect(t *testing.T) {
	for _, p := range detectPaths {
		if got, want := DetectFormat(p), legacyDetect(p); got != want {
			t.Errorf("DetectFormat(%q) = %q, ancien comportement %q", p, got, want)
		}
	}
}
