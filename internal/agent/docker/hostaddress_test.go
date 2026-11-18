// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"context"
	"testing"
)

func httpSpec(port int, backend string) *ProxySpec {
	return &ProxySpec{Type: "http", Port: port, BackendURL: backend}
}

func TestPreferHostAddress(t *testing.T) {
	published := []PortBinding{{PrivatePort: 8080, PublicPort: 8880, Type: "tcp", IP: "0.0.0.0"}, {PrivatePort: 8080, PublicPort: 8880, Type: "tcp", IP: "::"}}
	for name, tc := range map[string]struct {
		spec   *ProxySpec
		labels map[string]string
		ports  []PortBinding
		host   string
		want   string
	}{
		"port publié : l'adresse de l'hôte": {httpSpec(8080, "http://172.18.0.3:8080"), nil, published, "192.168.10.10", "http://192.168.10.10:8880"},
		"pas de port publié : IP interne":   {httpSpec(8080, "http://172.18.0.3:8080"), nil, []PortBinding{{PrivatePort: 8080, Type: "tcp"}}, "192.168.10.10", "http://172.18.0.3:8080"},
		"adresse de l'hôte inconnue":        {httpSpec(8080, "http://172.18.0.3:8080"), nil, published, "", "http://172.18.0.3:8080"},
		"autre port publié":                 {httpSpec(8080, "http://172.18.0.3:8080"), nil, []PortBinding{{PrivatePort: 9000, PublicPort: 9900, Type: "tcp"}}, "192.168.10.10", "http://172.18.0.3:8080"},
		"liaison sur la boucle locale":      {httpSpec(8080, "http://172.18.0.3:8080"), nil, []PortBinding{{PrivatePort: 8080, PublicPort: 8880, Type: "tcp", IP: "127.0.0.1"}}, "192.168.10.10", "http://172.18.0.3:8080"},
		"liaison sur une adresse précise":   {httpSpec(8080, "http://172.18.0.3:8080"), nil, []PortBinding{{PrivatePort: 8080, PublicPort: 8880, Type: "tcp", IP: "192.168.10.77"}}, "192.168.10.10", "http://192.168.10.77:8880"},
		"étiquette backend":                 {httpSpec(8080, "http://x:1"), map[string]string{LabelBackendURL: "http://x:1"}, published, "192.168.10.10", "http://x:1"},
		"étiquette ip":                      {httpSpec(8080, "http://10.1.1.1:8080"), map[string]string{LabelIP: "10.1.1.1"}, published, "192.168.10.10", "http://10.1.1.1:8080"},
		"route tcp":                         {&ProxySpec{Type: "tcp", Port: 8080, BackendURL: "172.18.0.3:8080"}, nil, published, "192.168.10.10", "172.18.0.3:8080"},
		"schéma https conservé":             {httpSpec(8080, "https://172.18.0.3:8080"), nil, published, "192.168.10.10", "https://192.168.10.10:8880"},
	} {
		PreferHostAddress([]*ProxySpec{tc.spec}, tc.labels, tc.ports, tc.host)
		if tc.spec.BackendURL != tc.want {
			t.Errorf("%s : %q, attendu %q", name, tc.spec.BackendURL, tc.want)
		}
	}
	a, b := httpSpec(8080, "http://172.18.0.3:8080"), httpSpec(9000, "http://172.18.0.3:9000")
	PreferHostAddress([]*ProxySpec{a, b}, nil, published, "192.168.10.10")
	if a.BackendURL != "http://172.18.0.3:8080" {
		t.Errorf("un conteneur à plusieurs routes est laissé tel quel : %q", a.BackendURL)
	}
}

func TestHostAddress_ConfiguredWinsAndIsResolved(t *testing.T) {
	if got := NewHostAddress(nil, "192.168.10.10", nil).Get(context.Background()); got != "192.168.10.10" {
		t.Errorf("IP configurée : %q", got)
	}
	if got := (*HostAddress)(nil).Get(context.Background()); got != "" {
		t.Errorf("sans résolveur : %q", got)
	}
	if got := NewHostAddress(nil, "", nil).Get(context.Background()); got != "" {
		t.Errorf("sans client ni configuration : %q", got)
	}
}

func TestUsableHostIP(t *testing.T) {
	for ip, want := range map[string]bool{"192.168.10.10": true, "10.0.0.5": true, "127.0.1.1": false, "0.0.0.0": false, "169.254.1.1": false, "": false, "nom": false} {
		if usableHostIP(ip) != want {
			t.Errorf("usableHostIP(%q) = %v", ip, !want)
		}
	}
}

func TestPublishedPorts(t *testing.T) {
	var ci ContainerInspect
	ci.NetworkSettings.Ports = map[string][]struct {
		HostIP   string `json:"HostIp"`
		HostPort string `json:"HostPort"`
	}{
		"8080/tcp": {{HostIP: "0.0.0.0", HostPort: "8880"}},
		"53/udp":   {{HostIP: "", HostPort: "5353"}},
		"9000/tcp": nil,
		"x/tcp":    {{HostPort: "1"}},
	}
	got := ci.PublishedPorts()
	if len(got) != 2 || got[0].PrivatePort != 53 || got[0].Type != "udp" || got[1].PrivatePort != 8080 || got[1].PublicPort != 8880 || got[1].IP != "0.0.0.0" {
		t.Errorf("ports publiés : %+v", got)
	}
}

func container(name string, ips ...string) ContainerSummary {
	var c ContainerSummary
	c.ID = "id-" + name
	c.Names = []string{"/" + name}
	c.NetworkSettings.Networks = map[string]struct {
		NetworkID string `json:"NetworkID"`
		IPAddress string `json:"IPAddress"`
	}{}
	for i, ip := range ips {
		c.NetworkSettings.Networks[string(rune('a'+i))] = struct {
			NetworkID string `json:"NetworkID"`
			IPAddress string `json:"IPAddress"`
		}{IPAddress: ip}
	}
	return c
}

// La passerelle de cet hôte est retrouvée sans configuration : par le nom de son conteneur, ou par l'IP qu'un nom ou un
// alias Docker désigne.
func TestMatchEdgeContainer(t *testing.T) {
	list := []ContainerSummary{container("termix", "172.18.0.3"), container("goproxify-core", "172.19.0.2"), container("goproxify-agent", "172.19.0.3")}
	noDNS := func(string) string { return "" }
	dns := func(h string) string {
		if h == "core" {
			return "172.19.0.2"
		}
		return ""
	}
	for name, tc := range map[string]struct {
		endpoints []string
		resolve   func(string) string
		want      string
	}{
		"nom du conteneur":           {[]string{"http://goproxify-core:8000"}, noDNS, "goproxify-core"},
		"nom en majuscules":          {[]string{"http://GoProxify-Core:8000"}, noDNS, "goproxify-core"},
		"alias résolu en IP":         {[]string{"http://core:8000"}, dns, "goproxify-core"},
		"IP du conteneur":            {[]string{"http://172.19.0.2:8000"}, noDNS, "goproxify-core"},
		"passerelle d'un autre hôte": {[]string{"http://192.168.10.91:8000"}, noDNS, ""},
		"la première qui correspond": {[]string{"http://192.168.10.91:8000", "http://goproxify-core:8000"}, noDNS, "goproxify-core"},
		"nom inconnu":                {[]string{"http://inconnu:8000"}, noDNS, ""},
		"adresse invalide":           {[]string{"::::"}, noDNS, ""},
	} {
		got, id := matchEdgeContainer(append([]ContainerSummary(nil), list...), tc.endpoints, tc.resolve)
		if got != tc.want || (tc.want != "" && id != "id-"+tc.want) {
			t.Errorf("%s : %q (%q), attendu %q", name, got, id, tc.want)
		}
	}
}
