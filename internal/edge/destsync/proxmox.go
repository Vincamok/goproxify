// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package destsync

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/modules"
)

// Proxmox VE : VM QEMU, conteneurs LXC et, au choix, les nœuds eux-mêmes. Lecture seule : le rôle PVEAuditor suffit
// sur « / » (jeton d'API avec séparation de privilèges désactivée, ou rôle donné au jeton).
func init() {
	Register(modules.Manifest{Type: "proxmox", Label: "Proxmox VE", Fields: []modules.Field{
		{Key: "url", Label: "API URL", Placeholder: "https://pve.example.com:8006", Kind: modules.KindText, Required: true},
		{Key: "token_id", Label: "API token ID", Placeholder: "audit@pve!goproxify", Kind: modules.KindText, Required: true,
			Help: "user@realm!tokenname — a token with the PVEAuditor role is enough"},
		{Key: "token_secret", Label: "API token secret", Kind: modules.KindPassword, Secret: true, Required: true},
		{Key: "ca_cert", Label: "CA certificate (PEM)", Kind: modules.KindText, Multiline: true,
			Help: "For a Proxmox certificate signed by a private CA"},
		{Key: "insecure_skip_verify", Label: "Do not verify the TLS certificate", Kind: modules.KindBool,
			Help: "Proxmox ships a self-signed certificate: prefer pasting it above"},
		{Key: "pool", Label: "Only this pool", Kind: modules.KindText},
		{Key: "tag", Label: "Only machines with this tag", Kind: modules.KindText},
		{Key: "only_running", Label: "Only running machines", Kind: modules.KindBool, Default: true},
		{Key: "include_nodes", Label: "Also list the Proxmox nodes", Kind: modules.KindBool,
			Help: "Offers the hypervisors themselves as SSH destinations"},
		{Key: "ssh_port", Label: "SSH port", Kind: modules.KindNumber, Default: 22},
	}}, newProxmox)
}

type proxmox struct {
	base         *url.URL
	auth         string
	client       *http.Client
	pool, tag    string
	onlyRunning  bool
	includeNodes bool
	port         int
}

func newProxmox(cfg map[string]any) (Source, error) {
	raw := str(cfg, "url")
	u, err := url.Parse(raw)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("url : adresse d'API invalide %q", raw)
	}
	id, secret := str(cfg, "token_id"), str(cfg, "token_secret")
	if id == "" || secret == "" {
		return nil, errors.New("jeton d'API incomplet (token_id et token_secret)")
	}
	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if pem := str(cfg, "ca_cert"); pem != "" {
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM([]byte(pem)) {
			return nil, errors.New("ca_cert : aucun certificat PEM lisible")
		}
		tlsCfg.RootCAs = pool
	}
	if boolean(cfg, "insecure_skip_verify", false) {
		tlsCfg.InsecureSkipVerify = true //nolint:gosec // choix explicite de l'opérateur, documenté sur le champ
	}
	port := integer(cfg, "ssh_port", 22)
	if port <= 0 || port > 65535 {
		port = 22
	}
	return &proxmox{
		base:         &url.URL{Scheme: u.Scheme, Host: u.Host},
		auth:         "PVEAPIToken=" + id + "=" + secret,
		client:       &http.Client{Timeout: 20 * time.Second, Transport: &http.Transport{TLSClientConfig: tlsCfg}},
		pool:         str(cfg, "pool"),
		tag:          strings.ToLower(str(cfg, "tag")),
		onlyRunning:  boolean(cfg, "only_running", true),
		includeNodes: boolean(cfg, "include_nodes", false),
		port:         port,
	}, nil
}

// flexInt lit un entier que Proxmox rend tantôt en nombre, tantôt en chaîne ou en booléen.
type flexInt int

func (f *flexInt) UnmarshalJSON(b []byte) error {
	s := strings.Trim(string(b), `"`)
	switch s {
	case "true":
		*f = 1
		return nil
	case "false", "null", "":
		*f = 0
		return nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return err
	}
	*f = flexInt(n)
	return nil
}

type pveResource struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"`
	VMID     flexInt `json:"vmid"`
	Name     string  `json:"name"`
	Node     string  `json:"node"`
	Status   string  `json:"status"`
	Tags     string  `json:"tags"`
	Pool     string  `json:"pool"`
	Template flexInt `json:"template"`
}

type pveClusterEntry struct {
	Type   string  `json:"type"`
	Name   string  `json:"name"`
	IP     string  `json:"ip"`
	Online flexInt `json:"online"`
}

func (p *proxmox) get(ctx context.Context, path string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.base.String()+"/api2/json"+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", p.auth)
	req.Header.Set("Accept", "application/json")
	resp, err := p.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 8<<20))
	if err != nil {
		return err
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("proxmox %s : %s", path, httpReason(resp.StatusCode, body))
	}
	var env struct {
		Data json.RawMessage `json:"data"`
	}
	if err := json.Unmarshal(body, &env); err != nil {
		return fmt.Errorf("proxmox %s : réponse illisible", path)
	}
	return json.Unmarshal(env.Data, out)
}

// httpReason résume une réponse d'erreur sans en reproduire le corps entier.
func httpReason(status int, body []byte) string {
	msg := strings.TrimSpace(string(body))
	if len(msg) > 160 {
		msg = msg[:160]
	}
	switch status {
	case http.StatusUnauthorized, http.StatusForbidden:
		return fmt.Sprintf("HTTP %d — jeton refusé ou droits insuffisants (rôle PVEAuditor requis)", status)
	}
	if msg == "" {
		return fmt.Sprintf("HTTP %d", status)
	}
	return fmt.Sprintf("HTTP %d — %s", status, msg)
}

// List interroge le cluster. Une erreur sur l'inventaire est rendue telle quelle (l'exécuteur ne touche alors à rien) ;
// une erreur sur l'adresse d'une machine laisse seulement son adresse vide.
func (p *proxmox) List(ctx context.Context) ([]Machine, error) {
	var res []pveResource
	if err := p.get(ctx, "/cluster/resources?type=vm", &res); err != nil {
		return nil, err
	}
	var kept []pveResource
	for _, r := range res {
		if r.Template != 0 || (r.Type != "qemu" && r.Type != "lxc") {
			continue
		}
		if p.onlyRunning && r.Status != "running" {
			continue
		}
		if p.pool != "" && r.Pool != p.pool {
			continue
		}
		if p.tag != "" && !hasTag(r.Tags, p.tag) {
			continue
		}
		kept = append(kept, r)
	}

	out := make([]Machine, len(kept))
	var wg sync.WaitGroup
	sem := make(chan struct{}, 6)
	for i, r := range kept {
		out[i] = Machine{
			ExternalID: r.Type + "/" + strconv.Itoa(int(r.VMID)),
			Name:       r.Name,
			Port:       p.port,
			Tags:       normalizeTags(splitTags(r.Tags)...),
			Running:    r.Status == "running",
			Detail:     map[string]string{"node": r.Node, "type": r.Type, "vmid": strconv.Itoa(int(r.VMID))},
		}
		if out[i].Name == "" {
			out[i].Name = r.Type + "-" + strconv.Itoa(int(r.VMID))
		}
		if r.Pool != "" {
			out[i].Detail["pool"] = r.Pool
		}
		wg.Add(1)
		go func(i int, r pveResource) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			out[i].Host = p.guestAddress(ctx, r)
		}(i, r)
	}
	wg.Wait()
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	if p.includeNodes {
		var st []pveClusterEntry
		if err := p.get(ctx, "/cluster/status", &st); err != nil {
			return nil, err
		}
		for _, n := range st {
			if n.Type != "node" || n.Name == "" {
				continue
			}
			out = append(out, Machine{
				ExternalID: "node/" + n.Name, Name: n.Name, Host: pickIPv4([]string{n.IP}), Port: p.port,
				Running: n.Online != 0, Detail: map[string]string{"type": "node"},
			})
		}
	}
	return out, nil
}

func splitTags(s string) []string {
	return strings.FieldsFunc(s, func(r rune) bool { return r == ';' || r == ',' || r == ' ' })
}

func hasTag(tags, want string) bool {
	for _, t := range splitTags(tags) {
		if strings.EqualFold(t, want) {
			return true
		}
	}
	return false
}

// virtualIface : interfaces que l'on n'offre jamais en destination (ponts et paires virtuelles d'un hôte de conteneurs).
var virtualIface = regexp.MustCompile(`^(lo|docker\d*|br-.*|veth.*|virbr.*|cni.*|flannel.*|cali.*|tun\d*|tap\d*|podman\d*)$`)

// guestAddress cherche l'adresse d'une machine : agent invité (QEMU) ou état du conteneur (LXC) quand elle tourne, sinon
// l'adresse statique de sa configuration (cloud-init, réseau du conteneur).
func (p *proxmox) guestAddress(ctx context.Context, r pveResource) string {
	vmid := strconv.Itoa(int(r.VMID))
	node := url.PathEscape(r.Node)
	if r.Status == "running" {
		switch r.Type {
		case "qemu":
			var out struct {
				Result []struct {
					Name string `json:"name"`
					IPs  []struct {
						Address string `json:"ip-address"`
						Type    string `json:"ip-address-type"`
					} `json:"ip-addresses"`
				} `json:"result"`
			}
			if err := p.get(ctx, "/nodes/"+node+"/qemu/"+vmid+"/agent/network-get-interfaces", &out); err == nil {
				var addrs []string
				for _, ifc := range out.Result {
					if virtualIface.MatchString(ifc.Name) {
						continue
					}
					for _, ip := range ifc.IPs {
						if ip.Type == "ipv4" {
							addrs = append(addrs, ip.Address)
						}
					}
				}
				if ip := pickIPv4(addrs); ip != "" {
					return ip
				}
			}
		case "lxc":
			var ifaces []struct {
				Name string `json:"name"`
				Inet string `json:"inet"`
			}
			if err := p.get(ctx, "/nodes/"+node+"/lxc/"+vmid+"/interfaces", &ifaces); err == nil {
				var addrs []string
				for _, ifc := range ifaces {
					if !virtualIface.MatchString(ifc.Name) {
						addrs = append(addrs, ifc.Inet)
					}
				}
				if ip := pickIPv4(addrs); ip != "" {
					return ip
				}
			}
		}
	}
	var cfg map[string]any
	if err := p.get(ctx, "/nodes/"+node+"/"+r.Type+"/"+vmid+"/config", &cfg); err != nil {
		return ""
	}
	return staticAddress(cfg)
}

var staticIP = regexp.MustCompile(`(?:^|,)ip=([0-9.]+)(?:/\d+)?(?:,|$)`)

// staticAddress lit l'adresse fixe déclarée dans la configuration : ipconfigN (cloud-init QEMU) ou netN (conteneur).
// Une adresse obtenue par DHCP n'y figure pas.
func staticAddress(cfg map[string]any) string {
	keys := make([]string, 0, len(cfg))
	for k := range cfg {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var addrs []string
	for _, k := range keys {
		s, ok := cfg[k].(string)
		if !ok || !(strings.HasPrefix(k, "ipconfig") || strings.HasPrefix(k, "net")) {
			continue
		}
		if m := staticIP.FindStringSubmatch(s); m != nil {
			addrs = append(addrs, m[1])
		}
	}
	return pickIPv4(addrs)
}
