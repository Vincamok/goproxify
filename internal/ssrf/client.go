// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ssrf

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"syscall"
	"time"
)

// Les outils auto-hébergés que l'Admin appelle (ntfy, Gotify, Jira, GitLab, GLPI, Zammad, WebDAV, MinIO…) sont presque
// toujours sur le réseau interne : leur interdire les adresses privées, comme au webhook générique, les rendrait
// inutilisables. Le client ci-dessous refuse en revanche ce qu'aucun outil légitime n'est : les adresses link-local
// (dont les métadonnées des fournisseurs cloud, qui livrent des identifiants), multicast et « non spécifiées ».
// Le contrôle porte sur l'adresse *résolue* au moment de la connexion, redirections comprises.

var metadataAddrs = []net.IP{net.ParseIP("100.100.100.200"), net.ParseIP("fd00:ec2::254")}

// RefusedAddr indique si l'adresse est interdite même aux clients « auto-hébergés ».
func RefusedAddr(ip net.IP) bool {
	if ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsMulticast() || ip.IsUnspecified() {
		return true
	}
	for _, m := range metadataAddrs {
		if m.Equal(ip) {
			return true
		}
	}
	return false
}

// SelfHostedClient est le client HTTP des outils auto-hébergés.
func SelfHostedClient(timeout time.Duration) *http.Client {
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: func(_, address string, _ syscall.RawConn) error {
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			if ip := net.ParseIP(host); ip != nil && RefusedAddr(ip) {
				return fmt.Errorf("adresse %s refusée (link-local ou métadonnées cloud)", host)
			}
			return nil
		},
	}
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         dialer.DialContext,
			TLSHandshakeTimeout: timeout,
		},
		CheckRedirect: func(_ *http.Request, via []*http.Request) error {
			if len(via) >= 3 {
				return errors.New("trop de redirections")
			}
			return nil
		},
	}
}
