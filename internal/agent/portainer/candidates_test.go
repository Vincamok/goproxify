// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portainer

import (
	"slices"
	"testing"

	"github.com/vincamok/goproxify/internal/agent/docker"
)

func candidateContainer(labels map[string]string) Container {
	var c Container
	c.ID = "c1"
	c.Labels = labels
	c.Ports = []ContainerPort{{PrivatePort: 8080, PublicPort: 32788, Type: "tcp"}}
	c.NetworkSettings.Networks = map[string]struct {
		NetworkID string `json:"NetworkID"`
		IPAddress string `json:"IPAddress"`
	}{"bridge": {IPAddress: "172.17.0.4"}, "lan": {IPAddress: "10.20.0.77"}}
	return c
}

func candidatesOf(t *testing.T, nets []string, c Container, isLocal bool, specs ...*docker.ProxySpec) []string {
	t.Helper()
	d := &Discovery{}
	if err := d.SetRoutableNetworks(nets); err != nil {
		t.Fatal(err)
	}
	d.addCandidates(c, specs, isLocal)
	return specs[0].Candidates
}

// Un conteneur d'un endpoint distant propose l'IP qu'il a dans un réseau routable déclaré, avant son port publié ; une IP de
// bridge n'est jamais proposée.
func TestAddCandidates_OnlyRoutableNetworks(t *testing.T) {
	spec := func() *docker.ProxySpec { return &docker.ProxySpec{BackendURL: "http://10.0.0.5:32788"} }

	got := candidatesOf(t, []string{"10.20.0.0/16"}, candidateContainer(nil), false, spec())
	if want := []string{"http://10.20.0.77:8080", "http://10.0.0.5:32788"}; !slices.Equal(got, want) {
		t.Errorf("réseau routable : %v, attendu %v", got, want)
	}
	if got := candidatesOf(t, []string{"192.168.0.0/16"}, candidateContainer(nil), false, spec()); got != nil {
		t.Errorf("aucune IP du conteneur dans un réseau déclaré : %v", got)
	}
	if got := candidatesOf(t, nil, candidateContainer(nil), false, spec()); got != nil {
		t.Errorf("sans réseau déclaré : %v", got)
	}
	if got := candidatesOf(t, []string{"10.20.0.0/16"}, candidateContainer(nil), true, spec()); got != nil {
		t.Errorf("endpoint local : l'IP interne est déjà servie : %v", got)
	}
	if got := candidatesOf(t, []string{"10.20.0.0/16"}, candidateContainer(map[string]string{docker.LabelIP: "192.168.1.9"}), false, spec()); got != nil {
		t.Errorf("l'étiquette ip désigne une seule adresse : %v", got)
	}
	if got := candidatesOf(t, []string{"10.20.0.0/16"}, candidateContainer(nil), false, spec(), spec()); got != nil {
		t.Errorf("un conteneur à plusieurs routes : %v", got)
	}
	if got := candidatesOf(t, []string{"10.20.0.0/16"}, candidateContainer(map[string]string{docker.LabelPort: "3000"}), false, spec()); len(got) != 2 || got[0] != "http://10.20.0.77:3000" {
		t.Errorf("le port applicatif de l'étiquette : %v", got)
	}
}

func TestSetRoutableNetworks_RejectsABadCIDR(t *testing.T) {
	if err := (&Discovery{}).SetRoutableNetworks([]string{"10.0.0.0/8", "pas-un-cidr"}); err == nil {
		t.Error("un CIDR invalide doit être refusé")
	}
}

func TestPayloadCarriesCandidates(t *testing.T) {
	d := &Discovery{agentName: "ag"}
	spec := &docker.ProxySpec{Host: "app.example.com", ContainerID: "c1", BackendURL: "http://10.0.0.5:32788", Candidates: []string{"http://10.20.0.77:8080", "http://10.0.0.5:32788"}}
	p := d.payload(Endpoint{ID: 1, Name: "nas"}, spec)
	if c, _ := p["candidates"].([]string); len(c) != 2 || c[0] != "http://10.20.0.77:8080" {
		t.Errorf("candidats absents de la charge utile : %v", p["candidates"])
	}
	spec.Candidates = nil
	if _, ok := d.payload(Endpoint{ID: 1, Name: "nas"}, spec)["candidates"]; ok {
		t.Error("sans candidats, le champ n'est pas envoyé")
	}
}
