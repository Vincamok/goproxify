// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/agent/catalog"
	"github.com/vincamok/goproxify/internal/modules"
)

// Annuaires de services interrogés par le moteur commun de internal/agent/catalog : Consul, Nomad, etcd et Amazon ECS.
// Leur configuration est `sources.<type>` dans agent.json.
func init() {
	text := func(key, label, placeholder string, required bool) modules.Field {
		return modules.Field{Key: key, Label: label, Placeholder: placeholder, Kind: modules.KindText, Required: required}
	}
	secret := func(key, label string, required bool) modules.Field {
		return modules.Field{Key: key, Label: label, Kind: modules.KindPassword, Secret: true, Required: required}
	}
	kind := func(key, label, kind string) modules.Field {
		return modules.Field{Key: key, Label: label, Kind: kind}
	}
	common := func() []modules.Field {
		return []modules.Field{
			kind("enabled", "Enabled", modules.KindBool),
			text("label_prefix", "Label prefix", "goproxify.", false),
			kind("poll_interval_s", "Poll interval (s)", modules.KindNumber),
		}
	}

	Register(modules.Manifest{Type: "consul", Label: "Consul", Fields: append([]modules.Field{
		text("address", "Consul address", "http://127.0.0.1:8500", false),
		secret("token", "ACL token", false),
		text("datacenter", "Datacenter", "", false),
		text("namespace", "Namespace (Enterprise)", "", false),
		text("ca_cert", "CA certificate (PEM or path)", "", false),
	}, common()...)}, consulSource)

	Register(modules.Manifest{Type: "nomad", Label: "Nomad", Fields: append([]modules.Field{
		text("address", "Nomad address", "http://127.0.0.1:4646", false),
		secret("token", "ACL token", false),
		text("namespace", "Namespace (empty = all)", "*", false),
		text("region", "Region", "", false),
		text("ca_cert", "CA certificate (PEM or path)", "", false),
	}, common()...)}, nomadSource)

	Register(modules.Manifest{Type: "etcd", Label: "etcd", Fields: append([]modules.Field{
		kind("endpoints", "Endpoints", modules.KindList),
		text("key_prefix", "Key prefix", "/goproxify/services/", false),
		text("username", "User", "", false),
		secret("password", "Password", false),
		text("ca_cert", "CA certificate (PEM or path)", "", false),
	}, common()...)}, etcdSource)

	Register(modules.Manifest{Type: "ecs", Label: "Amazon ECS", Fields: append([]modules.Field{
		text("region", "AWS region", "eu-west-1", true),
		text("cluster", "Cluster (name or ARN)", "", true),
		secret("access_key_id", "Access key ID (empty = AWS_* variables or task role)", false),
		secret("secret_access_key", "Secret access key", false),
		secret("session_token", "Session token", false),
	}, common()...)}, ecsSource)
}

// --- lecture de la configuration `sources.<type>` ---------------------------------------------------------------

func settingString(m map[string]any, key string) string {
	switch v := m[key].(type) {
	case string:
		return strings.TrimSpace(v)
	case nil:
		return ""
	default:
		return strings.TrimSpace(fmt.Sprint(v))
	}
}

func settingBool(m map[string]any, key string) bool {
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	}
	return false
}

func settingInt(m map[string]any, key string) int {
	switch v := m[key].(type) {
	case int:
		return v
	case int64:
		return int(v)
	case float64:
		return int(v)
	case string:
		n, _ := strconv.Atoi(strings.TrimSpace(v))
		return n
	}
	return 0
}

func settingList(m map[string]any, key string) []string {
	var out []string
	switch v := m[key].(type) {
	case []string:
		out = v
	case []any:
		for _, e := range v {
			out = append(out, fmt.Sprint(e))
		}
	case string:
		out = strings.Split(v, ",")
	}
	return out
}

func pollInterval(m map[string]any) time.Duration {
	n := settingInt(m, "poll_interval_s")
	if n <= 0 {
		n = 30
	}
	if n < 5 {
		n = 5
	}
	return time.Duration(n) * time.Second
}

// catalogInstance câble un moteur d'annuaire sur la passerelle de l'Agent.
func catalogInstance(d Deps, typ string, l catalog.Lister, s map[string]any) *Instance {
	eng := catalog.New(typ, l, pollInterval(s), settingString(s, "label_prefix"),
		d.Cfg.ControlPlane.EdgeEndpoint, d.Cfg.ControlPlane.AuthToken, d.Cfg.Identity.NodeName, d.Log)
	eng.SetEndpointFunc(d.Edges.Current)
	return &Instance{Impl: eng, Start: eng.Start, Blocking: true, SetToken: eng.SetToken, Reannounce: eng.Resync, Runtimes: []string{typ}}
}

func consulSource(d Deps) (*Instance, error) {
	s := d.Settings("consul")
	if !settingBool(s, "enabled") {
		return nil, nil
	}
	l, err := catalog.NewConsul(catalog.ConsulConfig{
		Address: settingString(s, "address"), Token: settingString(s, "token"), Datacenter: settingString(s, "datacenter"),
		Namespace: settingString(s, "namespace"), CACert: settingString(s, "ca_cert"), Prefix: settingString(s, "label_prefix"),
	})
	if err != nil {
		return nil, err
	}
	return catalogInstance(d, "consul", l, s), nil
}

func nomadSource(d Deps) (*Instance, error) {
	s := d.Settings("nomad")
	if !settingBool(s, "enabled") {
		return nil, nil
	}
	l, err := catalog.NewNomad(catalog.NomadConfig{
		Address: settingString(s, "address"), Token: settingString(s, "token"), Namespace: settingString(s, "namespace"),
		Region: settingString(s, "region"), CACert: settingString(s, "ca_cert"), Prefix: settingString(s, "label_prefix"),
	})
	if err != nil {
		return nil, err
	}
	return catalogInstance(d, "nomad", l, s), nil
}

func etcdSource(d Deps) (*Instance, error) {
	s := d.Settings("etcd")
	if !settingBool(s, "enabled") {
		return nil, nil
	}
	l, err := catalog.NewEtcd(catalog.EtcdConfig{
		Endpoints: settingList(s, "endpoints"), KeyPrefix: settingString(s, "key_prefix"),
		Username: settingString(s, "username"), Password: settingString(s, "password"),
		CACert: settingString(s, "ca_cert"), Prefix: settingString(s, "label_prefix"),
	})
	if err != nil {
		return nil, err
	}
	return catalogInstance(d, "etcd", l, s), nil
}

func ecsSource(d Deps) (*Instance, error) {
	s := d.Settings("ecs")
	if !settingBool(s, "enabled") {
		return nil, nil
	}
	l, err := catalog.NewECS(catalog.ECSConfig{
		Region: settingString(s, "region"), Cluster: settingString(s, "cluster"),
		AccessKeyID: settingString(s, "access_key_id"), SecretAccessKey: settingString(s, "secret_access_key"),
		SessionToken: settingString(s, "session_token"), Prefix: settingString(s, "label_prefix"),
	})
	if err != nil {
		return nil, err
	}
	return catalogInstance(d, "ecs", l, s), nil
}
