// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package labels

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"
)

// Format est la façon de présenter les labels.
type Format string

const (
	FormatCompose    Format = "compose"
	FormatDockerRun  Format = "docker_run"
	FormatPortainer  Format = "portainer"
	FormatKubernetes Format = "kubernetes"
)

// Formats liste les formats dans l'ordre d'affichage.
var Formats = []Format{FormatCompose, FormatPortainer, FormatDockerRun, FormatKubernetes}

// Output est un bloc à copier ; Env, quand il existe, est le fichier de variables qui l'accompagne.
type Output struct {
	Text string `json:"text"`
	Env  string `json:"env,omitempty"`
}

// ServiceName donne un nom de service lisible à partir de l'hôte de la route.
func ServiceName(host string) string {
	first := strings.ToLower(strings.SplitN(strings.TrimSpace(host), ".", 2)[0])
	var sb strings.Builder
	for _, c := range first {
		if (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '-' {
			sb.WriteRune(c)
		} else {
			sb.WriteByte('-')
		}
	}
	name := strings.Trim(sb.String(), "-")
	if name == "" {
		return "app"
	}
	return name
}

const placeholder = "CHANGE_ME"

// segments découpe une valeur en morceaux littéraux et noms de variables.
func segments(v string) (parts []string, isVar []bool) {
	for {
		i := strings.Index(v, tokenOpen)
		if i < 0 {
			break
		}
		rest := v[i+len(tokenOpen):]
		j := strings.Index(rest, "}}")
		if j < 0 {
			break
		}
		if i > 0 {
			parts, isVar = append(parts, v[:i]), append(isVar, false)
		}
		parts, isVar = append(parts, rest[:j]), append(isVar, true)
		v = rest[j+2:]
	}
	if v != "" {
		parts, isVar = append(parts, v), append(isVar, false)
	}
	return parts, isVar
}

// expand écrit une valeur en remplaçant les marqueurs ; lit échappe les morceaux littéraux.
func expand(v string, lit func(string) string, withVars bool) string {
	parts, isVar := segments(v)
	var sb strings.Builder
	for i, p := range parts {
		switch {
		case !isVar[i]:
			sb.WriteString(lit(p))
		case withVars:
			sb.WriteString("${" + p + "}")
		default:
			sb.WriteString(placeholder)
		}
	}
	return sb.String()
}

func yamlQuote(s string) string {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	_ = enc.Encode(s)
	return strings.TrimSuffix(buf.String(), "\n")
}

func (g *Generated) envFile(prefix string) string {
	var sb strings.Builder
	for _, name := range g.Env() {
		sb.WriteString(prefix + name + "=\n")
	}
	return sb.String()
}

func (g *Generated) value(key string) string {
	for _, p := range g.Labels {
		if p.Key == key {
			return p.Value
		}
	}
	return ""
}

// Render présente les labels dans le format demandé. withEnv : les secrets passent par des variables
// (${NOM}) fournies par un fichier .env / stack.env ; sinon, ils sont remplacés par CHANGE_ME dans le texte.
func (g *Generated) Render(f Format, withEnv bool) (Output, error) {
	secrets := len(g.Env()) > 0
	host := strings.SplitN(g.value("goproxify.host"), ",", 2)[0]
	svc := ServiceName(host)
	switch f {
	case FormatCompose:
		return g.compose(svc, secrets), nil
	case FormatPortainer:
		return g.portainer(svc, secrets && withEnv, secrets), nil
	case FormatDockerRun:
		return g.dockerRun(svc), nil
	case FormatKubernetes:
		return g.kubernetes(svc), nil
	}
	return Output{}, fmt.Errorf("format inconnu %q", f)
}

func composeLit(s string) string { return strings.ReplaceAll(s, "$", "$$") }

func (g *Generated) composeBody(svc string, withVars bool) string {
	var sb strings.Builder
	sb.WriteString("services:\n  " + svc + ":\n    image: your-image:latest\n    labels:\n")
	for _, p := range g.Labels {
		sb.WriteString("      " + p.Key + ": " + yamlQuote(expand(p.Value, composeLit, withVars)) + "\n")
	}
	return sb.String()
}

// compose lit déjà le fichier .env voisin : les secrets y passent toujours.
func (g *Generated) compose(svc string, secrets bool) Output {
	return Output{Text: g.composeBody(svc, secrets), Env: g.envFile("")}
}

func (g *Generated) portainer(svc string, withVars, secrets bool) Output {
	text := g.composeBody(svc, withVars)
	if secrets && !withVars {
		text = "# CHANGE_ME : à remplacer par la valeur du secret avant de déployer\n" + text
	}
	if !withVars {
		return Output{Text: text}
	}
	return Output{Text: text, Env: g.envFile("")}
}

func shellSingle(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func shellDouble(s string) string {
	r := strings.NewReplacer(`\`, `\\`, `"`, `\"`, `$`, `\$`, "`", "\\`")
	return r.Replace(s)
}

func (g *Generated) dockerRun(svc string) Output {
	var sb strings.Builder
	sb.WriteString("docker run -d --name " + svc + " \\\n")
	for _, p := range g.Labels {
		arg := p.Key + "=" + p.Value
		if len(envTokens(p.Value)) == 0 {
			sb.WriteString("  -l " + shellSingle(arg) + " \\\n")
			continue
		}
		sb.WriteString(`  -l "` + p.Key + "=" + expand(p.Value, shellDouble, true) + `" \` + "\n")
	}
	sb.WriteString("  your-image:latest\n")
	return Output{Text: sb.String(), Env: g.envFile("export ")}
}

func (g *Generated) kubernetes(svc string) Output {
	port := "80"
	if u, err := url.Parse(g.value("goproxify.backend")); err == nil && u.Port() != "" {
		port = u.Port()
	}
	var sb strings.Builder
	sb.WriteString("apiVersion: v1\nkind: Service\nmetadata:\n  name: " + svc + "\n  labels:\n    goproxify.enabled: \"true\"\n  annotations:\n")
	warned := false
	for _, p := range g.Labels {
		if p.Key == "goproxify.enable" {
			continue
		}
		if len(envTokens(p.Value)) > 0 && !warned {
			warned = true
			sb.WriteString("    # CHANGE_ME : une annotation n'est pas un secret — préférez un plugin ou un fournisseur d'authentification\n")
		}
		sb.WriteString("    " + p.Key + ": " + yamlQuote(expand(p.Value, func(s string) string { return s }, false)) + "\n")
	}
	sb.WriteString("spec:\n  selector:\n    app: " + svc + "\n  ports:\n    - port: " + port + "\n      targetPort: " + port + "\n")
	return Output{Text: sb.String()}
}
