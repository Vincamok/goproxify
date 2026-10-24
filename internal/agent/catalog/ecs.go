// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package catalog

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"
)

// ECSConfig est la configuration de la source Amazon ECS.
type ECSConfig struct {
	Region  string
	Cluster string
	// Identifiants : à défaut, variables AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY / AWS_SESSION_TOKEN, puis le rôle
	// de la tâche (AWS_CONTAINER_CREDENTIALS_RELATIVE_URI) quand l'Agent tourne lui-même sur ECS.
	AccessKeyID     string
	SecretAccessKey string
	SessionToken    string
	Prefix          string

	endpoint string // tests
}

// ECS liste les tâches RUNNING d'un cluster dont les étiquettes Docker du conteneur (dockerLabels de la définition de
// tâche) ou les tags de la tâche portent « goproxify.enable=true ». Il faut une adresse IP privée par tâche, donc le mode
// réseau awsvpc (Fargate, ou EC2 en awsvpc) : en bridge ou host, l'IP de l'instance EC2 et le port dynamique ne sont pas
// lus.
type ECS struct {
	cfg    ECSConfig
	client *http.Client
	now    func() time.Time

	mu    sync.Mutex
	creds *awsCreds
}

type awsCreds struct {
	key, secret, token string
	expires            time.Time
}

func NewECS(cfg ECSConfig) (*ECS, error) {
	if strings.TrimSpace(cfg.Region) == "" || strings.TrimSpace(cfg.Cluster) == "" {
		return nil, fmt.Errorf("ecs : region et cluster requis")
	}
	if cfg.Prefix == "" {
		cfg.Prefix = "goproxify."
	}
	if cfg.endpoint == "" {
		cfg.endpoint = (&url.URL{Scheme: "https", Host: "ecs." + cfg.Region + ".amazonaws.com"}).String()
	}
	return &ECS{cfg: cfg, client: &http.Client{Timeout: 20 * time.Second}, now: time.Now}, nil
}

func (e *ECS) credentials(ctx context.Context) (*awsCreds, error) {
	if e.cfg.AccessKeyID != "" && e.cfg.SecretAccessKey != "" {
		return &awsCreds{key: e.cfg.AccessKeyID, secret: e.cfg.SecretAccessKey, token: e.cfg.SessionToken}, nil
	}
	if k, s := os.Getenv("AWS_ACCESS_KEY_ID"), os.Getenv("AWS_SECRET_ACCESS_KEY"); k != "" && s != "" {
		return &awsCreds{key: k, secret: s, token: os.Getenv("AWS_SESSION_TOKEN")}, nil
	}
	rel := os.Getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")
	if rel == "" {
		return nil, fmt.Errorf("ecs : aucun identifiant AWS (configuration, variables AWS_* ou rôle de tâche)")
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.creds != nil && e.now().Add(5*time.Minute).Before(e.creds.expires) {
		return e.creds, nil
	}
	var out struct {
		AccessKeyID     string    `json:"AccessKeyId"`
		SecretAccessKey string    `json:"SecretAccessKey"`
		Token           string    `json:"Token"`
		Expiration      time.Time `json:"Expiration"`
	}
	if _, err := doJSON(ctx, e.client, http.MethodGet, "http://169.254.170.2"+rel, nil, nil, &out); err != nil {
		return nil, fmt.Errorf("ecs : identifiants du rôle de tâche : %w", err)
	}
	e.creds = &awsCreds{key: out.AccessKeyID, secret: out.SecretAccessKey, token: out.Token, expires: out.Expiration}
	return e.creds, nil
}

func hmacSHA(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// sign signe une requête POST sur « / » (AWS Signature Version 4) : signed liste, en minuscules et triés, les en-têtes
// signés ; X-Amz-Date est posé ici.
func sign(req *http.Request, payload []byte, c *awsCreds, region, service string, signed []string, now time.Time) {
	amzDate := now.UTC().Format("20060102T150405Z")
	day := amzDate[:8]
	req.Header.Set("X-Amz-Date", amzDate)
	var canon strings.Builder
	for _, h := range signed {
		v := req.Header.Get(h)
		if h == "host" {
			v = req.URL.Host
		}
		canon.WriteString(h + ":" + strings.TrimSpace(v) + "\n")
	}
	sum := sha256.Sum256(payload)
	canonical := strings.Join([]string{"POST", "/", "", canon.String(), strings.Join(signed, ";"), hex.EncodeToString(sum[:])}, "\n")
	scope := day + "/" + region + "/" + service + "/aws4_request"
	csum := sha256.Sum256([]byte(canonical))
	toSign := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + scope + "\n" + hex.EncodeToString(csum[:])
	k := hmacSHA([]byte("AWS4"+c.secret), day)
	k = hmacSHA(k, region)
	k = hmacSHA(k, service)
	k = hmacSHA(k, "aws4_request")
	sig := hex.EncodeToString(hmacSHA(k, toSign))
	req.Header.Set("Authorization", "AWS4-HMAC-SHA256 Credential="+c.key+"/"+scope+", SignedHeaders="+strings.Join(signed, ";")+", Signature="+sig)
}

func (e *ECS) call(ctx context.Context, target string, body, out any) error {
	creds, err := e.credentials(ctx)
	if err != nil {
		return err
	}
	payload, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.cfg.endpoint+"/", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-amz-json-1.1")
	req.Header.Set("X-Amz-Target", "AmazonEC2ContainerServiceV20141113."+target)
	signed := []string{"content-type", "host", "x-amz-date", "x-amz-target"}
	if creds.token != "" {
		req.Header.Set("X-Amz-Security-Token", creds.token)
		signed = []string{"content-type", "host", "x-amz-date", "x-amz-security-token", "x-amz-target"}
	}
	sign(req, payload, creds, e.cfg.Region, "ecs", signed, e.now())
	resp, err := e.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes))
	if resp.StatusCode/100 != 2 {
		msg := strings.TrimSpace(string(raw))
		if len(msg) > 200 {
			msg = msg[:200]
		}
		return fmt.Errorf("ecs %s : HTTP %d %s", target, resp.StatusCode, msg)
	}
	return json.Unmarshal(raw, out)
}

type ecsTask struct {
	TaskArn           string `json:"taskArn"`
	TaskDefinitionArn string `json:"taskDefinitionArn"`
	LastStatus        string `json:"lastStatus"`
	HealthStatus      string `json:"healthStatus"`
	Group             string `json:"group"`
	Attachments       []struct {
		Type    string `json:"type"`
		Details []struct {
			Name  string `json:"name"`
			Value string `json:"value"`
		} `json:"details"`
	} `json:"attachments"`
	Containers []struct {
		Name              string `json:"name"`
		NetworkInterfaces []struct {
			PrivateIpv4Address string `json:"privateIpv4Address"`
		} `json:"networkInterfaces"`
	} `json:"containers"`
	Tags []struct {
		Key   string `json:"key"`
		Value string `json:"value"`
	} `json:"tags"`
}

type ecsTaskDef struct {
	ContainerDefinitions []struct {
		Name         string            `json:"name"`
		DockerLabels map[string]string `json:"dockerLabels"`
		PortMappings []struct {
			ContainerPort int `json:"containerPort"`
		} `json:"portMappings"`
	} `json:"containerDefinitions"`
}

func (t ecsTask) privateIP() string {
	for _, a := range t.Attachments {
		if a.Type != "ElasticNetworkInterface" {
			continue
		}
		for _, d := range a.Details {
			if d.Name == "privateIPv4Address" && d.Value != "" {
				return d.Value
			}
		}
	}
	for _, c := range t.Containers {
		for _, n := range c.NetworkInterfaces {
			if n.PrivateIpv4Address != "" {
				return n.PrivateIpv4Address
			}
		}
	}
	return ""
}

func (e *ECS) List(ctx context.Context) ([]Instance, error) {
	var arns []string
	next := ""
	for {
		req := map[string]any{"cluster": e.cfg.Cluster, "desiredStatus": "RUNNING", "maxResults": 100}
		if next != "" {
			req["nextToken"] = next
		}
		var out struct {
			TaskArns  []string `json:"taskArns"`
			NextToken string   `json:"nextToken"`
		}
		if err := e.call(ctx, "ListTasks", req, &out); err != nil {
			return nil, err
		}
		arns = append(arns, out.TaskArns...)
		if out.NextToken == "" {
			break
		}
		next = out.NextToken
	}

	defs := map[string]*ecsTaskDef{}
	var res []Instance
	for i := 0; i < len(arns); i += 100 {
		batch := arns[i:min(i+100, len(arns))]
		var out struct {
			Tasks []ecsTask `json:"tasks"`
		}
		if err := e.call(ctx, "DescribeTasks", map[string]any{"cluster": e.cfg.Cluster, "tasks": batch, "include": []string{"TAGS"}}, &out); err != nil {
			return nil, err
		}
		for _, t := range out.Tasks {
			inactive := ""
			switch {
			case t.LastStatus != "RUNNING":
				inactive = strings.ToLower(t.LastStatus)
			case strings.EqualFold(t.HealthStatus, "UNHEALTHY"):
				inactive = "unhealthy"
			}
			def, ok := defs[t.TaskDefinitionArn]
			if !ok {
				var d struct {
					TaskDefinition ecsTaskDef `json:"taskDefinition"`
				}
				if err := e.call(ctx, "DescribeTaskDefinition", map[string]any{"taskDefinition": t.TaskDefinitionArn}, &d); err != nil {
					return nil, err
				}
				def = &d.TaskDefinition
				defs[t.TaskDefinitionArn] = def
			}
			if inst, ok := e.instance(t, def); ok {
				inst.Inactive = inactive
				res = append(res, inst)
			}
		}
	}
	return res, nil
}

// instance construit l'instance d'une tâche : étiquettes des conteneurs (le premier qui définit une clé l'emporte),
// puis tags de la tâche, qui les complètent ; port : étiquette « port », sinon premier port du conteneur activé.
func (e *ECS) instance(t ecsTask, def *ecsTaskDef) (Instance, bool) {
	labels := map[string]string{}
	port := 0
	for _, c := range def.ContainerDefinitions {
		own := map[string]string{}
		for k, v := range c.DockerLabels {
			if strings.HasPrefix(k, e.cfg.Prefix) {
				own[k] = v
			}
		}
		if len(own) == 0 {
			continue
		}
		for k, v := range own {
			if _, set := labels[k]; !set {
				labels[k] = v
			}
		}
		if port == 0 && len(c.PortMappings) > 0 {
			port = c.PortMappings[0].ContainerPort
		}
	}
	for _, tg := range t.Tags {
		if strings.HasPrefix(tg.Key, e.cfg.Prefix) {
			labels[tg.Key] = tg.Value
		}
	}
	if !strings.EqualFold(labels[e.cfg.Prefix+"enable"], "true") && !strings.EqualFold(labels[e.cfg.Prefix+"enabled"], "true") {
		return Instance{}, false
	}
	ip := t.privateIP()
	be := backendURL(labels, e.cfg.Prefix, ip, port)
	if be == "" {
		return Instance{}, false
	}
	name := t.TaskArn
	if i := strings.LastIndex(name, "/"); i >= 0 {
		name = name[i+1:]
	}
	if t.Group != "" {
		name = strings.TrimPrefix(t.Group, "service:") + " (" + shortAddr(be) + ")"
	}
	return Instance{Key: t.TaskArn, Name: name, Backend: be, Labels: labels}, true
}
