// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package grpctrans

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/bufbuild/protocompile"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"

	_ "google.golang.org/genproto/googleapis/rpc/errdetails" // types des détails d'erreur gRPC (google.rpc.Status)

	"github.com/vincamok/goproxify/internal/edge/router"
)

const (
	defaultMaxRequestBody  = 4 << 20
	defaultMaxResponseBody = 16 << 20
	maxProtoSourceBytes    = 2 << 20
)

// binding relie une route HTTP à une méthode gRPC unaire.
type binding struct {
	httpMethod   string
	tpl          *template
	body         string // "", "*" ou chemin de champ
	responseBody string // "" ou nom de champ
	method       protoreflect.MethodDescriptor
	grpcPath     string // /paquet.Service/Méthode
}

// Transcoder porte les routes compilées d'une configuration.
type Transcoder struct {
	bindings        []*binding
	emitDefaults    bool
	protoFieldNames bool
	maxRequest      int64
	maxResponse     int64
	Skipped         []string // méthodes sans route (ni annotation google.api.http, ni auto_mapping)
}

// googleResolver résout les imports google/* (annotations, rpc, protobuf) depuis les types compilés
// dans le binaire : un .proto qui importe google/api/annotations.proto n'a rien d'autre à fournir.
func googleResolver(path string) (protocompile.SearchResult, error) {
	fd, err := protoregistry.GlobalFiles.FindFileByPath(path)
	if err != nil {
		return protocompile.SearchResult{}, err
	}
	return protocompile.SearchResult{Desc: fd}, nil
}

func loadFromProto(files map[string]string) ([]protoreflect.FileDescriptor, error) {
	total := 0
	names := make([]string, 0, len(files))
	for n, src := range files {
		total += len(src)
		names = append(names, n)
	}
	if total > maxProtoSourceBytes {
		return nil, fmt.Errorf("grpc_transcode.proto dépasse %d Mo", maxProtoSourceBytes>>20)
	}
	sort.Strings(names)
	comp := protocompile.Compiler{
		Resolver: protocompile.WithStandardImports(protocompile.CompositeResolver{
			&protocompile.SourceResolver{Accessor: protocompile.SourceAccessorFromMap(files)},
			protocompile.ResolverFunc(googleResolver),
		}),
	}
	res, err := comp.Compile(context.Background(), names...)
	if err != nil {
		return nil, fmt.Errorf("grpc_transcode.proto : %w", err)
	}
	out := make([]protoreflect.FileDescriptor, 0, len(res))
	for _, f := range res {
		out = append(out, f)
	}
	return out, nil
}

func loadFromDescriptorSet(b64 string) ([]protoreflect.FileDescriptor, error) {
	raw, err := base64.StdEncoding.DecodeString(strings.TrimSpace(b64))
	if err != nil {
		return nil, fmt.Errorf("grpc_transcode.descriptor_set : base64 invalide : %w", err)
	}
	var set descriptorpb.FileDescriptorSet
	if err := proto.Unmarshal(raw, &set); err != nil {
		return nil, fmt.Errorf("grpc_transcode.descriptor_set : FileDescriptorSet illisible : %w", err)
	}
	if len(set.File) == 0 {
		return nil, fmt.Errorf("grpc_transcode.descriptor_set : aucun fichier")
	}
	// Les dépendances absentes de l'ensemble (google/protobuf/*, google/api/*) viennent du binaire :
	// protoc sans --include_imports reste donc utilisable pour les types bien connus.
	have := map[string]bool{}
	for _, f := range set.File {
		have[f.GetName()] = true
	}
	for i := 0; i < len(set.File); i++ {
		for _, dep := range set.File[i].Dependency {
			if have[dep] {
				continue
			}
			fd, err := protoregistry.GlobalFiles.FindFileByPath(dep)
			if err != nil {
				return nil, fmt.Errorf("grpc_transcode.descriptor_set : import %q absent (utiliser protoc --include_imports)", dep)
			}
			set.File = append(set.File, protodesc.ToFileDescriptorProto(fd))
			have[dep] = true
		}
	}
	files, err := protodesc.NewFiles(&set)
	if err != nil {
		return nil, fmt.Errorf("grpc_transcode.descriptor_set : %w", err)
	}
	var out []protoreflect.FileDescriptor
	files.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		out = append(out, fd)
		return true
	})
	return out, nil
}

// httpRule lit l'annotation google.api.http d'une méthode (nil si absente). Les options sont
// relues via les types enregistrés dans le binaire, quelle que soit leur origine (protoc ou protocompile).
func httpRule(m protoreflect.MethodDescriptor) *annotations.HttpRule {
	opts := m.Options()
	if opts == nil {
		return nil
	}
	raw, err := proto.Marshal(opts)
	if err != nil || len(raw) == 0 {
		return nil
	}
	var mo descriptorpb.MethodOptions
	if err := (proto.UnmarshalOptions{Resolver: protoregistry.GlobalTypes}).Unmarshal(raw, &mo); err != nil {
		return nil
	}
	rule, _ := proto.GetExtension(&mo, annotations.E_Http).(*annotations.HttpRule)
	return rule
}

// ruleVerb retourne le verbe HTTP et le gabarit d'une règle.
func ruleVerb(r *annotations.HttpRule) (verb, path string) {
	switch p := r.GetPattern().(type) {
	case *annotations.HttpRule_Get:
		return http.MethodGet, p.Get
	case *annotations.HttpRule_Put:
		return http.MethodPut, p.Put
	case *annotations.HttpRule_Post:
		return http.MethodPost, p.Post
	case *annotations.HttpRule_Delete:
		return http.MethodDelete, p.Delete
	case *annotations.HttpRule_Patch:
		return http.MethodPatch, p.Patch
	case *annotations.HttpRule_Custom:
		return strings.ToUpper(p.Custom.GetKind()), p.Custom.GetPath()
	}
	return "", ""
}

func addBinding(t *Transcoder, m protoreflect.MethodDescriptor, verb, path, body, respBody string) error {
	tpl, err := parseTemplate(path)
	if err != nil {
		return fmt.Errorf("%s : %w", m.FullName(), err)
	}
	if m.IsStreamingClient() && body != "*" {
		return fmt.Errorf("%s : un flux client exige body: \"*\" (chaque valeur JSON du corps est un message)", m.FullName())
	}
	in := m.Input()
	for _, v := range tpl.vars {
		if _, err := resolveField(in, v.field); err != nil {
			return fmt.Errorf("%s : variable {%s} : %w", m.FullName(), v.field, err)
		}
	}
	if body != "" && body != "*" {
		if _, err := resolveField(in, body); err != nil {
			return fmt.Errorf("%s : body %q : %w", m.FullName(), body, err)
		}
	}
	if respBody != "" {
		if in2 := m.Output().Fields(); in2.ByName(protoreflect.Name(respBody)) == nil && in2.ByJSONName(respBody) == nil {
			return fmt.Errorf("%s : response_body %q : champ inconnu", m.FullName(), respBody)
		}
	}
	t.bindings = append(t.bindings, &binding{
		httpMethod: verb, tpl: tpl, body: body, responseBody: respBody, method: m,
		grpcPath: "/" + string(m.Parent().FullName()) + "/" + string(m.Name()),
	})
	return nil
}

// Compile construit un Transcoder depuis la configuration.
func Compile(cfg *router.GRPCTranscodeConfig) (*Transcoder, error) {
	hasProto, hasSet := len(cfg.Proto) > 0, strings.TrimSpace(cfg.DescriptorSet) != ""
	var files []protoreflect.FileDescriptor
	var err error
	switch {
	case hasProto && hasSet:
		return nil, fmt.Errorf("grpc_transcode : proto ou descriptor_set, pas les deux")
	case hasProto:
		files, err = loadFromProto(cfg.Proto)
	case hasSet:
		files, err = loadFromDescriptorSet(cfg.DescriptorSet)
	default:
		return nil, fmt.Errorf("grpc_transcode : proto ou descriptor_set requis")
	}
	if err != nil {
		return nil, err
	}

	want := map[string]bool{}
	for _, s := range cfg.Services {
		want[strings.TrimPrefix(strings.TrimSpace(s), ".")] = true
	}
	t := &Transcoder{
		emitDefaults: cfg.EmitDefaults, protoFieldNames: cfg.ProtoFieldNames,
		maxRequest: cfg.MaxRequestBody, maxResponse: cfg.MaxResponseBody,
	}
	if t.maxRequest <= 0 {
		t.maxRequest = defaultMaxRequestBody
	}
	if t.maxResponse <= 0 {
		t.maxResponse = defaultMaxResponseBody
	}
	seen := map[string]bool{}
	for _, f := range files {
		svcs := f.Services()
		for i := 0; i < svcs.Len(); i++ {
			svc := svcs.Get(i)
			if len(want) > 0 && !want[string(svc.FullName())] {
				continue
			}
			seen[string(svc.FullName())] = true
			ms := svc.Methods()
			for j := 0; j < ms.Len(); j++ {
				m := ms.Get(j)
				rule := httpRule(m)
				added := 0
				if rule != nil {
					rules := append([]*annotations.HttpRule{rule}, rule.GetAdditionalBindings()...)
					for _, r := range rules {
						verb, path := ruleVerb(r)
						if verb == "" || path == "" {
							continue
						}
						if err := addBinding(t, m, verb, path, r.GetBody(), r.GetResponseBody()); err != nil {
							return nil, err
						}
						added++
					}
				}
				if added == 0 && cfg.AutoMapping {
					if err := addBinding(t, m, http.MethodPost, "/"+string(svc.FullName())+"/"+string(m.Name()), "*", ""); err != nil {
						return nil, err
					}
					added++
				}
				if added == 0 {
					t.Skipped = append(t.Skipped, string(m.FullName())+" (sans annotation google.api.http)")
				}
			}
		}
	}
	for s := range want {
		if !seen[s] {
			return nil, fmt.Errorf("grpc_transcode.services : service %q introuvable", s)
		}
	}
	if len(t.bindings) == 0 {
		return nil, fmt.Errorf("grpc_transcode : aucune méthode unaire exposée (annoter avec google.api.http ou activer auto_mapping)")
	}
	sort.SliceStable(t.bindings, func(i, j int) bool {
		a, b := t.bindings[i].tpl, t.bindings[j].tpl
		if a.literals() != b.literals() {
			return a.literals() > b.literals()
		}
		return len(a.elems) > len(b.elems)
	})
	return t, nil
}

// Routes décrit les routes compilées (« POST /v1/users/{id} → paquet.Service/Méthode »), pour le dry-run.
func (t *Transcoder) Routes() []string {
	out := make([]string, len(t.bindings))
	for i, b := range t.bindings {
		out[i] = b.httpMethod + " " + b.tpl.String() + " → " + strings.TrimPrefix(b.grpcPath, "/") + b.streamKind()
	}
	sort.Strings(out)
	return out
}

// streamKind décrit le flux de la méthode pour le dry-run (vide pour une méthode unaire).
func (b *binding) streamKind() string {
	switch {
	case b.method.IsStreamingClient() && b.method.IsStreamingServer():
		return " [flux bidirectionnel]"
	case b.method.IsStreamingClient():
		return " [flux client]"
	case b.method.IsStreamingServer():
		return " [flux serveur]"
	}
	return ""
}

func (t *template) String() string {
	var sb strings.Builder
	inVar := map[int]pathVar{}
	for _, v := range t.vars {
		inVar[v.start] = v
	}
	for i := 0; i < len(t.elems); {
		sb.WriteByte('/')
		if v, ok := inVar[i]; ok {
			sb.WriteString("{" + v.field + "}")
			i = v.end
			continue
		}
		switch e := t.elems[i]; e.kind {
		case elemLiteral:
			sb.WriteString(e.lit)
		case elemStar:
			sb.WriteByte('*')
		default:
			sb.WriteString("**")
		}
		i++
	}
	if t.verb != "" {
		sb.WriteString(":" + t.verb)
	}
	return sb.String()
}
