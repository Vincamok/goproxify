// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package grpctrans

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/dynamicpb"
)

// errUnknownField distingue un champ inexistant (ignoré dans la chaîne de requête) d'une valeur invalide.
type errUnknownField string

func (e errUnknownField) Error() string { return "champ inconnu : " + string(e) }

func findField(md protoreflect.MessageDescriptor, name string) protoreflect.FieldDescriptor {
	if fd := md.Fields().ByName(protoreflect.Name(name)); fd != nil {
		return fd
	}
	return md.Fields().ByJSONName(name)
}

// resolveField suit un chemin « a.b.c » (noms proto ou JSON) jusqu'au champ final.
func resolveField(md protoreflect.MessageDescriptor, path string) (protoreflect.FieldDescriptor, error) {
	parts := strings.Split(path, ".")
	var fd protoreflect.FieldDescriptor
	for i, p := range parts {
		fd = findField(md, p)
		if fd == nil {
			return nil, errUnknownField(path)
		}
		if i < len(parts)-1 {
			if fd.Kind() != protoreflect.MessageKind || fd.IsList() || fd.IsMap() {
				return nil, fmt.Errorf("%q n'est pas un message : impossible d'y descendre", p)
			}
			md = fd.Message()
		}
	}
	return fd, nil
}

// jsonNames convertit un chemin de champs en noms JSON (pour envelopper un corps de requête).
func jsonNames(md protoreflect.MessageDescriptor, path string) ([]string, error) {
	var out []string
	for _, p := range strings.Split(path, ".") {
		fd := findField(md, p)
		if fd == nil {
			return nil, errUnknownField(path)
		}
		out = append(out, fd.JSONName())
		if fd.Kind() == protoreflect.MessageKind && !fd.IsList() && !fd.IsMap() {
			md = fd.Message()
		}
	}
	return out, nil
}

// parseScalar convertit un texte en valeur du type du champ.
func parseScalar(fd protoreflect.FieldDescriptor, s string) (protoreflect.Value, error) {
	switch fd.Kind() {
	case protoreflect.BoolKind:
		b, err := strconv.ParseBool(s)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("%q n'est pas un booléen", s)
		}
		return protoreflect.ValueOfBool(b), nil
	case protoreflect.Int32Kind, protoreflect.Sint32Kind, protoreflect.Sfixed32Kind:
		n, err := strconv.ParseInt(s, 10, 32)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("%q n'est pas un entier 32 bits", s)
		}
		return protoreflect.ValueOfInt32(int32(n)), nil
	case protoreflect.Int64Kind, protoreflect.Sint64Kind, protoreflect.Sfixed64Kind:
		n, err := strconv.ParseInt(s, 10, 64)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("%q n'est pas un entier 64 bits", s)
		}
		return protoreflect.ValueOfInt64(n), nil
	case protoreflect.Uint32Kind, protoreflect.Fixed32Kind:
		n, err := strconv.ParseUint(s, 10, 32)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("%q n'est pas un entier non signé 32 bits", s)
		}
		return protoreflect.ValueOfUint32(uint32(n)), nil
	case protoreflect.Uint64Kind, protoreflect.Fixed64Kind:
		n, err := strconv.ParseUint(s, 10, 64)
		if err != nil {
			return protoreflect.Value{}, fmt.Errorf("%q n'est pas un entier non signé 64 bits", s)
		}
		return protoreflect.ValueOfUint64(n), nil
	case protoreflect.FloatKind:
		f, err := parseFloat(s, 32)
		if err != nil {
			return protoreflect.Value{}, err
		}
		return protoreflect.ValueOfFloat32(float32(f)), nil
	case protoreflect.DoubleKind:
		f, err := parseFloat(s, 64)
		if err != nil {
			return protoreflect.Value{}, err
		}
		return protoreflect.ValueOfFloat64(f), nil
	case protoreflect.StringKind:
		return protoreflect.ValueOfString(s), nil
	case protoreflect.BytesKind:
		for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
			if b, err := enc.DecodeString(s); err == nil {
				return protoreflect.ValueOfBytes(b), nil
			}
		}
		return protoreflect.Value{}, fmt.Errorf("%q n'est pas du base64", s)
	case protoreflect.EnumKind:
		if v := fd.Enum().Values().ByName(protoreflect.Name(s)); v != nil {
			return protoreflect.ValueOfEnum(v.Number()), nil
		}
		if n, err := strconv.ParseInt(s, 10, 32); err == nil {
			return protoreflect.ValueOfEnum(protoreflect.EnumNumber(n)), nil
		}
		return protoreflect.Value{}, fmt.Errorf("%q n'est pas une valeur de %s", s, fd.Enum().Name())
	}
	return protoreflect.Value{}, fmt.Errorf("type de champ non pris en charge dans l'URL")
}

func parseFloat(s string, bits int) (float64, error) {
	switch s {
	case "NaN":
		return math.NaN(), nil
	case "Infinity":
		return math.Inf(1), nil
	case "-Infinity":
		return math.Inf(-1), nil
	}
	f, err := strconv.ParseFloat(s, bits)
	if err != nil {
		return 0, fmt.Errorf("%q n'est pas un nombre", s)
	}
	return f, nil
}

// setFromStrings affecte les valeurs textuelles (chemin ou chaîne de requête) au champ désigné.
func setFromStrings(msg protoreflect.Message, path string, values []string) error {
	parts := strings.Split(path, ".")
	for i, p := range parts {
		fd := findField(msg.Descriptor(), p)
		if fd == nil {
			return errUnknownField(path)
		}
		if i < len(parts)-1 {
			if fd.Kind() != protoreflect.MessageKind || fd.IsList() || fd.IsMap() {
				return errUnknownField(path)
			}
			msg = msg.Mutable(fd).Message()
			continue
		}
		if fd.IsMap() {
			return fmt.Errorf("le champ map %q ne se renseigne pas par l'URL", path)
		}
		if fd.IsList() {
			list := msg.Mutable(fd).List()
			for _, v := range values {
				pv, err := parseOne(fd, v)
				if err != nil {
					return fmt.Errorf("%s : %w", path, err)
				}
				list.Append(pv)
			}
			return nil
		}
		pv, err := parseOne(fd, values[len(values)-1])
		if err != nil {
			return fmt.Errorf("%s : %w", path, err)
		}
		msg.Set(fd, pv)
	}
	return nil
}

// parseOne gère les scalaires et les types bien connus (Timestamp, Duration, FieldMask, enveloppes).
func parseOne(fd protoreflect.FieldDescriptor, s string) (protoreflect.Value, error) {
	if fd.Kind() != protoreflect.MessageKind && fd.Kind() != protoreflect.GroupKind {
		return parseScalar(fd, s)
	}
	if !strings.HasPrefix(string(fd.Message().FullName()), "google.protobuf.") {
		return protoreflect.Value{}, fmt.Errorf("un champ message ne se renseigne pas par l'URL (utiliser le corps)")
	}
	m := dynamicpb.NewMessage(fd.Message())
	for _, candidate := range []string{strconv.Quote(s), s} {
		if err := protojson.Unmarshal([]byte(candidate), m); err == nil {
			return protoreflect.ValueOfMessage(m), nil
		}
	}
	return protoreflect.Value{}, fmt.Errorf("valeur %q invalide", s)
}

// BadRequest est une erreur de traduction côté client (400).
type BadRequest struct{ Msg string }

func (e *BadRequest) Error() string { return e.Msg }

// Request retourne la méthode gRPC visée et le message encodé (sans cadrage).
func (b *binding) buildRequest(r *http.Request, body []byte, vars map[string]string) ([]byte, error) {
	msg := dynamicpb.NewMessage(b.method.Input())

	switch {
	case b.body == "*":
		if len(strings.TrimSpace(string(body))) > 0 {
			if err := (protojson.UnmarshalOptions{}).Unmarshal(body, msg); err != nil {
				return nil, &BadRequest{"corps invalide : " + err.Error()}
			}
		}
	case b.body != "":
		if len(strings.TrimSpace(string(body))) > 0 {
			names, err := jsonNames(b.method.Input(), b.body)
			if err != nil {
				return nil, err
			}
			wrapped := string(body)
			for i := len(names) - 1; i >= 0; i-- {
				k, _ := json.Marshal(names[i])
				wrapped = "{" + string(k) + ":" + wrapped + "}"
			}
			if err := (protojson.UnmarshalOptions{}).Unmarshal([]byte(wrapped), msg); err != nil {
				return nil, &BadRequest{"corps invalide : " + err.Error()}
			}
		}
	}

	names := make([]string, 0, len(vars))
	for k := range vars {
		names = append(names, k)
	}
	sort.Strings(names)
	for _, k := range names {
		if err := setFromStrings(msg, k, []string{vars[k]}); err != nil {
			return nil, &BadRequest{err.Error()}
		}
	}

	if b.body != "*" {
		q := queryValues(r.URL)
		keys := make([]string, 0, len(q))
		for k := range q {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			if _, isVar := vars[k]; isVar || (b.body != "" && (k == b.body || strings.HasPrefix(k, b.body+"."))) {
				continue
			}
			if err := setFromStrings(msg, k, q[k]); err != nil {
				if _, unknown := err.(errUnknownField); unknown {
					continue // paramètre étranger (cache-buster, jeton…) : ignoré
				}
				return nil, &BadRequest{err.Error()}
			}
		}
	}
	return proto.Marshal(msg)
}

func queryValues(u *url.URL) url.Values { return u.Query() }

// marshalJSON écrit un message de réponse en JSON (response_body : seulement ce champ).
func (t *Transcoder) marshalJSON(b *binding, msg proto.Message) ([]byte, error) {
	mo := protojson.MarshalOptions{EmitUnpopulated: t.emitDefaults, UseProtoNames: t.protoFieldNames}
	out, err := mo.Marshal(msg)
	if err != nil {
		return nil, err
	}
	if b.responseBody == "" {
		return out, nil
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(out, &obj); err != nil {
		return nil, err
	}
	fd := findField(b.method.Output(), b.responseBody)
	if fd == nil {
		return nil, fmt.Errorf("response_body %q introuvable", b.responseBody)
	}
	name := fd.JSONName()
	if t.protoFieldNames {
		name = string(fd.Name())
	}
	if v, ok := obj[name]; ok {
		return v, nil
	}
	// Champ à valeur par défaut omis : on renvoie la valeur « vide » du type plutôt qu'un objet.
	switch {
	case fd.IsList():
		return []byte("[]"), nil
	case fd.Kind() == protoreflect.MessageKind:
		return []byte("{}"), nil
	}
	return []byte("null"), nil
}
