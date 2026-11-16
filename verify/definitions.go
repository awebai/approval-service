package verify

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"sync"

	"github.com/awebai/aw/awid"
)

var definitionsOnce sync.Once
var definitions map[string]any
var definitionsError error

func definitionBody(id string) (map[string]any, error) {
	definitionsOnce.Do(func() {
		v, e := Parse([]byte(schemaJSON))
		if e != nil {
			definitionsError = e
			return
		}
		definitions = v["x-act-definitions"].(map[string]any)
	})
	if definitionsError != nil {
		return nil, definitionsError
	}
	v, ok := definitions[id].(map[string]any)
	if !ok {
		return nil, refuse("definition_unavailable")
	}
	return v, nil
}
func DefinitionRef(id string) (map[string]any, error) {
	v, e := definitionBody(id)
	if e != nil {
		return nil, e
	}
	b, e := Canonical(v)
	if e != nil {
		return nil, e
	}
	h := sha256.Sum256(b)
	return map[string]any{"id": id, "version": json.Number("1"), "sha256": hex.EncodeToString(h[:])}, nil
}
func CheckDefinition(request map[string]any) error {
	if validate("request", request) != nil {
		return refuse("definition_invalid")
	}
	ref := object(request, "definition")
	id := text(ref, "id")
	want, e := DefinitionRef(id)
	if e != nil {
		return e
	}
	if !equalValue(ref, want) {
		return refuse("definition_mismatch")
	}
	v, e := definitionBody(id)
	if e != nil {
		return e
	}
	if request["purpose"] != v["purpose"] {
		return refuse("purpose_invalid")
	}
	spec := wireSchema["x-act-definitions"].(map[string]any)[id].(map[string]any)["act_schema"].(map[string]any)
	if validateNode(spec, request["act"]) != nil {
		return refuse("definition_invalid")
	}
	if id == "agent.root.authorize" {
		target := object(object(request, "act"), "target")
		for _, field := range []string{"person", "root_id"} {
			if _, err := awid.DecodeStableID(strings.TrimPrefix(text(target, field), "did:aw:")); err != nil {
				return refuse("definition_invalid")
			}
		}
		if _, err := awid.ExtractPublicKey(text(target, "root_key")); err != nil {
			return refuse("definition_invalid")
		}
		previous := ""
		for _, item := range target["teams"].([]any) {
			team := item.(string)
			domain, name, err := awid.ParseTeamID(team)
			if err != nil || awid.BuildTeamID(domain, name) != team || team < previous {
				return refuse("definition_invalid")
			}
			if domain != text(request, "organisation") {
				return refuse("root_team_organisation_mismatch")
			}
			previous = team
		}
	}
	return nil
}
