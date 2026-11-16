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
		if _, err := awid.DecodeStableID(strings.TrimPrefix(text(target, "person"), "did:aw:")); err != nil {
			return refuse("definition_invalid")
		}
		rootID := text(target, "root_id")
		if strings.HasPrefix(rootID, "did:aw:") {
			if _, err := awid.DecodeStableID(strings.TrimPrefix(rootID, "did:aw:")); err != nil {
				return refuse("definition_invalid")
			}
		} else if _, err := awid.ExtractPublicKey(rootID); err != nil {
			return refuse("definition_invalid")
		}
		if _, err := awid.ExtractPublicKey(text(target, "root_key")); err != nil {
			return refuse("definition_invalid")
		}
		if strings.HasPrefix(rootID, "did:key:") && text(target, "root_key") != rootID {
			return refuse("root_key_mismatch")
		}
		teams := target["teams"].([]any)
		// Like Python, check whole-list ordering before any team domain.
		for i := 1; i < len(teams); i++ {
			if teams[i].(string) < teams[i-1].(string) {
				return refuse("definition_invalid")
			}
		}
		for _, item := range teams {
			team := item.(string)
			domain, name, err := awid.ParseTeamID(team)
			if err != nil || awid.BuildTeamID(domain, name) != team {
				return refuse("definition_invalid")
			}
			if domain != text(request, "organisation") {
				return refuse("root_team_organisation_mismatch")
			}
		}
	}
	return nil
}
