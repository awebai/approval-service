package verify

import "testing"

func TestRootAgentSeam(t *testing.T) {
	for _, item := range seamCases(t, "root-agent") {
		c := item.(map[string]any)
		t.Run(text(c, "id"), func(t *testing.T) {
			trust := *seamTrust(t, c["trust"])
			r := object(c, "root")
			root := RootIdentity{ID: text(r, "id"), CurrentKey: text(r, "current_key"), ContinuousKeys: stringList(r["continuous_keys"])}
			var got CheckedRootAgent
			var err error
			if text(c, "phase") == "historical" {
				h := object(c, "continuity")
				var since *int64
				if h["since"] != nil {
					n := number(h, "since")
					since = &n
				}
				got, err = VerifyRootAgentProof(object(c, "proof"), root, text(c, "parent_person"), trust, PersonContinuity{FromKey: text(h, "from_key"), CurrentKey: text(h, "current_key"), Mode: text(h, "mode"), Since: since})
			} else {
				secret, _ := decode(text(c, "nonce_key"))
				got, err = CheckRootAgentPresentation(object(c, "presentation"), RootAgentInput{ExpectedRequest: object(c, "request"), Root: root, Trust: trust, Now: number(c, "now"), Presenter: object(c, "presenter"), RequiredGrade: text(c, "required_grade"), NonceKeys: map[string][]byte{"k1": secret}, Origin: text(c, "origin"), Audience: text(c, "audience"), EnforcerKind: text(c, "enforcer_kind"), OwnedTeams: stringList(c["owned_teams"]), Revision: number(c, "revision")})
			}
			if (err == nil) != c["accept"].(bool) {
				t.Fatalf("accept=%v want=%v: %v", err == nil, c["accept"], err)
			}
			if err != nil {
				if err.Error() != text(c, "expected_error") {
					t.Fatalf("code=%v want=%s", err, text(c, "expected_error"))
				}
				return
			}
			teams := make([]any, len(got.Teams))
			for i, team := range got.Teams {
				teams[i] = team
			}
			actual := map[string]any{"person": got.Person, "root_id": got.RootID, "root_key": got.RootKey, "mode": got.Mode, "teams": teams, "status": got.Status, "continuity": got.Continuity, "enforcer": got.Enforcer}
			if got.Since == nil {
				actual["since"] = nil
			} else {
				actual["since"] = *got.Since
			}
			for k, want := range object(c, "expected") {
				a, e := Canonical(actual[k])
				b, f := Canonical(want)
				if e != nil || f != nil || string(a) != string(b) {
					t.Fatalf("%s: got=%v want=%v", k, actual[k], want)
				}
			}
		})
	}
}

func stringList(v any) []string {
	items, _ := v.([]any)
	values := make([]string, len(items))
	for i, item := range items {
		values[i], _ = item.(string)
	}
	return values
}
